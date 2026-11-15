"""R3: real recovery loop with in-memory native boundaries; root-only scope fixture."""
import ast
import copy
from contextlib import ExitStack, contextmanager, nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/semantic_provider_operation"))
sys.path.insert(0, str(ROOT / "tools/semantic_lease_recovery"))
import lease_supervisor as s
from bounded_recovery import Permanent, Policy
from continuous_supervisor import Supervisor
from lease_recovery_budget import LeaseRecovery
import continuous_supervisor

bootstrap_spec = importlib.util.spec_from_file_location("lease_supervisor_bootstrap", ROOT / s.SELF)
bootstrap = importlib.util.module_from_spec(bootstrap_spec)
bootstrap_spec.loader.exec_module(bootstrap)

NATIVE = os.environ.get("OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE requires Linux root:root")


def configuration():
    bind = lambda name, digest="a": {"path": "/run/fixture/" + name, "sha256": digest * 64}
    return {"schema": s.SCHEMA, "installationRef": "inst", "entityRef": "ent", "issuerRef": "installer",
            "sourceRoot": "/run/fixture/source",
            "sourceHashes": {**dict.fromkeys(s.SOURCES, "a" * 64), **s.RECOVERY_SOURCES},
            "authorizationRoot": "/run/fixture/operation", "anchorBinding": bind("anchor"),
            "mandateRoot": "/run/fixture/ledger", "opensslBinding": {**bind("openssl"), "version": "3.0.0"},
            "mandatesModule": bind("mandates.py"), "registryRoot": "/run/fixture/registry",
            "coordinator": {"ownerConfiguration": bind("owner", "8"), "journalPath": "/run/fixture/journal",
                            "commonLockPath": "/run/fixture/common.lock", "dnsProfile": bind("dns", "0"),
                            "nftBinding": bind("nft")},
            "recoveryJournalRoot": "/run/fixture/recoveries", "statusPath": "/run/fixture/status",
            "limits": {"maxActivationsPerHour": 6, "heartbeatSeconds": 1, "pollSeconds": 15}}


def source_fixture(cfg):
    # Prepare LF delivery, without modifying the checkout or normalizing in a loader.
    sources = {relative: (ROOT / relative).read_bytes().replace(b"\r\n", b"\n") for relative in s.SOURCES}
    cfg["sourceHashes"] = {relative: s.sha(raw) for relative, raw in sources.items()}
    return sources


class Config:
    def __init__(self):
        self.value, self.error = configuration(), None

    def custody(self):
        if self.error:
            raise self.error


class Clock:
    value = 10000

    def __call__(self):
        return self.value


class Stop:
    """Deterministic event: advance clocks, then deliver epoch changes or SIGTERM."""
    def __init__(self, clock, hook):
        self.clock, self.hook, self.stopped, self.waits = clock, hook, False, 0

    def set(self):
        self.stopped = True

    def is_set(self):
        return self.stopped

    def wait(self, seconds):
        if not self.stopped:
            self.clock.value += seconds
            self.waits += 1
            self.hook(self)
        return self.stopped


class Coordinator:
    def __init__(self):
        self.calls = []
        self.state, self.members = "LEASE_READY", [["SENTINEL_PRIVATE_ADDRESS"]]

    def hold_lock(self):
        return nullcontext()

    def quiesce(self):
        self.calls.append("quiesce")
        self.state, self.members = "QUIESCED", [[], []]

    def sets(self):
        return self.members

    def journal(self):
        return {"state": self.state, "leaseAuthorized": self.state == "LEASE_READY", "startAuthorized": False}


class MemoryJournal:
    def read(self):
        return copy.deepcopy(self.row)

    def compare_and_save(self, previous, value):
        assert previous == self.row
        self.row = copy.deepcopy(value)

    def invocation(self):
        return nullcontext()


class Adapter:
    def __init__(self, c, guards):
        self.c, self.guards = c, guards

    def guard(self):
        self.guards.custody_guard()
        self.guards.scope_guard()

    def pause(self):
        self.c.calls.append("pause")
        self.c.quiesce()

    def prepare(self, deadline):
        self.guard()
        self.pause()
        self.c.calls.append("prepare")
        return {}

    def publish(self, evidence, deadline):
        self.guard()
        self.c.calls.append("publish")
        self.c.state, self.c.members = "LEASE_READY", [["SENTINEL_PRIVATE_ADDRESS"]]
        return "d" * 64

    def prepare_renewal(self, deadline):
        self.guard()
        self.c.calls.append("prepare_renewal")
        return {}

    def publish_renewal(self, evidence, deadline):
        self.guard()
        self.c.calls.append("renew")
        return "e" * 64


class Tests(unittest.TestCase):
    def setUp(self):
        self.config, self.clock, self.c = Config(), Clock(), Coordinator()
        self.h = {"sequence": 1, "sha256": "f" * 64, "decision": "OPERATE", "authorization": {
            "lease": {"ownerConfigurationSha256": "8" * 64, "leaseStructureHash": "9" * 64,
                      "dnsProfileSha256": "0" * 64},
            "roles": {r: {"containerId": r} for r in s.ROLES}}}
        self.journals = {r: {"epoch": 1, "generation": {"pid": i + 5, "startTicks": 123},
                             "authorizationSha256": "f" * 64, "bootId": "this-boot", "state": "STARTED"}
                         for i, r in enumerate(s.ROLES)}
        self.head_error = None
        self.g = s.Guards(self.config, None, "9" * 64, Permanent, head=self.head,
            current=lambda root, cid: self.journals[cid],
            live=lambda journal, boot: journal["state"] == "STARTED" and journal["bootId"] == boot,
            boot=lambda: "this-boot", clock=self.clock)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config.value["statusPath"] = str(Path(self.temp.name) / "status.json")
        self.statuses, self.recoveries = [], []
        self.store = self.new_store()
        self.schedule = patch.object(continuous_supervisor, "window", side_effect=lambda *a, **kw:
            {"waitSeconds": 1, "deadlineMonotonic": self.clock() + 30})
        self.schedule.start()
        self.addCleanup(self.schedule.stop)

    def new_store(self):
        def write(path, value):
            Path(path).write_bytes(s.canonical(value))
        return s.ActivationStore(self.config.value["statusPath"], reader=lambda p: Path(p).read_bytes(), writer=write)

    def head(self, *args):
        if self.head_error:
            raise self.head_error
        return self.h

    def factory(self, guards):
        guards.scope_guard()
        j = MemoryJournal()
        recovery = LeaseRecovery(j, Adapter(self.c, guards), Policy(), "a" * 64, "b" * 64,
                                 lambda: (self.clock(), self.clock()), lambda: .5)
        j.row = recovery.initial()
        self.recoveries.append(j)
        return Supervisor(recovery, self.c, 15, heartbeat=1)

    def service(self, hook=None, store=None, writer=None):
        stop = Stop(self.clock, hook or (lambda event: event.set()))
        return s.Service(self.config.value, self.c, self.g, self.factory, store or self.store, stop=stop,
                         clock=self.clock, writer=writer or (lambda p, v: self.statuses.append(copy.deepcopy(v))))

    def assert_denial(self, category, reason, function=None):
        with self.assertRaises(Permanent) as caught:
            (function or self.g.scope_guard)()
        self.assertEqual(caught.exception.code, category)
        self.assertEqual(self.g.reason, reason)

    def test_startup_quiesces_before_authorization_even_if_stop_already_set(self):
        def read(*args):
            self.assertEqual(self.c.calls[0], "quiesce")
            raise s.authorization.OperationDenied("OPERATION_AUTHORIZATION_ABSENT")
        self.g.head = read
        self.assertEqual(self.service().run(), 0)
        self.assertEqual(self.statuses[0]["state"], "WAITING")
        self.assertEqual(self.c.state, "QUIESCED")
        self.c.calls.clear()
        service = self.service()
        service.terminate()
        self.assertEqual(service.run(), 0)
        self.assertEqual(self.c.calls[0], "quiesce")

    def test_waiting_absent_stop_dead_and_other_boot(self):
        for variant in ("absent", "stop", "dead", "boot"):
            with self.subTest(variant=variant):
                self.head_error = None
                self.h["decision"] = "OPERATE"
                self.journals["adapter"].update(state="STARTED", bootId="this-boot")
                if variant == "absent":
                    self.head_error = s.authorization.OperationDenied("OPERATION_AUTHORIZATION_ABSENT")
                    expected = "OPERATION_AUTHORIZATION_ABSENT"
                elif variant == "stop":
                    self.h["decision"] = "STOP"
                    expected = "OPERATION_STOP"
                else:
                    self.journals["adapter"].update({"state": "FAILED"} if variant == "dead" else {"bootId": "old-boot"})
                    expected = "EPOCH_NOT_LIVE"
                self.statuses.clear()
                self.assertEqual(self.service().run(), 0)
                self.assertEqual((self.statuses[0]["state"], self.statuses[0]["reason"]), ("WAITING", expected))
                self.assertNotIn("publish", self.c.calls)
                self.assertEqual(self.store.count(self.clock()), 0)

    def test_activation_renewal_and_sigterm(self):
        service = self.service(lambda event: service.terminate(signal.SIGTERM, None) if event.waits == 3 else None)
        self.assertEqual(service.run(), 0)
        self.assertEqual(self.c.calls[0], "quiesce")
        self.assertEqual(self.c.calls.count("publish"), 1)
        self.assertEqual(self.c.calls.count("renew"), 2)
        self.assertEqual(self.statuses[-1]["state"], "STOPPED")
        self.assertEqual(self.statuses[-1]["renewals"], 2)
        self.assertEqual(self.c.state, "QUIESCED")

    def test_epoch_change_revokes_and_returns_to_waiting(self):
        def hook(event):
            if event.waits == 1:
                self.journals["southbound"]["epoch"] = 2
            elif event.waits == 2:
                event.set()
        self.assertEqual(self.service(hook).run(), 0)
        self.assertIn(("WAITING", "EPOCH_SCOPE_CHANGED"), [(v["state"], v["reason"]) for v in self.statuses])
        self.assertEqual(self.g.reason, "EPOCH_SCOPE_CHANGED")
        self.assertEqual(self.recoveries[0].row["state"], "CANCELLED")
        self.assertEqual(self.c.state, "QUIESCED")
        self.assertNotIn("renew", self.c.calls)

    def test_generation_scope_and_detailed_categories(self):
        self.g.fixed = self.g.scope_guard()
        self.journals["adapter"]["generation"]["startTicks"] += 1
        self.assert_denial("GENERATION_CHANGED", "EPOCH_SCOPE_CHANGED")
        self.g.fixed = None
        self.journals["adapter"]["bootId"] = "old"
        self.assert_denial("GENERATION_CHANGED", "EPOCH_NOT_LIVE")
        self.journals["adapter"]["bootId"] = "this-boot"
        self.journals["adapter"]["authorizationSha256"] = "e" * 64
        self.assert_denial("AUTHORITY_REVOKED", "EPOCH_AUTHORIZATION_CHANGED")
        self.h["authorization"]["lease"]["dnsProfileSha256"] = "b" * 64
        self.assert_denial("CONFIGURATION_DRIFT", "LEASE_BINDINGS_CHANGED")
        self.head_error = s.authorization.OperationDenied("OPERATION_KEY_REVOKED")
        self.assert_denial("AUTHORITY_REVOKED", "OPERATION_KEY_REVOKED")
        self.head_error = RuntimeError("SENTINEL_PRIVATE_ADDRESS")
        self.assert_denial("INTEGRITY_UNPROVEN", "LOCAL_STATE_UNPROVEN")

    def test_custody_guard_and_verified_compilation(self):
        self.config.error = s.Denied("SUPERVISOR_BINDING_HASH_MISMATCH")
        self.assert_denial("CONFIGURATION_DRIFT", "SUPERVISOR_BINDING_HASH_MISMATCH", self.g.custody_guard)
        self.config.error = RuntimeError("SENTINEL_PRIVATE_ADDRESS")
        self.assert_denial("INTEGRITY_UNPROVEN", "LOCAL_STATE_UNPROVEN", self.g.custody_guard)
        raw = b"VALUE = 73\n"
        path = Path(self.temp.name) / "mod.py"
        path.write_text("raise RuntimeError('must not import from disk')")
        try:
            module = s.compiled(raw, path, "supervisor_test_verified", s.sha(raw))
            self.assertEqual(module.VALUE, 73)
            with self.assertRaises(s.Denied):
                s.compiled(b"raise RuntimeError('must not execute')", path, "supervisor_test_bad", s.sha(raw))
        finally:
            sys.modules.pop("supervisor_test_verified", None)

    def test_six_openings_persist_restart_then_resume_at_window_boundary(self):
        for _ in range(6):
            self.store.reserve(self.clock())
        restarted = self.new_store()
        def hook(event):
            if event.waits == 1:
                self.assertEqual(self.c.state, "QUIESCED")
                self.clock.value += 3599  # first heartbeat already advanced one second
            else:
                event.set()
        self.assertEqual(self.service(hook, store=restarted).run(), 0)
        self.assertEqual(self.statuses[0]["state"], "PARKED_RATE_LIMITED")
        self.assertEqual(self.statuses[0]["activationsLastHour"], 6)
        self.assertIn("ACTIVE", [v["state"] for v in self.statuses])
        self.assertEqual(self.c.calls.count("publish"), 1)
        self.assertEqual(self.new_store().count(self.clock()), 1)

    def test_only_six_real_scopes_in_sliding_hour(self):
        def hook(event):
            if len(self.recoveries) <= 6:
                self.journals["adapter"]["epoch"] += 1
            if any(v["state"] == "PARKED_RATE_LIMITED" for v in self.statuses):
                event.set()
        self.assertEqual(self.service(hook).run(), 0)
        self.assertEqual(len(self.recoveries), 6)
        self.assertEqual(self.store.count(self.clock()), 6)
        self.assertEqual(self.c.state, "QUIESCED")

    def test_status_schema_and_unknown_error_sentinel(self):
        service = self.service()
        service.factory = lambda _: (_ for _ in ()).throw(RuntimeError("SENTINEL_PRIVATE_ADDRESS"))
        self.assertEqual(service.run(), 1)
        self.assertEqual(self.statuses[-1]["reason"], "LOCAL_STATE_UNPROVEN")
        self.assertNotIn("SENTINEL", json.dumps(self.statuses))
        expected = {"schema", "state", "reason", "activationsLastHour", "renewals", "authorizationSequence",
                    "epochs", "updatedAt"}
        for value in self.statuses:
            self.assertEqual(set(value), expected)
            self.assertEqual(value["schema"], s.STATUS_SCHEMA)
            self.assertEqual(set(value["epochs"]), set(s.ROLES))
            self.assertTrue(value["reason"] is None or s.CODE.fullmatch(value["reason"]))

    def test_configuration_hash_extra_fields_and_nested_schema(self):
        value = configuration()
        raw = s.canonical(value)
        def reader(path, expected, **kw):
            s.require(s.sha(raw) == expected, "SUPERVISOR_BINDING_HASH_MISMATCH")
            return raw
        self.assertEqual(s.Configuration("fixture", s.sha(raw), reader).value, value)
        with self.assertRaisesRegex(s.Denied, "SUPERVISOR_BINDING_HASH_MISMATCH"):
            s.Configuration("fixture", "b" * 64, reader)
        for change in (lambda v: v.update(extra=True), lambda v: v["coordinator"].update(extra=True),
                       lambda v: v["limits"].update(maxActivationsPerHour=7),
                       lambda v: v["mandatesModule"].update(extra=True),
                       lambda v: v["limits"].update(heartbeatSeconds=True)):
            bad = copy.deepcopy(value)
            change(bad)
            with self.assertRaises(s.Denied):
                s.validate(s.canonical(bad))
        with self.assertRaises(s.authorization.OperationDenied):
            s.validate(raw + b"\n")

    def test_configuration_custody_rechecks_all_required_bindings(self):
        cfg = configuration()
        sources = source_fixture(cfg)
        raw = s.canonical(cfg)
        calls = []
        def reader(path, expected, **kw):
            calls.append((path, expected, kw))
            relative = Path(path).relative_to(cfg["sourceRoot"]).as_posix() if isinstance(path, Path) else None
            return sources[relative] if relative else raw
        directories = []
        c = s.Configuration("/run/fixture/config", s.sha(raw), reader, directories.append)
        self.assertEqual(c.custody(), sources)
        self.assertEqual([v[0] for v in calls[1:6]], ["/run/fixture/config", "/run/fixture/owner",
                         "/run/fixture/dns", "/run/fixture/nft", "/run/fixture/mandates.py"])
        self.assertTrue(calls[4][2]["executable"])
        self.assertEqual(directories, [Path(cfg["sourceRoot"])])
        self.assertEqual({Path(v[0]).relative_to(cfg["sourceRoot"]).as_posix() for v in calls[6:]}, s.SOURCES)

    def test_reviewed_library_pins_match_repository_lf_delivery(self):
        for name, expected in s.PINS.items():
            raw = (ROOT / "tools/semantic_lease_recovery" / (name + ".py")).read_bytes()
            # Windows checkout conversion is only accounted for in this assertion.
            # Production loader verifies exact raw bytes and never normalizes them.
            self.assertEqual(s.sha(raw.replace(b"\r\n", b"\n")), expected, name)

    def test_cli_sigterm_handler_and_restore(self):
        handlers = []
        def handler(sig, callback):
            handlers.append(callback)
            return "previous-handler"
        stop = Stop(self.clock, lambda event: handlers[0](signal.SIGTERM, None))
        with patch.object(s, "Configuration", return_value=self.config), \
                patch.object(s, "lifetime_lock", return_value=nullcontext()), \
                patch.object(s, "runtime", return_value=(self.c, self.g, self.factory)), \
                patch.object(s, "ActivationStore", return_value=self.store), \
                patch.object(s.threading, "Event", return_value=stop), \
                patch.object(s.signal, "signal", side_effect=handler), \
                patch.object(s, "atomic", side_effect=lambda path, row: self.statuses.append(row)):
            # Service defaults are bound at definition time: inject the test clock/store writer.
            real_service = s.Service
            def build(*args, **kwargs):
                return real_service(*args, **kwargs, clock=self.clock,
                                    writer=lambda p, row: self.statuses.append(row))
            with patch.object(s, "Service", side_effect=build):
                result = s.main(["--configuration", "/run/config", "--configuration-sha256", "a" * 64])
        self.assertEqual(result, 0)
        self.assertEqual(handlers[-1], "previous-handler")
        self.assertEqual(self.c.calls[0], "quiesce")
        self.assertEqual(self.statuses[-1]["state"], "STOPPED")

    def test_history_corruption_missing_and_clock_regression_fail_closed(self):
        self.store.reserve(self.clock())
        with self.assertRaisesRegex(s.Denied, "ACTIVATION_CLOCK_REGRESSION"):
            self.store.count(self.clock() - 1)
        self.store.path.write_bytes(b"{}")
        with self.assertRaises(s.Denied):
            self.new_store()
        self.store.path.unlink()
        Path(self.config.value["statusPath"]).write_bytes(b"{}")
        with self.assertRaisesRegex(s.Denied, "ACTIVATION_HISTORY_MISSING"):
            self.new_store()

    def test_failed_quiescence_never_advertises_waiting_or_stopped(self):
        self.c.quiesce = lambda: None
        self.assertEqual(self.service().run(), 1)
        self.assertEqual([(v["state"], v["reason"]) for v in self.statuses], [("FAILED", "QUIESCENCE_UNPROVEN")])

    def test_rate_reservation_precedes_factory_and_failure_does_not_reset_history(self):
        service = self.service()
        def factory(guards):
            self.assertEqual(self.new_store().count(self.clock()), 1)
            raise RuntimeError("SENTINEL_PRIVATE_ADDRESS")
        service.factory = factory
        self.assertEqual(service.run(), 1)
        self.assertEqual(self.new_store().count(self.clock()), 1)


class QuiesceOnlyTests(unittest.TestCase):
    def test_static_revocation_path_has_no_activation_publication_or_service_lock(self):
        tree = ast.parse((ROOT / 'tools/semantic_provider_operation/lease_supervisor.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'quiesce_only')
        calls = {n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id
                 for n in ast.walk(function) if isinstance(n, ast.Call)
                 and isinstance(n.func, (ast.Attribute, ast.Name))}
        self.assertFalse(calls & {'fresh_start', 'refresh', 'publish', 'publish_renewal', 'lifetime_lock',
                                  'run', 'run_scope', 'factory', 'atomic', 'status'})
        self.assertTrue({'runtime', 'quiesce', 'verify_quiesced', 'custody'} <= calls)
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        body = next(n for n in main.body if isinstance(n, ast.Try)).body
        branch = next(n for n in body if isinstance(n, ast.If))
        self.assertEqual(ast.unparse(branch.test), 'args.quiesce_only')
        self.assertIsInstance(branch.body[0], ast.Return)

    def invoke(self, coordinator, configuration=None):
        config = configuration or Config()
        def forbidden(*args, **kwargs):
            raise AssertionError('ACTIVATION_OR_SERVICE_LIFETIME_FORBIDDEN')
        with ExitStack() as stack:
            stack.enter_context(patch.object(s, 'Configuration', return_value=config))
            stack.enter_context(patch.object(s, 'runtime', return_value=(coordinator, None, forbidden)))
            for name in ('atomic', 'lifetime_lock'):
                stack.enter_context(patch.object(s, name, side_effect=forbidden))
            stack.enter_context(patch.object(s.Service, 'run', side_effect=forbidden))
            stack.enter_context(patch.object(s.signal, 'signal', side_effect=forbidden))
            for name in ('fresh_start', 'refresh', 'publish', 'publish_renewal'):
                stack.enter_context(patch.object(coordinator, name, side_effect=forbidden, create=True))
            stderr = stack.enter_context(patch.object(sys, 'stderr', io.StringIO()))
            result = s.main(['--configuration', '/run/config', '--configuration-sha256', 'a'*64, '--quiesce-only'])
        return result, stderr.getvalue()

    def test_dynamic_one_revocation_no_activation_publication_or_lifetime_lock(self):
        coordinator = Coordinator()
        self.assertEqual(self.invoke(coordinator), (0, ''))
        self.assertEqual(coordinator.calls, ['quiesce'])
        self.assertEqual(coordinator.journal(), {'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False})
        self.assertFalse(any(coordinator.sets()))

    def test_failed_revocation_or_verification_returns_one_without_status(self):
        coordinator = Coordinator()
        def bad_quiesce():
            coordinator.calls.append('quiesce')
        coordinator.quiesce = bad_quiesce
        self.assertEqual(self.invoke(coordinator), (1, 'QUIESCENCE_UNPROVEN\n'))
        self.assertEqual(coordinator.calls, ['quiesce'])

    def test_custody_rechecked_after_revocation(self):
        config = Config(); config.error = s.Denied('CONFIGURATION_CUSTODY_CHANGED')
        coordinator = Coordinator()
        self.assertEqual(self.invoke(coordinator, config), (1, 'CONFIGURATION_CUSTODY_CHANGED\n'))
        self.assertEqual(coordinator.calls, ['quiesce'])


class SourceClosureTests(unittest.TestCase):
    def setUp(self):
        self.cfg = configuration()
        self.sources = source_fixture(self.cfg)
        self.path = "/run/fixture/configuration.json"
        self.files = {Path(self.cfg["sourceRoot"]) / p: raw for p, raw in self.sources.items()}
        self.bind_configuration()

    def bind_configuration(self):
        self.raw = s.canonical(self.cfg)
        self.files[Path(self.path)] = self.raw

    def read(self, path, expected, **kwargs):
        raw = self.files[Path(path)]
        s.require(s.sha(raw) == expected, "SUPERVISOR_BINDING_HASH_MISMATCH")
        return raw

    @contextmanager
    def boot_boundary(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(bootstrap, "private", side_effect=self.read))
            stack.enter_context(patch.object(bootstrap, "private_root"))
            stack.enter_context(patch.object(bootstrap, "__file__", self.cfg["sourceRoot"] + "/" + s.SELF))
            # POSIX custody is exercised by NativeClosure; retain lexical POSIX paths on Windows here.
            stack.enter_context(patch.object(Path, "absolute", lambda path: path))
            stack.enter_context(patch.object(bootstrap.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(bootstrap.os, "getegid", return_value=0, create=True))
            stack.enter_context(patch.object(bootstrap.sys, "flags", SimpleNamespace(isolated=1)))
            stack.enter_context(patch.object(bootstrap.sys, "dont_write_bytecode", True))
            yield

    def boot_args(self):
        return ["--configuration", self.path, "--configuration-sha256", s.sha(self.raw)]

    def test_quiesce_only_bootstrap_verifies_closure_and_forwards_exact_args(self):
        args = self.boot_args() + ['--quiesce-only']
        target = SimpleNamespace(main=lambda received: 0 if received == args else 7)
        with self.boot_boundary(), patch.object(bootstrap, 'execute', return_value=target) as execute:
            self.assertEqual(bootstrap.main(args), 0)
            self.assertEqual(execute.call_args.args, (Path(self.cfg['sourceRoot']), self.sources))
        relative = 'tools/semantic_provider_operation/epochs.py'
        self.files[Path(self.cfg['sourceRoot'])/relative] += b'\nchanged'
        with self.boot_boundary(), patch.object(bootstrap, 'execute') as execute, \
                patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(bootstrap.main(args), 1)
            execute.assert_not_called()

    def test_exact_source_set_and_fixed_recovery_pins(self):
        self.assertEqual(bootstrap.SOURCES, s.SOURCES)
        self.assertEqual(len(s.SOURCES), 15)
        changes = (
            (lambda cfg: cfg["sourceHashes"].pop(s.SELF), "EXACT_SUPERVISOR_SOURCE_SET_REQUIRED"),
            (lambda cfg: cfg["sourceHashes"].update({"extra.py": "a" * 64}), "EXACT_SUPERVISOR_SOURCE_SET_REQUIRED"),
            (lambda cfg: cfg["sourceHashes"].update({s.SELF: "A" * 64}), "EXACT_SUPERVISOR_SOURCE_SET_REQUIRED"),
            (lambda cfg: cfg["sourceHashes"].update({next(iter(s.RECOVERY_SOURCES)): "0" * 64}),
             "SUPERVISOR_RECOVERY_PIN_MISMATCH"),
            (lambda cfg: cfg.update(sourceRoot="relative"), "ABSOLUTE_SOURCE_ROOT_REQUIRED"),
            (lambda cfg: cfg.update(sourceRoot="/run/../source"), "ABSOLUTE_SOURCE_ROOT_REQUIRED"),
        )
        for change, code in changes:
            with self.subTest(code=code, change=change):
                cfg = copy.deepcopy(self.cfg)
                change(cfg)
                with self.assertRaisesRegex(s.Denied, code):
                    s.validate(s.canonical(cfg))

    def test_startup_rejects_each_tampered_source_before_any_exec(self):
        for relative in sorted(s.SOURCES):
            with self.subTest(relative=relative):
                path = Path(self.cfg["sourceRoot"]) / relative
                self.files[path] += b"\nraise RuntimeError('SENTINEL_PRIVATE_ADDRESS')\n"
                try:
                    stderr = io.StringIO()
                    with self.boot_boundary(), patch.object(bootstrap, "execute") as execute, \
                            patch.object(sys, "stderr", stderr):
                        self.assertEqual(bootstrap.main(self.boot_args()), 1)
                    execute.assert_not_called()
                    self.assertEqual(stderr.getvalue(), "SUPERVISOR_BINDING_HASH_MISMATCH\n")
                finally:
                    self.files[path] = self.sources[relative]

    def test_bootstrap_binds_configuration_and_own_path(self):
        with self.boot_boundary(), patch.object(bootstrap, "execute") as execute:
            root, verified = bootstrap.load_sources(self.path, s.sha(self.raw))
            self.assertEqual((root, verified), (Path(self.cfg["sourceRoot"]), self.sources))
            with self.assertRaisesRegex(s.Denied, "SUPERVISOR_BINDING_HASH_MISMATCH"):
                bootstrap.load_sources(self.path, "0" * 64)
            with patch.object(bootstrap, "__file__", "/run/fixture/elsewhere.py"):
                with self.assertRaisesRegex(RuntimeError, "SUPERVISOR_ENTRYPOINT_PATH_DRIFT"):
                    bootstrap.load_sources(self.path, s.sha(self.raw))
            execute.assert_not_called()

    def test_bootstrap_rejects_extra_or_missing_source_before_exec(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                hashes = dict(self.cfg["sourceHashes"])
                if missing:
                    self.cfg["sourceHashes"].pop(s.SELF)
                else:
                    self.cfg["sourceHashes"]["extra.py"] = "a" * 64
                self.bind_configuration()
                stderr = io.StringIO()
                with self.boot_boundary(), patch.object(bootstrap, "execute") as execute, \
                        patch.object(sys, "stderr", stderr):
                    self.assertEqual(bootstrap.main(self.boot_args()), 1)
                execute.assert_not_called()
                self.assertEqual(stderr.getvalue(), "EXACT_SUPERVISOR_SOURCE_SET_REQUIRED\n")
                self.cfg["sourceHashes"] = hashes

    def test_compiles_retained_bytes_and_registers_dependencies_in_order(self):
        verified = dict(self.sources)
        for relative in s.OPERATION_SOURCES:
            self.files[Path(self.cfg["sourceRoot"]) / relative] = b"raise RuntimeError('must not read again')"
        with patch.dict(sys.modules):
            module = bootstrap.execute(Path(self.cfg["sourceRoot"]), verified)
            self.assertIs(module.authorization, sys.modules["authorization"])
            self.assertIs(module.epochs, sys.modules["epochs"])
            self.assertIs(module.epochs.OperationDenied, module.authorization.OperationDenied)
            self.assertEqual(module.validate(self.raw), self.cfg)

    def test_next_guard_detects_each_changed_source(self):
        # All unrelated bindings remain valid; only one member of the closure changes.
        for item in [self.cfg["mandatesModule"], *[self.cfg["coordinator"][name]
                     for name in ("ownerConfiguration", "dnsProfile", "nftBinding")]]:
            item["sha256"] = s.sha(b"binding")
            self.files[Path(item["path"])] = b"binding"
        self.bind_configuration()
        cfg = s.Configuration(self.path, s.sha(self.raw), self.read, lambda path: None)
        guards = s.Guards(cfg, None, "9" * 64, Permanent)
        guards.custody_guard()
        for relative in sorted(s.SOURCES):
            with self.subTest(relative=relative):
                path = Path(self.cfg["sourceRoot"]) / relative
                self.files[path] += b"# changed\n"
                try:
                    with self.assertRaises(Permanent) as caught:
                        guards.custody_guard()
                    self.assertEqual(caught.exception.code, "CONFIGURATION_DRIFT")
                    self.assertEqual(guards.reason, "SUPERVISOR_BINDING_HASH_MISMATCH")
                finally:
                    self.files[path] = self.sources[relative]

    def test_runtime_compiles_recovery_from_verified_source_root(self):
        cfg = SimpleNamespace(value=self.cfg, custody=lambda: self.sources)
        with patch.object(s, "__file__", "/unrelated/not-the-source-root.py"), \
                patch.object(s, "compiled", side_effect=RuntimeError("STOP_AFTER_CORE")) as compiled:
            with self.assertRaisesRegex(RuntimeError, "STOP_AFTER_CORE"):
                s.runtime(cfg)
        relative = "tools/semantic_lease_recovery/activation_core.py"
        compiled.assert_called_once_with(self.sources[relative], Path(self.cfg["sourceRoot"]) / relative,
                                         "lease_activation_core_v2", s.PINS["activation_core"])
        self.cfg["sourceHashes"][relative] = "0" * 64
        with patch.object(s, "compiled") as compiled:
            with self.assertRaisesRegex(s.Denied, "SUPERVISOR_RECOVERY_PIN_MISMATCH"):
                s.runtime(cfg)
            compiled.assert_not_called()

    def test_no_source_search_path_mutation(self):
        for relative in (s.SELF, "tools/semantic_provider_operation/lease_supervisor.py"):
            self.assertNotIn("sys.path", (ROOT / relative).read_text(encoding="utf-8"), relative)


spec = importlib.util.spec_from_file_location("operation_scope_fixture", ROOT / "tests/test_semantic_provider_operation.py")
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


@unittest.skipUnless(NATIVE, "set OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE=1 under Linux root")
class NativeClosure(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-supervisor-closure-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = configuration()
        self.cfg["sourceRoot"] = str(self.root / "source")
        Path(self.cfg["sourceRoot"]).mkdir(mode=0o700)
        self.sources = source_fixture(self.cfg)
        for relative, raw in self.sources.items():
            path = Path(self.cfg["sourceRoot"]) / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.write(path, raw)
        for name in ("ownerConfiguration", "dnsProfile", "nftBinding"):
            path = self.root / name
            self.write(path, b"binding", 0o700 if name == "nftBinding" else 0o600)
            self.cfg["coordinator"][name] = {"path": str(path), "sha256": s.sha(b"binding")}
        path = self.root / "mandates.py"
        self.write(path, b"binding")
        self.cfg["mandatesModule"] = {"path": str(path), "sha256": s.sha(b"binding")}
        self.path = self.root / "configuration.json"
        self.bind_configuration()

    def write(self, path, raw, mode=0o600):
        Path(path).write_bytes(raw)
        Path(path).chmod(mode)

    def bind_configuration(self):
        self.raw = s.canonical(self.cfg)
        self.write(self.path, self.raw)

    def launch(self, entrypoint=None, digest=None):
        return subprocess.run([sys.executable, "-I", "-B", str(entrypoint or Path(self.cfg["sourceRoot"]) / s.SELF),
            "--configuration", str(self.path), "--configuration-sha256", digest or s.sha(self.raw)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def test_native_verified_bootstrap_and_next_guard_for_each_source(self):
        entrypoint = Path(self.cfg["sourceRoot"]) / s.SELF
        # Probe the bootstrap through its real private file reader, without starting a service.
        probe = ("import runpy,sys; b=runpy.run_path(sys.argv[1],run_name='probe'); "
                 "root,raw=b['load_sources'](sys.argv[2],sys.argv[3]); "
                 "m=b['execute'](root,raw); m.validate(open(sys.argv[2],'rb').read()); print('VERIFIED')")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(entrypoint),
            str(self.path), s.sha(self.raw)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"VERIFIED\n", b""))
        configuration_ = s.Configuration(self.path, s.sha(self.raw))
        guards = s.Guards(configuration_, None, "9" * 64, Permanent)
        guards.custody_guard()
        for relative in sorted(s.SOURCES):
            with self.subTest(relative=relative):
                path = Path(self.cfg["sourceRoot"]) / relative
                self.write(path, self.sources[relative] + b"\n# changed after startup\n")
                try:
                    with self.assertRaises(Permanent) as caught:
                        guards.custody_guard()
                    self.assertEqual(caught.exception.code, "CONFIGURATION_DRIFT")
                    self.assertEqual(guards.reason, "SUPERVISOR_BINDING_HASH_MISMATCH")
                    result = self.launch()
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (1, b"", b"SUPERVISOR_BINDING_HASH_MISMATCH\n"))
                finally:
                    self.write(path, self.sources[relative])

    def test_native_configuration_source_set_pins_and_entrypoint_path(self):
        result = self.launch(digest="0" * 64)
        self.assertEqual((result.returncode, result.stderr), (1, b"SUPERVISOR_BINDING_HASH_MISMATCH\n"))
        copied = self.root / "copied-entrypoint.py"
        self.write(copied, self.sources[s.SELF])
        result = self.launch(copied)
        self.assertEqual((result.returncode, result.stderr), (1, b"SUPERVISOR_ENTRYPOINT_PATH_DRIFT\n"))
        hashes = dict(self.cfg["sourceHashes"])
        for change, code in (
            (lambda h: h.pop(s.SELF), b"EXACT_SUPERVISOR_SOURCE_SET_REQUIRED\n"),
            (lambda h: h.update({"extra.py": "a" * 64}), b"EXACT_SUPERVISOR_SOURCE_SET_REQUIRED\n"),
        ):
            self.cfg["sourceHashes"] = dict(hashes)
            change(self.cfg["sourceHashes"])
            self.bind_configuration()
            result = self.launch()
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b"", code))
        # A recovery library replaced together with a matching configuration hash passes the
        # bootstrap's file check; only the reviewed PINS can stop it.
        relative = sorted(s.RECOVERY_SOURCES)[0]
        path = Path(self.cfg["sourceRoot"]) / relative
        tampered = self.sources[relative] + b"\n# tampered library\n"
        try:
            self.write(path, tampered)
            self.cfg["sourceHashes"] = {**hashes, relative: s.sha(tampered)}
            self.bind_configuration()
            result = self.launch()
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (1, b"", b"SUPERVISOR_RECOVERY_PIN_MISMATCH\n"))
        finally:
            self.write(path, self.sources[relative])
            self.cfg["sourceHashes"] = dict(hashes)
            self.bind_configuration()

    def test_native_source_custody_root_mode_links_and_ancestors(self):
        root = Path(self.cfg["sourceRoot"])
        path = root / "tools/semantic_provider_operation/authorization.py"
        configuration_ = s.Configuration(self.path, s.sha(self.raw))
        guards = s.Guards(configuration_, None, "9" * 64, Permanent)

        def denied(code):
            with self.assertRaises(Permanent) as caught:
                guards.custody_guard()
            self.assertEqual(caught.exception.code, "CONFIGURATION_DRIFT")
            result = self.launch()
            self.assertEqual((result.returncode, result.stderr), (1, code + b"\n"))

        root.chmod(0o755)
        denied(b"SUPERVISOR_PRIVATE_DIRECTORY_REQUIRED")
        root.chmod(0o700)
        path.chmod(0o644)
        denied(b"SUPERVISOR_FILE_CUSTODY_REQUIRED")
        path.chmod(0o600)
        hardlink = self.root / "hardlink.py"
        os.link(path, hardlink)
        denied(b"SUPERVISOR_FILE_CUSTODY_REQUIRED")
        hardlink.unlink()
        path.parent.chmod(0o777)
        denied(b"SUPERVISOR_ANCESTOR_CUSTODY_REQUIRED")
        path.parent.chmod(0o700)
        retained = self.root / "retained.py"
        path.rename(retained)
        path.symlink_to(retained)
        denied(b"LOCAL_STATE_UNPROVEN")
        path.unlink()
        retained.rename(path)
        guards.custody_guard()


class NativeScope(fixture_module.Fixture):
    __unittest_skip__ = not NATIVE  # independent gate; reuse the original ephemeral fixture
    __unittest_skip_why__ = "set OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE=1 under Linux root"
    journal = fixture_module.EpochTests.journal
    publish = fixture_module.EpochTests.publish

    def setUp(self):
        super().setUp()
        self.cfg = Config()
        self.cfg.value.update(anchorBinding=self.anchor, mandateRoot=str(self.ledger_root), opensslBinding=self.ssl,
                              authorizationRoot=str(self.chain), registryRoot=str(self.root / "registry"))
        self.first = self.put(1, self.payload())
        for cid in (fixture_module.CID_A, fixture_module.CID_S):
            self.publish(self.journal(cid=cid, bootId=self.e.boot_id(), authorizationSha256=fixture_module.sha(self.first)), cid)
        self.auth_patch = patch.object(s, "authorization", self.a)
        self.auth_patch.start()
        self.addCleanup(self.auth_patch.stop)
        self.g = s.Guards(self.cfg, self.m, "9" * 64, Permanent, head=self.a.head,
                          current=self.e.current, live=self.e.live, boot=self.e.boot_id, clock=self.clock)

    def denied_scope(self, category, detail):
        with self.assertRaises(Permanent) as caught:
            self.g.scope_guard()
        self.assertEqual(caught.exception.code, category)
        self.assertEqual(self.g.reason, detail)

    def test_real_head_live_epochs_change_and_old_boot(self):
        self.g.fixed = self.g.scope_guard()
        self.assertEqual(self.g.epochs, {"adapter": 1, "southbound": 1})
        cid = fixture_module.CID_A
        self.publish(self.journal(cid=cid, epoch=2, bootId=self.e.boot_id(),
                                 authorizationSha256=fixture_module.sha(self.first)), cid, 2)
        self.denied_scope("GENERATION_CHANGED", "EPOCH_SCOPE_CHANGED")
        self.g.fixed = None
        self.publish(self.journal(cid=cid, epoch=2, bootId=fixture_module.BOOT,
                                 authorizationSha256=fixture_module.sha(self.first)), cid, 2)
        self.denied_scope("GENERATION_CHANGED", "EPOCH_NOT_LIVE")

    def test_real_stop_and_revoked_signing_key(self):
        self.put(2, self.payload(2, fixture_module.sha(self.first), 1450, "STOP"))
        self.denied_scope("AUTHORITY_REVOKED", "OPERATION_STOP")
        self.append([{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900 + 60 * fixture_module.DAY,
                      "state": "REVOKED"}])
        self.now = 1600
        self.denied_scope("AUTHORITY_REVOKED", "OPERATION_KEY_REVOKED")

    def test_real_dead_generation_and_authorization_binding(self):
        cid = fixture_module.CID_S
        self.publish(self.journal(cid=cid, bootId=self.e.boot_id(), generation={"pid": os.getpid(),
                     "startTicks": self.e.start_ticks(os.getpid()) + 1},
                     authorizationSha256=fixture_module.sha(self.first)), cid)
        self.denied_scope("GENERATION_CHANGED", "EPOCH_NOT_LIVE")
        self.publish(self.journal(cid=cid, bootId=self.e.boot_id()), cid)
        self.denied_scope("AUTHORITY_REVOKED", "EPOCH_AUTHORIZATION_CHANGED")

    def test_configuration_custody_and_atomic_status(self):
        import stat
        cfg = configuration()
        cfg["statusPath"] = str(self.root / "supervisor-status.json")
        raw = s.canonical(cfg)
        path = self.root / "configuration.json"
        self.write(path, raw)
        self.assertEqual(s.Configuration(path, s.sha(raw)).value, cfg)
        with self.assertRaises(s.Denied):
            s.Configuration(path, "b" * 64)
        os.chmod(path, 0o644)
        with self.assertRaises(s.Denied):
            s.Configuration(path, s.sha(raw))
        value = {"schema": s.STATUS_SCHEMA, "state": "WAITING", "reason": "OPERATION_AUTHORIZATION_ABSENT",
                 "activationsLastHour": 0, "renewals": 0, "authorizationSequence": None,
                 "epochs": dict.fromkeys(s.ROLES), "updatedAt": 1500}
        s.atomic(cfg["statusPath"], value)
        first_inode = Path(cfg["statusPath"]).stat().st_ino
        s.atomic(cfg["statusPath"], {**value, "state": "STOPPED", "reason": None})
        self.assertEqual(stat.S_IMODE(Path(cfg["statusPath"]).stat().st_mode), 0o600)
        self.assertNotEqual(Path(cfg["statusPath"]).stat().st_ino, first_inode)
        self.assertEqual(json.loads(Path(cfg["statusPath"]).read_bytes())["state"], "STOPPED")
        self.assertFalse(list(self.root.glob(".lease-*")))

    def test_native_activation_history_and_worker_fencing(self):
        path = self.root / "supervisor-status.json"
        with s.lifetime_lock(path):
            with self.assertRaises(BlockingIOError):
                with s.lifetime_lock(path):
                    self.fail("second worker admitted")
            store = s.ActivationStore(path)
            for _ in range(6):
                store.reserve(self.now)
            self.assertEqual(s.ActivationStore(path).count(self.now), 6)
            with self.assertRaisesRegex(s.Denied, "ACTIVATION_RATE_LIMITED"):
                store.reserve(self.now)
        with s.lifetime_lock(path):
            restarted = s.ActivationStore(path)
            self.assertEqual(restarted.count(self.now + 3600), 0)
            restarted.reserve(self.now + 3600)
            self.assertEqual(s.ActivationStore(path).count(self.now + 3600), 1)


if __name__ == "__main__":
    unittest.main()
