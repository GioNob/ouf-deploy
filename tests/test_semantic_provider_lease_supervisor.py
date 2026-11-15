"""R3: real recovery loop with in-memory native boundaries; root-only scope fixture."""
import copy
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
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

NATIVE = os.environ.get("OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE requires Linux root:root")


def configuration():
    bind = lambda name, digest="a": {"path": "/run/fixture/" + name, "sha256": digest * 64}
    return {"schema": s.SCHEMA, "installationRef": "inst", "entityRef": "ent", "issuerRef": "installer",
            "authorizationRoot": "/run/fixture/operation", "anchorBinding": bind("anchor"),
            "mandateRoot": "/run/fixture/ledger", "opensslBinding": {**bind("openssl"), "version": "3.0.0"},
            "mandatesModule": bind("mandates.py"), "registryRoot": "/run/fixture/registry",
            "coordinator": {"ownerConfiguration": bind("owner", "8"), "journalPath": "/run/fixture/journal",
                            "commonLockPath": "/run/fixture/common.lock", "dnsProfile": bind("dns", "0"),
                            "nftBinding": bind("nft")},
            "recoveryJournalRoot": "/run/fixture/recoveries", "statusPath": "/run/fixture/status",
            "limits": {"maxActivationsPerHour": 6, "heartbeatSeconds": 1, "pollSeconds": 15}}


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
        raw = s.canonical(configuration())
        calls = []
        def reader(path, expected, **kw):
            calls.append((path, expected, kw))
            return raw
        c = s.Configuration("/run/fixture/config", s.sha(raw), reader)
        c.custody()
        self.assertEqual([v[0] for v in calls[1:]], ["/run/fixture/config", "/run/fixture/owner",
                         "/run/fixture/dns", "/run/fixture/nft", "/run/fixture/mandates.py"])
        self.assertTrue(calls[-2][2]["executable"])

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


spec = importlib.util.spec_from_file_location("operation_scope_fixture", ROOT / "tests/test_semantic_provider_operation.py")
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


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
