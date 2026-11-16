"""Portable upgrade denials and gated /var/lib real-wrapper lifecycle fixture."""
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.semantic_provider_r3 import upgrade as U
import test_semantic_provider_r3_operate as F

I, A, C = U.I, U.A, U.C
NATIVE = os.environ.get("OUF_R3_UPGRADE_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_R3_UPGRADE_NATIVE requires Linux root:root; refusing to skip")


class PortableTests(unittest.TestCase):
    def test_arguments_and_public_errors(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(U.main(["--unknown", "PRIVATE_SENTINEL"]), 1)
        row = json.loads(output.getvalue())
        self.assertEqual(row["reason"], "INVALID_ARGUMENTS")
        self.assertFalse(row["doNotRerunApply"])
        self.assertEqual((row["privateKeysRead"], row["signaturesIssued"], row["containerLifecycleOperations"]), (0, 0, 0))
        self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(U.version_root(PurePosixPath("/install"), 1), PurePosixPath("/install"))
        self.assertEqual(U.version_root(PurePosixPath("/install"), 3), PurePosixPath("/install/versions/3"))

    @contextmanager
    def observation_fixture(self):
        inputs = F.F.F.issuance.fixtures.fixture()
        files, sources = inputs["files"], inputs["sources"]
        settings = C.document(files["settings"])
        root = PurePosixPath(settings["installRoot"])
        old = C.compose(inputs)
        composed = C.compose(inputs, 2, sequence=2, supersedes=A.sha(old["authorization"]))
        cfg = C.document(old["documents"]["runtime-configuration.json"])
        payload = A.validate(composed["authorization"])
        head = {"sequence": 2, "decision": "OPERATE", "sha256": A.sha(composed["authorization"]), "authorization": payload}
        old_sup = C.document(old["documents"]["supervisor/configuration.json"])
        args = SimpleNamespace(install_root=str(root), output_directory="/evidence", issued_at=settings["issuedAt"],
            table_name=[r+"="+settings["tableNames"][r] for r in A.ROLES],
            wrapper="/wrapper", current_wrapper_sha256=A.sha(I.wrapper_bytes(cfg["pythonPath"], root)),
            lock="/guard", systemctl="/systemctl", systemctl_sha256="a"*64, docker="/docker",
            docker_sha256="b"*64, docker_socket="unix:///docker.sock")
        with patch.object(I, "Path", PurePosixPath):
            unit = I.unit_bytes(root, cfg, old_sup)
        disk = {str(root/"authorization/1.json"): old["authorization"], str(root/"authorization/2.json"): composed["authorization"],
                str(I.UNIT_PATH): unit, "/wrapper": I.wrapper_bytes(cfg["pythonPath"], root)}
        identity = tuple(range(9))
        reader = SimpleNamespace(hashes={}, verify=lambda: None)
        runtime = SimpleNamespace(bound_bytes=lambda _: old["documents"]["supervisor/configuration.json"])
        with patch.object(I, "native_switch", return_value=SimpleNamespace(custody=lambda path, _: (disk[str(path)], identity))), \
                patch.object(U.V, "absolute", side_effect=PurePosixPath), patch.object(U.V, "private_directory"), \
                patch.object(I, "Path", PurePosixPath), patch.object(I, "output_directory"), \
                patch.object(U, "read_inputs", return_value=(reader, files, sources, settings)), \
                patch.object(I, "authorization", return_value=(None, head)), \
                patch.object(U, "installed_runtime", return_value=(runtime, cfg, old["documents"]["runtime-configuration.json"])), \
                patch.object(U, "stopped_provider", return_value={cid: {} for cid in cfg["candidates"]}), \
                patch.object(I, "coordinator_state", return_value={"state": "QUIESCED"}), \
                patch.object(U.V, "guard_lock", return_value={"identity": list(identity)}), \
                patch.object(I, "systemctl", return_value=("FragmentPath="+str(I.UNIT_PATH)+
                    "\nNeedDaemonReload=no\nDropInPaths=\nLoadState=loaded\n").encode()), \
                patch.object(U.os.path, "lexists", return_value=False) as exists:
            yield args, head, disk, root, exists, composed

    def test_readonly_plan_and_required_denials(self):
        with self.observation_fixture() as (args, head, disk, root, exists, composed):
            with patch.object(U.os, "open", side_effect=AssertionError("no writes")):
                state, result = U.observe(args)
            self.assertEqual((state["versionBefore"], state["versionAfter"]), (1, 2))
            self.assertEqual(result, composed)
            self.assertTrue(all(row["path"].startswith(str(root)+"/versions/") for row in state["writes"]["files"]))
            self.assertIn("/versions/2/source/", state["wrapperProposed"]["text"])
            self.assertIn(str(root)+"/supervisor/state", state["unit"]["text"])
            with patch.object(U, "stopped_provider", side_effect=A.OperationDenied(U.STOPPED)):
                with self.assertRaisesRegex(A.OperationDenied, U.STOPPED): U.observe(args)
            for name, code in (("/wrapper", "R3_WRAPPER_DRIFT"), (str(I.UNIT_PATH), "R3_UNIT_DRIFT")):
                previous = disk[name]; disk[name] += b"\n"
                with self.subTest(path=name), self.assertRaisesRegex(A.OperationDenied, code): U.observe(args)
                disk[name] = previous
            head["authorization"]["acceptanceSha256"] = "0"*64
            disk[str(root/"authorization/2.json")] = A.canonical(head["authorization"])
            head["sha256"] = A.sha(disk[str(root/"authorization/2.json")])
            with self.assertRaisesRegex(A.OperationDenied, "R3_AUTHORIZATION_PAYLOAD_MISMATCH"): U.observe(args)
            head["authorization"] = A.validate(composed["authorization"])
            disk[str(root/"authorization/2.json")] = composed["authorization"]
            head["sha256"] = A.sha(composed["authorization"])
            exists.side_effect = lambda path: str(path).endswith("/versions/2")
            with self.assertRaisesRegex(A.OperationDenied, "R3_UPGRADE_VERSION_ALREADY_EXISTS"): U.observe(args)

    def test_stopped_provider_denies_each_open_state_and_running_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); cid = "a"*64
            folder = root/cid/"epochs"; folder.mkdir(parents=True)
            cfg = {"registryRoot": str(root), "candidates": {cid: {}}}
            epoch_reader = SimpleNamespace(TERMINAL=F.O.TERMINAL, current=lambda *_: None)
            runtime = SimpleNamespace(operation_modules=lambda _: (None, epoch_reader))
            args = SimpleNamespace(docker="/docker", docker_sha256="b"*64, docker_socket="unix:///docker.sock")
            frame = {"State": {"Status": "exited", "Running": False, "Pid": 0}}
            with patch.object(U.V, "private_directory"), patch.object(I, "native_switch"), \
                    patch.object(U.V, "docker_inspect", return_value=frame) as docker:
                self.assertIsNone(U.stopped_provider(runtime, cfg, args)[cid]["current"])
                for state in ("OPENING", "PREPARING", "CREATING", "CREATED", "ADMITTED", "STARTING", "STARTED", "DELETING"):
                    epoch_reader.current = lambda *_, state=state: {"state": state}
                    docker.reset_mock()
                    with self.subTest(state=state), self.assertRaisesRegex(A.OperationDenied, U.STOPPED):
                        U.stopped_provider(runtime, cfg, args)
                    docker.assert_not_called()
                for terminal in F.O.TERMINAL:
                    epoch_reader.current = lambda *_, terminal=terminal: {"state": terminal}
                    self.assertEqual(U.stopped_provider(runtime, cfg, args)[cid]["current"]["state"], terminal)
                for status in ("running", "paused", "restarting", "removing"):
                    frame["State"].update(Status=status, Running=True, Pid=100)
                    with self.subTest(status=status), self.assertRaisesRegex(A.OperationDenied, U.STOPPED):
                        U.stopped_provider(runtime, cfg, args)

    def test_digest_denied_before_any_effect(self):
        with patch.object(I, "mkdir_once") as mkdir:
            with self.assertRaisesRegex(A.OperationDenied, "R3_PLAN_DIGEST_CHANGED"):
                U.apply(SimpleNamespace(plan_sha256="0"*64), {"planSha256": "1"*64}, {}, {})
            mkdir.assert_not_called()

    def test_versioned_loader_authenticates_before_compiling(self):
        S = SimpleNamespace(custody=lambda *_: (b"{}", ()))
        with patch.object(I, "native_switch", return_value=S), patch.object(U.V, "private_directory"), \
                patch.object(I, "compiled") as compile_source:
            with self.assertRaisesRegex(A.OperationDenied, "R3_INSTALLED_CONFIGURATION_DRIFT"):
                U.installed_runtime(PurePosixPath("/install"), PurePosixPath("/install"), {"runtimeConfigurationSha256": "0"*64})
            compile_source.assert_not_called()

    def test_apply_orders_publication_service_and_cas_without_container_mutations(self):
        with self.observation_fixture() as (args, head, disk, root, exists, composed):
            state, _ = U.observe(args)
            plan = I.digest_plan(state); args.plan_sha256 = plan["planSha256"]
            report = {"doNotRerunApply": False, **I.COUNTERS}
            calls = []
            def mkdir(path, progress):
                calls.append(("mkdir", str(path))); progress["doNotRerunApply"] = True
            def write(path, raw, progress):
                calls.append(("write", str(path))); disk[str(path)] = raw
                progress["doNotRerunApply"] = True
            def rename(source, target):
                calls.append(("rename", str(target))); disk[str(target)] = disk[str(source)]
            def switch(wrapper, expected, raw, output, lock, identity, verifier):
                calls.append(("cas", expected))
                verifier(99, "BEFORE_CLAIM"); verifier(99, "BEFORE_RENAME")
                disk[wrapper] = raw
                verifier(99, "AFTER_RENAME")
                return {"status": "WRAPPER_SWITCHED"}
            S = SimpleNamespace(custody=lambda p, _: (disk[str(p)], tuple(range(9))),
                                sync=lambda _: None, switch_existing_wrapper=switch)
            cfg = C.document(composed["documents"]["versions/2/runtime-configuration.json"])
            with patch.object(U, "Path", PurePosixPath), patch.object(I, "native_switch", return_value=S), \
                    patch.object(U, "observe", return_value=(state, composed)), \
                    patch.object(I, "operation_locks", return_value=nullcontext()), \
                    patch.object(I, "guard", side_effect=lambda *_: nullcontext(99)), \
                    patch.object(I, "mkdir_once", side_effect=mkdir), patch.object(I, "write_once", side_effect=write), \
                    patch.object(I, "verify_publication", side_effect=lambda *a, **kw: calls.append(("verify", kw)) or cfg), \
                    patch.object(I, "command", side_effect=lambda *a: calls.append(("smoke", a[0]))), \
                    patch.object(I, "systemctl", side_effect=lambda _, *a: calls.append(("systemctl", a))), \
                    patch.object(I, "service_readback", side_effect=lambda _, state, *a, **kw: calls.append(("service", state))), \
                    patch.object(U.os, "replace", side_effect=rename), \
                    patch.object(U.os, "fstat", return_value=SimpleNamespace(st_dev=0, st_ino=1)):
                U.apply(args, plan, composed, report)
            events = [c[0] for c in calls]
            stop = calls.index(("systemctl", ("stop", I.UNIT)))
            self.assertLess(events.index("verify"), events.index("smoke"))
            self.assertLess(events.index("smoke"), stop)
            self.assertLess(stop, events.index("rename"))
            self.assertLess(events.index("rename"), calls.index(("systemctl", ("daemon-reload",))))
            self.assertLess(calls.index(("systemctl", ("start", I.UNIT))), events.index("cas"))
            self.assertEqual(calls[-1], ("write", "/evidence/result.json"))
            self.assertEqual(report["status"], "SEMANTIC_PROVIDER_R3_UPGRADED_WAITING")
            self.assertTrue(report["doNotRerunApply"])
            self.assertEqual(report["containerLifecycleOperations"], 0)

    def test_native_program_compiles(self):
        compile(F.F.F.render(SYSTEMCTL, BASE="/var/lib/fixture"), "<systemctl-fixture>", "exec")

    def test_service_waiting_preserves_activation_history(self):
        properties = ("ActiveState=active\nSubState=running\nFragmentPath="+str(I.UNIT_PATH)+
                      "\nNeedDaemonReload=no\nDropInPaths=\nLoadState=loaded\n").encode()
        status = {"schema": "ouf.semantic-provider-lease-supervisor-status.v1", "state": "WAITING",
            "reason": "EPOCH_NOT_LIVE", "epochs": dict.fromkeys(A.ROLES), "renewals": 0,
            "authorizationSequence": 2, "activationsLastHour": 5}
        with patch.object(I, "systemctl", return_value=properties), patch.object(I.os.path, "lexists", return_value=True), \
                patch.object(I, "native_switch", return_value=SimpleNamespace(custody=lambda *_: (A.canonical(status), ()))):
            I.service_readback(None, "active", {"statusPath": "/status"}, 2, retained_history=True)

    def test_main_records_partial_effects_and_public_primitive_failure(self):
        args = SimpleNamespace(apply=True, plan=False, output_directory="/evidence")
        output = io.StringIO()
        def partial(_args, _plan, _composed, report):
            report.update(outputCreated=True, doNotRerunApply=True, phase="START_SUPERVISOR")
            raise OSError(5, "PRIVATE_SENTINEL")
        with patch.object(U, "arguments", return_value=args), patch.object(U.sys, "platform", "linux"), \
                patch.object(U.os, "geteuid", return_value=0, create=True), \
                patch.object(U.os, "getegid", return_value=0, create=True), patch.object(U.os, "umask"), \
                patch.object(U.sys, "flags", SimpleNamespace(isolated=True, dont_write_bytecode=True)), \
                patch.object(U.os.path, "lexists", return_value=False), \
                patch.object(U, "observe", return_value=({}, {})), patch.object(U, "apply", side_effect=partial), \
                patch.object(I, "write_once") as write, redirect_stdout(output):
            self.assertEqual(U.main([]), 1)
        row = json.loads(output.getvalue())
        self.assertEqual(row["status"], "HELD")
        self.assertTrue(row["doNotRerunApply"])
        self.assertEqual(row["errno"], 5)
        self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
        self.assertEqual(json.loads(write.call_args.args[1]), row)


# Explicit Engine/systemd/lease simulators inherited from tasks 41b/42. The
# runtime, broker, hooks, epoch writer, signatures and guarded switch are real.
SYSTEMCTL = F.SYSTEMCTL.replace(
    "assert args==['show','ouf-semantic-lease-supervisor-v2.service','--property=ActiveState','--property=SubState','--property=NRestarts']",
    "unit='ouf-semantic-lease-supervisor-v2.service'\n"
    "unitpath=pathlib.Path('/etc/systemd/system')/unit\n"
    "if args==['stop',unit]: (base/'unit-active').write_text('inactive'); raise SystemExit(0)\n"
    "if args==['daemon-reload']: raise SystemExit(0)\n"
    "if args==['start',unit]: (base/'unit-active').write_text('active')\n"
    "elif not (args[:2]==['show',unit]): raise SystemExit(2)"
).replace(
    "install=base/'install'; cfg=json.loads((install/'runtime-configuration.json').read_bytes())\nsup=json.loads((install/'supervisor/configuration.json').read_bytes())",
    "import shlex\ninstall=base/'install'\n"
    "command=shlex.split(next(s for s in unitpath.read_text().splitlines() if s.startswith('ExecStart=')).split('=',1)[1])\n"
    "sup=json.loads(pathlib.Path(command[command.index('--configuration')+1]).read_bytes())\n"
    "cfg=json.loads((pathlib.Path(sup['sourceRoot']).parent/'runtime-configuration.json').read_bytes())\n"
    "sequence=len(list((install/'authorization').glob('*.signature.json')))"
).replace("'authorizationSequence':1", "'authorizationSequence':sequence").replace(
    "print('ActiveState=active\\nSubState=running\\nNRestarts=0')",
    "active=(base/'unit-active').read_text()\n"
    "if '--property=NRestarts' in args: print('ActiveState='+active+'\\nSubState=running\\nNRestarts=0')\n"
    "else: print('ActiveState='+active+'\\nSubState='+('running' if active=='active' else 'dead')+"
    "'\\nFragmentPath='+str(unitpath)+'\\nNeedDaemonReload=no\\nDropInPaths=\\nLoadState=loaded')"
)


class UpgradeFixture(F.OperateFixture):
    __unittest_skip__ = False

    def upgrade_args(self, mode="--plan", digest=None):
        args = self.install_args(mode, digest)
        for field in ("--v51-root", "--acceptance-signature", "--acceptance-signature-sha256"):
            index = args.index(field); del args[index:index+2]
        args[args.index("--current-wrapper-sha256")+1] = A.sha(self.wrapper.read_bytes())
        args[args.index("--output-directory")+1] = str(self.root/"upgraded")
        return args

    def upgrade_cli(self, args, code=0):
        result = subprocess.run([str(self.python), "-I", "-B", str(I.ROOT/"scripts/upgrade-semantic-provider-r3.py"),
                                 *args], capture_output=True, timeout=250)
        self.assertEqual(result.returncode, code, result.stdout.decode()+result.stderr.decode()+self.diagnostic())
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def supersede(self, refresh=True):
        # Current quiesced journal is an explicit input; never rewind it to the
        # initial journal. Only public composition input bindings are refreshed.
        owner = C.document(self.inputs["files"]["coordinator"])
        if refresh:
            self.inputs["files"]["coordinationJournal"] = Path(owner["journalFile"]).read_bytes()
        self.publish_inputs()
        self.output = self.root/"issued-next"
        plan = self.issuer_cli([*self.argv(), "--supersede"])
        result = self.issuer_cli([*self.argv("--apply", plan["planSha256"]), "--supersede"])
        self.assertEqual(result["sequence"], 2)
        return result

    def action(self, action, suffix=""):
        # Task-42 argument builder reads only nft from the retained root config;
        # it remains the same coordinator after an upgrade.
        args = self.operate_args(action)
        args[args.index("--output-directory")+1] += suffix
        plan = self.operate_cli(args)
        args[0] = "--apply"
        return self.operate_cli([*args, "--plan-sha256", plan["planSha256"]])

    def scenario_upgrade_lifecycle(self):
        self.assertTrue(str(self.root).startswith("/var/lib/"))
        self.installed()
        self.docker = self.script("docker", F.DOCKER)
        self.systemctl = self.script("systemctl-upgrade", SYSTEMCTL)
        self.assertEqual(self.action("start")["status"], F.O.SUCCESS["start"])
        self.action("stop")
        old_rows = {r: self.row(r) for r in C.ROLES}
        old_history = {str(p.relative_to(self.registry)): p.read_bytes() for p in self.registry.rglob("*") if p.is_file()}
        first_pair = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        issued = self.supersede()
        old_closure = {str(p.relative_to(self.install)): p.read_bytes() for name in ("source", "broker", "documents")
                       for p in (self.install/name).rglob("*") if p.is_file()}
        plan = self.upgrade_cli(self.upgrade_args())
        self.assertEqual(plan, self.upgrade_cli(self.upgrade_args()))
        before_calls = (self.root/"docker.jsonl").read_bytes()
        result = self.upgrade_cli(self.upgrade_args("--apply", plan["planSha256"]))
        self.assertEqual(result["status"], "SEMANTIC_PROVIDER_R3_UPGRADED_WAITING")
        self.assertEqual((result["versionBefore"], result["versionAfter"]), (1, 2))
        self.assertEqual(json.loads((self.root/"upgraded/result.json").read_bytes()), result)
        self.assertEqual({str(p.relative_to(self.registry)): p.read_bytes() for p in self.registry.rglob("*") if p.is_file()}, old_history)
        for name, raw in first_pair.items(): self.assertEqual((self.chain/name).read_bytes(), raw)
        for name, raw in old_closure.items(): self.assertEqual((self.install/name).read_bytes(), raw)
        calls = (self.root/"docker.jsonl").read_bytes()[len(before_calls):].splitlines()
        self.assertTrue(all(json.loads(line)[2] == "inspect" for line in calls))
        self.assertEqual((result["privateKeysRead"], result["signaturesIssued"], result["containerLifecycleOperations"]), (0, 0, 0))
        started = self.action("start", "-v2")
        self.assertEqual(started["status"], F.O.SUCCESS["start"])
        self.assertEqual(started["lastObservation"]["authorization"]["sequence"], 2)
        for role in C.ROLES:
            self.assertEqual((self.row(role)["state"], self.row(role)["epoch"]), ("STARTED", old_rows[role]["epoch"]+1))
            self.assertEqual(self.row(role)["authorizationSha256"], issued["payloadSha256"])
        self.assertEqual(self.action("restart-one", "-v2")["status"], F.O.SUCCESS["restart-one"])
        self.assertEqual(self.row()["epoch"], old_rows["adapter"]["epoch"]+2)
        self.action("stop", "-v2")

    def scenario_open_epoch_denied(self):
        self.installed()
        self.docker = self.script("docker", F.DOCKER)
        self.systemctl = self.script("systemctl-upgrade", SYSTEMCTL)
        self.action("start")
        # Negative fixture only: issuing N+1 does not close the live epoch.
        self.supersede(refresh=False)
        held = self.upgrade_cli(self.upgrade_args(), code=1)
        self.assertEqual(held["reason"], U.STOPPED)
        self.assertFalse(held["doNotRerunApply"])
        self.assertFalse((self.install/"versions").exists())


@unittest.skipUnless(NATIVE, "set OUF_R3_UPGRADE_NATIVE=1 under Linux root:root")
class NativeTests(unittest.TestCase):
    def run_scenario(self, name):
        for command in ("unshare", "mount", "umount", "ip", "openssl"):
            self.assertIsNotNone(shutil.which(command), "native prerequisite: "+command)
        result = subprocess.run([shutil.which("unshare"), "--mount", "--net", "--fork", sys.executable,
            "-I", "-B", str(Path(__file__).resolve()), "--native-child", name], capture_output=True, timeout=1000)
        for line in result.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith("FIXTURE_EXEC_DIAGNOSTIC="): print(line, file=sys.stderr)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())

    def test_upgrade_lifecycle(self): self.run_scenario("scenario_upgrade_lifecycle")
    def test_open_epoch_denied(self): self.run_scenario("scenario_open_epoch_denied")


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([loader.loadTestsFromTestCase(PortableTests), loader.loadTestsFromTestCase(NativeTests)])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--native-child":
        if not NATIVE or sys.argv[2] not in {"scenario_upgrade_lifecycle", "scenario_open_epoch_denied"}:
            raise RuntimeError("unknown/disabled native scenario")
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([UpgradeFixture(sys.argv[2])]))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
