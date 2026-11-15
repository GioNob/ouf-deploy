"""Portable sealed-loader fakes plus optional reuse of the real operate fixture."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools import operational_signals as S
from tools.operational_signals import r3_health as H
import test_semantic_provider_r3_operate as F

NATIVE = os.environ.get("OUF_R3_HEALTH_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_R3_HEALTH_NATIVE requires Linux root:root")


def assert_schema(test, value):
    test.assertEqual(set(value), {"schema", "checkedAt", "head", "supervisor", "lease", "roles", "readError"})
    test.assertEqual(value["schema"], H.SCHEMA)
    test.assertIs(type(value["checkedAt"]), int)
    test.assertEqual(set(value["head"]), {"decision", "sequence"})
    test.assertIn(value["head"]["decision"], {"OPERATE", "STOP", "UNPROVEN"})
    test.assertEqual(set(value["supervisor"]), {"unitActive", "state", "reason", "updatedAt", "activationsLastHour"})
    test.assertIs(type(value["supervisor"]["unitActive"]), bool)
    test.assertIn(value["supervisor"]["state"], H.STATES | {None})
    test.assertEqual(set(value["lease"]), {"state", "leaseAuthorized"})
    test.assertIn(value["lease"]["leaseAuthorized"], (True, False, None))
    test.assertEqual(set(value["roles"]), set(H.O.ROLES))
    for row in value["roles"].values():
        test.assertEqual(set(row), {"epoch", "state", "failure", "live", "previousState", "dockerRunning", "denials"})
        test.assertIs(type(row["live"]), bool)
        test.assertIn(row["dockerRunning"], (True, False, None))
        test.assertLessEqual(len(row["denials"]), 4)
        for d in row["denials"]:
            test.assertEqual(set(d), {"mode", "reason", "at"})
            test.assertIs(type(d["mode"]), str)
            test.assertIs(type(d["at"]), int)
            test.assertRegex(d["reason"], r"\A[A-Z0-9_]{1,80}\Z")
        for field in ("state", "failure", "previousState"):
            if row[field] is not None:
                test.assertRegex(row[field], r"\A[A-Z0-9_]{1,80}\Z")
        for field in ("epoch",):
            if row[field] is not None:
                test.assertIs(type(row[field]), int)
    for code in (value["readError"], value["supervisor"]["reason"], value["lease"]["state"]):
        if code is not None:
            test.assertRegex(code, r"\A[A-Z0-9_]{1,80}\Z")
    for number in (value["head"]["sequence"], value["supervisor"]["updatedAt"], value["supervisor"]["activationsLastHour"]):
        if number is not None:
            test.assertIs(type(number), int)
    raw = S.M.canonical(value)
    test.assertLessEqual(len(raw), 16384)
    for secret in (b'"cohort":', b"192.0.2.10", b"02:00:00:00:00:01", b"1"*64, b"2"*64, b"PRIVATE"):
        test.assertNotIn(secret, raw)


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "install"
        self.root.mkdir()
        self.args = F.arguments(install_root=str(self.root), wrapper_sha256=H.O.sha(b"wrapper"))
        self.args.status_path = str(self.root.parent / "status.json")
        self.ids = {r: str(n+1)*64 for n, r in enumerate(H.O.ROLES)}
        self.cfg = {"registryRoot": str(self.root / "registry"), "pythonPath": "/python",
            "operation": {"authorizationRoot": str(self.root / "authorization"),
                "mandatesModule": {"path": "mandates", "sha256": "0"*64}, "anchorBinding": {},
                "mandateRoot": "mandates", "installationRef": "installation", "entityRef": "entity", "issuerRef": "issuer"},
            "opensslBinding": {}, "candidates": {cid: {"role": role} for role, cid in self.ids.items()},
            "admissionConfigurations": {cid: {"sha256": "a"*64} for cid in self.ids.values()},
            "leaseQuiesce": {"configuration": {}}}
        self.head = {"decision": "OPERATE", "sequence": 1, "sha256": "e"*64,
            "authorization": {"runtimeConfigurationSha256": H.O.sha(b"cfg"),
                "roles": {r: {"containerId": cid, "admissionConfigurationSha256": "a"*64} for r, cid in self.ids.items()}}}
        self.row = {"epoch": 1, "state": "STARTED", "failure": None, "bootId": "boot", "generation": {"pid": 42},
            "authorizationSha256": "e"*64, "configurationHash": H.O.sha(b"cfg")}
        self.status = {"schema": "ouf.semantic-provider-lease-supervisor-status.v1", "state": "ACTIVE", "reason": None,
            "epochs": dict.fromkeys(H.O.ROLES, 1), "activationsLastHour": 1, "authorizationSequence": 1, "updatedAt": 1500}
        self.lease = {"state": "LEASE_READY", "leaseAuthorized": True}
        self.unit = b"ActiveState=active\nSubState=running\nNRestarts=0\n"
        self.sup = {"registryRoot": self.cfg["registryRoot"], "authorizationRoot": self.cfg["operation"]["authorizationRoot"],
            "statusPath": str(self.root / "status"), "coordinator": {"journalPath": str(self.root / "journal"),
                "commonLockPath": str(self.root / "common.lock")}}
        self.epochs = SimpleNamespace(boot_id=lambda: "boot", current=lambda *_: copy.deepcopy(self.row),
            live=lambda row, boot: row["state"] == "STARTED", validate_journal=lambda raw, *_: json.loads(raw))
        auth = SimpleNamespace(head=lambda *_: copy.deepcopy(self.head))
        self.runtime = SimpleNamespace(load_configuration=lambda _: (self.cfg, b"cfg"), verify_files=lambda _: None,
            operation_modules=lambda _: (auth, self.epochs), compiled=lambda *_: S.M,
            bound_bytes=lambda _: H.O.canonical(self.sup), read=lambda path: path.read_bytes())
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def mock(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        mock(H.I, "native_switch", return_value=SimpleNamespace(custody=self.custody))
        mock(H.V, "absolute", side_effect=Path)
        mock(H.V, "private_directory")
        self.compile = mock(H.I, "compiled", return_value=self.runtime)
        mock(H.I, "wrapper_code_root", return_value=self.root)
        mock(H.I, "wrapper_bytes", return_value=b"wrapper")
        self.docker = mock(H, "docker", side_effect=self.inspect)
        self.command = mock(H, "command", side_effect=lambda *_: self.unit)
        mock(H.O, "command", side_effect=AssertionError("temporary output file forbidden"))
        mock(H.O, "docker", side_effect=AssertionError("temporary output file forbidden"))
        # Fail immediately if a future implementation tries any mutation/lock/nft path.
        mock(H.I, "operation_locks", side_effect=AssertionError("lock forbidden"))
        mock(H.V, "guard_lock", side_effect=AssertionError("lock forbidden"))
        mock(H.O, "apply", side_effect=AssertionError("mutation forbidden"))

    def custody(self, path, mode):
        if str(path) == self.args.wrapper or Path(path).as_posix().endswith(H.C.RUNTIME):
            return b"wrapper", ()
        path = Path(path)
        return path.read_bytes(), S.M.attributes(path.stat())

    def publish(self):
        (self.root / "status").write_bytes(H.O.canonical(self.status))
        (self.root / "journal").write_bytes(H.O.canonical(self.lease))
        for cid in self.ids.values():
            base = self.root / "registry" / cid
            folder = base / "epochs" / str(self.row["epoch"])
            folder.mkdir(parents=True, exist_ok=True)
            raw = H.O.canonical(self.row)
            (folder / "adapter.json").write_bytes(raw)
            (base / "current").write_bytes(H.O.canonical({"epoch": self.row["epoch"], "journalSha256": H.O.sha(raw)}))

    def inspect(self, args, verb, cid):
        self.assertEqual(verb, "inspect")
        return H.O.canonical([{"Id": cid, "State": {"Status": "running", "Running": True, "Pid": 42,
            "StartedAt": "2026-11-15T00:00:00Z"}, "RestartCount": 0,
            "HostConfig": {"Runtime": "ouf-semantic-admitted-v2", "RestartPolicy": {"Name": "no"}}, "private": "PRIVATE"}])

    def health(self):
        self.publish()
        result = H.collect(self.args)
        assert_schema(self, result)
        return result

    def test_active_and_waiting(self):
        result = self.health()
        self.assertIsNone(result["readError"])
        self.assertEqual(result["lease"], self.lease)
        self.assertEqual(result["supervisor"]["state"], "ACTIVE")
        self.assertTrue(all(call.args[0] == self.args.systemctl and call.args[2][0] == "show"
                            for call in self.command.call_args_list))
        self.assertEqual(self.compile.call_args.args[3], H.O.sha((H.I.ROOT / H.C.RUNTIME).read_bytes()))
        self.status.update(state="WAITING", reason="EPOCH_NOT_LIVE")
        self.row["state"] = "CREATED"
        result = self.health()
        self.assertFalse(result["roles"]["adapter"]["live"])
        self.assertEqual(result["supervisor"]["reason"], "EPOCH_NOT_LIVE")

    def test_failed_epoch_current_denial_only_and_previous(self):
        self.row.update(epoch=2, state="FAILED", failure="PEER_MAC_IP_DRIFT")
        self.publish()
        for cid in self.ids.values():
            previous = self.root / "registry" / cid / "epochs/1"
            previous.mkdir()
            (previous / "adapter.json").write_bytes(H.O.canonical({**self.row, "epoch": 1, "state": "DELETED"}))
            cohort = {"peers": [{"containerId": "3"*64, "lastReason": None, "attempts": 1, "runc": None,
                "networkBindings": [{"interface": "eth0", "bridge": "br0", "ipv4": "192.0.2.10", "mac": "02:00:00:00:00:01"}]}]}
            for epoch in (1, 2):
                for mode in H.C.B.MODES:
                    row = dict(schema=H.C.B.DENIAL_SCHEMA, containerId=cid, epoch=epoch, mode=mode,
                               reason="PEER_MAC_IP_DRIFT" if epoch == 2 else "OLD_DENIAL", at=1500, cohort=cohort)
                    (previous.parent / str(epoch) / ("broker-denial-"+mode+".json")).write_bytes(H.O.canonical(row))
            (previous.parent / "2/broker-denial-invalid.json").write_bytes(b"PRIVATE")
        with patch.object(H.O, "terminal_binding") as terminal:
            result = H.collect(self.args)
        assert_schema(self, result)
        self.assertIsNone(result["readError"])
        self.assertEqual(terminal.call_count, 4)
        for row in result["roles"].values():
            self.assertEqual(row["previousState"], "DELETED")
            self.assertEqual(row["failure"], "PEER_MAC_IP_DRIFT")
            self.assertEqual(len(row["denials"]), min(4, len(H.C.B.MODES)))
            self.assertTrue(all(d["reason"] == "PEER_MAC_IP_DRIFT" for d in row["denials"]))

    def test_stop_authentication_failure_supervisor_failed_and_inactive(self):
        self.head.update(decision="STOP", sequence=2)
        with patch.object(H, "historical_binding") as binding:
            result = self.health()
        self.assertEqual(result["head"], {"decision": "STOP", "sequence": 2})
        self.assertEqual(binding.call_count, 2)
        with patch.object(H, "authorization", side_effect=H.O.A.OperationDenied("OPERATION_SIGNATURE_INVALID")):
            result = self.health()
        self.assertEqual(result["head"], {"decision": "UNPROVEN", "sequence": None})
        self.assertEqual(result["readError"], "OPERATION_SIGNATURE_INVALID")
        self.head["decision"] = "OPERATE"
        self.status.update(state="FAILED", reason="LEASE_ACTIVATION_FAILED")
        self.unit = b"ActiveState=inactive\nSubState=dead\nNRestarts=0\n"
        result = self.health()
        self.assertEqual(result["supervisor"]["state"], "FAILED")
        self.assertFalse(result["supervisor"]["unitActive"])

    def test_retry_once_then_read_error_and_recovery(self):
        self.publish()
        for errors in ([S.SignalError("EPOCH_POINTER_JOURNAL_DRIFT")]*2,
                       [S.SignalError("R3_SNAPSHOT_CHANGED"), None]):
            original = H.observe
            count = []
            def observe(args, result):
                error = errors[len(count)]
                count.append(1)
                if error: raise error
                original(args, result)
            with patch.object(H, "observe", side_effect=observe):
                result = H.collect(self.args)
            self.assertEqual(len(count), 2)
            assert_schema(self, result)
            self.assertEqual(result["readError"], "EPOCH_POINTER_JOURNAL_DRIFT" if errors[-1] else None)

    def test_snapshot_detects_actual_replacement(self):
        self.publish()
        snapshot = H.Snapshot(self.custody)
        path = self.root / "journal"
        snapshot.read(path)
        other = self.root / "replacement"
        other.write_bytes(path.read_bytes())
        os.replace(other, path)
        with self.assertRaisesRegex(S.SignalError, "R3_SNAPSHOT_CHANGED"):
            snapshot.verify()

    def test_arguments_require_bindings_and_reject_actions_and_output(self):
        args = []
        for name in ("install_root", "wrapper", "wrapper_sha256", "docker", "docker_sha256", "docker_socket",
                     "systemctl", "systemctl_sha256", "nft", "nft_sha256", "status_path"):
            args += ["--"+name.replace("_", "-"), getattr(self.args, name)]
        self.assertEqual(H.arguments(args).status_path, self.args.status_path)
        for extra in (["--action", "start"], ["--output-directory", "output"], ["--timeout-seconds", "0"],
                      ["--docker-sha256", "INVALID"], ["--docker-socket", "tcp://example"]):
            with self.assertRaises((S.SignalError, H.O.A.OperationDenied)):
                H.arguments(args+extra)

    def test_source_hash_and_wrapper_drift_fail_closed(self):
        self.args.wrapper_sha256 = "0"*64
        self.assertEqual(self.health()["readError"], "R3_WRAPPER_DRIFT")
        self.compile.assert_not_called()
        self.args.wrapper_sha256 = H.O.sha(b"wrapper")
        self.compile.side_effect = H.O.A.OperationDenied("R3_SOURCE_HASH_DRIFT")
        self.assertEqual(self.health()["readError"], "R3_SOURCE_HASH_DRIFT")
        self.docker.assert_not_called()

    def test_held_common_and_operation_locks_do_not_block(self):
        self.publish()
        with ExitStack() as locks:
            paths = [Path(self.sup["coordinator"]["commonLockPath"])]
            paths += [self.root / "registry" / cid / "operation.lock" for cid in self.ids.values()]
            for path in paths:
                stream = locks.enter_context(open(path, "w+b"))
                stream.write(b"0"); stream.flush(); stream.seek(0)
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            result = H.collect(self.args)
            self.assertLess(time.monotonic() - started, 3)
            self.assertIsNone(result["readError"])

    def test_exit_zero_on_read_error_nonzero_only_on_write_failure_no_details(self):
        for fail_write in (False, True):
            with patch.object(H, "arguments", return_value=self.args), \
                    patch.object(H, "collect", return_value={**H.empty(), "readError": "PUBLIC_READ_FAILED"}), \
                    patch.object(H, "atomic_status", side_effect=OSError("PRIVATE") if fail_write else None) as write, \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(H.main(["--status-path", self.args.status_path]), int(fail_write))
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertRegex(output.getvalue(), r"\AR3_HEALTH_STATUS_[A-Z_]+\n\Z")
            self.assertEqual(write.call_count, 1)


class AtomicTests(unittest.TestCase):
    def test_memory_only_authentication_transport_retains_verification(self):
        proxy = H.readonly_mandates(S.M)
        verifier = object.__new__(proxy.MandateAuthenticator)
        verifier.openssl_binding = {"version": "3.0.0"}
        verifier.budget = SimpleNamespace(check=lambda: None)
        with patch.object(verifier, "executable", return_value="/openssl") as executable, \
                patch.object(verifier, "timeout", return_value=2), \
                patch.object(H, "capture", return_value=b"OpenSSL 3.0.0 fixture\n"), \
                patch.object(H, "memory_file", side_effect=[101, 102, 103]) as memory, \
                patch.object(H.os, "close") as close, \
                patch.object(H.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            verifier.verify(b"public-frame", b"public-key", b"signature")
        self.assertEqual([c.args[0] for c in memory.call_args_list], [S.M.DER_PREFIX+b"public-key", b"signature", b"public-frame"])
        self.assertEqual(run.call_args.kwargs["pass_fds"], (101, 102, 103))
        self.assertIn("/proc/self/fd/103", run.call_args.args[0])
        self.assertEqual([c.args[0] for c in close.call_args_list], [101, 102, 103])
        self.assertEqual(executable.call_count, 2)
        self.assertIs(proxy.MandateLedger, S.M.MandateLedger)
        self.assertIsNot(proxy.MandateAuthenticator, S.M.MandateAuthenticator)
        with patch.object(verifier, "executable", return_value="/openssl"), \
                patch.object(verifier, "timeout", return_value=2), \
                patch.object(H, "capture", return_value=b"OpenSSL 3.0.0 fixture\n"), \
                patch.object(H, "memory_file", side_effect=[101, 102, 103]), \
                patch.object(H.os, "close") as close, \
                patch.object(H.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(S.M.MandateDenied, "DETACHED_SIGNATURE_INVALID"):
                verifier.verify(b"public-frame", b"public-key", b"bad-signature")
        self.assertEqual(close.call_count, 3)

    def test_readonly_command_hash_socket_environment_and_no_tempfiles(self):
        with patch.object(H.V, "executable_hash", return_value="/binary") as verify, \
                patch.object(H.subprocess, "run", return_value=SimpleNamespace(stdout=b"{}", returncode=0)) as run:
            args = F.arguments()
            self.assertEqual(H.docker(args, "inspect", "1"*64), b"{}")
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(run.call_args.args[0], ["/binary", "--host", args.docker_socket, "inspect", "1"*64])
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(run.call_args.kwargs["env"], H.I.ENV)
        with self.assertRaisesRegex(S.SignalError, "INSPECT_ONLY"):
            H.docker(args, "start", "1"*64)

    def test_atomic_order_canonical_and_failure_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            path = Path(folder) / "status.json"
            stack.enter_context(patch.object(S, "status_directory", side_effect=Path))
            seal = stack.enter_context(patch.object(S, "seal_status"))
            directory = stack.enter_context(patch.object(S, "sync_directory", side_effect=lambda _: events.append("directory-fsync")))
            real_replace = os.replace
            events = []
            def replace(src, dst):
                events.append("rename")
                self.assertEqual(Path(src).read_bytes(), b'{"a":"\\u00e8","z":1}')
                real_replace(src, dst)
            with patch.object(S.os, "fsync", side_effect=lambda _: events.append("fsync")), \
                    patch.object(S.os, "replace", side_effect=replace):
                S.atomic_status(path, {"z": 1, "a": "è"})
            self.assertEqual(events, ["fsync", "rename", "directory-fsync"])
            seal.assert_called_once()
            directory.assert_called_once_with(path.parent)
            old = path.read_bytes()
            with patch.object(S.os, "replace", side_effect=OSError("PRIVATE")):
                with self.assertRaises(OSError): S.atomic_status(path, {})
            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(list(path.parent.iterdir()), [path])
            with self.assertRaisesRegex(S.SignalError, "TOO_LARGE"):
                S.atomic_status(path, {"large": "x"*16384})

    def test_service_contracts(self):
        root = H.I.ROOT
        for name, directory in (("ouf-semantic-provider-r3-health", "ouf-semantic-provider-health"),
                                ("ouf-trust-window-status", "ouf-trust-windows")):
            service = (root / "ops/systemd" / (name+".service")).read_text()
            for field in ("User=root", "Group=root", "Type=oneshot", "ProtectSystem=strict", "PrivateTmp=yes", "NoNewPrivileges=yes",
                          "ReadWritePaths=/var/lib/"+directory):
                self.assertIn(field, service)
            self.assertEqual(service.count("ReadWritePaths="), 1)
        self.assertIn("OnUnitActiveSec=5min", (root / "ops/systemd/ouf-semantic-provider-r3-health.timer").read_text())
        self.assertIn("OnCalendar=daily", (root / "ops/systemd/ouf-trust-window-status.timer").read_text())


class HealthFixture(F.OperateFixture):
    def scenario_health(self):
        self.installed()
        self.docker = self.script("docker", F.DOCKER)
        self.systemctl = self.script("systemctl", F.SYSTEMCTL)
        status = self.root / "health/status.json"
        status.parent.mkdir(mode=0o700)
        for action in ("start", "stop"):
            plan = self.operate_cli(self.operate_args(action))
            self.operate_cli(self.operate_args(action, "--apply", plan["planSha256"]))
            args = self.operate_args(action)
            for flag in ("--action", "--output-directory"):
                index = args.index(flag); del args[index:index+2]
            args += ["--status-path", str(status)]
            # Operate's simulator updates status/journal on show. Health must use a
            # strictly read-only systemctl fake after lifecycle has settled.
            readonly = self.script("systemctl-health", "print('ActiveState=active\\nSubState=running\\nNRestarts=0')")
            args[args.index("--systemctl")+1] = readonly["path"]
            args[args.index("--systemctl-sha256")+1] = readonly["sha256"]
            import fcntl
            sup = json.loads((self.install / "supervisor/configuration.json").read_bytes())
            with ExitStack() as locks:
                paths = [Path(sup["coordinator"]["commonLockPath"])]
                paths += [self.install / "registry" / cid / "operation.lock" for cid in self.ids.values()]
                for path in paths:
                    handle = locks.enter_context(open(path, "rb"))
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run([str(self.python), "-I", "-B", str(H.I.ROOT / "scripts/semantic-provider-r3-health.py"),
                    *args], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())
            self.assertEqual(result.stderr, b"")
            value = json.loads(status.read_bytes())
            assert_schema(self, value)
            self.assertIsNone(value["readError"], value)
            self.assertEqual(value["supervisor"]["state"], "ACTIVE" if action == "start" else "WAITING")
            self.assertEqual(value["lease"]["state"], "LEASE_READY" if action == "start" else "QUIESCED")
            self.assertEqual(value["roles"]["adapter"]["state"], "STARTED" if action == "start" else "DELETED")
            info = status.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o600))
            self.assertEqual(status.read_bytes(), S.M.canonical(value))


@unittest.skipUnless(NATIVE, "set OUF_R3_HEALTH_NATIVE=1 under Linux root:root")
class NativeTests(unittest.TestCase):
    def test_real_installed_start_stop_health_with_writer_locks_held(self):
        for name in ("unshare", "mount", "umount", "ip", "openssl"):
            self.assertIsNotNone(shutil.which(name))
        result = subprocess.run([shutil.which("unshare"), "--mount", "--net", "--fork", sys.executable, "-I", "-B",
            str(Path(__file__).resolve()), "--native-child"], capture_output=True, timeout=700)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(loader.loadTestsFromTestCase(c) for c in (PortableTests, AtomicTests, NativeTests))


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-child"]:
        if not NATIVE: raise RuntimeError("disabled native scenario")
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([HealthFixture("scenario_health")]))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
