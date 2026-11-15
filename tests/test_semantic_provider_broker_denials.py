"""Portable denial publication and actual collect with fake bound commands."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_semantic_provider_admission_v2 as F
from tools.semantic_provider_r3 import operate as O

b, a = F.b, F.a
CID, PEER = F.CID, "b" * 64


def receipt(mode="cohort-ready", epoch=1):
    return dict(schema=b.DENIAL_SCHEMA, containerId=CID, epoch=epoch, mode=mode,
                reason="PEER_MAC_IP_DRIFT", at=1500, cohort=None)


class DenialTests(unittest.TestCase):
    def test_invocation_each_mode_exclusive_and_write_failure(self):
        with F.libraries(), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
            def initialize(self, cfg, raw, path, args):
                self.cid, self.args, self.clock = CID, args, lambda: 1500
                self.epochs = SimpleNamespace(directory=lambda _: None)
                self.denial_root, self.cohort = root, None
            # Keep the real exclusive open/write, adapting only POSIX directory IO
            # and permission operations unavailable on Windows.
            original_open = os.open
            opens = []
            def native_open(path, flags, mode=0o777):
                opens.append((path, flags, mode))
                if Path(path) == root:
                    return original_open(root / "fsync-fixture", os.O_CREAT | os.O_WRONLY, 0o600)
                return original_open(path, flags, mode)
            with patch.object(b.Broker, "__init__", initialize), patch.object(b, "load", return_value=({}, b"")), \
                    patch.object(b.Broker, "operate", side_effect=ValueError("PEER_MAC_IP_DRIFT")) as operate, \
                    patch.object(Path, "lstat", return_value=info), \
                    patch.object(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True), \
                    patch.object(os, "O_DIRECTORY", getattr(os, "O_DIRECTORY", 0), create=True), \
                    patch.object(os, "fchmod", getattr(os, "fchmod", lambda *_: None), create=True), \
                    patch.object(os, "open", side_effect=native_open), \
                    patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}"))):
                for mode in b.MODES:
                    argv = ["--configuration", "/cfg", "--container-id", CID, "--epoch", "1",
                            "--bundle", "/bundle", "--runtime-root", "/runtime", "--mode", mode]
                    for attempt in range(2):
                        reason = "PEER_MAC_IP_DRIFT" if attempt == 0 else "SECOND_DENIAL"
                        operate.side_effect = ValueError(reason)
                        sys.stdin.buffer = io.BytesIO(b"{}")
                        output = io.StringIO()
                        with redirect_stderr(output):
                            self.assertEqual(b.main(argv), 1)
                        self.assertEqual(output.getvalue(), "SEMANTIC_DEPLOYMENT_BROKER=DENIED " + reason + "\n")
                        path = root / ("broker-denial-" + mode + ".json")
                        self.assertEqual(b.validate_denial(path.read_bytes(), CID, 1, mode), receipt(mode))
                        if sys.platform == "linux":
                            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    file_opens = [x for x in opens if Path(x[0]) == path]
                    self.assertTrue(all(flags & os.O_EXCL and mode == 0o600 for _, flags, mode in file_opens))
                with patch.object(b.evidence_v2, "write_exclusive", side_effect=OSError("PRIVATE")), redirect_stderr(io.StringIO()):
                    self.assertEqual(b.main(argv), 1)
                # An initialization failure after discovering the private epoch
                # is recorded by main even though __init__ never returns.
                (root / "broker-denial-cleanup.json").unlink()
                def fail_after_private(self, *args):
                    initialize(self, *args)
                    raise ValueError("LATE_CONSTRUCTOR_DENIED")
                with patch.object(b.Broker, "__init__", fail_after_private), redirect_stderr(io.StringIO()):
                    self.assertEqual(b.main(argv), 1)
                self.assertEqual(json.loads((root / "broker-denial-cleanup.json").read_bytes())["reason"],
                                 "LATE_CONSTRUCTOR_DENIED")
                with patch.object(b.Broker, "operate", return_value=None), \
                        patch.object(b.Broker, "record_denial") as denial, redirect_stdout(io.StringIO()):
                    self.assertEqual(b.main(argv), 0)
                    denial.assert_not_called()

    def test_constructor_failure_before_or_after_private_epoch(self):
        for known in (False, True):
            def initialize(self, *args):
                if known:
                    self.denial_root = Path("/private/epoch")
                raise ValueError("CONSTRUCTOR_DENIED")
            with patch.object(b, "load", return_value=({}, b"")), patch.object(b.Broker, "__init__", initialize), \
                    patch.object(b.Broker, "record_denial", autospec=True) as save, redirect_stderr(io.StringIO()) as err:
                self.assertEqual(b.main(["--configuration", "/cfg", "--container-id", CID, "--epoch", "1",
                    "--bundle", "/bundle", "--runtime-root", "/runtime", "--mode", "prepare"]), 1)
                self.assertEqual(hasattr(save.call_args.args[0], "denial_root"), known)
                self.assertEqual(err.getvalue(), "SEMANTIC_DEPLOYMENT_BROKER=DENIED CONSTRUCTOR_DENIED\n")
        broker = b.Broker.__new__(b.Broker)
        with patch.object(b.evidence_v2, "write_exclusive") as write:
            broker.record_denial(ValueError("EARLY_DENIAL"))
            write.assert_not_called()

    def test_bootstrap_stderr_code_and_sanitization(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("broker_bootstrap_denial", F.ROOT / b.ENTRYPOINTS[0])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for error, code in ((ValueError("SOURCE_DENIED"), "SOURCE_DENIED"), (ValueError("private/bundle"), "INTERNAL_ERROR")):
            with patch.object(module.os, "geteuid", return_value=0, create=True), \
                    patch.object(module.os, "getegid", return_value=0, create=True), \
                    patch.object(module, "require", side_effect=error), redirect_stderr(io.StringIO()) as output:
                self.assertEqual(module.main([]), 1)
            self.assertEqual(output.getvalue(), "SEMANTIC_DEPLOYMENT_BROKER=DENIED " + code + "\n")

    def test_operate_reads_current_and_previous_invalid_is_only_observation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for number in (1, 2, 3):
                epoch = root / CID / "epochs" / str(number)
                epoch.mkdir(parents=True)
                (epoch / "broker-denial-cohort-ready.json").write_bytes(a.canonical(receipt(epoch=number)))
            epoch = root / CID / "epochs/3"
            invalid = epoch / "broker-denial-prepare.json"
            invalid.write_bytes(b"PRIVATE")
            runtime = SimpleNamespace(read=Mock(side_effect=lambda p: p.read_bytes()))
            rows = O.broker_denials(runtime, root, CID, 3)
            self.assertEqual(rows, [receipt(epoch=3), {"invalid": "BROKER_DENIAL_INVALID"}, receipt(epoch=2)])
            self.assertEqual(runtime.read.call_count, 3)
            self.assertNotIn("PRIVATE", a.canonical(rows).decode())
            self.assertEqual(O.broker_denials(runtime, root, CID, None), [])
            for mutation in ({"schema": "wrong"}, {"at": True}, {"epoch": 2}, {"mode": "cleanup"},
                             {"reason": "PRIVATE/path"}, {"secret": "PRIVATE"}, {"cohort": {"secret": "PRIVATE"}}):
                invalid.write_bytes(a.canonical({**receipt(mode="prepare", epoch=3), **mutation}))
                rows = O.broker_denials(runtime, root, CID, 3)
                self.assertEqual(rows[1], {"invalid": "BROKER_DENIAL_INVALID"})
            invalid.write_bytes(b" " * 65537)
            self.assertEqual(O.broker_denials(runtime, root, CID, 3)[1], {"invalid": "BROKER_DENIAL_INVALID"})


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.libs = F.libraries()
        self.libs.__enter__()
        self.addCleanup(self.libs.__exit__, None, None, None)
        import tools.semantic_provider_deployment_authentication as auth
        import tools.semantic_provider_peer_bindings as peers
        import tools.semantic_provider_preexec_native as native
        import tools.semantic_provider_deployment_producer as producer
        self.peers = peers
        self.now = 0
        self.broker = b.Broker.__new__(b.Broker)
        broker = self.broker
        broker.cid, broker.cohort = CID, None
        broker.args = SimpleNamespace(runtime_root="/runtime/owned")
        broker.cfg = {"registryRoot": "/registry"}
        broker.binding = {"authorizationSha256": "f" * 64}
        broker.epochs = SimpleNamespace(current=lambda *_: None)
        broker.budget = auth.VerificationBudget(18, monotonic=lambda: self.now)
        self.nic = dict(interface="eth0", bridge="br_test", mac="02:42:ac:15:00:03", ipv4="172.21.0.3",
                        workloadRef="peer", bindingRef="peer_nic")
        self.peer = dict(containerId=PEER, applicationHash=a.sha(b"{}"), networkBindings=[self.nic])
        self.binding = {"path": "/runc", "sha256": "a" * 64}
        broker.template = {"candidate": {"runtimeBinding": self.binding, "transport": [{"peerIngress": {
            "kind": "CREATED_CANDIDATE", "bindingRef": "peer_nic", "declaration": self.peer}}]}}
        broker.runtime = Mock(return_value=("app", "generation"))
        broker.record = Mock(return_value={"state": "CREATED", "bundleHash": "app"})
        broker.gate = SimpleNamespace(record=lambda: {"state": "CREATED", "bundleHash": "app", "generation": "generation"})
        broker.stable = Mock()
        broker.commands = lambda: {k: {"path": "/" + k, "sha256": "a" * 64} for k in ("nsenter", "ip")}
        broker.observer = lambda: SimpleNamespace(run=self.run_command)
        self.row = dict(id=PEER, status="created", pid=42, bundle="/peer/bundle", secret="PRIVATE")
        self.rows = [self.row]
        self.children = [{"ifname": "lo"}, {"ifname": "eth0", "ifindex": 12, "link_index": 13,
            "address": self.nic["mac"], "addr_info": [{"family": "inet", "local": self.nic["ipv4"]}], "secret": "PRIVATE"}]
        self.hosts = [{"ifindex": 13, "ifname": "veth_peer", "link_index": 12, "master": "br_test", "secret": "PRIVATE"}]
        self.snapshot_failure = False
        for target, attr, value in ((native.NativeBackend, "generation", lambda *_: F.GEN),
                                    (producer, "program", lambda item, _: item["path"]),
                                    (peers.socket, "if_indextoname", lambda _: "veth_peer"),
                                    (b, "private", lambda _: b"{}"), (b.time, "sleep", self.pause)):
            patched = patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)

    def pause(self, seconds):
        self.now += seconds

    def run_command(self, binding, args, limit=131072):
        if binding["path"] == "/runc":
            return json.dumps(self.rows if "list" in args else self.row).encode()
        if binding["path"] == "/nsenter":
            if self.snapshot_failure:
                raise ValueError("NODE_OBSERVATION_UNPROVEN")
            return json.dumps(self.children).encode()
        self.assertEqual(binding["path"], "/ip")
        return json.dumps(self.hosts).encode()

    def denied(self, code):
        with self.assertRaisesRegex((ValueError, a.OperationDenied), "^" + code + "$"):
            self.broker.cohort_ready({})
        value = {**receipt(), "reason": code, "cohort": self.broker.cohort}
        b.validate_denial(a.canonical(value), CID, 1, "cohort-ready")
        self.assertNotIn("PRIVATE", a.canonical(value).decode())
        return value["cohort"]["peers"][0]

    def test_never_listed_timeout_records_attempts_and_reserves_budget(self):
        self.rows = []
        peer = self.denied("COHORT_PEER_WAIT_TIMEOUT")
        self.assertEqual(peer["lastReason"], "PEER_NOT_LISTED")
        self.assertGreater(peer["attempts"], 1)
        self.assertLess(self.now, 15.11)
        self.assertEqual(peer["snapshotError"], "COHORT_SNAPSHOT_PID_UNAVAILABLE")

    def test_missing_interfaces_timeout_has_snapshot(self):
        self.children = self.children[:1]
        peer = self.denied("COHORT_PEER_WAIT_TIMEOUT")
        self.assertEqual(peer["lastReason"], "PEER_INTERFACES_NOT_READY")
        self.assertEqual(peer["snapshot"], {"interfaces": [], "hosts": []})

    def test_missing_name_and_addresses_retain_specific_reason(self):
        for change, code in (({"ifname": "other"}, "PEER_INTERFACE_MISSING"),
                             ({"addr_info": []}, "PEER_ADDRESSES_NOT_READY")):
            with self.subTest(code=code):
                self.now = 0
                old = copy.deepcopy(self.children[1])
                self.children[1].update(change)
                peer = self.denied("COHORT_PEER_WAIT_TIMEOUT")
                self.assertEqual(peer["lastReason"], code)
                self.assertIn("snapshot", peer)
                self.children[1] = old

    def test_mac_drift_immediate_with_public_snapshot(self):
        self.children[1]["address"] = "02:00:00:00:00:01"
        peer = self.denied("PEER_MAC_IP_DRIFT")
        self.assertEqual(peer["attempts"], 1)
        self.assertEqual(self.now, 0)
        self.assertEqual(peer["runc"], {"status": "created", "pid": 42})
        self.assertEqual(peer["snapshot"]["hosts"], [{"link_index": 13, "ifname": "veth_peer", "master": "br_test"}])

    def test_failed_snapshot_does_not_change_original_denial(self):
        with patch.object(self.peers, "collect", side_effect=ValueError("PEER_MAC_IP_DRIFT")):
            self.snapshot_failure = True
            peer = self.denied("PEER_MAC_IP_DRIFT")
        self.assertEqual(peer["snapshotError"], "NODE_OBSERVATION_UNPROVEN")

    def test_ready_is_unchanged_without_diagnosis(self):
        self.broker.cohort_ready({})
        self.assertIsNone(self.broker.cohort)
        self.broker.stable.assert_called_once()

    def test_other_pending_states_and_fatal_probe_include_all_peers(self):
        for status, code in (("creating", "PEER_CREATING"), ("stopped", "PEER_STOPPED_SIBLING_CREATING")):
            with self.subTest(status=status):
                self.now = 0
                self.row.update(status=status, pid=0)
                self.broker.epochs = SimpleNamespace(boot_id=lambda: "boot", current=lambda *_: dict(
                    bootId="boot", authorizationSha256="f"*64, runtimeRoot="/runtime/owned", state="CREATING",
                    bundleHash=self.peer["applicationHash"], driverHash=None))
                peer = self.denied("COHORT_PEER_WAIT_TIMEOUT")
                self.assertEqual(peer["lastReason"], code)
        self.now = 0
        self.row.update(status="stopped", pid=0)
        self.broker.epochs.current = lambda *_: None
        peer = self.denied("COHORT_PEER_STATE_DENIED")
        self.assertEqual(peer["attempts"], 1)
        second = {**copy.deepcopy(self.peer), "containerId": "c" * 64}
        self.broker.template["candidate"]["transport"].append({"peerIngress": {
            "kind": "CREATED_CANDIDATE", "bindingRef": "peer_nic", "declaration": second}})
        self.rows.append({**self.row, "id": second["containerId"], "pid": 43, "status": "created"})
        self.denied("COHORT_PEER_STATE_DENIED")
        self.assertEqual(len(self.broker.cohort["peers"]), 2)
        later = self.broker.cohort["peers"][1]
        self.assertEqual(later["attempts"], 0)
        self.assertIsNone(later["lastReason"])
        self.assertEqual(later["runc"], {"status": "created", "pid": 43})
        self.assertIn("snapshot", later)

    def test_snapshot_budget_exhaustion_and_bounded_diagnostics(self):
        with patch.object(self.peers, "collect", side_effect=ValueError("PEER_MAC_IP_DRIFT")):
            original = self.broker.peer_snapshot
            def after_deadline(diagnostic):
                self.now = 18
                original(diagnostic)
            with patch.object(self.broker, "peer_snapshot", side_effect=after_deadline):
                peer = self.denied("PEER_MAC_IP_DRIFT")
            self.assertEqual(peer["snapshotError"], "AUTHENTICATION_DEADLINE_MISSED")


if __name__ == "__main__":
    unittest.main()
