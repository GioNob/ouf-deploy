"""A2 contract tests: synthetic Docker, private inputs and /proc; no daemon IO."""

import copy
from contextlib import ExitStack, contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    selected = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(selected)
    return selected


m = load("prepare-semantic-provider-a2-20261113.py")
r = load("recreate-southbound-successor-20261113.py")
# P imports POSIX account modules. Its two consumers under test do not use them.
with patch.dict(sys.modules, {name: types.ModuleType(name) for name in ("grp", "pwd")}
                if os.name == "nt" else {}):
    p = load("prepare-semantic-provider-installation.py")

ADAPTER, OLD_SB, SOUTHBOUND = (digit * 64 for digit in "abc")
ADAPTER_TX, SOUTHBOUND_TX = "1" * 32, "2" * 32
LEAF = b"-----BEGIN CERTIFICATE-----\nZmFrZS1kZXI=\n-----END CERTIFICATE-----\n"


@contextmanager
def portable_stage():
    """Use real POSIX IO on CI; adapt only missing Windows descriptor operations."""
    if os.name != "nt":
        yield
        return
    original_open, original_close, original_sync = os.open, os.close, os.fsync
    directories = {}

    def open_fd(path, flags, mode=0o777, *, dir_fd=None):
        path = Path(path) if dir_fd is None else directories[dir_fd] / path
        if path.is_dir():
            fd = -100 - len(directories)
            directories[fd] = path
            return fd
        return original_open(path, flags | os.O_BINARY, mode)

    with ExitStack() as stack:
        for name in ("O_DIRECTORY", "O_NOFOLLOW"):
            stack.enter_context(patch.object(os, name, 0, create=True))
        stack.enter_context(patch.object(os, "open", side_effect=open_fd))
        stack.enter_context(patch.object(os, "close", side_effect=lambda fd: None if fd in directories else original_close(fd)))
        stack.enter_context(patch.object(os, "fsync", side_effect=lambda fd: None if fd in directories else original_sync(fd)))
        stack.enter_context(patch.object(os, "fchown", create=True))
        stack.enter_context(patch.object(os, "fchmod", create=True))
        yield


class A2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.args = types.SimpleNamespace(
            adapter_id=ADAPTER, adapter_transaction=ADAPTER_TX,
            southbound_id=SOUTHBOUND, southbound_transaction=SOUTHBOUND_TX,
            previous_a_root=root / "previous-a", previous_a_plan_sha256="d" * 64,
            previous_a_successors_sha256=None, recreation_receipt=root / "recreation.json",
            recreation_receipt_sha256=None, output_root=root, output_name="a2", plan=True,
            apply=False, plan_sha256=None)
        self.work = root / "a2"
        self.cutover = types.SimpleNamespace(
            OLD="e" * 64, WORK=root / "cutover", LABEL="cutover-label", NETWORK="backend",
            NETWORK_ID="f" * 64, ADDRESS="172.18.0.6", MAC="b2:96:a1:e2:c1:8d",
            SOUTHBOUND_ROUTES=root / "routes.yaml", SOUTHBOUND_LEAF=root / "leaf.crt",
            SOUTHBOUND_ROUTES_TARGET="/routes", SOUTHBOUND_LEAF_SHA=m.sha(LEAF),
            # Deliberately unusable historical selectors: A2 must never use them.
            SUCCESSORS=("wrong",), SOUTHBOUND_SUCCESSOR="wrong", SUCCESSOR_TRANSACTION="wrong")
        self.rollout = types.SimpleNamespace(JAVA=b"java")
        self.docs = {ADAPTER: self.created(ADAPTER, ADAPTER_TX, False),
                     SOUTHBOUND: self.created(SOUTHBOUND, SOUTHBOUND_TX, True)}
        self.docs[SOUTHBOUND]["Mounts"] = [{"Type": "bind", "RW": False,
            "Source": str(self.cutover.SOUTHBOUND_ROUTES), "Destination": "/routes"}]
        semantic = self.created(m.SEMANTIC, "3" * 32, False)
        semantic.update(Name="/semantic", State={"Status": "running", "Running": True,
            "Pid": 1234, "StartedAt": "2026-11-11", "Paused": False, "Restarting": False})
        semantic["NetworkSettings"]["Networks"] = {"backend": {"EndpointID": "9" * 64,
            "NetworkID": self.cutover.NETWORK_ID}}
        self.docs[m.SEMANTIC] = semantic
        self.docs[self.cutover.OLD] = {"Name": "/retained", "State": {"Status": "exited", "Pid": 0},
                                        "NetworkSettings": {"Networks": {}}}
        self.cutover.inspect = Mock(side_effect=lambda deadline, cid: copy.deepcopy(self.docs[cid]))
        self.cutover.process = Mock(return_value=b"java")
        self.cutover.verify_new = Mock()
        endpoint = {"EndpointID": "9" * 64, "MacAddress": self.cutover.MAC,
                    "IPv4Address": self.cutover.ADDRESS + "/16"}
        self.network = {"Id": self.cutover.NETWORK_ID, "Name": "backend", "Driver": "bridge",
                        "EnableIPv6": False, "Containers": {m.SEMANTIC: endpoint}}

        def engine(deadline, method, resource):
            self.assertEqual(method, "GET")
            if resource == "/info":
                return {"ServerVersion": "29.8.1", "Driver": "overlayfs", "CgroupDriver": "systemd",
                        "DockerRootDir": "/var/lib/docker"}
            self.assertEqual(resource, "/networks/" + self.cutover.NETWORK_ID)
            return copy.deepcopy(self.network)

        self.cutover.engine = Mock(side_effect=engine)
        self.inputs = {}
        historical = {"retainedName": "retained", "newContainer": {"name": "semantic"},
                      "network": {"dnsNames": ["semantic"]}}
        self.put(self.cutover.WORK / "result.json", {"schema": "ouf.semantic-provider-cutover.v1",
            "status": "SEMANTIC_PROVIDER_CUTOVER_READY", "planSha256": m.CUTOVER_PLAN,
            "replacementContainerId": m.SEMANTIC, "southboundIssuerMatch": True, "manifest": historical})
        self.put(self.cutover.WORK / "manifest.json", {"planSha256": m.CUTOVER_PLAN, "manifest": historical})
        self.put(self.cutover.WORK / "complete.json", {"containerId": m.SEMANTIC,
            "oldContainerId": self.cutover.OLD, "planSha256": m.CUTOVER_PLAN})
        self.put(self.cutover.WORK / "creation-request.private.json", {"Labels": {self.cutover.LABEL: m.CUTOVER_PLAN}})
        self.inputs[self.cutover.SOUTHBOUND_LEAF] = LEAF
        self.put(self.cutover.SOUTHBOUND_ROUTES, {"ssls": [{"type": "server", "status": 1,
            "snis": [m.SOUTHBOUND_HOST], "cert": LEAF.decode()}]}, suffix=b"#END\n")
        previous_successors = {"transaction": ADAPTER_TX, "containers": [
            {"containerId": ADAPTER, "dockerFrameSha256": m.sha(m.canonical(m.frame(self.docs[ADAPTER])))},
            {"containerId": OLD_SB, "dockerFrameSha256": "8" * 64}]}
        previous_peer = {"fixture": "prior peer"}
        self.args.previous_a_successors_sha256 = self.put(self.args.previous_a_root / "successors.json", previous_successors)
        peer_pin = self.put(self.args.previous_a_root / "semantic-peer.json", previous_peer)
        self.previous_body = {"schema": "ouf.semantic-provider-preparation-a.manifest.v1",
            "directory": {"path": str(self.args.previous_a_root)}, "semanticPeer": previous_peer,
            "successors": previous_successors, "filesCreated": [
                {"path": str(self.args.previous_a_root / "semantic-peer.json"), "sha256": peer_pin},
                {"path": str(self.args.previous_a_root / "successors.json"),
                 "sha256": self.args.previous_a_successors_sha256}]}
        self.update_previous()
        new_request = {"HostConfig": {"Tmpfs": copy.deepcopy(self.docs[SOUTHBOUND]["HostConfig"]["Tmpfs"])}}
        recreation_plan = {"newSouthboundRequest": new_request}
        self.recreation = {"schema": "ouf.semantic-southbound-successor-recreation.v1",
            "status": "SOUTHBOUND_RECREATED_STOPPED", "oldCid": OLD_SB, "newCid": SOUTHBOUND,
            "newTransaction": SOUTHBOUND_TX, "noswapRemoved": True, "containerStarts": 0,
            "newFrameSha256": r.frame_digest(self.docs[SOUTHBOUND]), "plan": recreation_plan,
            "planSha256": m.sha(m.canonical(recreation_plan)), "newRequestSha256": m.sha(m.canonical(
                new_request | {"Labels": {m.CREATION_LABEL: SOUTHBOUND_TX}}))}
        self.update_recreation()

        def private_input(path, **options):
            expected_uid = 636 if path in {self.cutover.SOUTHBOUND_ROUTES, self.cutover.SOUTHBOUND_LEAF} else 0
            self.assertEqual((options["uid"], options["gid"], options["mode"]), (expected_uid, expected_uid, 0o600))
            self.assertLessEqual(len(self.inputs[path]), options["limit"])
            return self.inputs[path]

        self.cutover.private_input = Mock(side_effect=private_input)
        self.peer = {"containerId": m.SEMANTIC, "generation": {"pid": 1234},
                     "startedAt": "2026-11-11", "binding": {"hostIfindex": 17}}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(m, "check_work_parent", side_effect=lambda work:
            m.require(not os.path.lexists(work), "PREPARATION_SCOPE_ALREADY_EXISTS")))
        self.stack.enter_context(patch.object(m, "observe_peer", side_effect=lambda *unused: copy.deepcopy(self.peer)))
        self.stack.enter_context(patch.object(m.subprocess, "run", side_effect=AssertionError("unexpected native IO")))

    @staticmethod
    def created(cid, transaction, southbound):
        return {"Id": cid, "Name": "/" + ("southbound" if southbound else "adapter"),
            "Image": "sha256:" + "0" * 64, "RestartCount": 0, "Path": "/bin/sh", "Args": ["-c", "fixture"],
            "Config": {"Labels": {m.CREATION_LABEL: transaction}},
            "HostConfig": {"RestartPolicy": {"Name": "no"}, "Runtime": "ouf-semantic-admitted-v2",
                           "Tmpfs": {"/run/fixture": "rw,noexec,nosuid,nodev"}},
            "Mounts": [], "State": {"Status": "created", "Pid": 0, "Running": False,
                                      "StartedAt": "0001-01-01T00:00:00Z"},
            "NetworkSettings": {"Networks": {"fixture": {"EndpointID": "", "IPAddress": "",
                "Aliases": [m.SOUTHBOUND_HOST] if southbound else ["adapter"]}}}}

    def put(self, path, document, suffix=b"\n"):
        raw = m.canonical(document) + suffix
        self.inputs[path] = raw
        return m.sha(raw)

    def update_previous(self):
        self.put(self.args.previous_a_root / "manifest.json", {"manifest": self.previous_body,
            "planSha256": self.args.previous_a_plan_sha256})
        self.put(self.args.previous_a_root / "result.json", {"manifest": self.previous_body,
            "planSha256": self.args.previous_a_plan_sha256,
            "status": "SEMANTIC_PROVIDER_PREPARATION_A_STAGED", "replayAllowed": False})

    def update_recreation(self):
        self.args.recreation_receipt_sha256 = self.put(self.args.recreation_receipt, self.recreation)

    def plan(self):
        return m.plan(self.cutover, self.rollout, self.args)

    def assert_held(self, reason):
        with self.assertRaisesRegex(m.Held, "^" + reason + "$"):
            self.plan()
        self.assertFalse(self.work.exists())

    def test_correct_lineage_and_stable_plan(self):
        manifest, digest, staged = self.plan()
        self.assertEqual((manifest, digest, staged), self.plan())
        successors = staged["successors.json"]
        self.assertNotIn("transaction", successors)
        self.assertEqual(successors["transactions"], {ADAPTER: ADAPTER_TX, SOUTHBOUND: SOUTHBOUND_TX})
        self.assertEqual(successors["lineage"]["recreation"]["oldCid"], OLD_SB)
        for row in successors["containers"]:
            self.assertEqual(row["transaction"], successors["transactions"][row["containerId"]])
        self.cutover.verify_new.assert_called()
        self.assertEqual(self.cutover.SUCCESSORS, ("wrong",))
        self.assertIn(str(self.args.recreation_receipt), manifest["inputFiles"])

    def test_adapter_frame_changed(self):
        self.docs[ADAPTER]["Config"]["MacAddress"] = "02:00:00:00:00:01"
        self.assert_held("A2_ADAPTER_LINEAGE_MISMATCH")

    def test_adapter_prior_transaction_changed(self):
        self.previous_body["successors"]["transaction"] = "4" * 32
        pin = self.put(self.args.previous_a_root / "successors.json", self.previous_body["successors"])
        self.previous_body["filesCreated"][1]["sha256"] = self.args.previous_a_successors_sha256 = pin
        self.update_previous()
        self.assert_held("A2_ADAPTER_LINEAGE_MISMATCH")

    def test_recreation_lineage_fields(self):
        for key, wrong in (("newCid", "9" * 64), ("oldCid", "9" * 64),
                           ("newTransaction", "9" * 32), ("noswapRemoved", False),
                           ("containerStarts", 1), ("containerStarts", False),
                           ("status", "PARTIAL"), ("schema", "other")):
            with self.subTest(key=key, wrong=wrong):
                original = self.recreation[key]
                self.recreation[key] = wrong
                self.update_recreation()
                self.assert_held("A2_RECREATION_LINEAGE_MISMATCH")
                self.recreation[key] = original

    def test_recreation_frame_and_tmpfs_and_request_and_plan(self):
        for key, code in (("newFrameSha256", "FRAME"), ("newRequestSha256", "REQUEST"), ("planSha256", "PLAN")):
            with self.subTest(key=key):
                original = self.recreation[key]
                self.recreation[key] = "0" * 64
                self.update_recreation()
                self.assert_held("A2_RECREATION_" + code + "_MISMATCH")
                self.recreation[key] = original
        self.docs[SOUTHBOUND]["HostConfig"]["Tmpfs"] = {"/run/fixture": "changed"}
        self.recreation["newFrameSha256"] = r.frame_digest(self.docs[SOUTHBOUND])
        self.update_recreation()
        self.assert_held("A2_RECREATION_TMPFS_MISMATCH")

    def test_label_must_match_each_cli_transaction(self):
        for cid in (ADAPTER, SOUTHBOUND):
            with self.subTest(cid=cid):
                original = self.docs[cid]["Config"]["Labels"][m.CREATION_LABEL]
                self.docs[cid]["Config"]["Labels"][m.CREATION_LABEL] = "9" * 32
                self.assert_held("A2_SUCCESSOR_TRANSACTION_MISMATCH")
                self.docs[cid]["Config"]["Labels"][m.CREATION_LABEL] = original

    def test_successor_must_never_have_started(self):
        for cid in (ADAPTER, SOUTHBOUND):
            original = copy.deepcopy(self.docs[cid])
            for section, key, value in (("State", "Status", "running"), ("State", "Pid", 2),
                ("State", "Running", True), ("State", "StartedAt", "2026-11-13"),
                ("HostConfig", "Runtime", "runc")):
                with self.subTest(cid=cid, key=key):
                    self.docs[cid][section][key] = value
                    self.assert_held("SUCCESSOR_NOT_STOPPED")
                    self.docs[cid] = copy.deepcopy(original)
            for mutation in (lambda d: d.update(RestartCount=1),
                             lambda d: d["HostConfig"]["RestartPolicy"].update(Name="always"),
                             lambda d: d["NetworkSettings"]["Networks"]["fixture"].update(EndpointID="active")):
                mutation(self.docs[cid])
                self.assert_held("SUCCESSOR_NOT_STOPPED")
                self.docs[cid] = copy.deepcopy(original)

    def test_role_sni_and_routes_must_match(self):
        self.docs[ADAPTER]["NetworkSettings"]["Networks"]["fixture"]["Aliases"] = [m.SOUTHBOUND_HOST]
        self.assert_held("A2_SUCCESSOR_ROLE_MISMATCH")
        self.docs[ADAPTER]["NetworkSettings"]["Networks"]["fixture"]["Aliases"] = ["adapter"]
        self.docs[SOUTHBOUND]["Mounts"][0]["RW"] = True
        self.recreation["newFrameSha256"] = r.frame_digest(self.docs[SOUTHBOUND])
        self.update_recreation()
        self.assert_held(m.MISMATCH)

    def test_existing_output_preserved(self):
        self.work.mkdir()
        sentinel = self.work / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaisesRegex(m.Held, "PREPARATION_SCOPE_ALREADY_EXISTS"):
            self.plan()
        with self.assertRaisesRegex(m.Held, "PREPARATION_SCOPE_ALREADY_EXISTS"):
            m.stage({}, "0" * 64, {}, {}, self.work)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def main_report(self):
        output = []
        with patch.object(m, "arguments", return_value=self.args), \
             patch.object(m, "helpers", return_value=(self.cutover, self.rollout)), \
             patch.object(os, "geteuid", return_value=0, create=True), \
             patch.object(os, "write", side_effect=lambda fd, raw: output.append(bytes(raw)) or len(raw)):
            code = m.main()
        return code, json.loads(b"".join(output))

    def test_plan_no_writes_and_changed_digest_no_writes(self):
        with patch.object(m, "stage", side_effect=AssertionError("unexpected staging")), \
             patch.object(Path, "mkdir", side_effect=AssertionError("unexpected mkdir")):
            code, report = self.main_report()
            self.assertEqual((code, report["status"]), (0, "PLAN_READY"))
            # Change only receipt bytes (hash included in plan inputs).
            self.inputs[self.args.recreation_receipt] += b" "
            self.args.recreation_receipt_sha256 = m.sha(self.inputs[self.args.recreation_receipt])
            self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, report["planSha256"]
            code, changed = self.main_report()
            self.assertEqual((code, changed["reason"]), (1, "PLAN_DIGEST_CHANGED"))
        self.assertFalse(self.work.exists())

    def test_input_hash_and_custody_fail_closed(self):
        self.args.recreation_receipt_sha256 = "0" * 64
        self.assert_held("A2_RECREATION_HASH_MISMATCH")
        self.update_recreation()
        original = self.cutover.private_input.side_effect
        def denied(path, **options):
            if path == self.args.recreation_receipt:
                raise RuntimeError("MATERIAL_METADATA_CHANGED")
            return original(path, **options)
        self.cutover.private_input.side_effect = denied
        self.assert_held("A2_RECREATION_CUSTODY_UNPROVEN")

    def test_previous_receipt_pins_and_scope(self):
        self.previous_body["directory"]["path"] = "wrong"
        self.update_previous()
        self.assert_held("A2_PREVIOUS_A_SCOPE_MISMATCH")
        self.previous_body["directory"]["path"] = str(self.args.previous_a_root)
        self.previous_body["filesCreated"][1]["sha256"] = "0" * 64
        self.update_previous()
        self.assert_held("A2_PREVIOUS_A_SUCCESSORS_HASH_MISMATCH")

    def test_final_successor_reread_detects_change(self):
        self.cutover.inspect.side_effect = None
        originals = self.docs
        counts = {}
        def inspect(deadline, cid):
            counts[cid] = counts.get(cid, 0) + 1
            doc = copy.deepcopy(originals[cid])
            if cid == ADAPTER and counts[cid] == 2:
                doc["Image"] = "changed"
            return doc
        self.cutover.inspect.side_effect = inspect
        self.assert_held("DISCOVERY_GENERATION_CHANGED_DURING_READ")

    def test_final_lineage_reread_detects_change(self):
        original = self.cutover.private_input.side_effect
        reads = 0
        def changed(path, **options):
            nonlocal reads
            raw = original(path, **options)
            if path == self.args.previous_a_root / "result.json":
                reads += 1
                if reads == 2:
                    return raw + b" "
            return raw
        self.cutover.private_input.side_effect = changed
        self.assert_held("A2_LINEAGE_CHANGED_DURING_READ")

    def test_inherited_engine_and_certificate_guards(self):
        original = self.cutover.engine.side_effect
        def changed(deadline, method, resource):
            value = original(deadline, method, resource)
            return value | {"ServerVersion": "other"} if resource == "/info" else value
        self.cutover.engine.side_effect = changed
        self.assert_held("ENGINE_PROFILE_CHANGED")
        self.cutover.engine.side_effect = original
        self.inputs[self.cutover.SOUTHBOUND_ROUTES] = b'{"ssls": []}#END\n'
        self.assert_held(m.MISMATCH)

    def test_staged_receipt_consumed_by_unmodified_p(self):
        manifest, digest, staged = self.plan()
        report = {"status": "HELD", "manifest": manifest, "planSha256": digest, "replayAllowed": False}
        with portable_stage():
            m.stage(manifest, digest, staged, report, self.work)
            with self.assertRaisesRegex(m.Held, "PREPARATION_SCOPE_ALREADY_EXISTS"):
                m.stage(manifest, digest, staged, {}, self.work)
        self.assertEqual({path.name for path in self.work.iterdir()}, set(m.OUTPUTS))
        if os.name != "nt":
            self.assertEqual(self.work.stat().st_mode & 0o777, 0o700)
            for path in self.work.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        class Reader:
            def document(inner, path, expected=None):
                raw = Path(path).read_bytes()
                if expected is not None:
                    self.assertEqual(m.sha(raw), expected)
                return json.loads(raw)
        peer, successors = p.receipt_a(Reader(), str(self.work), digest)
        docker = types.SimpleNamespace(inspect=lambda cid: copy.deepcopy(self.docs[cid]))
        roles = p.read_roles(docker, peer, successors)
        self.assertEqual({key: doc["Id"] for key, doc in roles.items()},
                         {"semantic": m.SEMANTIC, "adapter": ADAPTER, "southbound": SOUTHBOUND})
        self.assertEqual(json.loads((self.work / "result.json").read_bytes()), report)


class InheritedTests(unittest.TestCase):
    def test_frame_digest_matches_recreation_including_mac_and_missing_fields(self):
        for mac in ({}, {"MacAddress": None}, {"MacAddress": ""}, {"MacAddress": "02:00:00:00:00:01"}):
            doc = {"Id": SOUTHBOUND, "Config": mac, "Path": "/bin/sh", "Args": ["a"]}
            self.assertEqual(m.recreation_frame_digest(doc), r.frame_digest(doc))
            other = doc | {"Args": ["b"]}
            self.assertNotEqual(m.recreation_frame_digest(doc), m.recreation_frame_digest(other))

    def test_historical_modules_are_hash_loaded_and_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("cutover-semantic-provider-20261111.py", "upgrade-semantic-application-20261108.py"):
                # Windows checkout uses CRLF; Git blobs and delivery are LF.
                (root / name).write_bytes((ROOT / "scripts" / name).read_bytes().replace(b"\r\n", b"\n"))
            with patch.object(m, "__file__", str(root / "a2.py")):
                cutover, rollout = m.helpers()
                self.assertEqual(cutover.SUCCESSORS[0],
                    "85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef")
                self.assertTrue(rollout.JAVA)
                with (root / "cutover-semantic-provider-20261111.py").open("ab") as stream:
                    stream.write(b"\n")
                with self.assertRaisesRegex(m.Held, "DEPENDENCY_SOURCE_CHANGED"):
                    m.helpers()

    def test_observe_peer_with_simulated_proc_and_native_links(self):
        child = {"ifname": "eth0", "ifindex": 3, "link_index": 17, "address": "02:00:00:00:00:01",
                 "addr_info": [{"family": "inet", "local": "172.18.0.6"}], "linkinfo": {"info_kind": "veth"}}
        host = {"ifname": "vethfixture", "ifindex": 17, "link_index": 3, "master": "br-" + "f" * 12,
                "linkinfo": {"info_kind": "veth"}}
        cutover = types.SimpleNamespace(ADDRESS="172.18.0.6", MAC=child["address"], NETWORK_ID="f" * 64,
                                        NETWORK="backend")
        current = {"Id": m.SEMANTIC, "Image": "fixture", "State": {"Pid": 1234, "StartedAt": "fixture"},
                   "NetworkSettings": {"Networks": {"backend": {"EndpointID": "9" * 64}}}}
        boot = "11111111-2222-3333-4444-555555555555"
        namespace = types.SimpleNamespace(st_dev=1, st_ino=2)
        with patch.object(Path, "read_bytes", return_value=b"1234 (java) S " + b"0 " * 18 + b"99 0"), \
             patch.object(Path, "read_text", return_value=boot), patch.object(Path, "stat", return_value=namespace), \
             patch.object(os, "open", return_value=55), patch.object(os, "close"), \
             patch.object(os, "fstat", return_value=namespace), patch.object(os, "O_CLOEXEC", 0, create=True), \
             patch.object(m.socket, "if_indextoname", return_value="vethfixture"), \
             patch.object(m, "native_json", side_effect=[[child], [host], [child], [host]]):
            peer = m.observe_peer(cutover, 100, current)
        self.assertEqual(peer["generation"], {"pid": 1234, "startTicks": 99, "namespaceDevice": 1, "namespaceInode": 2})
        self.assertEqual(peer["binding"]["hostIfindex"], 17)

    def test_cli_has_no_identity_hash_or_path_defaults(self):
        values = {"adapter-id": ADAPTER, "adapter-transaction": ADAPTER_TX, "southbound-id": SOUTHBOUND,
                  "southbound-transaction": SOUTHBOUND_TX, "previous-a-root": str(ROOT),
                  "previous-a-plan-sha256": "a" * 64, "previous-a-successors-sha256": "b" * 64,
                  "recreation-receipt": str(ROOT / "result.json"), "recreation-receipt-sha256": "c" * 64,
                  "output-root": str(ROOT), "output-name": "a2"}
        argv = [part for key, value in values.items() for part in ("--" + key, value)]
        self.assertTrue(m.arguments(["--plan", *argv]).plan)
        with patch.object(sys, "stderr", io.StringIO()):
            for key in values:
                missing = argv.copy()
                index = missing.index("--" + key)
                del missing[index:index + 2]
                with self.subTest(key=key), self.assertRaises(SystemExit):
                    m.arguments(["--plan", *missing])
            for prefix in (["--apply"], ["--apply", "--plan-sha256", "invalid"],
                           ["--plan", "--plan-sha256", "a" * 64]):
                with self.assertRaises(SystemExit):
                    m.arguments([*prefix, *argv])


if __name__ == "__main__":
    unittest.main()
