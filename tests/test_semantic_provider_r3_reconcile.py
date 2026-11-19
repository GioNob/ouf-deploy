"""Offline R3 reconciliation with a fixed clock and simulated native observations."""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
import io
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_runtime_v52_epochs as V52
import test_semantic_provider_r3_v18 as V18
from tools.semantic_provider_r3 import install_common as I
from tools.semantic_provider_r3 import reconcile_prepared_epoch as R

C = V18.C
BOOT = "6dc087ac-1111-4222-8333-444455556666"
NOW = 1500


class Reconcile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inputs, cls.old = V18.fixture()
        cls.new = C.compose(inputs, 18, sequence=18, supersedes=R.sha(cls.old["authorization"]))
        cls.runtime_source = cls.new["documents"]["versions/18/source/" + R.overlay.RUNTIME]

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = PurePosixPath("/fixture/r3")
        self.runtime = C.contract_module(self.runtime_source, "reconcile_test")
        self.disk = {}
        self.actions = []
        self.lock_events = []
        self.runc = {}
        self.ticks = {}
        self.tables = []
        self.lease = {"state": "QUIESCED", "leaseAuthorized": False, "leaseAddresses": [[], []]}
        self.mounts = {}
        self.boot = BOOT
        self.rows = {}
        self.gates = {}
        self.packages = {}
        self.configs = {}
        self.entries = {}
        self.held = set()
        for version, result in ((17, self.old), (18, self.new)):
            for relative, raw in result["documents"].items():
                self.disk[self.root / relative] = raw
            raw = self.disk[self.root / f"versions/{version}/runtime-configuration.json"]
            cfg = R.A.decode(raw)
            old_root = PurePosixPath(cfg["registryRoot"]).parent
            cfg = self.rebase(cfg, str(old_root))
            raw = R.canonical(cfg)
            path = self.root / f"versions/{version}/runtime-configuration.json"
            self.disk[path] = raw
            self.configs[version] = cfg, raw
            payload = R.A.decode(result["authorization"])
            payload["runtimeConfigurationSha256"] = R.sha(raw)
            payload["supersedes"] = next(iter(self.entries)) if version == 18 else payload["supersedes"]
            digest = R.sha(R.canonical(payload))
            self.entries[digest] = {"sequence": version, "decision": "OPERATE", "sha256": digest,
                                    "authorization": payload}
        self.historical, self.head = self.entries.values()
        self.current = self.configs[18][0]
        self.owner = {"kernel": {"tableName": "shared_g2"}, "binding": {}}
        self.coordinator = {"ownerConfiguration": {"sha256": "d" * 64},
                            "nftBinding": {"path": "/nft", "sha256": "f" * 64}, "journalPath": "/lease.json"}
        for cid, row in self.current["candidates"].items():
            self.stage(cid, row["role"])

        self.epochs = SimpleNamespace(current=lambda _, cid: self.rows[cid], boot_id=lambda: self.boot,
                                      start_ticks=self.ticks.get)
        self.runtime.operation_modules = lambda _: (None, self.epochs)
        self.runtime.read = self.disk.__getitem__
        self.runtime.bound_bytes = self.bound_bytes
        self.runtime.verify_files = lambda _: None
        self.runtime.executable = lambda *_: None
        self.runtime.private_directory = lambda _: None
        self.runtime.failed_runtime_state = lambda _cfg, cid, *_: self.runc[cid]
        self.patch(R, "Path", PurePosixPath)
        self.patch(R, "installed_runtime", lambda _: (self.runtime, *self.configs[18], "a" * 64))
        self.patch(R, "chain", lambda *_: (self.head, self.entries, R.sha(R.canonical(self.entries))))
        self.patch(R, "coordinator", lambda *_: (self.coordinator, self.owner))
        self.patch(R, "historical_package", lambda _rt, _cfg, cid: nullcontext(self.packages[cid]))
        self.patch(R, "cleanup_broker", lambda _b, cfg, *_: cfg["fixturePort"])
        self.patch(R, "docker_state", self.docker)
        self.patch(R, "native_command", self.command)
        self.patch(R.custody, "private", lambda path, *_: self.disk[path])
        self.patch(R.custody, "write_once", self.write_once)
        self.patch(R.custody, "lock", self.lock)
        self.patch(R.custody, "directory_lock", self.lock)
        real_lexists = os.path.lexists
        self.patch(os.path, "lexists", lambda path: path in self.disk or any(
            path in p.parents for p in self.disk) if isinstance(path, PurePosixPath) else real_lexists(path))
        real_stat = os.stat
        self.patch(os, "stat", lambda path, *args, **kwargs: SimpleNamespace(st_ino=42)
                   if path == "/proc/self/ns/net" else real_stat(path, *args, **kwargs))
        app = SimpleNamespace(application_hash=self.runtime.digest)
        self.stack.enter_context(patch.dict(R.sys.modules, {"tools.semantic_provider_deployment_admission": app}))
        self.tool = R.Reconciliation(self.root, clock=lambda: NOW)

    def patch(self, obj, name, value):
        self.stack.enter_context(patch.object(obj, name, value))

    def rebase(self, value, prefix):
        if isinstance(value, dict):
            return {k: self.rebase(v, prefix) for k, v in value.items()}
        if isinstance(value, list):
            return [self.rebase(v, prefix) for v in value]
        if isinstance(value, str) and value.startswith(prefix + "/"):
            return str(self.root) + value[len(prefix):]
        return value

    def stage(self, cid, role):
        cfg, raw = self.configs[17]
        folder = self.root / "registry" / cid / "epochs/21"
        root = "/run/docker/runtime-runc/moby"
        generation = {"pid": 42 if role == "adapter" else 43, "startTicks": 150, "namespaceInode": 112}
        bound = cfg["admissionConfigurations"][cid]
        broker_data = {"sourceRoot": str(self.root / "versions/17/source"), "sourceHashes": {},
                       "containerId": cid, "role": role, "registryRoot": cfg["registryRoot"],
                       "runtimeRootParent": cfg["runtimeStateRoot"],
                       "operation": {**{k: v for k, v in cfg["operation"].items()
                                       if k not in ("installationRef", "entityRef", "issuerRef")},
                                     "opensslBinding": cfg["opensslBinding"]},
                       "authorities": {k: cfg["operation"][k] for k in ("installationRef", "entityRef", "issuerRef")},
                       "creationFrameObserverBinding": {}}
        self.disk[PurePosixPath(bound["path"])] = R.canonical(broker_data)
        binding = {"containerId": cid, "epoch": 21, "configurationHash": bound["sha256"],
                   "authorizationSha256": self.historical["sha256"]}
        profile = {"bundlePath": str(folder / "bundle"), "namespacePath": str(folder / "netns"),
                   "namespaceInode": 112, "namespaceOrigin": "OCI_CREATED",
                   "policy": {"tableName": self.historical["authorization"]["roles"][role]["tableName"]}}
        bundle = {"linux": {"namespaces": [{"type": "network"}]}}
        profile["bundleHash"] = self.runtime.digest(bundle)
        template = {"kernel": self.owner["kernel"], "coordinationBinding": self.owner["binding"],
                    "dns": {}, "lockFile": str(R.GUARD), "coordinationJournal": self.coordinator["journalPath"],
                    "commands": {"nft": "/nft"}, "hostNetworkNamespace": 42, "budgetSeconds": 12}
        evidence = {**binding, "bundleHash": profile["bundleHash"], "generation": generation}
        evidence_binding = {"path": str(folder / "evidence.json"), "sha256": R.sha(R.canonical(evidence))}
        driver = {"profile": profile, "operationBinding": binding, "commands": template["commands"],
                  "operation": {**cfg["operation"], "opensslBinding": cfg["opensslBinding"]},
                  "sourceRoot": broker_data["sourceRoot"], "sourceHashes": {},
                  "runtimeBinding": {"path": cfg["runtimePath"], "sha256": cfg["runtimeSha256"], "root": root},
                  "evidenceBinding": evidence_binding, "creationFrameObserverBinding": {},
                  **{k: template[k] for k in ("lockFile", "coordinationJournal", "kernel", "coordinationBinding",
                                              "dns", "budgetSeconds")}}
        epoch = {"containerId": cid, "epoch": 21, "bootId": BOOT, "failure": "TWO_PHASE_BROKER_DENIED",
                 "state": "FAILED", "openedAt": 1200, "bundleHash": profile["bundleHash"], "runtimeRoot": root,
                 "configurationHash": R.sha(raw), "authorizationSha256": binding["authorizationSha256"],
                 "driverHash": R.sha(R.canonical(driver)),
                 "generation": {k: generation[k] for k in ("pid", "startTicks")}}
        self.rows[cid] = epoch
        self.ticks[generation["pid"]] = None
        self.runc[cid] = None
        self.mounts[folder / "netns"] = {"namespaceInode": 112, "namespaceDevice": 4,
                                         "mountId": generation["pid"]}
        preexec = {"state": "ROLLED_BACK", "transactionId": cid, "containerGeneration": generation}
        self.gates[cid] = preexec
        admission = {"state": "PROTECTED", "transactionId": cid, "driverHash": epoch["driverHash"],
                     "namespaceOwned": True, "namespaceInode": 112, "containerGeneration": generation}
        broker = {"state": "PROTECTED", "driverHash": epoch["driverHash"], "bundleHash": profile["bundleHash"]}
        consumption = {**broker, "state": "STARTED", "generation": generation,
                       "evidenceHash": evidence_binding["sha256"]}
        request = {"evidenceBinding": evidence_binding}
        denial = {"schema": V52.grant_fixture.b.DENIAL_SCHEMA, "containerId": cid, "epoch": 21,
                  "mode": "cleanup", "reason": "CONSUMPTION_CONFIGURATION_DRIFT", "at": 1400, "cohort": None}
        self.disk.update({folder / name: R.canonical(value) for name, value in
                          (("adapter.json", epoch), ("preexec.json", preexec), ("driver.json", driver),
                           ("broker-state.json", broker), ("admission.json", admission), ("bundle/config.json", bundle),
                           ("deployment.json", consumption), ("evidence.json", evidence), ("preparer.json", request),
                           ("broker-denial-cleanup.json", denial), ("netns", {}))})
        self.disk[folder.parent.parent / "current"] = R.canonical({"epoch": 21})

        def read(name):
            return R.A.decode(self.disk[folder / name])

        def cas(name, before, after):
            self.assertEqual(read(name), before)
            self.assertTrue(self.held)
            self.disk[folder / name] = R.canonical(after)
            self.actions.append((role, name))

        port = SimpleNamespace(cfg=broker_data, gate=SimpleNamespace(record=lambda: read("deployment.json")),
                               record=lambda: read("broker-state.json"), binding=binding, bound={},
                               preparer_request=lambda _: request, stable=Mock(),
                               publish=lambda before, **kw: cas("broker-state.json", before, before | kw))
        worker = SimpleNamespace(template=template, request=request, record=lambda: read("admission.json"),
                                 stable=Mock(), command=lambda _: self.coordinator["nftBinding"],
                                 run=lambda name, args: self.unmount(role, name, args),
                                 journal=SimpleNamespace(write=lambda b, a: cas("admission.json", b, a)))
        gate = SimpleNamespace(record=lambda: self.gates[cid], coord=SimpleNamespace(journal=lambda: self.lease),
                               quiesced=lambda: R.require(self.lease["state"] == "QUIESCED",
                                                           "LEASE_QUIESCENCE_REQUIRED"))
        native = SimpleNamespace(generation_alive=lambda g: self.ticks[g["pid"]] == g["startTicks"])
        evidence_module = SimpleNamespace(verify=lambda value, *_: value)
        package = SimpleNamespace(read_binding=self.bound_bytes, owned_namespace_mount=self.mount,
                                  evidence_v2=evidence_module, validate_denial=V52.grant_fixture.b.validate_denial)
        self.packages[cid] = (SimpleNamespace(validate=R.A.decode, components=lambda _: (gate, native)), package,
                              {**broker_data, "fixturePort": port}, SimpleNamespace(Worker=lambda *_: worker))

    def bound_bytes(self, binding):
        return self.disk[PurePosixPath(binding["path"])]

    def lock(self, path):
        from contextlib import contextmanager

        @contextmanager
        def hold():
            self.assertNotIn(path, self.held)
            self.held.add(path)
            self.lock_events.append(path)
            try:
                yield
            finally:
                self.held.remove(path)
        return hold()

    def docker(self, _, cid):
        return {"status": "exited", "pid": 0, "restartCount": 0, "cid": cid}

    def command(self, _, binding, args):
        if binding["path"] == "/nft":
            self.assertEqual(args, ["-j", "list", "tables"])
            return R.canonical({"nftables": self.tables})
        cid = args[-1]
        self.assertEqual(args[-2], "delete")
        self.assertEqual(self.runc[cid]["status"], "stopped")
        self.runc[cid] = None
        self.actions.append(("runc", cid))
        return b""

    def mount(self, path, inode):
        row = self.mounts.get(path)
        if row is not None:
            R.require(row.get("filesystem", "nsfs") == "nsfs" and row["namespaceInode"] == inode,
                      "OWNED_NAMESPACE_DRIFT")
        return row

    def unmount(self, role, name, args):
        self.assertEqual(name, "umount")
        self.assertEqual(len(args), 1)
        self.assertTrue(self.held)
        del self.mounts[PurePosixPath(args[0])]
        self.actions.append((role, name))

    def write_once(self, path, raw):
        self.assertTrue(self.held)
        self.assertNotIn(path, self.disk)
        self.disk[path] = raw

    def row(self, role="adapter"):
        cid = next(cid for cid, spec in self.current["candidates"].items() if spec["role"] == role)
        return cid, self.root / "registry" / cid / "epochs/21"

    def assert_held(self, reason, digest=None):
        before = deepcopy(self.disk)
        with self.assertRaisesRegex((ValueError, RuntimeError), "^" + reason + "$"):
            self.tool.run(digest)
        self.assertEqual(self.disk, before)
        self.assertFalse(self.held)

    def test_plan_apply_and_actual_v18_dispatch(self):
        before = deepcopy(self.disk)
        plan = self.tool.run()
        self.assertEqual(self.disk, before)
        self.assertEqual(plan["planSha256"], R.plan_digest(plan))
        self.assertEqual(self.lock_events[-2:], [self.root / "authorization", R.GUARD])
        result = self.tool.run(plan["planSha256"])
        self.assertEqual(result["status"], "CLEANED")
        self.assertEqual(len(self.actions), 6)
        self.assertFalse(self.mounts)
        for role, proof in result["roles"].items():
            _, folder = self.row(role)
            for name in ("adapter.json", "deployment.json", "preexec.json", "broker-denial-cleanup.json"):
                self.assertEqual(self.disk[folder / name], before[folder / name])
            self.assertEqual(proof["receipt"]["at"], NOW)
            self.assertEqual(R.A.decode(self.disk[folder / "broker-state.json"])["state"], "CLEANED")
            self.assertEqual(R.A.decode(self.disk[folder / "admission.json"])["state"], "CLEANED")
        # Exercise the actual v18 runtime program with the portable runc bridge.
        wrapper = V52.PortableFailedCleanup()
        wrapper.setUp()
        self.addCleanup(wrapper.doCleanups)
        r = self.runtime_source
        with patch.dict(R.sys.modules, {"fcntl": ModuleType("fcntl")}):
            actual = ModuleType("actual_r3_v18")
            exec(compile(r, "v18-runtime.py", "exec"), vars(actual))
        wrapper.r = actual
        wrapper.folder = wrapper.base / "epochs/21"
        wrapper.record["epoch"] = 21
        wrapper.prepared()
        wrapper.record["configurationHash"] = "0" * 64
        wrapper.state = None
        wrapper.denied("delete", "FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY")
        receipt = self.row()[1] / "runtime-cleanup.json"
        wrapper.files[str(wrapper.folder / receipt.name)] = self.disk[receipt]
        self.assertEqual(wrapper.run_op("delete"), 0)
        self.assertEqual(wrapper.calls[-1][-2:], ["delete", V52.CID])
        self.assertFalse(wrapper.transitions)
        wrapper.quiesce.assert_not_called()
        self.assert_held("R3_RECONCILE_CLAIM_ALREADY_CONSUMED", plan["planSha256"])
        self.assertEqual(self.tool.run(self.tool.run()["planSha256"])["status"], "ALREADY_CLEANED")

    def test_stopped_runc_owned_delete_precedes_namespace_cleanup(self):
        cid, folder = self.row()
        self.runc[cid] = {"id": cid, "bundle": str(folder / "bundle"), "status": "stopped", "pid": 0}
        result = self.tool.run(self.tool.run()["planSha256"])
        self.assertEqual(self.actions[:2], [("runc", cid), ("adapter", "umount")])
        self.assertEqual(result["roles"]["adapter"]["receipt"]["runcStatusBefore"], "stopped")

    def test_wrong_historical_authorization_and_head(self):
        cid, _ = self.row()
        self.rows[cid]["authorizationSha256"] = "0" * 64
        self.assert_held("R3_RECONCILE_HISTORICAL_AUTHORIZATION_UNPROVEN")
        self.rows[cid]["authorizationSha256"] = self.historical["sha256"]
        self.head["sequence"] = 17
        self.assert_held("R3_RECONCILE_HISTORICAL_AUTHORIZATION_UNPROVEN")

    def test_wrong_historical_configuration(self):
        self.disk[self.root / "versions/17/runtime-configuration.json"] += b" "
        self.assert_held("R3_RECONCILE_HISTORICAL_CONFIGURATION_UNPROVEN")

    def test_boot_rollback_live_recycled_mount_tables_and_lease_denials(self):
        cid, folder = self.row()
        cases = [
            (self.__dict__, "boot", "other-boot", "R3_RECONCILE_SAME_BOOT_PREPARED_FAILURE_REQUIRED"),
            (self.gates[cid], "state", "PROTECTED", "R3_RECONCILE_ROLLBACK_UNPROVEN"),
            (self.ticks, 42, 150, "R3_RECONCILE_LIVE_OR_RECYCLED_GENERATION"),
            (self.ticks, 42, 151, "R3_RECONCILE_LIVE_OR_RECYCLED_GENERATION"),
            (self.mounts[folder / "netns"], "namespaceInode", 999, "OWNED_NAMESPACE_DRIFT"),
            (self.mounts, folder / "netns", {"namespaceInode": 112, "filesystem": "tmpfs"}, "OWNED_NAMESPACE_DRIFT"),
            (self.__dict__, "tables", [{"table": {"family": "inet", "name":
                self.historical["authorization"]["roles"]["adapter"]["tableName"]}}], "R3_RECONCILE_ROLE_TABLE_PRESENT"),
            (self.lease, "state", "LEASE_READY", "LEASE_QUIESCENCE_REQUIRED"),
            (self.runc, cid, {"status": "running"}, "R3_RECONCILE_RUNC_NOT_STOPPED"),
        ]
        for store, key, unsafe, reason in cases:
            with self.subTest(reason=reason, key=key):
                original = store[key]
                store[key] = unsafe
                try:
                    self.assert_held(reason)
                finally:
                    store[key] = original

    def test_drift_between_plan_and_apply_writes_nothing(self):
        plan = self.tool.run()
        self.mounts[self.row()[1] / "netns"]["mountId"] += 1
        self.assert_held("R3_RECONCILE_PLAN_DIGEST_CHANGED", plan["planSha256"])

    def test_supersession_between_plan_and_apply_writes_nothing(self):
        plan = self.tool.run()
        payload = {**self.head["authorization"], "sequence": 19, "supersedes": self.head["sha256"]}
        digest = R.sha(R.canonical(payload))
        self.head = {**self.head, "sha256": digest, "sequence": 19, "authorization": payload}
        self.entries[digest] = self.head
        self.assert_held("R3_RECONCILE_PLAN_DIGEST_CHANGED", plan["planSha256"])

    def test_interrupt_between_roles_requires_fresh_plan_and_proves_first(self):
        plan = self.tool.run()
        original = self.tool.inspect_role

        def interrupt(role, **kwargs):
            if role == "southbound" and "approve" in kwargs:
                raise KeyboardInterrupt
            return original(role, **kwargs)

        with patch.object(self.tool, "inspect_role", interrupt), self.assertRaises(KeyboardInterrupt):
            self.tool.run(plan["planSha256"])
        self.assert_held("R3_RECONCILE_CLAIM_ALREADY_CONSUMED", plan["planSha256"])
        resumed = self.tool.run()
        self.assertEqual([r["state"] for r in resumed["roles"].values()], ["CLEANED", "PENDING"])
        self.assertNotEqual(plan["planSha256"], resumed["planSha256"])
        self.assertEqual(self.tool.run(resumed["planSha256"])["status"], "CLEANED")
        self.assertEqual(self.actions.count(("adapter", "umount")), 1)

    def test_interrupt_inside_role_is_sticky_and_has_no_runtime_receipt(self):
        plan = self.tool.run()
        _, directory = self.row()
        with patch.object(self, "unmount", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.tool.run(plan["planSha256"])
        self.assertIn(directory / R.INTENT, self.disk)
        self.assertNotIn(directory / "runtime-cleanup.json", self.disk)
        self.assert_held("R3_RECONCILE_UNPROVEN_PARTIAL_ROLE")


class NativeContracts(unittest.TestCase):
    def test_real_mount_identity_denies_wrong_type_inode_and_stacked_mounts(self):
        broker = V52.grant_fixture.b
        with patch.object(Path, "lstat", return_value=SimpleNamespace(
                st_mode=stat.S_IFREG, st_ino=112, st_dev=os.makedev(0, 4) if hasattr(os, "makedev") else 4)), \
                patch.object(broker.os, "major", return_value=0, create=True), \
                patch.object(broker.os, "minor", return_value=4, create=True):
            target = Path("netns")
            mount = b"81 1 0:4 net:[112] netns rw - nsfs nsfs rw\n"
            for content, inode, error in ((mount, 113, "OWNED_NAMESPACE_DRIFT"),
                                          (mount.replace(b" - nsfs", b" - tmpfs"), 112, "OWNED_NAMESPACE_DRIFT"),
                                          (mount * 2, 112, "OWNED_NAMESPACE_MOUNT_AMBIGUOUS")):
                with self.subTest(reason=error), patch("builtins.open", return_value=io.BytesIO(content)), \
                        self.assertRaisesRegex(RuntimeError, error):
                    broker.owned_namespace_mount(target, inode)
            with patch("builtins.open", return_value=io.BytesIO(mount)):
                self.assertEqual(broker.owned_namespace_mount(target, 112)["mountId"], 81)

    def test_v18_delivery_pins_match_composed_runtime_and_wrapper(self):
        inputs, v17 = V18.fixture()
        v18 = C.compose(inputs, 18, sequence=18, supersedes=R.sha(v17["authorization"]))
        files = {p: V18.V12.blob(p) for p in (R.overlay.RUNTIME, R.overlay.EPOCHS)}
        emitted = R.overlay.sources_v16(files, {p: p for p in files})
        for result, version in ((v17, 17), (v18, 18)):
            prefix = f"versions/{version}/source/"
            for source, raw in emitted.items():
                self.assertEqual(result["documents"][prefix + source], raw)
            self.assertEqual(result["documents"][prefix + R.BOOTSTRAP], V18.V12.blob(R.BOOTSTRAP))
        root = PurePosixPath("/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1/versions/18")
        self.assertEqual(R.sha(I.wrapper_bytes(R.PYTHON, root)),
                         "4f16421ed7bec5b51266b2a7bdf7ac0b74b6180be14ee22e073bb974b09f4d54")

    def test_historical_closure_before_loading_admission_code(self):
        _, old = V18.fixture()
        prefix = "versions/17/"
        cfg = R.A.decode(old["documents"][prefix + R.RUNTIME_CONFIGURATION])
        rt = C.contract_module(old["documents"][prefix + "source/" + R.overlay.RUNTIME], "closure")
        cid = next(iter(cfg["candidates"]))
        root = PurePosixPath(cfg["registryRoot"]).parent
        files = {str(root / path): raw for path, raw in old["documents"].items()}

        class AbsolutePath(PurePosixPath):
            def absolute(self):
                return self

        def read(path, expected=None):
            raw = files[str(path)]
            if expected is not None:
                self.assertEqual(R.sha(raw), expected)
            return raw

        compiled = rt.compiled
        executions = Mock()

        def bootstrap(raw, path, name):
            module = compiled(raw, path, name)
            execute = module.execute
            module.Path = AbsolutePath
            module.private = read
            module.private_root = lambda _: None

            def traced(*args):
                executions()
                return execute(*args)
            module.execute = traced
            return module

        rt.compiled = bootstrap
        rt.bound_bytes = lambda bound: read(bound["path"], bound["sha256"])
        class Delivery:
            def __truediv__(self, path):
                return SimpleNamespace(read_bytes=lambda: V18.V12.blob(path))

        with patch.dict(R.sys.modules, {"fcntl": ModuleType("fcntl")}), patch.object(R, "DELIVERY", Delivery()):
            with R.historical_package(rt, cfg, cid) as (driver, broker, broker_config, preparer):
                self.assertTrue(callable(driver.validate))
                self.assertTrue(callable(broker.Broker.publish))
                self.assertTrue(callable(preparer.Worker.record))
                self.assertEqual(broker_config["containerId"], cid)
            executions.assert_called_once()
            files[str(root / prefix / "source/tools/semantic_provider_admission_v2/preparer_v2.py")] += b"\n"
            with self.assertRaisesRegex(RuntimeError, "BROKER_SOURCE_PACKAGE_DRIFT"):
                with R.historical_package(rt, cfg, cid):
                    self.fail("tampered closure executed")
            executions.assert_called_once()

    @unittest.skipUnless(os.environ.get("OUF_PROVIDER_OPERATION_NATIVE") == "1",
                         "set OUF_PROVIDER_OPERATION_NATIVE=1 under native Linux root")
    def test_real_ledger_verifies_every_historical_signature(self):
        fixture = V52.operation_fixture.Fixture()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.chain = fixture.root / "authorization"
        fixture.chain.mkdir(mode=0o700)
        previous = fixture.payload()
        fixture.put(1, previous)
        head_bytes = fixture.payload(sequence=2, supersedes=R.sha(previous))
        fixture.put(2, head_bytes)
        op = {"anchorBinding": fixture.anchor, "mandateRoot": str(fixture.ledger_root),
              "installationRef": "inst", "entityRef": "ent", "issuerRef": "installer",
              "mandatesModule": {"path": str(C.MANDATES)}}
        runtime = SimpleNamespace(bound_bytes=lambda _: b"", compiled=lambda *_: fixture.m)
        cfg = {"operation": op, "opensslBinding": fixture.ssl}
        head, entries, _ = R.chain(runtime, cfg, fixture.a, fixture.root, fixture.clock)
        self.assertEqual(head["sha256"], R.sha(head_bytes))
        self.assertEqual(entries[R.sha(previous)]["sequence"], 1)
        signature = fixture.chain / "1.signature.json"
        fixture.write(signature, (fixture.chain / "2.signature.json").read_bytes())
        with self.assertRaises(fixture.a.OperationDenied):
            R.chain(runtime, cfg, fixture.a, fixture.root, fixture.clock)


class Runbook(unittest.TestCase):
    def test_pinned_delivery_and_root_launcher(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "ops/vps/r3-reconcile.sh").read_text(encoding="utf-8")
        commit = re.search(r"^C=([0-9a-f]{40})$", script, re.M)[1]
        files = re.findall(r"^  fetch (\S+) ([0-9a-f]{64})$", script, re.M)
        expected = {"scripts/reconcile-semantic-provider-r3-epoch.py", R.BOOTSTRAP, "ops/vps/r3-settings.json",
                    R.MANDATES, R.overlay.RUNTIME, R.overlay.EPOCHS,
                    "tools/semantic_provider_r3/reconcile_prepared_epoch.py",
                    "tools/semantic_provider_r3/driver_denial_overlay_v16.py",
                    "tools/semantic_provider_r3/__init__.py",
                    "tools/semantic_provider_operation/__init__.py",
                    "tools/semantic_provider_operation/authorization.py",
                    "tools/semantic_lease_kernel_migration/__init__.py",
                    "tools/semantic_lease_kernel_migration/boot_dispatcher.py"}
        self.assertEqual(len(files), len(expected))
        self.assertEqual({p for p, _ in files}, expected)
        for path, digest in files:
            with self.subTest(file=path):
                if commit == "0" * 40:
                    raw = (root / path).read_bytes().replace(b"\r\n", b"\n")
                else:
                    raw = subprocess.check_output(["git", "-C", str(root), "show", f"{commit}:{path}"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        self.assertIn("$C != " + "0" * 40, script)
        self.assertIn('[[ $EUID == 0', script)
        self.assertIn('sha256sum --check --status', script)
        self.assertIn('-I -B "$D/scripts/reconcile-semantic-provider-r3-epoch.py" "$@"', script)
        self.assertIn("https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path", script)


if __name__ == "__main__":
    unittest.main()
