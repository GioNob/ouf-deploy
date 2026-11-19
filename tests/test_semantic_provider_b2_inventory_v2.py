"""Task-40a: public projections run everywhere; real custody runs on Linux.

Portable fixtures replace only file IO, never projection or section handling.
Linux fixtures exercise the real no-follow/uid/mode/bounds reader. No VPS access.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/read-semantic-provider-b2-inputs-v2.py"
RUNBOOK = ROOT / "ops/vps/b2-read-v2.sh"
DRAFT = "tools/semantic_cohort_admission/cohort-draft"
SENTINEL = "SENTINEL-NEVER-PRINTED"
HASH = "a" * 64
OTHER = "b" * 64
POSIX = sys.platform == "linux"
SECTIONS = ("coordinatorSuccessor", "historicTemplates", "rootfs", "recipesV2",
            "preparationA2", "generationSourcesReceipt", "installedClosures")


def load():
    spec = importlib.util.spec_from_file_location("b2_inventory_v2", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def blob(path, commit="HEAD"):
    return subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{path}"],
                          capture_output=True, check=True).stdout


def fixture(m, root="/inventory"):
    data = {}

    def put(path, value):
        path = root + "/" + path
        raw = value if type(value) is bytes else m.canonical(value)
        data[path] = raw
        return {"path": path, "sha256": m.sha(raw)}

    triple = {"transactionId": HASH, "configurationHash": HASH, "leaseStructureHash": OTHER}
    owner = {"schema": "ouf.semantic-coordinated-owner-runtime.v1", "secret": SENTINEL,
        "journalFile": root + "/context/coordination-journal.json", "commonLockFile": "/run/boot.lock",
        "nftPath": "/usr/sbin/nft", "nftSha256": HASH, "expectedStructureHash": OTHER,
        "readBudgetSeconds": 5, "sourceHashes": {"ignored.py": SENTINEL},
        "kernel": {"tableName": "ouf_sem_provider", "secret": SENTINEL,
                   "providerFlows": [{"endpointRef": "adapter", "leaseSeconds": 30,
                                      "endpoint": SENTINEL, "hidden": SENTINEL}]},
        "dns": {"resolvers": ["46.38.225.230"], "resolverPort": 53, "hidden": SENTINEL}}
    owner["binding"] = {**triple, "configurationHash": m.sha(m.canonical(owner)), "secret": SENTINEL}
    owner_binding = put("context/coordinated-configuration.json", owner)
    boot_binding = put("context/boot-configuration.json", {"schema": "boot.v1", "journalFile": "/run/boot.json",
                                                            "kernel": owner["kernel"], "hidden": SENTINEL})
    put("context/coordination-journal.json", {"schema": "ouf.semantic-lease-coordination.v1", **triple,
        "state": "QUIESCED", "leaseAuthorized": False, "leaseAddresses": [SENTINEL], "hidden": SENTINEL})
    put("context/boot-profile.json", {"schema": "ouf.semantic-coordinated-boot-profile.v1",
        "coordinatedConfiguration": owner_binding["path"], "coordinatedConfigurationHash": owner_binding["sha256"],
        "bootConfiguration": boot_binding["path"], "bootConfigurationHash": boot_binding["sha256"],
        "bootGuardFile": "/frozen/guard.py", "bootGuardHash": HASH, "profile": "successor", "mode": "READ",
        "hidden": SENTINEL})
    put("context/second/extra.json", {"schema": "extra.v1", "payload": SENTINEL})
    put("context/second/third/ignored.json", {"payload": SENTINEL})
    put("install/receipt.json", {"schema": "installation.v1", "secret": SENTINEL})
    candidate = {"tableName": "candidate_table", "networkBindings": [{"interface": "eth0", "bridge": "oufsp-int",
        "mac": "02:00:00:00:00:02", "ipv4": "172.21.0.3", "workloadRef": "adapter", "bindingRef": "internal",
        "leaseGuard": {"configurationHash": HASH, "tableName": "ouf_sem_provider", "key": SENTINEL},
        "signingKeyBinding": {"path": "/never/read.key", "sha256": HASH}, "secret": SENTINEL}],
        "transport": [{"endpoint": SENTINEL, "payload": SENTINEL}]}
    put("registry/old/preparer-template.json", {"schema": "ouf.semantic-admission-preparer-template.v1",
        "candidate": candidate, "kernel": owner["kernel"], "coordinationBinding": {**triple, "hidden": SENTINEL},
        "coordinationJournal": "/historic/journal.json", "lockFile": "/run/boot.lock", "hostNetworkNamespace": 4026531840,
        "commands": {**dict.fromkeys(m.COMMANDS, "/usr/bin/public"), "hidden": SENTINEL},
        "commandHashes": {**dict.fromkeys(m.COMMANDS, HASH), "hidden": SENTINEL},
        "pythonPath": "/usr/bin/python3.13", "pythonHash": HASH, "budgetSeconds": 5, "secret": SENTINEL})
    put("rootfs/result.json", {"schema": "ouf.semantic-provider-b1-rootfs-evidence.v1", "status": "PREPARED",
        "rootfsLimits": {"maxBytes": 1000, "maxEntries": 10, "maxDepth": 5, "secret": SENTINEL},
        "roles": {role: {"containerId": cid, "imageId": "sha256:" + HASH, "secret": SENTINEL,
            "effectiveSeal": {"schema": "ouf.semantic-rootfs-seal.v1", "sha256": HASH, "entries": 5,
                              "bytes": 100, "payload": SENTINEL}} for role, cid in zip(m.ROLES, (HASH, OTHER))},
        "hidden": SENTINEL})
    for role, cid in zip(m.ROLES, (HASH, OTHER)):
        for name in ("template", "launch", "context", "policy"):
            value = {"schema": name + ".v1", "secret": SENTINEL}
            if name == "context":
                value.update(containerId=cid, bundleParent="/run/containerd", networkNamespaceName=None,
                             rootfsPath="/var/lib/docker/rootfs/" + cid)
            if name == "policy":
                value["expectedOci"] = {"process": {"env": [SENTINEL]}, "z": 1, "a": 2}
            put(f"recipes/{role}/{name}.json", value)
    successors = {"containers": [{"containerId": cid, "image": "sha256:" + HASH, "transaction": "tx-" + role,
        "manifestDigest": "sha256:" + OTHER, "configDigest": "sha256:" + HASH, "status": "created",
        "hidden": SENTINEL} for role, cid in zip(m.ROLES, (HASH, OTHER))], "secret": SENTINEL}
    put("a2/successors.json", successors)
    put("a2/manifest.json", {"manifest": {"schema": "ouf.semantic-provider-preparation-a.manifest.v1",
        "successors": successors, "secret": SENTINEL}, "planSha256": HASH, "hidden": SENTINEL})
    put("generation.json", {"schema": "ouf.discovery-generation-source-read.v1", "status": "COMPLETE", "secret": SENTINEL})
    put("source/tools/a.py", ("# " + SENTINEL).encode())
    put("source/scripts/b.py", ("# " + SENTINEL).encode())
    argv = [part for name, path in (("coordinator-context", "context"), ("coordinator-install", "install"),
        ("historic-registry", "registry"), ("rootfs-result", "rootfs/result.json"), ("recipes-root", "recipes"),
        ("a2-root", "a2"), ("generation-receipt", "generation.json"), ("historic-source", "source"))
        for part in ("--" + name, root + "/" + path)]
    return data, m.arguments(argv)


def virtual_files(data):
    def listing(root, *, depth=2, suffix=None, complete=False):
        return sorted(path for path in data if path.startswith(root + "/")
                      and len(PurePosixPath(path).relative_to(root).parts) <= depth
                      and (suffix is None or path.endswith(suffix)))
    return listing


class Projections(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.data, self.args = fixture(self.m)
        self.m.read = Mock(side_effect=lambda path, **_: self.data[str(path)])
        self.m.files = Mock(side_effect=virtual_files(self.data))

    def report(self):
        return self.m.collect(self.args)

    def test_all_sections_and_canonical_digests(self):
        report = self.report()
        self.assertEqual(report["sectionErrors"], [], report)
        rows = report["coordinatorSuccessor"]["documents"]
        self.assertEqual(len(rows), 6)
        owner = next(row for row in rows if "configurationHashMatches" in row)
        self.assertTrue(owner["configurationHashMatches"])
        self.assertEqual(owner["kernel"]["providerFlows"], [{"endpointRef": "adapter", "leaseSeconds": 30}])
        self.assertEqual(owner["sourceHashes"], {"count": 1})
        profile = next(row for row in rows if "bindings" in row)
        self.assertTrue(profile["bindings"]["coordinatedConfiguration"]["matchesObservedFile"])
        journal = next(row for row in rows if row["schema"] == "ouf.semantic-lease-coordination.v1")
        self.assertEqual((journal["state"], journal["leaseAuthorized"]), ("QUIESCED", False))
        template = report["historicTemplates"]["templates"][0]
        self.assertEqual(set(template["coordinationBinding"]), {"transactionId", "configurationHash", "leaseStructureHash"})
        self.assertEqual(template["hostNetworkNamespace"], 4026531840)
        self.assertEqual(template["candidate"]["transport"], {"flows": 1, "digest": self.m.sha(
            self.m.canonical([{ "endpoint": SENTINEL, "payload": SENTINEL}]))})
        self.assertEqual(set(template["candidate"]["networkBindings"][0]),
                         {"interface", "bridge", "mac", "ipv4", "workloadRef", "bindingRef", "leaseGuard"})
        self.assertEqual(report["rootfs"]["roles"]["adapter"]["effectiveSeal"]["bytes"], 100)
        self.assertEqual(report["rootfs"]["rootfsLimits"], {"maxBytes": 1000, "maxEntries": 10, "maxDepth": 5})
        policy = report["recipesV2"]["roles"]["adapter"]["policy"]
        expected = json.loads(self.data[policy["path"]])["expectedOci"]
        self.assertEqual(policy["expectedOciSha256"], self.m.sha(json.dumps(
            expected, sort_keys=True, separators=(",", ":")).encode()))
        self.assertIsNone(report["recipesV2"]["roles"]["adapter"]["context"]["networkNamespaceName"])
        self.assertTrue(report["preparationA2"]["rolesMatch"])
        self.assertEqual(report["preparationA2"]["manifest.json"]["manifest"]["schema"],
                         "ouf.semantic-provider-preparation-a.manifest.v1")
        self.assertEqual(report["preparationA2"]["manifest.json"]["roles"]["southbound"]["transaction"], "tx-southbound")
        self.assertFalse(report["generationSourcesReceipt"]["matchesExpected"])
        self.assertEqual(len(report["installedClosures"]["files"]), 2)
        for name in self.m.COUNTERS:
            self.assertEqual(report[name], 0)

    def test_sentinel_every_section_and_no_binding_targets_read(self):
        before = dict(self.data)
        output = json.dumps(self.report())
        self.assertNotIn(SENTINEL, output)
        self.assertNotIn("read.key", output)
        self.assertNotIn('"endpoint"', output)
        self.assertEqual(self.data, before)
        for call in self.m.read.call_args_list:
            self.assertIn(str(call.args[0]), self.data)

    def test_drift_remains_visible_per_section(self):
        before = self.report()
        for path, raw in list(self.data.items()):
            self.data[path] = raw + b"\n"
        after = self.report()
        self.assertEqual(after["sectionErrors"], [])
        for section in SECTIONS:
            with self.subTest(section=section):
                self.assertNotEqual(before[section], after[section])
        profile = next(row for row in after["coordinatorSuccessor"]["documents"] if "bindings" in row)
        self.assertFalse(profile["bindings"]["coordinatedConfiguration"]["matchesObservedFile"])
        self.m.RECEIPT_SHA256 = self.m.sha(self.data[self.args.generation_receipt])
        self.assertTrue(self.report()["generationSourcesReceipt"]["matchesExpected"])
        self.data["/inventory/a2/successors.json"] = self.data["/inventory/a2/successors.json"].replace(b"tx-adapter", b"tx-drift")
        self.assertFalse(self.report()["preparationA2"]["rolesMatch"])

    def test_each_section_is_independent_and_sanitizes_exceptions(self):
        targets = ("coordinator_section", "templates_section", "rootfs_section", "recipes_section",
                   "preparation_section", "receipt_section", "sources_section")
        for section, target in zip(SECTIONS, targets):
            for error in (self.m.Held("PRIVATE_CUSTODY_REQUIRED"), OSError(13, SENTINEL), ValueError(SENTINEL)):
                with self.subTest(section=section, error=type(error).__name__), patch.object(
                        self.m, target, side_effect=error):
                    report = self.report()
                    self.assertEqual(report["sectionErrors"], [section])
                    self.assertNotIn(SENTINEL, json.dumps(report))

    def test_nested_objects_in_scalar_whitelist_fail_closed(self):
        path = "/inventory/recipes/adapter/context.json"
        value = json.loads(self.data[path])
        value["rootfsPath"] = {"payload": SENTINEL}
        self.data[path] = self.m.canonical(value)
        report = self.report()
        self.assertEqual(report["recipesV2"]["error"], "ABSOLUTE_PATH_REQUIRED")
        self.assertNotIn(SENTINEL, json.dumps(report))

    def test_optional_receipt_and_strict_json(self):
        self.args.generation_receipt = None
        self.assertEqual(self.report()["generationSourcesReceipt"]["provided"], False)
        for raw, code in ((b'{"x":1,"x":2}', "DUPLICATE_JSON_KEY"), (b'{"x":NaN}', "FINITE_JSON_REQUIRED"),
                          (b"[]", "OBJECT_REQUIRED"), (b"not json", "JSON_REQUIRED")):
            self.data[self.args.rootfs_result] = raw
            self.assertEqual(self.report()["rootfs"]["error"], code)


@unittest.skipUnless(POSIX, "Linux real custody requires uid, dir_fd and O_NOFOLLOW")
class NativeCustody(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.m.REQUIRED_UID = os.geteuid()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data, self.args = fixture(self.m, self.root.as_posix())
        for path, raw in self.data.items():
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(raw)
            target.chmod(0o600)
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)

    def test_real_inventory_no_writes_or_subprocesses(self):
        before = {str(path): (path.read_bytes(), path.stat().st_mode) for path in self.root.rglob("*") if path.is_file()}
        with patch("subprocess.run", side_effect=AssertionError("no subprocess")):
            report = self.m.collect(self.args)
        self.assertEqual(report["sectionErrors"], [], report)
        self.assertNotIn(SENTINEL, json.dumps(report))
        self.assertEqual(before, {str(path): (path.read_bytes(), path.stat().st_mode)
                                  for path in self.root.rglob("*") if path.is_file()})

    def test_custody_failures_in_every_section(self):
        paths = ("context/coordinated-configuration.json", "registry/old/preparer-template.json", "rootfs/result.json",
                 "recipes/adapter/context.json", "a2/successors.json", "generation.json", "source/tools/a.py")
        for section, relative in zip(SECTIONS, paths):
            path = self.root / relative
            with self.subTest(section=section):
                path.chmod(0o666)
                try:
                    report = self.m.collect(self.args)
                    self.assertEqual(report["sectionErrors"], [section])
                    self.assertEqual(report[section]["error"], "NOT_WRITABLE_BY_OTHERS_REQUIRED")
                finally:
                    path.chmod(0o600)

    def test_private_modes_directory_and_ownership(self):
        path = Path(self.args.rootfs_result)
        path.chmod(0o644)
        self.assertEqual(self.m.collect(self.args)["rootfs"]["error"], "PRIVATE_CUSTODY_REQUIRED")
        (self.root / "context").chmod(0o755)
        self.assertEqual(self.m.collect(self.args)["coordinatorSuccessor"]["error"], "PRIVATE_CUSTODY_REQUIRED")
        self.m.REQUIRED_UID = os.geteuid() + 1
        with self.assertRaisesRegex(self.m.Held, "ROOT_OWNERSHIP_REQUIRED"):
            self.m.read(self.args.rootfs_result)

    def test_symlink_leaf_and_ancestor_refused(self):
        path = Path(self.args.rootfs_result)
        path.unlink()
        path.symlink_to(self.root / "generation.json")
        self.assertEqual(self.m.collect(self.args)["rootfs"]["error"], "OS_ERROR")
        link = self.root / "linked"
        link.symlink_to(self.root / "recipes", target_is_directory=True)
        with self.assertRaises(OSError):
            self.m.read(str(link / "adapter/context.json"))
        (self.root / "context/linked.json").symlink_to(self.root / "generation.json")
        self.assertEqual(self.m.collect(self.args)["coordinatorSuccessor"]["error"], "SYMLINK_REFUSED")

    def test_fifo_key_and_bounds_refused_before_content_read(self):
        fifo = self.root / "pipe.json"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(self.m.Held, "REGULAR_FILE_REQUIRED"):
            self.m.read(str(fifo))
        key = self.root / "signing-key.json"
        key.write_text(SENTINEL)
        with self.assertRaisesRegex(self.m.Held, "KEY_FILE_REFUSED"), patch.object(self.m.os, "open") as opening:
            self.m.read(str(key))
        opening.assert_not_called()
        self.m.LIMIT = 8
        with self.assertRaisesRegex(self.m.Held, "FILE_TOO_LARGE"):
            self.m.read(self.args.rootfs_result)
        self.m.MAX_FILES = 1
        with self.assertRaisesRegex(self.m.Held, "DIRECTORY_TOO_LARGE"):
            self.m.files(self.args.coordinator_context)

    def test_racing_file_change_is_reported(self):
        original = os.read
        path = Path(self.args.rootfs_result)

        def changing(fd, size):
            raw = original(fd, size)
            if raw:
                path.chmod(0o400)
            return raw

        with patch.object(self.m.os, "read", side_effect=changing):
            self.assertEqual(self.m.collect(self.args)["rootfs"]["error"], "FILE_CHANGED_DURING_READ")


class Contract(unittest.TestCase):
    def test_absolute_cli_and_root_isolated_gate(self):
        m = load()
        _, args = fixture(m)
        argv = [part for name, value in vars(args).items() if value is not None
                for part in ("--" + name.replace("_", "-"), value)]
        for bad in ("relative", "/safe/../else", "//host/path"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.arguments([*argv, "--rootfs-result", bad])
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), *argv], capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "ROOT_ISOLATED_PYTHON_REQUIRED")

    def test_public_receipt_reproduces_private_producer_bytes(self):
        # Public JSON is indented; the producer used canonical JSON plus LF.
        # See docs/OUF_DISCOVERY_GENERATION_SOURCES_20261109.md:27.
        m = load()
        public = blob("evidence/discovery-generation-sources-read-operator-20261109.json")
        producer = m.canonical(json.loads(public)) + b"\n"
        self.assertEqual(len(producer), 7224)
        self.assertEqual(m.sha(producer), m.RECEIPT_SHA256)
        self.assertNotEqual(m.sha(public), m.RECEIPT_SHA256)

    def test_installed_closures_compare_to_all_cohort_draft_blobs_off_vps(self):
        m = load()
        manifest = json.loads(blob(DRAFT + "/sources.json"))["sourceHashes"]
        data = {"/installed/" + path: blob(DRAFT + "/" + path) for path in manifest}
        with patch.object(m, "read", side_effect=lambda path, **_: data[path]), patch.object(
                m, "files", side_effect=virtual_files(data)):
            reported = m.sources_section("/installed")["files"]
            self.assertEqual({path.removeprefix("/installed/"): digest for path, digest in reported.items()}, manifest)
            path = next(iter(data))
            data[path] += b"# drift\n"
            self.assertNotEqual(m.sources_section("/installed")["files"][path], manifest[path.removeprefix("/installed/")])

    def test_runbook_pin_contract(self):
        runbook = RUNBOOK.read_text()
        commit = re.search(r"^C=([0-9a-f]{40})$", runbook, re.M).group(1)
        reader = re.search(r"^R=([0-9a-f]{64})$", runbook, re.M).group(1)
        if reader == "0" * 64 or commit == "0" * 40:
            self.assertEqual((commit, reader), ("0" * 40, "0" * 64))
            self.skipTest("D-001: Claude pins C/R after commit; both placeholders verified")
        self.assertEqual(reader, hashlib.sha256(blob(SCRIPT.relative_to(ROOT).as_posix())).hexdigest())
        self.assertEqual(reader, hashlib.sha256(blob(SCRIPT.relative_to(ROOT).as_posix(), commit)).hexdigest())

    def test_runbook_and_reader_surface(self):
        runbook = RUNBOOK.read_text()
        self.assertIn("python3.13 -I -B", runbook)
        for word in ("--apply", "docker start", "nft add", "nft delete", "rm -"):
            self.assertNotIn(word, runbook)
        reader = SCRIPT.read_text()
        for word in ("import subprocess", "import socket", "import urllib", "write_bytes(", "write_text(", "O_WRONLY", "O_RDWR"):
            self.assertNotIn(word, reader)


if __name__ == "__main__":
    unittest.main()
