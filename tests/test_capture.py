"""PET A5/R-041 portable capture, resume and off-host integrity tests."""
from contextlib import nullcontext
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from capture import apply as writer
from capture import verify as reader
from capture.contract import Held, canonical, custody, digest_file, registry, schema, validate
from capture.host import Host
from capture.plan import make_plan

FAKE = ROOT / "tests/fixtures/capture/commands.py"
COMMIT = "1" * 40
SECRET = "fixture-private-content-F643"
spec = importlib.util.spec_from_file_location("capture_cli", ROOT / "scripts/capture.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class TestHost(Host):
    def __init__(self, cfg, root):
        super().__init__(cfg)
        self.root = root
        self.unit_dirs = [root / "systemd"]
        self.sudoers = root / "sudoers"
        self.real_age = False

    def binary(self, key):
        if self.real_age and key == "age":
            return shutil.which("age")
        return key

    def process(self, key, args, **streams):
        if key == "age" and self.real_age:
            argv = [self.binary(key), *args]
        else:
            if key == "docker":
                args = ["--host", "unix://" + self.cfg["dockerSocket"], *args]
            argv = [sys.executable, "-I", "-B", str(FAKE), str(self.root), "nice", "-n", "19", key, *args]
        return subprocess.Popen(argv, stderr=subprocess.DEVNULL, **streams)

    def lock(self, directory):
        return nullcontext()

    def boot_id(self):
        return "fixture-boot"


class CaptureTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir()
        self.source = self.root / "sources"
        self.source.mkdir()
        (self.source / "config").write_text(SECRET)
        self.private = self.source / "keys"
        self.private.mkdir()
        (self.private / "never-transfer").write_text(SECRET)
        self.profile = self.root / "private-profile"
        self.entries = registry()
        owners = [dict(id=k, custodian="operator", rotation="rotate on restore", consumers=["fixture"])
                  for k, e in self.entries.items() if e.get("kind") and e["secrets"]]
        exe = dict(path="/fixture/bin", sha256="0" * 64)
        def binding(key):
            return {"id": "capture." + key}
        active = {"profile", "postgres", "iam", "etcd", "docker", "volumes", "images",
                  "secrets", "r3-keys", "manifest"}
        self.cfg = dict(schema="ouf.capture-profile.v1", recipients=["age1" + "q"*58],
            outputDir=str(self.output), maxFileMiB=1, maxTotalGiB=1, minFreeMiB=1, docker=exe,
            dockerSocket=str(self.root / "engine.sock"), age=exe, nice=exe, inventory=binding("docker"),
            images=binding("images"), postgres=dict(**binding("postgres"), container="fixture-pg",
                user="reader", database="example", omitTableData=[], databases=[
                    dict(**binding("iam" if n == "example" else "postgres"), name=n)
                    for n in ("example", "template0", "template1")]),
            etcd=dict(**binding("etcd"), container="fixture-kv"),
            paths=[dict(**binding("secrets"), path=str(self.source))],
            excludePaths=[dict(**binding("r3-keys"), path=str(self.private))],
            units=[dict(**binding("units"), pattern="ouf-fixture.service")],
            volumes=[dict(**binding("volumes"), name="fixture-volume")],
            absent=[dict(id=k, reason="NOT_INSTALLED") for k, e in self.entries.items()
                    if e.get("kind") and k.removeprefix("capture.") not in active], secretOwners=owners)
        self.profile.write_bytes(canonical(self.cfg))
        self.host = TestHost(self.cfg, self.root)
        # Windows fixture paths and custody replace Linux root ownership only.
        self.patch_profile = patch.object(writer, "profile", side_effect=lambda p, _: json.loads(p.read_bytes()))
        self.patch_profile.start()
        self.addCleanup(self.patch_profile.stop)
        # Observe the command doubles once. Repeated fault cases replay this exact host observation.
        self.observation = self.host.inventory()
        self.host.inventory = lambda: copy.deepcopy(self.observation)

    def plan(self):
        return make_plan(self.host, self.cfg, self.entries, self.profile, COMMIT)

    def apply(self, digest):
        return writer.apply(self.host, self.cfg, self.entries, self.profile, COMMIT, digest)

    def test_a5_measure_and_classification(self):
        big = self.source / "large"
        big.write_bytes(bytes(1024 ** 2 + 1))
        plan, digest = self.plan()
        self.assertEqual(plan["reasons"], [])
        self.assertEqual(sorted(x["reason"] for x in plan["excluded"] if x["reason"] == "MAX_FILE"), ["MAX_FILE"])
        self.assertNotIn(str(big), plan["files"])
        self.assertNotIn(str(self.private / "never-transfer"), plan["files"])
        self.assertEqual([], list(self.output.iterdir()))
        # A replacement endpoint with unchanged inventory is outside plan identity.
        socket = Path(self.cfg["dockerSocket"])
        socket.touch()
        socket.unlink()
        socket.touch()
        self.assertEqual(digest, self.plan()[1])
        self.observation["volumes"].append(["new-volume", "local", "local", "/fixture/unknown"])
        self.assertIn("CAPTURE_UNCLASSIFIED", self.plan()[0]["reasons"])
        self.observation["images"]["image-1"]["size"] = 2**31
        self.assertIn("CAPTURE_TOTAL_CAP", self.plan()[0]["reasons"])
        self.host.sudoers.mkdir()
        (self.host.sudoers / "new-rule").touch()
        self.host.unit_dirs[0].mkdir()
        (self.host.unit_dirs[0] / "ouf-surprise.timer").touch()
        self.observation["volumes"].pop()
        self.assertIn("CAPTURE_UNCLASSIFIED", self.plan()[0]["reasons"])

    def test_a5_plan_cli_redaction(self):
        from argparse import Namespace
        args = Namespace(mode="plan", profile=self.profile, measure=False)
        with patch.object(cli.sys, "platform", "linux"), patch.object(os, "geteuid", return_value=0, create=True), \
             patch.object(os, "setpriority", create=True), patch.object(os, "PRIO_PROCESS", 0, create=True), \
             patch.object(cli, "profile", return_value=self.cfg), patch.object(cli, "Host", return_value=self.host), \
             patch.object(os, "umask"), patch.dict(os.environ, {"OUF_CAPTURE_COMMIT": COMMIT, "ENV_FIXTURE": SECRET}):
            output, code = cli.run(args)
            self.assertEqual(code, 0)
            self.assertNotIn(SECRET, json.dumps(output))
            self.assertNotIn(str(self.private), json.dumps(output))
            args.measure = True
            result, code = cli.run(args)
            self.assertEqual(set(result), {"estimatedBytes", "familyBytes", "excludedItems"})

    def test_a5_storage_volume_under_host_inclusion(self):
        raw = self.source / "engine-volume"
        raw.mkdir()
        (raw / "object").write_bytes(b"excluded fixture")
        self.observation["volumes"][0][3] = str(raw)
        self.cfg["volumes"][0]["id"] = "capture.storage"
        self.cfg["absent"] = [r for r in self.cfg["absent"] if r["id"] != "capture.storage"]
        self.cfg["absent"].append(dict(id="capture.volumes", reason="NO_INSTANCES"))
        plan, _ = self.plan()
        self.assertEqual(plan["reasons"], [])
        self.assertNotIn(str(raw / "object"), plan["files"])
        self.assertIn(str(raw), plan["inventory"]["exclusionRefs"].values())

    def test_a5_hash_pins_and_socket_type(self):
        binary = self.root / "tool"
        binary.write_bytes(b"fixture")
        binary.chmod(0o700)
        host = Host({**self.cfg, **{k: dict(path=str(binary), sha256=digest_file(binary))
                                    for k in ("docker", "nice", "age")}})
        with patch("capture.host.custody") as check:
            host.args("docker", ["ps"])
            check.assert_called_with(self.cfg["dockerSocket"], stat.S_ISSOCK)
            binary.write_bytes(b"changed")
            for key in ("age", "docker", "nice"):
                with self.assertRaisesRegex(Held, "PIN_CHANGED"):
                    host.binary(key)

    def test_a5_profile_schema_and_socket_custody(self):
        cfg = copy.deepcopy(self.cfg)
        cfg.update(outputDir="/fixture/output", dockerSocket="/fixture/engine.sock")
        cfg["paths"][0]["path"] = "/fixture/config"
        cfg["excludePaths"][0]["path"] = "/fixture/config/private"
        validate(cfg, schema("capture-profile"))
        cfg["dockerSocket"] = {"path": "/fixture/engine.sock", "inode": 7}
        with self.assertRaises(Held):
            validate(cfg, schema("capture-profile"))
        target = self.root / "socket"
        mode, uid, parent_mode = stat.S_IFSOCK | 0o660, 0, stat.S_IFDIR | 0o755
        def observed(path):
            return SimpleNamespace(st_uid=uid if path == target else 0,
                                   st_mode=mode if path == target else parent_mode)
        with patch.object(type(target), "lstat", observed):
            custody(target, stat.S_ISSOCK)
            for mode, uid, parent_mode in [(stat.S_IFREG | 0o600, 0, stat.S_IFDIR | 0o755),
                                            (stat.S_IFSOCK | 0o666, 0, stat.S_IFDIR | 0o755),
                                            (stat.S_IFSOCK | 0o660, 1, stat.S_IFDIR | 0o755),
                                            (stat.S_IFSOCK | 0o660, 0, stat.S_IFDIR | 0o775)]:
                with self.assertRaises(Held):
                    custody(target, stat.S_ISSOCK)

    def test_a5_database_data_exclusions(self):
        self.cfg["postgres"]["omitTableData"] = [
            dict(id="capture.logical-exclusions", database="example", schema="fixture", table="sessions")]
        self.cfg["absent"] = [r for r in self.cfg["absent"] if r["id"] != "capture.logical-exclusions"]
        self.profile.write_bytes(canonical(self.cfg))
        plan, digest = self.plan()
        self.assertEqual(plan["reasons"], [])
        self.assertIn("D064", {e["reason"] for e in plan["excluded"]})
        self.apply(digest)
        raw = (self.output / "postgres.age").read_bytes().split(b"\n", 1)[1]
        dump = self.root / "dump"
        dump.write_bytes(bytes(b ^ 17 for b in raw))
        reader.sql_structure(dump, 2)

    def test_a5_plan_drift_and_space(self):
        _, digest = self.plan()
        self.observation["networks"][0][1] = "changed"
        with self.assertRaisesRegex(Held, "PLAN_CHANGED"):
            self.apply(digest)
        _, digest = self.plan()
        with patch.object(shutil, "disk_usage", return_value=type("Space", (), {"free": 0})()):
            with self.assertRaisesRegex(Held, "CAPTURE_FREE_SPACE"):
                self.apply(digest)

    def test_a5_verify_and_tampering(self):
        _, digest = self.plan()
        manifest = self.apply(digest)
        self.assertNotIn(SECRET, canonical(manifest).decode())
        self.assertEqual(set(reader.verify(self.output, self.entries)), set(manifest["families"]))
        self.assertEqual(self.apply(digest), manifest)
        img = self.output / "images-1.age"
        raw = img.read_bytes()
        img.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaisesRegex(Held, "CIPHER_MISMATCH"):
            reader.verify(self.output, self.entries)
        img.write_bytes(raw)
        img.unlink()
        with self.assertRaisesRegex(Held, "CIPHER_MISMATCH"):
            reader.verify(self.output, self.entries)
        del manifest["archives"]["images-1"]
        del manifest["families"]["images-1"]
        with self.assertRaisesRegex(Held, "MISSING_IMAGE_FAMILY"):
            reader.check_manifest(manifest, self.entries)

    def test_a5_interrupt_each_checkpoint(self):
        plan, digest = self.plan()
        for number in range(1, len(plan["families"]) + 1):
            with self.subTest(after=number):
                self.crash_worker(digest, str(number))
                journal = json.loads((self.output / "manifest.partial.json").read_bytes())
                before = {k: (self.output / (k + ".age")).stat().st_mtime_ns for k in journal["archives"]}
                self.apply(digest)
                for k, timestamp in before.items():
                    self.assertEqual(timestamp, (self.output / (k + ".age")).stat().st_mtime_ns)
                for p in self.output.iterdir():
                    p.unlink()

    def crash_worker(self, digest, fault):
        (self.root / "observation.json").write_bytes(canonical(self.observation))
        result = subprocess.run([sys.executable, "-I", "-B", __file__, str(self.root), digest, fault],
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors="replace"))

    def test_a5_interrupted_encryption(self):
        plan, digest = self.plan()
        self.crash_worker(digest, "encrypt")
        work = self.output / ".capture-work"
        self.assertTrue((work / "cipher.part").is_file())
        plain = self.root / "etcd-private/db"
        self.assertTrue(plain.exists())
        manifest = self.apply(digest)
        self.assertEqual(set(manifest["cleanupEvents"]), {"PARTIAL_CIPHERTEXT_REMOVED", "ETCD_PLAINTEXT_REMOVED"})
        self.assertFalse(plain.exists() or work.exists())
        self.assertEqual(len(manifest["archives"]), len(plan["families"]))

    def test_a5_unjournaled_rename(self):
        _, digest = self.plan()
        self.crash_worker(digest, "rename")
        partial = json.loads((self.output / "manifest.partial.json").read_bytes())
        self.assertEqual(partial["archives"], {})
        orphan = self.output / "postgres.age"
        self.assertTrue(orphan.is_file())
        orphan.write_bytes(b"uncommitted")
        self.apply(digest)
        reader.verify(self.output, self.entries)

    def test_a5_snapshot_cleanup_before_drift_denial(self):
        _, digest = self.plan()
        self.crash_worker(digest, "encrypt")
        self.observation["networks"][0][1] = "changed"
        with self.assertRaisesRegex(Held, "PLAN_CHANGED"):
            self.apply(digest)
        self.assertFalse((self.root / "etcd-private/db").exists())
        partial = json.loads((self.output / "manifest.partial.json").read_bytes())
        self.assertIn("ETCD_PLAINTEXT_REMOVED", partial["cleanupEvents"])

    def test_a5_clear_structures(self):
        _, digest = self.plan()
        manifest = self.apply(digest)
        for name, row in manifest["archives"].items():
            plain = self.root / "clear-structure"
            raw = (self.output / (name + ".age")).read_bytes().split(b"\n", 1)[1]
            plain.write_bytes(bytes(b ^ 17 for b in raw))
            reader.structure(name, plain, row["counts"])
            plain.unlink()

    def test_a5_offhost_identity_stream(self):
        _, digest = self.plan()
        self.apply(digest)
        key = self.root / "fixture-identity"
        key.touch()
        real_popen = subprocess.Popen
        def fake_age(argv, **kwargs):
            return real_popen([sys.executable, "-I", "-B", str(FAKE), str(self.root),
                               "decrypt", *argv[1:]], **kwargs)
        scratch = self.root / "offhost-private"
        scratch.mkdir()
        with patch.object(reader.subprocess, "Popen", side_effect=fake_age), \
             patch.object(tempfile, "tempdir", str(scratch)):
            self.assertEqual(len(reader.verify(self.output, self.entries, key)), 5)
            path = self.output / "manifest.json"
            doc = json.loads(path.read_bytes())
            doc["archives"]["etcd"]["plainSha256"] = "0" * 64
            path.write_bytes(canonical(doc))
            with self.assertRaisesRegex(Held, "PLAIN_MISMATCH"):
                reader.verify(self.output, self.entries, key)
        self.assertEqual(list(scratch.iterdir()), [])

    def test_a5_generated_age_identity(self):
        if not (shutil.which("age") and shutil.which("age-keygen")):
            if os.environ.get("OUF_REQUIRE_TEST_AGE") == "1":
                self.fail("age and age-keygen required by CI")
            self.skipTest("age and age-keygen unavailable offline")
        key = self.root / "identity"
        subprocess.run(["age-keygen", "-o", str(key)], check=True, capture_output=True)
        self.cfg["recipients"] = [subprocess.check_output(["age-keygen", "-y", str(key)], text=True).strip()]
        self.profile.write_bytes(canonical(self.cfg))
        self.host.real_age = True
        _, digest = self.plan()
        self.apply(digest)
        self.assertEqual(len(reader.verify(self.output, self.entries, key)), 5)


def crash_worker(root, digest, fault):
    cfg = json.loads((root / "private-profile").read_bytes())
    host = TestHost(cfg, root)
    host.inventory = lambda: json.loads((root / "observation.json").read_bytes())
    publish, produce = writer.publish, writer.produce

    def checkpoint(path, doc):
        if fault == "rename" and doc["archives"]:
            os._exit(73)
        publish(path, doc)
        if str(len(doc["archives"])) == fault:
            os._exit(73)

    def payload(host, cfg, plan, family, sink, remaining, digest):
        if fault == "encrypt" and family == "etcd":
            plain = root / "etcd-private/db"
            plain.parent.mkdir(mode=0o700)
            plain.write_bytes(b"fixture snapshot")
            sink.write(plain.read_bytes())
            sink.pipe.flush()
            os._exit(73)
        produce(host, cfg, plan, family, sink, remaining, digest)

    with patch.object(writer, "profile", return_value=cfg), patch.object(writer, "publish", checkpoint), \
         patch.object(writer, "produce", payload):
        writer.apply(host, cfg, registry(), root / "private-profile", COMMIT, digest)


if __name__ == "__main__":
    crash_worker(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
