import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.snapshot_retention import retention as R


class Retention(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.policy = {**json.loads(R.POLICY.read_text()), "smallBytes": 8, "largeBytes": 64}
        for family in ("udp", "gateway", "semantic-provider-api", "peer-r3", "ca-trust"):
            for sequence in range(1, 5):
                top = self.root / f"{family}-v{sequence}"
                top.mkdir()
                for name, size in (("image.tar", 64), ("app.jar", 8), ("build.zip", 65),
                                   ("small.tar", 7), ("plan.json", 64)):
                    path = top / name
                    path.write_bytes(b"x" * size)
                    os.utime(path, (sequence + 1000000000,) * 2)

    def plan(self):
        return R.plan(self.root, self.policy, set())

    def test_retains_two_per_family_protected_and_small(self):
        proposal = self.plan()
        expected = {f"{family}-v{v}/{name}" for family in ("udp", "gateway") for v in (1, 2)
                    for name in ("app.jar", "image.tar", "build.zip")}
        self.assertEqual({r["path"] for r in proposal["remove"]}, expected)
        before = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")}
        receipt = R.apply(self.root, self.policy, set(), proposal["planSha256"])
        self.assertEqual(receipt["status"], "APPLIED")
        after = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")}
        self.assertEqual(after, before - expected)
        self.assertEqual(self.plan()["remove"], [])

    def test_drift_holds_entire_batch(self):
        proposal = self.plan()
        paths = [self.root / r["path"] for r in proposal["remove"]]
        paths[-1].write_bytes(b"replacement")
        receipt = R.apply(self.root, self.policy, set(), proposal["planSha256"])
        self.assertEqual((receipt["status"], receipt["removed"]), ("HELD", []))
        self.assertTrue(all(p.exists() for p in paths))

    def test_container_image_protects_whole_snapshot(self):
        path = self.root / "udp-v1/image.tar"
        ts = path.stat().st_mtime
        with tarfile.open(path, "w:") as archive:
            raw = json.dumps([{"Config": "a" * 64 + ".json"}]).encode()
            member = tarfile.TarInfo("manifest.json")
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        os.utime(path, (ts, ts))
        proposal = R.plan(self.root, self.policy, {"sha256:" + "a" * 64})
        self.assertFalse(any(r["path"].startswith("udp-v1/") for r in proposal["remove"]))
        self.assertTrue(any(r["path"].startswith("udp-v2/") for r in proposal["remove"]))
