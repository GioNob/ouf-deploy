import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TESTS = Path(__file__).resolve().parent
SCRIPT = TESTS.parent / "scripts" / "reboot-receipt.py"
FIXTURE = TESTS / "fixtures" / "reboot-receipt" / "fake_tool.py"
KERNEL = "6.1.0-test"
PRE_BOOT = "11111111-1111-4111-8111-111111111111"
POST_BOOT = "22222222-2222-4222-8222-222222222222"

# Reject attempted writes anywhere before the OS can perform them, including
# outside the fixture tree compared after observation.
AUDIT = """
import os, sys
def guard(event, args):
    write = event == 'open' and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
    if (write and args[0] != os.devnull) or event in ('os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.chmod',
                          'os.link', 'os.symlink', 'os.truncate', 'os.utime', 'os.chown'):
        raise AssertionError('filesystem mutation: ' + event)
sys.addaudithook(guard)
exec(compile(sys.stdin.buffer.read(), '<stdin>', 'exec'))
"""


def seal(doc):
    payload = {k: v for k, v in doc.items() if k != "digest"}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    doc["digest"] = hashlib.sha256(raw).hexdigest()
    return doc


class RebootReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.root = Path(temp.name)
        cls.bin = cls.root / "bin"
        cls.bin.mkdir()
        source = FIXTURE.read_text(encoding="utf-8")
        (cls.bin / FIXTURE.name).write_text(source, encoding="utf-8")
        for name in ("docker", "systemctl", "dpkg-query", "apt-mark", "r3-status"):
            if os.name == "nt":
                wrapper = f'@"{sys.executable}" -I -B "%~dp0fake_tool.py" {name} %*\n'
                (cls.bin / (name + ".cmd")).write_text(wrapper, encoding="utf-8")
            else:
                script = cls.bin / name
                script.write_text(f"#!{sys.executable}\n" + source, encoding="utf-8")
                script.chmod(0o755)
        cls.proc = cls.root / "proc"
        (cls.proc / "sys/kernel/random").mkdir(parents=True)
        (cls.proc / "sys/kernel/osrelease").write_text(KERNEL)
        (cls.proc / "uptime").write_text("42.5 12.0")
        cls.boot = cls.root / "boot"
        (cls.boot / "grub").mkdir(parents=True)
        (cls.boot / ("vmlinuz-" + KERNEL)).touch()
        (cls.boot / "grub/grub.cfg").write_text(
            'if [ "${next_entry}" ]; then\n  set default="${next_entry}"\nelse\n'
            '  set default="${saved_entry}"\nfi\n')
        (cls.boot / "grub/grubenv").write_text("saved_entry=menu-id\n")
        cls.env = {**os.environ, "PATH": str(cls.bin) + os.pathsep + os.environ["PATH"],
                   "HOME": temp.name, "TMPDIR": temp.name, "TEMP": temp.name,
                   "TMP": temp.name, "PYTHONDONTWRITEBYTECODE": "1"}
        cls.pre = cls.capture("pre", PRE_BOOT)
        cls.post = cls.capture("post", POST_BOOT)

    @classmethod
    def capture(cls, phase, boot_id, *, extra=(), env=None, code=0, audit=False):
        (cls.proc / "sys/kernel/random/boot_id").write_text(boot_id)

        def snapshot():
            return {p.relative_to(cls.root): (p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
                    for p in cls.root.rglob("*")}

        before = snapshot()
        program = ["-c", AUDIT] if audit else ["-"]
        argv = [sys.executable, "-I", "-B", *program, "observe", "--phase", phase,
                "--proc-root", str(cls.proc), "--boot-root", str(cls.boot), "--root", str(cls.root),
                "--receipts-dir", str(cls.root), "--unit", "runner.service",
                "--r3-status", 'r3-status "status marker"', *extra]
        # R3 runs in a new epoch after the reboot: the post receipt observes epoch 3.
        env = {**(env or cls.env), "FIXTURE_EPOCH": "3" if phase == "post" else "2"}
        result = subprocess.run(argv, cwd=cls.root, input=SCRIPT.read_bytes(), capture_output=True,
                                env=env, timeout=45)
        assert result.returncode == code, (result.stdout, result.stderr)
        assert before == snapshot(), "observation changed the fixture tree"
        assert b"private-fixture-sentinel" not in result.stdout + result.stderr
        return json.loads(result.stdout)

    def compare(self, post, *, flags=(), code=0, resign=True):
        first, last = (self.root / f"{phase}.json" for phase in ("pre", "post"))
        first.write_text(json.dumps(self.pre), encoding="utf-8")
        last.write_text(json.dumps(seal(post) if resign else post), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "compare", str(first),
                                 str(last), "--managed", "service-a", "--expect-r3", "STARTED", *flags],
                                cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, code, (result.stdout, result.stderr))
        doc = json.loads(result.stdout)
        self.assertEqual(doc["schema"], "ouf.reboot-comparison.v1")
        self.assertEqual(doc["status"], "FAIL" if code else "PASS")
        return {c["id"] for c in doc["checks"] if c["status"] != "PASS"}

    def test_stdin_receipts_comparison_and_no_writes(self):
        observed = self.capture("post", POST_BOOT, audit=True)
        for phase, doc in (("pre", self.pre), ("post", observed)):
            self.assertEqual(doc["schema"], "ouf.reboot-receipt.v1")
            self.assertEqual(doc["phase"], phase)
            self.assertEqual(doc["digest"], seal(doc.copy())["digest"])
            self.assertEqual(doc["uptimeSeconds"], 42.5)
            self.assertEqual(doc["grubDefault"], "menu-id")
            self.assertEqual(doc["bootImages"], ["vmlinuz-" + KERNEL])
            self.assertEqual(doc["packages"]["kernel"], {"linux-image-" + KERNEL + ":amd64": "1"})
            self.assertEqual(doc["containers"]["spare"]["networks"], ["net-a"])
            self.assertGreater(doc["freeBytes"]["receipts"], 0)
            self.assertTrue(all(c["status"] == "PASS" for c in doc["checks"]))
            self.assertNotIn("Config.Env", json.dumps(doc))
        self.assertEqual(self.compare(observed), set())

    def test_comparison_failures(self):
        cases = [
            (("bootId",), PRE_BOOT, "bootId"),
            (("kernelRelease",), "unexpected", "kernelRelease"),
            (("containers", "service-a", "cid"), "d" * 64, "managed.service-a.cid"),
            (("containers", "service-a", "imageId"), "sha256:" + "c" * 64, "managed.service-a.imageId"),
            (("containers", "service-a", "state"), "exited", "managed.service-a.state"),
            (("containers", "spare", "state"), "running", "unmanaged.spare"),
            (("containers", "spare", "StartedAt"), "later", "unmanaged.spare"),
            (("units", "runner.service", "ActiveState"), "inactive", "unit.runner.service"),
            (("units",), {}, "unit.runner.service"),
            (("r3", "roles", "adapter", "state"), "STOPPED", "r3.adapter"),
            (("r3", "roles", "southbound", "live"), False, "r3.southbound"),
            (("r3", "roles", "adapter", "epoch"), 2, "r3.adapter"),
            (("packages", "docker", "containerd.io:amd64"), "4", "docker.packages"),
            (("holds",), ["docker-ce"], "docker.holds"),
        ]
        for path, value, reason in cases:
            with self.subTest(reason=reason):
                doc = copy.deepcopy(self.post)
                parent = doc
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = value
                self.assertIn(reason, self.compare(doc, code=1))

    def test_kernel_target_and_docker_exception(self):
        doc = copy.deepcopy(self.post)
        doc["kernelRelease"] = "new-release"
        doc["packages"]["docker"]["docker-ce:amd64"] = "new-version"
        self.assertFalse(self.compare(doc, flags=("--expect-kernel", "new-release", "--allow-docker-change")))

    def test_digest_before_semantic_checks(self):
        doc = dict(self.post, bootId=PRE_BOOT)
        self.assertEqual(self.compare(doc, resign=False, code=1), {"post.digest"})

    def test_ambiguous_json(self):
        first, last = (self.root / f"{phase}.json" for phase in ("pre", "post"))
        first.write_text(json.dumps(self.pre), encoding="utf-8")
        raw = json.dumps(self.post)
        last.write_text('{"bootId":"other",' + raw[1:], encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "compare",
                                 str(first), str(last)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn({"id": "post.receipt", "status": "FAIL", "observed": {"code": "INVALID_DATA"}},
                      json.loads(result.stdout)["checks"])

    def test_r3_timeout(self):
        doc = self.capture("post", POST_BOOT, extra=("--timeout", "1"),
                           env={**self.env, "FIXTURE_DELAY": "1"}, code=1)
        self.assertIn({"id": "r3", "status": "FAIL", "observed": {"code": "TIMEOUT"}}, doc["checks"])
        self.assertIn("post.r3", self.compare(doc, code=1))

    def test_missing_proc_and_optional_grub(self):
        missing = str(self.root / "missing")
        doc = self.capture("pre", PRE_BOOT, extra=("--proc-root", missing, "--grub-config", missing), code=1)
        self.assertEqual(doc["grubDefault"], "unreadable")
        self.assertIn({"id": "bootId", "status": "FAIL", "observed": {"code": "ENOENT"}}, doc["checks"])


if __name__ == "__main__":
    unittest.main()
