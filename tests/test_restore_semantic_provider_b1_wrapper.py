"""Task-26: governed B1 wrapper restore. Native tests need root (CI: sudo)."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/restore-semantic-provider-b1-wrapper.py"
LAUNCHER = ROOT / "scripts/deliver-restore-semantic-provider-b1-wrapper.sh"
spec = importlib.util.spec_from_file_location("restore_b1", SCRIPT)
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
NATIVE = os.environ.get("OUF_B1_RESTORE_NATIVE") == "1" and hasattr(os, "geteuid") and os.geteuid() == 0
A_CID = "a" * 64
B_CID = "b" * 64


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Contract(unittest.TestCase):
    def base(self):
        return ["--plan", "--b1-root", "/x", "--wrapper", "/w", "--installed-wrapper-sha256", "1" * 64,
                "--prior-wrapper-sha256", "2" * 64, "--prior-source-sha256", "3" * 64,
                "--prior-configuration-sha256", "4" * 64, "--python-sha256", "5" * 64, "--lock", "/l",
                "--docker", "/d", "--docker-sha256", "6" * 64, "--docker-socket", "unix:///run/docker.sock",
                "--output-root", "/o", "--output-name", "r", "--successor", A_CID, "--successor", B_CID]

    def test_valid_arguments(self):
        self.assertEqual(R.arguments(self.base()).successor, [A_CID, B_CID])

    def test_rejections(self):
        cases = [
            lambda a: a.__setitem__(a.index("--python-sha256") + 1, "BAD"),
            lambda a: a.__setitem__(len(a) - 1, A_CID),
            lambda a: a.__setitem__(a.index("--docker-socket") + 1, "/run/docker.sock"),
            lambda a: a.extend(["--plan-sha256", "7" * 64]),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                argv = self.base()
                mutate(argv)
                with self.assertRaises(SystemExit):
                    R.arguments(argv)

    def test_launcher_two_state_pin_and_closure(self):
        launcher = LAUNCHER.read_text()
        placeholders = ("__PIN_COMMIT__" in launcher, "__PIN_CONTROLLER_SHA256__" in launcher)
        self.assertIn(placeholders, ((True, True), (False, False)))
        if not any(placeholders):
            self.assertNotIn("__PIN_", launcher)
            self.assertEqual(len(re.findall(r"^commit='[0-9a-f]{40}'$", launcher, re.M)), 1)
            pins = re.findall(r"^controller_sha='([0-9a-f]{64})'$", launcher, re.M)
            head = subprocess.check_output(["git", "show", "HEAD:scripts/restore-semantic-provider-b1-wrapper.py"],
                                           cwd=ROOT)
            self.assertEqual(pins, [sha(head)])
        for name, digest in re.findall(r"^fetch (\S+) ([0-9a-f]{64})$", launcher, re.M):
            raw = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)
            self.assertEqual(sha(raw), digest, name)


@unittest.skipUnless(NATIVE, "set OUF_B1_RESTORE_NATIVE=1 under native Linux root")
class Native(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/run", prefix="ouf-b1-restore-")
        self.addCleanup(self.temp.cleanup)
        t = Path(self.temp.name)
        os.chmod(t, 0o755)
        self.t = t
        self.python = os.path.realpath(sys.executable)
        self.source = t / "v4-runtime.py"
        self.write(self.source, b"# v4 runtime\n", 0o600)
        self.config = t / "v4-configuration.json"
        self.write(self.config, json.dumps({"schema": "ouf.semantic-docker-runtime-adapter.v4"}).encode(), 0o600)
        self.prior = (f'#!/bin/sh\nexec {self.python} -I -B {self.source} '
                      f'--configuration {self.config} "$@"\n').encode()
        self.installed = (f'#!/bin/sh\nexec {self.python} -I -B {t}/v5.py '
                          f'--configuration {t}/v5.json "$@"\n').encode()
        self.wrapper = t / "wrapper"
        self.write(self.wrapper, self.installed, 0o755)
        self.b1 = t / "b1"
        for d in (self.b1, self.b1 / "switch", self.b1 / "arming"):
            d.mkdir(mode=0o700)
        self.write(self.b1 / "switch/prior-runtime-wrapper.sh", self.prior, 0o600)
        claim = {"schema": "ouf.semantic-provider-runtime-switch-claim.v1", "state": "SWITCHING",
                 "priorWrapperHash": sha(self.prior), "proposedWrapperHash": sha(self.installed)}
        self.write(self.b1 / "switch/runtime-switch-claim.json", json.dumps(claim).encode(), 0o600)
        self.lock = t / "guard.lock"
        self.write(self.lock, b"", 0o600)
        self.state = t / "docker-state.json"
        self.docker_state(0)
        self.docker = t / "docker"
        self.write(self.docker, (f"#!/bin/sh\ncid=$4\n"
                                 f"{self.python} -I -c 'import json,sys; s=json.load(open(sys.argv[1])); "
                                 f"print(json.dumps([dict(s, Id=sys.argv[2])]))' {self.state} $cid\n").encode(), 0o755)
        self.out = t / "out"
        self.out.mkdir(mode=0o700)

    def write(self, path, raw, mode):
        path.write_bytes(raw)
        os.chmod(path, mode)

    def docker_state(self, pid, started="0001-01-01T00:00:00Z"):
        doc = {"Image": "sha256:" + "c" * 64, "Config": {}, "HostConfig": {}, "Mounts": [], "RestartCount": 0,
               "State": {"Status": "created" if pid == 0 else "running", "Running": pid != 0,
                         "Pid": pid, "StartedAt": started}}
        self.write(self.state, json.dumps(doc).encode(), 0o644)

    def argv(self, *mode):
        return [*mode, "--b1-root", str(self.b1), "--wrapper", str(self.wrapper),
                "--installed-wrapper-sha256", sha(self.installed), "--prior-wrapper-sha256", sha(self.prior),
                "--prior-source-sha256", sha(self.source.read_bytes()),
                "--prior-configuration-sha256", sha(self.config.read_bytes()),
                "--python-sha256", sha(Path(self.python).read_bytes()), "--lock", str(self.lock),
                "--docker", str(self.docker), "--docker-sha256", sha(self.docker.read_bytes()),
                "--docker-socket", "unix:///run/docker.sock", "--output-root", str(self.out),
                "--output-name", "restore-v1", "--successor", A_CID, "--successor", B_CID]

    def run_controller(self, *mode):
        result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), *self.argv(*mode)],
                                capture_output=True, timeout=120)
        return result.returncode, json.loads(result.stdout.decode().strip().splitlines()[-1])

    def plan(self):
        code, report = self.run_controller("--plan")
        self.assertEqual((code, report["status"]), (0, "PLAN_READY"), report)
        return report

    def test_plan_has_no_writes_and_apply_restores_exact_prior_bytes(self):
        report = self.plan()
        self.assertFalse((self.out / "restore-v1").exists())
        self.assertEqual(self.wrapper.read_bytes(), self.installed)
        code, result = self.run_controller("--apply", "--plan-sha256", report["planSha256"])
        self.assertEqual((code, result["status"]), (0, "SEMANTIC_PROVIDER_B1_WRAPPER_RESTORED"), result)
        self.assertEqual(self.wrapper.read_bytes(), self.prior)
        self.assertEqual((self.out / "restore-v1/prior-runtime-wrapper.sh").read_bytes(), self.installed)
        self.assertTrue((self.out / "restore-v1/restore-result.json").is_file())
        self.assertEqual(result["containerLifecycleOperations"], 0)
        # The original B1 claim root is evidence and stays untouched.
        self.assertEqual(sorted(p.name for p in (self.b1 / "switch").iterdir()),
                         ["prior-runtime-wrapper.sh", "runtime-switch-claim.json"])
        code, again = self.run_controller("--plan")
        self.assertEqual((code, again["reason"]), (1, "NOTHING_TO_RESTORE"))

    def test_changed_digest_writes_nothing(self):
        self.plan()
        code, result = self.run_controller("--apply", "--plan-sha256", "0" * 64)
        self.assertEqual((code, result["reason"]), (1, "RESTORE_PLAN_DIGEST_CHANGED"))
        self.assertFalse((self.out / "restore-v1").exists())
        self.assertEqual(self.wrapper.read_bytes(), self.installed)

    def test_progress_and_drift_are_held_before_any_write(self):
        cases = {
            "B2_ARMING_PRESENT_RESTORE_DENIED": lambda: self.write(self.b1 / "arming/1.json", b"{}", 0o600),
            "SUCCESSOR_PROGRESSED_RESTORE_DENIED": lambda: self.docker_state(4242, "2026-11-14T00:00:00Z"),
            "PRIOR_SOURCE_DRIFT": lambda: self.write(self.source, b"# changed\n", 0o600),
            "INSTALLED_WRAPPER_DRIFT": lambda: self.write(self.wrapper, b"#!/bin/sh\nexit 3\n", 0o755),
        }
        for reason, mutate in cases.items():
            with self.subTest(reason=reason):
                self.setUp()
                mutate()
                if reason == "PRIOR_SOURCE_DRIFT":
                    argv = self.argv("--plan")
                    argv[argv.index("--prior-source-sha256") + 1] = sha(b"# v4 runtime\n")
                    result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), *argv],
                                            capture_output=True, timeout=120)
                    report = json.loads(result.stdout.decode().strip().splitlines()[-1])
                else:
                    _, report = self.run_controller("--plan")
                self.assertEqual((report["status"], report["reason"]), ("HELD", reason))
                self.assertFalse((self.out / "restore-v1").exists())


if __name__ == "__main__":
    unittest.main()
