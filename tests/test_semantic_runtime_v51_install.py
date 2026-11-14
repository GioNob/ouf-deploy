"""Task-29b: governed v5.1 install and its restore. Native tests need root (CI: sudo).

No Docker daemon: docker inspect is a fixture script. runc is a fixture that
only answers --version. OpenSSL, root custody, flock and the unchanged switch
primitive run natively; the Ed25519 key is generated inside each fixture.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = "scripts/install-semantic-runtime-v51.py"
RESTORE = "scripts/restore-semantic-runtime-v51-wrapper.py"
RUNBOOKS = {INSTALL: ROOT / "ops/vps/runtime-v51-install.sh", RESTORE: ROOT / "ops/vps/runtime-v51-restore.sh"}
FETCH = re.compile(r"^  fetch (\S+) ([0-9a-f]{64})$", re.M)
NATIVE = os.environ.get("OUF_RUNTIME_V51_INSTALL_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_RUNTIME_V51_INSTALL_NATIVE requires Linux root:root; refusing to skip")
B1_PLAN = "e" * 64


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module(ROOT / "tools/semantic_runtime_v51_install/common.py", "v51_install_common")
I = module(ROOT / INSTALL, "v51_install_controller")
R = module(ROOT / RESTORE, "v51_restore_controller")


def blob(name):
    return subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)


class Contract(unittest.TestCase):
    def install_argv(self):
        return ["--plan", "--wrapper", "/w", "--wrapper-sha256", "1" * 64, "--b1-root", "/b",
                "--b1-plan-sha256", "2" * 64, "--acceptance-root", "/a", "--mandate-root", "/m", "--lock", "/l",
                "--docker", "/d", "--docker-sha256", "3" * 64, "--docker-socket", "unix:///run/docker.sock",
                "--output-root", "/o", "--output-name", "v51"]

    def restore_argv(self):
        return ["--plan", "--v51-root", "/v", "--b1-root", "/b", "--b1-plan-sha256", "2" * 64, "--wrapper", "/w",
                "--installed-wrapper-sha256", "1" * 64, "--prior-wrapper-sha256", "4" * 64, "--lock", "/l",
                "--docker", "/d", "--docker-sha256", "3" * 64, "--docker-socket", "unix:///run/docker.sock",
                "--output-root", "/o", "--output-name", "r"]

    def test_arguments(self):
        self.assertEqual(I.arguments(self.install_argv()).output_name, "v51")
        self.assertEqual(R.arguments(self.restore_argv()).output_name, "r")
        for parse, base in ((I.arguments, self.install_argv), (R.arguments, self.restore_argv)):
            for mutate in (lambda a: a.__setitem__(a.index("--b1-plan-sha256") + 1, "BAD"),
                           lambda a: a.__setitem__(a.index("--docker-socket") + 1, "/run/docker.sock"),
                           lambda a: a.extend(["--plan-sha256", "7" * 64]),
                           lambda a: a.__setitem__(0, "--apply")):
                argv = base()
                mutate(argv)
                with self.subTest(parse=parse, argv=argv), self.assertRaises(SystemExit):
                    parse(argv)
        argv = self.restore_argv()
        argv[argv.index("--prior-wrapper-sha256") + 1] = "1" * 64
        with self.assertRaises(SystemExit):
            R.arguments(argv)

    def test_closure_pins_are_the_unchanged_v51_sources(self):
        for name, pin in C.CLOSURE.items():
            self.assertEqual(sha(blob(name)), pin, name)
        self.assertEqual(sha(blob(C.V5_SOURCE)), C.V5_SOURCE_SHA256)

    def test_runbooks_pin_state_and_delivery_hashes(self):
        for script, runbook in RUNBOOKS.items():
            text = runbook.read_text()
            pins = re.findall(r"^C=([0-9a-f]{40})$", text, re.M)
            self.assertEqual(len(pins), 1, runbook)
            rows = FETCH.findall(text)
            names = [name for name, _ in rows]
            self.assertIn(script, names)
            self.assertIn("tools/semantic_runtime_v51_install/common.py", names)
            self.assertEqual(len(names), len(set(names)))
            for name, digest in rows:
                self.assertEqual(sha(blob(name)), digest, name)
        install = dict(FETCH.findall(RUNBOOKS[INSTALL].read_text()))
        for name, pin in C.CLOSURE.items():
            self.assertEqual(install[name], pin)

    def test_restore_runbook_expects_the_wrapper_install_writes(self):
        install = RUNBOOKS[INSTALL].read_text()
        restore = RUNBOOKS[RESTORE].read_text()
        snapshots = re.search(r"^S=(\S+)$", install, re.M)[1]
        name = re.search(r"--output-name (\S+)\n\)", install)[1]
        self.assertIn("V51=$S/" + name, restore)
        python = "/usr/bin/python3.13"
        wrapper = C.wrapper_bytes(python, snapshots + "/" + name)
        self.assertIn("--installed-wrapper-sha256 " + sha(wrapper), restore)
        prior = re.search(r"--wrapper-sha256 ([0-9a-f]{64})", install)[1]
        self.assertIn("--prior-wrapper-sha256 " + prior, restore)


@unittest.skipUnless(NATIVE, "set OUF_RUNTIME_V51_INSTALL_NATIVE=1 under native Linux root")
class Native(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/run", prefix="ouf-v51-install-")
        self.addCleanup(self.temp.cleanup)
        t = self.t = Path(self.temp.name)
        os.chmod(t, 0o755)
        self.python = os.path.realpath(sys.executable)
        self.openssl = os.path.realpath("/usr/bin/openssl")
        self.deliver()
        self.M = module(ROOT / C.MANDATES, "v51_install_test_mandates")
        self.B = module(ROOT / "tests/test_semantic_b1_acceptance.py", "v51_install_test_b1_fixture")
        self.key = t / "EPHEMERAL-TEST-KEY.pem"
        self.native("genpkey", "-algorithm", "Ed25519", "-out", str(self.key))
        public = self.native("pkey", "-in", str(self.key), "-pubout", "-outform", "DER")[12:].hex()
        gen2 = self.B.fixture()
        gen2["generation"] = 2
        self.anchor = t / "anchor.json"
        self.write(self.anchor, encoded({
            "schema": self.M.B1B2_ANCHOR_SCHEMA, "installationRef": gen2["installationRef"],
            "entityRef": gen2["entityRef"], "basePolicy": {"path": str(t / "unopened-base.json"), "sha256": "c" * 64},
            "authorityProfile": {"path": str(t / "unopened-authority.json"), "sha256": "d" * 64},
            "keys": [{"keyRef": "test-key", "issuerRef": "test-issuer", "publicKey": public,
                      "roles": ["RUNTIME_ARMING", "ARTIFACT_ACCEPTANCE"], "notBefore": 0,
                      "expiresAt": 4102444800, "state": "ACTIVE"}]}))
        gen2["trustPolicy"] = self.pin(self.anchor)
        self.gen2 = gen2
        self.ledger = self.directory(t / "mandates")
        self.runc = t / "runc"
        self.write(self.runc, b"#!/bin/sh\nexit 0\n", 0o755)
        for name in ("driver.py", "broker.py"):
            self.write(t / name, ("# fixture " + name + "\n").encode())
        self.directory(t / "registry")
        self.directory(t / "state")
        self.cids = sorted(row["containerId"] for row in gen2["roles"].values())
        self.b1_install()
        self.issue(gen2)
        self.lock = t / "guard.lock"
        self.write(self.lock, b"")
        self.docker_state = t / "docker-state.json"
        self.successors(0)
        self.docker = t / "docker"
        self.write(self.docker, (f"#!/bin/sh\n{self.python} -I -c 'import json,sys; s=json.load(open(sys.argv[1])); "
                                 f"print(json.dumps([dict(s, Id=sys.argv[2])]))' {self.docker_state} $4\n").encode(),
                   0o755)
        self.out = self.directory(t / "out")

    # --- fixture helpers -------------------------------------------------
    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        os.chmod(path, mode)

    def directory(self, path):
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        return path

    def pin(self, path):
        return {"path": str(path), "sha256": sha(path.read_bytes())}

    def native(self, *args):
        return subprocess.run([self.openssl, *args], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout

    def deliver(self):
        """The runbooks' exact file lists, copied with the custody the runbook gives them."""
        self.delivery = self.t / "delivery"
        self.delivery.mkdir(mode=0o700)
        names = {name for runbook in RUNBOOKS.values() for name, _ in FETCH.findall(runbook.read_text())}
        for name in names:
            target = self.delivery / name
            for parent in reversed(target.relative_to(self.delivery).parents):
                if not (self.delivery / parent).exists():
                    (self.delivery / parent).mkdir(mode=0o700)
            shutil.copyfile(ROOT / name, target)
            os.chmod(target, 0o600)

    def b1_install(self):
        t = self.t
        b1 = self.b1 = self.directory(t / "b1")
        for part in ("source", "source/tools", "source/tools/semantic_runtime_v5",
                     "source/tools/semantic_b1b2_authority", "arming", "switch"):
            self.directory(b1 / part)
        for name in (C.V5_SOURCE, "tools/semantic_runtime_v5/arming_verifier.py",
                     "tools/semantic_b1b2_authority/authority.py"):
            self.write(b1 / "source" / name, (ROOT / name).read_bytes())
        acceptance = self.directory(t / "b1-acceptance")
        self.write(acceptance / "manifest.json", encoded(self.gen2))
        ssl = {**self.pin(Path(self.openssl)), "version": self.native("version").decode().split()[1]}
        self.v5_config = {
            "schema": C.V5_SCHEMA, "sourceHash": C.V5_SOURCE_SHA256,
            "runtimePath": str(self.runc), "runtimeSha256": sha(self.runc.read_bytes()),
            "pythonPath": self.python, "pythonSha256": sha(Path(self.python).read_bytes()),
            "driverPath": str(t / "driver.py"), "driverSha256": sha((t / "driver.py").read_bytes()),
            "admissionPath": str(t / "broker.py"), "admissionSha256": sha((t / "broker.py").read_bytes()),
            "registryRoot": str(t / "registry"), "runtimeStateRoot": str(t / "state"),
            "acceptance": self.pin(acceptance / "manifest.json"), "b1b2TrustPolicy": self.pin(self.anchor),
            "armingRoot": str(b1 / "arming"),
            "armingVerifierPath": str(b1 / "source/tools/semantic_runtime_v5/arming_verifier.py"),
            "armingVerifierSha256": sha((b1 / "source/tools/semantic_runtime_v5/arming_verifier.py").read_bytes()),
            "b1b2AuthorityModule": self.pin(b1 / "source/tools/semantic_b1b2_authority/authority.py"),
            "opensslBinding": ssl, "armingIssuerRef": "test-issuer",
            "candidates": {cid: {"phase": "INACTIVE", "bundleParents": [str(t / "bundles")]} for cid in self.cids}}
        self.config_raw = encoded(self.v5_config) + b"\n"
        self.write(b1 / "runtime-configuration.json", self.config_raw)
        self.b1_wrapper = (f'#!/bin/sh\nexec {self.python} -I -B {b1}/source/{C.V5_SOURCE} '
                           f'--configuration {b1}/runtime-configuration.json "$@"\n').encode()
        self.wrapper = t / "ouf-semantic-admitted-v2"
        self.write(self.wrapper, self.b1_wrapper, 0o755)
        self.write(b1 / "result.json", encoded({
            "status": C.B1_STATUS, "planSha256": B1_PLAN, "configurationSha256": sha(self.config_raw),
            "wrapperAfter": {"path": str(self.wrapper), "sha256": sha(self.b1_wrapper)},
            "containerIds": self.cids}) + b"\n")

    def sign(self, raw):
        header = {"schema": self.M.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": "test-key",
                  "role": "ARTIFACT_ACCEPTANCE", "issuerRef": "test-issuer",
                  "installationRef": self.gen2["installationRef"], "entityRef": self.gen2["entityRef"],
                  "payloadHash": sha(raw)}
        frame = self.t / "test-signing-frame"
        self.write(frame, self.M.signing_bytes(raw, header))
        signature = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(frame)).hex()
        frame.unlink()
        return encoded({**header, "signature": signature}) + b"\n"

    def issue(self, base, **changes):
        manifest = copy.deepcopy(base)
        manifest.update(generation=3, issuedAt=1794691492,
                        softwareClosure={"sourceCommit": C.CLOSURE_COMMIT, "files": dict(C.CLOSURE)})
        manifest.update(changes)
        raw = encoded(manifest)
        root = self.t / "acceptance-v51-g3"
        if root.exists():
            shutil.rmtree(root)
        self.acceptance = self.directory(root)
        signature = self.sign(raw)
        name = sha(raw) + ".ARTIFACT_ACCEPTANCE.json"
        self.write(root / "manifest.json", raw)
        self.write(root / name, signature)
        self.write(root / "result.json", encoded({
            "schema": "ouf.semantic-provider-acceptance-v51-issuance.v1", "status": C.ACCEPTANCE_STATUS,
            "planSha256": "f" * 64, "payloadSha256": sha(raw),
            "manifest": {"path": str(root / "manifest.json"), "sha256": sha(raw)},
            "signature": {"path": str(root / name), "sha256": sha(signature)},
            "privateKeysRead": 1, "signaturesIssued": 1, "startAuthorized": False, "leaseAuthorized": False}) + b"\n")

    def successors(self, pid, started="0001-01-01T00:00:00Z"):
        doc = {"Image": "sha256:" + "c" * 64, "Config": {}, "HostConfig": {}, "Mounts": [], "RestartCount": 0,
               "State": {"Status": "created" if pid == 0 else "running", "Running": pid != 0, "Pid": pid,
                         "StartedAt": started}}
        self.write(self.docker_state, encoded(doc), 0o644)

    # --- controllers -----------------------------------------------------
    def common(self):
        return ["--b1-root", str(self.b1), "--b1-plan-sha256", B1_PLAN, "--wrapper", str(self.wrapper),
                "--lock", str(self.lock), "--docker", str(self.docker), "--docker-sha256",
                sha(self.docker.read_bytes()), "--docker-socket", "unix:///run/docker.sock",
                "--output-root", str(self.out)]

    def install(self, *mode):
        return self.run_script(INSTALL, *mode, *self.common(), "--wrapper-sha256", sha(self.b1_wrapper),
                               "--acceptance-root", str(self.acceptance), "--mandate-root", str(self.ledger),
                               "--output-name", "v51")

    def restore(self, *mode):
        installed = C.wrapper_bytes(self.python, self.out / "v51")
        return self.run_script(RESTORE, *mode, *self.common(), "--v51-root", str(self.out / "v51"),
                               "--installed-wrapper-sha256", sha(installed),
                               "--prior-wrapper-sha256", sha(self.b1_wrapper), "--output-name", "restore-v1")

    def run_script(self, script, *argv):
        result = subprocess.run([self.python, "-I", "-B", str(self.delivery / script), *argv],
                                capture_output=True, timeout=180)
        lines = result.stdout.decode().strip().splitlines()
        self.assertTrue(lines, result.stderr.decode()[-2000:])
        return result.returncode, json.loads(lines[-1])

    def planned(self, runner):
        code, report = runner("--plan")
        self.assertEqual((code, report["status"]), (0, "PLAN_READY"), report)
        return report

    def assert_untouched(self):
        self.assertFalse((self.out / "v51").exists())
        self.assertEqual(self.wrapper.read_bytes(), self.b1_wrapper)
        self.assertEqual(list((self.b1 / "switch").iterdir()), [])

    # --- tests -----------------------------------------------------------
    def test_plan_is_reproducible_apply_installs_and_restore_returns_to_v5(self):
        report = self.planned(self.install)
        self.assert_untouched()
        self.assertEqual(self.planned(self.install)["planSha256"], report["planSha256"])
        config = report["configuration"]
        self.assertEqual(config["schema"], C.V51_SCHEMA)
        self.assertEqual(config["acceptance"]["sha256"], report["acceptance"]["payloadSha256"])
        self.assertEqual(config["b1b2Anchor"], self.v5_config["b1b2TrustPolicy"])
        self.assertEqual(config["mandateRoot"], str(self.ledger))
        for key in I.COPIED:
            self.assertEqual(config[key], self.v5_config[key], key)
        self.assertEqual((report["privateKeysRead"], report["containerLifecycleOperations"]), (0, 0))

        code, result = self.install("--apply", "--plan-sha256", report["planSha256"])
        self.assertEqual((code, result["status"]), (0, "SEMANTIC_RUNTIME_V51_INSTALLED_INACTIVE"), result)
        root = self.out / "v51"
        installed = C.wrapper_bytes(self.python, root)
        self.assertEqual(self.wrapper.read_bytes(), installed)
        self.assertEqual(result["wrapperAfter"]["sha256"], sha(installed))
        self.assertEqual(result["priorConfigurationSha256"], sha(self.config_raw))
        self.assertEqual(sorted(p.name for p in (root / "switch").iterdir()),
                         ["prior-runtime-wrapper.sh", "runtime-switch-claim.json", "runtime-switch-receipt.json"])
        self.assertEqual((root / "switch/prior-runtime-wrapper.sh").read_bytes(), self.b1_wrapper)
        self.assertEqual(list((root / "arming").iterdir()), [])
        self.assertEqual(json.loads((root / "result.json").read_bytes())["status"], result["status"])
        for name, pin in C.CLOSURE.items():
            self.assertEqual(sha((root / "source" / name).read_bytes()), pin)
        self.assertEqual(subprocess.run([str(self.wrapper), "--version"], capture_output=True).returncode, 0)
        # B1 evidence is untouched; a second apply is refused before any write.
        self.assertEqual((self.b1 / "runtime-configuration.json").read_bytes(), self.config_raw)
        self.assertEqual(list((self.b1 / "switch").iterdir()), [])
        code, again = self.install("--plan")
        self.assertEqual((code, again["reason"], again["doNotRerunApply"]), (1, "V51_OUTPUT_ALREADY_EXISTS", True))

        undo = self.planned(self.restore)
        code, restored = self.restore("--apply", "--plan-sha256", undo["planSha256"])
        self.assertEqual((code, restored["status"]), (0, "SEMANTIC_RUNTIME_V51_WRAPPER_RESTORED"), restored)
        self.assertEqual(self.wrapper.read_bytes(), self.b1_wrapper)
        self.assertEqual((self.out / "restore-v1/prior-runtime-wrapper.sh").read_bytes(), installed)
        code, nothing = self.restore("--plan")
        self.assertEqual((code, nothing["reason"]), (1, "NOTHING_TO_RESTORE"))

    def test_changed_digest_writes_nothing(self):
        self.planned(self.install)
        code, result = self.install("--apply", "--plan-sha256", "0" * 64)
        self.assertEqual((code, result["reason"]), (1, "V51_PLAN_DIGEST_CHANGED"))
        self.assert_untouched()

    def test_drift_and_invalid_inputs_are_held_without_writes(self):
        cases = {
            "B1_WRAPPER_DRIFT": lambda: self.write(self.wrapper, self.b1_wrapper.replace(b" -B ", b" -B  "), 0o755),
            "B1_V5_CONFIGURATION_DRIFT": lambda: self.write(self.b1 / "runtime-configuration.json",
                                                            self.config_raw + b"\n"),
            "B1_V5_ARMING_PRESENT": lambda: self.write(self.b1 / "arming/1.json", b"{}"),
            "SUCCESSOR_EVER_STARTED": lambda: self.successors(4242, "2026-11-15T00:00:00Z"),
            "V51_MANDATE_LEDGER_INVALID": lambda: self.write(self.ledger / "unexpected", b"x"),
            "ACCEPTANCE_V51_CONTEXT_DRIFT": lambda: self.issue(self.gen2, creation={**self.gen2["creation"], "declaredGaps": []}),
            "ACCEPTANCE_V51_CLOSURE_MISMATCH": lambda: self.issue(self.gen2, softwareClosure={
                "sourceCommit": "0" * 40, "files": dict(C.CLOSURE)}),
            "GUARD_LOCK_NOT_EMPTY": lambda: self.write(self.lock, b"held"),
        }
        for reason, mutate in cases.items():
            with self.subTest(reason=reason):
                self.setUp()
                mutate()
                code, report = self.install("--plan")
                self.assertEqual((code, report["status"], report["reason"]), (1, "HELD", reason), report)
                if reason == "ACCEPTANCE_V51_CONTEXT_DRIFT":
                    self.assertEqual(report["diagnosis"], {"differingFields": ["creation"]})
                self.assert_untouched()

    def test_ledger_invalid_between_plan_and_apply_is_held_before_any_write(self):
        report = self.planned(self.install)
        self.write(self.ledger / "unexpected", b"x")
        code, result = self.install("--apply", "--plan-sha256", report["planSha256"])
        self.assertEqual((code, result["reason"]), (1, "V51_MANDATE_LEDGER_INVALID"))
        self.assert_untouched()

    def test_restore_is_denied_once_b2_progressed(self):
        report = self.planned(self.install)
        code, result = self.install("--apply", "--plan-sha256", report["planSha256"])
        self.assertEqual(code, 0, result)
        installed = self.wrapper.read_bytes()
        cases = {
            "B2_ARMING_PRESENT_RESTORE_DENIED": (lambda: self.write(self.out / "v51/arming/1.json", b"{}"),
                                                 lambda: (self.out / "v51/arming/1.json").unlink()),
            "SUCCESSOR_EVER_STARTED": (lambda: self.successors(4242, "2026-11-15T00:00:00Z"),
                                       lambda: self.successors(0)),
            "B1_V5_ARMING_PRESENT": (lambda: self.write(self.b1 / "arming/1.json", b"{}"),
                                     lambda: (self.b1 / "arming/1.json").unlink()),
        }
        for reason, (mutate, undo) in cases.items():
            with self.subTest(reason=reason):
                mutate()
                code, report = self.restore("--plan")
                self.assertEqual((code, report["reason"]), (1, reason), report)
                self.assertFalse((self.out / "restore-v1").exists())
                self.assertEqual(self.wrapper.read_bytes(), installed)
                undo()
        self.planned(self.restore)


if __name__ == "__main__":
    unittest.main()
