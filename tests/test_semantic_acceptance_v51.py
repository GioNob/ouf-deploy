"""Acceptance v5.1 issuance (task-29a): native root custody, real OpenSSL, real mandate ledger.

OUF_ACCEPTANCE_V51_NATIVE=1 refuses to skip without Linux root:root.
Disposable fixture keys only. No VPS, network or real installation inputs.
"""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from tools.semantic_b1b2_authority import authority as A
from tools.semantic_b1_acceptance import acceptance as B
import test_semantic_provider_b1_acceptance_issuance as legacy

spec = importlib.util.spec_from_file_location("acceptance_v51_issuance", ROOT / "scripts/issue-semantic-provider-acceptance-v51.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
mspec = importlib.util.spec_from_file_location("mandates_for_acceptance_tests", ROOT / "tools/semantic_authority_mandates/mandates.py")
M = importlib.util.module_from_spec(mspec)
mspec.loader.exec_module(M)
NATIVE = os.environ.get("OUF_ACCEPTANCE_V51_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_ACCEPTANCE_V51_NATIVE requires Linux root:root; refusing to skip")
OK = {"keyNotRevoked": True, "custodyIntact": True, "noOpenSecurityIncident": True}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@unittest.skipUnless(NATIVE, "set OUF_ACCEPTANCE_V51_NATIVE=1 under native Linux root")
class Native(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o077))
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-acceptance-v51-test-", dir="/root")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.openssl = Path(shutil.which("openssl")).resolve(strict=True)
        version = subprocess.check_output([str(self.openssl), "version"]).decode().split()[1]
        key = self.root / "generated-test-key.pem"
        subprocess.run([str(self.openssl), "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = subprocess.check_output([str(self.openssl), "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
        self.f = legacy.Fixture(str(self.root), key.read_bytes(), public[len(A.DER_PREFIX):].hex(),
                                {"path": str(self.openssl), "sha256": sha(self.openssl.read_bytes()), "version": version})
        closure = []
        for name in sorted(m.CLOSURE):
            binding = self.f.put(self.f.delivery / name, (ROOT / name).read_bytes())
            closure.append(name + "=" + binding["sha256"])
        self.f.args.closure_file = closure
        self.f.args.generation = 3
        self.materialize()
        (self.root / "output").mkdir(mode=0o700)
        self.ledger = self.root / "mandates"
        self.ledger.mkdir(mode=0o700)
        self.f.args.mandate_root = str(self.ledger)
        self.args = self.f.args
        patcher = patch.object(m, "ROOT", Path(self.f.delivery))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.progress = {"phase": "PREFLIGHT", "outputCreated": False, "privateKeysRead": 0,
                         "signingAttempted": False, "signaturesIssued": 0, "writtenFiles": []}

    def materialize(self):
        for name, raw in self.f.files.items():
            path = Path(name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.exists():
                path.unlink()
            path.write_bytes(raw)
            path.chmod(0o600)

    def update_policy(self, change):
        policy = copy.deepcopy(self.f.policy)
        policy["keys"][0].update(change)
        self.f.update("trust_policy", policy)
        self.materialize()
        self.f.policy = policy

    def anchor(self):
        return {"path": self.args.trust_policy, "sha256": self.args.trust_policy_sha256}

    def generation(self, state="ACTIVE", not_before=None, preconditions=OK):
        nb = int(time.time()) - 10 if not_before is None else not_before
        return M.write_generation(str(self.ledger), self.anchor(), "fixture-installation", "fixture-entity",
                                  [{"keyRef": "installer-key", "notBefore": nb, "expiresAt": nb + 30 * 86400,
                                    "state": state}], preconditions, "renewal-job", "9" * 64)

    def plan(self):
        self.args.plan, self.args.apply, self.args.plan_sha256 = True, False, None
        return m.execute(self.args, self.progress)

    def apply(self):
        plan = self.plan()
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan["planSha256"]
        return m.execute(self.args, self.progress)

    def denied(self, function):
        with self.assertRaises((A.AuthorityDenied, B.AcceptanceDenied)) as caught:
            function()
        return str(caught.exception)

    def test_plan_has_exact_v51_closure_generation_three_and_never_touches_the_key(self):
        Path(self.f.key).chmod(0)
        original = os.open
        opened = []
        def guard(path, *a, **kw):
            if str(path) == str(self.f.key):
                opened.append(path)
            return original(path, *a, **kw)
        with patch.object(os, "open", side_effect=guard):
            plan = self.plan()
            self.assertEqual(plan, self.plan())
        self.assertEqual(opened, [])
        self.assertEqual(plan["privateKeysRead"], 0)
        manifest = B.decode_manifest(plan["manifestRaw"].encode())
        self.assertEqual(set(manifest["softwareClosure"]["files"]), set(m.CLOSURE))
        self.assertEqual(manifest["generation"], 3)
        self.assertEqual(plan["mandate"]["generation"], 0)
        self.assertEqual(plan["ledger"]["generations"], 0)
        self.assertFalse((self.root / "output/issuance").exists())

    def test_generation_below_three_and_v5_closure_refused(self):
        self.args.generation = 2
        self.assertEqual(self.denied(self.plan), "ACCEPTANCE_GENERATION_REQUIRED")
        self.args.generation = 3
        self.args.closure_file = [n + "=" + "a" * 64 for n in sorted(legacy.m.CLOSURE)]
        self.assertEqual(self.denied(self.plan), "ACCEPTANCE_CLOSURE_SET_UNEXPECTED")

    def test_apply_signs_once_and_verifies_through_the_ledger(self):
        reads = []
        original = A.public_bytes
        def count(path, *a, **kw):
            if str(path) == str(self.f.key):
                reads.append(path)
            return original(path, *a, **kw)
        with patch.object(A, "public_bytes", side_effect=count):
            result = self.apply()
        self.assertEqual(result["status"], "SEMANTIC_PROVIDER_ACCEPTANCE_V51_ISSUED")
        self.assertEqual((result["privateKeysRead"], result["signaturesIssued"]), (1, 1))
        self.assertEqual(len(reads), 2)  # one key, hash checked before and after signing
        raw = Path(result["manifest"]["path"]).read_bytes()
        signature = Path(result["signature"]["path"]).read_bytes()
        authenticator = M.MandateAuthenticator(self.anchor(), str(self.ledger),
                                               {**m.cli_binding(self.args, "openssl"), "version": self.args.openssl_version})
        self.assertIs(authenticator.verify_b1b2_detached(raw, signature, "ARTIFACT_ACCEPTANCE", "fixture-issuer",
                                                         "fixture-installation", "fixture-entity"), True)
        for file in (self.root / "output/issuance").iterdir():
            self.assertEqual((file.stat().st_mode & 0o777, file.stat().st_nlink), (0o600, 1))

    def test_expired_generation_zero_renewed_by_the_ledger_still_signs(self):
        now = int(time.time())
        self.update_policy({"notBefore": now - 7200, "expiresAt": now - 3600})
        self.args.issued_at = now
        self.assertIn(self.denied(self.plan), ("EXACT_ACCEPTANCE_MANDATE_REQUIRED", "ACTIVE_MANDATE_REQUIRED"))
        self.generation(not_before=now - 60)
        self.args.issued_at = int(time.time())
        result = self.apply()
        self.assertEqual(result["status"], "SEMANTIC_PROVIDER_ACCEPTANCE_V51_ISSUED")

    def test_revocation_in_the_ledger_refuses_plan_and_sign(self):
        self.generation(state="REVOKED", not_before=int(time.time()) - 60,
                        preconditions={**OK, "keyNotRevoked": False})
        self.assertIn(self.denied(self.plan), ("EXACT_ACCEPTANCE_MANDATE_REQUIRED", "ACTIVE_MANDATE_REQUIRED"))
        self.assertFalse((self.root / "output/issuance").exists())

    def test_invalid_ledger_refuses_with_public_code(self):
        (self.ledger / (".tmp-1-" + "0" * 32)).write_bytes(b"partial")
        self.assertEqual(self.denied(self.plan), "MANDATE_TEMPORARY_ENTRY_PRESENT")

    def test_ledger_changed_between_plan_and_apply_changes_the_plan(self):
        plan = self.plan()
        self.generation(not_before=int(time.time()) - 60)
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan["planSha256"]
        self.assertEqual(self.denied(lambda: m.execute(self.args, self.progress)), "PLAN_DIGEST_MISMATCH")
        self.assertFalse((self.root / "output/issuance").exists())

    def test_no_private_key_read_during_plan_audit(self):
        touched = []
        active = [True]
        self.addCleanup(active.__setitem__, 0, False)

        def audit(event, args):
            if not active[0] or event != "open" or not args:
                return
            if isinstance(args[0], (str, bytes, os.PathLike)) and os.fsdecode(args[0]) == str(self.f.key):
                touched.append(event)

        sys.addaudithook(audit)
        self.plan()
        self.assertEqual(touched, [])



class RunbookContract(unittest.TestCase):
    FILES = {"I": "scripts/issue-semantic-provider-acceptance-v51.py",
             "VI": "tools/semantic_acceptance_v51/issuance.py", "V0": "tools/semantic_acceptance_v51/__init__.py",
             "BA": "tools/semantic_b1_acceptance/acceptance.py", "B0": "tools/semantic_b1_acceptance/__init__.py",
             "AA": "tools/semantic_b1b2_authority/authority.py", "A0": "tools/semantic_b1b2_authority/__init__.py",
             "R51": "tools/semantic_runtime_v51/semantic_provider_docker_runtime_v51.py",
             "V51": "tools/semantic_runtime_v51/arming_verifier_v51.py",
             "MD": "tools/semantic_authority_mandates/mandates.py"}

    def test_pins_and_argument_cleaning(self):
        text = (ROOT / "ops/vps/acceptance-v51.sh").read_text()
        pins = dict(line.split("=", 1) for line in text.splitlines()
                    if line.split("=", 1)[0] in set(self.FILES) | {"C", "ISSUED_AT", "P"} and "=" in line)
        self.assertRegex(pins["C"], r"\A[0-9a-f]{40}\Z")
        for key in self.FILES:
            self.assertRegex(pins[key], r"\A[0-9a-f]{64}\Z", key)
        self.assertIn("--generation 3", text)
        self.assertIn("--mandate-root /var/lib/ouf-authority-mandates/b1b2", text)
        if set(pins["C"]) != {"0"}:
            self.assertGreater(int(pins["ISSUED_AT"]), 1794672600)
            for key, path in self.FILES.items():
                self.assertEqual(pins[key], sha((ROOT / path).read_bytes()), path)
        result = subprocess.run(["bash", str(ROOT / "ops/vps/acceptance-v51.sh"), "apply", "x" + chr(13)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"ricevuti 1 caratteri", result.stderr)


if __name__ == "__main__":
    unittest.main()
