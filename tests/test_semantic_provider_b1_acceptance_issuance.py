"""Portable planning tests; opt-in Linux root/OpenSSL issuance qualification.

OUF_B1_ISSUANCE_NATIVE=1 refuses to skip if the native prerequisites are absent.
Disposable fixture keys only. No VPS, network or real installation inputs.
"""
import copy
from contextlib import ExitStack, contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_b1b2_authority import authority as A
from tools.semantic_b1_acceptance import acceptance as B
from tools.semantic_b1b2_authority import signer as S

spec = importlib.util.spec_from_file_location("acceptance_issuance", ROOT / "scripts/issue-semantic-provider-b1-acceptance.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NATIVE = os.environ.get("OUF_B1_ISSUANCE_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("Native issuance tests require Linux root:root; refusing to skip")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self, root="/synthetic-b1-issuance", key_raw=b"synthetic-unopened-key", public="ab" * 32,
                 openssl=None):
        self.root = PurePosixPath(str(root))
        self.files = {}
        self.now = int(time.time())
        self.key = self.root / "installer.pem"
        self.put(self.key, key_raw)
        self.cid = {"adapter": "a" * 64, "southbound": "b" * 64}
        self.tx = {"adapter": "1" * 32, "southbound": "2" * 32}
        self.image = {r: "sha256:" + sha(r.encode()) for r in B.ROLES}
        base = self.put(self.root / "base.json", {})
        self.authority = {"schema": "ouf.semantic-existing-installation-authority-bindings.v1",
            "keyRefs": {"installer": "installer-key"}, "keyBindings": {"installer": self.bind(self.key)},
            "policyBinding": base, "authorities": {"installationRef": "fixture-installation",
                "entityRef": "fixture-entity", "intentIssuerRef": "fixture-issuer", "approvalIssuerRef": "fixture-issuer"}}
        authority_binding = self.put(self.root / "authority.json", self.authority)
        self.mandate = {"keyRef": "installer-key", "issuerRef": "fixture-issuer", "roles": ["ARTIFACT_ACCEPTANCE"],
            "state": "ACTIVE", "notBefore": self.now - 1000, "expiresAt": self.now + 1000, "publicKey": public}
        self.policy = {"schema": A.POLICY_SCHEMA, "installationRef": "fixture-installation", "entityRef": "fixture-entity",
            "basePolicy": base, "authorityProfile": authority_binding, "keys": [self.mandate]}
        policy_binding = self.put(self.root / "trust-policy.json", self.policy)
        self.profile = {"installationRef": "fixture-installation", "entityRef": "fixture-entity",
            "paths": {"authorityProfile": authority_binding["path"]},
            "roles": {r: {"containerName": r + "-successor", "networks": {
                "backend": {"aliases": ["southbound.local"] if r == "southbound" else ["adapter.local"]}}} for r in B.ROLES}}
        profile_binding = self.put(self.root / "profile.json", self.profile)
        a2 = self.root / "a2"
        self.successors = {"containers": [{"containerId": self.cid[r], "name": "/" + r + "-successor",
            "image": self.image[r], "transaction": self.tx[r], "status": "created"} for r in B.ROLES],
            "transactions": {self.cid[r]: self.tx[r] for r in B.ROLES},
            "southboundCertificate": {"sni": "southbound.local", "configuredDerMatches": True}}
        self.put(a2 / "semantic-peer.json", {"fixture": "semantic-peer"})
        self.put(a2 / "successors.json", self.successors)
        body = {"schema": "ouf.semantic-provider-preparation-a.manifest.v1", "directory": {"path": str(a2)},
            "filesCreated": [self.bind(a2 / n) for n in ("semantic-peer.json", "successors.json")],
            "semanticPeer": {"fixture": "semantic-peer"}, "successors": self.successors}
        self.a_plan = sha(b"fixture-a2-plan")
        self.put(a2 / "manifest.json", {"planSha256": self.a_plan, "manifest": body})
        self.put(a2 / "result.json", {"status": "SEMANTIC_PROVIDER_PREPARATION_A_STAGED", "replayAllowed": False,
                                    "planSha256": self.a_plan, "manifest": body})
        self.preparation = {"root": str(a2), "planSha256": self.a_plan,
                            "files": {k: self.bind(a2 / n) for k, n in m.A_FILES.items()}}
        self.recreation = {"schema": "ouf.semantic-southbound-successor-recreation.v1", "status": "SOUTHBOUND_RECREATED_STOPPED",
                           "newCid": self.cid["southbound"], "newTransaction": self.tx["southbound"]}
        recreation_binding = self.put(self.root / "recreation.json", self.recreation)
        self.rootfs = {"schema": "ouf.semantic-provider-b1-rootfs-evidence.v1",
            "status": "SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED",
            "aSuccessors": self.preparation["files"]["successors"], "roles": {}}
        self.recipes = {"schema": "ouf.semantic-provider-b1-recipes.v1", "status": "SEMANTIC_PROVIDER_B1_RECIPES_PREPARED",
                        "preparationA": self.preparation, "recreation": recreation_binding, "roles": {}}
        for r in B.ROLES:
            rf = {f: self.put(self.root / "rootfs" / r / (f + ".json"), {"fixture": r + f})
                  for f in ("offlineImageReceipt", "offlineDockerReceipt", "comparison")}
            rf["effectiveSeal"] = {"schema": B.SEAL_SCHEMA, "sha256": sha(r.encode()), "entries": 5, "bytes": 10}
            self.rootfs["roles"][r] = {"containerId": self.cid[r], "imageId": self.image[r], **rf}
            self.recipes["roles"][r] = {"containerId": self.cid[r], "transaction": self.tx[r],
                "recipe": {f: self.put(self.root / "recipes" / r / (f + ".json"), {"fixture": r + f}) for f in B.RECIPE_PARTS}}
        rootfs_binding = self.put(self.root / "rootfs-result.json", self.rootfs)
        recipes_binding = self.put(self.root / "recipes-result.json", self.recipes)
        self.delivery = self.root / "delivery"
        closure = []
        for n in sorted(m.CLOSURE):
            b = self.put(self.delivery / n, (ROOT / n).read_bytes())
            closure.append(n + "=" + b["sha256"])
        if openssl is None:
            openssl = {**self.put(self.root / "openssl", b"synthetic-openssl"), "version": "3.0.0"}
        self.args = types.SimpleNamespace(plan=True, apply=False, plan_sha256=None, generation=1, issued_at=self.now,
            a2_root=str(a2), a2_plan_sha256=self.a_plan, a2_successors_sha256=self.bind(a2 / "successors.json")["sha256"],
            adapter_transaction=self.tx["adapter"], southbound_transaction=self.tx["southbound"],
            declared_gap=["ADAPTER_CREATION_PLAN_DIGEST_RECONSTRUCTED", "ADAPTER_CREATION_RECEIPT_NOT_RETAINED"],
            closure_source_commit="a" * 40, closure_file=closure, output_root=str(self.root / "output"), output_name="issuance")
        for name, binding in (("installation_profile", profile_binding), ("authority_profile", authority_binding),
                              ("trust_policy", policy_binding), ("recreation_receipt", recreation_binding),
                              ("rootfs_result", rootfs_binding), ("recipes_result", recipes_binding), ("openssl", openssl)):
            setattr(self.args, name, binding["path"])
            setattr(self.args, name + "_sha256", binding["sha256"])
        self.args.openssl_version = openssl["version"]

    def put(self, path, value):
        raw = value if isinstance(value, bytes) else A.canonical(value) + b"\n"
        self.files[str(path)] = raw
        return self.bind(path)

    def bind(self, path):
        return {"path": str(path), "sha256": sha(self.files[str(path)])}

    def update(self, field, value):
        path = getattr(self.args, field)
        binding = self.put(path, value)
        setattr(self.args, field + "_sha256", binding["sha256"])
        if NATIVE and Path(path).is_file():
            Path(path).write_bytes(self.files[path])

    @contextmanager
    def portable(self):
        fixture = self
        class VirtualReader(m.Reader):
            def read(self, path, expected=None, limit=8388608):
                A.require(not any(PurePosixPath(str(path)) == key or key in PurePosixPath(str(path)).parents
                                  for key in self.private_paths), "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN")
                if str(path) == str(fixture.key):
                    raise AssertionError("plan opened key")
                raw = fixture.files[str(path)]
                A.require(expected is None or sha(raw) == expected, "INPUT_SHA256_MISMATCH")
                self.hashes[str(path)] = sha(raw)
                return raw
        with ExitStack() as stack:
            stack.enter_context(patch.object(m, "ROOT", self.delivery))
            stack.enter_context(patch.object(m, "Reader", VirtualReader))
            stack.enter_context(patch.object(A, "absolute", side_effect=lambda p: PurePosixPath(p)))
            stack.enter_context(patch.object(A, "ancestors"))
            stack.enter_context(patch.object(A.B1B2Authenticator, "executable", return_value=self.args.openssl))
            stack.enter_context(patch.object(m, "check_openssl"))
            yield


class PlanTests(unittest.TestCase):
    def test_complete_deterministic_bytes_and_no_private_path_observation(self):
        f = Fixture()
        with f.portable(), patch.object(Path, "lstat", side_effect=AssertionError("stat in virtual plan")):
            p, raw, expected, *_ = m.observe(f.args)
            p2, raw2, *_ = m.observe(f.args)
        self.assertEqual(A.canonical(p), A.canonical(p2))
        self.assertEqual(raw, raw2)
        self.assertEqual(p["manifestRaw"].encode(), raw)
        self.assertEqual(p["payloadSha256"], sha(raw))
        self.assertEqual(p["privateKeysRead"], 0)
        self.assertNotIn(str(f.key), p["inputHashes"])
        self.assertEqual(B.decode_manifest(raw)["creation"]["declaredGaps"], f.args.declared_gap)
        self.assertEqual(expected["roles"]["southbound"]["containerId"], f.cid["southbound"])

    def test_each_cli_hash_mismatch_and_a2_plan(self):
        fields = ["installation_profile_sha256", "trust_policy_sha256", "authority_profile_sha256",
                  "a2_plan_sha256", "a2_successors_sha256", "recreation_receipt_sha256",
                  "rootfs_result_sha256", "recipes_result_sha256", "openssl_sha256"]
        for field in fields:
            with self.subTest(field=field):
                f = Fixture()
                setattr(f.args, field, "0" * 64)
                with f.portable(), self.assertRaises(A.AuthorityDenied):
                    m.observe(f.args)

    def test_every_recipe_rootfs_and_a2_file_tamper(self):
        f = Fixture()
        paths = [item["path"] for r in B.ROLES for item in f.recipes["roles"][r]["recipe"].values()]
        paths += [f.rootfs["roles"][r][k]["path"] for r in B.ROLES
                  for k in ("offlineImageReceipt", "offlineDockerReceipt", "comparison")]
        paths += [item["path"] for item in f.preparation["files"].values()]
        for path in paths:
            with self.subTest(path=path):
                other = Fixture()
                other.files[path] += b" "
                with other.portable():
                    with self.assertRaises(A.AuthorityDenied):
                        m.observe(other.args)

    def test_mandate_time_role_identity_and_issued_at(self):
        for change in ({"expiresAt": int(time.time()) - 1}, {"notBefore": int(time.time()) + 50},
                       {"roles": ["RUNTIME_ARMING"]}, {"state": "REVOKED"}, {"keyRef": "other"},
                       {"issuerRef": "other"}):
            f = Fixture()
            policy = copy.deepcopy(f.policy)
            policy["keys"][0].update(change)
            f.update("trust_policy", policy)
            with self.subTest(change=change), f.portable(), self.assertRaises(A.AuthorityDenied):
                m.observe(f.args)
        for issued in (-1, int(time.time()) + 301, int(time.time()) - 1001):
            f = Fixture()
            f.args.issued_at = issued
            with self.subTest(issued=issued), f.portable(), self.assertRaises(A.AuthorityDenied):
                m.observe(f.args)

    def test_scope_transactions_receipts_and_gap_order(self):
        changes = [("adapter_transaction", "f" * 32), ("southbound_transaction", "f" * 32),
                   ("generation", 0), ("closure_source_commit", "a" * 39),
                   ("declared_gap", ["ZZZ", "AAA"]), ("declared_gap", ["AAA", "AAA"]), ("declared_gap", ["bad gap"])]
        for field, value in changes:
            f = Fixture()
            setattr(f.args, field, value)
            with self.subTest(field=field), f.portable(), self.assertRaises((A.AuthorityDenied, B.AcceptanceDenied)):
                m.observe(f.args)
        for field, value in (("rootfs_result", {"status": "wrong"}), ("recipes_result", {"recreation": None}),
                             ("recreation_receipt", {"newCid": "c" * 64}), ("installation_profile", {"entityRef": "other"})):
            f = Fixture()
            doc = A.decode(f.files[getattr(f.args, field)], 8388608)
            doc.update(value)
            f.update(field, doc)
            with self.subTest(field=field), f.portable(), self.assertRaises(A.AuthorityDenied):
                m.observe(f.args)

    def test_exact_closure_set_and_content(self):
        for variant in ("missing", "extra", "duplicate", "hash", "bytes"):
            f = Fixture()
            if variant == "missing":
                f.args.closure_file.pop()
            elif variant == "extra":
                f.args.closure_file.append("other.py=" + "a" * 64)
            elif variant == "duplicate":
                f.args.closure_file.append(f.args.closure_file[0])
            elif variant == "hash":
                f.args.closure_file[0] = f.args.closure_file[0].partition("=")[0] + "=" + "0" * 64
            else:
                f.files[str(f.delivery / sorted(m.CLOSURE)[0])] += b" "
            with self.subTest(variant=variant), f.portable(), self.assertRaises(A.AuthorityDenied) as error:
                m.observe(f.args)
            if variant in ("missing", "extra", "duplicate"):
                self.assertEqual(str(error.exception), "ACCEPTANCE_CLOSURE_SET_UNEXPECTED")

    def test_private_key_cannot_be_referenced_as_public_evidence(self):
        f = Fixture()
        doc = copy.deepcopy(f.rootfs)
        doc["roles"]["adapter"]["comparison"] = f.bind(f.key)
        f.update("rootfs_result", doc)
        with f.portable(), self.assertRaisesRegex(A.AuthorityDenied, "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN"):
            m.observe(f.args)

    def test_wrong_plan_digest_precedes_signer_and_writes(self):
        f = Fixture()
        f.args.plan, f.args.apply, f.args.plan_sha256 = False, True, "0" * 64
        with f.portable(), patch.object(m, "output", return_value=(f.root / "output", ())), \
                patch.object(os, "mkdir", side_effect=AssertionError("mkdir")), \
                patch.object(S.ExistingB1B2Ed25519Signer, "sign", side_effect=AssertionError("sign")), \
                self.assertRaisesRegex(A.AuthorityDenied, "PLAN_DIGEST_MISMATCH"):
            m.execute(f.args, {})

    def test_launcher_pins_match_head_and_required_files(self):
        source = (ROOT / "scripts/deliver-semantic-provider-b1-acceptance-issuance.sh").read_text()
        rows = re.findall(r"^fetch (\S+) ([0-9a-f]{64})$", source, re.M)
        self.assertEqual(len(rows), 6)
        for name, digest in rows:
            raw = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)
            self.assertEqual(sha(raw), digest, name)
        placeholders = ("__PIN_COMMIT__", "__PIN_CONTROLLER_SHA256__", "__PIN_SIGNER_SHA256__")
        if all(pin in source for pin in placeholders):
            for name, pin in zip(("commit", "controller_sha", "signer_sha"), placeholders):
                self.assertEqual(re.findall(r"^" + name + r"=(.*)$", source, re.M), ["'" + pin + "'"])
        else:
            self.assertNotIn("__PIN_", source)
            commits = re.findall(r"^commit=(.*)$", source, re.M)
            self.assertEqual(len(commits), 1)
            self.assertRegex(commits[0], r"^'[0-9a-f]{40}'$")
            for name, path in (("controller_sha", "scripts/issue-semantic-provider-b1-acceptance.py"),
                               ("signer_sha", "tools/semantic_b1b2_authority/signer.py")):
                raw = subprocess.check_output(["git", "show", "HEAD:" + path], cwd=ROOT)
                self.assertEqual(re.findall(r"^" + name + r"=(.*)$", source, re.M), ["'" + sha(raw) + "'"])
        self.assertTrue(m.CLOSURE.issubset({name for name, _ in rows}))


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL unavailable for portable cryptographic smoke test")
class CryptographicSmokeTests(unittest.TestCase):
    def test_real_openssl_signer_with_only_posix_custody_adapted(self):
        # Exercises the actual signer and B1/B2 verifier even on Windows.
        # It is explicitly not evidence of Linux custody (NativeTests owns that).
        executable = str(Path(shutil.which("openssl")).resolve())
        with tempfile.TemporaryDirectory(prefix="b1-smoke-", dir=ROOT) as temp:
            root = Path(temp)
            key = root / "fixture.pem"
            subprocess.run([executable, "genpkey", "-algorithm", "Ed25519", "-out", str(key)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            public = subprocess.check_output([executable, "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
            fixture = Fixture(key_raw=key.read_bytes(), public=public[len(A.DER_PREFIX):].hex())
            with fixture.portable():
                _, raw, expected, mandate, *_ = m.observe(fixture.args)
            binding = {"path": str(key), "sha256": sha(key.read_bytes())}
            policy_binding = fixture.bind(fixture.args.trust_policy)
            openssl = {"path": executable, "sha256": sha(Path(executable).read_bytes()),
                       "version": subprocess.check_output([executable, "version"]).decode().split()[1]}
            reads = []
            def read(path, limit=65536):
                if path == key:
                    reads.append(path)
                    data = path.read_bytes()
                else:
                    self.assertEqual(path.as_posix(), policy_binding["path"])
                    data = fixture.files[policy_binding["path"]]
                self.assertLessEqual(len(data), limit)
                return data
            def pinned(verifier):
                self.assertEqual(sha(Path(executable).read_bytes()), verifier.openssl_binding["sha256"])
                return executable
            progress = {}
            original_absolute = A.absolute
            def absolute(path):
                return PurePosixPath(path) if path.startswith("/") else original_absolute(path)
            with patch.object(A, "ancestors"), patch.object(A, "public_bytes", side_effect=read), \
                    patch.object(A, "absolute", side_effect=absolute), \
                    patch.object(A.B1B2Authenticator, "executable", pinned), \
                    patch.object(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True):
                verifier = A.B1B2Authenticator(policy_binding, openssl)
                signer = S.ExistingB1B2Ed25519Signer(binding, mandate, verifier,
                    {"issuerRef": "fixture-issuer", "installationRef": "fixture-installation", "entityRef": "fixture-entity"}, progress)
                signature = signer.sign(raw)
                accepted = B.verify_acceptance(raw, signature, expected=expected, authenticator=verifier)
                self.assertEqual(accepted["payloadSha256"], sha(raw))
                self.assertEqual(len(reads), 2)
                self.assertEqual(progress["privateKeysRead"], 1)
                self.assertEqual(progress["signaturesIssued"], 1)
                record = A.decode(signature)
                header = {k: v for k, v in record.items() if k != "signature"}
                frame = A.signing_bytes(raw, header)
                with self.assertRaisesRegex(A.AuthorityDenied, "DETACHED_SIGNATURE_INVALID"):
                    verifier.verify(b"wrong-domain" + frame, bytes.fromhex(mandate["publicKey"]),
                                    bytes.fromhex(record["signature"]))


@unittest.skipUnless(NATIVE, "requires opt-in native Linux root/OpenSSL CI")
class NativeTests(unittest.TestCase):
    def setUp(self):
        os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-b1-issuance-test-", dir="/root")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        openssl = Path(shutil.which("openssl")).resolve(strict=True)
        version = subprocess.check_output([str(openssl), "version"]).decode().split()[1]
        key = self.root / "generated-test-key.pem"
        subprocess.run([str(openssl), "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = subprocess.check_output([str(openssl), "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
        self.f = Fixture(str(self.root), key.read_bytes(), public[len(A.DER_PREFIX):].hex(),
                         {"path": str(openssl), "sha256": sha(openssl.read_bytes()), "version": version})
        for name, raw in self.f.files.items():
            path = Path(name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o600)
        (self.root / "output").mkdir(mode=0o700)
        self.args = self.f.args
        self.root_patch = patch.object(m, "ROOT", Path(self.f.delivery))
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.progress = {"phase": "PREFLIGHT", "outputCreated": False, "privateKeysRead": 0,
                         "signingAttempted": False, "signaturesIssued": 0, "writtenFiles": []}

    def plan(self):
        self.args.plan, self.args.apply, self.args.plan_sha256 = True, False, None
        return m.execute(self.args, self.progress)

    def apply(self):
        plan = self.plan()
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan["planSha256"]
        return m.execute(self.args, self.progress)

    def test_unreadable_key_plan_no_open_or_stat_and_deterministic(self):
        Path(self.f.key).chmod(0)
        original_open, original_lstat = os.open, Path.lstat
        def no_key_open(path, *a, **kw):
            self.assertNotEqual(str(path), str(self.f.key))
            return original_open(path, *a, **kw)
        def no_key_stat(path, *a, **kw):
            self.assertNotEqual(str(path), str(self.f.key))
            return original_lstat(path, *a, **kw)
        with patch.object(os, "open", side_effect=no_key_open), patch.object(Path, "lstat", no_key_stat):
            p = self.plan()
            self.assertEqual(p, self.plan())
        self.assertEqual(p["privateKeysRead"], 0)
        self.assertFalse((self.root / "output/issuance").exists())

    def test_apply_real_signature_readback_modes_and_domain_separation(self):
        reads = []
        original = A.public_bytes
        def count(path, *a, **kw):
            if str(path) == str(self.f.key):
                reads.append(path)
            return original(path, *a, **kw)
        with patch.object(A, "public_bytes", side_effect=count):
            result = self.apply()
        self.assertEqual(len(reads), 2)  # One distinct key, pre/post hash checks.
        self.assertEqual(result["status"], "SEMANTIC_PROVIDER_B1_ACCEPTANCE_ISSUED")
        self.assertEqual(result["privateKeysRead"], result["signaturesIssued"], 1)
        directory = self.root / "output/issuance"
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for file in directory.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file.stat().st_nlink, 1)
        self.assertEqual(A.decode((directory / "result.json").read_bytes()), result)
        raw = Path(result["manifest"]["path"]).read_bytes()
        signature = Path(result["signature"]["path"]).read_bytes()
        record = A.decode(signature)
        header = {k: v for k, v in record.items() if k != "signature"}
        # Reconstruct the existing deployment frame (same length encoding),
        # then check the real Ed25519 signature against that different domain.
        deployment_source = (ROOT / "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py").read_text()
        domain_literal = re.search(r"^DOMAIN\s*=\s*(b[^\n]+)", deployment_source, re.M)
        import ast
        old_domain = ast.literal_eval(domain_literal[1].strip())
        self.assertNotEqual(old_domain, A.DOMAIN)
        old_header = dict(header, schema="ouf.semantic-deployment-detached-signature.v1")
        encoded = A.canonical(old_header)
        frame = old_domain + len(encoded).to_bytes(4, "big") + encoded + len(raw).to_bytes(4, "big") + raw
        verifier = A.B1B2Authenticator(m.cli_binding(self.args, "trust_policy"),
            {**m.cli_binding(self.args, "openssl"), "version": self.args.openssl_version})
        with self.assertRaisesRegex(A.AuthorityDenied, "DETACHED_SIGNATURE_INVALID"):
            verifier.verify(frame, bytes.fromhex(self.f.mandate["publicKey"]), bytes.fromhex(record["signature"]))
        with self.assertRaises(A.AuthorityDenied):
            A.signing_bytes(raw, old_header)

    def test_public_key_mismatch_and_private_key_hash_mismatch(self):
        policy = copy.deepcopy(self.f.policy)
        policy["keys"][0]["publicKey"] = "ff" * 32
        self.f.update("trust_policy", policy)
        with self.assertRaisesRegex(A.AuthorityDenied, "SIGNING_KEY_PUBLIC_MANDATE_DRIFT"):
            self.apply()
        self.assertFalse(self.progress["signingAttempted"])
        self.assertTrue((self.root / "output/issuance").is_dir())
        self.assertEqual(list((self.root / "output/issuance").iterdir()), [])

    def test_key_changed_after_plan(self):
        p = self.plan()
        Path(self.f.key).write_bytes(b"changed disposable key")
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, p["planSha256"]
        with self.assertRaisesRegex(A.AuthorityDenied, "EXISTING_SIGNING_KEY_DRIFT"):
            m.execute(self.args, self.progress)
        self.assertFalse(self.progress["signingAttempted"])

    def test_existing_output_refused_before_key_access(self):
        (self.root / "output/issuance").mkdir(mode=0o700)
        with patch.object(S.ExistingB1B2Ed25519Signer, "sign", side_effect=AssertionError("key")), \
                self.assertRaisesRegex(A.AuthorityDenied, "OUTPUT_ALREADY_EXISTS"):
            self.plan()

    def test_symlink_hardlink_and_writable_ancestor_rejected(self):
        path = Path(self.args.rootfs_result)
        original = path.read_bytes()
        target = self.root / "target.json"
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.plan()
        path.unlink()
        os.link(target, path)
        with self.assertRaisesRegex(A.AuthorityDenied, "INPUT_FILE_CUSTODY_REQUIRED"):
            self.plan()
        path.unlink()
        path.write_bytes(original)
        self.root.chmod(0o777)
        with self.assertRaises(A.AuthorityDenied):
            self.plan()
        self.root.chmod(0o700)

    def test_post_signature_failure_is_partial_without_rollback(self):
        original = m.write_once
        def fail(directory, name, raw):
            if name.endswith(".ARTIFACT_ACCEPTANCE.json"):
                raise OSError("injected")
            return original(directory, name, raw)
        with patch.object(m, "write_once", side_effect=fail), self.assertRaises(OSError):
            self.apply()
        self.assertEqual(self.progress["signaturesIssued"], 1)
        self.assertEqual(self.progress["phase"], "WRITE_SIGNATURE")
        self.assertEqual(self.progress["writtenFiles"], ["manifest.json"])
        self.assertTrue((self.root / "output/issuance/manifest.json").is_file())

    def test_cli_reports_partial_and_retains_post_sign_failure(self):
        plan = self.plan()
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan["planSha256"]
        original = m.write_once
        def fail(directory, name, raw):
            if name.endswith(".ARTIFACT_ACCEPTANCE.json"):
                # Also exercise a file created before an fsync/write failure.
                original(directory, name, raw)
                raise OSError("injected")
            original(directory, name, raw)
        output = io.StringIO()
        with patch.object(m, "arguments", return_value=self.args), patch.object(m, "write_once", side_effect=fail), \
                redirect_stdout(output):
            self.assertEqual(m.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["phase"], "WRITE_SIGNATURE")
        self.assertEqual(report["signaturesIssued"], 1)
        self.assertEqual(len(report["retainedOutput"]["files"]), 2)
        self.assertFalse(report["automaticRollback"])

    def test_key_and_policy_drift_after_sign_are_detected(self):
        original = S.ExistingB1B2Ed25519Signer.native
        for kind in ("key", "policy"):
            with self.subTest(kind=kind):
                self.args.output_name = "drift-" + kind
                Path(self.f.key).write_bytes(self.f.files[str(self.f.key)])
                Path(self.args.trust_policy).write_bytes(self.f.files[self.args.trust_policy])
                def drift(signer, argv, limit):
                    raw = original(signer, argv, limit)
                    if argv[:2] == ["pkeyutl", "-sign"]:
                        target = Path(self.f.key) if kind == "key" else Path(self.args.trust_policy)
                        target.write_bytes(target.read_bytes() + b" ")
                    return raw
                with patch.object(S.ExistingB1B2Ed25519Signer, "native", drift), self.assertRaises(A.AuthorityDenied):
                    self.apply()
                self.assertEqual(self.progress["signaturesIssued"], 1)
                self.assertEqual(list((self.root / "output" / self.args.output_name).iterdir()), [])

    def test_cli_plan_then_apply_with_isolation(self):
        # Deliver exactly the controller's import closure, as the launcher does.
        names = ["scripts/issue-semantic-provider-b1-acceptance.py", "tools/semantic_b1b2_authority/signer.py",
                 "tools/semantic_b1b2_authority/__init__.py", "tools/semantic_b1_acceptance/__init__.py",
                 "tools/semantic_b1_acceptance/acceptance.py"]
        for name in names:
            path = Path(self.f.delivery) / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
            path.chmod(0o600)
        argv = []
        for name, value in vars(self.args).items():
            if name in {"plan", "apply", "plan_sha256"}:
                continue
            for item in value if isinstance(value, list) else [value]:
                argv += ["--" + name.replace("_", "-"), str(item)]
        command = [sys.executable, "-I", "-B", str(Path(self.f.delivery) / names[0])]
        planned = subprocess.run(command + ["--plan", *argv], check=True, capture_output=True)
        plan = json.loads(planned.stdout)
        issued = subprocess.run(command + ["--apply", "--plan-sha256", plan["planSha256"], *argv],
                                check=True, capture_output=True)
        result = json.loads(issued.stdout)
        self.assertEqual(result["status"], "SEMANTIC_PROVIDER_B1_ACCEPTANCE_ISSUED")
        self.assertEqual(Path(result["manifest"]["path"]).read_bytes(), plan["manifestRaw"].encode())


if __name__ == "__main__":
    unittest.main()
