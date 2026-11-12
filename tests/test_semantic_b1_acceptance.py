"""Public schema tests and opt-in native Ed25519 verification with disposable keys."""

import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_b1_acceptance import acceptance as B
from tools.semantic_b1b2_authority import authority as A

NATIVE = os.environ.get("OUF_B1_ACCEPTANCE_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_B1_ACCEPTANCE_NATIVE requires native Linux root:root; refusing to skip")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def synthetic_binding(path):
    # A syntactic fixture, never a statement about bytes present on the VPS.
    return {"path": path, "sha256": sha(("SYNTHETIC:" + path).encode())}


def fixture():
    root = "/var/lib/ouf-storage-migration/semantic-provider-preparation-a-20261111"
    roles = {}
    identities = {
        "adapter": ("85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef",
                    "sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc"),
        "southbound": ("34adce783cba238c1954eb33e39c37a641ea4f0db212531951a2fd2b86290c52",
                       "sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366")}
    for role, (cid, image) in identities.items():
        base = "/fixture-future-b1/" + role
        roles[role] = {"containerId": cid, "imageId": image,
                       "recipe": {part: synthetic_binding(base + "/" + part + ".json")
                                  for part in B.RECIPE_PARTS},
                       "rootfs": {field: synthetic_binding(base + "/" + field + ".json")
                                  for field in ("offlineImageReceipt", "offlineDockerReceipt", "comparison")}}
        roles[role]["rootfs"]["effectiveSeal"] = {
            "schema": B.SEAL_SCHEMA, "sha256": sha(("SYNTHETIC-SEAL:" + role).encode()), "entries": 12, "bytes": 34}
    return {"schema": B.SCHEMA, "installationRef": "ouf-lab-netcup-01", "entityRef": "fixture-semantic-provider",
            "generation": 1,
            "profile": {"path": "/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json",
                        "sha256": "5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d"},
            "preparationA": {"root": root,
                             "planSha256": "17de05e7d9b9610e58919a5b22697f28865ea0b076327d0b477fbae03d22daa8",
                             "files": {key: synthetic_binding(root + "/" + name) for key, name in
                                       (("manifest", "manifest.json"), ("result", "result.json"),
                                        ("semanticPeer", "semantic-peer.json"), ("successors", "successors.json"))}},
            "creation": {"transactionRef": "7ff12b95c3f70c5eaebb1d0a12ab931d", "evidence": "PREPARATION_A_ONLY",
                         "declaredGaps": ["PRE_CREATE_REQUEST_NOT_RETAINED", "CREATION_RECEIPT_NOT_RETAINED"]},
            "roles": roles, "softwareClosure": {"sourceCommit": "a" * 40,
                                                "files": {"tools/fixture.py": "b" * 64}},
            "trustPolicy": {
                "path": "/etc/ouf/deploy-snapshots/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json",
                "sha256": "6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95"},
            "startAuthorized": False, "leaseAuthorized": False, "issuedAt": 2000000000}


def expected_for(value):
    """Test convenience only; production callers must obtain independent pins."""
    return {"installationRef": value["installationRef"], "entityRef": value["entityRef"],
            "issuerRef": "fixture-installer", "profileSha256": value["profile"]["sha256"],
            "preparationA": {"planSha256": value["preparationA"]["planSha256"],
                             "files": {key: row["sha256"] for key, row in value["preparationA"]["files"].items()}},
            "roles": {role: {key: row[key] for key in ("containerId", "imageId")}
                      for role, row in value["roles"].items()},
            "trustPolicy": copy.deepcopy(value["trustPolicy"]), "minimumGeneration": 1}


def at(value, parts):
    for part in parts:
        value = value[part]
    return value


class SchemaTests(unittest.TestCase):
    def denied(self, parts, replacement, code):
        value = fixture()
        at(value, parts[:-1])[parts[-1]] = replacement
        with self.assertRaisesRegex(B.AcceptanceDenied, "^" + code + "$"):
            B.build_acceptance(**value)

    def test_deterministic_ascii_lf_and_no_input_mutation_or_path_reads(self):
        value = fixture()
        value["roles"]["adapter"]["recipe"]["template"]["path"] = "/absent/teatri-à.json"
        before = copy.deepcopy(value)

        def reverse(item):
            if isinstance(item, dict):
                return {key: reverse(item[key]) for key in reversed(item)}
            if isinstance(item, list):
                return [reverse(row) for row in item]
            return item

        with patch.object(Path, "open", side_effect=AssertionError("artifact read")), \
                patch.object(Path, "stat", side_effect=AssertionError("artifact stat")):
            raw = B.build_acceptance(**value)
            self.assertEqual(raw, B.build_acceptance(**reverse(value)))
            self.assertEqual(raw, A.canonical(value) + b"\n")
            self.assertEqual(B.decode_manifest(raw), value)
        self.assertEqual(value, before)
        self.assertIn(b"\\u00e0", raw)
        self.assertTrue(raw.endswith(b"}\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        decoded = B.validate_acceptance(value)
        decoded["roles"]["adapter"]["imageId"] = "changed"
        self.assertEqual(value, before)

    def test_all_closed_objects_reject_missing_extra_keys_and_wrong_types(self):
        value = fixture()

        def objects(item, parts=()):
            if not isinstance(item, dict):
                return []
            result = [] if parts == ("softwareClosure", "files") else [(parts, item)]
            for key, row in item.items():
                result += objects(row, parts + (key,))
            return result

        for parts, row in objects(value):
            for key in row:
                changed = copy.deepcopy(value)
                del at(changed, parts)[key]
                with self.subTest(parts=parts, missing=key), self.assertRaises(B.AcceptanceDenied):
                    B.validate_acceptance(changed)
            changed = copy.deepcopy(value)
            at(changed, parts)["extra"] = True
            with self.subTest(parts=parts, extra=True), self.assertRaises(B.AcceptanceDenied):
                B.validate_acceptance(changed)
            for wrong in (None, [], "object", 1, True):
                changed = copy.deepcopy(value)
                if parts:
                    at(changed, parts[:-1])[parts[-1]] = wrong
                else:
                    changed = wrong
                with self.subTest(parts=parts, wrong=wrong), self.assertRaises(B.AcceptanceDenied):
                    B.validate_acceptance(changed)

    def test_schema_specific_codes_and_numeric_types(self):
        cases = [(("schema",), "other", "ACCEPTANCE_SCHEMA_REQUIRED"),
                 (("installationRef",), "bad/ref", "ACCEPTANCE_IDENTITY_REQUIRED"),
                 (("entityRef",), False, "ACCEPTANCE_IDENTITY_REQUIRED"),
                 (("generation",), 0, "ACCEPTANCE_GENERATION_REQUIRED"),
                 (("startAuthorized",), True, "ACCEPTANCE_START_FORBIDDEN"),
                 (("startAuthorized",), 0, "ACCEPTANCE_START_FORBIDDEN"),
                 (("leaseAuthorized",), True, "ACCEPTANCE_LEASE_FORBIDDEN"),
                 (("leaseAuthorized",), 0, "ACCEPTANCE_LEASE_FORBIDDEN"),
                 (("creation", "evidence"), "CREATION_RECEIPT", "ACCEPTANCE_CREATION_EVIDENCE_REQUIRED"),
                 (("creation", "transactionRef"), "", "ACCEPTANCE_TRANSACTION_REQUIRED"),
                 (("roles", "adapter", "containerId"), "a" * 63, "ACCEPTANCE_CID_REQUIRED"),
                 (("roles", "southbound", "imageId"), "a" * 64, "ACCEPTANCE_IMAGE_ID_REQUIRED"),
                 (("roles", "adapter", "rootfs", "effectiveSeal", "schema"), "other", "ACCEPTANCE_SEAL_SCHEMA_REQUIRED"),
                 (("softwareClosure", "sourceCommit"), "a" * 39, "ACCEPTANCE_SOURCE_COMMIT_REQUIRED")]
        for parts, replacement, code in cases:
            with self.subTest(parts=parts):
                self.denied(parts, replacement, code)
        for parts, code in [(("generation",), "ACCEPTANCE_GENERATION_REQUIRED"),
                            (("issuedAt",), "ACCEPTANCE_ISSUED_AT_REQUIRED"),
                            (("roles", "adapter", "rootfs", "effectiveSeal", "entries"), "ACCEPTANCE_SEAL_ENTRIES_REQUIRED"),
                            (("roles", "adapter", "rootfs", "effectiveSeal", "bytes"), "ACCEPTANCE_SEAL_BYTES_REQUIRED")]:
            for wrong in (True, False, -1, 1.0, "1", None):
                with self.subTest(parts=parts, wrong=wrong):
                    self.denied(parts, wrong, code)
        self.denied(("roles", "adapter", "rootfs", "effectiveSeal", "entries"), 0, "ACCEPTANCE_SEAL_ENTRIES_REQUIRED")
        value = fixture()
        value["roles"]["adapter"]["rootfs"]["effectiveSeal"]["bytes"] = 0
        value["issuedAt"] = 0
        B.build_acceptance(**value)

    def test_cids_and_recipe_sets_must_be_distinct_even_when_reordered(self):
        value = fixture()
        self.denied(("roles", "southbound", "containerId"), value["roles"]["adapter"]["containerId"],
                    "ACCEPTANCE_DISTINCT_CIDS_REQUIRED")
        recipe = value["roles"]["adapter"]["recipe"]
        self.denied(("roles", "southbound", "recipe"), recipe, "ACCEPTANCE_DISTINCT_RECIPES_REQUIRED")
        self.denied(("roles", "southbound", "recipe"), dict(zip(B.RECIPE_PARTS, reversed(list(recipe.values())))),
                    "ACCEPTANCE_DISTINCT_RECIPES_REQUIRED")

    def test_paths_hashes_gaps_closure_bounds_and_payload_bound(self):
        for wrong in ("relative.json", "/a/../b", "/a/./b", "/a//b", "//a/b", "/a/", "/a\x00b", "C:\\file", None):
            self.denied(("profile", "path"), wrong, "ACCEPTANCE_ABSOLUTE_PATH_REQUIRED")
        for wrong in ("A" * 64, "a" * 63, "g" * 64, "sha256:" + "a" * 64, 64, None):
            self.denied(("profile", "sha256"), wrong, "ACCEPTANCE_SHA256_REQUIRED")
        for wrong in (None, {}, "GAP", ["lower_case"], ["CODE", "CODE"], [1], [[]], ["_CODE"], ["CODE__GAP"]):
            self.denied(("creation", "declaredGaps"), wrong, "ACCEPTANCE_GAP_CODES_REQUIRED")
        for name in ("/absolute.py", "../file", "a/../file", "a//b", "a/./b", "C:/file", ".", ""):
            self.denied(("softwareClosure", "files"), {name: "b" * 64}, "ACCEPTANCE_RELATIVE_PATH_REQUIRED")
        self.denied(("softwareClosure", "files"), {}, "ACCEPTANCE_CLOSURE_FILES_REQUIRED")
        self.denied(("softwareClosure", "files"), {str(i): "b" * 64 for i in range(257)}, "ACCEPTANCE_CLOSURE_FILES_REQUIRED")
        value = fixture()
        value["softwareClosure"]["files"] = {str(i): "b" * 64 for i in range(256)}
        B.build_acceptance(**value)
        value["softwareClosure"]["files"] = {"a" * 131072: "b" * 64}
        with self.assertRaisesRegex(B.AcceptanceDenied, "ACCEPTANCE_PAYLOAD_BOUND_REQUIRED"):
            B.build_acceptance(**value)

    def test_json_duplicate_nonfinite_malformed_and_bounds(self):
        for raw, code in [(b'{"a":1,"a":2}', "ACCEPTANCE_DUPLICATE_KEY"),
                          (b'{"a":NaN}', "ACCEPTANCE_JSON_REQUIRED"), (b"\xff", "ACCEPTANCE_JSON_REQUIRED"),
                          (b"{", "ACCEPTANCE_JSON_REQUIRED"), (b"[" * 2000, "ACCEPTANCE_JSON_REQUIRED"),
                          (b"[]", "ACCEPTANCE_FIELDS_REQUIRED"), (b"", "ACCEPTANCE_PAYLOAD_BOUND_REQUIRED"),
                          ("{}", "ACCEPTANCE_PAYLOAD_BOUND_REQUIRED"),
                          (b"x" * 131073, "ACCEPTANCE_PAYLOAD_BOUND_REQUIRED")]:
            with self.subTest(code=code), self.assertRaisesRegex(B.AcceptanceDenied, "^" + code + "$"):
                B.decode_manifest(raw)


class ExpectedSchemaTests(unittest.TestCase):
    def test_expected_contract_is_closed_and_rejects_malformed_pins(self):
        original = expected_for(fixture())
        self.assertEqual(B.validate_expected(original), original)
        for key in original:
            changed = copy.deepcopy(original)
            del changed[key]
            with self.subTest(missing=key), self.assertRaisesRegex(B.AcceptanceDenied, "^ACCEPTANCE_EXPECTED_FIELDS_REQUIRED$"):
                B.validate_expected(changed)
        with self.assertRaisesRegex(B.AcceptanceDenied, "^ACCEPTANCE_EXPECTED_FIELDS_REQUIRED$"):
            B.validate_expected(original | {"extra": True})
        cases = [(("issuerRef",), "bad/issuer", "ACCEPTANCE_EXPECTED_IDENTITY_REQUIRED"),
                 (("profileSha256",), "G" * 64, "ACCEPTANCE_EXPECTED_SHA256_REQUIRED"),
                 (("preparationA",), {}, "ACCEPTANCE_EXPECTED_PREPARATION_REQUIRED"),
                 (("preparationA", "files"), {}, "ACCEPTANCE_EXPECTED_PREPARATION_FILES_REQUIRED"),
                 (("preparationA", "files", "manifest"), None, "ACCEPTANCE_EXPECTED_SHA256_REQUIRED"),
                 (("roles",), {}, "ACCEPTANCE_EXPECTED_ROLES_REQUIRED"),
                 (("roles", "adapter"), {}, "ACCEPTANCE_EXPECTED_ROLE_FIELDS_REQUIRED"),
                 (("roles", "adapter", "containerId"), False, "ACCEPTANCE_EXPECTED_CID_REQUIRED"),
                 (("roles", "adapter", "imageId"), "wrong", "ACCEPTANCE_EXPECTED_IMAGE_ID_REQUIRED"),
                 (("trustPolicy", "path"), "relative", "ACCEPTANCE_ABSOLUTE_PATH_REQUIRED"),
                 (("minimumGeneration",), 0, "ACCEPTANCE_EXPECTED_GENERATION_REQUIRED"),
                 (("minimumGeneration",), True, "ACCEPTANCE_EXPECTED_GENERATION_REQUIRED")]
        for parts, wrong, code in cases:
            changed = copy.deepcopy(original)
            at(changed, parts[:-1])[parts[-1]] = wrong
            with self.subTest(parts=parts), self.assertRaisesRegex(B.AcceptanceDenied, "^" + code + "$"):
                B.validate_expected(changed)


@unittest.skipUnless(NATIVE, "set OUF_B1_ACCEPTANCE_NATIVE=1 under native Linux root")
class NativeVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tools/semantic_cohort_admission/cohort-draft"))
        try:
            cls.old = importlib.import_module("tools.semantic_provider_deployment_authentication")
        finally:
            sys.path.pop(0)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-b1-acceptance-test-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.openssl = Path("/usr/bin/openssl").resolve(strict=True)
        self.key_path = self.root / "disposable-test-key.pem"
        self.native("genpkey", "-algorithm", "Ed25519", "-out", str(self.key_path))
        self.key_path.chmod(0o600)
        public = self.native("pkey", "-in", str(self.key_path), "-pubout", "-outform", "DER")
        self.assertEqual(public[:12], A.DER_PREFIX)
        self.now = 2000000000
        self.value = fixture()
        self.policy_path = self.root / "public-test-policy.json"
        self.document = {"schema": A.POLICY_SCHEMA, "installationRef": self.value["installationRef"],
                         "entityRef": self.value["entityRef"], "basePolicy": synthetic_binding(str(self.root / "base.json")),
                         "authorityProfile": synthetic_binding(str(self.root / "authority.json")),
                         "keys": [{"keyRef": "fixture-key", "issuerRef": "fixture-installer",
                                   "roles": ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"], "publicKey": public[12:].hex(),
                                   "notBefore": self.now - 100, "expiresAt": self.now + 100, "state": "ACTIVE"}]}
        self.policy_path.write_bytes(A.canonical(self.document))
        self.policy_path.chmod(0o600)
        self.value["trustPolicy"] = self.policy_binding()
        self.expected = expected_for(self.value)
        self.raw = B.build_acceptance(**self.value)
        self.ssl = {"path": str(self.openssl), "sha256": sha(self.openssl.read_bytes()),
                    "version": self.native("version").decode().split()[1]}
        self.signature = self.envelope()

    def native(self, *args):
        return subprocess.run([str(self.openssl), *args], check=True, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout

    def policy_binding(self):
        return {"path": str(self.policy_path), "sha256": sha(self.policy_path.read_bytes())}

    def envelope(self, role="ARTIFACT_ACCEPTANCE", header_changes=None, old_domain=False):
        # Signing is confined to this test, with a newly generated disposable key.
        header = {"schema": A.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": "fixture-key", "role": role,
                  "issuerRef": "fixture-installer", "installationRef": self.value["installationRef"],
                  "entityRef": self.value["entityRef"], "payloadHash": sha(self.raw)}
        header.update(header_changes or {})
        frame = self.old.signing_bytes(self.raw, header) if old_domain else A.signing_bytes(self.raw, header)
        frame_path = self.root / "test-frame.bin"
        frame_path.write_bytes(frame)
        frame_path.chmod(0o600)
        signature = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.key_path), "-in", str(frame_path))
        self.assertEqual(len(signature), 64)
        return A.canonical(header | {"signature": signature.hex()})

    def verifier(self):
        return A.B1B2Authenticator(self.policy_binding(), self.ssl, clock=lambda: self.now)

    def verify(self, signature=None, expected=None, raw=None, authenticator=None):
        return B.verify_acceptance(self.raw if raw is None else raw,
                                   self.signature if signature is None else signature,
                                   expected=self.expected if expected is None else expected,
                                   authenticator=self.verifier() if authenticator is None else authenticator)

    def test_valid_signature_result_scope_and_generation_floor(self):
        self.assertEqual(self.verify(), {"payloadSha256": sha(self.raw), "manifest": self.value})
        self.value["generation"] = 2
        self.raw = B.build_acceptance(**self.value)
        self.signature = self.envelope()
        for floor in (1, 2):
            self.assertEqual(self.verify(expected=self.expected | {"minimumGeneration": floor})["manifest"]["generation"], 2)

    def test_wrong_role_legacy_envelope_and_relabelled_legacy_domain(self):
        with self.assertRaisesRegex(A.AuthorityDenied, "^EXACT_DETACHED_SIGNATURE_REQUIRED$"):
            self.verify(self.envelope(role="RUNTIME_ARMING"))
        old = self.envelope(role="DEPLOYMENT_INTENT", old_domain=True,
                            header_changes={"schema": "ouf.semantic-deployment-detached-signature.v1"})
        with self.assertRaisesRegex(A.AuthorityDenied, "^EXACT_DETACHED_SIGNATURE_REQUIRED$"):
            self.verify(old)
        relabelled = json.loads(self.signature) | {"signature": json.loads(old)["signature"]}
        with self.assertRaisesRegex(A.AuthorityDenied, "^DETACHED_SIGNATURE_INVALID$"):
            self.verify(A.canonical(relabelled))
        # Isolate domain separation with the otherwise identical valid B1 header.
        record = json.loads(self.signature)
        header = {key: item for key, item in record.items() if key != "signature"}
        frame = A.signing_bytes(self.raw, header)
        frame = self.old.DOMAIN + frame[len(A.DOMAIN):]
        path = self.root / "wrong-domain.bin"
        path.write_bytes(frame)
        signature = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.key_path), "-in", str(path)).hex()
        with self.assertRaisesRegex(A.AuthorityDenied, "^DETACHED_SIGNATURE_INVALID$"):
            self.verify(A.canonical(header | {"signature": signature}))

    def test_payload_tamper_envelope_scope_and_signature_tamper(self):
        for change in ({"issuerRef": "other-installer"}, {"installationRef": "other-installation"},
                       {"entityRef": "other-entity"}, {"payloadHash": "0" * 64}, {"extra": True}):
            with self.subTest(change=change), self.assertRaisesRegex(A.AuthorityDenied, "^EXACT_DETACHED_SIGNATURE_REQUIRED$"):
                self.verify(A.canonical(json.loads(self.signature) | change))
        with self.assertRaisesRegex(A.AuthorityDenied, "^DETACHED_SIGNATURE_INVALID$"):
            self.verify(A.canonical(json.loads(self.signature) | {"signature": "00" * 64}))
        for raw in (self.raw + b"\n", self.raw.replace(b'"generation":1', b'"generation":2')):
            with self.assertRaisesRegex(A.AuthorityDenied, "^EXACT_DETACHED_SIGNATURE_REQUIRED$"):
                self.verify(raw=raw)

    def test_every_expected_pin_has_a_specific_mismatch_code(self):
        cases = [(("installationRef",), "other-installation", "ACCEPTANCE_INSTALLATION_MISMATCH"),
                 (("entityRef",), "other-entity", "ACCEPTANCE_ENTITY_MISMATCH"),
                 (("issuerRef",), "other-installer", "EXACT_DETACHED_SIGNATURE_REQUIRED"),
                 (("profileSha256",), "0" * 64, "ACCEPTANCE_PROFILE_MISMATCH"),
                 (("preparationA", "planSha256"), "0" * 64, "ACCEPTANCE_A_PLAN_MISMATCH"),
                 (("trustPolicy", "path"), "/other/policy.json", "ACCEPTANCE_TRUST_POLICY_MISMATCH"),
                 (("trustPolicy", "sha256"), "0" * 64, "ACCEPTANCE_TRUST_POLICY_MISMATCH"),
                 (("minimumGeneration",), 2, "ACCEPTANCE_GENERATION_MISMATCH")]
        for key, label in (("manifest", "MANIFEST"), ("result", "RESULT"),
                           ("semanticPeer", "SEMANTIC_PEER"), ("successors", "SUCCESSORS")):
            cases.append((("preparationA", "files", key), "0" * 64, "ACCEPTANCE_A_" + label + "_MISMATCH"))
        for role in B.ROLES:
            cases += [(("roles", role, "containerId"), "0" * 64, "ACCEPTANCE_CID_MISMATCH"),
                      (("roles", role, "imageId"), "sha256:" + "0" * 64, "ACCEPTANCE_IMAGE_MISMATCH")]
        for parts, replacement, code in cases:
            expected = copy.deepcopy(self.expected)
            at(expected, parts[:-1])[parts[-1]] = replacement
            with self.subTest(parts=parts), self.assertRaisesRegex((B.AcceptanceDenied, A.AuthorityDenied), "^" + code + "$"):
                self.verify(expected=expected)

    def test_authenticator_policy_must_match_signed_and_expected_binding(self):
        verifier = self.verifier()
        verifier.policy_binding = verifier.policy_binding | {"sha256": "0" * 64}
        with self.assertRaisesRegex(B.AcceptanceDenied, "^ACCEPTANCE_TRUST_POLICY_MISMATCH$"):
            self.verify(authenticator=verifier)
        with self.assertRaisesRegex(B.AcceptanceDenied, "^ACCEPTANCE_AUTHENTICATOR_REQUIRED$"):
            self.verify(authenticator=object())

    def test_current_active_mandate_required_even_for_earlier_issued_payload(self):
        self.assertTrue(self.verify())
        self.now += 100  # At expiresAt, payload and signature remain byte-for-byte unchanged.
        with self.assertRaisesRegex(A.AuthorityDenied, "^ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED$"):
            self.verify()

    def test_verification_callback_must_explicitly_succeed(self):
        verifier = self.verifier()
        for result in (False, None):
            with patch.object(verifier, "verify_b1b2_detached", return_value=result):
                with self.subTest(result=result), self.assertRaisesRegex(B.AcceptanceDenied, "^ACCEPTANCE_SIGNATURE_UNPROVEN$"):
                    self.verify(authenticator=verifier)

    def test_revoked_and_future_mandates_are_rejected(self):
        for change in ({"state": "REVOKED"}, {"notBefore": self.now + 1}):
            document = copy.deepcopy(self.document)
            document["keys"][0].update(change)
            self.policy_path.write_bytes(A.canonical(document))
            self.value["trustPolicy"] = self.policy_binding()
            self.expected = expected_for(self.value)
            self.raw = B.build_acceptance(**self.value)
            self.signature = self.envelope()
            with self.subTest(change=change), self.assertRaisesRegex(A.AuthorityDenied, "^ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED$"):
                self.verify()


if __name__ == "__main__":
    unittest.main()
