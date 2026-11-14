"""Public contract tests plus opt-in, native root/OpenSSL custody tests."""

from contextlib import redirect_stdout
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/prepare-semantic-provider-b1b2-trust-policy.py"
P = runpy.run_path(str(SCRIPT))
A = P["A"]
NATIVE = os.environ.get("OUF_B1B2_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_B1B2_NATIVE requires native Linux root:root; refusing to skip acceptance tests")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def grant():
    return {"keyRef": "installer-key", "issuerRef": "installer-issuer",
            "roles": ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"], "publicKey": "ab" * 32,
            "notBefore": 100, "expiresAt": 2100000000, "state": "ACTIVE"}


def policy():
    return {"schema": A.POLICY_SCHEMA, "installationRef": "fixture-installation", "entityRef": "fixture-entity",
            "basePolicy": {"path": str(ROOT / "base.json"), "sha256": "a" * 64},
            "authorityProfile": {"path": str(ROOT / "authority.json"), "sha256": "b" * 64}, "keys": [grant()]}


def header(role="ARTIFACT_ACCEPTANCE", raw=b"public payload"):
    return {"schema": A.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": "installer-key", "role": role,
            "issuerRef": "installer-issuer", "installationRef": "fixture-installation", "entityRef": "fixture-entity",
            "payloadHash": sha(raw)}


class SchemaTests(unittest.TestCase):
    def validate(self, value):
        return A.policy(A.canonical(value), "fixture-installation", "fixture-entity")

    def test_valid_subsets_revoked_and_eight_keys(self):
        for roles in (["ARTIFACT_ACCEPTANCE"], ["RUNTIME_ARMING"], sorted(A.B1B2_ROLES)):
            value = policy()
            value["keys"][0]["roles"] = roles
            value["keys"][0]["state"] = "REVOKED"
            self.assertEqual(self.validate(value), value)
        value = policy()
        value["keys"] = [grant() | {"keyRef": "key-" + str(i)} for i in range(8)]
        self.assertEqual(len(self.validate(value)["keys"]), 8)

    def test_schema_closed_fields_and_bindings(self):
        for place in ((), ("keys", 0), ("basePolicy",), ("authorityProfile",)):
            value = policy()
            target = value
            for part in place:
                target = target[part]
            target["extra"] = True
            with self.subTest(place=place), self.assertRaises(A.AuthorityDenied):
                self.validate(value)
        for field in list(policy()):
            value = policy()
            del value[field]
            with self.subTest(missing=field), self.assertRaises(A.AuthorityDenied):
                self.validate(value)
        for binding in ({"path": "relative", "sha256": "a" * 64},
                        {"path": str(ROOT / "base.json"), "sha256": "A" * 64}):
            with self.assertRaises(A.AuthorityDenied):
                self.validate(policy() | {"basePolicy": binding})
        with self.assertRaises(A.AuthorityDenied):
            A.policy(A.canonical(policy()), "other-installation", "fixture-entity")

    def test_all_legacy_unknown_duplicate_and_malformed_roles_rejected(self):
        bad = [[role] for role in A.BASE_ROLES] + [["UNKNOWN"], [], ["ARTIFACT_ACCEPTANCE"] * 2,
               ["RUNTIME_ARMING"] * 2, ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING", "UNKNOWN"], [None], [{}], "RUNTIME_ARMING"]
        for roles in bad:
            value = policy()
            value["keys"][0]["roles"] = roles
            with self.subTest(roles=roles), self.assertRaises(A.AuthorityDenied):
                self.validate(value)

    def test_bad_keys_and_windows(self):
        changes = [{"notBefore": -1}, {"notBefore": 100, "expiresAt": 100}, {"expiresAt": 99},
                   {"notBefore": True}, {"expiresAt": 2100000000.0}, {"state": "DISABLED"},
                   {"keyRef": "bad/key"}, {"issuerRef": ""}, {"publicKey": "AB" * 32}, {"publicKey": "ab"}]
        for change in changes:
            value = policy()
            value["keys"][0].update(change)
            with self.subTest(change=change), self.assertRaises(A.AuthorityDenied):
                self.validate(value)
        for keys in ([], [grant()] * 2, [grant() | {"keyRef": str(i)} for i in range(9)], {}):
            with self.subTest(keys=keys), self.assertRaises(A.AuthorityDenied):
                self.validate(policy() | {"keys": keys})

    def test_json_duplicates_constants_size_and_type(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"a":NaN}', b"[]", b"\xff", b"{}" * 40000, "{}"):
            with self.subTest(raw=str(raw)[:50]), self.assertRaises(A.AuthorityDenied):
                A.decode(raw)

    def test_signing_frame_exact_scope_and_role(self):
        raw = b"public payload"
        frame = A.signing_bytes(raw, header())
        self.assertTrue(frame.startswith(A.DOMAIN))
        self.assertNotEqual(frame, A.signing_bytes(raw, header("RUNTIME_ARMING")))
        for change in ({"schema": "ouf.semantic-deployment-detached-signature.v1"}, {"role": "DEPLOYMENT_INTENT"},
                       {"role": []}, {"algorithm": "RSA"}, {"payloadHash": "0" * 64}, {"extra": 0}):
            with self.subTest(change=change), self.assertRaises(A.AuthorityDenied):
                A.signing_bytes(raw, header() | change)
        for raw in (b"", b"x" * 131073, "payload"):
            with self.assertRaises(A.AuthorityDenied):
                A.signing_bytes(raw, header())

    def test_monotonic_budget_and_explicit_deadline(self):
        tick = [10.0]
        budget = A.VerificationBudget(3, deadline=12, monotonic=lambda: tick[0])
        self.assertEqual(budget.remaining(), 2)
        tick[0] = 11.5
        self.assertEqual(budget.remaining(), 0.5)
        tick[0] = 12
        with self.assertRaisesRegex(A.AuthorityDenied, "AUTHENTICATION_DEADLINE_MISSED"):
            budget.check()
        for seconds, deadline in ((0, None), (19, None), (True, None), (3, 12), (3, 16)):
            with self.subTest(seconds=seconds, deadline=deadline), self.assertRaises(A.AuthorityDenied):
                A.VerificationBudget(seconds, deadline=deadline, monotonic=lambda: 12)


@unittest.skipUnless(NATIVE, "set OUF_B1B2_NATIVE=1 under native Linux root")
class NativeFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-b1b2-test-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.old_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.old_umask)
        self.base_path = self.root / "base.json"
        self.profile_path = self.root / "authority.json"
        self.private = self.root / "installer-private.pem"
        self.write(self.private, b"unreadable dummy; must never be opened by the controller")
        self.private.chmod(0)
        self.attestor_private = self.root / "missing-attestor-private.pem"
        self.base = {"schema": "ouf.semantic-deployment-trust-policy.v1", "installationRef": "fixture-installation",
                     "entityRef": "fixture-entity", "keys": [grant() | {
                         "roles": ["DEPLOYMENT_INTENT", "FINAL_DEPLOYMENT_APPROVAL"]},
                         grant() | {"keyRef": "attestor-key", "issuerRef": "attestor-issuer", "roles": ["CREATION_ATTESTATION"]}]}
        self.write(self.base_path, A.canonical(self.base))
        self.profile = {"schema": "ouf.semantic-existing-installation-authority-bindings.v1",
                        "sourceCommit": "c" * 40, "sourceRoot": str(self.root / "source"),
                        "sourceHashes": {"tools/fixture.py": "d" * 64},
                        "authorities": {"installationRef": "fixture-installation", "entityRef": "fixture-entity",
                                        "intentIssuerRef": "installer-issuer", "approvalIssuerRef": "installer-issuer",
                                        "attestorRef": "attestor-issuer"},
                        "keyRefs": {"installer": "installer-key", "attestor": "attestor-key"},
                        "keyBindings": {"installer": {"path": str(self.private), "sha256": "e" * 64},
                                        "attestor": {"path": str(self.attestor_private), "sha256": "f" * 64}},
                        "policyBinding": self.binding(self.base_path),
                        "custodyReceiptBinding": {"path": str(self.root / "absent-custody.json"), "sha256": "0" * 64}}
        self.write(self.profile_path, A.canonical(self.profile))
        self.args = types.SimpleNamespace(base_policy=str(self.base_path), base_policy_sha256=sha(self.base_path.read_bytes()),
                                         authority_profile=str(self.profile_path), authority_sha256=sha(self.profile_path.read_bytes()),
                                         installation_ref="fixture-installation", entity_ref="fixture-entity",
                                         not_before=200, expires_at=2082758400, output_root=str(self.root), output_name="new-b1b2")

    def write(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def binding(self, path):
        return {"path": str(path), "sha256": sha(path.read_bytes())}

    def update_base(self):
        self.write(self.base_path, A.canonical(self.base))
        self.args.base_policy_sha256 = sha(self.base_path.read_bytes())
        self.profile["policyBinding"] = self.binding(self.base_path)
        self.update_profile()

    def update_profile(self):
        self.write(self.profile_path, A.canonical(self.profile))
        self.args.authority_sha256 = sha(self.profile_path.read_bytes())

    def cli(self, mode="--plan", digest=None, **changes):
        args = vars(self.args) | changes
        argv = [mode]
        for name, value in args.items():
            argv.extend(["--" + name.replace("_", "-"), str(value)])
        if digest is not None:
            argv.extend(["--plan-sha256", digest])
        output = io.StringIO()
        with redirect_stdout(output):
            code = P["main"](argv)
        return code, json.loads(output.getvalue())


class ControllerNativeTests(NativeFixture):
    def test_plan_apply_cli_and_no_private_path_opens(self):
        forbidden = {str(self.private), str(self.attestor_private)}
        opened = []

        def audit(event, args):
            if active[0] and event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
                name = os.fsdecode(args[0])
                opened.append(name)
                if name in forbidden:
                    raise AssertionError("controller attempted a private-key open")

        active = [True]
        sys.addaudithook(audit)
        try:
            before = {str(path): A.attributes(path.lstat()) for path in self.root.iterdir()}
            code, plan = self.cli()
            self.assertEqual((code, plan["status"], plan["privateKeysRead"]), (0, "PLAN_READY", 0))
            self.assertEqual(before, {str(path): A.attributes(path.lstat()) for path in self.root.iterdir()})
            projection = {key: value for key, value in plan.items() if key not in ("planSha256", "status")}
            self.assertEqual(plan["planSha256"], sha(A.canonical(projection)))
            self.assertEqual(plan["inputHashes"], {str(self.base_path): self.args.base_policy_sha256,
                                                   str(self.profile_path): self.args.authority_sha256})
            code, result = self.cli("--apply", plan["planSha256"])
            self.assertEqual((code, result["status"], result["privateKeysRead"]),
                             (0, "SEMANTIC_PROVIDER_B1B2_TRUST_POLICY_PREPARED", 0))
            self.assertTrue(result["publication"]["readbackVerified"])
            target = Path(result["writes"]["policyFile"])
            info, parent = target.stat(), target.parent.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (0, 0, 0o600, 1))
            self.assertEqual((parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)), (0, 0, 0o700))
            self.assertEqual(list(target.parent.iterdir()), [target])
            self.assertEqual(sha(target.read_bytes()), plan["policySha256"])
            self.assertEqual(A.policy(target.read_bytes(), self.args.installation_ref, self.args.entity_ref), plan["policy"])
            key = plan["policy"]["keys"][0]
            for field in ("keyRef", "issuerRef", "publicKey"):
                self.assertEqual(key[field], self.base["keys"][0][field])
            self.assertEqual(key["roles"], ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"])
            self.assertEqual(self.cli()[1]["reason"], "OUTPUT_ALREADY_EXISTS")
            self.assertTrue(opened)
            self.assertFalse(forbidden.intersection(opened))
        finally:
            active[0] = False

    def test_cli_isolated_entrypoint(self):
        argv = [sys.executable, "-I", "-B", str(SCRIPT), "--plan"]
        for name, value in vars(self.args).items():
            argv.extend(["--" + name.replace("_", "-"), str(value)])
        result = subprocess.run(argv, capture_output=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout)["status"], "PLAN_READY")

    def test_delivery_bootstrap_checks_both_sources_without_network(self):
        launcher = (ROOT / "scripts/deliver-semantic-provider-b1b2-trust-policy.sh").read_text()
        bootstrap = launcher.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0].encode()
        # Same flat layout as the launcher; only the preloaded, checked module
        # makes this controller executable here. This exercises -I without curl.
        controller = self.root / SCRIPT.name
        authority = self.root / "authority.py"
        self.write(controller, SCRIPT.read_bytes())
        self.write(authority, (ROOT / "tools/semantic_b1b2_authority/authority.py").read_bytes())
        argv = [sys.executable, "-I", "-B", "-", str(controller), sha(controller.read_bytes()),
                str(authority), sha(authority.read_bytes()), "--plan"]
        for name, value in vars(self.args).items():
            argv.extend(["--" + name.replace("_", "-"), str(value)])
        result = subprocess.run(argv, input=bootstrap, capture_output=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout)["status"], "PLAN_READY")
        for index in (5, 7):
            bad = argv.copy()
            bad[index] = "0" * 64
            result = subprocess.run(bad, input=bootstrap, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"B1B2_SOURCE_CHANGED", result.stderr)

    def test_wrong_base_hash_scope_and_profile_binding(self):
        for changes, reason in (({"base_policy_sha256": "0" * 64}, "BOUND_INPUT_HASH_CHANGED"),
                                ({"authority_sha256": "0" * 64}, "BOUND_INPUT_HASH_CHANGED"),
                                ({"installation_ref": "wrong"}, "EXACT_BASE_TRUST_POLICY_REQUIRED"),
                                ({"entity_ref": "wrong"}, "EXACT_BASE_TRUST_POLICY_REQUIRED")):
            with self.subTest(changes=changes):
                code, report = self.cli(**changes)
                self.assertEqual((code, report["status"], report["reason"]), (1, "HELD", reason))
        self.profile["policyBinding"]["sha256"] = "1" * 64
        self.update_profile()
        self.assertEqual(self.cli()[1]["reason"], "AUTHORITY_BASE_POLICY_BINDING_DIFFERS")

    def test_base_schema_and_installer_must_conform(self):
        original = copy.deepcopy(self.base)
        cases = [({"roles": ["DEPLOYMENT_INTENT"]}, "INSTALLER_GRANT_NONCONFORMING"),
                 ({"roles": sorted(A.BASE_ROLES)}, "INSTALLER_GRANT_NONCONFORMING"),
                 ({"state": "REVOKED"}, "INSTALLER_GRANT_NONCONFORMING"),
                 ({"issuerRef": "wrong"}, "INSTALLER_GRANT_NONCONFORMING"),
                 ({"keyRef": "other"}, "INSTALLER_KEY_NOT_FOUND"),
                 ({"roles": ["ARTIFACT_ACCEPTANCE"]}, "EXACT_LOCAL_KEY_MANDATE_REQUIRED")]
        for change, reason in cases:
            self.base = copy.deepcopy(original)
            self.base["keys"][0].update(change)
            self.update_base()
            with self.subTest(change=change):
                self.assertEqual(self.cli()[1]["reason"], reason)
        self.base = original | {"schema": A.POLICY_SCHEMA}
        self.update_base()
        self.assertEqual(self.cli()[1]["reason"], "EXACT_BASE_TRUST_POLICY_REQUIRED")

    def test_invalid_window_reports_base_values_and_never_writes(self):
        for changes in ({"not_before": 99}, {"expires_at": 2100000001}, {"expires_at": 200},
                        {"not_before": 2100000001}):
            with self.subTest(changes=changes):
                code, report = self.cli(**changes)
                self.assertEqual((code, report["reason"]), (1, "B1B2_WINDOW_OUTSIDE_BASE"))
                self.assertEqual((report["baseNotBefore"], report["baseExpiresAt"]), (100, 2100000000))
                self.assertFalse((self.root / self.args.output_name).exists())

    def test_stale_plan_cannot_write(self):
        _, plan = self.cli()
        for changes in ({}, {"expires_at": self.args.expires_at - 1}):
            code, report = self.cli("--apply", "0" * 64 if not changes else plan["planSha256"], **changes)
            self.assertEqual((code, report["reason"]), (1, "PLAN_DIGEST_CHANGED"))
            self.assertFalse((self.root / self.args.output_name).exists())
        self.profile["sourceCommit"] = "b" * 40
        self.update_profile()
        self.assertEqual(self.cli("--apply", plan["planSha256"])[1]["reason"], "PLAN_DIGEST_CHANGED")

    def test_names_existing_output_and_root_custody(self):
        for name in ("../escape", ".", "a/b", ".hidden", "a.b", "x" * 97):
            with self.subTest(name=name):
                self.assertEqual(self.cli(output_name=name)[1]["reason"], "RESTRICTED_OUTPUT_NAME_REQUIRED")
        target = self.root / self.args.output_name
        target.symlink_to(self.root / "absent")
        self.assertEqual(self.cli()[1]["reason"], "OUTPUT_ALREADY_EXISTS")
        target.unlink()
        with patch.object(os, "geteuid", return_value=1):
            self.assertEqual(self.cli()[1]["reason"], "ROOT_CUSTODY_REQUIRED")
        self.root.chmod(0o777)
        self.assertEqual(self.cli()[1]["reason"], "TRUSTED_AUTHENTICATION_ANCESTOR_REQUIRED")

    def test_input_custody_modes_owner_group_links_and_symlink(self):
        for path in (self.base_path, self.profile_path):
            original = path.read_bytes()
            for defect in ("mode", "uid", "gid", "hardlink", "symlink"):
                saved = self.root / "saved"
                if defect == "mode":
                    path.chmod(0o644)
                elif defect in ("uid", "gid"):
                    os.chown(path, int(defect == "uid"), int(defect == "gid"))
                elif defect == "hardlink":
                    os.link(path, saved)
                else:
                    path.rename(saved)
                    path.symlink_to(saved)
                try:
                    with self.subTest(path=path.name, defect=defect):
                        self.assertEqual(self.cli()[1]["status"], "HELD")
                finally:
                    if defect == "symlink":
                        path.unlink()
                        saved.rename(path)
                    elif defect == "hardlink":
                        saved.unlink()
                    os.chown(path, 0, 0)
                    self.write(path, original)

    def test_no_overwrite_and_no_rollback_on_link_failure(self):
        proposal = P["observe"](self.args)
        outcome = {}
        with patch.object(os, "link", side_effect=OSError("injected link failure")):
            with self.assertRaises(OSError):
                P["publish"](proposal, outcome)
        target = self.root / self.args.output_name
        self.assertTrue(target.is_dir())
        self.assertTrue(Path(outcome["temporaryFile"]).is_file())
        self.assertFalse((target / "trust-policy.json").exists())
        self.assertEqual(self.cli()[1]["reason"], "OUTPUT_ALREADY_EXISTS")


class SignatureNativeTests(NativeFixture):
    @classmethod
    def setUpClass(cls):
        # Import the actual unmodified deployment implementation for cross-tests.
        path = str(ROOT / "tools/semantic_cohort_admission/cohort-draft")
        sys.path.insert(0, path)
        try:
            cls.old = importlib.import_module("tools.semantic_provider_deployment_authentication")
        finally:
            sys.path.remove(path)

    def setUp(self):
        super().setUp()
        self.openssl = Path("/usr/bin/openssl").resolve(strict=True)
        self.key_path = self.root / "test-only-generated.pem"
        self.native("genpkey", "-algorithm", "Ed25519", "-out", str(self.key_path))
        self.key_path.chmod(0o600)
        public = self.native("pkey", "-in", str(self.key_path), "-pubout", "-outform", "DER")
        self.assertEqual(public[:12], A.DER_PREFIX)
        self.public = public[12:].hex()
        self.document = policy()
        self.document["keys"][0]["publicKey"] = self.public
        self.policy_path = self.root / "b1b2-policy.json"
        self.write(self.policy_path, A.canonical(self.document))
        self.base["keys"][0]["publicKey"] = self.public
        self.update_base()
        self.ssl_binding = self.binding(self.openssl) | {"version": self.native("version").decode().split()[1]}
        self.now = 2000000000
        self.raw = b"public payload"

    def native(self, *args):
        return subprocess.run([str(self.openssl), *args], check=True, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout

    def sign(self, frame):
        path = self.root / "test-frame.bin"
        self.write(path, frame)
        result = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.key_path), "-in", str(path))
        self.assertEqual(len(result), 64)
        return result.hex()

    def envelope(self, role="ARTIFACT_ACCEPTANCE"):
        scope = header(role)
        return A.canonical(scope | {"signature": self.sign(A.signing_bytes(self.raw, scope))})

    def verifier(self, **options):
        return A.B1B2Authenticator(self.binding(self.policy_path), self.ssl_binding, clock=lambda: self.now, **options)

    def verify(self, verifier, envelope, role="ARTIFACT_ACCEPTANCE"):
        return verifier.verify_b1b2_detached(self.raw, envelope, role, "installer-issuer", "fixture-installation", "fixture-entity")

    def old_verifier(self):
        signatures = self.root / "signatures"
        signatures.mkdir(mode=0o700, exist_ok=True)
        return self.old.DetachedAuthenticator(self.binding(self.base_path), str(signatures), self.ssl_binding,
                                               clock=lambda: self.now, budget=self.old.VerificationBudget(18))

    def test_valid_both_roles_and_function_api(self):
        for role in sorted(A.B1B2_ROLES):
            envelope = self.envelope(role)
            self.assertTrue(self.verify(self.verifier(), envelope, role))
            self.assertTrue(A.verify_b1b2_detached(self.raw, envelope, role, "installer-issuer", "fixture-installation",
                                                 "fixture-entity", policy_binding=self.binding(self.policy_path),
                                                 openssl_binding=self.ssl_binding, clock=lambda: self.now))

    def test_wrong_role_payload_issuer_signature_and_extra_fields(self):
        record = json.loads(self.envelope())
        with self.assertRaises(A.AuthorityDenied):
            self.verify(self.verifier(), A.canonical(record), "RUNTIME_ARMING")
        for change in ({"role": "DEPLOYMENT_INTENT"}, {"issuerRef": "wrong"}, {"entityRef": "wrong"},
                       {"payloadHash": "0" * 64}, {"signature": "00" * 64}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(A.AuthorityDenied):
                self.verify(self.verifier(), A.canonical(record | change))
        with self.assertRaisesRegex(A.AuthorityDenied, "EXACT_AUTHENTICATION_SCOPE_REQUIRED"):
            self.verify(self.verifier(), A.canonical(record), "DEPLOYMENT_INTENT")

    def test_inactive_future_expired_and_finish_window(self):
        envelope = self.envelope()
        for change in ({"state": "REVOKED"}, {"notBefore": self.now + 1}, {"expiresAt": self.now}):
            self.document["keys"] = [grant() | {"publicKey": self.public} | change]
            self.write(self.policy_path, A.canonical(self.document))
            with self.subTest(change=change), self.assertRaisesRegex(A.AuthorityDenied, "ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED"):
                self.verify(self.verifier(), envelope)
        self.document["keys"] = [grant() | {"publicKey": self.public}]
        self.write(self.policy_path, A.canonical(self.document))
        for finish in (self.now - 1, 2100000000):
            verifier = self.verifier()
            verifier.clock = iter([self.now, finish]).__next__
            with self.assertRaisesRegex(A.AuthorityDenied, "LOCAL_MANDATE_EXPIRED_OR_CLOCK_REGRESSED"):
                self.verify(verifier, envelope)

    def test_policy_changed_during_real_native_verification(self):
        envelope = self.envelope()
        verifier = self.verifier()
        native = verifier.verify

        def changed(*args):
            native(*args)
            self.write(self.policy_path, A.canonical(self.document) + b"\n")

        with patch.object(verifier, "verify", side_effect=changed):
            with self.assertRaisesRegex(A.AuthorityDenied, "LOCAL_TRUST_POLICY_REVOKED_OR_CHANGED"):
                self.verify(verifier, envelope)

    def test_openssl_hash_version_and_deadline_fail_closed(self):
        envelope = self.envelope()
        for change, reason in (({"sha256": "0" * 64}, "AUTHENTICATION_EXECUTABLE_DRIFT"),
                               ({"version": "0.0.0"}, "DETACHED_OPENSSL_VERSION_UNPROVEN")):
            verifier = A.B1B2Authenticator(self.binding(self.policy_path), self.ssl_binding | change, clock=lambda: self.now)
            with self.subTest(change=change), self.assertRaisesRegex(A.AuthorityDenied, reason):
                self.verify(verifier, envelope)
        tick = [10.0]
        verifier = self.verifier(budget=A.VerificationBudget(1, monotonic=lambda: tick[0]))
        tick[0] = 11
        with self.assertRaisesRegex(A.AuthorityDenied, "AUTHENTICATION_DEADLINE_MISSED"):
            self.verify(verifier, envelope)

    def test_domains_and_real_cross_verification_in_both_directions(self):
        self.assertNotEqual(A.DOMAIN, self.old.DOMAIN)
        b1b2_scope = header()
        b1b2_record = json.loads(self.envelope())
        old_scope = b1b2_scope | {"schema": "ouf.semantic-deployment-detached-signature.v1", "role": "DEPLOYMENT_INTENT"}
        old_frame = self.old.signing_bytes(self.raw, old_scope)
        old_record = old_scope | {"signature": self.sign(old_frame)}
        old_verifier = self.old_verifier()
        self.assertTrue(old_verifier.verify_detached(self.raw, A.canonical(old_record), "DEPLOYMENT_INTENT",
                                                     "installer-issuer", "fixture-installation", "fixture-entity"))
        with self.assertRaises(self.old.PreexecDenied):
            old_verifier.verify_detached(self.raw, A.canonical(b1b2_record), "DEPLOYMENT_INTENT",
                                         "installer-issuer", "fixture-installation", "fixture-entity")
        with self.assertRaises(A.AuthorityDenied):
            self.verify(self.verifier(), A.canonical(old_record))
        # Even relabeling the public schema/role cannot reuse either signature.
        with self.assertRaisesRegex(self.old.PreexecDenied, "DETACHED_SIGNATURE_INVALID"):
            old_verifier.verify_detached(self.raw, A.canonical(old_scope | {"signature": b1b2_record["signature"]}),
                                         "DEPLOYMENT_INTENT", "installer-issuer", "fixture-installation", "fixture-entity")
        with self.assertRaisesRegex(A.AuthorityDenied, "DETACHED_SIGNATURE_INVALID"):
            self.verify(self.verifier(), A.canonical(b1b2_scope | {"signature": old_record["signature"]}))
        # Isolate the domain itself while holding the entire valid header fixed.
        new_frame = A.signing_bytes(self.raw, b1b2_scope)
        wrong_new = self.old.DOMAIN + new_frame[len(A.DOMAIN):]
        wrong_old = A.DOMAIN + old_frame[len(self.old.DOMAIN):]
        with self.assertRaisesRegex(A.AuthorityDenied, "DETACHED_SIGNATURE_INVALID"):
            self.verify(self.verifier(), A.canonical(b1b2_scope | {"signature": self.sign(wrong_new)}))
        with self.assertRaisesRegex(self.old.PreexecDenied, "DETACHED_SIGNATURE_INVALID"):
            old_verifier.verify_detached(self.raw, A.canonical(old_scope | {"signature": self.sign(wrong_old)}),
                                         "DEPLOYMENT_INTENT", "installer-issuer", "fixture-installation", "fixture-entity")


if __name__ == "__main__":
    unittest.main()
