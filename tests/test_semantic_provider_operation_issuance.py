"""Native root-only issuance, disposable Ed25519 key and real mandate ledger."""
import json
from contextlib import redirect_stdout, redirect_stderr
import io
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
import test_semantic_provider_r3_compose as fixtures

ROOT, A, C = fixtures.ROOT, fixtures.A, fixtures.C
issue = fixtures.load("scripts/issue-semantic-provider-operation-authorization.py", "r3_operation_issuer")
operation = fixtures.load("tests/test_semantic_provider_operation.py", "r3_native_operation_fixture")
NATIVE = os.environ.get("OUF_OPERATION_ISSUANCE_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_OPERATION_ISSUANCE_NATIVE requires Linux root:root; refusing to skip")


class PortableTests(unittest.TestCase):
    def test_cli_argument_error_is_public_code_only(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(issue.main(["--unknown", "PRIVATE_SENTINEL"]), 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "INVALID_ARGUMENTS")
        self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
        self.assertEqual(errors.getvalue(), "")

    def test_public_errors_never_include_exception_content(self):
        for error in (ValueError("SECRET_SENTINEL"), OSError("/private/key"), RuntimeError("a key value")):
            self.assertEqual(issue.public(error), "INPUT_OR_IO_UNPROVEN")
        self.assertEqual(issue.public(A.OperationDenied("PLAN_DIGEST_MISMATCH")), "PLAN_DIGEST_MISMATCH")

    def test_exact_key_exclusion_happens_before_open(self):
        # Lexical path only on Windows: the exclusion precedes all custody IO.
        with patch.object(issue.AUTH, "Path", fixtures.PurePosixPath):
            reader = issue.Reader(["/private/installer.pem"])
            with patch.object(issue.os, "open", side_effect=AssertionError("must not open")):
                with self.assertRaisesRegex(A.OperationDenied, "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN"):
                    reader.read("/private/installer.pem", "1" * 64)


@unittest.skipUnless(NATIVE, "set OUF_OPERATION_ISSUANCE_NATIVE=1 under Linux root:root")
class NativeTests(operation.Fixture):
    __unittest_skip__ = False  # the base's independent native gate does not govern this suite

    def key(self, name, roles):
        return {**super().key(name, roles), "notBefore": int(time.time()) - 3600, "expiresAt": int(time.time()) + 3600}

    def setUp(self):
        super().setUp()
        self.now = int(time.time())
        self.install = self.root / "install"
        self.install.mkdir(mode=0o700)
        self.chain = self.install / "authorization"  # initially absent
        self.output = self.root / "issued"
        self.inputs = fixtures.fixture()
        settings = json.loads(self.inputs["files"]["settings"])
        settings.update(installationRef="inst", entityRef="ent", issuerRef="installer", installRoot=str(self.install),
            issuedAt=self.now, anchorBinding=self.anchor, mandateRoot=str(self.ledger_root), opensslBinding=self.ssl)
        self.owner = self.root / "owner.json"
        self.write(self.owner, self.inputs["files"]["coordinator"])
        settings["coordinatorBinding"] = {"path": str(self.owner), "sha256": A.sha(self.owner.read_bytes())}
        # Bind the real fixture anchor to this public authority profile.
        self.profile = self.root / "authority.json"
        self.write(self.profile, A.canonical({"schema": "ouf.semantic-existing-installation-authority-bindings.v1",
            "authorities": {"installationRef": "inst", "entityRef": "ent", "intentIssuerRef": "installer",
                            "approvalIssuerRef": "installer"},
            "keyBindings": {"installer": {"path": str(self.keys["key-a"]), "sha256": A.sha(self.keys["key-a"].read_bytes())},
                            "attestor": {"path": str(self.keys["key-b"]), "sha256": A.sha(self.keys["key-b"].read_bytes())}},
            "keyRefs": {"installer": "key-a", "attestor": "key-b"},
            "policyBinding": {"path": str(self.root / "unopened-base.json"), "sha256": "c" * 64}}))
        anchor = json.loads(Path(self.anchor["path"]).read_bytes())
        anchor["authorityProfile"] = {"path": str(self.profile), "sha256": A.sha(self.profile.read_bytes())}
        self.write(self.anchor["path"], A.canonical(anchor))
        self.anchor["sha256"] = A.sha(Path(self.anchor["path"]).read_bytes())
        settings["anchorBinding"] = self.anchor
        accepted = json.loads(self.inputs["files"]["acceptance"])
        accepted.update(installationRef="inst", entityRef="ent", trustPolicy=self.anchor)
        self.inputs["files"]["acceptance"] = A.canonical(accepted) + b"\n"
        self.inputs["files"]["settings"] = A.canonical(settings)
        self.settings = settings
        self.mapping = self.root / "inputs.json"
        self.publish_inputs()

    def publish_inputs(self):
        bundle = {"schema": "ouf.semantic-provider-r3-inputs.v1", "files": {}, "sources": {}}
        blobs = self.root / "blobs"
        blobs.mkdir(mode=0o700, exist_ok=True)
        for kind, values in self.inputs.items():
            for i, (name, raw) in enumerate(sorted(values.items())):
                path = blobs / (kind + str(i))
                self.write(path, raw)
                bundle[kind][name] = {"path": str(path), "sha256": A.sha(raw)}
        self.write(self.mapping, A.canonical(bundle))

    def argv(self, mode="--plan", digest=None):
        argv = [mode, "--inputs", str(self.mapping), "--inputs-sha256", A.sha(self.mapping.read_bytes()),
            "--authority-profile", str(self.profile), "--authority-profile-sha256", A.sha(self.profile.read_bytes()),
            "--install-root", str(self.install), "--issued-at", str(self.now),
            "--output-directory", str(self.output), "--table-name", "adapter=ouf_r3_adapter", "southbound=ouf_r3_southbound"]
        for path in self.keys.values():
            argv.extend(["--private-key-path", str(path)])
        if digest is not None:
            argv.extend(["--plan-sha256", digest])
        return argv

    def execute(self, mode="--plan", digest=None, progress=None):
        return issue.execute(issue.arguments(self.argv(mode, digest)),
                             progress if progress is not None else issue.progress_initial(), self.clock)

    def test_plan_apply_head_and_no_installation_publication(self):
        # Observe the original installer key through the single dedicated reader.
        original = issue.AUTH.public_bytes
        reads = []
        def key_reader(path, limit=65536):
            if Path(path) == self.keys["key-a"]:
                reads.append(path)
            return original(path, limit)
        with patch.object(issue.AUTH, "public_bytes", side_effect=key_reader):
            first = self.execute()
            self.assertEqual(first, self.execute())
            self.assertFalse(self.chain.exists())
            self.assertFalse(self.output.exists())
            self.assertEqual(reads, [])
            result = self.execute("--apply", first["planSha256"])
        # Hash check of the original custody path before and after signing; never a copy.
        self.assertEqual(len(reads), 2)
        self.assertEqual((result["privateKeysRead"], result["signaturesIssued"]), (1, 1))
        self.assertEqual(self.head()["sha256"], first["payloadSha256"])
        self.assertEqual(self.head()["decision"], "OPERATE")
        self.assertEqual(set(os.listdir(self.output)), {"result.json"})
        self.assertEqual(set(os.listdir(self.install)), {"authorization"})
        self.assertEqual(set(os.listdir(self.chain)), {"1.json", "1.signature.json"})
        self.assertFalse((self.chain / "1.signature.json").read_bytes().endswith(b"\n"))
        self.assertEqual((self.chain.stat().st_mode & 0o777), 0o700)
        for p in (self.chain / "1.json", self.chain / "1.signature.json", self.output / "result.json"):
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(A.OperationDenied):
            self.execute("--apply", first["planSha256"])

    def test_cli_plan_apply_and_readback(self):
        def run(args):
            result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/issue-semantic-provider-operation-authorization.py"),
                *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout.decode())
            self.assertEqual(result.stderr, b"")
            return json.loads(result.stdout)
        plan = run(self.argv())
        result = run(self.argv("--apply", plan["planSha256"]))
        self.assertTrue(result["doNotRerunApply"])
        self.assertEqual(self.head()["sha256"], plan["payloadSha256"])

    def test_native_runtime_load_configuration_without_portability_adapter(self):
        args = issue.arguments(self.argv())
        _, result, *_ = issue.observe(args, self.clock)
        path = self.root / "runtime-configuration.json"
        self.write(path, result["documents"]["runtime-configuration.json"])
        runtime = fixtures.load(C.RUNTIME, "r3_native_runtime_contract")
        value, raw = runtime.load_configuration(path)
        self.assertEqual(raw, result["documents"]["runtime-configuration.json"])
        self.assertEqual(A.sha(raw), json.loads(result["authorization"])["runtimeConfigurationSha256"])

    def test_wrong_digest_and_changed_input_issue_no_signature(self):
        plan = self.execute()
        for digest in ("0" * 64, plan["planSha256"]):
            if digest != "0" * 64:
                self.inputs["sources"][C.OBSERVER] += b"\n"
                self.publish_inputs()
            progress = issue.progress_initial()
            with self.assertRaisesRegex(A.OperationDenied, "PLAN_DIGEST_MISMATCH"), \
                    patch.object(issue.AUTH, "public_bytes", side_effect=AssertionError("key read forbidden")):
                self.execute("--apply", digest, progress)
            self.assertEqual(progress["signaturesIssued"], 0)
            self.assertFalse(progress["doNotRerunApply"])
            self.assertFalse(self.output.exists())

    def test_inactive_mandate_now_or_at_issuance_never_signs(self):
        plan = self.execute()
        for field, at in (("now", self.now + 7200), ("issued", self.now - 7200)):
            progress = issue.progress_initial()
            args = issue.arguments(self.argv("--apply", plan["planSha256"]))
            if field == "now":
                clock = lambda: at
            else:
                args.issued_at = at
                clock = self.clock
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "ACTIVE_(INSTALLER_)?MANDATE_REQUIRED"), \
                    patch.object(issue.AUTH, "public_bytes", side_effect=AssertionError("key read forbidden")) as key_read:
                issue.execute(args, progress, clock)
            key_read.assert_not_called()
            self.assertEqual(progress["signaturesIssued"], 0)
            self.assertFalse(progress["doNotRerunApply"])

    def test_nonempty_or_wrong_mode_authorization_root_never_signs(self):
        plan = self.execute()
        self.chain.mkdir(mode=0o700)
        self.write(self.chain / "foreign", b"retained")
        progress = issue.progress_initial()
        with self.assertRaisesRegex(A.OperationDenied, "AUTHORIZATION_ROOT_NOT_EMPTY"), \
                patch.object(issue.AUTH, "public_bytes", side_effect=AssertionError("key read forbidden")):
            self.execute("--apply", plan["planSha256"], progress)
        self.assertEqual(progress["signaturesIssued"], 0)
        (self.chain / "foreign").unlink()
        self.chain.chmod(0o755)
        with self.assertRaisesRegex(A.OperationDenied, "PRIVATE_DIRECTORY_REQUIRED"):
            self.execute()

    def test_existing_empty_authorization_root_accepted(self):
        self.chain.mkdir(mode=0o700)
        plan = self.execute()
        self.execute("--apply", plan["planSha256"])
        self.assertEqual(self.head()["sequence"], 1)

    def test_absent_install_root_created_exclusively(self):
        self.install.rmdir()
        plan = self.execute()
        self.assertFalse(self.install.exists())
        self.execute("--apply", plan["planSha256"])
        self.assertEqual(self.head()["sequence"], 1)
        self.assertEqual(self.install.stat().st_mode & 0o777, 0o700)

    def test_b1b2_domain_signature_rejected_by_head(self):
        plan = self.execute()
        raw = A.canonical(plan["payload"])
        self.chain.mkdir(mode=0o700)
        signature = self.signature(raw, domain=self.m.DOMAIN)
        self.put(1, raw, signature)
        with self.assertRaisesRegex(self.a.OperationDenied, "OPERATION_SIGNATURE_INVALID"):
            self.head()

    def test_bad_domain_during_issuance_is_partial_and_never_published(self):
        plan = self.execute()
        progress = issue.progress_initial()
        # Fault the signer only. Verification retains the real separate domain.
        original_native = issue.native
        def fault(verifier, argv, limit):
            if argv[0] == "pkeyutl":
                path = Path(argv[argv.index("-in") + 1])
                frame = path.read_bytes()
                path.write_bytes(self.m.DOMAIN + frame[len(A.DOMAIN):])
            return original_native(verifier, argv, limit)
        with patch.object(issue, "native", side_effect=fault), \
                self.assertRaisesRegex(A.OperationDenied, "OPERATION_SIGNATURE_INVALID"):
            self.execute("--apply", plan["planSha256"], progress)
        self.assertTrue(progress["doNotRerunApply"])
        self.assertEqual(progress["signaturesIssued"], 1)
        self.assertEqual(os.listdir(self.chain), [])
        self.assertEqual(os.listdir(self.output), [])
        with self.assertRaises(A.OperationDenied):
            self.execute("--apply", plan["planSha256"])

    def test_reader_custody_links_and_no_key_as_input(self):
        path = self.root / "public.json"
        self.write(path, b"{}")
        reader = issue.Reader([str(p) for p in self.keys.values()])
        self.assertEqual(reader.read(str(path), A.sha(b"{}")), b"{}")
        path.chmod(0o666)
        with self.assertRaisesRegex(A.OperationDenied, "INPUT_FILE_CUSTODY_REQUIRED"):
            reader.read(str(path), A.sha(b"{}"))
        path.chmod(0o600)
        link = self.root / "symlink"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            reader.read(str(link), A.sha(b"{}"))
        hard = self.root / "hardlink"
        os.link(path, hard)
        with self.assertRaisesRegex(A.OperationDenied, "INPUT_FILE_CUSTODY_REQUIRED"):
            reader.read(str(hard), A.sha(b"{}"))
        with self.assertRaisesRegex(A.OperationDenied, "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN"), \
                patch.object(issue.os, "open", side_effect=AssertionError("must not open")):
            reader.read(str(self.keys["key-a"]), "1" * 64)


if __name__ == "__main__":
    unittest.main()
