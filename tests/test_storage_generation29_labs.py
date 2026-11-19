import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
import zipfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result

lab = module("labs29", ROOT / "scripts/run-seaweedfs-452-generation29-labs.py")
fixtures = module("binding_fixtures", ROOT / "tests/test_storage_generation29_lab_binding.py")


class RuntimeAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.BindingTests.setUpClass()

    def setUp(self):
        value = fixtures.BindingTests().fixture()
        raw = json.dumps(value).encode()
        self.binding = lab.binding_api.validate(raw, lab.binding_api.sha(raw), fixtures.BindingTests.manifest)
        self.binding["cohortReceiptSha256"] = lab.binding_api.sha(b"synthetic cohort receipt fixture")
        self.binding["cohortReceiptPath"] = "/synthetic-test-only/cohort-receipt.json"

    def probe(self):
        return {"octetStreamCompatibility": {"status": "PASS", "findings": [],
                "requestedContentType": "application/octet-stream", "getContentType": "application/octet-stream",
                "headContentType": "application/octet-stream"}}

    def cohort(self):
        lock = self.binding["lock"]
        return {"schema": "ouf.seaweedfs-generation29-cohort.v1", "generation": 29,
                "status": "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED", "candidateLockSha256": self.binding["lockSha256"],
                "binarySha256": lab.binding_api.BINARY_SHA, "ociManifestDigest": lock["image"]["manifestDigest"],
                "producerArtifactSha256": lock["producerArtifact"]["digest"][7:],
                "independentReadbackSha256": lock["independentReadback"]["digest"][7:],
                "legalTextRebindingSha256": lab.binding_api.sha(b"synthetic legal fixture"),
                "readbackReproduced": True, "publisherVerificationRecordBound": True,
                "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0}

    def bundle(self, root, mutate=None, checksum_prefix="./"):
        root = Path(root)
        lock_bytes = json.dumps(self.binding["lock"]).encode()
        lock = root / lab.binding_api.LOCK_PATH; lock.parent.mkdir(parents=True, exist_ok=True); lock.write_bytes(lock_bytes)
        members = {name: b"synthetic unit fixture" for name in lab.COHORT_MEMBERS - {"SHA256SUMS"}}
        members["cohort-receipt.json"] = json.dumps(self.cohort()).encode()
        members["licence-rebinding.json"] = b"synthetic legal fixture"
        members["seaweedfs-452-generation29-candidate-lock-20261103.json"] = lock_bytes
        if mutate: mutate(members)
        members["SHA256SUMS"] = ''.join(lab.binding_api.sha(raw) + '  ' + checksum_prefix + name + '\n'
                                           for name, raw in sorted(members.items())).encode()
        archive = root / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as out:
            for name, raw in members.items(): out.writestr(name, raw)
        return archive, lab.binding_api.sha(archive.read_bytes()), lab.binding_api.sha(members["cohort-receipt.json"])

    def test_predecessor_artifact_full_checksums_lock_copy_and_receipt_are_bound(self):
        with tempfile.TemporaryDirectory() as root:
            archive, archive_sha, receipt_sha = self.bundle(root)
            out = Path(root) / "new"
            receipt = lab.bind_cohort_artifact(archive, out, self.binding, archive_sha, receipt_sha, Path(root))
            self.assertEqual(receipt, out / "cohort-receipt.json")
            self.assertEqual(lab.binding_api.sha(receipt.read_bytes()), receipt_sha)
            self.assertEqual({str(p.relative_to(out)) for p in out.rglob('*') if p.is_file()}, lab.COHORT_MEMBERS)

    def test_root_relative_manifest_without_dot_prefix_also_passes(self):
        with tempfile.TemporaryDirectory() as root:
            archive, archive_sha, receipt_sha = self.bundle(root, checksum_prefix="")
            lab.bind_cohort_artifact(archive, Path(root) / "new", self.binding, archive_sha, receipt_sha, Path(root))

    def test_logical_duplicate_checksum_and_changed_member_fail_before_extraction(self):
        for corruption, code in (("duplicate", "UNIQUE_COHORT_CHECKSUM_REQUIRED"),
                                 ("changed", "COHORT_MEMBER_CHECKSUM_MISMATCH")):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as root:
                archive, _, receipt_sha = self.bundle(root)
                with zipfile.ZipFile(archive) as source:
                    members = {e.filename: source.read(e) for e in source.infolist()}
                if corruption == "duplicate":
                    first = members["SHA256SUMS"].decode().splitlines()[0]
                    members["SHA256SUMS"] += (first.replace("  ./", "  ", 1) + "\n").encode()
                else:
                    members["ordered-patches.txt"] = b"changed after manifest seal"
                with zipfile.ZipFile(archive, "w") as output:
                    for name, raw in members.items(): output.writestr(name, raw)
                out = Path(root) / "new"
                with self.assertRaisesRegex(ValueError, code):
                    lab.bind_cohort_artifact(archive, out, self.binding, lab.binding_api.sha(archive.read_bytes()), receipt_sha, Path(root))
                self.assertFalse(out.exists())

    def test_wrong_predecessor_archive_hash_produces_no_output(self):
        with tempfile.TemporaryDirectory() as root:
            archive, _, receipt_sha = self.bundle(root); out = Path(root) / "new"
            with self.assertRaisesRegex(ValueError, "EXACT_COHORT_ARCHIVE_SHA_REQUIRED"):
                lab.bind_cohort_artifact(archive, out, self.binding, "1" * 64, receipt_sha, Path(root))
            self.assertFalse(out.exists())

    def test_cohort_copied_lock_cannot_substitute_committed_lock(self):
        with tempfile.TemporaryDirectory() as root:
            archive, archive_sha, receipt_sha = self.bundle(root, lambda m:m.__setitem__(
                "seaweedfs-452-generation29-candidate-lock-20261103.json", b"{}"))
            out = Path(root) / "new"
            with self.assertRaisesRegex(ValueError, "COHORT_LOCK_COPY_MUST_MATCH_COMMITTED_LOCK"):
                lab.bind_cohort_artifact(archive, out, self.binding, archive_sha, receipt_sha, Path(root))
            self.assertFalse(out.exists())

    def test_bad_cohort_legal_hash_and_unexpected_path_fail_before_extraction(self):
        for mutate, code in ((lambda m:m.__setitem__("licence-rebinding.json", b"changed"), "COHORT_LEGAL_REBINDING_CHANGED"),
                             (lambda m:m.__setitem__("../escaped", b"bad"), "EXACT_COHORT_BUNDLE_MEMBERS_REQUIRED")):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as root:
                archive, archive_sha, receipt_sha = self.bundle(root, mutate); out = Path(root) / "new"
                with self.assertRaisesRegex(ValueError, code):
                    lab.bind_cohort_artifact(archive, out, self.binding, archive_sha, receipt_sha, Path(root))
                self.assertFalse(out.exists())

    def test_predecessor_receipt_must_match_expected_digest(self):
        with tempfile.TemporaryDirectory() as root:
            archive, archive_sha, _ = self.bundle(root); out = Path(root) / "new"
            with self.assertRaisesRegex(ValueError, "EXACT_VERIFIED_COHORT_RECEIPT_REQUIRED"):
                lab.bind_cohort_artifact(archive, out, self.binding, archive_sha, "1" * 64, Path(root))
            self.assertFalse(out.exists())

    def test_cohort_requires_exact_hash_generation_binding_and_proof(self):
        value = self.cohort(); raw = json.dumps(value).encode()
        lab.binding_api.validate_cohort_receipt(raw, lab.binding_api.sha(raw), self.binding)
        with self.assertRaises(ValueError): lab.binding_api.validate_cohort_receipt(raw, "0" * 64, self.binding)
        for key, changed in (("generation", 15), ("candidateLockSha256", "wrong"),
                             ("binarySha256", "wrong"), ("ociManifestDigest", "wrong"),
                             ("producerArtifactSha256", "wrong"), ("independentReadbackSha256", "wrong"),
                             ("readbackReproduced", False), ("publisherVerificationRecordBound", False),
                             ("status", "PENDING"), ("releaseAdmitted", True)):
            altered = dict(value, **{key: changed}); raw = json.dumps(altered).encode()
            with self.subTest(key=key), self.assertRaises(ValueError):
                lab.binding_api.validate_cohort_receipt(raw, lab.binding_api.sha(raw), self.binding)

    def test_missing_lock_does_not_import_harness(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(lab, "load_module") as loader:
            with self.assertRaisesRegex(ValueError, "GENERATION29_LOCK_NOT_AVAILABLE"):
                lab.preflight("0" * 64, "0" * 64, Path(root))
            loader.assert_not_called()

    def test_missing_cohort_denies_after_binding_before_harness_import(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(lab.binding_api, "load", return_value=self.binding), \
                mock.patch.object(lab, "load_module") as loader:
            with self.assertRaisesRegex(ValueError, "VERIFIED_COHORT_RECEIPT_NOT_AVAILABLE"):
                lab.preflight(self.binding["lockSha256"], self.binding["cohortReceiptSha256"], Path(root))
            loader.assert_not_called()

    def test_each_generation_module_is_fresh_and_legacy_file_unchanged(self):
        original = {p: (ROOT / p).read_bytes() for p in lab.binding_api.HARNESS_SOURCES}
        first = lab.configured_harness("cold", self.binding)
        second = lab.configured_harness("cold", self.binding)
        identity = lab.configured_harness("identity", self.binding)
        self.assertIsNot(first, second)
        self.assertIsNot(identity.cold, first)
        self.assertEqual(first.BINARY_SHA, lab.binding_api.BINARY_SHA)
        self.assertEqual(identity.cold.IMAGE_ID, self.binding["lock"]["image"]["configDigest"])
        legacy = module("untouched_legacy", ROOT / "scripts/run-seaweedfs-452-cold-recovery.py")
        self.assertEqual(legacy.BINARY_SHA, "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033")
        self.assertEqual(original, {p: (ROOT / p).read_bytes() for p in original})

    def test_subprocess_reenters_adapter_and_preserves_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            for mode, action, timeout in (("cold", "ready", 90), ("cold", "seed", 180),
                                          ("cold", "verify", 180), ("identity", "ready", 90),
                                          ("identity", "verify", 240)):
                harness = lab.configured_harness(mode, self.binding)
                cold = harness if mode == "cold" else harness.cold
                instance = harness.Lab("fixture", Path(tmp), Path(tmp)); instance.pid = "123"
                with mock.patch.object(cold, "command", return_value=json.dumps(self.probe())) as command:
                    instance.client(action)
                argv = command.call_args.args[0]
                self.assertIn(str(lab.ENTRYPOINT), argv)
                self.assertFalse(any(x.endswith("run-seaweedfs-452-cold-recovery.py") or
                                     x.endswith("run-seaweedfs-452-identity-tls.py") for x in argv))
                self.assertEqual(command.call_args.kwargs["timeout"], timeout)
                self.assertIn(self.binding["lockSha256"], argv)
                self.assertIn(self.binding["cohortReceiptSha256"], argv)
                self.assertEqual(command.call_count, 1)

    def test_cold_seed_and_verify_mime_failure_cannot_escape_child_boundary(self):
        harness = lab.configured_harness("cold", self.binding)
        bad = self.probe(); bad["octetStreamCompatibility"]["headContentType"] = "text/plain"
        with tempfile.TemporaryDirectory() as tmp:
            instance = harness.Lab("fixture", Path(tmp), Path(tmp)); instance.pid = "123"
            for action in ("seed", "verify"):
                with self.subTest(action=action), mock.patch.object(harness, "command", return_value=json.dumps(bad)) as command:
                    with self.assertRaisesRegex(ValueError, "GENERATION29_OCTET_STREAM_REGRESSION"):
                        instance.client(action)
                    self.assertEqual(command.call_count, 1)

    def test_image_profile_mismatch_fails_before_readback_or_docker(self):
        reader = types.SimpleNamespace(candidate=types.SimpleNamespace(
            PROFILE=types.SimpleNamespace(binary_sha="old"), MANIFEST={"generation": 15}), verify=mock.Mock())
        cold = types.SimpleNamespace(command=mock.Mock())
        with mock.patch.object(lab, "check_archive"), mock.patch.object(lab, "load_module", return_value=reader):
            with self.assertRaisesRegex(ValueError, "GENERATION29_IMAGE_PROFILE_REQUIRED"):
                lab.prepare_image(Path("unused"), Path("unused"), self.binding, cold)
        reader.verify.assert_not_called(); cold.command.assert_not_called()

    def test_wrong_archive_size_and_hash_fail_before_module_import(self):
        with tempfile.TemporaryDirectory() as root:
            archive = Path(root) / "fixture.zip"; archive.write_bytes(b"different bytes")
            with self.assertRaisesRegex(ValueError, "SIZE_REQUIRED"): lab.check_archive(archive, self.binding)
            self.binding["lock"]["producerArtifact"]["bytes"] = archive.stat().st_size
            with self.assertRaisesRegex(ValueError, "SHA_REQUIRED"): lab.check_archive(archive, self.binding)

    def test_non_ci_run_has_no_archive_or_harness_effect(self):
        with mock.patch.dict(lab.os.environ, {}, clear=True), mock.patch.object(lab, "check_archive") as archive, \
                mock.patch.object(lab, "configured_harness") as harness:
            with self.assertRaisesRegex(ValueError, "ISOLATED_CI_ONLY"):
                lab.run(Path("unused"), Path("unused"), self.binding)
            archive.assert_not_called(); harness.assert_not_called()

    def test_success_requires_new_generation_results_and_exact_identity_counts(self):
        common = {"candidateLockSha256": self.binding["lockSha256"],
                  "ociManifestDigest": self.binding["lock"]["image"]["manifestDigest"],
                  "binarySha256": lab.binding_api.BINARY_SHA, "releaseAdmitted": False,
                  "runtimeAuthorityIssued": False, "targetOperations": 0, "gatesClosed": 0,
                  "acceptanceTestsPassed": 0}
        cold = {**common, **self.probe(), "status": "SYNTHETIC_STORAGE_COLD_RESTORE_PASS_NOT_ACCEPTANCE",
                "originalContainersRemoved": True, "restoreUsesOnlyIndependentRoots": True}
        identity = {**common, "status": "SYNTHETIC_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE",
                    "s3CasesPassed": 23, "tlsNegativesPassed": 2, "egressProbesPassed": 2}
        lab.validate_results(cold, identity, self.binding)
        for key, wrong in (("binarySha256", "old"), ("candidateLockSha256", "old"),
                           ("s3CasesPassed", 22), ("tlsNegativesPassed", 1), ("egressProbesPassed", 1)):
            changed = dict(identity, **{key: wrong})
            with self.subTest(key=key), self.assertRaises(ValueError):
                lab.validate_results(cold, changed, self.binding)
        bad = copy.deepcopy(cold); bad["octetStreamCompatibility"]["status"] = "FAIL"
        with self.assertRaisesRegex(ValueError, "GENERATION29_OCTET_STREAM_REGRESSION"):
            lab.validate_results(bad, identity, self.binding)

    def test_success_runs_cold_then_identity_and_writes_separate_generation_receipt(self):
        events = []
        def harness(mode, binding):
            events.append("configure-" + mode)
            def execute(archive, work):
                events.append("run-" + mode)
                (work / "evidence").mkdir(parents=True)
                name = "recovery-result.json" if mode == "cold" else "identity-result.json"
                (work / "evidence" / name).write_text("{}")
            return types.SimpleNamespace(run=execute)
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(lab.os.environ, {"GITHUB_ACTIONS": "true"}), \
                mock.patch.object(lab, "check_archive"), mock.patch.object(lab, "configured_harness", side_effect=harness), \
                mock.patch.object(lab, "validate_results") as verify:
            work = Path(root) / "new"
            lab.run(Path("unused"), work, self.binding)
            self.assertEqual(events, ["configure-cold", "run-cold", "configure-identity", "run-identity"])
            verify.assert_called_once()
            result = json.loads((work / "runtime-result.json").read_bytes())
            self.assertEqual(result["generation"], 29)
            self.assertEqual(result["maximumConcurrentContainers"], 4)
            self.assertEqual(result["binarySha256"], lab.binding_api.BINARY_SHA)
            self.assertFalse(result["releaseAdmitted"])

    def test_cold_failure_prevents_identity_launch(self):
        cold = types.SimpleNamespace(run=mock.Mock(side_effect=RuntimeError("synthetic cold failure")))
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(lab.os.environ, {"GITHUB_ACTIONS": "true"}), \
                mock.patch.object(lab, "check_archive"), mock.patch.object(lab, "configured_harness", return_value=cold) as factory:
            with self.assertRaisesRegex(RuntimeError, "synthetic cold failure"):
                lab.run(Path("unused"), Path(root) / "new", self.binding)
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(factory.call_args.args[0], "cold")
            self.assertFalse((Path(root) / "new/runtime-result.json").exists())


if __name__ == "__main__": unittest.main()
