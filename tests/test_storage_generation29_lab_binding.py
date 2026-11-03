"""Synthetic in-memory lock fixtures only; no producer fact or runtime lock created."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("binding29", ROOT / "scripts/storage-generation29-lab-binding.py")
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = (ROOT / binding.BUILD_MANIFEST_PATH).read_bytes()
        cls.tree = json.loads(cls.manifest)["build"]["patchedSourceTree"]

    def fixture(self):
        # Deliberately synthetic artifact bytes/IDs; hashes are derived from
        # fixture bytes. This object never leaves the unit test process.
        digest = "sha256:" + hashlib.sha256(b"explicit synthetic unit fixture").hexdigest()
        return {"schema": "ouf.storage-candidate-lock.v2", "generation": 29, "orderedPatchCount": 29,
                "buildManifest": {"path": binding.BUILD_MANIFEST_PATH, "sha256": binding.BUILD_MANIFEST_SHA,
                                  "patchedSourceTree": self.tree},
                "buildProfile": {"binarySha256": binding.BINARY_SHA}, "producerCommit": "1" * 40,
                "qualification": {"runId": 1, "allJobsPassed": True, "vulnerabilitySubgate": "PASS_RAW",
                                  "workflow": ".github/workflows/storage-452-generation29-image.yml",
                                  "rawSeverityCounts": dict.fromkeys(("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"), 0)},
                "producerArtifact": {"id": 1, "bytes": 32, "digest": digest},
                "independentReadback": {"id": 2, "bytes": 32, "digest": digest},
                "image": {**dict.fromkeys(("manifestDigest", "configDigest", "layerDigest"), digest),
                          **dict.fromkeys(("dockerArchiveSha256", "upstreamLicenceSha256"), digest[7:])},
                "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0}

    def validate(self, lock):
        value = json.dumps(lock).encode()
        return binding.validate(value, binding.sha(value), self.manifest)

    def test_complete_synthetic_binding_parses_without_side_effect(self):
        result = self.validate(self.fixture())
        self.assertEqual(result["generation"], 29)
        self.assertEqual(result["binarySha256"], binding.BINARY_SHA)

    def test_old_generation_and_old_binary_are_rejected(self):
        for path, value in (("generation", 15), ("orderedPatchCount", 15), ("schema", "ouf.storage-candidate-lock.v1")):
            lock = self.fixture(); lock[path] = value
            with self.subTest(path=path), self.assertRaises(ValueError): self.validate(lock)
        lock = self.fixture()
        lock["buildProfile"]["binarySha256"] = "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033"
        with self.assertRaisesRegex(ValueError, "EXACT_GENERATION29_BINARY_REQUIRED"): self.validate(lock)

    def test_unknown_artifact_facts_never_pass(self):
        for section in ("producerArtifact", "independentReadback"):
            for key, value in (("id", None), ("id", 0), ("id", True), ("bytes", 0), ("digest", None), ("digest", "sha256:" + "0" * 64)):
                lock = self.fixture(); lock[section][key] = value
                with self.subTest(section=section, key=key, value=value), self.assertRaises(ValueError): self.validate(lock)

    def test_lock_manifest_and_source_tree_substitution_fail(self):
        value = json.dumps(self.fixture()).encode()
        with self.assertRaises(ValueError): binding.validate(value, "0" * 64, self.manifest)
        with self.assertRaises(ValueError): binding.validate(value, binding.sha(value), self.manifest + b" ")
        lock = self.fixture(); lock["buildManifest"]["patchedSourceTree"] = "wrong"
        with self.assertRaises(ValueError): self.validate(lock)

    def test_failed_producer_or_raw_findings_fail(self):
        lock = self.fixture(); lock["qualification"]["allJobsPassed"] = False
        with self.assertRaises(ValueError): self.validate(lock)
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            lock = self.fixture(); lock["qualification"]["rawSeverityCounts"][severity] = 1
            with self.subTest(severity=severity), self.assertRaises(ValueError): self.validate(lock)

    def test_authority_escalation_fails(self):
        for field in ("releaseAdmitted", "runtimeAuthorityIssued", "targetOperations"):
            lock = self.fixture(); lock[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError): self.validate(lock)

    def test_missing_runtime_lock_fails_before_harness_loading(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "GENERATION29_LOCK_NOT_AVAILABLE"):
                binding.load(root, "0" * 64)

    def test_harness_hash_drift_fails_before_import(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); value = json.dumps(self.fixture()).encode()
            lock = root / binding.LOCK_PATH; lock.parent.mkdir(parents=True)
            lock.write_bytes(value); (root / binding.BUILD_MANIFEST_PATH).write_bytes(self.manifest)
            for path in binding.HARNESS_SOURCES:
                target = root / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text("modified fixture")
            with self.assertRaisesRegex(ValueError, "PINNED_LAB_HARNESS_CHANGED"):
                binding.load(root, binding.sha(value))

    def test_octet_probe_requires_get_and_head_pass_without_findings(self):
        value = {"octetStreamCompatibility": {"status": "PASS", "findings": [],
                 "requestedContentType": "application/octet-stream", "getContentType": "application/octet-stream",
                 "headContentType": "application/octet-stream"}}
        self.assertEqual(binding.require_octet_stream_pass(value), value)
        for field, wrong in (("status", "FAIL"), ("findings", [{}]), ("getContentType", "text/plain"),
                             ("headContentType", "text/plain"), ("requestedContentType", "application/x-fixture")):
            bad = copy.deepcopy(value); bad["octetStreamCompatibility"][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError): binding.require_octet_stream_pass(bad)
        with self.assertRaises(ValueError): binding.require_octet_stream_pass({})


if __name__ == "__main__": unittest.main()
