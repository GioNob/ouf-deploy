import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "cohort", ROOT / "scripts/verify-seaweedfs-452-cohort.py"
)
cohort = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cohort)


class CohortVerifierTest(unittest.TestCase):
    def archive(self, members):
        path = Path(self.directory.name) / (str(len(list(Path(self.directory.name).iterdir()))) + ".zip")
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in members.items():
                archive.writestr(name, value)
        return path

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_checked_zip_requires_exact_digest_and_members(self):
        path = self.archive({"required.json": b"{}\n"})
        found = cohort.checked_zip(path, cohort.sha256(path), ["required.json"], exact_count=1)
        self.assertEqual(found["required.json"], b"{}\n")
        with self.assertRaisesRegex(ValueError, "EXACT_ARCHIVE_REQUIRED"):
            cohort.checked_zip(path, "0" * 64, ["required.json"])
        with self.assertRaisesRegex(ValueError, "REQUIRED_ARCHIVE_MEMBERS_MISSING"):
            cohort.checked_zip(path, cohort.sha256(path), ["absent.json"])

    def test_checked_zip_denies_traversal_and_duplicates(self):
        traversal = self.archive({"../escape": b"x"})
        with self.assertRaisesRegex(ValueError, "SAFE_ARCHIVE_PATH_REQUIRED"):
            cohort.checked_zip(traversal, cohort.sha256(traversal), [])
        duplicate = Path(self.directory.name) / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("same", b"one")
                archive.writestr("same", b"two")
        with self.assertRaisesRegex(ValueError, "UNIQUE_BOUNDED_MEMBERS_REQUIRED"):
            cohort.checked_zip(duplicate, cohort.sha256(duplicate), [])

    def test_canonical_receipt_is_stable(self):
        value = {"status": "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED", "releaseAdmitted": False}
        self.assertEqual(cohort.canonical(value), cohort.canonical(json.loads(cohort.canonical(value))))

    def test_candidate_lock_must_not_claim_admission_or_authority(self):
        lock = json.loads((ROOT / "releases/seaweedfs-452-candidate-lock-20261103.json").read_bytes())
        cohort.validate_lock(lock)
        for key in ("releaseAdmitted", "runtimeAuthorityIssued"):
            changed = copy.deepcopy(lock)
            changed[key] = True
            with self.assertRaisesRegex(ValueError, "NO_RELEASE_OR_RUNTIME_AUTHORITY_REQUIRED"):
                cohort.validate_lock(changed)

    def test_candidate_lock_requires_zero_raw_findings_and_zero_target_operations(self):
        lock = json.loads((ROOT / "releases/seaweedfs-452-candidate-lock-20261103.json").read_bytes())
        changed = copy.deepcopy(lock)
        changed["qualification"]["rawSeverityCounts"]["UNKNOWN"] = 1
        with self.assertRaisesRegex(ValueError, "ZERO_RAW_VULNERABILITY_FINDINGS_REQUIRED"):
            cohort.validate_lock(changed)
        changed = copy.deepcopy(lock)
        changed["targetOperations"] = 1
        with self.assertRaisesRegex(ValueError, "ZERO_TARGET_OPERATIONS_REQUIRED"):
            cohort.validate_lock(changed)

    def test_licence_unknown_context_is_exact_and_not_an_acceptance(self):
        expected = cohort.EXPECTED_LICENCE_UNKNOWNS
        self.assertEqual(len(expected), 3)
        self.assertEqual({key[4] for key in expected},
                         {"Copyright", "GNU-All-permissive-Copying-License"})
        self.assertTrue(all("Apache-2.0" in detections for detections in expected.values()))


if __name__ == "__main__":
    unittest.main()
