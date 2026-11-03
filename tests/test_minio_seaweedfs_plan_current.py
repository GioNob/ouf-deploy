import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "plan_current", ROOT / "scripts/verify-minio-seaweedfs-plan-current.py"
)
plan_current = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan_current)


class CurrentStoragePlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = json.loads((ROOT / plan_current.PLAN_PATH).read_bytes())
        cls.lock_bytes = (ROOT / plan_current.LOCK_PATH).read_bytes()
        cls.lock = json.loads(cls.lock_bytes)
        cls.cohort = json.loads((ROOT / plan_current.COHORT_PATH).read_bytes())
        cls.dossiers = {
            path: json.loads((ROOT / path).read_bytes())
            for path in plan_current.EXPECTED_DOSSIERS
        }

    def validate(self, *, plan=None, lock=None, lock_bytes=None, cohort=None, dossiers=None):
        return plan_current.validate_documents(
            copy.deepcopy(self.plan if plan is None else plan),
            copy.deepcopy(self.lock if lock is None else lock),
            self.lock_bytes if lock_bytes is None else lock_bytes,
            copy.deepcopy(self.cohort if cohort is None else cohort),
            copy.deepcopy(self.dossiers if dossiers is None else dossiers),
        )

    def test_repository_current_plan_passes(self):
        result = plan_current.validate_tree(ROOT)
        self.assertEqual(result["status"], "PASS_NOT_ADMITTED")
        self.assertEqual(result["remainingRepositoryDirectSdkV1Importers"], 20)
        self.assertFalse(result["releaseAdmitted"])
        self.assertEqual(result["activeStorageBackend"], "MinIO")

    def test_historical_451_and_current_452_are_separate(self):
        self.assertEqual(self.plan["candidate"]["initialVersionToEvaluate"], "4.51")
        self.assertEqual(self.plan["currentQualification"]["version"], "4.52")
        self.assertFalse(self.plan["currentQualification"]["historicalApplicabilityApplied"])
        self.assertEqual(self.plan["historicalEvidenceFields"], plan_current.HISTORICAL_FIELDS)

    def test_historical_evidence_blocks_are_byte_value_stable(self):
        changed = copy.deepcopy(self.plan)
        changed["dependencyLifecycleReview"]["status"] = "CLOSED"
        with self.assertRaisesRegex(ValueError, "HISTORICAL_EVIDENCE_CHANGED"):
            self.validate(plan=changed)

    def test_candidate_lock_is_immutable_and_hash_bound(self):
        self.validate()
        with self.assertRaisesRegex(ValueError, "CANDIDATE_LOCK_BYTES_CHANGED"):
            self.validate(lock_bytes=self.lock_bytes + b"\n")

    def test_admission_authority_and_target_operations_fail_closed(self):
        for key, value, code in (
            ("releaseAdmitted", True, "CURRENT_NOT_ADMITTED_REQUIRED"),
            ("runtimeAuthorityIssued", True, "CURRENT_NO_RUNTIME_AUTHORITY_REQUIRED"),
            ("targetOperations", 1, "CURRENT_ZERO_TARGET_OPERATIONS_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(plan=changed)

    def test_gate_acceptance_and_object_counts_fail_closed(self):
        for key, value, code in (
            ("gatePass", 1, "ZERO_OF_EIGHT_GATES_REQUIRED"),
            ("acceptanceTestPass", 1, "ZERO_OF_TWENTY_ONE_AT_REQUIRED"),
            ("realObjectsCopied", 1, "ZERO_OF_ONE_HUNDRED_TWENTY_OBJECTS_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["progressEstimate"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(plan=changed)

    def test_progress_is_recomputed_from_original_weights(self):
        self.assertAlmostEqual(
            self.plan["progressEstimate"]["exactWeightedEstimatePercent"],
            15.9 / 46 * 100,
        )
        changed = copy.deepcopy(self.plan)
        changed["progressEstimate"]["weightedCredits"] = 16
        with self.assertRaisesRegex(ValueError, "WEIGHTED_CREDITS_REQUIRED"):
            self.validate(plan=changed)

    def test_hosted_test_dossier_sequence_is_exact(self):
        changed = copy.deepcopy(self.dossiers)
        changed[plan_current.EXPECTED_DOSSIERS[-1]]["directAwsSdkV1ImportersAfter"] = 22
        with self.assertRaisesRegex(ValueError, "DOSSIER_IMPORTER_SEQUENCE_REQUIRED"):
            self.validate(dossiers=changed)
        changed = copy.deepcopy(self.dossiers)
        changed[plan_current.EXPECTED_DOSSIERS[-1]]["workflow"]["status"] = "LOCAL_PASS"
        with self.assertRaisesRegex(ValueError, "HOSTED_PASS_REQUIRED"):
            self.validate(dossiers=changed)

    def test_minio_and_consumed_scope_remain_frozen(self):
        changed = copy.deepcopy(self.plan)
        changed["currentQualification"]["activeStorageBackend"] = "SeaweedFS"
        with self.assertRaisesRegex(ValueError, "MINIO_MUST_REMAIN_ACTIVE"):
            self.validate(plan=changed)
        changed = copy.deepcopy(self.plan)
        changed["invariants"]["cumulativeEngineGets"] = 53
        with self.assertRaisesRegex(ValueError, "ENGINE52_REQUIRED"):
            self.validate(plan=changed)


if __name__ == "__main__":
    unittest.main()
