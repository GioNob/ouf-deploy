import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "delivery_verifier", ROOT / "scripts/verify-seaweedfs-452-delivery-evidence.py"
)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class SeaweedFS452DeliveryEvidenceTest(unittest.TestCase):
    def paths(self):
        return (
            ROOT / "releases/seaweedfs-452-delivery-evidence-lock-20261103.json",
            ROOT / "evidence/seaweedfs-452-component-obligation-matrix-20261103.json",
            ROOT / "evidence/seaweedfs-452-component-obligation-matrix-20261103.csv",
            ROOT / "evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip",
            ROOT / "releases/seaweedfs-452-durable-custody-plan-20261103.json",
        )

    def test_complete_bundle_is_bound_and_review_open(self):
        result = VERIFIER.verify(*self.paths())
        self.assertEqual(result["status"],
                         "TECHNICAL_DELIVERY_DOSSIER_VERIFIED_REVIEW_OPEN")
        self.assertEqual(result["thirdPartyComponents"], 262)
        self.assertEqual(result["thirdPartyLegalTexts"], 353)
        self.assertEqual(result["mplSourceArchives"], 17)
        self.assertEqual(result["rawUnknownClassifications"], 3)
        self.assertEqual(result["unclassifiedViews"], 3)
        self.assertEqual(result["licenceReview"], "OPEN_HUMAN")
        self.assertFalse(result["redistributionAccepted"])
        self.assertFalse(result["releaseAdmitted"])
        self.assertFalse(result["runtimeAuthorityIssued"])
        self.assertEqual(result["targetOperations"], 0)

    def test_custody_plan_cannot_claim_execution(self):
        delivery, matrix, matrix_csv, bundle, custody = self.paths()
        value = json.loads(custody.read_bytes())
        value["copyExecuted"] = True
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "custody.json"
            changed.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CUSTODY_MUST_REMAIN_OPEN_REQUIRED"):
                VERIFIER.verify(delivery, matrix, matrix_csv, bundle, changed)

    def test_bundle_part_manifest_cannot_change(self):
        delivery, matrix, matrix_csv, bundle, custody = self.paths()
        value = json.loads(delivery.read_bytes())
        value["bundleParts"][0]["bytes"] += 1
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "delivery.json"
            changed.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "EXACT_BUNDLE_PARTS_REQUIRED"):
                VERIFIER.verify(changed, matrix, matrix_csv, bundle, custody)

    def test_matrix_cannot_accept_redistribution(self):
        delivery, matrix, matrix_csv, bundle, custody = self.paths()
        value = json.loads(matrix.read_bytes())
        value["redistributionAccepted"] = True
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "matrix.json"
            changed.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MATRIX_HASH_BINDING_REQUIRED"):
                VERIFIER.verify(delivery, changed, matrix_csv, bundle, custody)


if __name__ == "__main__":
    unittest.main()
