"""Actual offline Sigstore/parent plus every disposable module payload.

Runtime Engine, private mounts and remaining admission leaves are modeled.
This is not a target package admission or full current cohort acceptance.
"""
import sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import qualify_m2_discovery_artifact_membership_native as fixture
from tools.m2_discovery_installation_profile.package_membership import CurrentPackageMembership


class NativePackageMembership(unittest.TestCase):
    def prepared(self, **kwargs):
        case = fixture.NativeMembership(); self.addCleanup(case.doCleanups)
        return CurrentPackageMembership(case.prepared(**kwargs))

    def test_actual_parent_sigstore_and_all_six_payloads_five_images_join_offline(self):
        reader = self.prepared(); proof = reader.observe()
        self.assertTrue(proof['sixModulePackageBytesProven']); self.assertTrue(proof['fiveReviewedModuleImageIdentitiesProven'])
        self.assertEqual((proof['moduleCount'], proof['originalImageCount']), (6, 5))
        self.assertFalse(proof['fullCohortProven']); self.assertFalse(proof['targetApplyAuthorized'])

    def test_valid_signature_does_not_admit_altered_gateway_payload(self):
        reader = self.prepared(); reader.membership.publisher.observe()
        row = reader.guard(); root = Path(row['subject']['path']).parent
        path = root/'gateway/routes.file-loop.json'; original = path.read_bytes()
        self.addCleanup(path.write_bytes, original); path.write_bytes(b'{"altered":true}')
        with self.assertRaisesRegex(ValueError, 'COMPLETE_PACKAGE_MEMBER_BYTES'): reader.observe()

    def test_wrong_publisher_identity_denies_before_complete_package_proof(self):
        reader = self.prepared(wrong_id=True)
        with self.assertRaisesRegex(ValueError, 'CERTIFICATE_IDENTITY'): reader.observe()


if __name__ == '__main__': unittest.main()
