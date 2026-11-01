"""Original archive/source integrity and scope-limited provenance reconciliation."""
import importlib.util
import json
from pathlib import Path
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('origin_evidence', ROOT/'scripts/reconcile-m2-retained-origin-evidence-20261101.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OriginalEvidence(unittest.TestCase):
    def retained(self):
        with zipfile.ZipFile(ROOT/m.ZIP) as archive:
            result = json.loads(archive.read('semantic-origin-match.json'))
        receipt = json.loads((ROOT/'evidence/m2-runtime-origin-join-target-20261101.json').read_text())['receipt']
        return result, next(v for v in receipt['unresolvedOriginBindings'] if v['role'] == 'semantic')

    def test_actual_preserved_original_matches_198_independent_git_blobs_and_keeps_two_gaps(self):
        before = (ROOT/m.ZIP).read_bytes()
        report = m.reconcile(ROOT)
        self.assertEqual(before, (ROOT/m.ZIP).read_bytes())
        self.assertEqual(report, json.loads((ROOT/m.OUTPUT).read_text()))
        self.assertEqual(report['remainingOriginGaps'], ['gateway-owner', 'minio'])
        proof = report['roles']['semantic']['sourceEvidence']
        self.assertEqual(proof['originalSourceFilesIndependentlyMatched'], 198)
        self.assertEqual(proof['signedPayloadMembersIndependentlyMatched'], 7)
        self.assertFalse(proof['publisherChainReverifiedByThisReader'])
        for key in ('allRuntimeArtifactMembershipProven', 'completePrivateCustodyProven',
                    'currentApplicationConfigurationOrLivenessProven', 'runtimeAuthorityIssued',
                    'targetApplyAuthorized', 'releaseAcceptance', 'candidateSelectionChanged'):
            self.assertIs(report[key], False)
        self.assertEqual((report['cumulativeTargetControlsUnchanged'], report['cumulativeTargetEngineGetsUnchanged']), (12, 35))

    def test_source_config_native_and_consumed_receipt_are_distinct_required_bindings(self):
        for key in ('moduleSourceCommit', 'configurationDigest', 'publicTargetReceiptHash'):
            result, binding = self.retained()
            result[key] = '0'*64
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate_semantic(result, binding)
        result, binding = self.retained()
        result['qualifiedSchema2Envelope']['nativeImageId'] = 'sha256:'+'0'*64
        with self.assertRaisesRegex(ValueError, 'NATIVE_ENVELOPE'):
            m.validate_semantic(result, binding)

    def test_unsigned_or_partial_image_proof_cannot_become_source_membership(self):
        for key in ('originalSignatureVerified', 'originalConfigurationAndAllLayerAndExpandedDiffIdBytesVerified',
                    'configurationAndRootfsContentIdentityMatchesRetained'):
            result, binding = self.retained()
            result[key] = False
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'COHORT_PROOF'):
                m.validate_semantic(result, binding)

    def test_publisher_proof_cannot_smuggle_selection_runtime_or_security_admission(self):
        for key in ('runtimeAuthorityIssued', 'targetApplyAuthorized', 'releaseAcceptance',
                    'freshVulnerabilityAdmissionProven', 'candidateSelectionChanged'):
            result, binding = self.retained()
            result[key] = True
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'CONFER_RUNTIME'):
                m.validate_semantic(result, binding)

    def test_changed_zip_or_independent_tree_never_produces_report(self):
        result, binding = self.retained()
        original = Path.read_bytes
        for changed in (m.ZIP, m.TREE):
            def read(path):
                raw = original(path)
                return raw+b'changed' if path == ROOT/changed else raw
            with self.subTest(changed=changed), patch.object(Path, 'read_bytes', read), self.assertRaises(ValueError):
                m.original_semantic(ROOT, binding)

    def test_five_consumed_source_maps_are_byte_exact(self):
        directory = ROOT/'tools/m2_discovery_installation_profile'
        for name, count in (('current_review_sources.json', 235), ('retained_image_graph_sources.json', 19),
                            ('retained_image_verification_sources.json', 17), ('retained_selected_image_sources.json', 21),
                            ('retained_runtime_origin_sources.json', 23)):
            rows = json.loads((directory/name).read_text())
            self.assertEqual(len(rows), count)
            for row in rows.values():
                self.assertEqual(m.sha((ROOT/row['path']).read_bytes()), row['sha256'], row['path'])


if __name__ == '__main__':
    unittest.main()
