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
        self.assertEqual(report['roles']['semantic']['freshScanAdmission'], 'HELD_HIGH_CRITICAL_UNKNOWN')
        self.assertEqual(report['roles']['semantic']['vulnerabilityCounts']['HIGH'], 3)
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

    def test_held_actual_scan_cannot_be_promoted_to_pass(self):
        original = Path.read_bytes
        def read(path):
            raw = original(path)
            if path.name == 'm2-retained-semantic-scan-readback-20261101.json':
                document = json.loads(raw)
                document['result']['freshScanGatePassed'] = True
                return json.dumps(document).encode()
            return raw
        with patch.object(Path, 'read_bytes', read), self.assertRaisesRegex(ValueError, 'MUST_REMAIN_HELD'):
            m.reconcile(ROOT)

    def test_scan_path_substitution_and_compressed_report_drift_are_rejected(self):
        original = Path.read_bytes
        for kind in ('path', 'hash'):
            def read(path):
                raw = original(path)
                if path.name == 'm2-retained-semantic-scan-readback-20261101.json':
                    document = json.loads(raw)
                    document['preservedFullReport' if kind == 'path' else 'compressedReportSha256'] = '/unapproved' if kind == 'path' else '0'*64
                    return json.dumps(document).encode()
                return raw
            with self.subTest(kind=kind), patch.object(Path, 'read_bytes', read), self.assertRaises(ValueError):
                m.reconcile(ROOT)

    def test_remediation_binds_a_different_exact_image_and_preserves_the_target_hold(self):
        report = m.reconcile(ROOT)
        retained = report['roles']['semantic']
        replacement = retained['remediationCandidate']
        self.assertEqual(replacement['configurationImageId'],
                         'sha256:a6f00cda30f1c570082c94cb49d5564f40d512758441f6b6eac75e21f423d14f')
        self.assertEqual(len(replacement['remediatedFindings']), 3)
        self.assertEqual(replacement['vulnerabilityCounts'], {'MEDIUM':53, 'LOW':4})
        self.assertTrue(replacement['publisherChainVerifiedInNamedHostedJob'])
        self.assertFalse(replacement['publisherChainReverifiedByThisReader'])
        self.assertTrue(replacement['scanFreshnessMustBeRecheckedBeforeAdmission'])
        self.assertFalse(replacement['targetImageReplaced'])
        self.assertFalse(replacement['candidateSelectionChanged'])
        self.assertEqual(retained['freshScanAdmission'], 'HELD_HIGH_CRITICAL_UNKNOWN')
        self.assertEqual(retained['vulnerabilityCounts']['HIGH'], 3)

    def test_either_remediation_zip_changed_blocks_the_composed_report(self):
        original = Path.read_bytes
        for changed in (m.REMEDIATION_ZIP, m.REMEDIATION_PUBLISHER_ZIP):
            def read(path):
                raw = original(path)
                return raw+b'changed' if path == ROOT/changed else raw
            with self.subTest(changed=changed), patch.object(Path, 'read_bytes', read), self.assertRaisesRegex(ValueError, 'PUBLISHER_ZIPS'):
                m.reconcile(ROOT)

    def test_exact_minio_copy_never_becomes_original_publisher_or_security_admission(self):
        proof = m.reconcile(ROOT)['roles']['minio']['exactCopySecurityEvidence']
        self.assertEqual(proof['vulnerabilityCounts'], {'CRITICAL':9,'HIGH':127,'UNKNOWN':8,'MEDIUM':171,'LOW':27})
        self.assertEqual(len(proof['layers']),9)
        self.assertFalse(proof['originalVendorPublisherAuthenticated'])
        self.assertFalse(proof['freshSecurityGatePassed'])
        self.assertFalse(proof['runtimeReferenceChanged'])
        self.assertFalse(proof['deploymentReachabilityOfFindingsProven'])
        self.assertEqual(proof['securityAdmission'],'HELD_HIGH_CRITICAL_UNKNOWN')
        self.assertTrue(proof['ownerStorageDirectionRequired'])

    def test_changed_minio_evidence_is_denied_before_any_report_promotion(self):
        original = Path.read_bytes
        def read(path):
            raw = original(path)
            return raw+b'changed' if path == ROOT/m.MINIO_SECURITY_ZIP else raw
        with patch.object(Path,'read_bytes',read), self.assertRaisesRegex(ValueError,'MINIO_SECURITY_EVIDENCE'):
            m.reconcile(ROOT)

    def test_gateway_security_replacement_is_a_different_image_and_source_with_230_exact_blobs(self):
        role = m.reconcile(ROOT)['roles']['gateway-owner']
        new = role['replacementCandidate']
        self.assertNotEqual(new['nativeImageId'],role['nativeImageId'])
        self.assertEqual(new['sourceCommit'],'17439fed7a45d455baa6945ee72a65fa19c14029')
        self.assertEqual(new['declaredRetainedSourceCommit'],'81fdf7a5f9f3ef02ed930a1db911d34cab1a9415')
        self.assertEqual(new['sourceFilesIndependentlyMatched'],230)
        self.assertEqual(new['vulnerabilityCounts'],{'MEDIUM':53,'LOW':4})
        self.assertFalse(new['retainedImageSourceMembershipProven'])
        self.assertFalse(new['targetApplyAuthorized'])
        self.assertFalse(new['imageApplicationReadinessProven'])

    def test_changed_gateway_metadata_or_independent_source_tree_blocks_the_profile(self):
        original=Path.read_bytes
        for changed in (m.GATEWAY_METADATA_ZIP,'releases/m2-gateway-owner-security-source-tree-20261101.json'):
            def read(path):
                raw=original(path)
                return raw+b'changed' if path==ROOT/changed else raw
            with self.subTest(changed=changed),patch.object(Path,'read_bytes',read),self.assertRaises(ValueError):
                m.reconcile(ROOT)


if __name__ == '__main__':
    unittest.main()
