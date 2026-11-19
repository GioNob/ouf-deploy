import copy
import importlib.util
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('accepted_applicability', ROOT / 'tools/storage_security/accepted_applicability.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def inputs():
    # Original public metadata, no object bodies and no executable execution.
    with zipfile.ZipFile(ROOT / 'evidence/artifacts/storage-copy-readback-41507064288.zip') as z:
        candidate = json.loads(z.read('candidate.json'))
        graph = z.read('compiled-packages.json')
        scan = json.loads(z.read('trivy-binary.json'))
    decision = json.loads((ROOT / 'evidence/seaweedfs-g1-applicability-owner-decision-20261102.json').read_text())
    advisory = json.loads((ROOT / decision['advisory']['canonicalSnapshotPath']).read_text())
    vex = json.loads((ROOT / 'evidence/seaweedfs-g1-openvex-20261102.json').read_text())
    return [decision, advisory, candidate, graph, scan, vex]


class AcceptedApplicabilityTests(unittest.TestCase):
    def test_exact_owner_decision_classifies_one_finding_without_mutating_raw(self):
        values = inputs()
        before = copy.deepcopy(values)
        result = m.assess(*values)
        self.assertEqual(values, before)
        self.assertEqual(result['rawCounts']['UNKNOWN'], 1)
        self.assertEqual(result['unresolvedCounts']['UNKNOWN'], 0)
        self.assertEqual(result['vulnerabilitySubgate'], 'PASS_WITH_EXACT_DISPOSITION')
        self.assertEqual(result['rawGate'], 'HELD')
        self.assertEqual(result['overallSwG1'], 'OPEN')
        for key in ('runtimeAuthorityIssued', 'targetApplyAuthorized', 'releaseAcceptance', 'migrationReady'):
            self.assertIs(result[key], False)

    def test_other_high_critical_or_unknown_is_never_disposed(self):
        for severity in ('HIGH', 'CRITICAL', 'UNKNOWN'):
            with self.subTest(severity=severity):
                values = inputs()
                values[4]['Results'][-1]['Vulnerabilities'].append({'VulnerabilityID': 'NEW-UNREVIEWED', 'PkgName': 'other/module', 'Severity': severity})
                result = m.assess(*values)
                self.assertEqual(result['status'], 'HELD_OTHER_FINDINGS')
                self.assertEqual(result['unresolvedCounts'][severity], 1)
                self.assertEqual(len(result['classifiedFindings']), 1)

    def test_same_id_on_a_different_binary_stays_held(self):
        values = inputs()
        other = next(r for r in values[4]['Results'] if r['Target'] != 'weed')
        other.setdefault('Vulnerabilities', []).append({'VulnerabilityID': 'GO-2026-5932', 'PkgName': 'golang.org/x/crypto', 'Severity': 'UNKNOWN'})
        self.assertEqual(m.assess(*values)['unresolvedCounts']['UNKNOWN'], 1)

    def test_build_or_dependency_changes_invalidate(self):
        for field, value in [('binarySha256', 'a' * 64), ('declaredSource', 'b' * 40), ('buildToolchain', 'go1.27.4'), ('cgoEnabled', True), ('compiledPackagesSha256', 'c' * 64), ('dependencyPatchSha256', 'd' * 64)]:
            with self.subTest(field=field):
                values = inputs()
                values[2][field] = value
                with self.assertRaises(m.ApplicabilityError):
                    m.assess(*values)

    def test_graph_change_including_introduced_openpgp_invalidates(self):
        values = inputs()
        graph = json.loads(values[3])
        graph['packages'].append('golang.org/x/crypto/openpgp/packet')
        values[3] = m.canonical(graph)
        with self.assertRaisesRegex(m.ApplicabilityError, 'COMPILED_GRAPH_CHANGED'):
            m.assess(*values)

    def test_advisory_change_requires_new_assessment(self):
        values = inputs()
        values[1]['affected'][0]['ecosystem_specific']['imports'].append({'path': 'golang.org/x/crypto/new-package'})
        with self.assertRaisesRegex(m.ApplicabilityError, 'ADVISORY_CHANGED'):
            m.assess(*values)

    def test_unaccepted_or_broad_or_runtime_decision_rejected(self):
        for field, value in [('status', 'DRAFT'), ('decisionRef', ''), ('scope', 'ALL_VERSIONS'), ('targetApplyAuthorized', True), ('thsDecisionClaimed', True), ('rawGateChanged', True)]:
            with self.subTest(field=field):
                values = inputs()
                values[0][field] = value
                with self.assertRaises(m.ApplicabilityError):
                    m.assess(*values)

    def test_vex_cannot_expand_product_or_change_justification(self):
        for change in ('extra-product', 'wrong-hash', 'wrong-id', 'wrong-justification'):
            with self.subTest(change=change):
                values = inputs()
                s = values[5]['statements'][0]
                if change == 'extra-product':
                    s['products'].append({'@id': 'pkg:generic/seaweedfs@4.51'})
                elif change == 'wrong-hash':
                    s['products'][0]['hashes']['sha-256'] = 'e' * 64
                elif change == 'wrong-id':
                    s['vulnerability']['name'] = 'DIFFERENT-ADVISORY'
                else:
                    s['justification'] = 'component_not_present'
                with self.assertRaises(m.ApplicabilityError):
                    m.assess(*values)

    def test_empty_inventory_duplicate_target_unknown_severity_and_wrong_package_denied(self):
        for change in ('empty', 'duplicate', 'no-packages', 'bad-severity', 'wrong-package', 'changed-severity'):
            with self.subTest(change=change):
                values = inputs()
                scan = values[4]
                weed = next(r for r in scan['Results'] if r['Target'] == 'weed')
                if change == 'empty':
                    scan['Results'] = []
                elif change == 'duplicate':
                    scan['Results'].append(copy.deepcopy(weed))
                elif change == 'no-packages':
                    weed['Packages'] = []
                elif change == 'bad-severity':
                    weed['Vulnerabilities'][0]['Severity'] = 'UNRECOGNIZED'
                elif change == 'wrong-package':
                    weed['Vulnerabilities'][0]['PkgName'] = 'other/module'
                else:
                    weed['Vulnerabilities'][0]['Severity'] = 'HIGH'
                with self.assertRaises(m.ApplicabilityError):
                    m.assess(*values)


if __name__ == '__main__':
    unittest.main()
