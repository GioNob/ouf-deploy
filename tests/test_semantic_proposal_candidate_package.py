import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).parents[1]/'scripts/package-semantic-proposal-candidate.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)

class PackageGateTests(unittest.TestCase):
    def report(self, severity=None):
        result = {'Class': 'lang-pkgs', 'Type': 'gobinary', 'Target': 'ouf-mcp'}
        if severity is not None:
            result['Vulnerabilities'] = [{'VulnerabilityID': 'CVE-FIXTURE', 'Severity': severity}]
        return {'SchemaVersion': 2, 'Results': [result]}

    def test_clean_report_is_allowed_without_claiming_target_authority(self):
        self.assertEqual(candidate.scan_gate(self.report(), 'mcp'), 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED')

    def test_all_disallowed_severities_including_unfixed_fail(self):
        for severity in ['HIGH', 'CRITICAL', 'UNKNOWN', 'UNRECOGNIZED']:
            with self.subTest(severity=severity), self.assertRaises(candidate.Denied):
                candidate.scan_gate(self.report(severity), 'mcp')

    def test_missing_empty_or_unknown_coverage_cannot_pass(self):
        for report in [{}, {'SchemaVersion': 2, 'Results': []}, {'SchemaVersion': 2, 'Results': [{}]}]:
            with self.subTest(report=report), self.assertRaises(candidate.Denied):
                candidate.scan_gate(report, 'mcp')

    def test_image_scan_is_bound_to_exact_candidate_identity(self):
        report = self.report()
        report['Metadata'] = {'ImageID': 'sha256:'+'a'*64}
        report['Results'] = [{'Class': 'os-pkgs', 'Type': 'debian'}, {'Class': 'lang-pkgs', 'Type': 'jar'}]
        with self.assertRaises(candidate.Denied):
            candidate.scan_gate(report, 'semantic', 'sha256:'+'b'*64)
        self.assertTrue(candidate.scan_gate(report, 'semantic', 'sha256:'+'a'*64))

if __name__ == '__main__':
    unittest.main()
