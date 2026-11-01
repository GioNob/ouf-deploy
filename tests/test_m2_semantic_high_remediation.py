"""Deny false remediation from a wrong image, old package or incomplete scan."""
import copy
from datetime import datetime, timezone
import gzip
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('remediation', ROOT/'scripts/check-m2-semantic-high-remediation-20261101.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Remediation(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads(gzip.decompress((ROOT/m.REPORT).read_bytes()))
        self.origin = json.loads((ROOT/m.ORIGINS).read_bytes())['roles']['semantic']
        self.now = datetime(2026, 11, 1, 22, tzinfo=timezone.utc)
        self.report = copy.deepcopy(self.baseline)
        self.report['CreatedAt'] = self.now.isoformat()
        self.report['Metadata']['ImageID'] = m.CONFIG
        for row in self.report['Results']:
            row['Vulnerabilities'] = []
            for p in row.get('Packages', []):
                if p['Name'] in m.FIXES:
                    p['Version'], p['Release'] = m.FIXES[p['Name']][1].rsplit('-', 1)

    def run_gate(self, report=None, origin=None):
        return m.qualify(report or self.report, self.baseline, origin or self.origin, self.now)

    def test_three_fixed_versions_pass_without_clearing_retained_hold_or_target_authority(self):
        result = self.run_gate()
        self.assertEqual(len(result['remediatedFindings']), 3)
        self.assertEqual(result['retainedImageSecurityAdmission'], 'HELD_HIGH_CRITICAL_UNKNOWN')
        for key in ('imageRebuilt', 'candidateSelectionChanged', 'targetImageReplaced',
                    'targetApplyAuthorized', 'runtimeAuthorityIssued', 'releaseAcceptance', 'm2Acceptance'):
            self.assertIs(result[key], False)

    def test_original_image_wrong_source_and_selected_candidate_are_denied(self):
        report = copy.deepcopy(self.report)
        report['Metadata']['ImageID'] = self.baseline['Metadata']['ImageID']
        with self.assertRaisesRegex(Exception, 'IMAGE_BINDING'): self.run_gate(report)
        for key, value in [('sourceCommit', '0'*40), ('currentRoleFromOperatorPublicReceipt', True),
                           ('qualifiedReplacementCandidateNotYetSelected', False)]:
            origin = dict(self.origin, **{key:value})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'DISTINCT_UNSELECTED'):
                self.run_gate(origin=origin)

    def test_missing_duplicate_or_old_package_is_denied_even_with_empty_findings(self):
        for kind in ('missing', 'duplicate', 'old', 'malformed'):
            report = copy.deepcopy(self.report)
            packages = report['Results'][0]['Packages']
            target = next(p for p in packages if p['Name'] == 'curl')
            if kind == 'missing': packages.remove(target)
            elif kind == 'duplicate': packages.append(copy.deepcopy(target))
            elif kind == 'old': target['Release'] = '1ubuntu2.7'
            else: target['Release'] = '--invalid'
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.run_gate(report)

    def test_debian_revision_ordering_rejects_prerelease_and_accepts_later_revision(self):
        for release, allowed in [('1ubuntu2.8~rc1', False), ('1ubuntu2.10', True)]:
            report = copy.deepcopy(self.report)
            next(p for p in report['Results'][0]['Packages'] if p['Name'] == 'curl')['Release'] = release
            if allowed: self.run_gate(report)
            else:
                with self.assertRaisesRegex(ValueError, 'FIXED_PACKAGE'): self.run_gate(report)

    def test_target_cve_remains_denied_if_downgraded_to_low(self):
        report = copy.deepcopy(self.report)
        report['Results'][0]['Vulnerabilities'] = [{'Severity':'LOW', 'VulnerabilityID':'CVE-2026-92392'}]
        with self.assertRaisesRegex(ValueError, 'ANY_SEVERITY'): self.run_gate(report)

    def test_unrelated_blockers_and_missing_java_coverage_are_denied(self):
        for severity in ('HIGH', 'CRITICAL', 'UNKNOWN'):
            report = copy.deepcopy(self.report)
            report['Results'][1]['Vulnerabilities'] = [{'Severity':severity, 'VulnerabilityID':'OTHER'}]
            with self.subTest(severity=severity), self.assertRaisesRegex(Exception, 'VULNERABILITY_GATE'):
                self.run_gate(report)
        report = copy.deepcopy(self.report); report['Results'] = report['Results'][:1]
        with self.assertRaisesRegex(Exception, 'COVERAGE'): self.run_gate(report)

    def test_stale_future_naive_scan_and_suppressed_findings_are_denied(self):
        for date in ('2026-10-30T22:00:00Z', '2026-11-02T22:00:00Z', '2026-11-01T22:00:00'):
            report = dict(self.report, CreatedAt=date)
            with self.subTest(date=date), self.assertRaises(ValueError): self.run_gate(report)
        report = copy.deepcopy(self.report)
        report['Results'][0]['ModifiedFindings'] = [{'Status':'ignored'}]
        with self.assertRaisesRegex(ValueError, 'MODIFIED'): self.run_gate(report)


if __name__ == '__main__': unittest.main()
