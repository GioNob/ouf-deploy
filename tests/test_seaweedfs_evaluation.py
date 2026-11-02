import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('sw',Path(__file__).parents[1]/'scripts/qualify-seaweedfs-20261102.py')
sw=importlib.util.module_from_spec(spec);spec.loader.exec_module(sw)

class ScanDenialTest(unittest.TestCase):
    def report(self, severity=None):
        r={'Class':'lang-pkgs','Type':'gobinary','Packages':[{'Name':'stdlib'}]}
        if severity:r['Vulnerabilities']=[{'Severity':severity}]
        return {'SchemaVersion':2,'Results':[r]}
    def test_clean_binary_inventory(self):self.assertEqual(sum(sw.assess(self.report()).values()),0)
    def test_blocking_severities_are_counted(self):
        for severity in ['HIGH','CRITICAL','UNKNOWN']:
            self.assertEqual(sw.assess(self.report(severity))[severity],1)
    def test_missing_inventory_denied(self):
        for report in [{},{'SchemaVersion':2,'Results':[]},{'SchemaVersion':2,'Results':[{'Class':'os-pkgs','Packages':[{}]}]}]:
            with self.assertRaises(ValueError):sw.assess(report)
    def test_unknown_severity_denied(self):
        with self.assertRaises(ValueError):sw.assess(self.report('UNRATED'))

    def test_lab_diagnostics_only_for_absent_exact_openpgp_package(self):
        graph={'packages':['github.com/seaweedfs/seaweedfs/weed','golang.org/x/crypto/bcrypt']}
        report=self.report('UNKNOWN');finding=report['Results'][0]['Vulnerabilities'][0]
        finding.update(VulnerabilityID='GO-2026-5932',PkgName='golang.org/x/crypto')
        self.assertTrue(sw.lab_eligible(report,graph))
        graph['packages'].append('golang.org/x/crypto/openpgp/packet')
        self.assertFalse(sw.lab_eligible(report,graph))
    def test_other_unknown_or_high_cannot_enter_lab(self):
        graph={'packages':['github.com/seaweedfs/seaweedfs/weed']}
        for severity,identifier in [('HIGH','GO-2026-5932'),('UNKNOWN','OTHER')]:
            report=self.report(severity);report['Results'][0]['Vulnerabilities'][0].update(VulnerabilityID=identifier,PkgName='golang.org/x/crypto')
            self.assertFalse(sw.lab_eligible(report,graph))
