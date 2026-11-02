import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('evidence', ROOT/'tools/storage_licenses/evidence.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class LicenceEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.name = 'example.org/Module/v2'; self.version = 'v2.1.0'
        self.mod = b'module example.org/Module/v2\ngo 1.21\n'

    def module(self, extra=None):
        p = self.root/'module.zip'
        files = {'LICENSE': b'synthetic licence text', 'NOTICE.txt': b'attribution',
                 'nested/COPYING': b'other terms', 'code.go': b'package example\n'}
        files.update(extra or {})
        with zipfile.ZipFile(p, 'w') as z:
            for name, raw in files.items():
                z.writestr(self.name+'@'+self.version+'/'+name, raw)
        records = [(self.name+'@'+self.version+'/'+name, hashlib.sha256(raw).hexdigest())
                   for name, raw in files.items()]
        return p, m.h1_records(records), m.h1_records([('go.mod', m.sha(self.mod))])

    def test_go_h1_canonical_vector_and_order(self):
        raw = b'hello\n'
        expected = 'h1:'+base64.b64encode(hashlib.sha256((hashlib.sha256(raw).hexdigest()+'  go.mod\n').encode()).digest()).decode()
        self.assertEqual(m.h1_records([('go.mod', m.sha(raw))]), expected)
        records = [('b', m.sha(b'b')), ('a', m.sha(b'a'))]
        self.assertEqual(m.h1_records(records), m.h1_records(list(reversed(records))))

    def test_legal_texts_are_bound_to_complete_zip_not_only_licence(self):
        p, h, modh = self.module()
        texts, record = m.module_texts(self.name, self.version, p, self.mod, h, modh)
        self.assertEqual(set(texts), {'LICENSE', 'NOTICE.txt', 'nested/COPYING'})
        self.assertEqual(record['archiveMembers'], 4)
        # Altering an uncollected Go source must invalidate the evidence too.
        p, _, _ = self.module({'code.go': b'changed'})
        with self.assertRaisesRegex(ValueError, 'MODULE_ZIP_CHECKSUM'):
            m.module_texts(self.name, self.version, p, self.mod, h, modh)

    def test_go_mod_checksum_and_exact_module_prefix(self):
        p, h, modh = self.module()
        with self.assertRaisesRegex(ValueError, 'GO_MOD_CHECKSUM'):
            m.module_texts(self.name, self.version, p, b'wrong', h, modh)
        with self.assertRaisesRegex(ValueError, 'EXACT_MODULE_PREFIX'):
            m.module_texts('another.org/mod', self.version, p, self.mod, h, modh)

    def test_duplicate_members_symlink_and_traversal_denied(self):
        p, h, modh = self.module()
        with zipfile.ZipFile(p, 'a') as z:
            z.writestr(self.name+'@'+self.version+'/LICENSE', b'duplicate')
        with self.assertRaisesRegex(ValueError, 'DISTINCT_BOUNDED'):
            m.module_texts(self.name, self.version, p, self.mod, h, modh)
        p, h, modh = self.module({'../escape/LICENSE': b'bad'})
        with self.assertRaisesRegex(ValueError, 'SAFE_ARCHIVE_PATH'):
            m.module_texts(self.name, self.version, p, self.mod, h, modh)
        p, h, modh = self.module()
        with zipfile.ZipFile(p, 'a') as z:
            i = zipfile.ZipInfo(self.name+'@'+self.version+'/COPYING'); i.external_attr = 0o120777 << 16
            z.writestr(i, 'elsewhere')
        with self.assertRaisesRegex(ValueError, 'NO_LINK'):
            m.module_texts(self.name, self.version, p, self.mod, h, modh)

    def test_floating_versions_and_argument_injection_denied(self):
        for name, version in [('example.org/mod', 'latest'), ('example.org/mod', 'main'),
                              ('-evil.org/mod', 'v1.0.0'), ('example.org/../mod', 'v1.0.0'),
                              ('example.org/mod;exec', 'v1.0.0')]:
            with self.assertRaises(ValueError):
                m.validate_module_identity(name, version)
        m.validate_module_identity('github.com/Azure/azcore', 'v1.2.3')
        m.validate_module_identity('example.org/mod', 'v0.0.0-20261025193907-153ab668c997')

    def test_empty_or_missing_licence_is_not_fabricated(self):
        c = m.retain_component(self.root, self.name, self.version, {'LICENSE': b''}, {})
        self.assertEqual(c['rootLicenceCandidates'], 0)
        self.assertEqual(c['collectionStatus'], 'ROOT_LICENCE_REVIEW_REQUIRED')
        self.assertFalse(c['obligationsAccepted'])
        self.assertEqual(c['licenceExpression'], 'NOASSERTION')

    def classification(self, confidence=0.99, severity='LOW'):
        c = m.retain_component(self.root, self.name, self.version, {'LICENSE': b'licence'}, {})
        path = c['legalTexts'][0]['evidencePath']
        report = {'SchemaVersion': 2, 'Trivy': {'Version': '0.70.0'}, 'Results': [{'Licenses': [
            {'FilePath': path, 'Name': 'MIT', 'PkgName': '', 'Confidence': confidence, 'Severity': severity}]}]}
        return {'components': [c]}, report

    def test_classification_cannot_accept_redistribution_or_change_spdx(self):
        i, r = self.classification()
        a = m.assess_classification(i, r)
        self.assertEqual(a['componentsWithRootClassification'], 1)
        self.assertFalse(a['redistributionAccepted'])
        self.assertFalse(a['rawSpdxModified'])
        self.assertEqual(a['components'][0]['licenceExpression'], 'NOASSERTION')

    def test_low_confidence_unknown_and_empty_scan_stay_unresolved(self):
        i, r = self.classification(0.4, 'UNKNOWN')
        a = m.assess_classification(i, r)
        self.assertEqual(a['componentsWithRootClassification'], 0)
        self.assertEqual(a['severities']['UNKNOWN'], 1)
        r['Results'] = []
        with self.assertRaisesRegex(ValueError, 'NONEMPTY_PINNED'):
            m.assess_classification(i, r)

    def test_classifier_cannot_claim_text_not_retained(self):
        i, r = self.classification()
        r['Results'][0]['Licenses'][0]['FilePath'] = 'unknown/LICENSE'
        with self.assertRaisesRegex(ValueError, 'EXACT_RETAINED_FILE'):
            m.assess_classification(i, r)


if __name__ == '__main__':
    unittest.main()
