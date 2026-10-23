"""Offline deterministic release/case/source audit; no capsule is executed."""
import ast
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class PublishedArtifact(unittest.TestCase):
    def test_exact_case_capsule_declaration_and_source_membership_record(self):
        path = ROOT / 'tools/semantic_registry_recovery_execution/delivery.py'
        spec = importlib.util.spec_from_file_location('published_postboot_generator', path)
        delivery = importlib.util.module_from_spec(spec); spec.loader.exec_module(delivery)
        audit = json.loads((ROOT / 'evidence/semantic-registry-postboot-source-membership-20261023.json').read_bytes())
        capsule = (ROOT / audit['capsule']['path']).read_bytes()
        raw_declaration = (ROOT / audit['declaration']['path']).read_bytes()
        declaration = json.loads(raw_declaration); manifest = declaration['nativeDeclaration']
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-case-20261023.json').read_bytes())
        self.assertEqual(delivery.sha(capsule), audit['capsule']['sha256'])
        self.assertEqual(len(capsule), audit['capsule']['bytes'])
        self.assertEqual(delivery.sha(raw_declaration), audit['declaration']['sha256'])
        self.assertEqual(delivery.sha(delivery.encoded(manifest)), audit['sourceClosureHash'])
        self.assertEqual(delivery.sha(delivery.encoded(case)), audit['caseHash'])
        self.assertEqual(delivery.generate(ROOT, case, audit['sourceCommit'], audit['sourcePins']), (capsule, declaration))
        assignments = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(capsule).body
            if isinstance(node, ast.Assign)}
        self.assertEqual(assignments['DELIVERY'], declaration)
        self.assertEqual(assignments['DELIVERY_HASH'], audit['declaration']['sha256'])
        payload = json.loads(gzip.decompress(base64.b64decode(assignments['PACKED'], validate=True)))
        self.assertEqual(delivery.sha(payload['loader'].encode()), manifest['loaderHash'])
        self.assertEqual(manifest['sourceGitBlobs'], audit['sourceGitBlobs'])
        self.assertEqual(manifest['sourcePaths'], audit['sourcePaths'])
        self.assertEqual(set(payload['sources']), set(manifest['sourceHashes']))
        for name, text in payload['sources'].items():
            raw = text.encode()
            self.assertEqual(raw, (ROOT / manifest['sourcePaths'][name]).read_bytes())
            self.assertEqual(delivery.sha(raw), manifest['sourceHashes'][name])
            self.assertEqual(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                             manifest['sourceGitBlobs'][name])
        self.assertFalse(audit['operatorWrapperProvided'])
        self.assertFalse(audit['runtimeAuthorityIssued'])
        self.assertFalse(audit['targetExecutionPerformed'])
        self.assertFalse(audit['wholeNativeRecoveryQualified'])
        self.assertFalse(audit['releaseAcceptance'])


if __name__ == '__main__':
    unittest.main()
