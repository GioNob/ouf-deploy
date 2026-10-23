"""Offline deterministic release/case/source audit; no capsule is executed."""
import ast
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class PublishedArtifact(unittest.TestCase):
    def test_exact_case_capsule_declaration_and_source_membership_record(self):
        self.check_artifact('evidence/semantic-registry-postboot-source-membership-20261023.json', False)

    def test_immutable_properties_capsule_and_reconciled_case(self):
        self.check_artifact('evidence/semantic-registry-postboot-properties-source-membership-20261023.json', False)

    def check_artifact(self, audit_path, current):
        path = ROOT / 'tools/semantic_registry_recovery_execution/delivery.py'
        spec = importlib.util.spec_from_file_location('published_postboot_generator', path)
        delivery = importlib.util.module_from_spec(spec); spec.loader.exec_module(delivery)
        audit = json.loads((ROOT / audit_path).read_bytes())
        capsule = (ROOT / audit['capsule']['path']).read_bytes()
        raw_declaration = (ROOT / audit['declaration']['path']).read_bytes()
        declaration = json.loads(raw_declaration); manifest = declaration['nativeDeclaration']
        case = json.loads((ROOT / audit.get('casePath', 'releases/semantic-registry-postboot-case-20261023.json')).read_bytes())
        self.assertEqual(delivery.sha(capsule), audit['capsule']['sha256'])
        self.assertEqual(len(capsule), audit['capsule']['bytes'])
        self.assertEqual(delivery.sha(raw_declaration), audit['declaration']['sha256'])
        self.assertEqual(delivery.sha(delivery.encoded(manifest)), audit['sourceClosureHash'])
        self.assertEqual(delivery.sha(delivery.encoded(case)), audit['caseHash'])
        assignments = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(capsule).body
            if isinstance(node, ast.Assign)}
        self.assertEqual(assignments['DELIVERY'], declaration)
        self.assertEqual(assignments['DELIVERY_HASH'], audit['declaration']['sha256'])
        payload = json.loads(gzip.decompress(base64.b64decode(assignments['PACKED'], validate=True)))
        self.assertEqual(delivery.sha(payload['loader'].encode()), manifest['loaderHash'])
        # Regenerate an immutable release with its own sealed loader, including
        # when the development loader has since received a compatibility fix.
        # Current application sources must still match every published member.
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            release_root = Path(directory)
            members = {'tools/semantic_registry_recovery_execution/runtime.py': payload['loader']}
            members.update({manifest['sourcePaths'][name]: text for name, text in payload['sources'].items()})
            for member, text in members.items():
                target = release_root / member
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
            self.assertEqual(delivery.generate(release_root, case, audit['sourceCommit'], audit['sourcePins']),
                             (capsule, declaration))
        self.assertEqual(manifest['sourceGitBlobs'], audit['sourceGitBlobs'])
        self.assertEqual(manifest['sourcePaths'], audit['sourcePaths'])
        self.assertEqual(set(payload['sources']), set(manifest['sourceHashes']))
        for name, text in payload['sources'].items():
            raw = text.encode()
            if current:
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
