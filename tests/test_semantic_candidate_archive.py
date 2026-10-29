import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('verify', Path(__file__).parents[1]/'scripts/verify-semantic-proposal-candidate-archive.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

class ArchiveTests(unittest.TestCase):
    def archive(self, *, authority=False, severity=None, unsafe=False, bad_checksum=False):
        manifest = dict(schema='ouf.semantic-proposal-unsigned-candidate.v1', module='gateway',
                        sourceCommit=verify.SOURCES['gateway'], runtimeAuthorityIssued=False,
                        signatureIssued=False, targetApplyAuthorized=authority, notReleaseAcceptance=True,
                        vpsOperations=0, r12Touched=False, budgetReset=False,
                        transitivePythonRuntimeQualificationProven=False)
        requirements = b'fixture==1.0\n'
        manifest['requirementsSha256'] = hashlib.sha256(requirements).hexdigest()
        result = dict(Class='lang-pkgs', Type='pip', Packages=[dict(Name='fixture', Version='1.0')])
        if severity:
            result['Vulnerabilities'] = [dict(Severity=severity)]
        files = {'candidate-manifest.json': json.dumps(manifest).encode(),
                 'source-inventory.json': b'{"truncated":false,"tree":[{"path":"fixture"}]}',
                 'trivy-image.json': json.dumps(dict(SchemaVersion=2, Results=[result])).encode(),
                 'source.tar': b'fixture', 'gateway-scan/requirements.txt': requirements}
        if unsafe:
            files['../escape'] = b'bad'
        lines = ''.join(hashlib.sha256(raw).hexdigest()+'  '+name+'\n' for name, raw in files.items())
        files['SHA256SUMS'] = lines.encode()
        if bad_checksum:
            files['source.tar'] = b'changed-after-seal'
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, raw in files.items():
                archive.writestr(name, raw)
        return stream.getvalue()

    def check(self, raw, digest=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.zip'
            path.write_bytes(raw)
            return verify.verify(path, 'gateway', digest or hashlib.sha256(raw).hexdigest())

    def test_unsigned_archive_passes_without_runtime_authority(self):
        result = self.check(self.archive())
        self.assertFalse(result['targetApplyAuthorized'])

    def test_ci_digest_and_inner_file_tampering_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CI_ARCHIVE_DIGEST_MISMATCH'):
            self.check(self.archive(), '0'*64)
        with self.assertRaisesRegex(ValueError, 'PACKAGE_FILE_DIGEST_MISMATCH'):
            self.check(self.archive(bad_checksum=True))

    def test_traversal_is_rejected_even_with_matching_archive_digest(self):
        with self.assertRaisesRegex(ValueError, 'UNSAFE_ARCHIVE_ENTRY'):
            self.check(self.archive(unsafe=True))

    def test_authority_claim_and_disallowed_or_unknown_severity_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_AUTHORITY_FLAGS_INVALID'):
            self.check(self.archive(authority=True))
        for severity in ['HIGH','CRITICAL','UNKNOWN','OTHER']:
            with self.subTest(severity=severity), self.assertRaisesRegex(ValueError, 'VULNERABILITY_GATE_REJECTED'):
                self.check(self.archive(severity=severity))

if __name__ == '__main__':
    unittest.main()
