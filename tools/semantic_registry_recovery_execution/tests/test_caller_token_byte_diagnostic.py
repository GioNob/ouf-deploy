import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('token_byte_diagnostic',ROOT/'scripts/compare-registry-caller-token-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class TokenBytes(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.path=self.root/'token';self.path.write_bytes(b'secret-fixture-token');self.path.chmod(0o600)
        s=self.path.stat();parts=self.path.parts
        parents=['/']+['/'+'/'.join(parts[1:i])for i in range(2,len(parts))]
        self.b={'path':str(self.path),'sha256':hashlib.sha256(self.path.read_bytes()).hexdigest(),
                'metadata':list(d.identity(s)),
                'ancestors':[{'path':p,'identity':[v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode]}
                             for p in parents for v in[Path(p).stat()]]}
    def compare(self):return d.compare_token(d.Reader(),self.b)[0]
    def test_same_token_bytes_proven_without_printing_digest_or_value(self):
        r=self.compare();self.assertTrue(r['retainedTokenBytesMatch'])
        self.assertNotIn('secret-fixture-token',str(r));self.assertNotIn(self.b['sha256'],str(r))
        self.assertEqual(r['credentialContentReads'],1)
    def test_atomic_rewrite_same_bytes_is_distinct_from_changed_bearer(self):
        p=self.root/'new';p.write_bytes(self.path.read_bytes());p.chmod(0o600);p.replace(self.path)
        r=self.compare();self.assertTrue(r['retainedTokenBytesMatch']);self.assertTrue(r['tokenMetadataChangedOnlyInodeAndTimestamps'])
    def test_equal_size_new_bearer_reports_difference_without_adoption(self):
        self.path.write_bytes(b'SECRET-fixture-token');r=self.compare()
        self.assertFalse(r['retainedTokenBytesMatch']);self.assertTrue(r['diagnosticByteEqualityDoesNotAuthorizeRebinding'])
    def test_changed_mode_refused_before_reading_content(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'CALLER_TOKEN_ONLY_INODE_TIMESTAMPS_MAY_DIFFER'):self.compare()
    def test_symlink_refused_before_reading_content(self):
        self.path.unlink();self.path.symlink_to('/unavailable-private-token')
        with self.assertRaisesRegex(ValueError,'CALLER_TOKEN_ONLY_INODE_TIMESTAMPS_MAY_DIFFER'):self.compare()
    def test_drift_after_metadata_probe_is_refused(self):
        reader=d.Reader();original=reader.raw
        def changed(*a,**kw):
            value=original(*a,**kw);self.path.write_bytes(b'other-private-token!');return value
        reader.raw=changed
        with self.assertRaisesRegex(ValueError,'CALLER_TOKEN_CHANGED_DURING_BYTE_OBSERVATION'):d.compare_token(reader,self.b)
    def test_invalid_encoding_never_claims_valid_token(self):
        self.path.write_bytes(b'\xff'+b'a'*19)
        self.assertFalse(self.compare()['boundedTokenEncodingValid'])

if __name__=='__main__':unittest.main()
