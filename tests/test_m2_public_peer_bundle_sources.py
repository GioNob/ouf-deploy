"""Real root-owned files and immutable source repair; native NIC leaves modeled."""
import hashlib,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.semantic_transaction_profiles.repair_peer_bundle_sources import repair,PEER,ORIGINAL_SHA
from tools.semantic_provider_deployment_authentication import private_bytes

def private_reader(path):return private_bytes(Path(path))

class PublicPeerBundle(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='peer-oci-fixture-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700);self.cid='a'*64
        parent=self.root/self.cid;parent.mkdir(mode=0o700);self.path=parent/'config.json'
        self.raw=b'{"ociVersion":"1.3.0","fixture":"independently-approved-frame"}'
        self.path.write_bytes(self.raw);self.path.chmod(0o644)
        self.original=(ROOT/'tools/semantic_cohort_admission/cohort-draft'/PEER).read_bytes()
        self.source=repair({PEER:self.original})[PEER]
        self.module=types.ModuleType('public_peer_fixture');exec(compile(self.source,PEER,'exec'),self.module.__dict__)
        self.expected={'containerId':self.cid,'applicationHash':self.module.digest(json.loads(self.raw))}
    def read(self,reader=private_reader):return self.module.read_peer_bundle(str(self.path),self.expected,reader)
    def test_reproduces_original_private_denial_and_accepts_only_exact_hash_bound_engine_oci(self):
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_AUTHENTICATION_INPUT_REQUIRED'):private_bytes(self.path)
        self.assertEqual(self.read(),self.raw)
        self.assertEqual(self.path.stat().st_mode&0o777,0o644)
        self.path.chmod(0o600);self.assertEqual(self.read(),self.raw)
    def test_no_general_private_reader_fallback_for_credentials_or_foreign_peer(self):
        for name in ('approval.json','key.pem'):
            path=self.path.with_name(name);path.write_bytes(self.raw);path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'EXACT_ENGINE_PEER_BUNDLE_PATH'):
                self.module.read_peer_bundle(str(path),self.expected,private_reader)
        wrong={**self.expected,'containerId':'b'*64}
        with self.assertRaisesRegex(ValueError,'EXACT_ENGINE_PEER_BUNDLE_PATH'):
            self.module.read_peer_bundle(str(self.path),wrong,private_reader)
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_AUTHENTICATION_INPUT_REQUIRED'):private_bytes(self.path)
    def test_writable_nonstandard_modes_and_different_content_are_denied(self):
        for mode in (0o666,0o640,0o400):
            self.path.chmod(mode)
            with self.assertRaisesRegex(ValueError,'ROOT_OWNED_READONLY_ENGINE_PEER_OCI'):self.read()
        self.path.chmod(0o644);self.path.write_bytes(b'{"fixture":"different-frame"}')
        with self.assertRaisesRegex(ValueError,'PEER_COMPLETE_OCI_DRIFT'):self.read()
    def test_unknown_reader_error_is_not_reclassified_or_retried(self):
        calls=[]
        def unknown(_):calls.append(1);raise RuntimeError('UNKNOWN_IO_DENIAL')
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_IO_DENIAL'):self.read(unknown)
        self.assertEqual(calls,[1])
    def test_symlink_hardlink_and_untrusted_ancestor_are_denied(self):
        real=self.path.with_name('preserved');self.path.rename(real);self.path.symlink_to(real)
        with self.assertRaises(OSError):self.read()
        self.path.unlink();os.link(real,self.path)
        with self.assertRaisesRegex(ValueError,'ROOT_OWNED_READONLY_ENGINE_PEER_OCI'):self.read()
        self.path.unlink();real.rename(self.path);self.path.parent.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_ANCESTOR|TRUSTED_AUTHENTICATION_ANCESTOR'):self.read()
    def test_atomic_file_replacement_during_public_read_is_denied(self):
        original=os.read
        def changed(fd,count):
            raw=original(fd,count)
            if count==131073:
                replacement=self.path.with_name('replacement');replacement.write_bytes(self.raw);replacement.chmod(0o644)
                replacement.replace(self.path)
            return raw
        with patch('os.read',side_effect=changed),self.assertRaisesRegex(ValueError,'ENGINE_PEER_OCI_CHANGED'):self.read()
    def test_original_frozen_source_is_unchanged_and_revision_is_exact_and_one_use(self):
        self.assertEqual(hashlib.sha256(self.original).hexdigest(),ORIGINAL_SHA)
        with self.assertRaisesRegex(ValueError,'SOURCE_HASH_DRIFT'):repair({PEER:self.source})
        with self.assertRaisesRegex(ValueError,'SOURCE_HASH_DRIFT'):repair({PEER:self.original+b'\n'})
        self.assertEqual(repair({PEER:self.original,'unrelated':b'unchanged'})['unrelated'],b'unchanged')

if __name__=='__main__':unittest.main()
