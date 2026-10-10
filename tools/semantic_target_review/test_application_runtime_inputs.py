"""Native root POSIX custody: distinct consumers, exclusive claim, no replay."""
import importlib.util,json,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare_application_runtime_inputs.py'))
prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
class RootCustody(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0,'These custody checks require a disposable root test environment')
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_ROOT_CUSTODY_TEST_BASE',str(Path.cwd())));self.root=Path(self.temp.name);self.root.chmod(0o700);self.claim=self.root/'claim.json'
    def tearDown(self):self.temp.cleanup()
    def test_actual_role_owned_copies_and_exclusive_claim(self):
        prepare.prepare_files(self.root,self.claim,'existing-credential-value',b'public-ca-only',{'epoch':'test'})
        sem=self.root/'semantic-discovery-owner.key';gw=self.root/'gateway-discovery-owner.key';cred=self.root/'schema-gov-client-secret'
        self.assertEqual(sem.read_bytes(),gw.read_bytes());self.assertRegex(sem.read_text(),'^[a-f0-9]{64}$');self.assertEqual(cred.read_text(),'existing-credential-value')
        for path,uid in ((sem,10001),(gw,636),(cred,10001)):
            s=path.stat();self.assertEqual((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)),(uid,uid,0o400))
        key=sem.read_bytes()
        with self.assertRaises(FileExistsError):prepare.prepare_files(self.root,self.claim,'another-credential',b'other-ca',{})
        self.assertEqual(sem.read_bytes(),key)
        manifest=json.loads((self.root/'private-input-manifest.json').read_bytes());self.assertFalse(manifest['mountsInstalled']);self.assertFalse(manifest['leaseAuthorityGranted']);self.assertFalse(manifest['applicationCutoverAuthorized'])
    def test_insecure_root_rejected_before_claim(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'EXCLUSIVE_PRIVATE_ROOT_REQUIRED'):prepare.prepare_files(self.root,self.claim,'credential',b'ca',{})
        self.assertFalse(self.claim.exists())
    def test_failure_retains_claim_without_rearming(self):
        with patch.object(prepare.secrets,'token_hex',side_effect=RuntimeError('fixture-failure')):
            with self.assertRaises(RuntimeError):prepare.prepare_files(self.root,self.claim,'credential',b'ca',{})
        self.assertTrue(self.claim.exists());self.assertFalse((self.root/'semantic-discovery-owner.key').exists())
        with self.assertRaises(FileExistsError):prepare.prepare_files(self.root,self.claim,'credential',b'ca',{})
    def test_private_input_hash_mode_and_symlink_fail_closed(self):
        path=self.root/'input.json';path.write_bytes(b'bounded input');path.chmod(0o600)
        raw=prepare.file_bytes(path,0,{0o600},expected=prepare.sha(b'bounded input'));self.assertEqual(raw,b'bounded input')
        with self.assertRaisesRegex(ValueError,'EXACT_INPUT_HASH_REQUIRED'):prepare.file_bytes(path,0,{0o600},expected='0'*64)
        path.chmod(0o644)
        with self.assertRaises(ValueError):prepare.file_bytes(path,0,{0o600})
        link=self.root/'link';link.symlink_to(path)
        with self.assertRaises(OSError):prepare.file_bytes(link,0,{0o600})
if __name__=='__main__':unittest.main()
