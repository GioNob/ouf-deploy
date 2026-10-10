"""Native root POSIX custody: distinct consumers, exclusive claim, no replay."""
import copy,importlib.util,json,os,stat,tempfile,unittest
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
class PublicTrustBinding(unittest.TestCase):
    def setUp(self):
        source=str(prepare.BASE/'semantic-provider-v2-inputs-XE7IwlGm/config.yaml');target='/usr/local/apisix/conf/config.yaml'
        digest='77342a509b0b0e9498728fa366f50ce031c19d78a636d4225de5e95e1ba97140'
        self.bundle={'mounts':[{'destination':target,'source':source,'type':'bind','options':['rbind','ro']}]}
        self.policy={'sources':[{'source':source,'target':target,'readOnly':True,'sha256':digest,'uid':636,'gid':636,'mode':0o600}]}
        self.live={'Id':prepare.SOUTHBOUND,'Image':'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366','State':{'Running':True},'Mounts':[{'Destination':target,'Type':'bind','Source':source,'RW':False}]}
        self.startup={'schema':'ouf.semantic-provider-v2-startup-inputs.v1','status':'PRIVATE_STARTUP_INPUTS_PREPARED','directory':str(Path(source).parent),'sourceHash':'de06ef9b78cc0c33d7fe0efbedd9019edcac5ad2b680695adf4d2dc224e491b1','trustDirectory':str(prepare.BASE/'semantic-provider-v2-trust-vf7B4SM5'),'trustReceiptHash':'bb158aa0eda6c767f6bdf6f4ac6e0f8eefd93cfe6f0ee48196d0f9bf7f521458','outputHashes':{'config.yaml':digest}}
    def test_configuration_mount_binds_public_trust_without_certificate_mount(self):
        with patch.object(prepare,'file_bytes',side_effect=AssertionError('No file read in metadata binding')):
            self.assertEqual(prepare.public_trust_source(self.bundle,self.policy,self.live,self.startup),prepare.BASE/'semantic-provider-v2-trust-vf7B4SM5')
    def test_writable_oci_or_live_mount_rejected(self):
        for field in ('oci','live'):
            bundle=copy.deepcopy(self.bundle);live=copy.deepcopy(self.live)
            if field=='oci':bundle['mounts'][0]['options']=['rbind','rw']
            else:live['Mounts'][0]['RW']=True
            with self.assertRaises(ValueError):prepare.public_trust_source(bundle,self.policy,live,self.startup)
    def test_changed_sealed_hash_or_trust_receipt_rejected(self):
        for field in ('source','trust'):
            policy=copy.deepcopy(self.policy);startup=copy.deepcopy(self.startup)
            if field=='source':policy['sources'][0]['sha256']='0'*64
            else:startup['trustReceiptHash']='0'*64
            with self.assertRaises(ValueError):prepare.public_trust_source(self.bundle,policy,self.live,startup)
    def test_duplicate_or_retargeted_configuration_mount_rejected(self):
        for duplicate in (True,False):
            bundle=copy.deepcopy(self.bundle)
            if duplicate:bundle['mounts'].append(copy.deepcopy(bundle['mounts'][0]))
            else:bundle['mounts'][0]['source']='/unapproved/config.yaml'
            with self.assertRaises(ValueError):prepare.public_trust_source(bundle,self.policy,self.live,self.startup)

if __name__=='__main__':unittest.main()
