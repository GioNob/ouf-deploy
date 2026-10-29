import hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'scripts/read-acquisition-retained-config-difference-20261025.py'
spec=importlib.util.spec_from_file_location('reader',SOURCE);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Fields(unittest.TestCase):
    def test_no_sensitive_values_or_unknown_names(self):
        v=r.classify({'Env':['SECRET=hidden-value'],'Entrypoint':['secret-command'],'Shell':['hidden-shell'],'hidden-key':'hidden-value'})
        raw=json.dumps(v);self.assertNotIn('hidden',raw);self.assertTrue(any(x['causesOriginalGuardStop']for x in v))
    def test_defaults_exactly_match_original(self):
        for v in(None,False,0,'',[],{},True,'x',['x']):
            self.assertEqual(r.classify({'ArgsEscaped':v})[0]['causesOriginalGuardStop'],not(v in(None,False,0,'',[],{})))
    def test_known_shell(self):self.assertEqual(r.classify({'Shell':['/bin/sh','-c']})[0]['shellClassification'],'BIN_SH')
    def test_duplicate_keys(self):
        with self.assertRaises(r.Stop):r.decode(b'{"x":1,"x":2}')
    def test_original_guard_closed(self):
        spec=importlib.util.spec_from_file_location('planner',SOURCE.parent/'prepare-acquisition-read-native-plan-20261025.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
        self.assertEqual(r.CREATE_FIELDS,p.CREATE_FIELDS)
        with self.assertRaises(p.Stop):p.config_copy({'Config':{'Shell':['/bin/sh','-c']}})
@unittest.skipUnless(os.environ.get('OUF_RETAINED_ROOT_FIXTURE')=='1','root custody requires dedicated CI root fixture')
class RootFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/var/lib');self.base=Path(self.tmp.name);self.parent=self.base/'parent';self.parent.mkdir(mode=0o700);self.root=self.base/'reader';self.inputs=self.base/'inputs';r.READS=0
        r.put(self.parent/'claim.json',{'schema':'ouf.acquisition-native-plan-claim.v1','caseHash':'2f9a2336572e1bbc57215bc6fc7b4f3a5f9bc5fa74e160be751cc0f57dcb8a80','maximumEngineGets':0,'maximumAdminGets':1})
        refs={}
        for role in('ingestion','udp','mcp'):
            p=self.base/role;r.put(p,{'Config':{'Env':['SECRET=never-print'],'Shell':['/bin/sh','-c']}});refs[role]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        r.put(self.inputs,{'schema':'ouf.acquisition-read-current-private-inputs.v1','currentObservations':refs});self.hash=hashlib.sha256(self.inputs.read_bytes()).hexdigest()
    def tearDown(self):self.tmp.cleanup()
    def run_reader(self):return r.run(self.inputs,self.hash,self.parent,self.root)
    def test_success_and_no_replay(self):
        before={p.name:p.read_bytes()for p in self.parent.iterdir()};v=self.run_reader();self.assertEqual(v['privateMetadataReads'],6);self.assertEqual(v['firstFailingRoleInOriginalOrder'],'ingestion');self.assertEqual(before,{p.name:p.read_bytes()for p in self.parent.iterdir()});self.assertNotIn('never-print',json.dumps(v));self.assertEqual((self.root/'complete.json').stat().st_mode&0o777,0o400)
        with self.assertRaisesRegex(r.Stop,'CONSUMED'):self.run_reader()
    def test_parent_advanced_denied(self):
        r.put(self.parent/'gateway-get-claim.json',{'attempt':True})
        with self.assertRaisesRegex(r.Stop,'PARENT_ADVANCED'):self.run_reader()
    def test_hash_drift_denied(self):
        self.hash='0'*64
        with self.assertRaisesRegex(r.Stop,'HASH_REQUIRED'):self.run_reader()
    def test_symlink_denied(self):
        p=self.base/'ingestion';p.rename(self.base/'old');p.symlink_to(self.base/'old')
        with self.assertRaises(OSError):self.run_reader()
if __name__=='__main__':unittest.main()
