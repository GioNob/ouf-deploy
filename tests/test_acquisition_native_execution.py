import copy,hashlib,importlib.util,json,os,socketserver,stat,threading,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
f=module('mac_fixture',BASE/'tests/test_acquisition_mac_plan.py');n=module('native_preparation',BASE/'scripts/prepare-acquisition-read-native-execution-20261025.py');p=f.p
class NativePreparationTest(f.MacPlanTest):
    def setUp(self):
        super().setUp();self.frozen=self.prepare();self.native_root=self.base/'native-inputs';n.COUNTS.update({k:0 for k in n.COUNTS});self.saved_inputs=p.INPUTS;p.INPUTS=self.input_path;p.COUNTS.update({k:0 for k in p.COUNTS})
    def tearDown(self):p.INPUTS=self.saved_inputs;super().tearDown()
    def engine(self,helper,binding,allowed,root):
        outer=self
        class Fake:
            def get(self,path):
                outer.assertIn(path,allowed);n.COUNTS['engineGetAttempts']+=1
                if path=='/v1.44/info':return {'Driver':'overlayfs','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]}
                if '/networks/'in path:return {'Id':'1'*64,'Name':'ouf-backend','Driver':'bridge','Scope':'local'}
                cid=path.split('/')[-2];return next(copy.deepcopy(v)for v in outer.actual.values()if v['Id']==cid)
        return Fake()
    def fake_archive(self,helper,images,d,role,root,native):
        self.assertTrue(native);n.COUNTS['imageArchivesRead']+=1;n.COUNTS['nativeArchivesPrepared']+=1
        return {'nativeImageId':'sha256:'+'a'*64,'audit':{'imageConfig':{'Labels':{'org.opencontainers.image.source':'fixture-source'},'Env':[]}},'nativeArchive':{'path':str(root/'synthetic.tar'),'sha256':'b'*64,'bytes':1024}}
    def native_prepare(self,engine=None,authority=None):
        return n.prepare(p,None,self.root/'execution-plan.json',self.frozen['privatePlanHash'],p.sha((self.root/'complete.json').read_bytes()),self.native_root,engine or self.engine,authority or(lambda _: {'publicFixture':True}),self.fake_archive)
    def test_native_refinement_preserves_original_bytes_and_no_authority(self):
        before={path.name:path.read_bytes()for path in self.root.iterdir()if path.is_file()};v=self.native_prepare();self.assertTrue(v['complete']);self.assertEqual(v['engineGetAttempts'],12);self.assertEqual(v['nativeArchivesPrepared'],3);self.assertFalse(v['executionEntryQualified']);self.assertEqual(before,{path.name:path.read_bytes()for path in self.root.iterdir()if path.is_file()});self.assertEqual(v['gatewayAdminRequests'],0);self.assertEqual(v['containerWrites'],0)
        doc=p.decode((self.native_root/'native-inputs.json').read_bytes());old=p.decode((self.root/'execution-plan.json').read_bytes());new=doc['nativeProposal']
        for role in('ingestion','udp','mcp'):
            a=old['mcpReplacement']if role=='mcp'else old['readComponents'][role];b=new['mcpReplacement']if role=='mcp'else new['readComponents'][role];req=copy.deepcopy(b['request']);req['Image']=a['request']['Image'];self.assertEqual(a['request'],req)
        with self.assertRaisesRegex(n.Stop,'CONSUMED'):self.native_prepare()
        self.assertEqual(n.COUNTS['engineGetAttempts'],12)
    def test_runtime_drift_cannot_reach_archive(self):
        self.actual['udp']['Config']['Env'].append('DRIFT=true')
        with self.assertRaisesRegex(n.Stop,'CURRENT_RETAINED_COHORT_CHANGED'):self.native_prepare()
        self.assertEqual(n.COUNTS['nativeArchivesPrepared'],0)
    def test_public_authority_failure_cannot_reach_engine(self):
        def denied(_):raise n.Stop('CURRENT_AUTHORITY_DENIED')
        with self.assertRaisesRegex(n.Stop,'CURRENT_AUTHORITY_DENIED'):self.native_prepare(authority=denied)
        self.assertEqual(n.COUNTS['engineGetAttempts'],0)
    def test_exact_completion_hash_required(self):
        (self.root/'complete.json').chmod(0o600);(self.root/'complete.json').write_bytes(b'{}');(self.root/'complete.json').chmod(0o400)
        with self.assertRaises(Exception):self.native_prepare()
        self.assertEqual(n.COUNTS['engineGetAttempts'],0)
    def test_real_unix_engine_get_only_and_peer_pin(self):
        path=self.base/'engine.sock';seen=[]
        class Handler(socketserver.StreamRequestHandler):
            def handle(s):
                line=s.rfile.readline();seen.append(line);headers=b''
                while True:
                    line=s.rfile.readline()
                    if line in(b'\r\n',b''):break
                    headers+=line
                raw=b'{"syntheticPrivateValue":"not-public"}';s.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()+b'\r\nConnection: close\r\n\r\n'+raw)
        server=socketserver.UnixStreamServer(str(path),Handler);path.chmod(0o660);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();root=self.base/'socket-evidence';root.mkdir(mode=0o700);s=path.stat();binding={'socketPath':str(path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':[os.getpid(),0,0]};engine=n.Engine(p,binding,{'/v1.44/info'},root)
        try:
            value=engine.get('/v1.44/info');self.assertEqual(value['syntheticPrivateValue'],'not-public')
            with self.assertRaisesRegex(n.Stop,'EXACT_ENGINE_GETS'):engine.get('/v1.44/containers/other/json')
            self.assertEqual(len(seen),1);self.assertTrue(seen[0].startswith(b'GET /v1.44/info '));self.assertEqual(n.COUNTS['engineGetAttempts'],1)
        finally:server.shutdown();server.server_close();thread.join()
    def test_current_public_role_metadata_requires_full_future_window(self):
        import time
        now=int(time.time());policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':n.CONTEXT['installationRef'],'entityRef':n.CONTEXT['entityRef'],'keys':[]};profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':n.CONTEXT,'policyBinding':{},'keyRefs':{'installer':'i','attestor':'a'},'keyBindings':{r:{'path':'/private/'+r,'sha256':'a'*64}for r in('installer','attestor')}}
        for role,issuer,roles in(('installer',n.CONTEXT['intentIssuerRef'],['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('attestor',n.CONTEXT['attestorRef'],['CREATION_ATTESTATION'])):policy['keys'].append({'keyRef':profile['keyRefs'][role],'issuerRef':issuer,'roles':roles,'publicKey':'a'*64,'notBefore':now-1,'expiresAt':now+1000,'state':'ACTIVE'})
        policy_path=self.base/'policy';profile_path=self.base/'profile';self.write(policy_path,policy);pb={'path':str(policy_path),'sha256':p.digest(policy)};profile['policyBinding']=pb;self.write(profile_path,profile);pr={'path':str(profile_path),'sha256':p.digest(profile)};self.assertFalse(n.public_authority(p,pr,pb)['privateKeysOpened'])
        policy['keys'][0]['expiresAt']=now+10;self.write(policy_path,policy);pb['sha256']=p.digest(policy);profile['policyBinding']=pb;self.write(profile_path,profile);pr['sha256']=p.digest(profile)
        with self.assertRaisesRegex(n.Stop,'FUTURE_REVIEW_WINDOW'):n.public_authority(p,pr,pb)
class PureChecks(unittest.TestCase):
    def test_engine_identity_profiles_are_closed(self):
        self.assertEqual(n.identity_profile({'Driver':'overlayfs','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]}),'CONFIG_AND_NATIVE_MANIFEST');self.assertEqual(n.identity_profile({'Driver':'overlay2','DriverStatus':[]}), 'CONFIGURATION_ID')
        for info in({'Driver':'unknown','DriverStatus':[]},{'Driver':'overlayfs','DriverStatus':[['driver-type','unknown']]},{'Driver':'overlay2','DriverStatus':[['x','a'],['x','b']]}):
            with self.assertRaises(n.Stop):n.identity_profile(info)
    def test_main_catches_stop_without_traceback(self):
        import subprocess,sys
        r=subprocess.run([sys.executable,str(BASE/'scripts/prepare-acquisition-read-native-execution-20261025.py')],capture_output=True,text=True);self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_NATIVE_PREPARATION_REQUIRED');self.assertNotIn('Traceback',r.stderr)
    def test_new_label_defaults_are_declared_but_manager_additions_denied(self):
        request={'Labels':{'existing':'value'},'Env':['PATH=/bin']};audit={'imageConfig':{'Labels':{'org.opencontainers.image.source':'source'},'Env':['PATH=/bin']}};v=n.labels(request,audit);self.assertEqual(v['expectedLabels']['existing'],'value');self.assertEqual(v['imageDefaultAdditions'],audit['imageConfig']['Labels']);audit['imageConfig']['Labels']['com.docker.compose.project']='other'
        with self.assertRaises(n.Stop):n.labels(request,audit)
if __name__=='__main__':unittest.main()

def load_tests(loader,tests,pattern):
    # The24 inherited MAC protocol tests have their dedicated gate. Reuse its
    # fixture, run only the new preparation tests here, without replaying setup.
    names=[name for name in NativePreparationTest.__dict__ if name.startswith('test_')]
    import fnmatch
    cases=[*(NativePreparationTest(name)for name in names),*loader.loadTestsFromTestCase(PureChecks)]
    patterns=loader.testNamePatterns
    return unittest.TestSuite(case for case in cases if not patterns or any(fnmatch.fnmatchcase(case.id(),pattern)for pattern in patterns))
