"""Actual Unix HTTP Engine transport with a simulated container, not Docker."""
import copy,importlib.util,json,os,socketserver,sys,tempfile,threading,unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT.parents[1]))
sys.path.insert(0,str(ROOT.parent/'semantic_application_cutover'))
from engine_creation import Engine
from tools.semantic_registry_recovery_execution import core as c,authorization as a,lifecycle as l

class FixtureAuthority:
    def __init__(self,request):self.expected={'creationRequestHash':c.digest(request)};self.current=True
    def __call__(self,raw):return self.current
class FixtureProcess:
    def __init__(self,request):self.request=request

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def reply(self,status,value=None):
        raw=b'' if value is None else c.encoded(value)
        self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers()
        if raw:self.wfile.write(raw)
    def do_GET(self):
        self.server.calls.append(('GET',self.path))
        if self.path!='/v1.44/containers/'+'a'*64+'/json':return self.reply(404)
        self.reply(200,self.server.actual)
    def do_POST(self):
        self.server.calls.append(('POST',self.path));state=self.server.actual['State']
        suffix=self.path.rsplit('/',1)[-1]
        if suffix=='start':state.update(Status='running',Running=True,Pid=4242,StartedAt='new',Paused=False)
        elif suffix=='pause':state.update(Status='paused',Paused=True)
        elif suffix=='unpause':state.update(Status='running',Paused=False)
        elif suffix=='kill?signal=SIGUSR1':self.server.kind='APPLICATION_RUNNING'
        else:return self.reply(400)
        self.reply(204)

class Tests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('candidate',ROOT.parent/'semantic_registry_recovery_composition/compose.py')
        proposal_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(proposal_module)
        self.request={'Image':'sha256:'+'b'*64}
        self.baseline={'Id':'a'*64,'Image':self.request['Image'],'Config':{'fixture':'PRIVATE'},
            'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'OomKillDisable':False},
            'Mounts':[],'NetworkSettings':{},'RestartCount':0,
            'State':{'Status':'exited','Running':False,'Pid':0,'StartedAt':'old','Paused':False,'Restarting':False,'Dead':False}}
        pin={'containerId':'a'*64,'imageId':self.request['Image'],'configHash':c.digest(self.baseline['Config']),
             'hostConfigHash':c.digest(self.baseline['HostConfig']),'mountsHash':c.digest([])}
        self.proposal={'registry':pin,'requiredGates':list(proposal_module.GATES),'unresolvedGateCount':8}
        self.plan=proposal_module.candidate_contract(self.proposal,'b'*64,'c'*64)
        self.new={'containerId':'a'*64,'bootId':'11111111-2222-3333-4444-555555555555',
                  'pid':4242,'startTicks':12345,'namespaceDevice':4,'namespaceInode':12}
        self.temp=tempfile.TemporaryDirectory(dir=Path.cwd());self.addCleanup(self.temp.cleanup)
        parent=Path(self.temp.name);root=parent/('semantic-registry-recovery-'+self.plan['logicalOperationRef']);root.mkdir(mode=0o700)
        self.store=c.Store(root,self.plan['logicalOperationRef'])
        self.auth=FixtureAuthority(self.request)
        self.raw=c.encoded({'semanticRegistryRecovery':a.scope(self.plan),'issuedAt':99,'expiresAt':901})
        self.patch=patch.object(a,'cutover_type',return_value=FixtureAuthority);self.patch.start();self.addCleanup(self.patch.stop)
        self.authority=a.AuthorityScope(self.auth,self.raw,self.plan,self.request)
        row=c.initial(self.plan,authority_hash=self.authority.hash,expires_unix=900,expires_monotonic=850,
            boot_id=self.new['bootId'],predecessor_history_hash='e'*64,created_unix=100,created_monotonic=50)
        self.store.initialize(row)
        socket_path=str(parent/'s');self.server=socketserver.UnixStreamServer(socket_path,Handler)
        os.chmod(socket_path,0o600);info=os.stat(socket_path)
        self.server.actual=copy.deepcopy(self.baseline);self.server.kind='GATE_WAITING';self.server.calls=[]
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.close_server)
        self.engine=Engine(socket_path,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,0o600))
        self.process_patch=patch.object(l,'process_type',return_value=FixtureProcess);self.process_patch.start();self.addCleanup(self.process_patch.stop)
        self.observation_patch=patch.object(l,'observe_generation',side_effect=lambda *_:(copy.deepcopy(self.new),{'processKind':self.server.kind}))
        self.observation_patch.start();self.addCleanup(self.observation_patch.stop)
        self.native=l.Lifecycle(self.engine,self.authority,self.store,self.plan,self.request,self.baseline,self.proposal)
    def close_server(self):self.server.shutdown();self.server.server_close()
    def claim(self,name):
        index=next(i for i,s in enumerate(self.plan['stages']) if s['name']==name)
        row=self.store.read();effects=[]
        for stage in self.plan['stages'][:index]:
            proof={'newGeneration':self.new,'durableNativeStartEvidence':True}
            effects.append({'stage':stage['name'],'intentHash':stage['intentHash'],'authorityHash':self.authority.hash,
                            'state':'APPLIED','nativeEvidence':proof,'nativeEvidenceHash':c.digest(proof)})
        stage=self.plan['stages'][index]
        effects.append({'stage':name,'intentHash':stage['intentHash'],'authorityHash':self.authority.hash,'state':'CLAIMED','nativeEvidence':None})
        after={**row,'nextStage':index,'effects':effects,'state':'IN_FLIGHT','newGeneration':None if index<2 else self.new,'version':row['version']+1}
        self.store.cas(row,after);return stage
    def post_calls(self):return [path for method,path in self.server.calls if method=='POST']

    def test_new_start_captures_first_generation_and_cannot_be_transmitted_twice(self):
        stage=self.claim('START_NEW_WAIT_GATE');self.native.apply(stage)
        status,proof=self.native.observe(stage)
        self.assertEqual(status,'APPLIED');self.assertEqual(proof['newGeneration'],self.new)
        self.assertTrue(proof['durableNativeStartEvidence'])
        with self.assertRaisesRegex(c.RecoveryDenied,'ALREADY_ATTEMPTED'):self.native.apply(stage)
        self.assertEqual(self.post_calls(),['/v1.44/containers/'+'a'*64+'/start'])

    def test_crash_before_first_process_capture_never_adopts_later_pid(self):
        stage=self.claim('START_NEW_WAIT_GATE')
        with patch.object(self.native,'process_evidence',side_effect=OSError('capture interrupted')):
            with self.assertRaises(OSError):self.native.apply(stage)
        self.assertEqual(self.native.observe(stage),('UNKNOWN',{}))
        with self.assertRaises(c.RecoveryDenied):self.native.apply(stage)
        self.assertEqual(len(self.post_calls()),1)

    def test_pause_unpause_and_signal_have_separate_durable_attempts(self):
        stage=self.claim('START_NEW_WAIT_GATE');self.native.apply(stage)
        for name,suffix in [('PAUSE_NEW_WAIT_GATE','pause'),('UNPAUSE_ATTESTED_GENERATION','unpause'),
                            ('RELEASE_SAME_GENERATION_SIGUSR1','kill?signal=SIGUSR1')]:
            stage=self.claim(name);self.native.apply(stage)
            self.assertEqual(self.native.observe(stage)[0],'APPLIED')
            self.assertEqual(self.post_calls()[-1].rsplit('/',1)[-1],suffix)
        self.assertEqual(len(self.post_calls()),4)

    def test_pre_start_configuration_drift_prevents_effect(self):
        stage=self.claim('START_NEW_WAIT_GATE');self.server.actual['Config']['fixture']='CHANGED'
        with self.assertRaisesRegex(c.RecoveryDenied,'CONFIGURATION_CHANGED'):self.native.apply(stage)
        self.assertEqual(self.post_calls(),[])

    def test_pid_or_namespace_change_prevents_unpause(self):
        stage=self.claim('START_NEW_WAIT_GATE');self.native.apply(stage)
        stage=self.claim('PAUSE_NEW_WAIT_GATE');self.native.apply(stage)
        stage=self.claim('UNPAUSE_ATTESTED_GENERATION');self.new['namespaceInode']+=1
        with self.assertRaisesRegex(c.RecoveryDenied,'SAME_GATED_GENERATION'):self.native.apply(stage)
        self.assertEqual(len(self.post_calls()),2)

    def test_revoked_current_authority_prevents_effect(self):
        stage=self.claim('START_NEW_WAIT_GATE');self.auth.current=False
        with self.assertRaisesRegex(c.RecoveryDenied,'CURRENT_DUAL_ROLE'):self.native.apply(stage)
        self.assertEqual(self.post_calls(),[])

    def test_signed_scope_cannot_be_replaced_by_historical_or_partial_authority(self):
        for signed in ({},{'semanticRegistryRecovery':{'planHash':c.digest(self.plan)}}):
            with self.assertRaisesRegex(c.RecoveryDenied,'EXACT_SIGNED_REGISTRY_RECOVERY_SCOPE'):
                a.AuthorityScope(self.auth,c.encoded(signed),self.plan,self.request)

    def test_only_documented_oom_default_equivalence_is_tolerated(self):
        stage=self.claim('START_NEW_WAIT_GATE');self.server.actual['HostConfig']['OomKillDisable']=None
        self.native.apply(stage)
        self.server.actual['HostConfig']['OomKillDisable']=0
        with self.assertRaisesRegex(c.RecoveryDenied,'HOST_CONFIGURATION_CHANGED'):self.native.observe(stage)

if __name__=='__main__':unittest.main()
