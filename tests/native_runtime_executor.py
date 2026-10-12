"""Disposable sleep process: native pause/release + actual controller deaths.
No Semantic JVM or target; authority, DB/lease and attestation are synthetic.
"""
import hashlib,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from test_cutover_executor import j
from transition_journal import Transition,PHASES,digest
from engine_creation import Engine,CreationDenied
from creation_adapter import CreationAdapter
from runtime_adapters import PausedStageAdapter,ReleasePausedAdapter
from native_evidence_store import NativeEvidenceStore
from cutover_executor import Executor

class NativeRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['docker','pull','alpine:3.21'],check=True,stdout=subprocess.DEVNULL,timeout=90)
        cls.image=subprocess.check_output(['docker','image','inspect','alpine:3.21','--format','{{.Id}}'],timeout=15).decode().strip()
    def fixture(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
        socket='/var/run/docker.sock';s=os.stat(socket,follow_symlinks=False)
        engine=Engine(socket,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777))
        request={'Image':self.image,'Cmd':['sleep','600'],'User':'10001:10001','HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'RestartPolicy':{'Name':'no','MaximumRetryCount':0}}}
        intents={p:{'syntheticFixturePhase':p} for p in PHASES};intents['CREATE_REPLACEMENT']=request
        intents['STAGE_PAUSED_REPLACEMENT']={'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'}
        intents['START_REPLACEMENT']={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT'}
        now=int(time.time());authority={'schema':'ouf.semantic-cutover-execution-authority.v1','issuedAt':now-1,'expiresAt':now+600,'creationRequestHash':digest(request),'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64,'sourceClosureHash':'e'*64,'phaseIntentHashes':{p:digest(v) for p,v in intents.items()},'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True}
        raw=json.dumps(authority,sort_keys=True,separators=(',',':')).encode();sha=hashlib.sha256(raw).hexdigest()
        directory=root/'journal';directory.mkdir(mode=0o700);evidence=root/'native';evidence.mkdir(mode=0o700)
        journal=j.Journal(directory);initial=Transition.initial(sha,digest(request),'c'*64,'d'*64);journal.initialize(initial);t=Transition(journal,initial['contextHash'])
        store=NativeEvidenceStore(evidence)
        class Synthetic:
            def apply(self,value):pass
            def observe(self,value):return 'APPLIED',{'syntheticFixture':True}
        adapters={p:Synthetic() for p in PHASES}
        adapters['CREATE_REPLACEMENT']=CreationAdapter(engine,t,request,store)
        adapters['STAGE_PAUSED_REPLACEMENT']=PausedStageAdapter(engine,t,request,store)
        adapters['START_REPLACEMENT']=ReleasePausedAdapter(engine,t,request,store)
        def checkpoint(p,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':p,'point':point,'journalVersion':row['version'],'intentHash':authority['phaseIntentHashes'][p],'authorityHash':sha,'sourceClosureHash':'e'*64,'nativeEvidenceHash':'f'*64}
        e=Executor(t,raw,lambda value:value==raw,checkpoint,adapters,intents)
        def cleanup():
            actual=engine.inspect(t)
            if actual is not None:engine.request('DELETE','/v1.44/containers/'+actual['Id']+'?force=true')
        self.addCleanup(cleanup)
        return e,engine,store
    def death_after(self,e,phase,count):
        pid=os.fork()
        if pid==0:
            adapter=e.adapters[phase];original=adapter.apply
            def crash(value):original(value);os._exit(71)
            adapter.apply=crash
            try:e.run(count)
            except BaseException:os._exit(72)
            os._exit(73)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),71)
        self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
        def forbidden(value):raise AssertionError('RUNTIME_EFFECT_REPLAYED')
        e.adapters[phase].apply=forbidden
        e.t=Transition(e.t.journal,e.t.context)
        for adapter in e.adapters.values():
            if hasattr(adapter,'transition'):adapter.transition=e.t
    def test_pause_and_unpause_process_deaths_preserve_one_exact_generation(self):
        e,engine,store=self.fixture();e.run(5)
        cid=engine.inspect(e.t)['Id'];self.death_after(e,'STAGE_PAUSED_REPLACEMENT',6)
        paused=engine.inspect(e.t);self.assertTrue(paused['State']['Paused']);binding=engine.runtime_binding(paused)
        e.run(6);e.run(6);self.assertEqual(engine.runtime_binding(engine.inspect(e.t)),binding)
        e.run(10);self.death_after(e,'START_REPLACEMENT',11)
        e.run(11);e.run(11);actual=engine.inspect(e.t)
        self.assertFalse(actual['State']['Paused']);self.assertEqual(actual['Id'],cid)
        self.assertEqual(engine.runtime_binding(actual),binding)
        self.assertTrue(e.t.read()['applicationWritesMayHaveOccurred']);self.assertTrue(e.t.read()['databaseMayHaveChanged'])
    def test_start_pause_gap_remains_ambiguous_without_pause_or_start_replay(self):
        e,engine,store=self.fixture();e.run(5);original=engine.request;calls=[]
        def fail_pause(method,path,body=None):
            if method=='POST':calls.append(path)
            if path.endswith('/pause'):raise RuntimeError('fixture-death-between-start-and-pause')
            return original(method,path,body)
        engine.request=fail_pause
        with self.assertRaises(RuntimeError):e.run(6)
        self.assertTrue(engine.inspect(e.t)['State']['Running']);self.assertFalse(engine.inspect(e.t)['State']['Paused'])
        with self.assertRaises(CreationDenied):e.run(6)
        self.assertEqual(len(calls),2);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
    def test_corrupted_private_creation_payload_blocks_before_start(self):
        e,engine,store=self.fixture();e.run(5)
        store.path('CREATE_REPLACEMENT').write_bytes(b'{}')
        with self.assertRaises(ValueError):e.run(6)
        self.assertEqual(engine.inspect(e.t)['State']['Status'],'created')

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeRuntime))
    if result.wasSuccessful():print('OUF_RUNTIME_EXECUTOR_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualContainerProcess':True,'actualControllerDeaths':2,'oneGenerationPreserved':True,'startPauseGapReplayDenied':True,'authorityAndOtherPhasesSynthetic':True,'semanticJvmStarted':False,'targetApplied':False,'targetInstallerQualified':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
