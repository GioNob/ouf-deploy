"""Actual preapplication SIGSTOP/pause/unpause/SIGUSR1 + controller death.
Disposable sleep image; original V11 JVM/complete node/authority not qualified.
"""
import json,os,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from engine_creation import Engine
from creation_adapter import CreationAdapter
from gated_stage_adapter import GatedStageAdapter
from gated_creation_plan import ENTRY,PROFILE
from gated_process_observation import GatedProcessObservation
from gated_release_adapter import GatedReleaseAdapter
from native_evidence_store import NativeEvidenceStore
from transition_journal import digest,Transition
from executor_composition_fixture import compose
from cutover_executor import CutoverDenied

class NativeGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['docker','pull','alpine:3.21'],check=True,stdout=subprocess.DEVNULL,timeout=90)
        cls.image=subprocess.check_output(['docker','image','inspect','alpine:3.21','--format','{{.Id}}'],timeout=15).decode().strip()
    def fixture(self):
        self.assertEqual(os.geteuid(),0)
        socket='/var/run/docker.sock';s=os.stat(socket,follow_symlinks=False);engine=Engine(socket,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
        request={'Image':self.image,'User':'10001:10001','Entrypoint':ENTRY,'Cmd':['sleep','600'],'HostConfig':{'NetworkMode':'none','CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],'RestartPolicy':{'Name':'no','MaximumRetryCount':0}}}
        process=GatedProcessObservation(request);temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700);before=NativeEvidenceStore(root)
        intent={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT','preApplicationGateProfile':PROFILE}
        e,store=compose(self,'START_REPLACEMENT',intent,lambda t,s:GatedReleaseAdapter(engine,t,request,s,before,process,lambda point:None),
                        additional={'CREATE_REPLACEMENT':(request,lambda t,s:CreationAdapter(engine,t,request,s)),
                                    'STAGE_PAUSED_REPLACEMENT':({'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'},lambda t,s:GatedStageAdapter(engine,t,request,s,process,lambda point:None))},creation_request=request)
        def cleanup():
            actual=engine.inspect(e.t)
            if actual is not None:engine.request('DELETE','/v1.44/containers/'+actual['Id']+'?force=true')
        self.addCleanup(cleanup);return e,engine,process
    def reconcile(self,e,count):
        deadline=time.monotonic()+5
        while True:
            try:return e.run(count)
            except CutoverDenied:
                if e.t.read()['state']!='IN_FLIGHT' or time.monotonic()>deadline:raise
                time.sleep(.05)
    def test_real_gate_stops_before_application_then_releases_same_hardened_generation(self):
        e,engine,process=self.fixture();e.run(6);actual=engine.inspect(e.t);before=process.observe(actual['State']['Pid'])
        self.assertEqual(before['processKind'],'GATE_WAITING');self.assertTrue(before['capabilitiesEmpty']);self.assertTrue(before['noNewPrivileges'])
        self.reconcile(e,11);after=process.observe(actual['State']['Pid']);self.assertEqual(after['generation'],before['generation']);self.assertEqual(after['processKind'],'APPLICATION_RUNNING')
        engine.request_original=engine.request
        def forbidden(method,path,body=None):
            if method=='POST':self.fail('GATE_MUTATION_REPLAYED')
            return engine.request_original(method,path,body)
        engine.request=forbidden;e.run(11)
    def test_actual_controller_death_after_sigcont_reconciles_without_signal_replay(self):
        e,engine,process=self.fixture();e.run(10);adapter=e.adapters['START_REPLACEMENT'];original=adapter.apply
        def die(value):original(value);os._exit(71)
        adapter.apply=die;pid=os.fork()
        if pid==0:
            try:e.run(11)
            except BaseException:os._exit(72)
            os._exit(73)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),71);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
        e.t=Transition(e.t.journal,e.t.context)
        for a in e.adapters.values():
            if hasattr(a,'transition'):a.transition=e.t
        adapter.apply=lambda _:self.fail('GATE_SIGNAL_REPLAYED');self.reconcile(e,11)
    def test_native_unpause_signal_gap_retains_stopped_gate_and_ambiguity(self):
        e,engine,process=self.fixture();e.run(10);original=engine.request;mutations=[]
        def request(method,path,body=None):
            if method=='POST' and path.endswith('/kill?signal=SIGUSR1'):raise RuntimeError('native-gap')
            if method=='POST':mutations.append(path)
            return original(method,path,body)
        engine.request=request
        with self.assertRaises(RuntimeError):e.run(11)
        with self.assertRaises(CutoverDenied):e.run(11)
        actual=engine.inspect(e.t);self.assertFalse(actual['State']['Paused']);self.assertEqual(process.observe(actual['State']['Pid'])['processKind'],'GATE_WAITING')
        self.assertEqual(len(mutations),1);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')

if __name__=='__main__':unittest.main()
