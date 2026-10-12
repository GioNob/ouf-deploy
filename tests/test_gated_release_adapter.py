"""Synthetic authority/native process boundary tests; no target/JVM proof."""
import copy,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from engine_creation import Engine
from gated_release_adapter import GatedReleaseAdapter
from gated_process_observation import GatedProcessObservation
from gated_creation_plan import ENTRY,PROFILE
from native_evidence_store import NativeEvidenceStore
from executor_composition_fixture import compose
from transition_journal import digest,Transition
from cutover_executor import CutoverDenied

class Release(unittest.TestCase):
    def fixture(self):
        request={'Image':'sha256:'+'a'*64,'User':'10001:10001','Entrypoint':ENTRY,'Cmd':['fixture-application']}
        state={'Id':'1'*64,'Image':request['Image'],'Config':request,'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'Mounts':[],'NetworkSettings':{},'RestartCount':0,'State':{'Running':True,'Paused':True,'Status':'paused','Pid':1234,'StartedAt':'fixture-only'}}
        engine=Engine.__new__(Engine);engine.inspect=lambda _:copy.deepcopy(state);calls=[];kind=['GATE_WAITING']
        process=GatedProcessObservation.__new__(GatedProcessObservation)
        process.observe=lambda _: {'generation':{'pid':1234,'startTicks':12,'namespaceInode':13},'processKind':kind[0],'nonRootIdentityVerified':True,'capabilitiesEmpty':True,'noNewPrivileges':True}
        def request_native(method,path,body=None):
            calls.append(path)
            if path.endswith('/unpause'):state['State'].update(Paused=False,Status='running')
            if path.endswith('/kill?signal=SIGUSR1'):kind[0]='APPLICATION_RUNNING'
            return 204,None
        engine.request=request_native
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700);before=NativeEvidenceStore(root)
        intent={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT','preApplicationGateProfile':PROFILE}
        def stage(t,s):
            def observe(value):s.publish('STAGE_PAUSED_REPLACEMENT',copy.deepcopy(state));return 'APPLIED',copy.deepcopy(state)
            return types.SimpleNamespace(apply=lambda value:None,observe=observe)
        e,store=compose(self,'START_REPLACEMENT',intent,lambda t,s:GatedReleaseAdapter(engine,t,request,s,before,process,lambda point:None),
                        additional={'STAGE_PAUSED_REPLACEMENT':({'fixtureOnly':True},stage)},creation_request=request)
        return e,engine,state,kind,calls,process
    def test_unpause_signal_and_same_generation_release_are_one_use(self):
        e,engine,state,kind,calls,process=self.fixture();e.run(11);e.run(11)
        self.assertEqual(len(calls),2);self.assertTrue(e.t.read()['applicationWritesMayHaveOccurred']);self.assertTrue(e.t.read()['databaseMayHaveChanged'])
    def test_unpause_signal_gap_remains_ambiguous_without_retransmission(self):
        e,engine,state,kind,calls,process=self.fixture();original=engine.request
        def request(method,path,body=None):
            if path.endswith('/kill?signal=SIGUSR1'):raise RuntimeError('fixture-gap')
            return original(method,path,body)
        engine.request=request
        with self.assertRaises(RuntimeError):e.run(11)
        with self.assertRaises(CutoverDenied):e.run(11)
        self.assertEqual(len(calls),1);self.assertEqual(kind[0],'GATE_WAITING');self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
    def test_death_after_signal_reconciles_without_second_signal(self):
        e,engine,state,kind,calls,process=self.fixture();original=engine.request
        def request(method,path,body=None):
            result=original(method,path,body)
            if path.endswith('/kill?signal=SIGUSR1'):raise RuntimeError('fixture-death-after-signal')
            return result
        engine.request=request
        with self.assertRaises(RuntimeError):e.run(11)
        e.t=Transition(e.t.journal,e.t.context)
        for a in e.adapters.values():
            if hasattr(a,'transition'):a.transition=e.t
        engine.request=lambda *args:self.fail('SIGNAL_OR_UNPAUSE_REPLAYED')
        e.run(11);self.assertEqual(len(calls),2)
    def test_revocation_after_unpause_denies_signal_and_keeps_gate_stopped(self):
        e,engine,state,kind,calls,process=self.fixture()
        def checkpoint(point):
            if point=='BEFORE_PREAPPLICATION_SIGUSR1':raise ValueError('CURRENT_AUTHORITY_REVOKED')
        e.adapters['START_REPLACEMENT'].checkpoint=checkpoint
        with self.assertRaises(ValueError):e.run(11)
        self.assertEqual(len(calls),1);self.assertEqual(kind[0],'GATE_WAITING')

if __name__=='__main__':unittest.main()
