import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from engine_creation import Engine,CreationDenied
from producer_adapter import ProducerAdapter
from executor_composition_fixture import compose
from transition_journal import Transition
from cutover_executor import CutoverDenied

class Producers(unittest.TestCase):
    def fixture(self,count=1):
        states={};calls=[]
        for i in range(count):
            cid=str(i+1)*64
            states[cid]={'Id':cid,'Image':'sha256:'+'a'*64,'Config':{'fixture':i},'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'Mounts':[],'NetworkSettings':{},'RestartCount':0,'State':{'Running':True,'Paused':False,'Status':'running','Pid':100+i,'StartedAt':'2026-10-12T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z','Error':''}}
        engine=Engine.__new__(Engine)
        def request(method,path,body=None):
            cid=path.split('/')[3]
            if method=='GET':return (200,copy.deepcopy(states[cid])) if cid in states else (404,None)
            calls.append(cid);states[cid]['State'].update(Running=False,Status='exited',Pid=0,FinishedAt='2026-10-12T01:00:00Z')
            return 204,None
        engine.request=request
        intent={'producerBindings':[engine.runtime_binding(s) for s in states.values()],'stopTimeoutSeconds':1}
        e,store=compose(self,'QUIESCE_PRODUCERS',intent,lambda t,s:ProducerAdapter(engine,t,intent,s))
        return e,engine,states,calls,intent
    def test_crash_after_stop_reopens_without_retransmission(self):
        e,engine,states,calls,intent=self.fixture();a=e.adapters['QUIESCE_PRODUCERS'];original=a.apply
        def crash(value):original(value);raise RuntimeError('fixture-crash')
        a.apply=crash
        with self.assertRaises(RuntimeError):e.run(2)
        e.t=Transition(e.t.journal,e.t.context);a.transition=e.t
        a.apply=lambda value:self.fail('STOP_REPLAYED')
        e.run(2);e.run(2);self.assertEqual(len(calls),1)
    def test_partial_stop_retains_ambiguity_and_independent_producer(self):
        e,engine,states,calls,intent=self.fixture(2);original=engine.request
        def fail(method,path,body=None):
            if method=='POST' and len(calls)==1:raise RuntimeError('fixture-partial-stop')
            return original(method,path,body)
        engine.request=fail
        with self.assertRaises(RuntimeError):e.run(2)
        with self.assertRaises(CutoverDenied):e.run(2)
        self.assertEqual(len(calls),1);self.assertTrue(states['2'*64]['State']['Running']);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
    def test_restart_policy_or_generation_drift_blocks_entire_scope_before_stop(self):
        for change in ('generation','policy'):
            e,engine,states,calls,intent=self.fixture(2)
            if change=='generation':states['2'*64]['State']['Pid']+=1
            else:states['2'*64]['HostConfig']['RestartPolicy']['Name']='always'
            with self.assertRaises(CreationDenied):e.run(2)
            self.assertEqual(calls,[])
    def test_absent_container_or_changed_stopped_generation_blocks_reconciliation(self):
        for change in ('absent','generation'):
            e,engine,states,calls,intent=self.fixture();a=e.adapters['QUIESCE_PRODUCERS'];original=a.apply
            def crash(value):original(value);raise RuntimeError('fixture-crash')
            a.apply=crash
            with self.assertRaises(RuntimeError):e.run(2)
            if change=='absent':del states['1'*64]
            else:states['1'*64]['State']['StartedAt']='2026-10-12T02:00:00Z'
            with self.assertRaises((CutoverDenied,CreationDenied)):e.run(2)
            self.assertEqual(len(calls),1);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')

if __name__=='__main__':unittest.main()
