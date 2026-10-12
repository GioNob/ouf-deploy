"""Native inventoried quiescence: real controller death, partial stop, drift.
Authority, prior lease phase and writer inventory are synthetic, not target.
"""
import os,sys,uuid,unittest,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from native_runtime_executor import NativeRuntime
from engine_creation import CreationDenied
from producer_adapter import ProducerAdapter
from executor_composition_fixture import compose
from cutover_executor import CutoverDenied

class NativeProducers(NativeRuntime):
    def producers(self,count):
        _,engine,_=self.fixture();bindings=[]
        for _ in range(count):
            request={'Image':self.image,'Cmd':['sleep','600'],'HostConfig':{'NetworkMode':'none','RestartPolicy':{'Name':'no','MaximumRetryCount':0}}}
            status,result=engine.request('POST','/v1.44/containers/create?name=ouf-producer-fixture-'+uuid.uuid4().hex,request);self.assertEqual(status,201);cid=result['Id']
            self.addCleanup(lambda cid=cid:engine.request('DELETE','/v1.44/containers/'+cid+'?force=true'))
            self.assertEqual(engine.request('POST','/v1.44/containers/'+cid+'/start')[0],204)
            bindings.append(engine.runtime_binding(engine.request('GET','/v1.44/containers/'+cid+'/json')[1]))
        intent={'producerBindings':bindings,'stopTimeoutSeconds':1}
        e,store=compose(self,'QUIESCE_PRODUCERS',intent,lambda t,s:ProducerAdapter(engine,t,intent,s))
        return e,engine,bindings
    def test_controller_death_after_real_stop_reconciles_without_another_stop(self):
        e,engine,pins=self.producers(1);self.death_after(e,'QUIESCE_PRODUCERS',2)
        e.run(2);e.run(2);self.assertEqual(e.t.read()['nextPhase'],2)
        actual=engine.request('GET','/v1.44/containers/'+pins[0]['containerId']+'/json')[1]
        self.assertFalse(actual['State']['Running']);self.assertEqual(actual['State']['StartedAt'],pins[0]['startedAt'])
    def test_partial_native_stop_is_not_replayed_and_other_scope_stays_live(self):
        e,engine,pins=self.producers(2);original=engine.request;stops=[]
        def interrupt(method,path,body=None):
            if method=='POST' and '/stop?' in path:
                if stops:raise RuntimeError('fixture-controller-death-between-producers')
                stops.append(path)
            return original(method,path,body)
        engine.request=interrupt
        with self.assertRaises(RuntimeError):e.run(2)
        with self.assertRaises(CutoverDenied):e.run(2)
        self.assertEqual(len(stops),1)
        self.assertTrue(engine.request('GET','/v1.44/containers/'+pins[1]['containerId']+'/json')[1]['State']['Running'])
    def test_actual_recreated_process_generation_blocks_before_stop(self):
        e,engine,pins=self.producers(1);cid=pins[0]['containerId']
        self.assertEqual(engine.request('POST','/v1.44/containers/'+cid+'/restart?t=1')[0],204)
        with self.assertRaises(CreationDenied):e.run(2)
        self.assertTrue(engine.request('GET','/v1.44/containers/'+cid+'/json')[1]['State']['Running'])

if __name__=='__main__':
    names=[n for n in NativeProducers.__dict__ if n.startswith('test_')]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(NativeProducers(n) for n in names))
    if result.wasSuccessful():print('OUF_PRODUCER_EXECUTOR_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualContainerStop':True,'actualControllerProcessDeath':True,'partialStopReplayDenied':True,'independentScopePreserved':True,'staleProcessGenerationDenied':True,'authorityAndLeaseAndWriterInventorySynthetic':True,'targetApplied':False,'targetInstallerQualified':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
