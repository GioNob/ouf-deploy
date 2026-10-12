"""Native-state binding boundary; no accepted OCI or fixture authority claim."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from engine_creation import Engine
from paused_workload_binding import PausedWorkloadBinding
from transition_journal import digest

class Binding(unittest.TestCase):
    def fixture(self):
        request={'Image':'sha256:'+'a'*64}
        state={'Id':'1'*64,'Image':request['Image'],'Config':{},'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'Mounts':[],'NetworkSettings':{},'RestartCount':0,'State':{'Running':True,'Paused':True,'Status':'paused','Pid':1234,'StartedAt':'fixture-only'}}
        engine=Engine.__new__(Engine);engine.inspect=lambda t:copy.deepcopy(state)
        row={'state':'IN_FLIGHT','creationRequestHash':digest(request),'effects':[{'phase':'STAGE_PAUSED_REPLACEMENT','state':'APPLIED','nativeEvidenceHash':digest(state)},{'phase':'ATTEST_NEW_OCI_PEER','state':'IN_FLIGHT'}]}
        import types
        t=types.SimpleNamespace(context='c'*64,read=lambda:row)
        store=types.SimpleNamespace(read=lambda phase,h:copy.deepcopy(original))
        original=copy.deepcopy(state)
        return PausedWorkloadBinding(engine,t,request,store),state,row
    def test_native_state_is_kept_paused_and_observation_grants_no_acceptance(self):
        b,state,row=self.fixture();v=b.observe();proof=b.verify_runc_state({'id':'1'*64,'pid':1234,'status':'paused'},v)
        self.assertEqual(proof['stateContract'],'RUNC_PAUSED_ENGINE_PAUSED');self.assertFalse(proof['completeCreationAccepted'])
        self.assertFalse(v['ociAccepted']);self.assertFalse(v['rootfsAccepted']);self.assertFalse(v['peerAccepted'])
    def test_unpause_restart_or_changed_generation_denies_attestation_binding(self):
        for drift in ('unpause','restart','generation','image','policy'):
            b,state,row=self.fixture()
            if drift=='unpause':state['State'].update(Paused=False,Status='running')
            if drift=='restart':state['RestartCount']=1
            if drift=='generation':state['State']['StartedAt']='changed'
            if drift=='image':state['Image']='sha256:'+'b'*64
            if drift=='policy':state['HostConfig']['RestartPolicy']['Name']='unless-stopped'
            with self.assertRaises(ValueError):b.observe()
    def test_stale_observation_wrong_phase_or_native_created_status_denies(self):
        b,state,row=self.fixture();v=b.observe()
        with self.assertRaises(ValueError):b.verify_runc_state({'id':'1'*64,'pid':1234,'status':'created'},v)
        with self.assertRaises(ValueError):b.verify_runc_state({'id':'1'*64,'pid':1234,'status':'running'},v)
        with self.assertRaises(ValueError):b.verify_runc_state({'id':'1'*64,'pid':1235,'status':'paused'},v)
        state['State']['Paused']=False
        with self.assertRaises(ValueError):b.verify_runc_state({'id':'1'*64,'pid':1234,'status':'paused'},v)
        b,state,row=self.fixture();row['effects'][-1]['phase']='ADMIT_MIGRATION'
        with self.assertRaises(ValueError):b.observe()

if __name__=='__main__':unittest.main()
