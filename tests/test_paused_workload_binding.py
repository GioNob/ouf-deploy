"""Native-state binding boundary; no accepted OCI or fixture authority claim."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from engine_creation import Engine
from paused_workload_binding import PausedWorkloadBinding
from transition_journal import digest
from file_only_profile import PHASES

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

    def retained_fixture(self,cursor=7):
        b,state,row=self.fixture();stage=copy.deepcopy(row['effects'][0]);intent='a'*64;authority='b'*64
        receipt={'schema':'ouf.semantic-owner-signed-paused-node-phase.v1','transitionContextHash':b.transition.context,
            'creationRequestHash':b.request_hash,'intentHash':intent,'completeNativeObservationPerformed':True,
            'currentScopedAcceptanceSignatureVerified':True}
        row.update(nextPhase=cursor,version=2*cursor+1,effects=[{'phase':p,'state':'APPLIED','intentHash':str(i+1)*64,
            'authorityEvidenceHash':authority,'nativeEvidenceHash':'e'*64}for i,p in enumerate(PHASES[:cursor])]+
            [{'phase':PHASES[cursor],'state':'IN_FLIGHT','intentHash':'f'*64,'authorityEvidenceHash':authority}])
        row['effects'][5]=stage;row['effects'][6].update(intentHash=intent,nativeEvidenceHash=digest(receipt))
        def read(phase,h):
            value=copy.deepcopy(state if phase=='STAGE_PAUSED_REPLACEMENT'else receipt)
            if digest(value)!=h:raise ValueError('NATIVE_EVIDENCE_HASH_MISMATCH')
            return value
        b.store.read=read
        return b,state,row,receipt,intent
    def retained(self,b,row,intent):
        return PausedWorkloadBinding.retained_at_checkpoint(b.engine,b.transition,{'Image':'sha256:'+'a'*64},b.store,
            attestation_intent_hash=intent,checkpoint_row=copy.deepcopy(row))
    def test_retained_before_migration_and_before_unpause_keep_native_checks_and_no_authority(self):
        for cursor in(7,8):
            b,state,row,receipt,intent=self.retained_fixture(cursor)
            with self.assertRaisesRegex(ValueError,'CURRENT_ATTESTATION_PHASE'):b.observe()
            retained=self.retained(b,row,intent);observed=retained.observe()
            self.assertFalse(observed['startAuthorized']);self.assertEqual(observed['signaturesIssued'],0)
            self.assertFalse(retained.verify_runc_state({'id':'1'*64,'pid':1234,'status':'paused'},observed)['completeCreationAccepted'])
            state['State'].update(Paused=False,Status='running')
            with self.assertRaises(ValueError):retained.observe()
    def test_retained_mode_rejects_unsigned_receipt_wrong_intent_scope_or_phase(self):
        for drift in('phase','pending','intent','authority','request','receipt','prefix','snapshot'):
            b,state,row,receipt,intent=self.retained_fixture()
            if drift=='phase':row['nextPhase']=9
            if drift=='pending':row['effects'][6]['state']='IN_FLIGHT'
            if drift=='intent':intent='c'*64
            if drift=='authority':row['effects'][-1]['authorityEvidenceHash']='c'*64
            if drift=='request':row['creationRequestHash']='c'*64
            if drift=='receipt':receipt['currentScopedAcceptanceSignatureVerified']=False;row['effects'][6]['nativeEvidenceHash']=digest(receipt)
            if drift=='prefix':row['effects'][2]['state']='IN_FLIGHT'
            if drift=='snapshot':
                snapshot=copy.deepcopy(row);row['version']+=1
                with self.assertRaises(ValueError):PausedWorkloadBinding.retained_at_checkpoint(b.engine,b.transition,{'Image':'sha256:'+'a'*64},b.store,attestation_intent_hash=intent,checkpoint_row=snapshot)
                continue
            with self.subTest(drift=drift),self.assertRaises(ValueError):self.retained(b,row,intent)
    def test_retained_observation_denies_mid_read_journal_or_receipt_change(self):
        for drift in('journal','receipt','generation'):
            b,state,row,receipt,intent=self.retained_fixture();retained=self.retained(b,row,intent)
            original=b.engine.inspect;calls=[]
            def inspect(t):
                value=original(t);calls.append(1)
                if len(calls)==1:
                    if drift=='journal':row['version']+=1
                    if drift=='receipt':receipt['intentHash']='c'*64
                    if drift=='generation':state['State']['StartedAt']='changed'
                return value
            b.engine.inspect=inspect
            with self.subTest(drift=drift),self.assertRaises(ValueError):retained.observe()

if __name__=='__main__':unittest.main()
