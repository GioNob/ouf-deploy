"""Native Unix Engine client; simulated container/process/profile/authority.

These tests exercise the distinct recovery journal binding and refusal paths.
They do not certify a live Docker node or issue target signing authority.
"""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_lifecycle as fixture
from tools.semantic_registry_recovery_execution import core as c,paused_binding as p

class Profile:
    def __init__(self,request):self.request=request
    def verify(self,request):return c.digest(request)

class Binding(unittest.TestCase):
    setUp=fixture.Tests.setUp
    close_server=fixture.Tests.close_server
    claim=fixture.Tests.claim

    def prepare(self):
        for target,value in ((p,'profile_type'),):
            mocked=patch.object(target,value,return_value=Profile);mocked.start();self.addCleanup(mocked.stop)
        for target,value in (('time.time',100),('time.monotonic',50)):
            mocked=patch(target,return_value=value);mocked.start();self.addCleanup(mocked.stop)
        boot=patch.object(p.Path,'read_text',return_value=self.new['bootId']);boot.start();self.addCleanup(boot.stop)
        stage=self.claim('START_NEW_WAIT_GATE');self.native.apply(stage)
        state,proof=self.native.observe(stage);self.assertEqual(state,'APPLIED')
        self.complete(proof)
        self.next_claim();self.complete({'newGeneration':self.new})
        stage=self.next_claim();self.native.apply(stage)
        state,proof=self.native.observe(stage);self.assertEqual(state,'APPLIED');self.complete(proof)
        self.next_claim()
        return p.RecoveryPausedBinding(self.native,Profile(self.request))

    def complete(self,proof):
        row=self.store.read();effects=copy.deepcopy(row['effects'])
        effects[-1].update(state='APPLIED',nativeEvidence=proof,nativeEvidenceHash=c.digest(proof))
        self.store.cas(row,{**row,'effects':effects,'nextStage':row['nextStage']+1,'state':'READY',
            'newGeneration':copy.deepcopy(self.new),'version':row['version']+1})

    def next_claim(self):
        row=self.store.read();stage=self.plan['stages'][row['nextStage']]
        effects=copy.deepcopy(row['effects']);effects.append({'stage':stage['name'],'intentHash':stage['intentHash'],
            'authorityHash':self.authority.hash,'state':'CLAIMED','nativeEvidence':None})
        self.store.cas(row,{**row,'effects':effects,'state':'IN_FLIGHT','version':row['version']+1})
        return stage

    def change(self,edit):
        row=self.store.read();after=copy.deepcopy(row);edit(after);after['version']+=1;self.store.cas(row,after)

    def test_current_native_paused_state_keeps_new_context_and_grants_nothing(self):
        binding=self.prepare();before=len(self.server.calls);report=binding.observe()
        self.assertEqual(report['transitionContextHash'],self.plan['logicalOperationRef'])
        self.assertEqual(report['runtimeBinding']['pid'],self.new['pid'])
        self.assertEqual(report['stageEvidenceHash'],self.store.read()['effects'][3]['nativeEvidenceHash'])
        for name in ('ociAccepted','rootfsAccepted','peerAccepted','startAuthorized'):self.assertFalse(report[name])
        self.assertEqual(report['signaturesIssued'],0)
        self.assertTrue(all(method=='GET' for method,path in self.server.calls[before:]))
        self.assertFalse(hasattr(binding,'transition'))
        proof=binding.verify_runc_state({'id':self.native.cid,'pid':self.new['pid'],'status':'paused'},report)
        self.assertEqual(proof['stateContract'],'RUNC_PAUSED_ENGINE_PAUSED')
        self.assertFalse(proof['completeCreationAccepted'])

    def test_changed_namespace_or_unpaused_gate_is_refused(self):
        binding=self.prepare();original=copy.deepcopy(self.server.actual);fresh=copy.deepcopy(self.new)
        for drift in ('namespace','unpaused','application'):
            self.server.actual=copy.deepcopy(original);self.new.update(fresh);self.server.kind='GATE_WAITING'
            if drift=='namespace':self.new['namespaceInode']+=1
            if drift=='unpaused':self.server.actual['State'].update(Paused=False,Status='running')
            if drift=='application':self.server.kind='APPLICATION_RUNNING'
            with self.assertRaisesRegex(c.RecoveryDenied,'SAME_PAUSED_RECOVERY_GATE'):binding.observe()

    def test_missing_durable_first_start_never_adopts_current_pid(self):
        binding=self.prepare()
        self.change(lambda row:row['effects'][1].pop('nativeFirstProcess'))
        with self.assertRaisesRegex(c.RecoveryDenied,'FIRST_DURABLE'):binding.observe()

    def test_pause_request_without_response_receipt_is_not_accepted(self):
        binding=self.prepare();self.change(lambda row:row['effects'][3].pop('nativeResponse204'))
        with self.assertRaisesRegex(c.RecoveryDenied,'DURABLE_SEPARATE_START_AND_PAUSE'):binding.observe()

    def test_runc_created_state_cannot_replace_paused_state(self):
        binding=self.prepare();report=binding.observe()
        with self.assertRaisesRegex(c.RecoveryDenied,'RUNC_AND_ENGINE_PAUSED'):
            binding.verify_runc_state({'id':self.native.cid,'pid':self.new['pid'],'status':'created'},report)

    def test_revoked_authority_and_expired_window_refuse_observation(self):
        binding=self.prepare();self.auth.current=False
        with self.assertRaisesRegex(c.RecoveryDenied,'CURRENT_DUAL_ROLE'):binding.observe()
        self.auth.current=True
        with patch.object(p.time,'time',return_value=901):
            with self.assertRaisesRegex(c.RecoveryDenied,'CURRENT_FINITE'):binding.observe()

    def test_binding_refuses_stage_after_unpause(self):
        binding=self.prepare()
        self.change(lambda row:row.update(nextStage=8))
        with self.assertRaises(c.RecoveryDenied):binding.observe()

if __name__=='__main__':unittest.main()
