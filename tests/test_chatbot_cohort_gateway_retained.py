"""Completed post-Gateway attempt must be frozen before a fresh finite decision."""
import copy,json,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
import test_chatbot_cohort_assemble as bootstrap
from tools.chatbot_file_cohort import gateway_retained as r,gateway_recovery as base,postgrant_recovery
from tools.chatbot_file_cohort.gateway_runtime import STEPS,PROFILE
from tools.chatbot_file_cohort.plan import digest,encoded

class RetainedAttempt(unittest.TestCase):
    def fixture(self):
        tmp=tempfile.TemporaryDirectory(dir=bootstrap.ROOT);self.addCleanup(tmp.cleanup)
        parent=Path(tmp.name);parent.chmod(0o700);root=parent/'attempt';root.mkdir(mode=0o700)
        def write(path,value):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(encoded(value));path.chmod(0o600);return digest(value)
        plan={'runtimeBindingProfile':'ouf.apisix-runtime-binding.mount-set.v1'}
        prepared={'postGrantRecovery':{'profile':base.PROFILE},'gatewayRuntimePlan':plan,'gatewayPlan':{'syntheticRemaining':28},
            'authorization':{'plan':{}},'databasePlan':{'retainedDatabasePlan':True},'cohortPlan':{'replacements':[]},
            'postGrantWorkerDirectory':str(root/'owner')}
        bundle={'declaration':{'sourceCommit':r.SOURCE},'prepared':prepared};bh=write(root/'child-bundle.json',bundle)
        dirs={name:str(root/name)for name in ('authorization','gatewayRuntime','containers','databases','gateway')}
        process={'authorityDirectory':str(root),'bundle':{'path':str(root/'child-bundle.json'),'sha256':bh},'directoryPlan':dirs}
        scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')},
            'gatewayRuntimeInstallation':{'planHash':digest(plan)}}
        authority={**scopes,'expiresAt':1792135583};ah=write(root/'authority.json',authority)
        review={'sourceClosure':{'declaration':bundle['declaration'],'executables':{'systemctl':{}}},
            'sourceClosureHash':'c'*64,'scopes':scopes,'privateInputHashes':{'preparedInputs':digest(prepared)}}
        rh=write(root/'review.json',review)
        write(root/'decision.json',{'state':'ACTIVE','approvedReviewHash':rh,'approvedSourceClosureHash':'c'*64,
            'expiresAt':authority['expiresAt']})
        status={'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'AuthorizationPaused'}
        sh=write(root/'delivery-status.json',status)
        auth={'authorityHash':ah,'planHash':digest({}),'effects':{},'budgetReset':False}
        authh=write(root/'authorization/recovery.json',auth)
        pin={'containerId':'a'*64,'imageId':'sha256:'+'b'*64,'pid':123,'startedAt':'synthetic',
            **{k:'c'*64 for k in ('configHash','hostConfigHash','mountsHash','networkSettingsHash')}}
        effects=[{'step':step,'state':'APPLIED','intentHash':digest({'planHash':digest(plan),'step':step}),
            'evidence':{'containerId':pin['containerId'],'runtimeBinding':pin}}for step in STEPS]
        row={'schema':PROFILE,'planHash':digest(plan),'authorityHash':ah,'budgetReset':False,
            'nextStep':8,'effects':effects,'version':18}
        runtimeh=write(root/'gatewayRuntime/recovery.json',row)
        write(parent/base.CLAIM,{'schema':base.PROFILE,'authorityHash':ah,'proofHash':digest(prepared['postGrantRecovery']),
            'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY','priorControlledGrantAttempts':8})
        stack=self.enterContext(ExitStack())
        for name,value in [('CONTEXT','attempt'),('REVIEW',rh),('AUTHORITY',ah),('STATUS',sh),
            ('AUTHORIZATION',authh),('RUNTIME',runtimeh),('NATIVE',digest(pin))]:stack.enter_context(patch.object(r,name,value))
        stack.enter_context(patch.object(r.evidence,'PARENT',parent))
        stack.enter_context(patch.object(postgrant_recovery,'stopped_process'))
        previous={'recordBindings':[],'prepared':{'databasePlan':prepared['databasePlan'],'cohortPlan':prepared['cohortPlan']}}
        self.root,self.row,self.plan,self.previous=root,row,plan,previous
        self.write=write
        return previous
    def test_current_attempt_augments_original_history_and_uses_distinct_claim(self):
        previous=self.fixture();original=copy.deepcopy(previous);result=r.enrich(previous)
        self.assertEqual(previous,original);self.assertEqual(result['prepared'],original['prepared'])
        receipt=result['retainedGatewayAttempt']['receipt']
        proof={'retainedNumericGateway':receipt};r.validate_proof(proof)
        self.assertEqual(base.claim_for(proof),r.CLAIM);self.assertNotEqual(base.claim_for(proof),base.CLAIM)
        self.assertEqual(base.claim_for({}),base.CLAIM)
        self.assertEqual(receipt['historicalEffects'],8);self.assertFalse(receipt['newLifecycleEffectsAllowed'])
        for binding in result['recordBindings']:
            from tools.chatbot_file_cohort.action_process import private_file
            private_file(binding,8388608)
    def test_unexpected_worker_or_downstream_journal_blocks_adoption(self):
        previous=self.fixture()
        self.write(self.root/'owner/recovery.json',{})
        with self.assertRaisesRegex(Exception,'UNEXPECTED_POST_GATEWAY_WORKER'):r.enrich(previous)
        (self.root/'owner/recovery.json').unlink()
        self.write(self.root/'databases/recovery.json',{})
        with self.assertRaisesRegex(Exception,'UNEXPECTED_POST_GATEWAY_APPLICATION'):r.enrich(previous)
    def test_changed_effect_and_lifecycle_permission_are_rejected(self):
        self.fixture();row=copy.deepcopy(self.row);row['effects'][6]['state']='CLAIMED'
        with self.assertRaises(Exception):r.validate_runtime(self.plan,row)
        receipt=r.enrich(self.previous)['retainedGatewayAttempt']['receipt'];receipt['newLifecycleEffectsAllowed']=True
        with self.assertRaisesRegex(Exception,'EXACT_RETAINED'):base.claim_for({'retainedNumericGateway':receipt})

if __name__=='__main__':unittest.main()
