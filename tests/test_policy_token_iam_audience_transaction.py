"""Actual current dual-role crypto, persistent one-effect/no-replay protocol."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner')]
import test_cutover_authority_native as signed_fixture
encoded,sha=signed_fixture.encoded,signed_fixture.sha
import tools
tools.__path__.append(str(ROOT/'tools'))
import iam_binding_candidate as binding
import iam_audience_transaction as transaction
from test_policy_token_introspection_audience_plan import inputs,planner

class AudienceTransactionTest(unittest.TestCase):
    def fixture(self):
        signed=signed_fixture.SignedCutover();signed.setUp();self.addCleanup(signed.doCleanups)
        data=inputs();plan,_=planner.compile_plan(*data);digest=sha(encoded(plan))
        raw=json.loads(signed.authority)
        change=plan['changeProposal'];raw['policyTokenIamPreparation']={'reviewPlanHash':digest,'resource':change['resource'],
            'mapperHash':sha(encoded(change['proposedMapper'])),'operation':'ADD_EXACT_CALLER_AUDIENCE_MAPPER',
            'maximumIamMutations':1,'introspectionCheckMustRemainEnabled':True,'runtimeAuthorityIssued':False}
        raw['policyTokenIamFreshReconciliation']={'reviewPlanHash':digest,'observedClientMapperSetHash':sha(encoded([])),
            'metadataAndCoreDriftChecked':True,'callerAudienceReconciled':True}
        signed.authority=encoded(raw);signed.approval['executionAuthorityHash']=sha(signed.authority)
        signed.write(signed.mandate,encoded(signed.approval));signed.approved=sha(signed.mandate.read_bytes())
        for role in signed.grant['roles']:signed.sign(role)
        operation=transaction.AudienceTransaction(plan,digest,data[0],signed.gate(),signed.authority)
        return signed,operation
    def test_one_actual_signed_scope_effect_and_completed_reconciliation_never_reposts(self):
        signed,op=self.fixture();models=[];calls=[]
        def create(body):
            calls.append(body);model=copy.deepcopy(body);model['id']='22222222-2222-2222-2222-222222222222'
            model['config']['userinfo.token.claim']='false';models.append(model)
        with patch.object(binding,'PARENT',signed.root),patch.object(transaction.MapperAdmin,'models',side_effect=lambda:copy.deepcopy(models)), \
                patch.object(transaction.MapperAdmin,'baseline',side_effect=lambda s:copy.deepcopy(s)),patch.object(transaction.MapperAdmin,'create',side_effect=create):
            first=op.run();second=op.run()
        self.assertEqual(len(calls),1);self.assertEqual(first['iamMutations'],1);self.assertEqual(second['iamMutations'],0)
        self.assertFalse(first['runtimeAuthorityIssued']);self.assertFalse(first['budgetReset'])
        row=binding.decode((signed.root/('policy-token-iam-transaction-'+op.operation+'.private.json')).read_bytes())
        self.assertTrue(row['postConsumed']);self.assertEqual(row['state'],'APPLIED_RECONCILED')
        self.assertEqual(row['realizedMapperId'],'22222222-2222-2222-2222-222222222222')
        models[0]['id']='33333333-3333-3333-3333-333333333333'
        with patch.object(binding,'PARENT',signed.root),patch.object(transaction.MapperAdmin,'models',return_value=models):
            with self.assertRaisesRegex(binding.CandidateDenied,'REGISTERED_MAPPER_ID_DRIFT'):op.run()
            models[0]['id']='22222222-2222-2222-2222-222222222222'
            with self.assertRaisesRegex(binding.CandidateDenied,'BLOCKED_IAM'):op.run()
    def test_ambiguous_provider_effect_reconciles_and_missing_effect_cannot_repeat(self):
        for applied in (True,False):
            signed,op=self.fixture();models=[];calls=[]
            def create(body):
                calls.append(body)
                if applied:models.append(copy.deepcopy(body))
                raise TimeoutError('FIXTURE_AMBIGUOUS_EFFECT')
            with patch.object(binding,'PARENT',signed.root),patch.object(transaction.MapperAdmin,'models',side_effect=lambda:copy.deepcopy(models)), \
                    patch.object(transaction.MapperAdmin,'baseline',side_effect=lambda s:copy.deepcopy(s)),patch.object(transaction.MapperAdmin,'create',side_effect=create):
                with self.assertRaises(TimeoutError):op.run()
                if applied:self.assertEqual(op.run()['state'],'APPLIED_RECONCILED')
                else:
                    with self.assertRaisesRegex(binding.CandidateDenied,'CONSUMED_IAM'):op.run()
            self.assertEqual(len(calls),1)
    def test_missing_current_human_role_signature_scope_or_noop_denies_before_iam(self):
        for case in ('human','signature','scope'):
            signed,op=self.fixture()
            if case=='human':signed.approval['state']='REVOKED';signed.write(signed.mandate,encoded(signed.approval))
            if case=='signature':(signed.signatures/(sha(signed.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
            if case=='scope':op.raw=encoded({k:v for k,v in json.loads(op.raw).items() if k!='policyTokenIamPreparation'})
            with patch.object(binding,'PARENT',signed.root),patch.object(transaction.MapperAdmin,'models')as read:
                with self.assertRaises(Exception):op.run()
                self.assertFalse(read.called)
        with self.assertRaises(binding.CandidateDenied):transaction.AudienceTransaction({},'a'*64,{},lambda raw:True,b'{}')
    def test_current_core_drift_blocks_durably_before_post_and_cannot_resume_when_restored(self):
        signed,op=self.fixture();changed=copy.deepcopy(op.snapshot);changed['client']['clientId']='OTHER_CLIENT'
        with patch.object(binding,'PARENT',signed.root),patch.object(transaction.MapperAdmin,'models',return_value=[]), \
                patch.object(transaction.MapperAdmin,'baseline',return_value=changed),patch.object(transaction.MapperAdmin,'create')as create:
            with self.assertRaisesRegex(binding.CandidateDenied,'BASELINE_DRIFT'):op.run()
            self.assertFalse(create.called)
            with patch.object(transaction.MapperAdmin,'baseline',return_value=op.snapshot):
                with self.assertRaisesRegex(binding.CandidateDenied,'BLOCKED_IAM'):op.run()
            self.assertFalse(create.called)
    def test_late_revocation_after_effect_keeps_consumed_marker_and_cannot_restore_approval(self):
        signed,op=self.fixture();models=[]
        def create(body):
            models.append(copy.deepcopy(body));signed.approval['state']='REVOKED';signed.write(signed.mandate,encoded(signed.approval))
        with patch.object(binding,'PARENT',signed.root),patch.object(transaction.MapperAdmin,'models',side_effect=lambda:models), \
                patch.object(transaction.MapperAdmin,'baseline',side_effect=lambda s:copy.deepcopy(s)),patch.object(transaction.MapperAdmin,'create',side_effect=create):
            with self.assertRaises(Exception):op.run()
        row=binding.decode((signed.root/('policy-token-iam-transaction-'+op.operation+'.private.json')).read_bytes())
        self.assertTrue(row['postConsumed']);self.assertEqual(row['state'],'RECONCILE_REQUIRED')
    def test_nested_in_memory_intent_tamper_is_denied_before_provider(self):
        signed,op=self.fixture();op.desired['config']['included.client.audience']='OTHER_CLIENT'
        with patch.object(transaction.MapperAdmin,'models')as read:
            with self.assertRaisesRegex(binding.CandidateDenied,'IN_MEMORY'):op.run()
        self.assertFalse(read.called)
    def test_effective_userinfo_false_only_and_no_unknown_or_expanded_channels(self):
        signed,op=self.fixture();desired=op.desired
        normalized=copy.deepcopy(desired);normalized['config']['userinfo.token.claim']='false'
        self.assertTrue(transaction.equivalent(normalized,desired))
        for key,value in (('userinfo.token.claim','true'),('userinfo.token.claim',False),
                          ('lightweight.claim','true'),('included.custom.audience','OTHER'),('unknown','false')):
            changed=copy.deepcopy(normalized);changed['config'][key]=value
            self.assertFalse(transaction.equivalent(changed,desired))

if __name__=='__main__':unittest.main()
