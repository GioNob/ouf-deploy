"""New exact scope and real two-role issuance with disposable fixture keys.

Qualification receipts and HUMAN sessions here are synthetic unit inputs, never
target authority or a claim that representative qualification has completed.
"""
import copy
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_execution as core
import test_ingestion_rollout_native_review as fixture
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_rollout_execution import authority as a,contract as c
from tools.chatbot_file_cohort.human_session import HumanSession

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root fixture keys and role signatures required')
class NativeIssuer(unittest.TestCase):
    def setUp(self):
        core.SignedFiniteRunner.setUp(self);q=self.crypto
        self.fixture=fixture.NativeReview();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        native=self.fixture.compile();native['executionContext']=str(self.context)
        self.closure={'declaration':{'entryModule':'tools.ingestion_rollout_execution.entry',
            'sourceCommit':'1'*40,'sourceHashes':{'fixture.only':'a'*64},'requiredPythonFlags':['-I','-B','-S'],
            'runtimeAuthorityIssued':False},'executables':{
                'python':copy.deepcopy(native['ownerControlProfile']['pythonExecutable']),
                'docker':copy.deepcopy(native['databaseControlProfile']['dockerExecutable']),
                'openssl':copy.deepcopy(q.verifier.openssl_binding)},'stdlibHash':'b'*64,'stdlibFileCount':1}
        installed={'schema':'ouf.semantic-existing-installation-authority-bindings.v1',
            'authorities':q.context,'policyBinding':q.binding(q.policy),
            'keyRefs':{'installer':q.grant['keyRef'],'attestor':'synthetic-fixture-attestor-key'},
            'keyBindings':{'installer':q.binding(q.key),'attestor':q.binding(q.key)}}
        path=q.root/'existing-installation-profile.json';q.write(path,c.encoded(installed))
        self.issuer={'schema':'ouf.ingestion-rollout-existing-issuer-profile.v1',
            'installationAuthority':binding(path),'policy':binding(q.policy),'authorityContext':q.context}
        self.qualification={'schema':'ouf.ingestion-rollout-native-qualification.v1',
            'sourceCommit':'1'*40,'sourceHashes':self.closure['declaration']['sourceHashes'],
            'candidateNativeImageId':self.fixture.packet['candidate']['nativeImageId'],'candidateSourceCommit':'1'*40,
            'results':dict.fromkeys(a.QUALIFICATION,'PASS'),'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,
            'evidenceRefs':{k:{'repository':'synthetic/fixture-only','runId':1,'jobId':1,'sourceCommit':'1'*40}for k in a.QUALIFICATION}}
        self.native_review=native;self.review=self.compile()
        self.human=HumanSession.__new__(HumanSession)
        self.human.current=lambda:self.review['authenticatedHuman'];self.human.expires_at=int(time.time())+500
        now=int(time.time());self.decision={'schema':'ouf.semantic-scoped-terminal-decision.v1',
            'reviewHash':c.digest(self.review),'approvalRef':'mcp-scoped-'+c.digest(self.review)[:24]+'-'+str(now),
            'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':c.digest(self.review['authenticatedHuman']),
            'approvedAt':now,'expiresAt':now+210,'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
        q.write(self.context/'review.json',c.encoded(self.review))
    def compile(self):
        return a.compile_action_review(self.native_review,self.fixture.packet,self.closure,self.issuer,self.qualification,210)
    def issue(self):
        # Only executable/stdlib materialization is outside this test. Role
        # verification, existing key custody/signing and the claims are real.
        with patch.object(a,'verify_closure'):
            return a.issue_action(self.review,self.decision,self.human,c.digest(self.decision))
    def test_actual_existing_key_two_roles_exact_scope_and_consumed_issuance(self):
        action=self.issue();scope=c.scope(self.native_review);self.assertTrue(action.guard(c.AUTHORITY_KEY,scope))
        raw=json.loads(action.raw)
        self.assertNotIn('chatbotFileAuthorization',raw);self.assertFalse(raw['databaseRestoreAuthorized'])
        signatures=list(self.context.glob(action.authority_hash+'.*.json'));self.assertEqual(len(signatures),2)
        with self.assertRaises(c.Denied):self.issue()
        self.assertEqual(len(list(self.context.glob(action.authority_hash+'.*.json'))),2)
    def test_missing_platform_result_foreign_source_or_mutable_reference_blocks(self):
        original=copy.deepcopy(self.qualification)
        for mutate in(lambda q:q['results'].update(apisix='BLOCKED'),
                       lambda q:q.update(sourceCommit='f'*40),lambda q:q['evidenceRefs']['postgres17'].update(runId=True)):
            self.qualification=copy.deepcopy(original);mutate(self.qualification)
            with self.assertRaises(c.Denied):self.compile()
        self.assertFalse((self.context/'ingestion-rollout-issuance.claim.json').exists())
    def test_development_permission_or_wrong_explicit_decision_hash_never_issues(self):
        with self.assertRaises(c.Denied):a.issue_action(self.review,self.decision,self.human,'0'*64)
        self.assertFalse((self.context/'ingestion-rollout-issuance.claim.json').exists())
        changed=copy.deepcopy(self.review);changed['scopes']['foreignGrant']={'allowed':True}
        with self.assertRaises(c.Denied):a.validate_action_review(changed)
    def test_current_human_and_existing_policy_context_are_required_before_key_read(self):
        self.human.current=lambda:{**self.review['authenticatedHuman'],'sessionId':'foreign'}
        with self.assertRaises(Exception):self.issue()
        self.human.current=lambda:self.review['authenticatedHuman']
        changed=copy.deepcopy(self.issuer);changed['authorityContext']={**changed['authorityContext'],'entityRef':'another-ente'}
        with self.assertRaises(Exception):a.current_issuer(changed,self.decision['expiresAt'])
        self.assertFalse((self.context/'ingestion-rollout-issuance.claim.json').exists())
    def test_partial_signature_failure_retains_claim_and_never_reissues(self):
        original=a.ExistingEd25519Signer.sign;calls=[]
        def sign(signer,raw):
            calls.append(signer.scope['role'])
            if len(calls)==2:raise RuntimeError('synthetic second-signature interruption')
            return original(signer,raw)
        with patch.object(a.ExistingEd25519Signer,'sign',sign):
            with self.assertRaises(RuntimeError):self.issue()
        self.assertTrue((self.context/'ingestion-rollout-issuance.claim.json').exists())
        before=list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'));self.assertEqual(before,[])
        with patch.object(a.ExistingEd25519Signer,'sign')as signer:
            with self.assertRaises(c.Denied):self.issue()
            signer.assert_not_called()
    def test_qualification_receipt_cannot_be_removed_after_compilation(self):
        changed=copy.deepcopy(self.review);changed['qualification']['results']['adversarial']='BLOCKED'
        changed['qualificationHash']=c.digest(changed['qualification'])
        with self.assertRaises(c.Denied):a.validate_action_review(changed)

if __name__=='__main__':unittest.main()
