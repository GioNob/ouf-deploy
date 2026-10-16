"""Composed token-only issuance/dispatch; synthetic OAuth and terminal boundary.

Native role signatures, custody, TLS workload grant and publication remain real.
No target transport, real HUMAN approval or service operation is used.
"""
import copy
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT)]
import test_governed_owner_composed as composed
from tools.chatbot_file_cohort import review as r
from tools.chatbot_file_cohort.continued_owner import token_only_session_main
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.continued_owner import TOKEN_STAGE_SOURCE as STAGE_SOURCE
NATIVE_EXECUTABLE=r.governance.executable
NATIVE_RUN=r.subprocess.run


class Execution(unittest.TestCase):
    def setUp(self):
        f=composed.Composed();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        p=patch.object(r.governance,'executable',NATIVE_EXECUTABLE);p.start();self.addCleanup(p.stop)
        p=patch.object(r.subprocess,'run',NATIVE_RUN);p.start();self.addCleanup(p.stop)
        self.g=f.f.f
        # A one-hour mandate must fit both currently authorized role windows.
        policy=json.loads(self.g.policy.read_bytes())
        for key in policy['keys']:key['expiresAt']=int(time.time())+7200
        self.g.write(self.g.policy,r.encoded(policy));policy_binding=self.g.binding(self.g.policy)
        self.g.verifier.policy_binding=policy_binding
        profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1',
            'authorities':self.g.context,'policyBinding':policy_binding,
            'keyRefs':{'installer':policy['keys'][0]['keyRef'],'attestor':policy['keys'][1]['keyRef']},
            'keyBindings':{'installer':self.g.binding(self.g.key),
                'attestor':{'path':str(self.g.root/'unread-attestor.pem'),'sha256':'f'*64}}}
        profile_path=self.g.root/'existing-profile.json';self.g.write(profile_path,r.encoded(profile))
        for target,name,value in ((r.governance,'PROFILE',self.g.binding(profile_path)),
                (r.governance,'POLICY',policy_binding),(r.governance,'CONTEXT',self.g.context)):
            p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
        self.context=self.g.root/'semantic-token-execution-abcdefgh';self.context.mkdir(mode=0o700)
        program=f.f.f.verifier.openssl_binding
        self.closure={'declaration':{'requiredPythonFlags':['-I','-B','-S'],'sourceCommit':'a'*40},
            'executables':{k:program for k in ('python','docker','openssl','systemctl','systemdRun')},
            'stdlibHash':r.digest({'fileHashes':{}}),'stdlibFileCount':0}
        self.proposal={'path':str(f.review_path),'sha256':r.digest(f.review)}
        self.candidate={'schema':'ouf.semantic-functional-session-candidate.v1',
            'privateReviewHash':r.digest(f.review),'firstGrantReceiptHash':r.digest(f.first),
            'compiledSessionScope':f.make().worker_scope,'nativeQualification':{
                'nativeUidGidModeProven':True,'atomicPublisherCodeUsed':True,'syntheticDataOnly':True,
                'fixtureRemoved':True,'applicationReadinessProven':False},
            'runtimeAuthorityIssued':False,'readyForExecution':False}
        self.candidate_path=self.g.root/'candidate.json';self.g.write(self.candidate_path,r.encoded(self.candidate))
        self.cb={'path':str(self.candidate_path),'sha256':r.digest(self.candidate)}
        self.actor=f.review['requestedHumanActor']
        self.hb={**self.actor,'sessionId':'synthetic-login-boundary','expiresAt':int(time.time())+7200}
        self.human_directory=self.g.root/'human';self.human_directory.mkdir(mode=0o700)
        self.human=HumanSession(self.actor,self.human_directory,self.human_directory/'human-access.jwt',self.hb['expiresAt'])
        self.scopes=f.make().scopes();self.scopes['policyTokenOwnerInstallation']['sourceClosureHash']=r.digest(self.closure)
        self.review=r.compile_token_review(self.closure,self.scopes,self.proposal,self.cb,self.hb,self.context)

    def decision(self,review=None):
        review=review or self.review;now=int(time.time())
        return {'schema':'ouf.semantic-token-only-terminal-decision.v1',
            'approvalRef':'semantic-token-'+r.digest(review)[:24]+'-'+str(now),
            'reviewHash':r.digest(review),'sourceClosureHash':review['sourceClosureHash'],
            'humanSessionHash':r.digest(review['authenticatedHuman']),'approvedAt':now,'expiresAt':now+3600,
            'decision':r.TOKEN_DECISION,'state':'ACTIVE'}

    def test_review_denies_application_scopes_and_different_human_or_budget(self):
        for change in ('extra','actor','budget'):
            scopes=copy.deepcopy(self.scopes);human=copy.deepcopy(self.hb)
            if change=='extra':scopes['gatewayRoutePublication']={'write':True}
            if change=='actor':human['subject']='another-person'
            if change=='budget':scopes['policyTokenFiniteWorkerSession']['maximumCumulativeGrantAttempts']=198
            with self.assertRaises(Exception):r.compile_token_review(self.closure,scopes,self.proposal,self.cb,human,self.context)
        decision=self.decision();r.validate_token_decision(self.review,decision,time.time())
        for key,value in (('humanSessionHash','f'*64),('expiresAt',decision['approvedAt']+3601),('state','REVOKED')):
            with self.assertRaises(Exception):r.validate_token_decision(self.review,{**decision,key:value},time.time())

    def test_actual_dual_signatures_and_one_use_issuance(self):
        self.g.write(self.context/'review.json',r.encoded(self.review));before=self.f.grants()
        with patch.object(HumanSession,'current',return_value=self.hb),patch.object(r,'stdlib_binding',return_value={'fileHashes':{}}):
            action=r.issue_token_action(self.review,self.decision(),self.human)
            self.assertTrue(action.authority(action.raw))
            self.assertEqual(set(json.loads(action.raw))&r.REQUIRED_SCOPES,set(self.scopes)-{'semanticFunctionalRuntime'})
            with self.assertRaises(Exception):r.issue_token_action(self.review,self.decision(),self.human)
        self.assertEqual(self.f.grants(),before)
        self.assertEqual(len(list(self.context.glob('*.DEPLOYMENT_INTENT.json'))),1)
        self.assertEqual(len(list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)

    def test_altered_review_or_unverified_human_denies_before_issuance(self):
        self.g.write(self.context/'review.json',r.encoded({**self.review,'maximumCumulativeGrantAttempts':198}))
        with patch.object(HumanSession,'current',return_value=self.hb),patch.object(r,'stdlib_binding',return_value={'fileHashes':{}}):
            with self.assertRaises(Exception):r.issue_token_action(self.review,self.decision(),self.human)
        self.assertFalse((self.context/'issuance.claim.json').exists())
        with patch.object(HumanSession,'current',return_value={**self.hb,'subject':'different'}):
            with self.assertRaises(Exception):r.issue_token_action(self.review,self.decision(),self.human)
        self.assertFalse((self.context/'issuance.claim.json').exists())

    def main(self,rejected=False):
        # New directory creation belongs to this dispatcher rather than the component fixture.
        self.f.journal.rmdir()
        prepared={'owner':self.f.value,'engine':self.f.engine_binding,
            'authorization':{'plan':{'selection':self.actor}}}
        sources={module:self.f.base.files[name]for name,module in STAGE_SOURCE.items()}
        rows=[];before=self.f.grants()
        def once(worker,stop,reporter):
            row=worker.tick();rows.append(row);reporter.report(worker.status(row));stop.set()
        approve=(lambda *a:(_ for _ in ()).throw(ValueError('SYNTHETIC_REJECTION')))if rejected else lambda review,path:self.decision(review)
        with patch.object(HumanSession,'login',return_value=self.hb),patch.object(HumanSession,'current',return_value=self.hb),\
             patch.object(r,'stdlib_binding',return_value={'fileHashes':{}}),patch.object(r,'terminal_token_decision',side_effect=approve),\
             patch('tools.semantic_policy_token_owner.worker_entry.serve',side_effect=once):
            token_only_session_main(prepared,sources,self.closure,self.f.review,self.proposal,self.candidate,self.cb,
                self.f.records,self.f.first,self.context,{'path':str(self.g.root/'synthetic-executor.py'),'sha256':'d'*64},
                emit=lambda value:None,transport=self.f.installed.first.transport)
        return before,rows

    def test_dispatcher_signs_installs_and_performs_only_one_accounted_workload_grant(self):
        before,rows=self.main()
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'ACTIVE')
        self.assertEqual(rows[0]['controlledCumulativeGrantAttempts'],70)
        self.assertEqual(self.f.grants(),before+1)
        for name,raw in self.f.before.items():self.assertEqual((self.f.installed.journal.root/name).read_bytes(),raw)

    def test_terminal_rejection_has_no_signatures_fence_or_workload_grant(self):
        before=self.f.grants()
        with self.assertRaisesRegex(ValueError,'SYNTHETIC_REJECTION'):self.main(rejected=True)
        self.assertEqual(self.f.grants(),before)
        self.assertFalse((self.context/'issuance.claim.json').exists())
        self.assertFalse(Path(self.candidate['compiledSessionScope']['fenceBinding']['path']).exists())

if __name__=='__main__':unittest.main()
