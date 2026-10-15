"""Explicit new first-grant budget after completed credential/unused expiry.

Hosted native roots, real Ed25519 and closing TLS responses; no target access.
"""
import copy
import json
import os
from pathlib import Path
import types
import unittest
from unittest.mock import patch

import test_chatbot_cohort_pregrant_recovery as initial
from tools.semantic_policy_token_owner.owner_installation import AggregateAction,OwnerInstallation
from tools.semantic_policy_token_owner.producer import Binding
import legacy_retirement as recovery

class PostCredential(initial.SignedPregrantContinuation):
    def setUp(self):
        super().setUp()
        self.root=self.f.f.root
        context=self.root/'post-credential-fixture';context.mkdir(mode=0o700)
        value=json.loads(self.f.f.authority)
        value['finiteActionProcess']={'authorityDirectory':str(context)}
        self.f.f.authority=recovery.binding.encoded(value)
        self.f.f.approval['executionAuthorityHash']=recovery.binding.sha(self.f.f.authority)
        self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
        self.f.f.approved=recovery.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.previous=self.successor()
        with patch.object(self.previous.first.admission,'prepare',side_effect=OSError(9,'synthetic closed response')):
            with self.assertRaises(OSError):self.previous.install()
        self.assertEqual(self.grants(),0)
        self.before_admin=list(self.f.calls);self.before_commands=list(self.f.commands)
        old_scopes=self.previous.scopes()
        old_scopes['finiteActionProcess']={'authorityDirectory':str(context)}
        review={'sourceClosure':{'declaration':{'sourceCommit':'b'*40}},
            'sourceClosureHash':self.previous.action.closure,'scopes':old_scopes}
        raw=self.previous.action.raw;old_authority=self.previous.action.authority_hash
        self.f.f.write(context/'review.json',recovery.binding.encoded(review))
        self.f.f.write(context/'authority.json',raw)
        paths=recovery.names(old_scopes)
        # Simulate the complete passage of the old unused budget, retaining
        # its duration/counter/decision/boot. Production hashes are never edited.
        row=json.loads(paths['session'].read_bytes())
        for key in ('createdAt','lastObservedAt','expiresAt','createdMonotonic','lastMonotonic','expiresMonotonic'):
            row[key]-=400
        self.f.f.write(paths['session'],recovery.binding.encoded(row))
        code=recovery.CODE;closure=self.previous.scope['stageManifestHash']
        selected={
            'postContinuation':self.root/self.previous.intent_name,
            'postOutput':self.root/self.previous.output.name,
            'postRetirement':self.root/self.previous.first.transaction.retirement.name,
            'credential':paths['credential'],'session':paths['session'],
            'postStageIntent':code/('policy-token-source-stage-'+closure+'.intent'),
            'postStageIntake':code/('semantic-native-v11-intake-'+closure)/'intake.json'}
        hashes={k:recovery.binding.sha(p.read_bytes()) for k,p in selected.items()}
        info=self.previous.first.credential.path.stat()
        for p in (patch.object(recovery,'POST_SOURCE','b'*40),patch.object(recovery,'POST_CONTEXT',context.name),
            patch.object(recovery,'POST_REVIEW',recovery.digest(review)),patch.object(recovery,'POST_AUTHORITY',old_authority),
            patch.object(recovery,'POST_RECORD_HASHES',hashes),
            patch.object(recovery,'POST_CREDENTIAL_ID',(info.st_dev,info.st_ino,info.st_size))):
            p.start();self.addCleanup(p.stop)
        self.post_proof=recovery.observe_post_credential(review,old_authority)
        self.preserved={ref['path']:Path(ref['path']).read_bytes() for ref in self.post_proof['recordBindings'].values()}
        self.secret_before=self.previous.first.credential.path.read_bytes()
        self.actor={'issuer':'https://human.fixture.test/realms/fixture','tenant':'fixture-tenant','subject':'fixture-human'}
        self.f.f.expected['sourceClosureHash']='8'*64
        value=json.loads(self.f.f.authority);value['sourceClosureHash']='8'*64
        self.f.f.authority=recovery.binding.encoded(value)
        planned=self.post_successor();value.update(planned.scopes())
        self.f.f.authority=recovery.binding.encoded(value)
        self.f.f.approval['sourceClosureHash']='8'*64
        self.f.f.approval['approvalRef']='NEW_POST_CREDENTIAL_BUDGET_SYNTHETIC'
        self.f.f.approval['executionAuthorityHash']=recovery.binding.sha(self.f.f.authority)
        self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
        self.f.f.approved=recovery.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.post=self.post_successor()

    def post_successor(self,actor=True):
        f=self.f;action=AggregateAction(f.f.gate(),f.f.authority,f.f.expected['sourceClosureHash'])
        b=Binding(f.server.profile.token_endpoint,'fixture-client','authorization.bundle.read',
            str(self.previous.output.path),'token.jwt',10001)
        return OwnerInstallation(action,f.r.f.raw,f.root_hash,f.root_source,f.registration,b,
            f.server.profile,f.transport,'c'*40,self.files,self.policy,'5'*64,'6'*64,60,f.clock,
            pregrant_recovery=self.post_proof,renewal_actor=self.actor if actor else None)

    def assert_preserved(self):
        for path,raw in self.preserved.items():self.assertEqual(Path(path).read_bytes(),raw)
        self.assertEqual(self.previous.first.credential.path.read_bytes(),self.secret_before)
        self.assertEqual(self.f.calls,self.before_admin)
        self.assertEqual(self.f.commands,self.before_commands)

    def test_new_decision_reuses_credential_and_preserves_old_session_with_one_cumulative_grant(self):
        self.f.server.connection_close=True
        original_session=self.previous.first.session.name
        self.assertNotEqual(self.post.first.session.name,original_session)
        self.assertEqual(self.post.first.session.operation,self.previous.first.session.operation)
        self.assertEqual(self.post.first.name,self.previous.first.name)
        self.assertEqual(self.post.first.transaction.scope['maximumIamMutations'],0)
        self.assertEqual(self.post.output.scope['maximumMkdirAttempts'],0)
        worker=self.post.install()
        self.assertEqual(self.grants(),1);self.assert_preserved()
        session=json.loads((self.root/self.post.first.session.name).read_bytes())
        self.assertEqual(session['attemptSlotsConsumed'],1)
        self.assertEqual(session['schema'],'ouf.policy-token-first-gap-session.v2')
        decision=session['budgetDecision']
        self.assertEqual(decision['actor'],self.actor)
        self.assertEqual(decision['authorityHash'],self.post.action.authority_hash)
        self.assertEqual(decision['decisionRef'],self.f.f.approval['approvalRef'])
        self.assertEqual(decision['priorGrantAttempts'],0)
        self.assertEqual(decision['maximumCumulativeGrantAttempts'],1)
        self.assertEqual(self.post.journal.read()['controlledCumulativeGrantAttempts'],1)
        self.assertEqual(worker.tick()['state'],'ACTIVE');self.assertEqual(self.grants(),1)
        with self.assertRaisesRegex(Exception,'ALREADY_RESERVED|HISTORY_PRESENT'):self.post_successor().install()
        self.assertEqual(self.grants(),1);self.assert_preserved()

    def test_revoked_fresh_human_denies_before_credential_adoption_or_grant(self):
        self.f.f.approval['state']='REVOKED';self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
        with self.assertRaises(Exception):self.post.install()
        self.assertEqual(self.grants(),0);self.assert_preserved()
        self.assertFalse((self.root/self.post.intent_name).exists())

    def test_predecessor_session_counter_record_drift_denies_before_any_effect(self):
        bound=self.post_proof['recordBindings']['session'];path=Path(bound['path']);raw=path.read_bytes()
        row=json.loads(raw);row['attemptSlotsConsumed']=1;row['state']='ATTEMPT_SLOT_CONSUMED_OUTCOME_UNPROVEN'
        self.f.f.write(path,recovery.binding.encoded(row))
        with self.assertRaisesRegex(Exception,'RETAINED_RECORD_DRIFT'):self.post.install()
        self.f.f.write(path,raw);self.assertEqual(self.grants(),0);self.assert_preserved()

    def test_credential_content_or_inode_change_is_never_repaired_or_rotated(self):
        path=self.previous.first.credential.path;raw=path.read_bytes()
        path.chmod(0o600);path.write_bytes(raw[:-1]+bytes([raw[-1]^1]));path.chmod(0o400)
        with self.assertRaisesRegex(Exception,'CREDENTIAL.*CHANGED'):self.post.install()
        self.assertEqual(self.grants(),0);self.assertEqual(self.f.calls,self.before_admin)
        self.assertEqual(self.f.commands,self.before_commands)
        self.assertFalse((self.root/self.post.intent_name).exists())

    def test_parallel_continuation_lock_denies_without_new_records(self):
        import fcntl
        fd=os.open(self.root/(self.post.intent_name+'.lock'),os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.post.install()
        finally:os.close(fd)
        self.assertEqual(self.grants(),0);self.assert_preserved()

    def test_missing_or_changed_current_budget_actor_cannot_be_implicitly_selected(self):
        with self.assertRaisesRegex(Exception,'BUDGET_ACTOR_REQUIRED'):self.post_successor(actor=False)
        original=self.post.first.session.scope['newBudget']['actor']
        self.post.first.session.scope['newBudget']['actor']={**original,'subject':'other-human'}
        with self.assertRaises(Exception):self.post.install()
        self.assertEqual(self.grants(),0);self.assert_preserved()

    def test_revocation_after_credential_observation_leaves_receipt_but_no_grant(self):
        publish=self.post.pregrant_recovery.publish
        def revoked(name,row):
            value=publish(name,row)
            if name==self.post.first.transaction.name:
                self.f.f.approval['state']='REVOKED';self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
            return value
        with patch.object(self.post.pregrant_recovery,'publish',side_effect=revoked),self.assertRaises(Exception):
            self.post.install()
        self.assertTrue((self.root/self.post.first.transaction.name).exists())
        self.assertEqual(self.grants(),0);self.assert_preserved()

    def test_failed_online_admission_consumes_only_one_new_slot_and_never_replays(self):
        self.f.server.connection_close=True;self.f.server.active=lambda:{'active':False}
        with self.assertRaises(Exception):self.post.install()
        self.assertEqual(self.grants(),1)
        session=json.loads((self.root/self.post.first.session.name).read_bytes())
        self.assertEqual(session['attemptSlotsConsumed'],1)
        with self.assertRaises(Exception):self.post_successor().install()
        self.assertEqual(self.grants(),1);self.assert_preserved()

# Do not repeat pregrant-only contracts against the later partially completed fixture.
for _name in dir(initial.SignedPregrantContinuation):
    if _name.startswith('test_'):setattr(PostCredential,_name,None)


class PostCredentialInfrastructure(initial.CompletedInfrastructure):
    def setUp(self):
        super().setUp()
        self.original_review=copy.deepcopy(self.review)
        self.fresh_authority='c'*64
        self.fresh_context=self.root/('chatbot-file-cohort-signed-'+'e'*64);self.fresh_context.mkdir(mode=0o700)
        paths={name:str(self.fresh_context/name) for name in self.paths}
        for path in paths.values():Path(path).mkdir(mode=0o700)
        self.fresh_review=copy.deepcopy(self.review)
        self.fresh_review['scopes']['finiteActionProcess']=copy.deepcopy(self.plan)
        self.fresh_review['scopes']['finiteActionProcess']['directoryPlan']=paths
        self.fresh_review['sourceClosure']['declaration']['sourceCommit']=recovery.POST_SOURCE
        self.fresh_review['scopes']['gatewayRuntimeInstallation']={
            'profile':initial.GATEWAY_PROFILE,'required':False,'retainedTransportHash':'pending',
            'proposalKeyHash':'9'*64,'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False}
        self.fresh_prepared={'imagePlan':copy.deepcopy(self.image_plan),'gatewayRuntimePlan':None,
            'engine':{'socketPath':'/fixture-socket','socketBinding':[]},'owner':{'fixture':'public-discovery-only'},
            'gatewayPlan':{'transportBinding':{'runtimeBinding':initial.Engine.runtime_binding(self.new_gateway)},
                           'proposalKeyBinding':{'sha256':'9'*64}}}
        for row in self.image_plan['images']:
            state=initial.Import.initial(row['audit'],self.fresh_authority)
            native=self.by_id['/v1.44/images/'+initial.runtime_image_id(row['audit'])+'/json']
            state.update(state='VERIFIED',version=1,effectAttemptCount=0,imageCustodyProven=True,
                nativeEvidenceHash=initial.process.digest(initial.loaded(row['audit'],native)))
            self.write(Path(paths['image'+row['module'].capitalize()])/'recovery.json',state)
        self.fresh_paths=paths
        self.reseal()
        for p in (patch.object(recovery,'CONTEXT',self.context.name),
            patch.object(recovery,'AUTHORITY',self.authority_hash),
            patch.object(recovery,'REVIEW',recovery.digest(self.original_review)),
            patch.object(initial.process,'post_credential_discovery',return_value={'discoveryIdentityVerified':True,
                'tlsTrustSetVerified':True,'grantRequests':0,'credentialFilesRead':False,'maximumSeconds':10})):
            p.start();self.addCleanup(p.stop)
        self.write(self.context/'review.json',self.original_review)

    def reseal(self):
        plan=self.fresh_review['scopes']['finiteActionProcess']
        self.fresh_review['scopes']['gatewayRuntimeInstallation']['retainedTransportHash']=initial.process.digest(
            self.fresh_prepared['gatewayPlan']['transportBinding'])
        self.fresh_review['privateInputHashes']['preparedInputs']=initial.process.digest(self.fresh_prepared)
        bundle={'declaration':self.fresh_review['sourceClosure']['declaration'],'prepared':self.fresh_prepared}
        path=self.fresh_context/'bundle.json';self.write(path,bundle)
        plan['bundle']={'path':str(path),'sha256':recovery.binding.sha(path.read_bytes())}
        self.fresh_proof={'schema':recovery.POST_PROFILE,'predecessorReviewHash':initial.process.digest(self.fresh_review),
            'predecessorAuthorityHash':self.fresh_authority}

    def invoke(self):
        return initial.process.post_credential_native_readback(self.fresh_review,self.fresh_authority,self.fresh_proof)

    def test_current_images_are_read_without_load_and_original_apisix_is_still_bound(self):
        before={p:p.read_bytes() for p in self.root.rglob('*')if p.is_file()}
        images,gateway,bindings,discovery=self.invoke()
        self.assertEqual(len(images),5);self.assertTrue(all(row['effectAttemptCount']==0 for row in images))
        self.assertEqual(gateway['completedSteps'],list(initial.STEPS))
        self.assertTrue(discovery['discoveryIdentityVerified']);self.assertGreaterEqual(len(bindings),13)
        self.assertEqual(before,{p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()})

    def test_a_new_image_effect_attempt_cannot_be_hidden_as_reuse(self):
        path=Path(self.fresh_paths['imageUdp'])/'recovery.json';row=json.loads(path.read_bytes())
        row.update(version=2,effectAttemptCount=1);self.write(path,row)
        with self.assertRaisesRegex(Exception,'WITHOUT_RELOAD'):self.invoke()

    def test_changed_current_gateway_transport_or_native_image_denies_before_discovery(self):
        self.fresh_prepared['gatewayPlan']['transportBinding']['runtimeBinding']['pid']+=1;self.reseal()
        with self.assertRaisesRegex(Exception,'APISIX_BINDING_DRIFT'):self.invoke()
        self.fresh_prepared['gatewayPlan']['transportBinding']['runtimeBinding']['pid']-=1;self.reseal()
        image=next(iter(self.by_id.values()));image['Config']['Env']=['unreviewed=true']
        with self.assertRaises(Exception):self.invoke()

for _name in initial.CompletedInfrastructure.__dict__:
    if _name.startswith('test_'):setattr(PostCredentialInfrastructure,_name,None)

class PostCredentialHistory(initial.predecessor_fixture.Predecessor):
    def setUp(self):
        super().setUp()
        self.new_operation='e'*64;self.new_context=self.root/('chatbot-file-cohort-signed-'+self.new_operation)
        self.new_context.mkdir(mode=0o700)
        self.old_seed={'immutableOriginalHistory':'fixture'}
        self.proof={'schema':recovery.POST_PROFILE,'originalPregrantProofHash':initial.process.digest(self.old_seed),
            'priorCredentialMutationAttempts':1,'priorGrantAttempts':0}
        self.review['sourceClosure']['declaration']['sourceCommit']=recovery.SOURCE
        self.review['scopes']['cohortImageImport']={}
        self.authority['cohortImageImport']={}
        self.authority_hash=initial.process.digest(self.authority)
        self.status.update(authorityHash=self.authority_hash,reason='RETIREMENT_QUIESCENCE_UNPROVEN')
        self.claim.update(authorityHash=self.authority_hash);self.completed['authorityHash']=self.authority_hash
        self.journal['authorityHash']=self.authority_hash
        self.decision['approvedReviewHash']=initial.process.digest(self.review)
        for name,value in (('review.json',self.review),('authority.json',self.authority),('decision.json',self.decision),
            ('delivery-status.json',self.status),('directories.completed.json',self.completed)):
            self.write(self.context/name,value)
        self.write(self.claim_path,self.claim);self.write(self.journal_path,self.journal)
        paths={name:str(self.new_context/name)for name in self.paths}
        for path in paths.values():Path(path).mkdir(mode=0o700)
        plan=copy.deepcopy(self.plan);plan.update(logicalOperationHash=self.new_operation,
            unit='ouf-file-cohort-'+self.new_operation[:32]+'.service',authorityDirectory=str(self.new_context),directoryPlan=paths)
        review=copy.deepcopy(self.review);review['sourceClosure']['declaration']['sourceCommit']=recovery.POST_SOURCE
        review['scopes']['finiteActionProcess']=plan
        authority=copy.deepcopy(self.authority);authority['finiteActionProcess']=plan
        digest=initial.process.digest(authority)
        decision=copy.deepcopy(self.decision);decision['approvedReviewHash']=initial.process.digest(review)
        status=copy.deepcopy(self.status);status.update(authorityHash=digest,reason='OSError')
        completed={'authorityHash':digest,'planHash':initial.process.digest(paths),
            'identities':{path:{'device':Path(path).stat().st_dev,'inode':Path(path).stat().st_ino}for path in paths.values()}}
        claim=copy.deepcopy(self.claim);claim.update(authorityHash=digest,planHash=initial.process.digest(plan))
        journal=copy.deepcopy(self.journal);journal.update(authorityHash=digest,effects={})
        for name,value in (('review.json',review),('authority.json',authority),('decision.json',decision),
            ('delivery-status.json',status),('directories.completed.json',completed)):
            self.write(self.new_context/name,value)
        self.write(self.root/('chatbot-file-cohort-process-'+self.new_operation+'.claim.json'),claim)
        self.write(Path(paths['authorization'])/'recovery.json',journal)
        self.new_paths=paths;self.new_decision=decision
        for p in (patch.object(recovery,'POST_CONTEXT',self.new_context.name),patch.object(recovery,'POST_AUTHORITY',digest),
            patch.object(recovery,'observe_post_credential',return_value=self.proof),
            patch.object(recovery,'observe',side_effect=AssertionError('absence-only observer must not run')),
            patch.object(recovery,'retained_pregrant',return_value=self.old_seed),
            patch.object(initial.process,'pregrant_native_readback',return_value=([],{'completedSteps':list(initial.STEPS)},[])),
            patch.object(initial.process,'post_credential_native_readback',return_value=([],{'completedSteps':list(initial.STEPS)},[],{'discoveryIdentityVerified':True}))):
            p.start();self.addCleanup(p.stop)

    def test_completed_credential_history_supersedes_only_original_absence_check(self):
        before={p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        rows=self.observe();self.assertEqual(len(rows),2)
        first=next(row for row in rows if row['sourceCommit']==recovery.SOURCE)
        last=next(row for row in rows if row['sourceCommit']==recovery.POST_SOURCE)
        self.assertIsNone(first['ownerPregrantRecovery'])
        self.assertEqual(first['historicalOwnerSupersededBy']['proofHash'],initial.process.digest(self.proof))
        self.assertEqual(last['ownerPregrantRecovery'],self.proof)
        initial.process.verify_previous_authorization_actions(rows,self.manifest,self.systemctl,self.root/'new')
        self.assertEqual(before,{p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()})

    def test_unexpired_authority_and_new_application_claim_still_deny(self):
        import time
        self.new_decision['expiresAt']=int(time.time())+100
        self.write(self.new_context/'decision.json',self.new_decision)
        with self.assertRaisesRegex(Exception,'WINDOW_MUST_BE_EXPIRED'):self.observe()
        self.new_decision['expiresAt']=int(time.time())-20
        self.write(self.new_context/'decision.json',self.new_decision)
        self.write(Path(self.new_paths['databases'])/'recovery.json',{'state':'UNPROVEN'})
        with self.assertRaisesRegex(Exception,'STAGE_HISTORY'):self.observe()

for _name in initial.predecessor_fixture.Predecessor.__dict__:
    if _name.startswith('test_'):setattr(PostCredentialHistory,_name,None)

if __name__=='__main__':unittest.main()
