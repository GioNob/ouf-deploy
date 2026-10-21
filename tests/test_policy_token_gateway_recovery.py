"""Eight retained actual TLS grants, one new finite v8 session and ninth grant."""
import copy
import hashlib
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import test_policy_token_migration_recovery as prior
import test_policy_token_postgrant_continuation as base
from tools.chatbot_file_cohort import gateway_recovery as recovery
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.chatbot_file_cohort.action_process import private_file
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.supervisor import RenewalWorker


class GatewayWorker(unittest.TestCase):
    def test_eight_preserved_ninth_actual_grant_no_reset_or_replay(self):
        h=prior.MigrationRecoveryOwner();self.addCleanup(h.doCleanups);h.setUp()
        f=h.f;h.value['intervalSeconds']=1
        def sign(scopes,label):
            authority=json.loads(f.f.authority);authority.update(scopes)
            f.f.authority=base.existing.fixture.binding.encoded(authority)
            f.f.approval.update(approvalRef=label,executionAuthorityHash=base.existing.fixture.binding.sha(f.f.authority))
            f.f.write(f.f.mandate,base.existing.fixture.binding.encoded(f.f.approval));f.f.approved=base.existing.fixture.binding.sha(f.f.mandate.read_bytes())
            for role in f.f.grant['roles']:f.f.sign(role)
        sign(h.make().scopes(),'EXACT_TWO_RENEWAL_SYNTHETIC_SESSION')
        old=h.make();worker=old.install();self.assertEqual(worker.tick()['state'],'ACTIVE')
        self.assertEqual(h.harness.grants(),7)
        deadline=time.monotonic()+8
        while old.journal.read()['publicationCount']<2:
            self.assertLess(time.monotonic(),deadline);time.sleep(.1)
            self.assertEqual(worker.tick()['state'],'ACTIVE')
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED');self.assertEqual(h.harness.grants(),8)
        paths=[old.journal.root/n for n in ('recovery.json','owner-session.json','owner-admission.json')]
        preserved={p:p.read_bytes()for p in paths}
        previous=copy.deepcopy(h.previous);previous['review']={'scopes':old.scopes()}
        previous.update(worker=json.loads(paths[0].read_bytes()),session=json.loads(paths[1].read_bytes()),admission=json.loads(paths[2].read_bytes()))
        for name,key in [('WORKER_HASH','worker'),('SESSION_HASH','session'),('ADMISSION_HASH','admission')]:
            override=patch.object(recovery,name,base.fingerprint(previous[key]));override.start();self.addCleanup(override.stop)
        recovery.validate_worker(previous['firstGrant'],previous['worker'],previous['admission'],previous['session'])
        proof={'profile':recovery.PROFILE,'cancelledWorkerHash':base.fingerprint(previous['worker']),
            'workerSessionHash':base.fingerprint(previous['session']),
            'recordBindings':[{'path':str(p),'sha256':hashlib.sha256(raw).hexdigest()}for p,raw in preserved.items()],
            'newBudget':{**h.proof['newBudget'],'reason':'QUALIFY_GATEWAY_AFTER_EIGHT_GRANTS',
                'priorControlledGrantAttempts':8,'priorWorkerGrantAttempts':2}}
        def bindings(proof):
            for binding in proof['recordBindings']:private_file(binding,8388608)
        override=patch.object(recovery,'retained_bindings',side_effect=bindings);override.start();self.addCleanup(override.stop)
        directory=f.f.root/'gateway-recovery-v8';directory.mkdir(mode=0o700)
        value={**h.value,'contextRef':'a'*64,'generationRef':'b'*64,'sourceCommit':'c'*40}
        def make():
            action=AggregateAction(f.f.gate(),f.f.authority,f.f.expected['sourceClosureHash'])
            return ContinuedOwnerInstallation(action,value,h.harness.files,proof,previous,directory,f.clock,transport=f.transport)
        self.f=f;self.harness=h.harness;self.value=value;self.proof=proof
        self.predecessor=previous;self.directory=directory;self.old=old;self.unchanged=h.unchanged
        def complete_phase5(prepared):
            from tools.chatbot_file_cohort.authorization import OBSERVATION_POLICY
            prepared['authorization']['plan']['observationPolicy']=copy.deepcopy(OBSERVATION_POLICY)
            prepared['authorization']['plan']['retainedRoleObservation']={
                'profile':'ouf.authorization-retained-role-observation.v1','ownerReceiptHash':'d'*64,
                'policyRef':prepared['authorization']['plan']['baseline']['active']['policyRef'],
                'policyHash':'4'*64,'roleCatalogueHash':base.fingerprint(prepared['authorization']['plan']['targetRoles']),
                'allowedStage':'AFTER_GATEWAY','forceFreshMcpBeforeRelease':True,
                'ownerPublicationContract':'LOCKED_ATOMIC_ROLE_AND_POLICY_PUBLICATION'}
            from tools.chatbot_file_cohort import gateway_runtime as r
            prepared['gatewayRuntimePlan']={'schema':r.PROFILE,'sameExistingImageRequired':True,
                'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False,
                'oldRuntimeBinding':{'containerId':'1'*64,'imageId':r.NUMERIC_IMAGE},'proposalKeyHash':'3'*64,
                'numericCompatibility':{'profile':r.NUMERIC_PROFILE,'syntheticAssetBindings':True},
                'newConfigBinding':{'syntheticConfigBinding':True},'readinessPolicy':copy.deepcopy(r.APISIX_READINESS_POLICY)}
            prepared['gatewayPlan'].update(changes=[{'syntheticPlannedChange':i}for i in range(28)],
                governedReprocessing={'newIntentHash':'4'*64})
            database={'modules':[{'module':'mcp','database':'fixture_mcp','user':'fixture_app'}],
                'mcpAuditRoleAdministration':{'admin':'fixture_admin'},'mcpAuditRolePreflight':{'syntheticCompletedAudit':True},
                'mcpBackupReader':{'syntheticRetainedReader':True}}
            prepared['databasePlan']=database;prepared['cohortPlan']['databasePlanHash']=base.fingerprint(database)
            prepared['registry']['cohortPlanHash']=base.fingerprint(prepared['cohortPlan'])
        from tools.chatbot_file_cohort import gateway_retained
        self.phase5_transform=complete_phase5
        self.proof['retainedNumericGateway']={'profile':gateway_retained.PROFILE,
            'sourceCommit':gateway_retained.SOURCE,'reviewHash':gateway_retained.REVIEW,
            'authorityHash':gateway_retained.AUTHORITY,'runtimeJournalHash':gateway_retained.RUNTIME,
            'runtimeBindingHash':gateway_retained.NATIVE,'runtimePlanHash':'a'*64,'gatewayPlanHash':'b'*64,
            'authorizationReceiptHash':'d'*64,
            'historicalEffects':8,'newLifecycleEffectsAllowed':False,'newWorkerPreviouslyInstalled':False,
            'originalContinuationClaimHash':'c'*64}
        review=base.PostGrantOwner.compile_complete_review(self,complete_phase5)
        self.assertEqual(review['completedTechnicalPhases'],[1,2,3,4]);self.assertEqual(review['currentTechnicalPhase'],5)
        self.assertEqual(review['gatewayContinuationReview']['remainingChanges'],28)
        self.assertEqual(review['scopes']['policyTokenFiniteWorkerSession']['predecessorGrantAttempts'],8)
        self.assertEqual(review['mcpMigrationReview']['disposition'],'COMPLETE_CLEAN_VERIFY_ONLY_NO_REPLAY')
        self.assertEqual(review['mcpBackupReaderReview']['disposition'],'RETAINED_ARCHIVE_ONLY_ZERO_NEW_DUMPS')
        self.assertFalse(review['chatbotEndToEndProven']);self.assertEqual(h.harness.grants(),8)
        adopted_review=review
        self.assertEqual(adopted_review['gatewayContinuationReview']['runtimeDisposition'],'COMPLETED_EIGHT_STEPS_VERIFY_ONLY')
        self.assertEqual(adopted_review['gatewayContinuationReview']['retainedNumericGateway'],self.proof['retainedNumericGateway'])
        self.assertEqual(adopted_review['scopes']['policyTokenFiniteWorkerSession']['predecessorGrantAttempts'],8)
        sign(make().scopes(),'EXACT_V8_GATEWAY_FINITE_HUMAN_DECISION')
        owner=make();new=owner.install();initial=owner.journal.read()
        self.assertEqual(initial['controlledCumulativeGrantAttempts'],8);self.assertEqual(initial['attempts'],0)
        self.assertFalse(new.active_here);self.assertEqual(h.harness.grants(),8)
        with self.assertRaises(Exception):owner.observer.guard_worker_session({**initial,'controlledPredecessorGrantAttempts':6})
        self.assertEqual(new.tick()['state'],'ACTIVE');self.assertEqual(h.harness.grants(),9)
        self.assertEqual(owner.journal.read()['controlledCumulativeGrantAttempts'],9)
        owner.observer.guard_worker_session(owner.journal.read())
        self.successor_owner,self.successor_worker,self.sign=owner,new,sign
        token=(Path(owner.observer.binding.output_directory)/owner.observer.binding.output_member).read_text()
        self.assertTrue(owner.observer.admit_mounted(token,30,owner.observer.binding.digest(),time.monotonic()+20))
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):make().install()
        self.assertEqual(RenewalWorker(new.r).tick()['state'],'RECONCILE_REQUIRED')
        f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):make().install()
        self.assertEqual(h.harness.grants(),9)
        for path,raw in preserved.items():self.assertEqual(path.read_bytes(),raw)
        h.unchanged()

if __name__=='__main__':unittest.main()
