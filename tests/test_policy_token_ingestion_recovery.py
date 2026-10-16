"""Nine retained actual TLS grants, v9 full review, tenth grant and no replay."""
import copy,json,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_policy_token_gateway_recovery as phase5
import test_policy_token_postgrant_continuation as base
from tools.chatbot_file_cohort import ingestion_recovery as tail,gateway_recovery as recovery
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.supervisor import RenewalWorker
from test_chatbot_cohort_ingestion_recovery import receipt

class IngestionWorker(unittest.TestCase):
    def test_nine_preserved_tenth_actual_tls_grant_and_complete_phase6_review(self):
        h=phase5.GatewayWorker();self.addCleanup(h.doCleanups)
        h.test_eight_preserved_ninth_actual_grant_no_reset_or_replay()
        # The preceding test deliberately corrupts its fixture mandate to prove
        # denial. Restore only that disposable fixture before a new signed review.
        h.f.f.write(h.f.f.mandate,base.existing.fixture.binding.encoded(h.f.f.approval))
        h.f.f.approved=base.existing.fixture.binding.sha(h.f.f.mandate.read_bytes())
        old=h.successor_owner;worker=h.successor_worker
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED')
        paths=[old.journal.root/n for n in ('recovery.json','owner-session.json','owner-admission.json')]
        frozen={p:p.read_bytes()for p in paths}
        previous=copy.deepcopy(h.predecessor);previous['review']={'scopes':old.scopes()}
        previous.update(worker=json.loads(paths[0].read_bytes()),session=json.loads(paths[1].read_bytes()),admission=json.loads(paths[2].read_bytes()))
        for name,key in [('WORKER','worker'),('SESSION','session'),('ADMISSION','admission')]:
            self.enterContext(patch.object(tail,name,base.fingerprint(previous[key])))
        tail.validate_worker(previous['firstGrant'],previous['worker'],previous['admission'],previous['session'])
        h.predecessor=previous;h.old=old;h.proof=copy.deepcopy(h.proof)
        h.proof.update(cancelledWorkerHash=tail.WORKER,workerSessionHash=tail.SESSION,
            retainedCreatedIngestion=receipt())
        h.proof['newBudget'].update(priorControlledGrantAttempts=9,priorWorkerGrantAttempts=1,
            reason='QUALIFY_EXISTING_INGESTION_AFTER_NINE_GRANTS')
        h.directory=h.f.f.root/'ingestion-recovery-v9';h.directory.mkdir(mode=0o700)
        for name in ('complete-postgrant-review','preserved-backup'):
            (h.f.f.root/name).rename(h.f.f.root/('phase5-'+name))
        review=base.PostGrantOwner.compile_complete_review(h,h.phase5_transform)
        self.assertEqual(review['completedTechnicalPhases'],[1,2,3,4,5]);self.assertEqual(review['currentTechnicalPhase'],6)
        self.assertEqual(review['gatewayContinuationReview']['remainingChanges'],0)
        self.assertEqual(review['scopes']['policyTokenFiniteWorkerSession']['predecessorGrantAttempts'],9)
        self.assertEqual(h.harness.grants(),9)
        def make():
            return ContinuedOwnerInstallation(AggregateAction(h.f.f.gate(),h.f.f.authority,h.f.f.expected['sourceClosureHash']),
                h.value,h.harness.files,h.proof,previous,h.directory,h.f.clock,transport=h.f.transport)
        h.sign(make().scopes(),'EXACT_V9_PHASE6_FINITE_HUMAN_DECISION')
        owner=make();new=owner.install()
        self.assertEqual(owner.journal.read()['controlledCumulativeGrantAttempts'],9)
        self.assertEqual(new.tick()['state'],'ACTIVE');self.assertEqual(h.harness.grants(),10)
        self.assertEqual(owner.journal.read()['controlledCumulativeGrantAttempts'],10)
        owner.observer.guard_worker_session(owner.journal.read())
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):make().install()
        self.assertEqual(RenewalWorker(new.r).tick()['state'],'RECONCILE_REQUIRED')
        for path,value in frozen.items():self.assertEqual(path.read_bytes(),value)
        h.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):make().install()
        self.assertEqual(h.harness.grants(),10);h.unchanged()

if __name__=='__main__':unittest.main()
