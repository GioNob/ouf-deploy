"""Ten retained TLS grants, v10 exact review, actual eleventh grant."""
import copy,json,unittest
from pathlib import Path
from unittest.mock import patch
import test_policy_token_ingestion_recovery as previous_fixture
import test_policy_token_postgrant_continuation as base
from tools.chatbot_file_cohort import ingestion_path_recovery as tail
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.supervisor import RenewalWorker
from test_chatbot_cohort_ingestion_path_recovery import receipt

class PathWorker(unittest.TestCase):
    def test_ten_preserved_eleventh_tls_grant_complete_review_no_reset(self):
        previous_test=previous_fixture.IngestionWorker();self.addCleanup(previous_test.doCleanups)
        previous_test.test_nine_preserved_tenth_actual_tls_grant_and_complete_phase6_review()
        h=previous_test.h;old=previous_test.owner;worker=previous_test.worker
        h.f.f.write(h.f.f.mandate,base.existing.fixture.binding.encoded(h.f.f.approval))
        h.f.f.approved=base.existing.fixture.binding.sha(h.f.f.mandate.read_bytes())
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED')
        paths=[old.journal.root/n for n in ('recovery.json','owner-session.json','owner-admission.json')]
        frozen={p:p.read_bytes()for p in paths}
        previous=copy.deepcopy(h.predecessor);previous['review']={'scopes':old.scopes()}
        previous.update(worker=json.loads(paths[0].read_bytes()),session=json.loads(paths[1].read_bytes()),admission=json.loads(paths[2].read_bytes()))
        for name,key in [('WORKER','worker'),('SESSION','session'),('ADMISSION','admission')]:
            self.enterContext(patch.object(tail,name,base.fingerprint(previous[key])))
        tail.validate_worker(previous['firstGrant'],previous['worker'],previous['admission'],previous['session'])
        h.predecessor=previous;h.old=old;h.proof=copy.deepcopy(h.proof)
        h.proof.update(cancelledWorkerHash=tail.WORKER,workerSessionHash=tail.SESSION,retainedFailedIngestion=receipt())
        h.proof['newBudget'].update(priorControlledGrantAttempts=10,priorWorkerGrantAttempts=1,
            reason='QUALIFY_IMAGE_PATH_AFTER_TEN_GRANTS')
        h.directory=h.f.f.root/'ingestion-path-v10';h.directory.mkdir(mode=0o700)
        for name in ('complete-postgrant-review','preserved-backup'):
            (h.f.f.root/name).rename(h.f.f.root/('phase6-'+name))
        def transform(prepared):
            h.phase5_transform(prepared)
            # Review construction uses selected target observations as fixture.
            # The exact PATH change itself is qualified by the private/native suites.
            h.proof['retainedFailedIngestion']['proposedIngestionPlanHash']=base.fingerprint(prepared['cohortPlan']['replacements'][2])
            prepared['postGrantRecovery']['retainedFailedIngestion']=copy.deepcopy(h.proof['retainedFailedIngestion'])
            prepared['registry']['postGrantRecovery']['retainedFailedIngestion']=copy.deepcopy(h.proof['retainedFailedIngestion'])
        review=base.PostGrantOwner.compile_complete_review(h,transform)
        self.assertEqual(review['currentTechnicalPhase'],6);self.assertEqual(review['completedTechnicalPhases'],[1,2,3,4,5])
        self.assertEqual(review['scopes']['policyTokenFiniteWorkerSession']['predecessorGrantAttempts'],10)
        self.assertEqual(h.harness.grants(),10)
        def make():
            return ContinuedOwnerInstallation(AggregateAction(h.f.f.gate(),h.f.f.authority,h.f.f.expected['sourceClosureHash']),
                h.value,h.harness.files,h.proof,previous,h.directory,h.f.clock,transport=h.f.transport)
        h.sign(make().scopes(),'EXACT_V10_PATH_FINITE_HUMAN_DECISION')
        owner=make();new=owner.install()
        self.assertEqual(owner.journal.read()['controlledCumulativeGrantAttempts'],10)
        self.assertEqual(new.tick()['state'],'ACTIVE');self.assertEqual(h.harness.grants(),11)
        owner.observer.guard_worker_session(owner.journal.read())
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):make().install()
        self.assertEqual(RenewalWorker(new.r).tick()['state'],'RECONCILE_REQUIRED')
        for p,raw in frozen.items():self.assertEqual(p.read_bytes(),raw)
        h.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):make().install()
        self.assertEqual(h.harness.grants(),11)

if __name__=='__main__':unittest.main()
