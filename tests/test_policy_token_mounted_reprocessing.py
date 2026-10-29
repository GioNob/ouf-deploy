"""Actual signed v3 session after three TLS grants; no old token/worker adoption."""
import copy,hashlib,json,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_policy_token_paused_continuation as prior
from tools.chatbot_file_cohort import mounted_recovery as m
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.chatbot_file_cohort.action_process import private_file
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.supervisor import RenewalWorker

class MountedReprocessingOwner(unittest.TestCase):
    def setUp(self):
        h=prior.PausedPublishedWorker();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f
        worker=h.new.install();self.assertEqual(worker.tick()['state'],'ACTIVE')
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED');self.assertEqual(h.h.harness.grants(),3)
        previous=copy.deepcopy(h.previous);previous['review']={'scopes':h.new.scopes()}
        names=('recovery.json','owner-session.json','owner-admission.json');paths=[h.new.journal.root/n for n in names]
        previous.update(worker=json.loads(paths[0].read_bytes()),session=json.loads(paths[1].read_bytes()),admission=json.loads(paths[2].read_bytes()))
        m.validate_worker(previous['firstGrant'],previous['worker'],previous['admission'],previous['session'])
        self.previous=previous;self.preserved={str(p):p.read_bytes()for p in paths}
        self.proof={'profile':m.PROFILE,'cancelledWorkerHash':prior.prior.fingerprint(previous['worker']),
            'workerSessionHash':prior.prior.fingerprint(previous['session']),
            'recordBindings':[{'path':path,'sha256':hashlib.sha256(raw).hexdigest()}for path,raw in self.preserved.items()],
            'newBudget':{**h.proof['newBudget'],'reason':'QUALIFY_CORRECTED_MOUNT_LIFETIME_AFTER_THREE_GRANTS','priorControlledGrantAttempts':3}}
        def fixture_bindings(proof):
            for binding in proof['recordBindings']:private_file(binding,8388608)
        override=patch.object(m,'retained_bindings',side_effect=fixture_bindings);override.start();self.addCleanup(override.stop)
        self.directory=self.f.f.root/'mounted-reprocessing-v3';self.directory.mkdir(mode=0o700)
        self.value={**h.value,'contextRef':'5'*64,'generationRef':'4'*64,'sourceCommit':'d'*40}
        planned=self.make();authority=json.loads(self.f.f.authority);authority.update(planned.scopes())
        self.f.f.authority=prior.prior.existing.fixture.binding.encoded(authority)
        self.f.f.approval.update(approvalRef='NEW_V3_MOUNT_LIFETIME_EXACT_DECISION',executionAuthorityHash=prior.prior.existing.fixture.binding.sha(self.f.f.authority))
        self.f.f.write(self.f.f.mandate,prior.prior.existing.fixture.binding.encoded(self.f.f.approval));self.f.f.approved=prior.prior.existing.fixture.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.new=self.make()
    def make(self):
        action=AggregateAction(self.f.f.gate(),self.f.f.authority,self.f.f.expected['sourceClosureHash'])
        return ContinuedOwnerInstallation(action,self.value,self.h.h.harness.files,self.proof,self.previous,self.directory,self.f.clock,transport=self.f.transport)
    def unchanged(self):
        self.h.unchanged()
        for path,data in self.preserved.items():self.assertEqual(Path(path).read_bytes(),data)
    def test_actual_fourth_grant_and_current_mounted_admission_keep_three_predecessors(self):
        worker=self.new.install();row=self.new.journal.read()
        self.assertEqual(row['attempts'],0);self.assertEqual(row['controlledCumulativeGrantAttempts'],3)
        self.assertFalse(worker.active_here);self.assertEqual(self.h.h.harness.grants(),3)
        row=worker.tick();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['attempts'],1)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],4);self.assertEqual(self.h.h.harness.grants(),4)
        observer=self.new.observer;token=(Path(observer.binding.output_directory)/observer.binding.output_member).read_text()
        before=(observer.journal.read(),observer.store.read(),self.h.h.harness.grants())
        self.assertTrue(observer.admit_mounted(token,30,observer.binding.digest(),time.monotonic()+20))
        self.assertEqual((observer.journal.read(),observer.store.read(),self.h.h.harness.grants()),before);self.unchanged()
        self.assertEqual(RenewalWorker(worker.r).tick()['state'],'RECONCILE_REQUIRED')
        self.assertEqual(self.h.h.harness.grants(),4);self.unchanged()
    def test_changed_prior_v2_session_or_counter_reset_does_not_admit(self):
        self.new.install();row=self.new.journal.read()
        with self.assertRaises(Exception):self.new.observer.guard_worker_session({**row,'controlledPredecessorGrantAttempts':2,'controlledCumulativeGrantAttempts':2})
        path=self.directory/'owner-predecessor-session.json';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(Exception):self.new.observer._verified_state(self.new.first.binding.digest())
        self.assertEqual(self.h.h.harness.grants(),3);self.unchanged()
    def test_revoked_current_human_denies_new_worker_before_grant(self):
        self.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.h.h.harness.grants(),3);self.unchanged()
    def test_active_previous_worker_or_relabelled_prior_count_is_not_new_budget(self):
        for key,value in(('state','ACTIVE'),('controlledCumulativeGrantAttempts',2),('controlledPredecessorGrantAttempts',1)):
            previous=copy.deepcopy(self.previous);previous['worker'][key]=value
            with self.subTest(key=key),self.assertRaises(Exception):
                ContinuedOwnerInstallation(self.new.action,self.value,self.h.h.harness.files,self.proof,previous,self.directory,self.f.clock,transport=self.f.transport)
        self.assertEqual(self.h.h.harness.grants(),3);self.unchanged()
    def test_complete_review_compiles_v3_session_with_retained_output_and_no_target_effects(self):
        self.predecessor=self.previous;self.harness=self.h.h.harness;self.old=self.h.new
        prior.prior.PostGrantOwner.test_complete_review_compiles_new_worker_with_retained_output_and_backup_without_effects(self)
    def test_initialization_or_relaunch_never_reuses_the_previous_token(self):
        self.new.install()
        with self.assertRaises(Exception):self.new.observer.guard(self.new.first.binding.digest())
        before={p.name:p.read_bytes()for p in self.directory.iterdir()}
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):self.make().install()
        self.assertEqual(before,{p.name:p.read_bytes()for p in self.directory.iterdir()});self.assertEqual(self.h.h.harness.grants(),3);self.unchanged()

if __name__=='__main__':unittest.main()
