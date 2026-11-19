"""Actual signed v5 owner, seventh TLS grant and mounted admission after five grants."""
import copy,hashlib,json,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_policy_token_backup_recovery as prior
import test_policy_token_postgrant_continuation as base
from tools.chatbot_file_cohort import migration_recovery as s
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.chatbot_file_cohort.action_process import private_file
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.supervisor import RenewalWorker

class MigrationRecoveryOwner(unittest.TestCase):
    def setUp(self):
        h=prior.BackupRecoveryOwner();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f
        self.harness=h.harness
        worker=h.new.install();self.assertEqual(worker.tick()['state'],'ACTIVE')
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED');self.assertEqual(self.harness.grants(),6)
        previous=copy.deepcopy(h.previous);previous['review']={'scopes':h.new.scopes()}
        paths=[h.new.journal.root/n for n in('recovery.json','owner-session.json','owner-admission.json')]
        previous.update(worker=json.loads(paths[0].read_bytes()),session=json.loads(paths[1].read_bytes()),admission=json.loads(paths[2].read_bytes()))
        s.validate_worker(previous['firstGrant'],previous['worker'],previous['admission'],previous['session'])
        self.previous=previous;self.preserved={str(p):p.read_bytes()for p in paths}
        self.proof={'profile':s.PROFILE,'cancelledWorkerHash':base.fingerprint(previous['worker']),
            'workerSessionHash':base.fingerprint(previous['session']),
            'recordBindings':[{'path':path,'sha256':hashlib.sha256(raw).hexdigest()}for path,raw in self.preserved.items()],
            'newBudget':{**h.proof['newBudget'],'reason':'QUALIFY_CREATED_MIGRATION_AFTER_SIX_GRANTS','priorControlledGrantAttempts':6}}
        def bindings(proof):
            for binding in proof['recordBindings']:private_file(binding,8388608)
        override=patch.object(s,'retained_bindings',side_effect=bindings);override.start();self.addCleanup(override.stop)
        self.directory=self.f.f.root/'migration-recovery-v6';self.directory.mkdir(mode=0o700)
        self.value={**h.value,'contextRef':'4'*64,'generationRef':'2'*64,'sourceCommit':'e'*40}
        planned=self.make();authority=json.loads(self.f.f.authority);authority.update(planned.scopes())
        self.f.f.authority=base.existing.fixture.binding.encoded(authority)
        self.f.f.approval.update(approvalRef='NEW_V6_SIGNED_CHECKPOINT_EXACT_DECISION',executionAuthorityHash=base.existing.fixture.binding.sha(self.f.f.authority))
        self.f.f.write(self.f.f.mandate,base.existing.fixture.binding.encoded(self.f.f.approval));self.f.f.approved=base.existing.fixture.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.new=self.make()
    def make(self):
        action=AggregateAction(self.f.f.gate(),self.f.f.authority,self.f.f.expected['sourceClosureHash'])
        return ContinuedOwnerInstallation(action,self.value,self.harness.files,self.proof,self.previous,self.directory,self.f.clock,transport=self.f.transport)
    def unchanged(self):
        self.h.unchanged()
        for path,data in self.preserved.items():self.assertEqual(Path(path).read_bytes(),data)
    def test_actual_seventh_grant_and_mounted_admission_preserve_six_predecessors(self):
        worker=self.new.install();row=self.new.journal.read();self.assertEqual(row['controlledCumulativeGrantAttempts'],6)
        self.assertEqual(row['attempts'],0);self.assertFalse(worker.active_here);self.assertEqual(self.harness.grants(),6)
        row=worker.tick();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['controlledCumulativeGrantAttempts'],7)
        self.assertEqual(row['attempts'],1);self.assertEqual(self.harness.grants(),7)
        observer=self.new.observer;token=(Path(observer.binding.output_directory)/observer.binding.output_member).read_text()
        before=(observer.journal.read(),observer.store.read(),self.harness.grants())
        self.assertTrue(observer.admit_mounted(token,30,observer.binding.digest(),time.monotonic()+20))
        self.assertEqual((observer.journal.read(),observer.store.read(),self.harness.grants()),before)
        self.assertEqual(RenewalWorker(worker.r).tick()['state'],'RECONCILE_REQUIRED');self.assertEqual(self.harness.grants(),7);self.unchanged()
    def test_prior_v5_session_or_counter_reset_cannot_admit(self):
        self.new.install();row=self.new.journal.read()
        with self.assertRaises(Exception):self.new.observer.guard_worker_session({**row,'controlledPredecessorGrantAttempts':5,'controlledCumulativeGrantAttempts':5})
        path=self.directory/'owner-predecessor-session.json';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(Exception):self.new.observer._verified_state(self.new.first.binding.digest())
        self.assertEqual(self.harness.grants(),6);self.unchanged()
    def test_revoked_current_human_denies_before_seventh_grant(self):
        self.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.harness.grants(),6);self.unchanged()
    def test_complete_review_compiles_v6_session_without_target_effects(self):
        self.predecessor=self.previous;self.old=self.h.new
        base.PostGrantOwner.test_complete_review_compiles_new_worker_with_retained_output_and_backup_without_effects(self)
    def test_duplicate_install_never_adopts_previous_token_or_resets_budget(self):
        self.new.install()
        with self.assertRaises(Exception):self.new.observer.guard(self.new.first.binding.digest())
        before={p.name:p.read_bytes()for p in self.directory.iterdir()}
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):self.make().install()
        self.assertEqual(before,{p.name:p.read_bytes()for p in self.directory.iterdir()});self.assertEqual(self.harness.grants(),6);self.unchanged()

if __name__=='__main__':unittest.main()
