"""Real TLS renewal after two consumed grants; signed immutable history chain.

Only fixed VPS paths/systemctl/IAM administration use the existing fixtures.
The actual group custody, signatures, HTTP/JWT checks and source guard run in CI.
"""
import copy,dataclasses,hashlib,json,unittest
from pathlib import Path
from unittest.mock import patch
import test_policy_token_postgrant_continuation as prior
from tools.chatbot_file_cohort import paused_recovery as p
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.supervisor import RenewalWorker
from tools.chatbot_file_cohort.action_process import private_file

class PausedPublishedWorker(unittest.TestCase):
    def setUp(self):
        h=prior.PostGrantOwner('test_new_accounted_tls_grant_is_required_and_old_history_stays_immutable')
        self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f
        worker=h.new.install();self.assertEqual(worker.tick()['state'],'ACTIVE')
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED')
        self.assertEqual(h.harness.grants(),2)
        previous=copy.deepcopy(h.predecessor);previous['review']={'scopes':h.new.scopes()}
        paths={name:h.new.journal.root/name for name in('recovery.json','owner-session.json','owner-admission.json')}
        previous.update(worker=json.loads(paths['recovery.json'].read_bytes()),session=json.loads(paths['owner-session.json'].read_bytes()),
            admission=json.loads(paths['owner-admission.json'].read_bytes()))
        p.validate_worker(previous['firstGrant'],previous['worker'],previous['admission'],previous['session'])
        self.previous=previous;self.preserved={str(path):path.read_bytes()for path in paths.values()}
        self.proof={'profile':p.PROFILE,'cancelledWorkerHash':prior.fingerprint(previous['worker']),
            'workerSessionHash':prior.fingerprint(previous['session']),'recordBindings':[{'path':path,'sha256':hashlib.sha256(raw).hexdigest()}for path,raw in self.preserved.items()],
            'newBudget':{**h.proof['newBudget'],'reason':'FIXED_UNSIGNED_PAUSED_ATTESTATION_AFTER_CUMULATIVE_TWO',
                'priorControlledGrantAttempts':2,'priorWorkerGrantAttempts':1}}
        def fixture_bindings(proof):
            for binding in proof['recordBindings']:private_file(binding,8388608)
        override=patch.object(p,'retained_bindings',side_effect=fixture_bindings);override.start();self.addCleanup(override.stop)
        self.directory=self.f.f.root/'paused-distinct-new-worker';self.directory.mkdir(mode=0o700)
        self.value={**h.value,'contextRef':'7'*64,'generationRef':'6'*64,'sourceCommit':'c'*40}
        planned=self.make();authority=json.loads(self.f.f.authority);authority.update(planned.scopes())
        self.f.f.authority=prior.existing.fixture.binding.encoded(authority)
        self.f.f.approval.update(approvalRef='EXACT_PAUSED_NEW_FINITE_WORKER_DECISION',
            executionAuthorityHash=prior.existing.fixture.binding.sha(self.f.f.authority))
        self.f.f.write(self.f.f.mandate,prior.existing.fixture.binding.encoded(self.f.f.approval))
        self.f.f.approved=prior.existing.fixture.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.new=self.make()
    def make(self):
        action=AggregateAction(self.f.f.gate(),self.f.f.authority,self.f.f.expected['sourceClosureHash'])
        return ContinuedOwnerInstallation(action,self.value,self.h.harness.files,self.proof,self.previous,
            self.directory,self.f.clock,transport=self.f.transport)
    def unchanged(self):
        self.h.unchanged()
        for path,raw in self.preserved.items():self.assertEqual(Path(path).read_bytes(),raw)
    def test_prior_two_are_retained_and_new_real_tls_attempt_is_cumulative_three(self):
        worker=self.new.install();row=self.new.journal.read()
        self.assertEqual(row['attempts'],0);self.assertEqual(row['controlledCumulativeGrantAttempts'],2)
        self.assertEqual(self.h.harness.grants(),2);self.assertFalse(worker.active_here)
        row=worker.tick();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['attempts'],1)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],3);self.assertEqual(self.h.harness.grants(),3)
        self.new.observer.guard(self.new.first.binding.digest());self.unchanged()
        self.assertEqual(RenewalWorker(worker.r).tick()['state'],'RECONCILE_REQUIRED')
        self.assertEqual(self.h.harness.grants(),3);self.unchanged()
    def test_changed_prior_history_denies_before_grant(self):
        self.new.install();path=self.directory/'owner-predecessor-worker.json';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(Exception):self.new.observer._verified_state(self.new.first.binding.digest())
        self.assertEqual(self.h.harness.grants(),2);self.unchanged()
    def test_counter_reset_or_relabelled_history_is_not_admitted(self):
        self.new.install();row=self.new.journal.read();bad={**row,'controlledPredecessorGrantAttempts':1,'controlledCumulativeGrantAttempts':1}
        with self.assertRaises(Exception):self.new.observer.guard_worker_session(bad)
        self.assertEqual(self.h.harness.grants(),2);self.unchanged()
    def test_revoked_human_does_not_open_another_worker_or_reuse_first_token(self):
        self.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.h.harness.grants(),2);self.unchanged()

if __name__=='__main__':unittest.main()
