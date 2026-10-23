"""Real journal/renewal adapter and finite scheduler; IAM/authority/writer simulated.

These tests prove accounting/crash behavior, not issuer or bootstrap admission.
The separate native qualification uses actual TLS/IAM and typed signed scopes.
"""
import os
from pathlib import Path
import tempfile
import unittest

from tools.semantic_registry_postboot_owner import contract as c
from tools.semantic_registry_postboot_owner.scheduler import PostbootScheduledRecovery, PostbootRenewalWorker
from tools.semantic_lease_recovery.bounded_recovery import Policy, Temporary
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import Binding, CredentialFile, DomainOwner, HttpsGrant, TokenRenewalAdapter

ROOT = Path(__file__).resolve().parents[3]


class SimulatedOwner(DomainOwner):
    def __init__(self, binding):
        self.binding, self.pauses, self.allow = binding, 0, True
    def guard(self, binding_hash):
        c.require(self.allow and binding_hash == self.binding.digest(), 'SIMULATED_OWNER_REVOKED')
    def prepare(self, binding_hash, deadline):
        self.guard(binding_hash)
    def admit(self, token, expires, binding_hash, deadline):
        self.guard(binding_hash)
        return True
    def pause(self):
        self.pauses += 1


class Scheduler(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        output = self.root/'output'; output.mkdir(mode=0o750)
        credential = self.root/'client-secret'; credential.write_text('DISPOSABLE'); credential.chmod(0o400)
        self.binding = Binding('https://fixture.invalid/token','fixture','policy:read',str(output),'token.jwt',10001,
            minimum_remaining=1,maximum_token_seconds=3600)
        self.owner = SimulatedOwner(self.binding); self.clock_values = [1000.,100.]
        clock = lambda: tuple(self.clock_values)
        self.calls = 0; self.transport = HttpsGrant(clock)
        def grant(*_):
            self.calls += 1
            return {'access_token': 'DISPOSABLE-TOKEN', 'expires_in': 300, 'token_type': 'Bearer'}
        self.transport.request = grant
        self.adapter = TokenRenewalAdapter(self.binding,CredentialFile(credential),self.owner,self.transport,clock)
        # Scratch cannot chown to the production application gid. The native
        # fixture exercises the real AtomicTokenFile separately on Docker CI.
        self.adapter.writer.check_custody = lambda: None
        def publish(token, guard):
            guard(); (output/'token.jwt').write_text(token)
            return c.digest({'simulatedPublication': True})
        self.adapter.writer.publish = publish
        directory = self.root/'worker'; directory.mkdir(mode=0o700)
        self.journal = Journal(directory); self.policy = Policy(max_attempts=1,max_elapsed=600,attempt_timeout=30)
        self.recovery = PostbootScheduledRecovery(self.journal,self.adapter,self.policy,'a'*64,'b'*64,clock,lambda: .5,
            interval_seconds=60)
        row = self.recovery.initial()
        row.update(workerSessionHash='c'*64,controlledHistoryProfile=c.HISTORY,controlledPredecessorGrantAttempts=319,
            controlledCumulativeGrantAttempts=319,legacyHistory=dict(c.LEGACY))
        self.journal.initialize(row); self.worker = PostbootRenewalWorker(self.recovery)

    def advance(self, seconds):
        self.clock_values[:] = [value+seconds for value in self.clock_values]

    def test_only_permitted_grant_publishes_320_and_keeps_valid_lease_after_renewal_due(self):
        row = self.worker.tick()
        self.assertEqual(row['state'],'ACTIVE'); self.assertEqual(row['attempts'],1)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],320)
        self.advance(61)
        after = self.worker.tick()
        self.assertEqual(after,row); self.assertEqual(self.calls,1); self.assertEqual(self.owner.pauses,0)
        self.assertEqual((Path(self.binding.output_directory)/'token.jwt').read_text(),'DISPOSABLE-TOKEN')

    def test_new_invocation_cannot_adopt_previously_active_lease(self):
        self.worker.tick()
        replacement = PostbootRenewalWorker(self.recovery)
        row = replacement.tick()
        self.assertEqual(row['state'],'RECONCILE_REQUIRED')
        self.assertEqual(row['reason'],'WORKER_INVOCATION_RECONCILIATION_REQUIRED')
        self.assertEqual(self.calls,1); self.assertEqual(row['controlledCumulativeGrantAttempts'],320)

    def test_token_expiry_revokes_without_new_budget_or_grant(self):
        self.worker.tick(); self.advance(300)
        row = self.worker.tick()
        self.assertEqual(row['state'],'RECONCILE_REQUIRED')
        self.assertEqual(row['reason'],'TOKEN_VALIDITY_WINDOW_EXPIRED'); self.assertEqual(self.calls,1)

    def test_ambiguous_grant_is_counted_and_never_automatically_replayed(self):
        def ambiguous(*_):
            self.calls += 1
            raise Temporary('DEPENDENCY_TIMEOUT', no_effect=False)
        self.transport.request = ambiguous
        row = self.worker.tick()
        self.assertEqual(row['state'],'RECONCILE_REQUIRED')
        self.assertEqual(row['controlledCumulativeGrantAttempts'],320)
        self.worker.tick(); self.assertEqual(self.calls,1)
        self.assertFalse((Path(self.binding.output_directory)/'token.jwt').exists())

    def test_interrupted_publishing_is_not_resubmitted(self):
        row = self.journal.read()
        self.journal.compare_and_save(row,{**row,'state':'PUBLISHING','attempts':1,'controlledCumulativeGrantAttempts':320})
        after = self.worker.tick()
        self.assertEqual(after['state'],'RECONCILE_REQUIRED')
        self.assertEqual(after['reason'],'INTERRUPTED_ATTEMPT_REQUIRES_RECONCILIATION')
        self.assertEqual(self.calls,0)

    def test_revocation_while_active_preserves_counter_and_blocks_further_publication(self):
        self.worker.tick(); self.owner.allow = False
        row = self.worker.tick()
        self.assertEqual(row['state'],'BLOCKED'); self.assertEqual(row['controlledCumulativeGrantAttempts'],320)
        self.assertEqual(self.calls,1)


if __name__ == '__main__':
    unittest.main()
