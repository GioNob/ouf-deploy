import copy
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bounded_recovery import Policy, Temporary, Permanent
from lease_recovery_budget import LeaseRecovery as Recovery
from recovery_journal import Journal
from continuous_supervisor import Supervisor
from test_bounded_recovery import Clock, Memory, Adapter


class RenewalAdapter(Adapter):
    renewal_error = None
    renewal_calls = 0
    def prepare_renewal(self, deadline):
        self.renewal_calls += 1
        if self.renewal_error: raise self.renewal_error
        return {'fresh': self.renewal_calls}
    def publish_renewal(self, evidence, deadline):
        return self.publish(evidence, deadline)


class Tests(unittest.TestCase):
    def fixture(self, policy=None):
        clock = Clock()
        adapter = RenewalAdapter(clock)
        journal = Memory()
        journal.invocation = nullcontext
        recovery = Recovery(journal, adapter, policy or Policy(), 'a'*64, 'b'*64, clock, lambda: .5)
        journal.value = recovery.initial()
        supervisor = Supervisor(recovery, None, 15)
        schedule_patch = patch('continuous_supervisor.window',
                               side_effect=lambda *a, **kw: self.schedule(clock))
        schedule_patch.start()
        self.addCleanup(schedule_patch.stop)
        return clock, adapter, journal, recovery, supervisor

    def schedule(self, clock):
        return {'waitSeconds': 5, 'deadlineMonotonic': clock.mono + 30,
                'remainingSecondsLowerBound': 30}

    def test_healthy_renewals_do_not_reset_or_spend_recovery_attempts(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        first = supervisor.tick()
        with patch('continuous_supervisor.window', side_effect=lambda *a, **kw: self.schedule(clock)):
            for _ in range(200):
                scheduled = supervisor.tick()
                clock.advance(5)
                self.assertEqual(supervisor.renew(scheduled)['state'], 'ACTIVE')
        self.assertEqual(journal.read()['attempts'], 1)
        self.assertEqual(journal.read()['startedWall'], first['startedWall'])
        self.assertEqual(supervisor.renewals, 200)

    def test_outage_after_healthy_cycle_preserves_budget_then_recovers(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        original = supervisor.tick()
        scheduled = {**original, 'leaseDeadlineMonotonic': clock.mono + 30}
        adapter.renewal_error = Temporary('DNS_UNAVAILABLE')
        row = supervisor.renew(scheduled)
        self.assertEqual(row['state'], 'RETRY_WAIT')
        self.assertEqual(row['attempts'], 1)
        adapter.until = clock.mono + 4*3600
        while clock.mono < adapter.until:
            clock.advance(row['nextMonotonic'] - clock.mono)
            row = supervisor.tick()
        if row['state'] != 'ACTIVE':
            clock.advance(row['nextMonotonic'] - clock.mono)
            row = supervisor.tick()
        self.assertEqual(row['state'], 'ACTIVE')
        self.assertGreater(row['attempts'], 1)
        self.assertEqual(row['startedWall'], original['startedWall'])
        self.assertEqual(row['contextRef'], original['contextRef'])

    def test_expired_schedule_pauses_before_dns(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        supervisor.tick()
        row = supervisor.renew({'leaseDeadlineMonotonic': clock.mono})
        self.assertEqual(row['state'], 'RETRY_WAIT')
        self.assertEqual(adapter.renewal_calls, 0)
        self.assertGreater(adapter.pauses, 0)

    def test_reopened_active_requires_reconciliation_without_new_call(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        supervisor.tick()
        second = Supervisor(recovery, None, 15)
        row = second.tick()
        self.assertEqual(row['state'], 'RECONCILE_REQUIRED')
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(adapter.renewal_calls, 0)

    def test_exhaustion_keeps_liveness_and_revocation_remains_visible(self):
        clock, adapter, journal, recovery, supervisor = self.fixture(Policy(max_attempts=1))
        adapter.until = 10**9
        self.assertEqual(supervisor.tick()['state'], 'PAUSED_EXHAUSTED')
        for _ in range(4):
            clock.advance(5)
            self.assertEqual(supervisor.tick()['state'], 'PAUSED_EXHAUSTED')
        self.assertEqual(adapter.calls, 1)
        adapter.guard_error = Permanent('AUTHORITY_REVOKED')
        self.assertEqual(supervisor.tick()['reason'], 'AUTHORITY_REVOKED')
        self.assertEqual(adapter.calls, 1)

    def test_uncertain_publish_blocks_and_never_replays(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        supervisor.tick()
        adapter.publish_error = Temporary('DEPENDENCY_TIMEOUT')
        row = supervisor.renew({'leaseDeadlineMonotonic': clock.mono + 30})
        self.assertEqual(row['state'], 'RECONCILE_REQUIRED')
        for _ in range(3): supervisor.tick()
        self.assertEqual(adapter.renewal_calls, 1)

    def test_permanent_and_unknown_failure_never_retry(self):
        for error in [Permanent('CONFIGURATION_DRIFT'), RuntimeError('private token')]:
            clock, adapter, journal, recovery, supervisor = self.fixture()
            supervisor.tick()
            adapter.renewal_error = error
            row = supervisor.renew({'leaseDeadlineMonotonic': clock.mono + 30})
            self.assertEqual(row['state'], 'BLOCKED')
            self.assertNotIn('private token', str(row))
            supervisor.tick()
            self.assertEqual(adapter.renewal_calls, 1)

    def test_clock_regression_while_active_revokes(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        supervisor.tick()
        clock.wall -= 1
        self.assertEqual(supervisor.tick()['state'], 'BLOCKED')
        self.assertGreater(adapter.pauses, 0)

    def test_healthy_time_is_not_an_outage_but_real_authority_expiry_blocks(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        supervisor.tick()
        clock.advance(86400)
        self.assertEqual(supervisor.tick()['state'], 'ACTIVE')
        adapter.guard_error = Permanent('AUTHORITY_EXPIRED')
        self.assertEqual(supervisor.tick()['state'], 'BLOCKED')
        self.assertEqual(adapter.renewal_calls, 0)

    def test_cumulative_recovery_time_survives_healthy_interval_without_reset(self):
        clock, adapter, journal, recovery, supervisor = self.fixture(
            Policy(max_elapsed=100, attempt_timeout=30))
        supervisor.tick()
        clock.advance(86400)
        adapter.renewal_error = Temporary('DNS_UNAVAILABLE')
        row = supervisor.renew({'leaseDeadlineMonotonic': clock.mono + 30})
        self.assertEqual(row['state'], 'RETRY_WAIT')
        self.assertEqual(recovery.remaining(row), 100)
        clock.advance(5)
        self.assertEqual(supervisor.tick()['state'], 'ACTIVE')
        self.assertEqual(recovery.remaining(journal.read()), 95)
        clock.advance(86400)
        row = supervisor.renew({'leaseDeadlineMonotonic': clock.mono + 30})
        self.assertEqual(row['state'], 'RETRY_WAIT')
        self.assertEqual(recovery.remaining(row), 95)
        clock.advance(96)
        self.assertEqual(supervisor.tick()['state'], 'PAUSED_EXHAUSTED')
        self.assertEqual(journal.read()['attempts'], 2)

    def test_actual_invocation_fencing_is_separate_from_journal_transactions(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root).chmod(0o700)
            journal = Journal(root)
            _, _, _, recovery, _ = self.fixture()
            journal.initialize(recovery.initial())
            with journal.invocation():
                self.assertEqual(journal.read()['attempts'], 0)
                with self.assertRaises(BlockingIOError):
                    with Journal(root).invocation(): self.fail('second worker admitted')
            with journal.invocation():
                self.assertEqual(journal.read()['attempts'], 0)

    def test_observation_failure_revokes_and_does_not_create_budget(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        class Stop:
            def is_set(self): return False
        def observe(row): raise OSError('private observation failure')
        with self.assertRaises(OSError): supervisor.serve(Stop(), observe)
        self.assertGreater(adapter.pauses, 0)
        self.assertEqual(journal.read()['attempts'], 1)

    def test_first_active_serve_cycle_has_a_real_schedule_and_renews(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        observations = []
        class Stop:
            ticks = 0
            def is_set(self): return self.ticks >= 3
            def wait(self, seconds):
                self.ticks += 1
                clock.advance(seconds)
                return self.is_set()
        with patch('continuous_supervisor.window', side_effect=lambda *a, **kw: self.schedule(clock)):
            supervisor.serve(Stop(), observations.append)
        self.assertTrue(all(row['ready'] for row in observations))
        self.assertEqual(adapter.renewal_calls, 2)
        self.assertEqual(journal.read()['state'], 'CANCELLED')

    def test_zero_ttl_during_status_readback_pauses_without_process_failure(self):
        clock, adapter, journal, recovery, supervisor = self.fixture()
        observations = []
        class Stop:
            ticks = 0
            def is_set(self): return self.ticks >= 3
            def wait(self, seconds):
                self.ticks += 1
                clock.advance(seconds)
                return self.is_set()
        def observe(row):
            observations.append(row['state'])
            if len(observations) == 1:
                error = RuntimeError('NFT_SET_TTL_UNPROVEN')
                error.nft_readback = {'expiresType': 'int', 'expiresValue': 0, 'duplicateAddress': False}
                raise error
        supervisor.serve(Stop(), observe)
        self.assertEqual(observations[:2], ['ACTIVE', 'RETRY_WAIT'])
        self.assertIn('ACTIVE', observations[2:])
        self.assertEqual(journal.read()['state'], 'CANCELLED')


if __name__ == '__main__': unittest.main()
