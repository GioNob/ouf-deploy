import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest

from bounded_recovery import Policy, Recovery, Temporary, Permanent
from recovery_journal import Journal

class Clock:
    def __init__(self): self.wall = 100000.; self.mono = 100.
    def __call__(self): return self.wall, self.mono
    def advance(self, seconds): self.wall += seconds; self.mono += seconds

class Memory:
    def __init__(self): self.value = None
    def read(self): return copy.deepcopy(self.value)
    def compare_and_save(self, previous, value):
        if self.value != previous: raise ValueError('RECOVERY_CAS_CONFLICT')
        self.value = copy.deepcopy(value)

class Adapter:
    def __init__(self, clock):
        self.clock = clock; self.until = 0; self.calls = 0; self.publications = []; self.pauses = 0
        self.guard_error = None; self.publish_error = None; self.prepare_delay = 0; self.pause_failed = False
    def guard(self):
        if self.guard_error: raise self.guard_error
    def pause(self):
        self.pauses += 1
        if self.pause_failed: raise RuntimeError('private fixture detail')
    def prepare(self, deadline):
        self.calls += 1; self.clock.advance(self.prepare_delay)
        if self.clock.mono < self.until: raise Temporary('DEPENDENCY_UNAVAILABLE')
        return {'freshAttempt': self.calls}
    def publish(self, evidence, deadline):
        if self.publish_error: raise self.publish_error
        self.publications.append(evidence)
        return 'f' * 64

class Tests(unittest.TestCase):
    def fixture(self, policy=None, journal=None):
        clock = Clock(); adapter = Adapter(clock); journal = journal or Memory()
        recovery = Recovery(journal, adapter, policy or Policy(), 'a'*64, 'b'*64, clock, lambda: .5)
        initial = recovery.initial()
        if isinstance(journal, Journal): journal.initialize(initial)
        else: journal.value = initial
        return clock, adapter, journal, recovery

    def test_four_hour_outage_then_fresh_recovery_no_duplicate_publication(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = clock.mono + 4*3600
        while True:
            row = recovery.step()
            if row['state'] == 'ACTIVE': break
            self.assertEqual(row['state'], 'RETRY_WAIT')
            self.assertEqual(adapter.publications, [])
            clock.advance(row['nextMonotonic'] - clock.mono)
        self.assertGreater(clock.mono, 4*3600); self.assertLess(row['attempts'], 128)
        self.assertEqual(adapter.publications, [{'freshAttempt': row['attempts']}])
        before = adapter.calls; recovery.step(); self.assertEqual(adapter.calls, before)

    def test_incremental_waits_and_no_dependency_probe_before_due(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
        for expected in (5, 15, 60, 300, 900, 900):
            row = recovery.step(); self.assertEqual(row['nextMonotonic'] - clock.mono, expected)
            calls = adapter.calls; recovery.step(); self.assertEqual(adapter.calls, calls)
            clock.advance(expected)

    def test_attempt_budget_exhaustion_stays_paused_without_more_attempts(self):
        clock, adapter, journal, recovery = self.fixture(Policy(max_attempts=3)); adapter.until = 10**9
        for _ in range(2):
            row = recovery.step(); clock.advance(row['nextMonotonic'] - clock.mono)
        row = recovery.step(); self.assertEqual(row['state'], 'PAUSED_EXHAUSTED')
        clock.advance(36000); recovery.step(); self.assertEqual(adapter.calls, 3)

    def test_elapsed_budget_includes_attempt_duration_and_never_publishes_expired_evidence(self):
        clock, adapter, journal, recovery = self.fixture(Policy(max_elapsed=30))
        adapter.prepare_delay = 31
        row = recovery.step(); self.assertEqual(row['state'], 'PAUSED_EXHAUSTED')
        self.assertEqual(adapter.publications, [])

    def test_retry_after_is_never_clamped_to_backoff_cap_and_budget_is_finite(self):
        clock, adapter, journal, recovery = self.fixture()
        adapter.prepare = lambda _: (_ for _ in ()).throw(Temporary('RATE_LIMITED', retry_after=3600))
        row = recovery.step(); self.assertEqual(row['nextMonotonic'] - clock.mono, 3600)
        clock.advance(3600)
        adapter.prepare = lambda _: (_ for _ in ()).throw(Temporary('RATE_LIMITED', retry_after=86400))
        self.assertEqual(recovery.step()['state'], 'PAUSED_EXHAUSTED')

    def test_jitter_is_bounded_and_cap_remains_finite(self):
        for sample, expected in ((0, 4), (1, 6)):
            clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
            recovery.random = lambda: sample
            row = recovery.step(); self.assertEqual(row['nextMonotonic'] - clock.mono, expected)
        with self.assertRaises(ValueError): Policy(max_attempts=0)
        with self.assertRaises(ValueError): Temporary('unknown')

    def test_revocation_is_checked_while_waiting_and_never_retries(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
        recovery.step(); adapter.guard_error = Permanent('AUTHORITY_REVOKED')
        row = recovery.step(); self.assertEqual(row['state'], 'BLOCKED')
        self.assertEqual(row['reason'], 'AUTHORITY_REVOKED'); self.assertEqual(adapter.calls, 1)

    def test_cancel_during_pause_preserves_attempt_budget(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
        recovery.step(); row = recovery.step(cancelled=True)
        self.assertEqual(row['state'], 'CANCELLED'); self.assertEqual(row['attempts'], 1)

    def test_generation_change_or_inflight_restart_requires_reconciliation_without_reset(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
        recovery.step(); recovery.generation = 'c'*64
        row = recovery.step(); self.assertEqual(row['state'], 'RECONCILE_REQUIRED'); self.assertEqual(row['attempts'], 1)
        clock, adapter, journal, recovery = self.fixture()
        journal.value.update(state='PUBLISHING', attempts=7)
        row = recovery.step(); self.assertEqual(row['state'], 'RECONCILE_REQUIRED'); self.assertEqual(row['attempts'], 7)

    def test_ambiguous_publication_never_retries_but_proven_no_effect_can_retry(self):
        for safe, expected in ((False, 'RECONCILE_REQUIRED'), (True, 'RETRY_WAIT')):
            clock, adapter, journal, recovery = self.fixture()
            adapter.publish_error = Temporary('DEPENDENCY_TIMEOUT', no_effect=safe)
            self.assertEqual(recovery.step()['state'], expected)

    def test_unknown_error_and_unproven_pause_are_blocked_without_private_messages(self):
        clock, adapter, journal, recovery = self.fixture()
        adapter.prepare = lambda _: (_ for _ in ()).throw(RuntimeError('fixture-private-token'))
        row = recovery.step(); self.assertEqual(row['state'], 'BLOCKED')
        self.assertNotIn('fixture-private-token', json.dumps(row))
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9; adapter.pause_failed = True
        self.assertEqual(recovery.step()['reason'], 'SAFE_PAUSE_UNPROVEN')

    def test_clock_regression_and_policy_change_do_not_extend_budget(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
        recovery.step(); clock.wall -= 1
        self.assertEqual(recovery.step()['state'], 'BLOCKED')
        clock, adapter, journal, recovery = self.fixture(); recovery.policy = Policy(max_attempts=10)
        with self.assertRaisesRegex(RuntimeError, 'RECOVERY_JOURNAL_OR_STATE_UNPROVEN'): recovery.step()
        self.assertEqual(adapter.calls, 0); self.assertEqual(adapter.pauses, 1)

    def test_storage_failure_before_attempt_or_after_publication_revokes_without_replay(self):
        for fail_at, expected_calls in ((1, 0), (3, 1)):
            clock, adapter, journal, recovery = self.fixture()
            original = journal.compare_and_save; writes = []
            def save(previous, value):
                writes.append(value['state'])
                if len(writes) >= fail_at: raise OSError('fixture-private-storage')
                original(previous, value)
            journal.compare_and_save = save
            with self.assertRaisesRegex(RuntimeError, '^RECOVERY_JOURNAL_OR_STATE_UNPROVEN$'):
                recovery.step()
            self.assertEqual(adapter.calls, expected_calls)
            self.assertGreaterEqual(adapter.pauses, 1)
            self.assertLessEqual(len(adapter.publications), 1)

    def test_forward_wall_adjustment_never_causes_busy_wait_or_early_probe(self):
        clock, adapter, journal, recovery = self.fixture(); adapter.until = 10**9
        row = recovery.step(); clock.wall += 10
        self.assertEqual(recovery.wait_seconds(row), 5)
        self.assertEqual(recovery.step()['state'], 'RETRY_WAIT'); self.assertEqual(adapter.calls, 1)

    def test_actual_posix_journal_persists_and_no_journal_lock_covers_callbacks(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root).chmod(0o700); journal = Journal(root)
            clock, adapter, journal, recovery = self.fixture(journal=journal)
            original = adapter.prepare
            def prepare(deadline):
                fd = os.open(journal.lock, os.O_RDWR)
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(fd)
                return original(deadline)
            adapter.prepare = prepare
            self.assertEqual(recovery.step()['state'], 'ACTIVE')
            self.assertEqual(Journal(root).read()['attempts'], 1)
            with self.assertRaises(FileExistsError): Journal(root).initialize(recovery.initial())
            stale = recovery.initial()
            with self.assertRaisesRegex(ValueError, 'RECOVERY_CAS_CONFLICT'): journal.compare_and_save(stale, stale)
            journal.record.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'RECOVERY_FILE_CUSTODY_REQUIRED'): journal.read()

    def test_exhausted_service_keeps_waiting_without_dependency_retries(self):
        clock, adapter, journal, recovery = self.fixture(Policy(max_attempts=1)); adapter.until = 10**9
        observations = []
        class Stop:
            ticks = 0
            def is_set(self): return self.ticks >= 3
            def wait(self, seconds):
                self.ticks += 1; clock.advance(seconds); return self.is_set()
        recovery.serve(Stop(), lambda row: observations.append(row['state']))
        self.assertEqual(observations, ['PAUSED_EXHAUSTED']*3)
        self.assertEqual(adapter.calls, 1)

if __name__ == '__main__': unittest.main()
