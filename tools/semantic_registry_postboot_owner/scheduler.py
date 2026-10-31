"""Bounded postboot worker; a consumed last grant does not revoke a valid lease."""
import threading

from .contract import HISTORY, PROFILE, LEGACY, digest, require
from tools.semantic_lease_recovery.bounded_recovery import Permanent, number
from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery, RenewalWorker
from tools.semantic_policy_token_owner.producer import protected_directory


class PostbootScheduledRecovery(ScheduledRecovery):
    PROFILE = PROFILE

    def validate(self, row):
        require(row.get('renewalProfile') == self.PROFILE and row.get('controlledHistoryProfile') == HISTORY
                and row.get('intervalSeconds') == self.interval
                and row.get('contextRef') == self.context and row.get('generationRef') == self.generation
                and row.get('policyHash') == digest(__import__('dataclasses').asdict(self.policy))
                and type(row.get('attempts')) is int and 0 <= row['attempts'] <= self.policy.max_attempts
                and type(row.get('controlledPredecessorGrantAttempts')) is int
                and 1 <= row['controlledPredecessorGrantAttempts'] <= 1000000
                and row.get('controlledCumulativeGrantAttempts') == row['controlledPredecessorGrantAttempts'] + row['attempts']
                and row.get('legacyHistory') == LEGACY and type(row.get('publicationCount')) is int
                and 0 <= row['publicationCount'] <= row['attempts'], 'POSTBOOT_SCHEDULE_OR_RETAINED_ACCOUNTING_DRIFT')
        if row['state'] == 'ACTIVE':
            require(all(number(row.get(k)) for k in ('nextRenewalWall', 'nextRenewalMonotonic', 'tokenExpiresWall', 'tokenExpiresMonotonic'))
                    and row['lastWall'] <= row['nextRenewalWall'] < row['tokenExpiresWall']
                    and row['lastMonotonic'] <= row['nextRenewalMonotonic'] < row['tokenExpiresMonotonic'],
                    'POSTBOOT_DURABLE_PUBLISHED_TOKEN_WINDOW_REQUIRED')


class PostbootRenewalWorker(RenewalWorker):
    def __init__(self, recovery, *, heartbeat=5):
        require(type(recovery) is PostbootScheduledRecovery and type(heartbeat) is int and 1 <= heartbeat <= 30,
                'ACTUAL_POSTBOOT_SCHEDULER_REQUIRED')
        self.r, self.heartbeat, self.active_here = recovery, heartbeat, False

    def _tick(self):
        r = self.r; row = r.journal.read()
        try:
            r.adapter.guard()
        except Permanent as error:
            return r.pause(row, 'BLOCKED', error.code)
        except Exception:
            return r.pause(row, 'BLOCKED', 'LOCAL_AUTHORITY_UNPROVEN')
        preceding = row['state']; row = r.step()
        if row['state'] != 'ACTIVE':
            self.active_here = False
            return row
        if preceding != 'ACTIVE':
            self.active_here = True
            return row
        if not self.active_here:
            return r.pause(row, 'RECONCILE_REQUIRED', 'WORKER_INVOCATION_RECONCILIATION_REQUIRED')
        wall, mono = r.now()
        if wall >= row['tokenExpiresWall'] or mono >= row['tokenExpiresMonotonic']:
            self.active_here = False
            return r.pause(row, 'RECONCILE_REQUIRED', 'TOKEN_VALIDITY_WINDOW_EXPIRED')
        if r.remaining(row) <= 0:
            self.active_here = False
            return r.pause(row, 'PAUSED_EXHAUSTED', 'FINITE_OWNER_OPERATION_EXHAUSTED')
        # A positive token window survives consumption of the last permitted
        # grant. It never becomes permission for a fresh grant, longer window,
        # invocation adoption, or an authority/elapsed-time extension.
        if row['attempts'] >= r.policy.max_attempts:
            return row
        if wall < row['nextRenewalWall'] or mono < row['nextRenewalMonotonic']:
            return row
        self.active_here = False
        r.save(row, 'NEW', 'SCHEDULED_RENEWAL_DUE')
        return self._attempt()

    def wait_seconds(self, row):
        if row['state'] == 'ACTIVE' and row['attempts'] >= self.r.policy.max_attempts:
            wall, mono = self.r.now()
            return max(0, min(self.heartbeat, row['tokenExpiresWall']-wall,
                              row['tokenExpiresMonotonic']-mono, self.r.remaining(row)))
        return super().wait_seconds(row)

    def run(self, stop_event, observe=None, coordination_lock=None):
        require(type(stop_event) is threading.Event and (observe is None or callable(observe)),
                'BOUNDED_POSTBOOT_WORKER_CONTROL_REQUIRED')
        lock = threading.RLock() if coordination_lock is None else coordination_lock
        require(type(lock) is type(threading.RLock()), 'SHARED_POSTBOOT_COORDINATION_RLOCK_REQUIRED')
        with protected_directory(self.r.journal.root), self.r.journal.invocation():
            self.active_here = False
            try:
                while not stop_event.is_set():
                    with lock:
                        row = self._advance()
                        if observe is not None:
                            observe(self.status(row))
                        if row['state'] in ('BLOCKED', 'CANCELLED', 'PAUSED_EXHAUSTED', 'RECONCILE_REQUIRED'):
                            return row
                        delay = self.wait_seconds(row)
                    if stop_event.wait(delay):
                        break
                with lock:
                    return self.r.step(cancelled=True)
            except Exception:
                with lock:
                    try:
                        self.r.pause(self.r.journal.read(), 'BLOCKED', 'LOCAL_AUTHORITY_UNPROVEN')
                    finally:
                        self.active_here = False
                raise
            finally:
                with lock:
                    self.active_here = False
                    self.r.adapter.pause()
