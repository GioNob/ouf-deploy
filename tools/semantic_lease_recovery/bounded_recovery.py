"""Bounded durable recovery protocol; never creates grants or activation claims.

Adapters own fresh evidence, safe pause/revocation, idempotence and publication.
Journal CAS is short; no callback or wait executes inside that transaction.
An ATTEMPTING/PUBLISHING record after interruption requires reconciliation.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re

TRANSIENT = {'DNS_UNAVAILABLE', 'DNS_WINDOW_TOO_SHORT', 'DEPENDENCY_UNAVAILABLE',
             'DEPENDENCY_TIMEOUT', 'RATE_LIMITED', 'SERVICE_UNAVAILABLE'}
PERMANENT = {'AUTHORITY_REVOKED', 'AUTHORITY_EXPIRED', 'GENERATION_CHANGED',
             'CONFIGURATION_DRIFT', 'INTEGRITY_UNPROVEN', 'PERMANENT_FAILURE'}
PARKED = {'ACTIVE', 'PAUSED_EXHAUSTED', 'BLOCKED', 'RECONCILE_REQUIRED', 'CANCELLED'}

def require(value, reason):
    if not value: raise ValueError(reason)

def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

@dataclass(frozen=True)
class Policy:
    delays: tuple = (5, 15, 60, 300, 900)
    max_attempts: int = 128
    max_elapsed: int = 86400
    attempt_timeout: int = 30
    jitter: float = .2

    def __post_init__(self):
        require(type(self.delays) is tuple and bool(self.delays)
                and all(type(v) is int and 1 <= v <= 86400 for v in self.delays)
                and tuple(sorted(self.delays)) == self.delays, 'BOUNDED_INCREMENTAL_DELAYS_REQUIRED')
        require(type(self.max_attempts) is int and 1 <= self.max_attempts <= 10000
                and type(self.max_elapsed) is int and 1 <= self.max_elapsed <= 2592000
                and type(self.attempt_timeout) is int and 1 <= self.attempt_timeout <= self.max_elapsed
                and type(self.jitter) in (float, int) and math.isfinite(self.jitter) and 0 <= self.jitter <= .5,
                'FINITE_RETRY_POLICY_REQUIRED')

class Temporary(Exception):
    def __init__(self, code, *, retry_after=0, no_effect=False):
        require(code in TRANSIENT and number(retry_after) and type(no_effect) is bool,
                'EXPLICIT_TRANSIENT_CLASS_REQUIRED')
        self.code, self.retry_after, self.no_effect = code, retry_after, no_effect
        super().__init__(code)

class Permanent(Exception):
    def __init__(self, code):
        require(code in PERMANENT, 'EXPLICIT_PERMANENT_CLASS_REQUIRED')
        self.code = code
        super().__init__(code)

class Recovery:
    def __init__(self, journal, adapter, policy, context_ref, generation_ref, clock, random_value):
        require(all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in (context_ref, generation_ref)),
                'IMMUTABLE_CONTEXT_AND_GENERATION_REFS_REQUIRED')
        self.journal, self.adapter, self.policy = journal, adapter, policy
        self.context, self.generation = context_ref, generation_ref
        self.clock, self.random = clock, random_value

    def now(self):
        wall, monotonic = self.clock()
        require(number(wall) and number(monotonic), 'FINITE_CLOCKS_REQUIRED')
        return wall, monotonic

    def initial(self):
        wall, mono = self.now()
        return {'schema': 'ouf.bounded-recovery.v1', 'contextRef': self.context, 'generationRef': self.generation,
                'policyHash': fingerprint(asdict(self.policy)), 'state': 'NEW', 'attempts': 0,
                'startedWall': wall, 'startedMonotonic': mono, 'lastWall': wall, 'lastMonotonic': mono,
                'nextWall': None, 'nextMonotonic': None, 'reason': 'NONE'}

    def save(self, previous, state, reason, **values):
        wall, mono = self.now()
        require(state in PARKED | {'NEW', 'RETRY_WAIT', 'ATTEMPTING', 'PUBLISHING'}, 'KNOWN_RECOVERY_STATE_REQUIRED')
        require(type(reason) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason), 'SAFE_REASON_REQUIRED')
        row = {**previous, **values, 'state': state, 'reason': reason, 'lastWall': wall, 'lastMonotonic': mono}
        self.journal.compare_and_save(previous, row)
        return row

    def remaining(self, row):
        wall, mono = self.now()
        return min(self.policy.max_elapsed - (wall - row['startedWall']),
                   self.policy.max_elapsed - (mono - row['startedMonotonic']))

    def pause(self, row, state, reason):
        # A failed/unknown revocation can never be advertised as safely paused.
        try:
            self.adapter.pause()
        except Exception:
            return self.save(row, 'BLOCKED', 'SAFE_PAUSE_UNPROVEN', nextWall=None, nextMonotonic=None)
        return self.save(row, state, reason, nextWall=None, nextMonotonic=None)

    def retry(self, row, error):
        try:
            self.adapter.pause()
        except Exception:
            return self.save(row, 'BLOCKED', 'SAFE_PAUSE_UNPROVEN', nextWall=None, nextMonotonic=None)
        remaining = self.remaining(row)
        if row['attempts'] >= self.policy.max_attempts or remaining <= 0:
            return self.save(row, 'PAUSED_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED', nextWall=None, nextMonotonic=None)
        random = self.random()
        require(number(random) and random <= 1, 'BOUNDED_JITTER_REQUIRED')
        base = self.policy.delays[min(max(row['attempts'] - 1, 0), len(self.policy.delays) - 1)]
        delay = min(self.policy.delays[-1], base * (1 - self.policy.jitter + 2 * self.policy.jitter * random))
        delay = max(delay, error.retry_after)
        if delay >= remaining:
            return self.save(row, 'PAUSED_EXHAUSTED', 'NO_RETRY_WINDOW_WITHIN_BUDGET', nextWall=None, nextMonotonic=None)
        wall, mono = self.now()
        return self.save(row, 'RETRY_WAIT', error.code, nextWall=wall + delay, nextMonotonic=mono + delay)

    def step(self, *, cancelled=False):
        row = self.journal.read()
        require(type(row) is dict and row.get('schema') == 'ouf.bounded-recovery.v1', 'RECOVERY_JOURNAL_REQUIRED')
        require(row.get('contextRef') == self.context and row.get('policyHash') == fingerprint(asdict(self.policy)),
                'RECOVERY_CONTEXT_OR_POLICY_DRIFT')
        if row['generationRef'] != self.generation:
            return self.pause(row, 'RECONCILE_REQUIRED', 'GENERATION_RECONCILIATION_REQUIRED')
        wall, mono = self.now()
        if wall < row['lastWall'] or mono < row['lastMonotonic']:
            return self.pause(row, 'BLOCKED', 'CLOCK_REGRESSION')
        if cancelled:
            return self.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')
        if row['state'] in PARKED:
            return row
        if row['state'] in {'ATTEMPTING', 'PUBLISHING'}:
            return self.pause(row, 'RECONCILE_REQUIRED', 'INTERRUPTED_ATTEMPT_REQUIRES_RECONCILIATION')
        require(row['state'] in {'NEW', 'RETRY_WAIT'} and type(row['attempts']) is int and row['attempts'] >= 0,
                'RECOVERY_STATE_UNPROVEN')
        # Only local authority/configuration/generation checks belong here.
        # No dependency probes are made during the backoff interval.
        try:
            self.adapter.guard()
        except Permanent as error:
            return self.pause(row, 'BLOCKED', error.code)
        except Exception:
            return self.pause(row, 'BLOCKED', 'LOCAL_AUTHORITY_UNPROVEN')
        if self.remaining(row) <= 0 or row['attempts'] >= self.policy.max_attempts:
            return self.pause(row, 'PAUSED_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED')
        if row['state'] == 'RETRY_WAIT':
            if wall < row['nextWall'] or mono < row['nextMonotonic']:
                return row
        row = self.save(row, 'ATTEMPTING', 'FRESH_ATTEMPT', attempts=row['attempts'] + 1,
                        nextWall=None, nextMonotonic=None)
        deadline = mono + min(self.policy.attempt_timeout, self.remaining(row))
        try:
            # Prepare has no durable effect and never reuses preceding evidence.
            evidence = self.adapter.prepare(deadline)
            self.adapter.guard()
            if self.now()[1] >= deadline or self.remaining(row) <= 0:
                raise Temporary('DEPENDENCY_TIMEOUT')
            row = self.save(row, 'PUBLISHING', 'FRESH_EVIDENCE_READY')
            result_ref = self.adapter.publish(evidence, deadline)
            if self.now()[1] >= deadline or self.remaining(row) <= 0:
                return self.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_DEADLINE_UNPROVEN')
            require(type(result_ref) is str and re.fullmatch('[0-9a-f]{64}', result_ref), 'DURABLE_RESULT_REF_REQUIRED')
            return self.save(row, 'ACTIVE', 'RECOVERED', resultRef=result_ref)
        except Temporary as error:
            if row['state'] == 'PUBLISHING' and not error.no_effect:
                return self.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS')
            return self.retry(row, error)
        except Permanent as error:
            return self.pause(row, 'BLOCKED', error.code)
        except Exception:
            state = 'RECONCILE_REQUIRED' if row['state'] == 'PUBLISHING' else 'BLOCKED'
            return self.pause(row, state, 'UNCLASSIFIED_FAILURE')

    def wait_seconds(self, row, heartbeat=5):
        require(type(heartbeat) is int and 1 <= heartbeat <= 30, 'BOUNDED_LOCAL_HEARTBEAT_REQUIRED')
        if row['state'] != 'RETRY_WAIT': return heartbeat
        wall, mono = self.now()
        return max(0, min(heartbeat, row['nextWall'] - wall, row['nextMonotonic'] - mono))

    def serve(self, stop, observe):
        """Keep paused process alive; return success to its normal owner loop."""
        while not stop.is_set():
            row = self.step()
            observe(row)  # Owner persists/deduplicates events; no raw exception.
            if row['state'] == 'ACTIVE': return row
            if stop.wait(self.wait_seconds(row)): break
        return self.step(cancelled=True)
