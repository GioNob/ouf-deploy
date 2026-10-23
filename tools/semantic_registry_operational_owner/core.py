"""Durable renewal scheduling. No endpoint, credential, installer or authority defaults.

This core never treats installation approval as IAM permission. Native adapters
must check installation custody, current service binding and online IAM admission.
Unknown grant/publication outcomes park; no same-attempt redispatch is possible.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math


class Denied(RuntimeError): pass


class NotSubmitted(RuntimeError):
    """Native adapter proof that this whole grant attempt sent no request."""
    def __init__(self, reason='DEPENDENCY_UNAVAILABLE_BEFORE_SUBMISSION'):
        self.reason = reason
        super().__init__(reason)


def require(ok, reason):
    if not ok: raise Denied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value): return hashlib.sha256(encoded(value)).hexdigest()


def integer(value, low, high): return type(value) is int and low <= value <= high


def number(value): return type(value) in (int, float) and math.isfinite(value) and value >= 0


@dataclass(frozen=True)
class RenewalPolicy:
    minimum_interval_seconds: int
    renew_before_seconds: int
    expiry_safety_seconds: int
    maximum_attempts_per_hour: int
    maximum_consecutive_failures: int
    attempt_timeout_seconds: int
    failure_delays: tuple

    def __post_init__(self):
        require(integer(self.minimum_interval_seconds, 10, 3600)
                and integer(self.renew_before_seconds, 15, 3600)
                and integer(self.expiry_safety_seconds, 1, 60)
                and self.expiry_safety_seconds < self.renew_before_seconds
                and integer(self.maximum_attempts_per_hour, 1, 360)
                and integer(self.maximum_consecutive_failures, 1, 10)
                and integer(self.attempt_timeout_seconds, 1, 30)
                and type(self.failure_delays) is tuple and 1 <= len(self.failure_delays) <= 10
                and all(integer(x, 1, 3600) for x in self.failure_delays)
                and list(self.failure_delays) == sorted(self.failure_delays), 'BOUNDED_OPERATIONAL_RENEWAL_POLICY_REQUIRED')

    @property
    def sha256(self): return digest(asdict(self))


STATES = frozenset(('READY', 'RESERVED', 'DISPATCHING', 'PUBLISHING', 'ACTIVE', 'RETRY_WAIT', 'BLOCKED', 'REVOKED'))
FIELDS = frozenset(('schema', 'installationHash', 'policyHash', 'predecessorInputsHash', 'version', 'state',
                    'priorControlledAttempts', 'attempts', 'cumulativeAttempts', 'publications', 'consecutiveFailures',
                    'hourlyAttemptsWall', 'bootId', 'lastWall', 'lastMono', 'nextWall', 'nextMono',
                    'tokenExpiresWall', 'tokenExpiresMono', 'tokenHash', 'attemptId', 'reason'))


def initial(installation_hash, predecessor_hash, prior, policy, boot, clocks):
    require(integer(prior, 1, 1000000000) and type(policy) is RenewalPolicy
            and type(boot) is str and boot and all(number(x) for x in clocks), 'EXACT_OPERATIONAL_INITIAL_INPUTS_REQUIRED')
    for value in (installation_hash, predecessor_hash):
        require(type(value) is str and len(value) == 64 and set(value) <= set('0123456789abcdef'), 'EXACT_OPERATIONAL_INITIAL_HASHES_REQUIRED')
    wall, mono = clocks
    return dict(schema='ouf.registry-operational-token-ledger.v1', installationHash=installation_hash,
                policyHash=policy.sha256, predecessorInputsHash=predecessor_hash, version=0, state='READY',
                priorControlledAttempts=prior, attempts=0, cumulativeAttempts=prior, publications=0,
                consecutiveFailures=0, hourlyAttemptsWall=[], bootId=boot, lastWall=wall, lastMono=mono,
                nextWall=wall, nextMono=mono, tokenExpiresWall=None, tokenExpiresMono=None,
                tokenHash=None, attemptId=None, reason='INSTALLED_NO_TOKEN_REQUESTED')


def validate(row, policy):
    require(type(row) is dict and set(row) == FIELDS and row['schema'] == 'ouf.registry-operational-token-ledger.v1'
            and row['policyHash'] == policy.sha256 and row['state'] in STATES, 'EXACT_OPERATIONAL_LEDGER_REQUIRED')
    for key in ('installationHash', 'policyHash', 'predecessorInputsHash'):
        require(type(row[key]) is str and len(row[key]) == 64 and set(row[key]) <= set('0123456789abcdef'), 'OPERATIONAL_LEDGER_HASH_REQUIRED')
    require(integer(row['version'], 0, 1000000000000) and integer(row['priorControlledAttempts'], 1, 1000000000)
            and integer(row['attempts'], 0, 1000000000000)
            and type(row['cumulativeAttempts']) is int
            and row['cumulativeAttempts'] == row['priorControlledAttempts'] + row['attempts']
            and integer(row['publications'], 0, row['attempts'])
            and integer(row['consecutiveFailures'], 0, row['attempts'])
            and type(row['hourlyAttemptsWall']) is list
            and len(row['hourlyAttemptsWall']) <= policy.maximum_attempts_per_hour
            and all(number(x) for x in row['hourlyAttemptsWall'])
            and row['hourlyAttemptsWall'] == sorted(row['hourlyAttemptsWall']), 'OPERATIONAL_ACCOUNTING_DRIFT')
    require(type(row['bootId']) is str and bool(row['bootId']) and number(row['lastWall']) and number(row['lastMono'])
            and all(row[k] is None or number(row[k]) for k in ('nextWall', 'nextMono', 'tokenExpiresWall', 'tokenExpiresMono')),
            'OPERATIONAL_CLOCK_FIELDS_REQUIRED')
    require(row['tokenHash'] is None or (type(row['tokenHash']) is str and len(row['tokenHash']) == 64
            and set(row['tokenHash']) <= set('0123456789abcdef')), 'OPERATIONAL_TOKEN_FINGERPRINT_REQUIRED')
    if row['state'] == 'ACTIVE':
        require(row['tokenHash'] is not None and all(row[k] is not None for k in
                ('nextWall', 'nextMono', 'tokenExpiresWall', 'tokenExpiresMono'))
                and row['nextWall'] < row['tokenExpiresWall']
                and row['nextMono'] < row['tokenExpiresMono'], 'BOUNDED_ACTIVE_TOKEN_LEASE_REQUIRED')
    if row['state'] in ('RESERVED', 'DISPATCHING', 'PUBLISHING'):
        require(row['attemptId'] == digest({'installationHash': row['installationHash'],
                'cumulativeAttempt': row['cumulativeAttempts']}), 'EXACT_RESERVED_ATTEMPT_ID_REQUIRED')
    return row


class Worker:
    """One invocation lock must enclose start/step and all native adapter calls.

    Adapters return authenticated absolute expiry; a response or local decode is
    insufficient. Installation liveness is checked on every step independently
    of the finite HUMAN installation window, which is never extended or reused.
    """
    def __init__(self, store, adapter, policy, installation_hash, predecessor_hash, prior, clock):
        require(type(policy) is RenewalPolicy, 'ACTUAL_OPERATIONAL_POLICY_REQUIRED')
        self.store, self.adapter, self.policy, self.clock = store, adapter, policy, clock
        self.installation, self.predecessor, self.prior = installation_hash, predecessor_hash, prior
        self.started_here = False

    def row(self):
        row = validate(self.store.read(), self.policy)
        require((row['installationHash'], row['predecessorInputsHash'], row['priorControlledAttempts'])
                == (self.installation, self.predecessor, self.prior), 'OPERATIONAL_INSTALLATION_OR_HISTORY_CHANGED')
        self.store.assert_invocation()
        return row

    def now(self, row, *, allow_boot_change=False):
        boot, wall, mono = self.clock()
        require(type(boot) is str and bool(boot) and number(wall) and number(mono)
                and wall >= row['lastWall'] and (boot != row['bootId'] or mono >= row['lastMono']), 'OPERATIONAL_CLOCK_REGRESSED')
        require(boot != row['bootId'] or abs((wall-row['lastWall'])-(mono-row['lastMono'])) <= 5,
                'OPERATIONAL_WALL_MONOTONIC_CLOCK_DIVERGENCE')
        require(allow_boot_change or boot == row['bootId'], 'HOST_REBOOT_REQUIRES_FRESH_NATIVE_RECONCILIATION')
        return boot, wall, mono

    def save(self, row, **values):
        boot, wall, mono = self.now(row, allow_boot_change=True)
        updated = dict(row, **values)
        updated.update(version=row['version'] + 1, bootId=boot, lastWall=wall, lastMono=mono)
        validate(updated, self.policy)
        self.store.cas(row, updated)
        return updated

    def block(self, row, reason):
        self.started_here = False
        return self.save(row, state='BLOCKED', reason=reason, nextWall=None, nextMono=None)

    def start(self):
        row = self.row()
        if row['state'] in ('BLOCKED', 'REVOKED'): return row
        if row['state'] in ('DISPATCHING', 'PUBLISHING'):
            return self.block(row, 'UNKNOWN_PREVIOUS_GRANT_OR_PUBLICATION_OUTCOME')
        self.adapter.guard()
        boot, wall, mono = self.now(row, allow_boot_change=True)
        if row['state'] == 'RESERVED':
            # Dispatch has its own durable barrier. RESERVED has never called
            # the remote grant transport and is abandoned without decrementing.
            row = self.save(row, state='READY', reason='UNDISPATCHED_RESERVATION_ABANDONED', attemptId=None,
                            nextWall=wall, nextMono=mono)
        if row['state'] == 'ACTIVE':
            self.adapter.verify_publication(row['tokenHash'])
            if row['tokenExpiresWall'] - wall > self.policy.renew_before_seconds:
                expiry = self.adapter.readmit_existing(row['tokenHash'])
                require(number(expiry) and expiry <= row['tokenExpiresWall'] and expiry > wall,
                        'FRESH_EXISTING_TOKEN_ADMISSION_REQUIRED')
                delay = min(max(0, row['nextWall'] - wall), expiry - wall - self.policy.expiry_safety_seconds)
                require(delay >= 0, 'EXISTING_TOKEN_WINDOW_TOO_SHORT')
                row = self.save(row, tokenExpiresWall=expiry, tokenExpiresMono=mono + expiry - wall,
                                nextWall=wall + delay, nextMono=mono + delay, reason='CURRENT_PUBLICATION_READMITTED')
            else:
                row = self.save(row, state='READY', reason='EXISTING_TOKEN_RENEWAL_DUE',
                                nextWall=wall, nextMono=mono, attemptId=None)
        elif boot != row['bootId']:
            # The native guard has reobserved the approved service and custody.
            # Retry waits retain the old wall deadline; never create a budget.
            delay = max(0, (row['nextWall'] or wall) - wall)
            row = self.save(row, nextWall=wall + delay, nextMono=mono + delay, reason='NEW_BOOT_NATIVE_CUSTODY_RECHECKED')
        self.started_here = True
        return row

    def step(self):
        require(self.started_here, 'OPERATIONAL_INVOCATION_START_REQUIRED')
        row = self.row()
        if row['state'] in ('BLOCKED', 'REVOKED'): return row
        self.adapter.guard()
        _, wall, mono = self.now(row)
        if row['state'] == 'ACTIVE':
            self.adapter.verify_publication(row['tokenHash'])
        if row['nextWall'] is not None and (wall < row['nextWall'] or mono < row['nextMono']): return row
        require(row['state'] in ('READY', 'ACTIVE', 'RETRY_WAIT'), 'NO_OPERATIONAL_ATTEMPT_REDISPATCH')
        hours = [x for x in row['hourlyAttemptsWall'] if wall - x < 3600]
        if len(hours) >= self.policy.maximum_attempts_per_hour:
            due = hours[0] + 3600
            return self.save(row, state='RETRY_WAIT', reason='HOURLY_ATTEMPT_RATE_LIMIT',
                             nextWall=due, nextMono=mono + due - wall)
        attempt = row['cumulativeAttempts'] + 1
        row = self.save(row, state='RESERVED', reason='NEW_DISTINCT_ATTEMPT_RESERVED', attempts=row['attempts'] + 1,
                        cumulativeAttempts=attempt, hourlyAttemptsWall=hours + [wall],
                        attemptId=digest({'installationHash': self.installation, 'cumulativeAttempt': attempt}))
        self.adapter.guard()
        row = self.save(row, state='DISPATCHING', reason='GRANT_DISPATCH_BARRIER_DURABLE')
        try:
            token, expiry = self.adapter.grant_and_admit(mono + self.policy.attempt_timeout_seconds)
            _, after_wall, after_mono = self.now(row)
            require(type(token) is str and 0 < len(token) <= 16384 and not any(x.isspace() for x in token)
                    and number(expiry) and expiry > after_wall + self.policy.minimum_interval_seconds + self.policy.expiry_safety_seconds,
                    'AUTHENTICATED_NEW_TOKEN_WINDOW_REQUIRED')
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            row = self.save(row, state='PUBLISHING', reason='ADMITTED_TOKEN_NOT_YET_PUBLISHED')
            self.adapter.publish(token, row['attemptId'], token_hash)
            self.adapter.verify_publication(token_hash)
            self.adapter.guard()
            _, final_wall, final_mono = self.now(row)
            remaining = expiry - final_wall
            delay = max(self.policy.minimum_interval_seconds, remaining - self.policy.renew_before_seconds)
            require(delay < remaining - self.policy.expiry_safety_seconds, 'TOKEN_PUBLICATION_WINDOW_EXHAUSTED')
            return self.save(row, state='ACTIVE', reason='TOKEN_ATOMICALLY_PUBLISHED',
                             publications=row['publications'] + 1, consecutiveFailures=0,
                             tokenHash=token_hash, tokenExpiresWall=expiry,
                             tokenExpiresMono=final_mono + remaining,
                             nextWall=final_wall + delay, nextMono=final_mono + delay)
        except NotSubmitted:
            current = self.row()
            require(current['state'] == 'DISPATCHING', 'NO_EFFECT_PROOF_CANNOT_COVER_PUBLICATION')
            failures = current['consecutiveFailures'] + 1
            delay = self.policy.failure_delays[min(failures-1, len(self.policy.failure_delays)-1)]
            if failures >= self.policy.maximum_consecutive_failures:
                delay = self.policy.failure_delays[-1]
            _, retry_wall, retry_mono = self.now(current)
            return self.save(current, state='RETRY_WAIT', reason='NO_SUBMISSION_PROVEN_BOUNDED_BACKOFF',
                             consecutiveFailures=failures, nextWall=retry_wall+delay, nextMono=retry_mono+delay)
        except Exception:
            # No transport exception is interpreted as "no effect" here.
            # The previous valid token is not unlinked or revoked by shutdown.
            self.block(self.row(), 'GRANT_OR_PUBLICATION_OUTCOME_REQUIRES_RECONCILIATION')
            raise
