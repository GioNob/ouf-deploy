"""Overlay the sealed R3 sources at their existing installed paths."""
from tools.semantic_provider_operation.authorization import require


RECOVERY = 'tools/semantic_lease_recovery/'
JOURNAL = RECOVERY + 'recovery_journal.py'
BUDGET = RECOVERY + 'lease_recovery_budget.py'
ADAPTER = RECOVERY + 'resilient_lease_adapter.py'
CONTINUOUS = RECOVERY + 'continuous_supervisor.py'
ADAPTIVE = RECOVERY + 'adaptive_supervisor.py'
SUPERVISOR = 'tools/semantic_provider_operation/lease_supervisor.py'

# This fragment is installed inside recovery_journal.py.
INCIDENT = '''

INCIDENT_SCHEMA = 'ouf.semantic-lease-recovery-incident.v1'
INCIDENT_PHASES = ('PLAN', 'DNS', 'LOCK_ACQUIRE', 'COMPILE', 'APPLY', 'READBACK', 'COMMIT', 'REVOKE')
RECOVERY_STATES = ('NEW', 'ATTEMPTING', 'PUBLISHING', 'ACTIVE', 'RETRY_WAIT',
                   'PAUSED_EXHAUSTED', 'BLOCKED', 'RECONCILE_REQUIRED', 'CANCELLED')
INCIDENT_CODES = (
    'DNS_UNAVAILABLE', 'DNS_WINDOW_TOO_SHORT', 'DEPENDENCY_UNAVAILABLE', 'DEPENDENCY_TIMEOUT',
    'RATE_LIMITED', 'SERVICE_UNAVAILABLE', 'AUTHORITY_REVOKED', 'AUTHORITY_EXPIRED',
    'GENERATION_CHANGED', 'CONFIGURATION_DRIFT', 'INTEGRITY_UNPROVEN', 'PERMANENT_FAILURE',
    'COMMON_LOCK_TIMEOUT', 'NFT_ATTEMPT_DEADLINE_UNPROVEN', 'RECOVERY_SCOPE_TIME_EXHAUSTED',
    'RETRY_BUDGET_EXHAUSTED', 'LOCAL_AUTHORITY_UNPROVEN', 'LOCAL_STATE_UNPROVEN',
    'CLOCK_REGRESSION', 'GENERATION_RECONCILIATION_REQUIRED',
    'WORKER_INVOCATION_RECONCILIATION_REQUIRED', 'INTERRUPTED_ATTEMPT_REQUIRES_RECONCILIATION',
    'PUBLICATION_DEADLINE_UNPROVEN', 'PUBLICATION_OUTCOME_AMBIGUOUS', 'DURABLE_RESULT_UNPROVEN',
    'SAFE_PAUSE_UNPROVEN', 'UNCLASSIFIED_FAILURE',
)
INCIDENT_FIELDS = {
    'schema', 'scopeRef', 'authorizationSequence', 'epochs', 'incidentCount',
    'failedAt', 'pausedAt', 'resumedAt', 'nextRetryAt', 'phase', 'code',
    'revocation', 'stateAtFailure', 'leaseRemainingMs', 'lockWaitMs', 'deadlineMonotonic',
}


def incident_integer(value):
    return type(value) is int and 0 < value < 2**63


def incident_time(value):
    return type(value) in (int, float) and 0 <= value < 2**63


def validate_incident(row):
    require(type(row) is dict, 'RECOVERY_RECORD_INVALID')
    incident = row.get('lastIncident')
    if incident is None:
        return
    require(
        type(incident) is dict and set(incident) == INCIDENT_FIELDS
        and incident['schema'] == INCIDENT_SCHEMA and incident['scopeRef'] == row.get('contextRef')
        and type(incident['scopeRef']) is str and re.fullmatch('[0-9a-f]{64}', incident['scopeRef'])
        and incident_integer(incident['authorizationSequence'])
        and incident_integer(incident['incidentCount'])
        and type(incident['epochs']) is dict and set(incident['epochs']) == {'adapter', 'southbound'}
        and all(map(incident_integer, incident['epochs'].values()))
        and incident['phase'] in INCIDENT_PHASES and incident['code'] in INCIDENT_CODES
        and incident['stateAtFailure'] in RECOVERY_STATES and incident_time(incident['failedAt'])
        and incident['revocation'] in ('VERIFIED', 'UNPROVEN')
        and (incident['pausedAt'] is not None) == (incident['revocation'] == 'VERIFIED')
        and all(incident[key] is None or incident_time(incident[key])
                for key in ('pausedAt', 'resumedAt', 'nextRetryAt', 'deadlineMonotonic'))
        and all(incident[key] is None or type(incident[key]) is int and incident_time(incident[key])
                for key in ('leaseRemainingMs', 'lockWaitMs')),
        'RECOVERY_INCIDENT_INVALID')


class Incident:
    """Capture only phase markers and scalars, then extend the next durable CAS."""
    def __init__(self, sequence, epochs, wall, monotonic):
        self.sequence, self.epochs = sequence, dict(epochs)
        self.wall, self.monotonic = wall, monotonic
        self.begin()

    def begin(self, lease_deadline=None):
        self.lease_deadline = lease_deadline
        self.deadline = lease_deadline
        self.lock_wait = self.failure = self.paused_at = self.ready_at = None
        self.next_retry_at = None
        self.at('PLAN')

    def at(self, phase, deadline=None):
        self.phase = phase
        if deadline is not None:
            self.deadline = deadline
        self.entered = self.monotonic()

    def remaining_at_entry(self):
        if self.lease_deadline is not None:
            return max(0, int((self.lease_deadline - self.entered) * 1000))

    @contextmanager
    def lock(self, acquire, phase='LOCK_ACQUIRE'):
        self.at(phase)
        started = self.monotonic()
        acquired = False
        try:
            with acquire:
                acquired = True
                self.lock_wait = max(0, int((self.monotonic() - started) * 1000))
                yield
        finally:
            if not acquired:
                self.lock_wait = max(0, int((self.monotonic() - started) * 1000))

    def failed(self, error, fallback='UNCLASSIFIED_FAILURE'):
        if self.failure is None:
            # Any earlier quiescence predates this failure.
            self.paused_at = None
            code = error if type(error) is str else getattr(error, 'code', None)
            if code not in INCIDENT_CODES and isinstance(error, (RuntimeError, TimeoutError)):
                # Accept only exact, public internal signals.
                code = str(error)
            self.failure = dict(failedAt=self.wall(), phase=self.phase,
                code=code if code in INCIDENT_CODES else fallback,
                leaseRemainingMs=self.remaining_at_entry(), lockWaitMs=self.lock_wait,
                deadlineMonotonic=self.deadline)

    @contextmanager
    def revoking(self, deadline):
        previous_deadline, previous_wait = self.deadline, self.lock_wait
        self.lock_wait = None
        self.at('REVOKE', deadline)
        try:
            yield
        except Exception:
            self.failed('SAFE_PAUSE_UNPROVEN')
            raise
        else:
            if self.paused_at is None:
                self.paused_at = self.wall()
        finally:
            self.deadline, self.lock_wait = previous_deadline, previous_wait

    def project(self, previous, state, reason, values):
        last = previous.get('lastIncident')
        open_incident = last is not None and last['resumedAt'] is None
        fast_retry = state == 'ACTIVE' and reason == 'RENEWAL_RETRY_PENDING'
        if self.failure is not None and (fast_retry or state in {
                'RETRY_WAIT', 'BLOCKED', 'RECONCILE_REQUIRED', 'PAUSED_EXHAUSTED'}):
            if not open_incident:
                last = {**self.failure, 'schema': INCIDENT_SCHEMA, 'scopeRef': previous['contextRef'],
                        'authorizationSequence': self.sequence, 'epochs': self.epochs,
                        'incidentCount': 1 if last is None else last['incidentCount'] + 1,
                        'stateAtFailure': previous['state'], 'pausedAt': None,
                        'resumedAt': None, 'nextRetryAt': None, 'revocation': 'UNPROVEN'}
            if state == 'RETRY_WAIT':
                last = {**last, 'nextRetryAt': values['nextWall']}
            if fast_retry:
                last = {**last, 'nextRetryAt': self.next_retry_at}
        if (last is not None and last['resumedAt'] is None
                and self.paused_at is not None and last['pausedAt'] is None):
            last = {**last, 'pausedAt': self.paused_at, 'revocation': 'VERIFIED'}
        if (open_incident and state == 'ACTIVE' and reason in ('RECOVERED', 'RENEWED')
                and self.ready_at is not None):
            last = {**last, 'resumedAt': self.ready_at}
        return last
'''


OBSERVED_RECOVERY = '''

class ObservedRecovery(LeaseRecovery):
    """Extend checkpoint writes without changing the recovery policy."""
    def initial(self):
        return {**super().initial(), 'lastIncident': None}

    def pause(self, row, state, reason):
        if state != 'CANCELLED':
            self.adapter.incident.failed(reason)
        return super().pause(row, state, reason)

    def retry(self, row, error):
        self.adapter.incident.failed(error)
        return super().retry(row, error)

    def save(self, previous, state, reason, **values):
        incident = self.adapter.incident
        if state == 'ATTEMPTING':
            incident.begin()
        values['lastIncident'] = incident.project(previous, state, reason, values)
        row = super().save(previous, state, reason, **values)
        if state not in ('ATTEMPTING', 'PUBLISHING'):
            incident.begin()
        return row
'''


def sources_v18_observability(sources, source_map):
    emitted = dict(sources)

    def edit(target, old, new):
        source = source_map[target]
        raw = emitted[source]
        if b'\r\n' in raw and raw.count(b'\n') == raw.count(b'\r\n'):
            old, new = (text.replace('\n', '\r\n') for text in (old, new))
        old, new = old.encode(), new.encode()
        require(raw.count(old) == 1, 'R3_V18_OBSERVABILITY_SOURCE_CONTRACT_DRIFT')
        emitted[source] = raw.replace(old, new)

    def before(target, marker, line):
        edit(target, marker, line + marker)

    edit(JOURNAL, 'import os\n', 'import os\nimport re\n')
    before(JOURNAL, '\nclass Journal:', INCIDENT)
    before(JOURNAL, "        self.create(self.lock, b'')", '        validate_incident(record)\n')
    edit(JOURNAL, '            return json.loads(raw, object_pairs_hook=unique)',
         '            row = json.loads(raw, object_pairs_hook=unique)\n'
         '            validate_incident(row)\n            return row')
    edit(JOURNAL, '    def compare_and_save(self, previous, value):\n',
         '    def compare_and_save(self, previous, value):\n        validate_incident(value)\n')
    marker = '        return super().save(previous, state, reason, **values)\n'
    edit(BUDGET, marker, marker + OBSERVED_RECOVERY)

    _adapter_observation(edit, before)
    _renewal_observation(edit, before)

    before(SUPERVISOR, '        self.renewals = 0\n', '        self.recovery_scope = None\n')
    before(SUPERVISOR, '                 "updatedAt": int(self.clock())}',
           '                 "recoveryScope": self.recovery_scope,\n')
    before(SUPERVISOR, '                    "authorizationSequence": None, "epochs": dict.fromkeys(ROLES),',
           '                    "recoveryScope": self.recovery_scope,\n')
    before(SUPERVISOR, '            supervisor.serve(token, observe)\n',
           '            self.recovery_scope = supervisor.r.journal.root.name\n')
    edit(SUPERVISOR, 'loaded["lease_recovery_budget"].LeaseRecovery(',
         'loaded["lease_recovery_budget"].ObservedRecovery(')
    before(SUPERVISOR, '        journal.initialize(recovery.initial())\n',
           '        adapter.incident = loaded["recovery_journal"].Incident(\n'
           '            guards.sequence, guards.epochs, time.time, time.monotonic)\n')
    return emitted


def _publication_phases(before, target, padding, commit_guard):
    def phase(marker, name, deadline=''):
        before(target, '\n' + padding + marker,
               '\n' + padding + f"self.incident.at('{name}'{deadline})")

    phase('plan = self.compiler.compile_refresh(', 'COMPILE')
    phase('pending = {**previous,', 'COMMIT', ', deadline')
    phase('backend.verify_ownership(cfg)\n' + padding + 'if self.clock() >= deadline:', 'APPLY')
    phase('sets = backend.read_sets(cfg)', 'READBACK')
    phase(commit_guard, 'COMMIT')
    before(target, '\n' + padding + 'return fingerprint(ready)',
           '\n' + padding + 'self.incident.ready_at = self.incident.wall()')


def _adapter_observation(edit, before):
    before(ADAPTER, "        cfg = self.c.configuration; profile = self.c.owner.profile\n",
           "        self.incident.at('DNS', deadline)\n")
    before(ADAPTER, "        plan = self.compiler.compile_refresh(cfg, values, self.clock(),",
           "        self.incident.at('COMPILE')\n")
    edit(ADAPTER, '\n        with self.c.hold_lock():\n',
         "\n        with self.incident.lock(self.c.hold_lock(), 'REVOKE'):\n")

    # Recovery publication begins with a quiesced coordinator.
    before(ADAPTER, "        values = evidence['values']\n", "        self.incident.at('PLAN', deadline)\n")
    edit(ADAPTER, '            with self.c.hold_lock():\n',
         "            with self.incident.lock(self.c.hold_lock()):\n"
         "                self.incident.at('READBACK')\n")
    _publication_phases(before, ADAPTER, ' ' * 16, 'backend.verify_ownership(cfg); self.guard()\n')

    # Capture the cause before the recovery adapter revokes or translates it.
    edit(ADAPTER, '        except Temporary:\n            self.pause()',
         '        except Temporary as error:\n            self.incident.failed(error)\n            self.pause()')
    before(ADAPTER, '                self.pause()\n                raise Temporary(',
           "                self.incident.failed('DNS_WINDOW_TOO_SHORT')\n")
    edit(ADAPTER, """                raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
            raise Permanent('INTEGRITY_UNPROVEN') from None""",
         """                raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
            self.incident.failed(error, 'INTEGRITY_UNPROVEN')
            raise Permanent('INTEGRITY_UNPROVEN') from None""")


def _renewal_observation(edit, before):
    edit(CONTINUOUS, '''\
            super().pause()
            if self.clock() >= backend.active_deadline:
                raise RuntimeError("REVOCATION_DEADLINE_UNPROVEN")
''', '''\
            with self.incident.revoking(backend.active_deadline):
                super().pause()
                if self.clock() >= backend.active_deadline:
                    raise RuntimeError("REVOCATION_DEADLINE_UNPROVEN")
''')
    for prepare in ('prepare', 'prepare_renewal'):
        edit(CONTINUOUS, f'    def {prepare}(self, deadline):\n',
             f"    def {prepare}(self, deadline):\n        self.incident.at('PLAN', deadline)\n")
    edit(CONTINUOUS, '            return super().prepare(deadline)\n',
         '            evidence = super().prepare(deadline)\n'
         "        self.incident.at('PLAN')\n"
         '        return evidence\n')
    edit(CONTINUOUS, '        except Exception:\n            self.pause()\n            raise\n',
         '        except Exception as error:\n            self.incident.failed(error)\n'
         '            self.pause()\n            raise\n')
    before(CONTINUOUS, '        journal, expires, _ = sample_locked(self.c, clock=self.clock)\n',
           "        self.incident.at('READBACK')\n")
    edit(CONTINUOUS, """\
        with backend.within(deadline), self.c.hold_until(
                min(deadline, self.clock() + self.c.renewal['lockWaitSeconds'])):
""", """\
        with backend.within(deadline), self.incident.lock(self.c.hold_until(
                min(deadline, self.clock() + self.c.renewal['lockWaitSeconds']))):
""")
    before(CONTINUOUS, '\n        if self.clock() >= lock_deadline:\n',
           "\n        self.incident.at('LOCK_ACQUIRE', deadline)")
    edit(CONTINUOUS, '        with backend.within(deadline), self.c.hold_until(lock_deadline):\n',
         '        with backend.within(deadline), self.incident.lock(self.c.hold_until(lock_deadline)):\n')
    _publication_phases(before, CONTINUOUS, ' ' * 12,
                        'backend.verify_ownership(cfg)\n            self.guard()\n')

    edit(CONTINUOUS, '    def tick(self):\n', '    def tick(self):\n        self.r.adapter.incident.begin()\n')
    edit(CONTINUOUS, 'clock=lambda: self.r.now()[1])',
         'clock=lambda: self.r.now()[1], incident=self.r.adapter.incident)')
    edit(CONTINUOUS, "        except Exception:\n            return self.r.pause(row, 'BLOCKED', 'LOCAL_STATE_UNPROVEN')",
         '        except Exception as error:\n'
         "            self.r.adapter.incident.failed(error, 'LOCAL_STATE_UNPROVEN')\n"
         "            return self.r.pause(row, 'BLOCKED', 'LOCAL_STATE_UNPROVEN')")

    before(CONTINUOUS, '        publishing = False\n        try:\n',
           '        incident = adapter.incident\n        incident.begin()\n')
    before(CONTINUOUS, "            if expires - started < self.c.renewal['renewalMarginSeconds']:\n",
           '            incident.lease_deadline = expires\n')
    before(CONTINUOUS, '                    evidence = adapter.prepare_renewal(deadline)\n',
           '                    incident.begin(expires)\n')
    before(CONTINUOUS, "                    index = row['fastRenewalRetries']\n",
           '                    incident.failed(error)\n')
    before(CONTINUOUS, '                    row = self.r.begin_fast_retry(row)\n',
           '                    incident.next_retry_at = incident.wall() + delay\n')
    edit(CONTINUOUS, '        except Temporary as error:\n            self.active_here = False\n',
         '        except Temporary as error:\n            incident.failed(error)\n            self.active_here = False\n')
    edit(CONTINUOUS, '        except RuntimeError as error:\n            self.active_here = False\n',
         "        except RuntimeError as error:\n"
         "            incident.failed('DNS_WINDOW_TOO_SHORT' if ttl_zero(error) else error, 'INTEGRITY_UNPROVEN')\n"
         "            self.active_here = False\n")
    edit(CONTINUOUS, '        except Exception:\n            self.active_here = False\n',
         '        except Exception as error:\n            incident.failed(error)\n            self.active_here = False\n')

    edit(ADAPTIVE, 'def window(coordinator, poll_seconds, *, clock=time.monotonic):',
         'def window(coordinator, poll_seconds, *, clock=time.monotonic, incident=None):')
    edit(ADAPTIVE, """\
    with coordinator.hold_until(clock() + policy['lockWaitSeconds']):
        journal, deadline, remaining = sample_locked(coordinator, clock=clock)
""", """\
    acquire = coordinator.hold_until(clock() + policy['lockWaitSeconds'])
    with (incident.lock(acquire) if incident is not None else acquire):
        if incident is not None:
            incident.at('READBACK')
        journal, deadline, remaining = sample_locked(coordinator, clock=clock)
    if incident is not None:
        incident.lease_deadline = deadline
""")
