"""Overlay the sealed R3 sources at their existing installed paths."""
import hashlib
import re

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
            code = error if type(error) is str else getattr(error, 'code', None)
            if code not in INCIDENT_CODES and isinstance(error, (RuntimeError, TimeoutError)):
                # Accept only exact, public internal signals.
                code = str(error)
            self.failure = dict(failedAt=self.wall(), phase=self.phase,
                code=code if code in INCIDENT_CODES else fallback,
                leaseRemainingMs=self.remaining_at_entry(), lockWaitMs=self.lock_wait,
                deadlineMonotonic=self.deadline)

    @contextmanager
    def revoking(self):
        previous_deadline, previous_wait = self.deadline, self.lock_wait
        self.deadline = self.lock_wait = None
        self.at('REVOKE')
        try:
            yield
        except Exception:
            self.failed('SAFE_PAUSE_UNPROVEN')
            raise
        else:
            if self.failure is not None and self.paused_at is None:
                self.paused_at = self.wall()
        finally:
            self.deadline, self.lock_wait = previous_deadline, previous_wait

    def project(self, previous, state, reason, values):
        last = previous.get('lastIncident')
        open_incident = last is not None and last['resumedAt'] is None
        if self.failure is not None and state in {
                'RETRY_WAIT', 'BLOCKED', 'RECONCILE_REQUIRED', 'PAUSED_EXHAUSTED'}:
            if not open_incident:
                last = {**self.failure, 'schema': INCIDENT_SCHEMA, 'scopeRef': previous['contextRef'],
                        'authorizationSequence': self.sequence, 'epochs': self.epochs,
                        'incidentCount': 1 if last is None else last['incidentCount'] + 1,
                        'stateAtFailure': previous['state'], 'pausedAt': None,
                        'resumedAt': None, 'nextRetryAt': None, 'revocation': 'UNPROVEN'}
            if self.paused_at is not None and last['pausedAt'] is None:
                last = {**last, 'pausedAt': self.paused_at, 'revocation': 'VERIFIED'}
            if state == 'RETRY_WAIT':
                last = {**last, 'nextRetryAt': values['nextWall']}
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
    original = source_map[BUDGET]
    eol = '\r\n' if b'\r\n' in emitted[original] else '\n'
    emitted[original] += OBSERVED_RECOVERY.replace('\n', eol).encode()

    before(ADAPTER, "        cfg = self.c.configuration; profile = self.c.owner.profile\n",
           "        self.incident.at('DNS', deadline)\n")
    before(ADAPTER, "        plan = self.compiler.compile_refresh(cfg, values, self.clock(),",
           "        self.incident.at('COMPILE')\n")
    edit(ADAPTER, '\n        with self.c.hold_lock():\n',
         "\n        with self.incident.lock(self.c.hold_lock(), 'REVOKE'):\n")

    for target in (ADAPTER, CONTINUOUS):
        publish_method = ('def publish(self, evidence, deadline):' if target == ADAPTER
                          else 'def _publish_renewal(self, evidence, deadline):')
        edit(target, f'    {publish_method}\n', f"    {publish_method}\n        self.incident.at('PLAN', deadline)\n")
        edit(target, '            with self.c.hold_lock():\n',
             "            with self.incident.lock(self.c.hold_lock()):\n"
             "                self.incident.at('READBACK')\n")
        marker = '                plan = self.compiler.compile_refresh('
        before(target, marker, "                self.incident.at('COMPILE')\n")
        before(target, "                pending = {**previous,",
               "                self.incident.at('COMMIT', deadline)\n")
        before(target, '                backend.verify_ownership(cfg)\n                if self.clock() >= deadline:',
               "                self.incident.at('APPLY')\n")
        before(target, '                sets = backend.read_sets(cfg)',
               "                self.incident.at('READBACK')\n")
        final_guard = ('                backend.verify_ownership(cfg); self.guard()\n' if target == ADAPTER
                       else '                backend.verify_ownership(cfg)\n                self.guard()\n')
        before(target, final_guard,
               "                self.incident.at('COMMIT')\n")
        edit(target, '                self.c.publish(pending, ready)\n',
             '                self.c.publish(pending, ready)\n'
             '                self.incident.ready_at = self.incident.wall()\n')

    # Preserve the phase and time before the existing exception handlers revoke
    # or translate the original outcome. Exact NFT expiry keeps its public code.
    edit(ADAPTER, '        except Temporary:\n            self.pause()',
         '        except Temporary as error:\n            self.incident.failed(error)\n            self.pause()')
    before(ADAPTER, '                self.pause()\n                raise Temporary(',
           "                self.incident.failed('DNS_WINDOW_TOO_SHORT')\n")
    edit(ADAPTER, """                raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
            raise Permanent('INTEGRITY_UNPROVEN') from None""",
         """                raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
            self.incident.failed(error, 'INTEGRITY_UNPROVEN')
            raise Permanent('INTEGRITY_UNPROVEN') from None""")
    edit(CONTINUOUS, '            return super().pause()\n',
         '            with self.incident.revoking():\n                return super().pause()\n')
    edit(CONTINUOUS, '        with self.c.owner.backend.within(deadline):\n            return super().prepare(deadline)\n',
         "        self.incident.at('PLAN', deadline)\n"
         '        with self.c.owner.backend.within(deadline):\n'
         '            evidence = super().prepare(deadline)\n'
         "        self.incident.at('PLAN')\n"
         '        return evidence\n')
    edit(CONTINUOUS, '        except Temporary:\n            self.pause()',
         '        except Temporary as error:\n            self.incident.failed(error)\n            self.pause()')
    before(CONTINUOUS, '            if ttl_zero(error):\n                self.pause()',
           "            self.incident.failed('DNS_WINDOW_TOO_SHORT' if ttl_zero(error) else error)\n")
    for next_method in ('prepare_renewal', '_publish_renewal'):
        edit(CONTINUOUS, f'        except Exception:\n            self.pause()\n            raise\n\n    def {next_method}',
             '        except Exception as error:\n            self.incident.failed(error)\n'
             f'            self.pause()\n            raise\n\n    def {next_method}')
    edit(CONTINUOUS, '        except Exception:\n            raise\n',
         '        except Exception as error:\n'
         "            failure = 'DNS_WINDOW_TOO_SHORT' if ttl_zero(error) else error\n"
         "            self.incident.failed(failure, 'INTEGRITY_UNPROVEN' if isinstance(error, RuntimeError)\n"
         "                                 else 'UNCLASSIFIED_FAILURE')\n"
         '            raise\n')
    edit(CONTINUOUS, "        row = self.r.journal.read()\n        if row['state'] == 'ACTIVE':",
         "        self.r.adapter.incident.begin()\n        row = self.r.journal.read()\n        if row['state'] == 'ACTIVE':")
    edit(CONTINUOUS, 'clock=lambda: self.r.now()[1])',
         'clock=lambda: self.r.now()[1], incident=self.r.adapter.incident)')
    edit(CONTINUOUS, '        except Exception:\n            return self.r.pause(row, \'BLOCKED\', \'LOCAL_STATE_UNPROVEN\')',
         '        except Exception as error:\n'
         "            self.r.adapter.incident.failed(error, 'LOCAL_STATE_UNPROVEN')\n"
         "            return self.r.pause(row, 'BLOCKED', 'LOCAL_STATE_UNPROVEN')")
    before(CONTINUOUS, '        publishing = False\n',
           "        self.r.adapter.incident.begin(scheduled['leaseDeadlineMonotonic'])\n")
    before(CONTINUOUS, '            evidence = self.r.adapter.prepare_renewal(deadline)\n',
           "            self.r.adapter.incident.at('PLAN', deadline)\n")
    before(CONTINUOUS, '            self.local_guard()\n            if self.r.now()[1] >= deadline:',
           "            self.r.adapter.incident.at('PLAN')\n")
    edit(CONTINUOUS, '        except Exception:\n            return self.r.pause(row, \'RECONCILE_REQUIRED\'',
         '        except Exception as error:\n            self.r.adapter.incident.failed(error)\n'
         '            return self.r.pause(row, \'RECONCILE_REQUIRED\'')
    edit(ADAPTIVE, 'def window(coordinator, poll_seconds, *, clock=time.monotonic):',
         'def window(coordinator, poll_seconds, *, clock=time.monotonic, incident=None):')
    edit(ADAPTIVE, '    with coordinator.hold_lock():\n        before = clock()',
         '    acquire = coordinator.hold_lock()\n'
         '    with (incident.lock(acquire) if incident is not None else acquire):\n'
         "        if incident is not None:\n            incident.at('READBACK')\n        before = clock()")
    before(ADAPTIVE, '        remaining = deadline - after\n',
           '        if incident is not None:\n            incident.lease_deadline = deadline\n')

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
    # Bind the final emitted bytes, including other overlays already applied.
    sup = source_map[SUPERVISOR]
    for target in (JOURNAL, BUDGET, ADAPTER, CONTINUOUS, ADAPTIVE):
        name = target.removeprefix(RECOVERY).removesuffix('.py')
        pin = re.findall(rb'(?m)^    "' + name.encode() + rb'": "[0-9a-f]{64}",', emitted[sup])
        require(len(pin) == 1, 'R3_V18_OBSERVABILITY_PIN_CONTRACT_DRIFT')
        digest = hashlib.sha256(emitted[source_map[target]]).hexdigest()
        edit(SUPERVISOR, pin[0].decode(), f'    "{name}": "{digest}",')
    return emitted
