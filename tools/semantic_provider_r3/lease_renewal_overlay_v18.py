"""Version-local edits to the reviewed v17 lease closure."""
import re
from textwrap import dedent, indent

from tools.semantic_provider_operation.authorization import require


RECOVERY = 'tools/semantic_lease_recovery/'
SUPERVISOR = 'tools/semantic_provider_operation/lease_supervisor.py'
BOOTSTRAP = 'scripts/semantic-provider-lease-supervisor-v2.py'
POLICY_MODULE = 'lease_renewal_v18'
SCHEMA_V1 = 'ouf.semantic-provider-lease-supervisor.v1'
SCHEMA_V2 = 'ouf.semantic-provider-lease-supervisor.v2'
DRIFT = 'R3_V18_SOURCE_CONTRACT_DRIFT'


def seal_v18(base_sources, sources, source_map, recovery_modules, sha):
    """Seal the composed closure and share its digests with sourceHashes."""
    out = dict(sources)
    edit, _ = _editor(out, source_map[BOOTSTRAP])
    edit(SCHEMA_V1, SCHEMA_V2)
    edit('RECOVERY_MODULES = ("activation_core",',
         f'RECOVERY_MODULES = ("{POLICY_MODULE}", "activation_core",')

    recovery_paths = {name: source_map[RECOVERY + name + '.py']
                      for name in (POLICY_MODULE, *recovery_modules)}
    digests = {path: sha(out[path]) for path in dict.fromkeys(recovery_paths.values())}

    def format_pins(entries):
        return 'PINS = {\n' + ''.join(f'    "{name}": "{pin}",\n' for name, pin in entries) + '}'

    def final_pins(block):
        entries = re.findall(r'    "([a-z0-9_]+)": "([0-9a-f]{64})",\n', block)
        require(tuple(name for name, _ in entries) == recovery_modules
                and block == format_pins(entries), DRIFT)
        for name, pin in entries:
            path = recovery_paths[name]
            if out[path] == base_sources[path]:
                require(digests[path] == pin, DRIFT)
        return format_pins((name, digests[path]) for name, path in recovery_paths.items())

    edit, section = _editor(out, source_map[SUPERVISOR])
    edit(SCHEMA_V1, SCHEMA_V2)
    section('PINS = {\n', '\nSELF = ', final_pins)
    for path in sorted(set(source_map.values()) - digests.keys()):
        digests[path] = sha(out[path])
    return out, {target: digests[original] for target, original in source_map.items()}


def _editor(out, path):
    def edit(old, new):
        before, after = old.encode('utf-8'), new.encode('utf-8')
        require(out[path].count(before) == 1, DRIFT)
        out[path] = out[path].replace(before, after)

    def section(start, end, replacement):
        raw = out[path].decode('utf-8')
        require(raw.count(start) == raw.count(end) == 1, DRIFT)
        first, last = raw.index(start), raw.index(end)
        require(first < last, DRIFT)
        old = raw[first:last]
        edit(old, replacement(old) if callable(replacement) else replacement)

    return edit, section


def sources_v18(sources, source_map):
    out = dict(sources)
    for name, update in (
        ('bounded_recovery', _bounded), ('lease_recovery_budget', _budget),
        ('resilient_lease_adapter', _adapter), ('adaptive_supervisor', _adaptive),
        ('continuous_supervisor', _continuous),
    ):
        update(*_editor(out, source_map[RECOVERY + name + '.py']))
    edit, _ = _editor(out, source_map[SUPERVISOR])
    _supervisor(edit)
    return out


def _bounded(edit, _section):
    edit("TRANSIENT = {'DNS_UNAVAILABLE',", "TRANSIENT = {'COMMON_LOCK_TIMEOUT', 'DNS_UNAVAILABLE',")
    edit('class Permanent(Exception):', dedent('''\
        class BeforeLeaseMutation(Temporary):
            # Created only at explicitly audited pre-mutation call sites.
            # Temporary.no_effect can also describe effects followed by revocation.
            pass


        class Permanent(Exception):'''))
    edit("base = self.policy.delays[min(max(row['attempts'] - 1, 0), len(self.policy.delays) - 1)]",
         "base = self.policy.delays[min(max(row['backoffAttempts'] - 1, 0), len(self.policy.delays) - 1)]")
    edit("attempts=row['attempts'] + 1,\n                        nextWall",
         "attempts=row['attempts'] + 1,\n                        backoffAttempts=row['backoffAttempts'] + 1, nextWall")


def _budget(edit, _section):
    edit("'healthyWallSeconds': 0, 'healthyMonotonicSeconds': 0, 'publicationCount': 0}",
         "'healthyWallSeconds': 0, 'healthyMonotonicSeconds': 0, 'publicationCount': 0,\n"
         "                'backoffAttempts': 0, 'fastRenewalRetries': 0,\n"
         "                'healthySinceWall': None, 'healthySinceMonotonic': None}")
    edit("'DURABLE_RECOVERY_TIME_ACCOUNTING_REQUIRED')",
         "'DURABLE_RECOVERY_TIME_ACCOUNTING_REQUIRED')\n"
         "        counts = (row.get('backoffAttempts'), row.get('fastRenewalRetries'))\n"
         "        since = (row.get('healthySinceWall'), row.get('healthySinceMonotonic'))\n"
         "        require(type(row.get('attempts')) is int\n"
         "                and all(type(n) is int and 0 <= n <= row['attempts'] for n in counts)\n"
         "                and (since == (None, None) or all(number(t) for t in since)),\n"
         "                'DURABLE_RENEWAL_ACCOUNTING_REQUIRED')")
    edit("    def _step(self, *, cancelled=False):", indent(dedent('''\
        def begin_fast_retry(self, row):
            # Count against both the per-cycle allowance and the hard cap.
            return self.save(row, 'ACTIVE', 'RENEWAL_RETRY_PENDING',
                             fastRenewalRetries=row['fastRenewalRetries'] + 1,
                             attempts=row['attempts'] + 1)

        def _step(self, *, cancelled=False):'''), '    '))
    for row in ('row', 'previous'):
        edit(f"if {row}['state'] == 'ACTIVE':",
             f"if {row}['state'] == 'ACTIVE' and {row}['reason'] != 'RENEWAL_RETRY_PENDING':")
    edit("        return super().save(previous, state, reason, **values)", indent(dedent('''\
        if state != 'ACTIVE' or reason == 'RENEWAL_RETRY_PENDING':
            values.update(healthySinceWall=None, healthySinceMonotonic=None)
        elif reason in {'RECOVERED', 'RENEWED'}:
            values['fastRenewalRetries'] = 0
            since_wall, since_mono = previous['healthySinceWall'], previous['healthySinceMonotonic']
            if since_wall is None:
                values.update(healthySinceWall=wall, healthySinceMonotonic=mono)
            elif min(wall - since_wall, mono - since_mono) >= self.adapter.c.renewal['healthyResetSeconds']:
                values['backoffAttempts'] = 1
        return super().save(previous, state, reason, **values)'''), '        '))


def _adapter(edit, _section):
    edit('from bounded_recovery import Permanent, Temporary, fingerprint',
         'from bounded_recovery import BeforeLeaseMutation, Permanent, Temporary, fingerprint')
    # Only a classified fresh DNS error may enter the retained-lease lane.
    # A denyOnly plan can also mean corrupt evidence and stays on the close path.
    edit("raise Temporary('DNS_UNAVAILABLE') from None",
         "raise BeforeLeaseMutation('DNS_UNAVAILABLE') from None")
    edit("raise Temporary('DNS_WINDOW_TOO_SHORT') from None",
         "raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT') from None")


def _adaptive(edit, section):
    edit('import time\n', 'import time\nfrom lease_renewal_v18 import GUARD_SECONDS\n')

    def sample(old):
        start = "        before = clock()\n"
        end = "        # Reserve the complete shared DNS budget"
        require(old.count(start) == old.count(end) == 1, DRIFT)
        read = old[old.index(start):old.index(end)]
        return ("def sample_locked(coordinator, *, clock):\n"
                "    flows = coordinator.configuration['providerFlows']\n"
                + indent(dedent(read), '    ')
                + "    return journal, deadline, remaining\n\n\n"
                + dedent('''\
        def window(coordinator, poll_seconds, *, clock=time.monotonic):
            require(type(poll_seconds) is int and 1 <= poll_seconds <= 300
                    and bool(coordinator.configuration['providerFlows']), 'BOUNDED_LEASE_POLL_REQUIRED')
            policy = coordinator.renewal
            with coordinator.hold_until(clock() + policy['lockWaitSeconds']):
                journal, deadline, remaining = sample_locked(coordinator, clock=clock)
            reserve = policy['renewalMarginSeconds']
            require(remaining >= reserve, 'LEASE_READ_WINDOW_EXHAUSTED')
            return {'deadlineMonotonic': deadline, 'journal': journal,
                    'waitSeconds': min(poll_seconds, remaining / 2, max(0, remaining - reserve - GUARD_SECONDS)),
                    'remainingSecondsLowerBound': remaining}


        '''))

    section('def window(', 'def supervise(', sample)
    edit("and set(left).issubset(set(journal['leaseAddresses'][i]))",
         "and set(left) == set(journal['leaseAddresses'][i])")


def _continuous(edit, section):
    edit('from bounded_recovery import Permanent, Temporary, fingerprint\nfrom adaptive_supervisor import window',
         'from bounded_recovery import BeforeLeaseMutation, Permanent, Temporary, fingerprint\n'
         'from adaptive_supervisor import sample_locked, window\n'
         'from lease_renewal_v18 import COMMIT_SECONDS, REVOCATION_SECONDS, compiler_margin, retry_reserve')
    edit('backend.active_deadline = None', 'backend.active_deadline = self.clock() + REVOCATION_SECONDS')
    edit('            return super().pause()', '            super().pause()\n'
         '            if self.clock() >= backend.active_deadline:\n'
         '                raise RuntimeError("REVOCATION_DEADLINE_UNPROVEN")')
    section('    def publish_renewal(', '\n\nclass Supervisor:', _publication)
    edit("'leaseDeadlineMonotonic': schedule['deadlineMonotonic']}",
         "'leaseDeadlineMonotonic': schedule['deadlineMonotonic'], 'leaseJournal': schedule['journal']}")
    # A real acquisition timeout during scheduling has no trustworthy prior
    # sample for a retained retry. It must therefore revoke before retrying.
    edit("        except RuntimeError as error:\n            if ttl_zero(error) or str(error) in {",
         "        except BeforeLeaseMutation as error:\n"
         "            self.active_here = False\n"
         "            return self.r.retry(row, error)\n"
         "        except RuntimeError as error:\n            if ttl_zero(error) or str(error) in {")
    section('    def renew(', '    def serve(', indent(dedent(_RENEW), '    '))
    edit("if row['state'] == 'ACTIVE': self.renew(row)", "if row['state'] == 'ACTIVE': self.renew(row, stop)")


def _publication(old):
    # Keep the reviewed atomic update, exact readback and fenced READY path.
    start = "                plan = self.compiler.compile_refresh"
    end = "        except Exception:\n            raise"
    require(old.count(start) == old.count(end) == 1, DRIFT)
    body = old[old.index(start):old.index(end)]
    anchor = "                pending = {**previous, 'state': 'LEASE_UPDATING', 'leaseAuthorized': False}"
    require(body.count(anchor) == 1, DRIFT)
    body = body.replace(anchor,
        "                if self.clock() >= deadline: raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')\n"
        "                backend.active_deadline = deadline\n" + anchor)
    return indent(dedent(_PUBLICATION), '    ') + indent(dedent(body), '            ')


_PUBLICATION = '''\
def prior_lease(self, expected):
    # Called under the unchanged common lock. Custody, live generations,
    # exact two-family membership and an actual positive TTL are needed.
    self.guard()
    journal, expires, _ = sample_locked(self.c, clock=self.clock)
    if journal != expected:
        raise Permanent('INTEGRITY_UNPROVEN')
    self.guard()
    return journal, expires - COMMIT_SECONDS

def prove_retry(self, expected, deadline):
    backend = self.c.owner.backend
    with backend.within(deadline), self.c.hold_until(
            min(deadline, self.clock() + self.c.renewal['lockWaitSeconds'])):
        if self.clock() >= deadline:
            raise Temporary('DNS_WINDOW_TOO_SHORT')
        _, prior_deadline = self.prior_lease(expected)
    return min(deadline, prior_deadline)

def publish_renewal(self, evidence, deadline, expected):
    values = evidence['values']
    backend, cfg = self.c.owner.backend, self.c.configuration
    profile = self.c.owner.profile
    dns_limit = min(value['expiresMonotonic'] for value in values) - compiler_margin(profile)
    # The attempt deadline already reserves time on the outgoing lease.
    lock_deadline = min(self.clock() + self.c.renewal['lockWaitSeconds'],
                        deadline - COMMIT_SECONDS, dns_limit)
    if self.clock() >= lock_deadline:
        raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')
    with backend.within(deadline), self.c.hold_until(lock_deadline):
        if self.clock() >= lock_deadline:
            raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')
        previous, prior_deadline = self.prior_lease(expected)
        deadline = min(deadline, prior_deadline)
        if self.clock() >= min(deadline - COMMIT_SECONDS, dns_limit):
            raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')
'''


_RENEW = '''\
def renew(self, scheduled, stop):
    row = self.r.journal.read()
    if row['state'] != 'ACTIVE' or not self.active_here:
        raise RuntimeError('CURRENT_INVOCATION_ACTIVE_REQUIRED')
    adapter = self.r.adapter
    publishing = False
    try:
        started = self.r.now()[1]
        remaining = self.r.remaining(row)
        if remaining <= 0:
            return self.r.pause(row, 'PAUSED_EXHAUSTED', 'RECOVERY_SCOPE_TIME_EXHAUSTED')
        expires = scheduled['leaseDeadlineMonotonic']
        if expires - started < self.c.renewal['renewalMarginSeconds']:
            raise Temporary('DNS_WINDOW_TOO_SHORT')
        deadline = min(started + min(self.r.policy.attempt_timeout, remaining), expires - COMMIT_SECONDS)
        expected = scheduled['leaseJournal']
        delays = self.c.renewal['fastRetryDelaysSeconds']
        reserve = retry_reserve(self.c.owner.profile)
        while True:
            if stop.is_set():
                return self.r.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')
            try:
                publishing = False
                evidence = adapter.prepare_renewal(deadline)
                if stop.is_set():
                    return self.r.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')
                publishing = True
                result = adapter.publish_renewal(evidence, deadline, expected)
                break
            except BeforeLeaseMutation as error:
                publishing = False
                index = row['fastRenewalRetries']
                if index >= len(delays) or row['attempts'] >= self.r.policy.max_attempts:
                    raise
                delay = max(delays[index], error.retry_after)
                if self.r.now()[1] + delay + reserve >= deadline:
                    raise
                deadline = adapter.prove_retry(expected, deadline)
                if self.r.now()[1] + delay + reserve >= deadline:
                    raise
                row = self.r.begin_fast_retry(row)
                if stop.wait(delay):
                    return self.r.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')
                deadline = adapter.prove_retry(expected, deadline)
                if self.r.now()[1] + reserve >= deadline or self.r.remaining(row) <= 0:
                    raise
        if self.r.now()[1] >= deadline or self.r.remaining(row) <= 0:
            return self.r.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_DEADLINE_UNPROVEN')
        if type(result) is not str or not re.fullmatch('[0-9a-f]{64}', result):
            return self.r.pause(row, 'RECONCILE_REQUIRED', 'DURABLE_RESULT_UNPROVEN')
        row = self.r.save(row, 'ACTIVE', 'RENEWED', resultRef=result)
        self.renewals += 1
        return row
    except Temporary as error:
        self.active_here = False
        if publishing:
            return self.r.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS')
        return self.r.retry(row, error)
    except Permanent as error:
        self.active_here = False
        return self.r.pause(row, 'BLOCKED', error.code)
    except RuntimeError as error:
        self.active_here = False
        if ttl_zero(error):
            return self.r.retry(row, Temporary('DNS_WINDOW_TOO_SHORT'))
        return self.r.pause(row, 'RECONCILE_REQUIRED' if publishing else 'BLOCKED',
                            'INTEGRITY_UNPROVEN')
    except Exception:
        self.active_here = False
        return self.r.pause(row, 'RECONCILE_REQUIRED' if publishing else 'BLOCKED',
                            'UNCLASSIFIED_FAILURE')

'''


def _supervisor(edit):
    edit('from contextlib import contextmanager', 'from contextlib import ExitStack, contextmanager')
    edit('"recoveryJournalRoot", "statusPath", "limits"}',
         '"recoveryJournalRoot", "statusPath", "limits", "leaseRenewal", "driverBudgetSeconds"}')
    edit('allowed = {"DNS_UNAVAILABLE",', 'allowed = {"COMMON_LOCK_TIMEOUT", "DNS_UNAVAILABLE",')
    edit('    class BoundBackend(loaded["deadline_backend"].DeadlineNftBackend):',
         indent(dedent('''\
        policy = loaded["lease_renewal_v18"]
        renewal = cfg["leaseRenewal"]
        profile = {**owner["dns"], "timeoutSeconds": 10}
        try:
            policy.budgets(renewal, profile, owner["kernel"]["providerFlows"], cfg["driverBudgetSeconds"],
                           loaded["bounded_recovery"].Policy().attempt_timeout)
        except ValueError as error:
            raise Denied(str(error)) from None

        class BoundBackend(loaded["deadline_backend"].DeadlineNftBackend):'''), '    '))
    edit('    coordinator = coordination.Coordinator(owner_object, owner["binding"],\n'
         '        lambda: locking.wait_common_lock(Path(c["commonLockPath"]), time.monotonic() + 20),\n'
         '        journal.read, journal.write)',
         indent(dedent('''\
        lock_path = Path(c["commonLockPath"])

        def hold_lock():
            end = time.monotonic() + 20
            if backend.active_deadline is not None:
                end = min(end, backend.active_deadline)
            return locking.wait_common_lock(lock_path, end)

        @contextmanager
        def hold_until(deadline):
            with ExitStack() as stack:
                try:
                    stack.enter_context(locking.wait_common_lock(lock_path, deadline))
                except locking.CommonLockTimeout:
                    raise loaded["bounded_recovery"].BeforeLeaseMutation("COMMON_LOCK_TIMEOUT") from None
                yield

        coordinator = coordination.Coordinator(owner_object, owner["binding"], hold_lock, journal.read, journal.write)
        coordinator.hold_until = hold_until
        coordinator.renewal = renewal'''), '    '))
