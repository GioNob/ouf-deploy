"""R-022. Apply timing probes to the already composed v20 closure before its final seal."""
from tools.semantic_provider_operation.authorization import require
from .lease_observability_overlay_v18 import ADAPTER, ADAPTIVE, BUDGET, CONTINUOUS, JOURNAL, RECOVERY, SUPERVISOR

DRIFT = 'R3_V21_TIMING_SOURCE_CONTRACT_DRIFT'
# The standalone status reader verifies the same closed wire contract.
SCHEMA = '''
TIMING_SCHEMA = 'ouf.lease-renewal-timing.v1'
# Each event begins with a fixed tag and a monotonic timestamp in seconds.
TIMING_EVENTS = {
    'tick': '', 'plan': 'duration', 'wait': 'duration', 'wake': '', 'renew': '',
    'deny': '', 'guardEnd': '', 'dnsStart': '', 'dnsRound': '', 'dnsEnd': 'count',
    'ttl': 'flow ttl bool', 'compile': '', 'timeout': 'flow lease',
    'lockStart': 'site', 'acquired': 'site', 'released': 'site',
    'apply': '', 'applyEnd': 'bool', 'dump': 'family', 'dumpEnd': 'family bool',
    'verify': '', 'verifyEnd': '', 'ready': '', 'readyEnd': '',
    'sampleBefore': 'margin', 'expires': 'flow lease lease', 'sampleAfter': 'signed time',
    'attemptLimit': 'time', 'planLimit': 'time', 'leaseLimit': 'time',
}
TIMING_MAX_EVENTS = 1024
TIMING_LIMITS = {'flow': 31, 'family': 1, 'site': 6, 'ttl': 2**31-1, 'lease': 3600,
                 'margin': 300, 'count': 2**31-1}
TIMING_MODULES = ('adaptive_supervisor', 'continuous_supervisor', 'resilient_lease_adapter',
                  'dns', 'nft_seconds_backend', 'deadline_backend', 'readback_margin_compiler',
                  'bounded_recovery', 'lease_recovery_budget', 'semantic_common_lock_v2',
                  'semantic_provider_lease_coordination', 'lease_supervisor', 'recovery_journal')


def timing_scalar(kind, value):
    if kind == 'bool':
        return type(value) is bool
    if kind in ('time', 'duration', 'signed'):
        low = -2**63 if kind == 'signed' else 0
        return type(value) in (int, float) and low <= value < 2**63
    return type(value) is int and 0 <= value <= TIMING_LIMITS[kind]


def valid_timing_frame(frame):
    if (type(frame) is not dict or set(frame) != {'sequence', 'events', 'truncated'}
            or type(frame['sequence']) is not int or not 0 < frame['sequence'] < 2**63
            or type(frame['truncated']) is not bool or type(frame['events']) is not list
            or len(frame['events']) > TIMING_MAX_EVENTS):
        return False
    return all(map(valid_timing_event, frame['events']))


def valid_timing_event(event):
    if (type(event) is not list or len(event) < 2 or type(event[0]) is not str
            or event[0] not in TIMING_EVENTS or not timing_scalar('time', event[1])):
        return False
    kinds = TIMING_EVENTS[event[0]].split()
    return len(event) == len(kinds) + 2 and all(
        timing_scalar(kind, value) for kind, value in zip(kinds, event[2:]))


def valid_timing(value):
    if (type(value) is not dict or set(value) != {'schema', 'branch', 'previous', 'current'}
            or value['schema'] != TIMING_SCHEMA or not valid_timing_frame(value['current'])):
        return False
    branch, previous = value['branch'], value['previous']
    return (type(branch) is list and len(branch) == 2
            and type(branch[0]) is int and 0 <= branch[0] < len(TIMING_MODULES)
            and type(branch[1]) is int and 0 < branch[1] <= 65535
            and (previous is None or valid_timing_frame(previous)
                 and previous['sequence'] < value['current']['sequence']))
'''

RECORDER = '''

def denial_branch(error):
    # Preserve the source of a translated exception while it is still in scope.
    active = sys.exc_info()[1]
    cause = active if active is not None else error
    result = None
    if isinstance(cause, BaseException):
        trace = cause.__traceback__
        while trace is not None:
            frame = trace.tb_frame
            name = frame.f_globals.get('__name__')
            if name in TIMING_MODULES and frame.f_code.co_name != 'require':
                result = [TIMING_MODULES.index(name), trace.tb_lineno]
            trace = trace.tb_next
    if result is not None:
        return result
    # Direct policy decisions (pause/retry without an exception).
    caller = sys._getframe(1)
    frame = caller
    while frame:
        name = frame.f_globals.get('__name__')
        if name in TIMING_MODULES and name != 'recovery_journal' and frame.f_code.co_name not in ('pause', 'retry'):
            return [TIMING_MODULES.index(name), frame.f_lineno]
        frame = frame.f_back
    # A decision originating at the recovery boundary itself.
    return [TIMING_MODULES.index('recovery_journal'), caller.f_lineno]


class TimedLock:
    def __init__(self, timing, acquire, site):
        self.timing, self.acquire, self.site = timing, acquire, site

    def __enter__(self):
        self.timing.event('lockStart', self.site)
        value = self.acquire.__enter__()
        self.timing.event('acquired', self.site)
        return value

    def __exit__(self, *exc):
        result = self.acquire.__exit__(*exc)
        self.timing.event('released', self.site)
        return result


class Timing:
    def __init__(self, clock):
        self.clock = clock
        self.previous = self.current = None
        self.next_cycle()

    def next_cycle(self):
        if self.current is not None and not self.current['events']:
            return
        sequence = 1 if self.current is None else self.current['sequence'] + 1
        if self.current and self.attempted:
            self.previous = self.current
        self.current = dict(sequence=sequence, events=deque(maxlen=TIMING_MAX_EVENTS), truncated=False)
        self.attempted = False

    def event(self, tag, *values, at=None):
        events = self.current['events']
        if len(events) >= TIMING_MAX_EVENTS:
            self.current['truncated'] = True
        events.append([tag, self.clock() if at is None else at, *values])

    @staticmethod
    def freeze(frame):
        if frame is None:
            return None
        # A rejected clock/sample must never make the original denial unsavable.
        # Charge exact JSON bytes only on fault. Reserve space for both frames
        # and the existing recovery record; retain the end nearest the fault.
        events = []
        used = 2
        for event in reversed(frame['events']):
            if valid_timing_event(event):
                used += 1 + len(json.dumps(event, separators=(',', ':')))
                if used > 28 * 1024:
                    break
                events.append(event.copy())
        events.reverse()
        return {**frame, 'events': events,
                'truncated': frame['truncated'] or len(events) != len(frame['events'])}

    def snapshot(self, error):
        self.event('deny')
        return dict(schema=TIMING_SCHEMA, branch=denial_branch(error),
                    current=self.freeze(self.current), previous=self.freeze(self.previous))

    def lock(self, acquire, site):
        return TimedLock(self, acquire, site)

    def wait(self, stop, seconds):
        self.event('wait', seconds)
        try:
            return stop.wait(seconds)
        finally:
            self.event('wake')
'''


def sources_v21(sources, source_map):
    out = dict(sources)

    def edit(target, old, new):
        path = source_map[target]
        raw = out[path]
        lf = b'\r\n' if b'\r\n' in raw else b'\n'
        anchor, replacement = (s.encode('ascii').replace(b'\n', lf) for s in (old, new))
        require(raw.count(anchor) == 1, DRIFT)
        out[path] = raw.replace(anchor, replacement)

    edit(JOURNAL, 'import os\n', 'import os\nimport sys\nfrom collections import deque\n')
    edit(JOURNAL, 'class Incident:', SCHEMA + RECORDER + '\n\nclass Incident:')
    edit(JOURNAL, '        self.wall, self.monotonic = wall, monotonic',
         '        self.timing = Timing(monotonic)\n        self.timing_open = False\n        self.wall, self.monotonic = wall, monotonic')
    marker = '                deadlineMonotonic=self.deadline)'
    edit(JOURNAL, marker, marker + "\n            if not self.timing_open:\n"
         "                self.failure['timing'] = self.timing.snapshot(error)")
    marker = '        row = super().save(previous, state, reason, **values)'
    edit(BUDGET, marker, marker + "\n        last = row['lastIncident']\n"
         "        incident.timing_open = last is not None and last['resumedAt'] is None")
    edit(JOURNAL, 'set(incident) == INCIDENT_FIELDS',
         "(set(incident) == INCIDENT_FIELDS or set(incident) == INCIDENT_FIELDS | {'timing'}\n"
         "            and valid_timing(incident['timing']))")

    _schedule(edit)
    _dns(edit)
    _publish(edit)
    _backend(edit)
    return out


def _schedule(edit):
    edit(CONTINUOUS, '        self.renewals = 0',
         '        self.renewals = 0\n        coordinator.owner.backend.timing = recovery.adapter.incident.timing')
    edit(CONTINUOUS, '        self.r.adapter.incident.begin()',
         '        timing = self.r.adapter.incident.timing\n        timing.next_cycle()\n'
         "        timing.event('tick')\n        self.r.adapter.incident.begin()")
    edit(CONTINUOUS, '            started = self.r.now()[1]',
         "            started = self.r.now()[1]\n            incident.timing.attempted = True\n"
         "            incident.timing.event('renew', at=started)")
    edit(CONTINUOUS, "        with self.c.owner.backend.within(deadline):\n            evidence =",
         "        self.incident.timing.attempted = True\n        self.incident.timing.event('renew')\n"
         "        with self.c.owner.backend.within(deadline):\n            evidence =")
    edit(CONTINUOUS, "            return {**row, 'waitSeconds': min(self.heartbeat, schedule['waitSeconds']),",
         "            wait = min(self.heartbeat, schedule['waitSeconds'])\n"
         "            self.r.adapter.incident.timing.event('plan', wait)\n"
         "            return {**row, 'waitSeconds': wait,")
    for delay in ("row.get('waitSeconds', self.r.wait_seconds(row, self.heartbeat))", 'delay'):
        edit(CONTINUOUS, f'if stop.wait({delay}):', f'if self.r.adapter.incident.timing.wait(stop, {delay}):')
    edit(ADAPTIVE, 'def sample_locked(coordinator, *, clock):',
         'def sample_locked(coordinator, *, clock, incident=None):')
    edit(ADAPTIVE, '    before = clock()',
         "    timing = incident.timing if incident is not None else None\n    before = clock()\n"
         "    if timing:\n        timing.event('sampleBefore', coordinator.renewal['renewalMarginSeconds'], at=before)")
    edit(ADAPTIVE, '            ttls.append(ttl)',
         "            ttls.append(ttl)\n        if timing:\n"
         "            timing.event('expires', i, min(left.values()), min(right.values()))")
    edit(ADAPTIVE, '    remaining = deadline - after',
         "    remaining = deadline - after\n    if timing:\n"
         "        timing.event('sampleAfter', remaining, deadline, at=after)")
    edit(ADAPTIVE, 'sample_locked(coordinator, clock=clock)', 'sample_locked(coordinator, clock=clock, incident=incident)')
    edit(CONTINUOUS, 'sample_locked(self.c, clock=self.clock)', 'sample_locked(self.c, clock=self.clock, incident=self.incident)')
    edit(CONTINUOUS, '            incident.lease_deadline = expires',
         "            incident.lease_deadline = expires\n            incident.timing.event('leaseLimit', expires)")


def _dns(edit):
    target = RECOVERY + 'dns.py'
    edit(target, 'question, qtype, deadline):\n    address =',
         'question, qtype, deadline, *, attempt=None):\n    address =')
    edit(target, '                raw = _udp_response',
         '                if attempt is not None:\n                    attempt()\n                raw = _udp_response')
    for method in ('prepare', 'prepare_renewal'):
        # Record the original attempt limit even if a pre-DNS guard denies.
        header = f'    def {method}(self, deadline):\n'
        edit(CONTINUOUS, header, header + "        self.incident.timing.event('attemptLimit', deadline)\n")
    edit(ADAPTER, 'import ipaddress', 'from itertools import count\nimport ipaddress')
    edit(ADAPTER, '        def bounded_query', '        attempts = count()\n        def bounded_query')
    edit(ADAPTER, 'min(query_deadline, time.monotonic() + remaining))',
         'min(query_deadline, time.monotonic() + remaining), attempt=attempts.__next__)')
    edit(ADAPTER, '        try:\n            observations =',
         "        timing = self.incident.timing\n"
         "        timing.event('dnsStart')\n        try:\n            observations =")
    edit(ADAPTER, 'monotonic=self.clock, deadline=deadline)', 'monotonic=self.clock, deadline=deadline, timing=timing)')
    edit(ADAPTER, '        values = [dict(endpointRef=',
         "        finally:\n            timing.event('dnsEnd', next(attempts))\n        values = [dict(endpointRef=")

    # Carry SOA provenance beside the private resolver result. Strip it before
    # any observation is returned. Late workers only access worker-local data.
    edit(target, 'qtype, deadline, query=exchange):', 'qtype, deadline, query=exchange, *, soa_ttls=None):')
    edit(target, "                ttls.extend(min(r['ttl'], r['value']) for r in soa)",
         "                negatives = [min(r['ttl'], r['value']) for r in soa]\n"
         "                ttls.extend(negatives)\n                if soa_ttls is not None:\n"
         "                    soa_ttls.append(min(negatives))")
    edit(target, 'query, monotonic, thread_factory):', 'query, monotonic, thread_factory, measure=False):')
    edit(target, '                types = {}', '                types = {}\n                soa = [] if measure else None')
    edit(target, 'qtype, deadline, bounded)', 'qtype, deadline, bounded, soa_ttls=soa)')
    edit(target, "                result = {'resolver': resolver, 'port': resolver_port, 'types': types}",
         "                result = {'resolver': resolver, 'port': resolver_port, 'types': types}\n"
         "                if soa:\n                    result['_soa'] = min(soa)")
    edit(target, 'wall_clock=time.time, thread_factory=threading.Thread):',
         'wall_clock=time.time, thread_factory=threading.Thread, timing=None):')
    edit(target, 'thread_factory=threading.Thread, deadline=None):',
         'thread_factory=threading.Thread, deadline=None, timing=None):')
    edit(target, 'wall_clock=wall_clock, thread_factory=thread_factory)',
         'wall_clock=wall_clock, thread_factory=thread_factory, timing=timing)')
    edit(target, 'deadline, query, monotonic, thread_factory)\n    elapsed',
         'deadline, query, monotonic, thread_factory, timing is not None)\n    elapsed')
    edit(target, '    results = []\n    # Integrity', '''    results = []
    if timing is not None:
        timing.event('dnsRound')
        minima = {}
        for (_, index), row in completed.items():
            if 'types' in row:
                ttl = min(t for value in row['types'].values() for t in value['ttls'])
                negative = row.pop('_soa', None) == ttl
                prior = minima.get(index)
                if prior is None or ttl < prior[0]:
                    minima[index] = (ttl, negative)
                elif ttl == prior[0] and negative:
                    minima[index] = (ttl, True)
        for index, (ttl, negative) in sorted(minima.items()):
            timing.event('ttl', index, ttl, negative)
    # Integrity''')


def _publish(edit):
    compiler = RECOVERY + 'readback_margin_compiler.py'
    edit(compiler, '*, apply_budget_seconds):', '*, apply_budget_seconds, timing=None):')
    edit(compiler, '    baseline = materialize(',
         "    if timing is not None:\n        timing.event('compile', at=now_monotonic)\n"
         "    timeouts = []\n    baseline = materialize(")
    edit(compiler, '            candidate = copy.deepcopy(configuration)',
         '            if timing is not None:\n                timeouts.append(seconds)\n'
         '            candidate = copy.deepcopy(configuration)')
    edit(compiler, "    return {'schema': 'ouf.southbound-lease-refresh-plan.v1'",
         "    if timing is not None and reason is None:\n"
         "        for index, seconds in enumerate(timeouts):\n            timing.event('timeout', index, seconds)\n"
         "        timing.event('planLimit', now_monotonic + apply_budget_seconds)\n"
         "    return {'schema': 'ouf.southbound-lease-refresh-plan.v1'")
    edit(ADAPTER, '        self.sealed(); self.scope_guard()',
         "        self.sealed(); self.scope_guard()\n        self.incident.timing.event('guardEnd')")
    edit(ADAPTER, "self.clock(), apply_budget_seconds=profile['applyBudgetSeconds'])",
         "self.clock(), apply_budget_seconds=profile['applyBudgetSeconds'], timing=self.incident.timing)")
    for target, indent in ((ADAPTER, ' ' * 16), (CONTINUOUS, ' ' * 12)):
        edit(target, "apply_budget_seconds=self.c.owner.profile['applyBudgetSeconds'])",
             "apply_budget_seconds=self.c.owner.profile['applyBudgetSeconds'], timing=self.incident.timing)")
        marker = ("backend.verify_ownership(cfg); self.guard()" if target == ADAPTER
                  else "backend.verify_ownership(cfg)\n" + indent + "self.guard()")
        edit(target, indent + marker,
             indent + "self.incident.timing.event('verify')\n" + indent + marker
             + '\n' + indent + "self.incident.timing.event('verifyEnd')")
        marker = 'self.c.publish(pending, ready)'
        edit(target, marker, "self.incident.timing.event('ready')\n" + indent + marker
             + '\n' + indent + "self.incident.timing.event('readyEnd')")


def _backend(edit):
    # Wrap the public lock factories, including the lock taken inside quiesce.
    # Site is selected at construction, before contextlib enters the generator.
    marker = '    coordinator = coordination.Coordinator(owner_object, owner["binding"], hold_lock, journal.read, journal.write)'
    edit(SUPERVISOR, marker, '''    def timed_lock(factory):
        def request(*args):
            acquire = factory(*args)
            timing = getattr(backend, 'timing', None)
            if timing is None:
                return acquire
            site = {'window': 0, 'publish_renewal': 1, 'prove_retry': 2, 'publish': 3,
                    'pause': 4, 'quiesce': 5}.get(sys._getframe(1).f_code.co_name, 6)
            return timing.lock(acquire, site)
        return request

''' + marker.replace(', hold_lock,', ', timed_lock(hold_lock),'))
    edit(SUPERVISOR, '    coordinator.hold_until = hold_until', '    coordinator.hold_until = timed_lock(hold_until)')
    target = RECOVERY + 'deadline_backend.py'
    marker = '        return super().run(arguments, raw, timeout=budget)'
    edit(target, marker, '''        timing = getattr(self, 'timing', None)
        if timing is None:
            return super().run(arguments, raw, timeout=budget)
        if arguments == ['-f', '-']:
            tag, indices = 'apply', ()
        elif len(arguments) == 5 and arguments[:3] == ['-j', 'list', 'table'] and arguments[3] in ('inet', 'bridge'):
            tag, indices = 'dump', (int(arguments[3] == 'bridge'),)
        else:
            return super().run(arguments, raw, timeout=budget)
        timing.event(tag, *indices)
        ok = False
        try:
            result = super().run(arguments, raw, timeout=budget)
            ok = True
            return result
        finally:
            timing.event(tag + 'End', *indices, ok)''')

