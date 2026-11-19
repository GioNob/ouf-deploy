"""R-022. Compose the cache-expiry continuation before the single source seal."""
from tools.semantic_provider_operation.authorization import require
from .lease_observability_overlay_v18 import ADAPTER, BUDGET, CONTINUOUS, JOURNAL, RECOVERY


DRIFT = 'R3_V23_SOURCE_CONTRACT_DRIFT'
EVENTS = ('cacheWait', 'cachePaused', 'cacheCollect', 'cacheShort', 'cacheRenewed', 'cacheFailed')


def sources_v23(sources, source_map):
    out = dict(sources)

    def edit(target, old, new):
        path = source_map[target]
        raw = out[path]
        eol = b'\r\n' if b'\r\n' in raw else b'\n'
        before, after = (s.encode('ascii').replace(b'\n', eol) for s in (old, new))
        require(raw.count(before) == 1, DRIFT)
        out[path] = raw.replace(before, after)

    bounded = RECOVERY + 'bounded_recovery.py'
    edit(bounded, 'class BeforeLeaseMutation', '''class CacheWait(Temporary):
    """A verified pause followed by one ordinary, budgeted recovery at cache expiry."""
    def __init__(self, collect_after):
        super().__init__('DNS_WINDOW_TOO_SHORT')
        self.collect_after = collect_after


class BeforeLeaseMutation''')
    edit(bounded, '        if delay >= remaining:', '''        wall, mono = self.now()
        if isinstance(error, CacheWait):
            delay = max(0, error.collect_after - mono)
        if delay >= remaining:''')
    edit(bounded, "        wall, mono = self.now()\n        return self.save(row, 'RETRY_WAIT'",
         "        return self.save(row, 'RETRY_WAIT'")

    # Only an accepted, compilable observation can arm a wait. End of DNS
    # bounds the latest packet supplying the minimum; compiler expiry is an
    # independent, conservative authorization bound and is never retimed.
    edit(ADAPTER, "            timing.event('dnsEnd', next(attempts))",
         "            dns_end = self.clock()\n            timing.event('dnsEnd', next(attempts))")
    edit(ADAPTER, "        return {'plan': plan, 'values': values, 'dnsObservations': observations}",
         """        minimum = self.c.renewal['immediateMinimumSeconds']
        now = self.clock()
        limits = {i: dns_end + data['minimumObservedTtlSeconds'] for i, data in enumerate(observations)
                  if data['minimumObservedTtlSeconds'] < min(profile['maxLeaseSeconds'],
                                                             cfg['providerFlows'][i]['leaseSeconds'])}
        short = [expiry for i, expiry in limits.items()
                 if values[i]['expiresMonotonic'] - now - profile['applyBudgetSeconds'] < minimum + 1]
        return {'plan': plan, 'values': values, 'dnsObservations': observations,
                'cacheBounds': limits, 'cacheExpiry': min(short, default=None)}""")
    edit(ADAPTER, "        timing.event('dnsStart')", """        single_round = self.cache_collect
        if single_round:
            self.cache_collect = False
            self.cache_event('cacheCollect')
        timing.event('dnsStart')""")
    edit(ADAPTER, 'monotonic=self.clock, deadline=deadline, timing=timing)',
         'monotonic=self.clock, deadline=deadline, timing=timing, single_round=single_round)')
    edit(ADAPTER, "            if str(error) == 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE':",
         "            if str(error) == 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE':\n"
         "                if single_round:\n                    self.cache_event('cacheShort')")
    # Both installed aliases of dns.py map to this one source blob.
    dns = RECOVERY + 'dns.py'
    edit(dns, 'sleep=time.sleep, thread_factory=threading.Thread, deadline=None, timing=None):',
         'sleep=time.sleep, thread_factory=threading.Thread, deadline=None, timing=None, single_round=False):')
    edit(dns, '            if attempt == 3: raise', '            if single_round or attempt == 3: raise')
    edit(ADAPTER, 'class LeaseAdapter:', 'CACHE_MARGIN = 1\n\n\nclass LeaseAdapter:\n' + CACHE_STATE)

    edit(CONTINUOUS, 'from bounded_recovery import BeforeLeaseMutation,',
         'from bounded_recovery import CacheWait, BeforeLeaseMutation,')
    edit(CONTINUOUS, '            evidence = super().prepare(deadline)', """            if self.cache_phase == 'cachePaused':
                if self.clock() < self.cache_due:
                    raise CacheWait(self.cache_due)
                self.cache_collect = True
            evidence = super().prepare(deadline)
            if evidence['cacheExpiry'] is not None and self.cache_phase in ('cacheCollect', 'cacheShort', 'cacheFailed'):
                if self.cache_phase == 'cacheCollect':
                    self.cache_event('cacheShort')
                raise Temporary('DNS_WINDOW_TOO_SHORT')""")
    # Capture the first readback time before the two nft dumps. Only the
    # exact READY/ref from this invocation can enable read-only waiting.
    for target in (ADAPTER, CONTINUOUS):
        padding = ' ' * 16
        marker = padding + 'sets = backend.read_sets(cfg)'
        edit(target, marker, padding + 'sampled = self.clock()\n' + marker)
        marker = padding + "self.incident.timing.event('ready')"
        edit(target, marker, padding + 'ref = fingerprint(ready)\n'
             + padding + 'self.track_cache_lease(evidence, ref, sampled, now, sets)\n' + marker)
        edit(target, padding + 'return fingerprint(ready)', padding + 'return ref')
    edit(CONTINUOUS, '            schedule = window(self.c,', '''            if self.r.adapter.cache_lease_ref is not None:
                return self.cache_lease_tick(row)
            schedule = window(self.c,''')
    edit(CONTINUOUS, "                return self.r.retry(row, Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True))",
         """                if self.r.adapter.cache_lease_ref is not None:
                    return self.pause_for_cache(row)
                return self.r.retry(row, Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True))""")
    edit(CONTINUOUS, "                if row['state'] == 'ACTIVE': self.renew(row, stop)",
         "                if row['state'] == 'ACTIVE' and not row.get('cacheWaitOnly'):\n"
         "                    self.renew(row, stop)")
    edit(CONTINUOUS, '    def renew(self, scheduled, stop):', WAIT + '    def renew(self, scheduled, stop):')
    edit(CONTINUOUS, "            while True:\n                if stop.is_set():",
         "            rollover = False\n            while True:\n                if stop.is_set():")
    edit(CONTINUOUS, '                    evidence = adapter.prepare_renewal(deadline)', """                    evidence = adapter.prepare_renewal(deadline)
                    if (evidence['cacheExpiry'] is not None
                            and all(set(v['addresses']) == set(a) for v, a in
                                    zip(evidence['values'], expected['leaseAddresses']))):
                        rollover = True
                        if row['attempts'] >= self.r.policy.max_attempts:
                            raise Temporary('DNS_WINDOW_TOO_SHORT')
                        adapter.arm_cache(evidence['cacheExpiry'])
                        row = self.r.save(row, 'ACTIVE', 'RENEWAL_RETRY_PENDING')
                        deadline = self.await_cache(row, expected, expires, deadline, stop)
                        if stop.is_set():
                            raise RenewalCancelled
                        row = self.r.save(row, 'ACTIVE', 'RENEWAL_RETRY_PENDING', attempts=row['attempts'] + 1)
                        adapter.cache_collect = True
                        evidence = adapter.prepare_renewal(deadline)
                        if evidence['cacheExpiry'] is not None:
                            adapter.cache_event('cacheShort')
                            raise Temporary('DNS_WINDOW_TOO_SHORT')""")
    edit(CONTINUOUS, "if (immediate or error.code == 'COMMON_LOCK_TIMEOUT'",
         "if (rollover or immediate or error.code == 'COMMON_LOCK_TIMEOUT'")

    # Persist the latest bounded scalar event even on successful renewals:
    # normal v22 timing frames are otherwise retained only at an incident.
    edit(BUDGET, "        values['lastIncident'] = incident.project", """        adapter = self.adapter
        if adapter.cache_phase == 'cacheCollect' and state == 'ACTIVE' and reason in ('RENEWED', 'RECOVERED'):
            adapter.cache_event('cacheRenewed')
        elif adapter.cache_phase in ('cacheWait', 'cacheCollect', 'cachePaused') and (
                state in ('BLOCKED', 'RECONCILE_REQUIRED', 'CANCELLED', 'PAUSED_EXHAUSTED')
                or state == 'RETRY_WAIT' and reason != 'DNS_WINDOW_TOO_SHORT'
                or state == 'RETRY_WAIT' and adapter.cache_phase != 'cachePaused'):
            adapter.cache_event('cacheFailed')
        if adapter.cache_record is not None:
            values['lastCacheRollover'] = adapter.cache_record
        values['lastIncident'] = incident.project""")
    # A long evidence accepted by ordinary recovery ends a short-TTL episode.
    edit(BUDGET, "        last = row['lastIncident']", """        if state != 'ACTIVE':
            adapter.cache_lease_ref = None
        if state == 'ACTIVE' and reason in ('RENEWED', 'RECOVERED') and adapter.cache_lease_ref is None:
            adapter.cache_phase = None
        last = row['lastIncident']""")
    edit(JOURNAL, "    'tick': '',", ''.join(f"    '{tag}': 'time time time',\n" for tag in EVENTS)
         + "    'tick': '',")
    edit(JOURNAL, "    incident = row.get('lastIncident')", """    if 'lastCacheRollover' in row:
        event = row['lastCacheRollover']
        require(valid_timing_event(event) and event[0] in """ + repr(EVENTS) + """,
                'RECOVERY_CACHE_ROLLOVER_INVALID')
    incident = row.get('lastIncident')""")
    return out


CACHE_STATE = '''
    cache_phase = cache_record = cache_lease_ref = None
    cache_collect = False

    def arm_cache(self, expiry):
        self.cache_expiry = expiry
        self.cache_due = expiry + CACHE_MARGIN
        self.cache_collected = 0
        self.cache_event('cacheWait')

    def cache_event(self, phase):
        now = self.clock()
        if phase == 'cacheCollect':
            self.cache_collected = now
        self.cache_collect = False
        self.cache_phase = phase
        self.cache_record = [phase, now, self.cache_expiry, self.cache_due, self.cache_collected]
        self.incident.timing.event(phase, *self.cache_record[2:], at=now)

    def track_cache_lease(self, evidence, ref, sampled, read_end, sets):
        now = self.clock()
        ends = {i: sampled + min(min(sets[family, i].values()) for family in ('inet', 'bridge'))
                for i in evidence['cacheBounds']}
        short = [expiry for i, expiry in evidence['cacheBounds'].items()
                 if ends[i] - now < self.c.renewal['immediateMinimumSeconds'] + 1]
        if short:
            if self.cache_phase in ('cacheCollect', 'cacheShort', 'cacheFailed'):
                if self.cache_phase == 'cacheCollect':
                    self.cache_event('cacheShort')
                raise Temporary('DNS_WINDOW_TOO_SHORT')
            self.arm_cache(min(short))
            self.cache_lease_ref = ref
            ttl = min(min(m.values()) for m in sets.values())
            self.cache_lease_end = sampled + ttl
            # Integer nft seconds truncate. Between the lower and upper bound
            # report WAITING and leave the actual finite element to the kernel.
            self.cache_lease_upper = min(read_end + ttl + 1,
                                         min(v['expiresMonotonic'] for v in evidence['values']))
'''


WAIT = '''    def cache_lease_tick(self, row):
        adapter = self.r.adapter
        if row.get('resultRef') != adapter.cache_lease_ref:
            raise Permanent('INTEGRITY_UNPROVEN')
        if self.r.now()[1] < adapter.cache_lease_end:
            lock_end = min(adapter.cache_lease_end, self.r.now()[1] + self.c.renewal['lockWaitSeconds'])
            with self.c.owner.backend.within(adapter.cache_lease_end), adapter.incident.lock(self.c.hold_until(lock_end)):
                adapter.incident.at('READBACK')
                sampled = adapter.clock()
                journal, end, _ = sample_locked(self.c, clock=adapter.clock, incident=adapter.incident)
            if fingerprint(journal) != adapter.cache_lease_ref:
                raise Permanent('INTEGRITY_UNPROVEN')
            adapter.cache_lease_end = min(adapter.cache_lease_end, end)
            now = self.r.now()[1]
            adapter.cache_lease_upper = min(adapter.cache_lease_upper, end + (now - sampled) + 1)
            wait = min(self.heartbeat, adapter.cache_lease_end - now)
            if wait > 0:
                return {**row, 'waitSeconds': wait, 'cacheWaitOnly': True}
        drain = adapter.cache_lease_upper - self.r.now()[1]
        if drain > 0:
            return {**row, 'state': 'WAITING', 'reason': 'DNS_WINDOW_TOO_SHORT',
                    'waitSeconds': min(self.heartbeat, drain)}
        return self.pause_for_cache(row)

    def pause_for_cache(self, row):
        adapter = self.r.adapter
        self.active_here = False
        adapter.cache_lease_ref = None
        adapter.cache_event('cachePaused')
        return self.r.retry(row, CacheWait(adapter.cache_due))

    def await_cache(self, row, expected, expires, deadline, stop):
        adapter = self.r.adapter
        timing = adapter.incident.timing
        # Retain only the independently installed lease. No nft or lease
        # journal writes while waiting. Recheck authority and exact membership
        # at each heartbeat; neither a later read nor DNS can move expires out.
        while True:
            if stop.is_set():
                raise RenewalCancelled
            adapter.guard()
            now = self.r.now()[1]
            remaining = self.r.remaining(row)
            if remaining <= 0:
                raise Temporary('DNS_WINDOW_TOO_SHORT')
            if now >= expires:
                adapter.cache_event('cachePaused')
                raise CacheWait(adapter.cache_due)
            if now < expires - COMMIT_SECONDS:
                try:
                    proved = adapter.prove_retry(expected, expires - COMMIT_SECONDS)
                except RuntimeError as error:
                    if not ttl_zero(error) and str(error) != 'LEASE_READ_WINDOW_EXHAUSTED':
                        raise
                    adapter.cache_event('cachePaused')
                    raise CacheWait(adapter.cache_due) from error
                expires = min(expires, proved + COMMIT_SECONDS)
                deadline = min(deadline, proved)
            now = self.r.now()[1]
            if now >= adapter.cache_due and now < deadline:
                # Continuation of the already admitted v22 attempt. The DNS
                # round and both publication fences share its original cap.
                return deadline
            wake = min(expires, adapter.cache_due) if now < adapter.cache_due else expires
            if timing.wait(stop, max(0, min(self.heartbeat, remaining, wake - now))):
                raise RenewalCancelled

'''
