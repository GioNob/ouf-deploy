"""R-022. Observe the installed finite elements until fresh collection or natural expiry."""
from tools.semantic_provider_operation.authorization import require
from .cache_rollover_overlay_v23 import WAIT
from .lease_observability_overlay_v18 import ADAPTER, ADAPTIVE, CONTINUOUS, RECOVERY


DRIFT = 'R3_V24_SOURCE_CONTRACT_DRIFT'


def sources_v24(sources, source_map):
    out = dict(sources)

    def edit(target, old, new):
        path = source_map[target]
        raw = out[path]
        eol = b'\r\n' if b'\r\n' in raw else b'\n'
        before, after = (s.encode('ascii').replace(b'\n', eol) for s in (old, new))
        require(raw.count(before) == 1, DRIFT)
        out[path] = raw.replace(before, after)

    nft = RECOVERY + 'nft_seconds_backend.py'
    edit(nft, 'def read_sets(self, configuration):', 'def read_sets(self, configuration, *, expiring=False):')
    edit(nft, "not 0 < ttl <= configuration", "not (0 if expiring else 1) <= ttl <= configuration")

    # Carry the original locked sample into an already admitted v23 continuation.
    edit(ADAPTIVE, 'def sample_locked(coordinator, *, clock, incident=None):',
         'def sample_locked(coordinator, *, clock, incident=None, bounds=None):')
    edit(ADAPTIVE, '    return journal, deadline, remaining', '''    if bounds is not None:
        bounds.update(expiry_bounds(sets, before, after))
    return journal, deadline, remaining


def expiry_bounds(sets, before, after):
    return {key: {addr: (before + ttl, after + ttl + 1) for addr, ttl in members.items()}
            for key, members in sets.items()}''')
    edit(ADAPTIVE, '    with (incident.lock(acquire)', '    bounds = {}\n    with (incident.lock(acquire)')
    edit(ADAPTIVE, 'clock=clock, incident=incident)', 'clock=clock, incident=incident, bounds=bounds)')
    edit(ADAPTIVE, "'remainingSecondsLowerBound': remaining}", "'remainingSecondsLowerBound': remaining, 'bounds': bounds}")
    edit(CONTINUOUS, "'leaseJournal': schedule['journal']}", "'leaseJournal': schedule['journal'], 'bounds': schedule['bounds']}")

    edit(ADAPTER, '        if short:', '''        self.cache_lease_ref = None
        if short:''')
    edit(ADAPTER, '            ttl = min(min(m.values()) for m in sets.values())',
         '''            from adaptive_supervisor import expiry_bounds
            self.cache_bounds = expiry_bounds(sets, sampled, read_end)
            self.cache_dns_limits = {i: v['expiresMonotonic'] for i, v in enumerate(evidence['values'])}
            ttl = min(min(m.values()) for m in sets.values())''')
    edit(ADAPTER, '''            # Integer nft seconds truncate. Between the lower and upper bound
            # report WAITING and leave the actual finite element to the kernel.
            self.cache_lease_upper = min(read_end + ttl + 1,
                                         min(v['expiresMonotonic'] for v in evidence['values']))''', '')
    edit(CONTINUOUS, WAIT, WATCH)
    edit(CONTINUOUS, '''                if self.r.adapter.cache_lease_ref is not None:
                    return self.pause_for_cache(row)''', '''                if self.r.adapter.cache_lease_ref is not None:
                    return self.r.pause(row, 'BLOCKED', 'INTEGRITY_UNPROVEN')''')
    edit(CONTINUOUS, "            expires = scheduled['leaseDeadlineMonotonic']",
         """            if scheduled.get('cacheTarget'):
                return self.collect_cache(row, scheduled, stop)
            expires = scheduled['leaseDeadlineMonotonic']""")
    edit(CONTINUOUS, '''                        deadline = self.await_cache(row, expected, expires, deadline, stop)
                        if stop.is_set():
                            raise RenewalCancelled
                        row = self.r.save(row, 'ACTIVE', 'RENEWAL_RETRY_PENDING', attempts=row['attempts'] + 1)
                        adapter.cache_collect = True
                        evidence = adapter.prepare_renewal(deadline)
                        if evidence['cacheExpiry'] is not None:
                            adapter.cache_event('cacheShort')
                            raise Temporary('DNS_WINDOW_TOO_SHORT')''', '''                        adapter.cache_bounds = scheduled['bounds']
                        adapter.cache_lease_ref = fingerprint(expected)
                        adapter.cache_lease_end = expires
                        adapter.cache_dns_limits = {}
                        while True:
                            if stop.is_set():
                                raise RenewalCancelled
                            pending = self.cache_lease_tick(row)
                            if pending.get('cacheTarget'):
                                return self.collect_cache(row, pending, stop, deadline)
                            if pending['state'] != 'ACTIVE' or not pending.get('cacheWaitOnly'):
                                return pending
                            if incident.timing.wait(stop, pending['waitSeconds']):
                                raise RenewalCancelled''')
    edit(CONTINUOUS, "                if row['state'] == 'ACTIVE' and not row.get('cacheWaitOnly'):",
         "                if row.get('cacheTarget') or row['state'] == 'ACTIVE' and not row.get('cacheWaitOnly'):")
    edit(CONTINUOUS, '''                    self.active_here = False
                    row = self.r.retry(self.r.journal.read(),
                                       Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True))
                    observe(projection(row))''', '''                    if self.r.adapter.cache_lease_ref is not None:
                        row = self.tick()
                    else:
                        self.active_here = False
                        row = self.r.retry(self.r.journal.read(),
                                           Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True))
                    observe(projection(row))''')
    # Recheck the same per-element bounds under the publication lock as well.
    edit(CONTINUOUS, '        journal, expires, _ = sample_locked(self.c, clock=self.clock, incident=self.incident)',
         '''        if self.cache_lease_ref is not None:
            journal, expires, _ = self.read_cache_lease()
            if expires is None:
                raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')
        else:
            journal, expires, _ = sample_locked(self.c, clock=self.clock, incident=self.incident)''')
    edit(CONTINUOUS, '    def prior_lease(self, expected):', READ + '    def prior_lease(self, expected):')
    # The mixed-flow continuation publishes through the cold, empty-set
    # entry point. Fence cancellation at both journal writes in that path.
    for target in (CONTINUOUS, ADAPTER):
        edit(target, 'def publish(self, evidence, deadline):',
             'def publish(self, evidence, deadline, check_commit=None):')
    edit(CONTINUOUS, 'return super().publish(evidence, deadline)',
         'return super().publish(evidence, deadline, check_commit)')
    edit(ADAPTER, '            with self.incident.lock(self.c.hold_lock()):',
         '''            lock = (self.c.hold_lock() if check_commit is None else
                    self.c.hold_until(min(deadline, self.clock() + self.c.renewal['lockWaitSeconds'])))
            with self.incident.lock(lock):''')
    for transition, mutated in [('previous, pending', False), ('pending, ready', True)]:
        marker = f'                self.c.publish({transition})'
        edit(ADAPTER, marker, f'                if check_commit is not None:\n'
             f'                    check_commit(deadline, {mutated})\n' + marker)
    return out


READ = '''    def read_cache_lease(self):
        # Caller owns the common lock. Zero is diagnostic only: it never proves
        # a usable lease. Each later interval must intersect its original proof.
        self.guard()
        self.incident.at('READBACK')
        journal = self.c.journal()
        if fingerprint(journal) != self.cache_lease_ref:
            raise Permanent('INTEGRITY_UNPROVEN')
        backend, cfg = self.c.owner.backend, self.c.configuration
        backend.verify_ownership(cfg)
        before = self.clock()
        sets = backend.read_sets(cfg, expiring=True)
        after = self.clock()
        if set(sets) != set(self.cache_bounds) or after < before:
            raise Permanent('INTEGRITY_UNPROVEN')
        full = True
        boundaries = []
        for key, members in sets.items():
            bounds = self.cache_bounds[key]
            dns_limit = self.cache_dns_limits.get(key[1])
            if not members.keys() <= bounds.keys():
                raise Permanent('INTEGRITY_UNPROVEN')
            for addr, (lower, upper) in list(bounds.items()):
                if addr not in members:
                    if after < lower:
                        raise Permanent('INTEGRITY_UNPROVEN')
                    del bounds[addr]  # A vanished member cannot reappear.
                    continue
                ttl = members[addr]
                self.cache_lease_end = min(self.cache_lease_end, before + ttl)
                if ttl == 0:
                    full = False
                lower, upper = max(lower, before + ttl), min(upper, after + ttl + 1)
                if lower >= upper:
                    raise Permanent('INTEGRITY_UNPROVEN')
                if dns_limit is not None and (lower > dns_limit or before >= dns_limit):
                    raise Permanent('INTEGRITY_UNPROVEN')
                bounds[addr] = lower, upper
                boundaries.extend((lower, min(upper, dns_limit) if dns_limit is not None else upper))
            if set(members) != set(journal['leaseAddresses'][key[1]]):
                full = False
        backend.verify_ownership(cfg)
        self.guard()
        if self.c.journal() != journal:
            raise Permanent('INTEGRITY_UNPROVEN')
        now = self.clock()
        end = self.cache_lease_end if full else None
        if end is not None and end <= now:
            end = None
        return journal, end, boundaries

'''


WATCH = '''    def inspect_cache(self, row):
        adapter = self.r.adapter
        if row.get('resultRef') != adapter.cache_lease_ref:
            raise Permanent('INTEGRITY_UNPROVEN')
        deadline = adapter.clock() + self.c.renewal['lockWaitSeconds']
        with self.c.owner.backend.within(deadline), adapter.incident.lock(self.c.hold_until(deadline)):
            journal, end, boundaries = adapter.read_cache_lease()
            if not boundaries:
                # All owned sets were read empty. Record quiescence without
                # sending the ordinary revoke transaction to nft.
                self.c.publish(journal, {**journal, 'state': 'QUIESCED', 'leaseAuthorized': False,
                                         'leaseAddresses': [[] for _ in journal['leaseAddresses']]})
            return journal, end, boundaries

    def cache_lease_tick(self, row):
        adapter = self.r.adapter
        remaining = self.r.remaining(row)
        if remaining <= 0:
            return self.r.pause(row, 'PAUSED_EXHAUSTED', 'RECOVERY_SCOPE_TIME_EXHAUSTED')
        journal, end, boundaries = self.inspect_cache(row)
        now = adapter.clock()
        if not boundaries:
            adapter.cache_event('cachePaused')
            self.active_here = False
            delay = max(0, adapter.cache_due - now)
            if row['attempts'] >= self.r.policy.max_attempts or delay >= self.r.remaining(row):
                return self.r.save(row, 'PAUSED_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED',
                                   nextWall=None, nextMonotonic=None)
            return self.r.save(row, 'RETRY_WAIT', 'DNS_WINDOW_TOO_SHORT',
                               nextWall=self.r.now()[0] + delay, nextMonotonic=now + delay)

        if row['reason'] != 'RENEWAL_RETRY_PENDING':
            row = self.r.save(row, 'ACTIVE', 'RENEWAL_RETRY_PENDING')
        remaining = self.r.remaining(row)
        if remaining <= 0:
            return self.r.pause(row, 'PAUSED_EXHAUSTED', 'RECOVERY_SCOPE_TIME_EXHAUSTED')
        now = adapter.clock()
        if end is not None and end <= now:
            end = None
        # The trace records supervision separately from lack of a complete
        # positive lease. Neither event grants additional time to any element.
        expired = any(len(members) < len(journal['leaseAddresses'][index])
                      for (_, index), members in adapter.cache_bounds.items())
        tag = 'cachePaused' if expired else 'cacheWait'
        adapter.incident.timing.event(tag, adapter.cache_expiry, adapter.cache_due, 0)
        value = dict(row) if end is not None else {**row, 'state': 'WAITING', 'reason': 'DNS_WINDOW_TOO_SHORT'}
        if now >= adapter.cache_due:
            return {**value, 'cacheTarget': True, 'leaseJournal': journal,
                    'leaseDeadlineMonotonic': end, 'waitSeconds': 0}
        wake = min(t for t in [adapter.cache_due, adapter.cache_lease_end, *boundaries] if t > now)
        return {**value, 'waitSeconds': min(self.heartbeat, remaining, wake - now), 'cacheWaitOnly': True}

    def collect_cache(self, row, scheduled, stop, prior_deadline=None):
        adapter = self.r.adapter
        if stop.is_set():
            return self.r.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')
        if (adapter.cache_phase != 'cacheWait' or adapter.clock() < adapter.cache_due
                or row['resultRef'] != adapter.cache_lease_ref
                or fingerprint(scheduled['leaseJournal']) != adapter.cache_lease_ref):
            return self.r.pause(row, 'BLOCKED', 'INTEGRITY_UNPROVEN')
        if row['attempts'] >= self.r.policy.max_attempts:
            return self.r.pause(row, 'PAUSED_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED')
        row = self.r.save(row, 'ACTIVE', 'RENEWAL_RETRY_PENDING', attempts=row['attempts'] + 1)
        started = adapter.clock()
        deadline = started + min(self.r.policy.attempt_timeout, self.r.remaining(row))
        end = scheduled['leaseDeadlineMonotonic']
        if end is not None:
            live_limit = min(deadline, end - COMMIT_SECONDS)
            if prior_deadline is not None:
                live_limit = min(live_limit, prior_deadline)
            if live_limit <= started + COMMIT_SECONDS:
                end = None  # Only publication from verified empty will be allowed.
            else:
                deadline = live_limit
        publishing = False
        try:
            adapter.cache_collect = True
            evidence = adapter.prepare_renewal(deadline)
            if stop.is_set():
                raise RenewalCancelled
            if evidence['cacheExpiry'] is not None:
                adapter.cache_event('cacheShort')
                raise Temporary('DNS_WINDOW_TOO_SHORT')
            if end is None:
                # Mixed flows can straddle cache_due. Collect on time, then
                # finish natural expiry before ordinary publication from empty.
                while True:
                    if stop.is_set():
                        raise RenewalCancelled
                    if adapter.clock() >= deadline or self.r.remaining(row) <= 0:
                        raise Temporary('DNS_WINDOW_TOO_SHORT')
                    _, _, boundaries = self.inspect_cache(row)
                    if not boundaries:
                        break
                    now = adapter.clock()
                    if max(boundaries) <= now:
                        continue  # The last timer elapsed during the read.
                    wake = min([deadline] + [t for t in boundaries if t > now])
                    if adapter.incident.timing.wait(stop, max(0, min(self.heartbeat, wake - now))):
                        raise RenewalCancelled
            if stop.is_set():
                raise RenewalCancelled
            if adapter.clock() >= deadline or self.r.remaining(row) <= 0:
                raise Temporary('DNS_WINDOW_TOO_SHORT')
            publishing = True
            if end is None:
                def check_commit(limit, mutated):
                    if stop.is_set():
                        if mutated:
                            raise PublicationAmbiguous
                        raise RenewalCancelled
                    if adapter.clock() >= limit or self.r.remaining(row) <= 0:
                        if mutated:
                            raise PublicationAmbiguous
                        raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')
                ref = adapter.publish(evidence, deadline, check_commit)
            else:
                ref = adapter.publish_renewal(evidence, deadline, scheduled['leaseJournal'], stop)
            if stop.is_set() or adapter.clock() >= deadline or self.r.remaining(row) <= 0:
                raise PublicationAmbiguous
            if type(ref) is not str or not re.fullmatch('[0-9a-f]{64}', ref):
                raise PublicationAmbiguous
            result = self.r.save(row, 'ACTIVE', 'RENEWED', resultRef=ref)
            self.renewals += 1
            return result
        except RenewalCancelled:
            return self.r.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')
        except BeforeLeaseMutation as error:
            return self.r.retry(row, error)
        except Exception as error:
            adapter.incident.failed(error)
            if publishing:
                return self.r.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS')
            if isinstance(error, Temporary):
                return self.r.retry(row, error)
            return self.r.pause(row, 'BLOCKED', getattr(error, 'code', 'INTEGRITY_UNPROVEN'))

'''
