"""R-002. Compose the supervisor's private positive signature memo and renewal handoff."""
from tools.semantic_provider_operation.authorization import require
from .lease_observability_overlay_v18 import ADAPTER, BUDGET, CONTINUOUS, JOURNAL, RECOVERY, SUPERVISOR


AUTH = 'tools/semantic_provider_operation/authorization.py'
DRIFT = 'R3_V27_SOURCE_CONTRACT_DRIFT'


MEMO = '''class SignatureMemo:
    """One supervisor instance. A slot represents exactly one verified chain link."""
    def __init__(self):
        self.slots = {}

    def head(self, *args, **kwargs):
        try:
            return head(*args, **kwargs, memo=self)
        except BaseException:
            self.slots.clear()
            raise

    def verify(self, mandates, authenticator, slot, frame, public_key, signature):
        require(type(slot) is int and 1 <= slot <= MAX_CHAIN, "OPERATION_CHAIN_UNBOUNDED")
        binding = authenticator.openssl_binding
        path = Path(binding["path"])
        # Retain path custody on hits. An inode change requires requalifying
        # the binding and version via the complete native verifier.
        mandates.ancestors(path)
        before = mandates.attributes(path.lstat())
        key = (sha(frame), sha(signature), sha(public_key), str(path),
               binding["sha256"], binding["version"], before)
        authenticator.budget.check()
        if self.slots.get(slot) != key:
            authenticator.verify(frame, public_key, signature)
        require(mandates.attributes(path.lstat()) == before, "OPERATION_EXECUTABLE_CHANGED")
        authenticator.budget.check()
        self.slots[slot] = key


def chain_identity(root, count, attributes):
    return (attributes(root.lstat()), tuple(attributes((root / f"{n}.{suffix}").lstat())
            for n in range(1, count + 1) for suffix in ("json", "signature.json")))


'''


LOCKS = '''class IngressWriterBusy(Exception):
    """An exclusive writer prevented this tick from taking a shared flock."""


@contextmanager
def ingress_writer_locks(cfg, guards):
    # Writers acquire CID locks before the authorization directory. A writer
    # may already be waiting for our common lock: never wait for these locks.
    import errno
    import fcntl
    with ExitStack() as stack:
        paths = [Path(cfg["registryRoot"]) / cid / "operation.lock"
                 for cid in sorted(v["containerId"] for v in guards.fixed.values())]
        for path in [*paths, Path(cfg["authorizationRoot"])]:
            directory = path == Path(cfg["authorizationRoot"])
            ancestors(path)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(path, flags | (os.O_DIRECTORY if directory else 0))
            stack.callback(os.close, fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as error:
                if error.errno != errno.EWOULDBLOCK:
                    raise
                raise IngressWriterBusy() from error
            info = os.fstat(fd)
            semantic_check(info.st_uid == info.st_gid == 0 and os.path.samestat(info, path.lstat()))
            if directory:
                semantic_check(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
            else:
                semantic_check(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                               and info.st_size == 0 and info.st_nlink == 1)
        yield


'''


def sources_v27(sources, mapping):
    out = dict(sources)

    def edit(target, old, new):
        path = mapping[target]
        raw = out[path]
        # The identity module is appended by v25 and may have its own EOL.
        before, after = old.encode(), new.encode()
        require(raw.replace(b'\r\n', b'\n').count(before) == 1, DRIFT)
        crlf = before.replace(b'\n', b'\r\n')
        if b'\r\n' in raw and crlf in raw:
            before, after = crlf, after.replace(b'\n', b'\r\n')
        require(before in raw, DRIFT)
        out[path] = raw.replace(before, after)

    edit(AUTH, 'def verify_entry(mandates, ledger, authenticator, raw, signature_raw, expected):',
         MEMO + 'def verify_entry(mandates, ledger, authenticator, raw, signature_raw, expected, *, memo=None, slot=None):')
    edit(AUTH, '''        authenticator.verify(signing_bytes(raw, header), bytes.fromhex(mandate["publicKey"]),
                             bytes.fromhex(record["signature"]))''', '''        args = signing_bytes(raw, header), bytes.fromhex(mandate["publicKey"]), bytes.fromhex(record["signature"])
        if memo is None:
            authenticator.verify(*args)
        else:
            memo.verify(mandates, authenticator, slot, *args)''')
    edit(AUTH, 'clock, budget=None):', 'clock, budget=None, *, memo=None):')
    edit(AUTH, '    previous = None', '''    if memo is not None:
        for n in tuple(memo.slots):
            if n > count:
                del memo.slots[n]
        identities = chain_identity(root, count, mandates.attributes)
    previous = None''')
    edit(AUTH, 'authenticator, raw, signature_raw, expected)\n',
         'authenticator, raw, signature_raw, expected, memo=memo, slot=number)\n')
    edit(AUTH, '    return {"sequence": count', '''    if memo is not None:
        require(chain_identity(root, count, mandates.attributes) == identities,
                "OPERATION_CHAIN_CHANGED_DURING_VERIFICATION")
    return {"sequence": count''')
    edit(SUPERVISOR, '                    retained=custody)',
         '                    head=authorization.SignatureMemo().head, retained=custody)')
    edit(SUPERVISOR, 'def bind_semantic_gate(', LOCKS + 'def bind_semantic_gate(')
    edit(SUPERVISOR, '    coordinator.semantic_result = None',
         '    coordinator.semantic_window_ms = None\n    coordinator.semantic_result = None')
    edit(SUPERVISOR, "        outcome = 'DEFERRED'", """        available = 0 if lease_end is None else min(wake, lease_end) - started
        coordinator.semantic_window_ms = int(max(0, available) * 1000)
        outcome = 'DEFERRED'""")
    edit(SUPERVISOR, '''                        footprint = driver_footprint()
                        check_time()
                        gate.reconcile(footprint, link=link, refresh=cadence, clock=clock)''',
         '''                        check_time()
                        semantic_check(min(wake, lease_end) >= ordinary_end + reserve)
                        with ingress_writer_locks(cfg, guards):
                            footprint = driver_footprint()
                            check_time()
                            gate.reconcile(footprint, link=link, refresh=cadence, clock=clock)
                            # The mandate ledger has no writer flock. Recheck its
                            # snapshot and live epochs before acknowledging the opening.
                            guards.scope_guard()''')
    edit(SUPERVISOR, 'fatal = footprint is None and not timeout',
         '''fatal = (footprint is None and not timeout and not isinstance(error, IngressWriterBusy)
                             or isinstance(error, guards.Permanent))''')
    for spaces in (17, 20):
        marker = '\n' + ' ' * spaces + '"lastSemanticVerifiedAgeMs":'
        edit(SUPERVISOR, marker, marker.replace('VerifiedAge', 'Window') + ' self.c.semantic_window_ms,' + marker)
    edit(BUDGET, "'lastSemanticVerifiedAgeMs': self.adapter.c.semantic_verified_age_ms()}",
         "'lastSemanticWindowMs': self.adapter.c.semantic_window_ms,\n"
         "                'lastSemanticVerifiedAgeMs': self.adapter.c.semantic_verified_age_ms()}")
    edit(BUDGET, "        values['lastSemanticTick']", "        values['lastSemanticWindowMs'] = adapter.c.semantic_window_ms\n"
         "        values['lastSemanticTick']")
    edit(JOURNAL, "    age = row.get('lastSemanticVerifiedAgeMs')", """    window = row.get('lastSemanticWindowMs')
    require(window is None or type(window) is int and 0 <= window < 2**63, 'RECOVERY_SEMANTIC_TICK_INVALID')
    age = row.get('lastSemanticVerifiedAgeMs')""")
    _schedule(edit)
    return out


def _schedule(edit):
    policy = RECOVERY + 'lease_renewal_v18.py'
    edit(policy, 'and margin + 1 < effective_lease',
         'and semantic_horizon(value) <= min(effective_lease / 2, effective_lease - margin - GUARD_SECONDS)\n'
         '            and margin + 1 < effective_lease')
    edit(ADAPTER, '        ends = {i: sampled', '''        # Keep the validated two-family readback private until RENEWED.
        end = sampled + min(min(members.values()) for members in sets.values())
        self.publication_sample = (ref, read_end, end)
        ends = {i: sampled''')
    edit(CONTINUOUS, '        self.renewals = 0',
         '        self.renewals = 0\n        self.committed_sample = self.renewed_ref = None')
    edit(CONTINUOUS, '    def tick(self):', '''    def tick(self):
        committed, self.committed_sample = self.committed_sample, None''')
    edit(CONTINUOUS, '    def renew(self, scheduled, stop):', '''    def renew(self, scheduled, stop):
        self.committed_sample = None
        self.r.adapter.publication_sample = None
        row = self._renew(scheduled, stop)
        # Both ordinary renewal and collect_cache have left their publication
        # handlers and durably saved ACTIVE/RENEWED before this handoff.
        if row['state'] == 'ACTIVE' and row['reason'] == 'RENEWED':
            sample = self.r.adapter.publication_sample
            if sample is None or sample[0] != row['resultRef']:
                return self.r.pause(row, 'BLOCKED', 'INTEGRITY_UNPROVEN')
            self.committed_sample = sample
            self.renewed_ref = sample[0]
        return row

    def _renew(self, scheduled, stop):''')
    edit(CONTINUOUS, "            if self.r.adapter.cache_lease_ref is not None:\n                return self.cache_lease_tick(row)",
         """            if self.r.adapter.cache_lease_ref is not None:
                planned = self.cache_lease_tick(row)
                if committed is not None and planned.get('cacheWaitOnly'):
                    ref, sampled, end = committed
                    if ref != row['resultRef']:
                        raise Permanent('INTEGRITY_UNPROVEN')
                    wake, lease_end, journal = planned['semanticSlot']
                    wake = min(wake, sampled + self.heartbeat)
                    planned.update(wakeMonotonic=wake, waitSeconds=max(0, wake - self.r.now()[1]),
                                   semanticSlot=(wake, min(end, lease_end) if lease_end is not None else None, journal))
                return planned""")
    edit(CONTINUOUS, "            self.c.semantic_tick(wake, schedule['deadlineMonotonic'], schedule['journal'])",
         """            slot = None
            if committed is not None:
                ref, sampled, end = committed
                if ref != row['resultRef'] or fingerprint(schedule['journal']) != ref:
                    raise Permanent('INTEGRITY_UNPROVEN')
                remaining = end - sampled
                wake = min(wake, sampled + min(self.poll, self.heartbeat, remaining / 2),
                           end - self.c.renewal['renewalMarginSeconds'] - GUARD_SECONDS,
                           self.r.now()[1] + self.r.remaining(row))
                slot = (wake, min(end, schedule['deadlineMonotonic']), schedule['journal'])""")
    edit(CONTINUOUS, "return {**row, 'waitSeconds': wait, 'wakeMonotonic': wake,",
         "return {**row, 'semanticSlot': slot, 'waitSeconds': wait, 'wakeMonotonic': wake,")
    edit(CONTINUOUS, 'from lease_renewal_v18 import COMMIT_SECONDS,',
         'from lease_renewal_v18 import GUARD_SECONDS, COMMIT_SECONDS,')
    edit(CONTINUOUS, '            self.c.semantic_tick(adapter.cache_due, end, journal)\n', '')
    edit(CONTINUOUS, "        self.c.semantic_tick(wake, end, journal)\n        return {**value,",
         """        slot = (wake, end, journal) if self.renewed_ref == adapter.cache_lease_ref else None
        return {**value, 'semanticSlot': slot,""")
    edit(CONTINUOUS, "        if row['state'] != 'ACTIVE':\n            try:",
         "        if row['state'] != 'ACTIVE':\n            self.renewed_ref = None\n            try:")
    edit(CONTINUOUS, '    def serve(self, stop, observe):', '''    def ingress_before_wait(self, row, stop):
        slot = row.pop('semanticSlot', None)
        if slot is not None and not stop.is_set():
            try:
                self.c.semantic_tick(*slot)
            except Exception as error:
                self.active_here = False
                return self.r.pause(self.r.journal.read(), 'BLOCKED', getattr(error, 'code', 'INTEGRITY_UNPROVEN'))
        return row

    def serve(self, stop, observe):''')
    edit(CONTINUOUS, "                if 'wakeMonotonic' in row:", """                # All mandatory pre-wait work (including status observation) is complete.
                planned = self.ingress_before_wait(row, stop)
                if planned is not row:
                    row = planned
                    observe(projection(row))
                if 'wakeMonotonic' in row:""")
    edit(CONTINUOUS, "                            if incident.timing.wait(stop, pending['waitSeconds']):",
         """                            pending = self.ingress_before_wait(pending, stop)
                            if pending['state'] != 'ACTIVE':
                                return pending
                            if incident.timing.wait(stop, max(0, pending['wakeMonotonic'] - adapter.clock())):""")
