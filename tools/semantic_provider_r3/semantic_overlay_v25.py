"""Bind the stable ingress to the v24 broker, preexec template and lease owner."""
from tools.semantic_provider_operation.authorization import require


def sources_v25(sources, mapping, identity):
    out = dict(sources)
    peers = 'tools/semantic_provider_peer_bindings.py'
    supervisor = 'tools/semantic_provider_operation/lease_supervisor.py'
    faces = 'tools/materialize_semantic_shared_faces.py'
    continuous = 'tools/semantic_lease_recovery/continuous_supervisor.py'
    recovery = 'tools/semantic_lease_recovery/'
    policy = recovery + 'lease_renewal_v18.py'

    def edit(target, old, new):
        path = mapping[target]
        eol = b'\r\n' if b'\r\n' in out[path] else b'\n'
        old, new = (v.encode().replace(b'\n', eol) for v in (old, new))
        require(out[path].count(old) == 1, 'R3_V25_SOURCE_CONTRACT_DRIFT')
        out[path] = out[path].replace(old, new)

    for target in (peers, supervisor):
        out[mapping[target]] += b'\n' + sources[identity]
    edit(peers, "        elif peer.get('kind') == IDENTITY_KIND:", """        elif peer.get('kind') == 'SEMANTIC_PROFILE':
            require(set(peer) == {'kind', 'declaration'}, 'R3_SEMANTIC_PROFILE_DRIFT')
            semantic_profile(peer['declaration'])
        elif peer.get('kind') == IDENTITY_KIND:""")
    for target, old in (
            ('tools/semantic_provider_deployment_admission.py', "if peer['kind'] in ('HOST', 'IDENTITY_PROVIDER_MAC'):"),
            ('tools/semantic_provider_deployment_admission.py', "if f['peerIngress']['kind'] not in ('HOST', 'IDENTITY_PROVIDER_MAC')}"),
            ('tools/semantic_provider_preexec_native.py', "if v['peerIngress']['kind'] not in ('HOST', 'IDENTITY_PROVIDER_MAC'))"),
            ('tools/semantic_provider_preexec_native.py', "if ingress['kind'] in ('HOST', 'IDENTITY_PROVIDER_MAC'):"),
            ('tools/semantic_provider_admission_v2/preparer_v2.py',
             'if v["peerIngress"]["kind"] not in ("HOST", "IDENTITY_PROVIDER_MAC"))')):
        edit(target, old, old.replace("'IDENTITY_PROVIDER_MAC'", "'IDENTITY_PROVIDER_MAC', 'SEMANTIC_PROFILE'")
                            .replace('"IDENTITY_PROVIDER_MAC"', '"IDENTITY_PROVIDER_MAC", "SEMANTIC_PROFILE"'))

    edit(faces, "        fields(peer, ('kind', 'ifindex'))", """        if peer.get('kind') == 'SEMANTIC_PROFILE':
            from tools.semantic_provider_peer_bindings import semantic_profile, semantic_check
            fields(peer, ('kind', 'declaration'))
            p_sem = semantic_profile(peer['declaration'])
            key = (str(source), str(destination), proto, p)
            semantic_check(key == (p_sem['ipv4'], p_sem['destination'], p_sem['protocol'], p_sem['port'])
                and flow['purpose'] == 'WORKLOAD_GATEWAY' and key not in seen
                and p_sem['bridge'] not in delegated and any(a['ipv4'] == str(destination)
                and a['bridge'] == p_sem['bridge'] for a in attachments))
            seen.add(key)
            checked.append((*key, peer))
            continue
        fields(peer, ('kind', 'ifindex'))""")
    edit(faces, "\n            elif not outgoing:", """
            elif peer['kind'] == 'SEMANTIC_PROFILE':
                if peer['declaration']['bridge'] != bridge: continue
                if outgoing:
                    incoming = 'ip daddr @semantic_open '
                elif layer == 'bridge':
                    incoming = 'meta iif @semantic_port ip saddr @semantic_open '
                else:
                    incoming = 'iifname "'+bridge+'" ip saddr @semantic_open '
            elif not outgoing:""")
    edit(faces, "            elif p['kind'] == 'BRIDGE_PORT':",
         "            elif p['kind'] in ('BRIDGE_PORT', 'SEMANTIC_PROFILE'):")
    for family in ('bridge', 'inet'):
        marker = f"    {family}_lines = ['table {family} '+table+' {{']"
        sets = ["' set semantic_open { type ipv4_addr; size 1; }'"]
        if family == 'bridge':
            sets.append("' set semantic_port { type iface_index; size 1; }'")
        edit(faces, marker, marker + "\n    if any(p['kind'] == 'SEMANTIC_PROFILE' for *_, p in checked):\n"
             + f"        {family}_lines.extend([{', '.join(sets)}])")

    edit('tools/semantic_provider_admission_v2/preparer_v2.py',
         '        verify_identity_flows(candidate["transport"], NodeObservation({}, self.budget).run)',
         '''        from tools.semantic_provider_peer_bindings import semantic_kernel_probe
        if any(f['peerIngress']['kind'] == 'SEMANTIC_PROFILE' for f in candidate['transport']):
            semantic_kernel_probe(self.command('ip'))
        verify_identity_flows(candidate["transport"], NodeObservation({}, self.budget).run)''')
    edit(supervisor, '"leaseRenewal", "driverBudgetSeconds"}',
         '"leaseRenewal", "driverBudgetSeconds", "semanticIngress"}')
    edit(policy, 'def validate(value):', '''def semantic_horizon(value):
    return value["semanticTickBudgetSeconds"] + value["semanticCloseReserveSeconds"] + 0.05


def validate(value):''')
    edit(policy, '"dnsTimeoutSeconds", "immediateMinimumSeconds",',
         '"semanticTickBudgetSeconds", "semanticCloseReserveSeconds", "semanticFullObservationSeconds",\n'
         '            "dnsTimeoutSeconds", "immediateMinimumSeconds",')
    edit(policy, 'if not (integer(value["dnsTimeoutSeconds"],', '''if not (type(value["semanticTickBudgetSeconds"]) in (int, float)
            and 0.70 <= value["semanticTickBudgetSeconds"] <= 3
            and type(value["semanticCloseReserveSeconds"]) in (int, float)
            and 0.2 <= value["semanticCloseReserveSeconds"] <= 0.75
            and integer(value["semanticFullObservationSeconds"], 5, 60)
            and integer(value["dnsTimeoutSeconds"],''')
    edit(policy, 'required + 2 <= minimum < margin',
         'required + 2 <= minimum and minimum + semantic_horizon(value) <= margin\n'
         '            and semantic_horizon(value) <= cap')
    edit(policy, 'def retry_reserve(profile):', '''def semantic_schedule(value, limits):
    if semantic_horizon(value) >= min(limits["heartbeatSeconds"], limits["pollSeconds"]):
        raise ValueError(INCOMPATIBLE)


def retry_reserve(profile):''')
    edit(supervisor, '        policy.budgets(renewal,',
         '        policy.semantic_schedule(renewal, cfg["limits"])\n        policy.budgets(renewal,')
    edit(supervisor, '    def factory(guards):',
         '    coordinator.semantic_horizon = policy.semantic_horizon(renewal)\n'
         '    bind_semantic_gate(cfg, coordinator, guards, read_file)\n\n    def factory(guards):')
    edit(supervisor, '                 "updatedAt": int(self.clock())}',
         '                 "semanticEpoch": self.c.semantic_epoch(), "lastSemanticTick": self.c.semantic_result,\n'
         '                 "lastSemanticVerifiedAgeMs": self.c.semantic_verified_age_ms(),\n'
         '                 "updatedAt": int(self.clock())}')
    edit(supervisor, '                    "recoveryScope": self.recovery_scope,',
         '                    "lastSemanticTick": self.c.semantic_result,\n'
         '                    "lastSemanticVerifiedAgeMs": self.c.semantic_verified_age_ms(),\n'
         '                    "recoveryScope": self.recovery_scope,')
    edit(supervisor, 'allowed = {"COMMON_LOCK_TIMEOUT",',
         'allowed = {"R3_SEMANTIC_CLOSE_UNVERIFIED", "COMMON_LOCK_TIMEOUT",')
    journal = recovery + 'recovery_journal.py'
    edit(recovery + 'bounded_recovery.py', "PERMANENT = {'AUTHORITY_REVOKED',",
         "PERMANENT = {'R3_SEMANTIC_CLOSE_UNVERIFIED', 'AUTHORITY_REVOKED',")
    edit(journal, "    'DNS_UNAVAILABLE', 'DNS_WINDOW_TOO_SHORT',",
         "    'R3_SEMANTIC_CLOSE_UNVERIFIED', 'DNS_UNAVAILABLE', 'DNS_WINDOW_TOO_SHORT',")
    edit(journal, "    incident = row.get('lastIncident')", """    age = row.get('lastSemanticVerifiedAgeMs')
    require(age is None or type(age) is int and 0 <= age < 2**63, 'RECOVERY_SEMANTIC_TICK_INVALID')
    tick = row.get('lastSemanticTick')
    if tick is not None:
        require(type(tick) is dict and set(tick) == {'outcome', 'durationMs'}
                and tick['outcome'] in ('VERIFIED', 'DEFERRED', 'CLOSED', 'R3_SEMANTIC_CLOSE_UNVERIFIED')
                and type(tick['durationMs']) is int and 0 <= tick['durationMs'] < 2**63,
                'RECOVERY_SEMANTIC_TICK_INVALID')
    incident = row.get('lastIncident')""")
    recovery_budget = recovery + 'lease_recovery_budget.py'
    edit(recovery_budget, "return {**super().initial(), 'lastIncident': None}",
         "return {**super().initial(), 'lastIncident': None, 'lastSemanticTick': self.adapter.c.semantic_result,\n"
         "                'lastSemanticVerifiedAgeMs': self.adapter.c.semantic_verified_age_ms()}")
    edit(recovery_budget, "        values['lastIncident'] = incident.project",
         "        values['lastSemanticTick'] = adapter.c.semantic_result\n"
         "        values['lastSemanticVerifiedAgeMs'] = adapter.c.semantic_verified_age_ms()\n"
         "        values['lastIncident'] = incident.project")
    edit(recovery + 'adaptive_supervisor.py', "'remainingSecondsLowerBound': remaining, 'bounds': bounds}",
         "'remainingSecondsLowerBound': remaining, 'bounds': bounds, 'sampledMonotonic': deadline - remaining}")
    edit(continuous, "            self.r.adapter.incident.timing.event('plan', wait)",
         """            wake = schedule['sampledMonotonic'] + wait
            self.c.semantic_tick(wake, schedule['deadlineMonotonic'], schedule['journal'])
            wait = max(0, wake - self.r.now()[1])
            self.r.adapter.incident.timing.event('plan', wait)""")
    edit(continuous, "            return {**row, 'waitSeconds': wait,",
         "            return {**row, 'waitSeconds': wait, 'wakeMonotonic': wake,")
    edit(continuous, "        if now >= adapter.cache_due:", """        if now >= adapter.cache_due:
            self.c.semantic_tick(adapter.cache_due, end, journal)""")
    edit(continuous, "        return {**value, 'waitSeconds': min(self.heartbeat, remaining, wake - now), 'cacheWaitOnly': True}",
         """        wake = min(wake, now + self.heartbeat, now + remaining)
        self.c.semantic_tick(wake, end, journal)
        return {**value, 'waitSeconds': max(0, wake - adapter.clock()), 'wakeMonotonic': wake, 'cacheWaitOnly': True}""")
    edit(continuous, "                if self.r.adapter.incident.timing.wait(stop, row.get('waitSeconds', self.r.wait_seconds(row, self.heartbeat))):",
         """                if 'wakeMonotonic' in row:
                    delay = max(0, row['wakeMonotonic'] - self.r.now()[1])
                else:
                    delay = row.get('waitSeconds', self.r.wait_seconds(row, self.heartbeat))
                if self.r.adapter.incident.timing.wait(stop, delay):""")
    return out
