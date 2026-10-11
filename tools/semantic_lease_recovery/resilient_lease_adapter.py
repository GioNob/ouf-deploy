"""Prospective scoped recovery of owned finite leases; new authority required.

Does not install a service, adopt a claim, recreate tables or mutate profiles.
Entrypoint must supply sealed modules, command/ancestor custody and a new live
recovery scope bound to exact current process generations and finite budgets.
"""
import ipaddress
from bounded_recovery import Permanent, Temporary, fingerprint

class LeaseAdapter:
    def __init__(self, coordinator, dns, compiler, scope_guard, custody_guard, clock):
        self.c = coordinator; self.dns = dns; self.compiler = compiler
        self.scope_guard = scope_guard; self.custody_guard = custody_guard; self.clock = clock
        self.config_hash = fingerprint(coordinator.configuration)
        self.profile_hash = fingerprint(coordinator.owner.profile)
        self.structure_hash = coordinator.owner.backend.expected

    def sealed(self):
        if (fingerprint(self.c.configuration) != self.config_hash
                or fingerprint(self.c.owner.configuration) != self.config_hash
                or fingerprint(self.c.owner.profile) != self.profile_hash
                or self.c.owner.backend.expected != self.structure_hash):
            raise Permanent('CONFIGURATION_DRIFT')
        self.custody_guard()

    def guard(self):
        self.sealed(); self.scope_guard()

    def pause(self):
        # Narrowing/revocation remains possible after recovery authority expires;
        # independent ownership/custody must still be proved before any write.
        self.sealed()
        with self.c.hold_lock():
            value = self.c.journal()
            if value['state'] == 'QUIESCED' and value['leaseAuthorized'] is False:
                if any(self.c.sets()): raise Permanent('INTEGRITY_UNPROVEN')
                return
        self.c.quiesce()

    def prepare(self, deadline):
        self.guard(); self.pause()
        cfg = self.c.configuration; profile = self.c.owner.profile
        values = []
        for flow in cfg['providerFlows']:
            before = self.clock()
            if before >= deadline: raise Temporary('DEPENDENCY_TIMEOUT')
            try:
                data = self.dns.observe(flow['endpoint'], profile['resolvers'], profile['resolverPort'],
                    ipaddress.ip_address(flow['source']).version,
                    [a + '/' + str(ipaddress.ip_address(a).max_prefixlen) for a in flow['allowedPrivateAddresses']],
                    profile['timeoutSeconds'], profile['maxLeaseSeconds'])
            except self.dns.DNSDenied as error:
                if str(error) in {'DNS_RESOLVER_TRANSPORT_FAILED', 'DNS_DEADLINE_EXPIRED'}:
                    raise Temporary('DNS_UNAVAILABLE') from None
                if str(error) == 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE':
                    raise Temporary('DNS_WINDOW_TOO_SHORT') from None
                raise Permanent('INTEGRITY_UNPROVEN') from None
            values.append(dict(endpointRef=flow['endpointRef'], endpoint=flow['endpoint'],
                resolutionEvidenceRef=flow['resolutionEvidenceRef'], addresses=data['usableAddresses'],
                observedMonotonic=before, expiresMonotonic=before + data['remainingLeaseSecondsAtObservation'],
                historicalEvidenceOnly=False))
        self.guard()
        plan = self.compiler.compile_refresh(cfg, values, self.clock(), apply_budget_seconds=profile['applyBudgetSeconds'])
        if plan['denyOnly']: raise Temporary('DNS_WINDOW_TOO_SHORT')
        return {'plan': plan, 'values': values}

    def publish(self, evidence, deadline):
        self.guard()
        plan, values = evidence['plan'], evidence['values']
        deadline = min(deadline, plan['mustApplyByMonotonic'])
        if self.clock() >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True)
        try:
            with self.c.hold_lock():
                self.guard()
                previous = self.c.journal()
                if previous['state'] != 'QUIESCED' or previous['leaseAuthorized'] is not False or any(self.c.sets()):
                    raise Permanent('INTEGRITY_UNPROVEN')
                pending = {**previous, 'state': 'LEASE_UPDATING', 'leaseAuthorized': False}
                self.c.publish(previous, pending)
                backend = self.c.owner.backend; cfg = self.c.configuration
                backend.verify_ownership(cfg)
                if self.clock() >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT')
                backend.apply(plan['nftTransaction'], deadline)
                sets = backend.read_sets(cfg); now = self.clock()
                if now >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT')
                expected = {(family, i) for family in ('inet', 'bridge') for i in range(len(values))}
                if set(sets) != expected: raise Permanent('INTEGRITY_UNPROVEN')
                for (family, index), members in sets.items():
                    if set(members) != set(values[index]['addresses']): raise Permanent('INTEGRITY_UNPROVEN')
                    for ttl in members.values():
                        if type(ttl) is not int or not 0 < ttl <= cfg['providerFlows'][index]['leaseSeconds']:
                            raise Permanent('INTEGRITY_UNPROVEN')
                        if now + ttl > values[index]['expiresMonotonic']:
                            raise Permanent('INTEGRITY_UNPROVEN')
                backend.verify_ownership(cfg); self.guard()
                if self.clock() >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT')
                ready = {**pending, 'state': 'LEASE_READY', 'leaseAuthorized': True,
                         'leaseAddresses': [sorted(sets['inet', i]) for i in range(len(values))]}
                self.c.publish(pending, ready)
                return fingerprint(ready)
        except Temporary:
            self.pause()
            # Atomic ACL operation + verified revocation is safely repeatable
            # with NEW evidence. No application/provider request was replayed.
            raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
        except RuntimeError as error:
            facts = getattr(error, 'nft_readback', {})
            if (str(error) == 'NFT_SET_TTL_UNPROVEN' and facts.get('expiresType') == 'int'
                    and facts.get('expiresValue') == 0 and facts.get('duplicateAddress') is False):
                self.pause()
                raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
            raise Permanent('INTEGRITY_UNPROVEN') from None
