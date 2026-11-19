"""Bind the stable ingress to the v24 broker, preexec template and lease owner."""
from tools.semantic_provider_operation.authorization import require


def sources_v25(sources, mapping, identity):
    out = dict(sources)
    peers = 'tools/semantic_provider_peer_bindings.py'
    supervisor = 'tools/semantic_provider_operation/lease_supervisor.py'
    faces = 'tools/materialize_semantic_shared_faces.py'
    continuous = 'tools/semantic_lease_recovery/continuous_supervisor.py'

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
    edit(supervisor, '    def factory(guards):', '    bind_semantic_gate(cfg, coordinator, guards, read_file)\n\n    def factory(guards):')
    edit(supervisor, '                 "updatedAt": int(self.clock())}',
         '                 "semanticEpoch": self.c.semantic_epoch(),\n                 "updatedAt": int(self.clock())}')
    edit(continuous, '    def tick(self):\n', '    def tick(self):\n        self.c.semantic_tick()\n')
    edit(continuous, '    def inspect_cache(self, row):\n',
         '    def inspect_cache(self, row):\n        self.c.semantic_tick()\n')
    return out
