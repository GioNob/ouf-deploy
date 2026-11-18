"""Narrow, version-local patches of the frozen admission/role source contracts.

As with sources_v12, each anchor must occur exactly once. Installed source names
and the broker's closed package stay identical; all patched bytes are hashed.
"""
from tools.semantic_provider_operation.authorization import require


def sources_v13(sources, historical_map, identity_source, driver_check=True):
    """driver_check=False (v14+): the live identity read stays in the preparer only.

    The driver re-runs authorize() up to three times inside one 5 s verification
    budget during OCI start; four Docker reads per call exceeded it on the VPS
    (start v13, 18/11). The bridge rules stay bound to the declared IP/MAC.
    """
    out = dict(sources)

    def edit(target, old, new):
        path = historical_map.get(target, target)
        old, new = old.encode(), new.encode()
        require(out[path].count(old) == 1, 'R3_V13_SOURCE_CONTRACT_DRIFT')
        out[path] = out[path].replace(old, new)

    peers = 'tools/semantic_provider_peer_bindings.py'
    out[historical_map[peers]] += b'\n' + sources[identity_source]
    edit(peers, "        else:\n            require(set(peer) == {'kind', 'ifindex'}",
         "        elif peer.get('kind') == IDENTITY_KIND:\n"
         "            identity_peer(peer['declaration'])\n"
         "            identity_require(set(peer) == {'kind', 'declaration'})\n"
         "        else:\n            require(set(peer) == {'kind', 'ifindex'}")

    faces = 'tools/materialize_semantic_shared_faces.py'
    edit(faces, "        fields(peer, ('kind', 'ifindex'))", """        if peer.get('kind') == 'IDENTITY_PROVIDER_MAC':
            from tools.semantic_provider_peer_bindings import identity_peer, identity_require
            identity_require(set(peer) == {'kind', 'declaration'})
            identity = identity_peer(peer['declaration'])
            own = [a for a in attachments if a['ipv4'] == str(source) and a['bridge'] == identity['bridge']]
            identity_require(len(own) == 1 and identity['bridge'] not in delegated
                and flow['purpose'] == 'IDENTITY' and proto == 'tcp'
                and str(destination) == identity['ipv4'] and p == identity['port'],
                'R3_IDENTITY_PROVIDER_FLOW_DRIFT')
            key = (str(source), str(destination), proto, p)
            if key in seen: raise ValueError('duplicate transport binding')
            seen.add(key); checked.append((*key, peer))
            continue
        fields(peer, ('kind', 'ifindex'))""")
    edit(faces, "            if not outgoing:\n                if layer == 'bridge':", """            if peer['kind'] == 'IDENTITY_PROVIDER_MAC':
                if peer['declaration']['bridge'] != bridge: continue
                if layer == 'bridge':
                    incoming = 'ether '+('daddr' if outgoing else 'saddr')+' '+peer['declaration']['mac']+' '
                elif not outgoing:
                    incoming = 'iifname "'+bridge+'" '
            elif not outgoing:
                if layer == 'bridge':""")
    # Preserve historical ARP on other faces. On the identity shared face allow
    # only the declared peers; bind both Ethernet and ARP sender on replies.
    edit(faces, "    bridge_lines = ['table bridge '+table+' {']", """    def arp_rules(address, mac, bridge, outgoing):
        identities = [p['declaration'] for s, d, proto, port, p in checked
                      if p['kind'] == 'IDENTITY_PROVIDER_MAC' and s == address and p['declaration']['bridge'] == bridge]
        if not identities:
            return ([f'  ether type arp arp saddr ether {mac} arp saddr ip {address} arp operation {{ request, reply }} counter accept']
                    if outgoing else [f'  ether type arp arp daddr ip {address} arp operation {{ request, reply }} counter accept'])
        lines = []
        for s, d, proto, port, p in checked:
            if address not in (s, d): continue
            other = d if s == address else s
            if p['kind'] == 'IDENTITY_PROVIDER_MAC':
                peer_mac = p['declaration']['mac']
                if outgoing:
                    lines += [f'  ether daddr {{ ff:ff:ff:ff:ff:ff, {peer_mac} }} ether type arp arp saddr ether {mac} arp saddr ip {address} arp daddr ip {other} arp operation request counter accept',
                              f'  ether daddr {peer_mac} ether type arp arp saddr ether {mac} arp daddr ether {peer_mac} arp saddr ip {address} arp daddr ip {other} arp operation reply counter accept']
                else:
                    lines += [f'  ether saddr {peer_mac} ether daddr {{ ff:ff:ff:ff:ff:ff, {mac} }} ether type arp arp saddr ether {peer_mac} arp saddr ip {other} arp daddr ip {address} arp operation request counter accept',
                              f'  ether saddr {peer_mac} ether daddr {mac} ether type arp arp saddr ether {peer_mac} arp daddr ether {mac} arp saddr ip {other} arp daddr ip {address} arp operation reply counter accept']
            elif p['kind'] == 'BRIDGE_PORT':
                sender = f'arp saddr ether {mac} ' if outgoing else ''
                lines.append(f'  ether type arp {sender}arp saddr ip {address if outgoing else other} arp daddr ip {other if outgoing else address} arp operation {{ request, reply }} counter accept')
        return lines
    bridge_lines = ['table bridge '+table+' {']""")
    edit(faces, "            f'  ether type arp arp saddr ether {mac} arp saddr ip {address} arp operation {{ request, reply }} counter accept',",
         "            *arp_rules(address, mac, bridge, True),")
    edit(faces, "            f'  ether type arp arp daddr ip {address} arp operation {{ request, reply }} counter accept',",
         "            *arp_rules(address, mac, bridge, False),")

    admission = 'tools/semantic_provider_deployment_admission.py'
    edit(admission, "        if peer['kind'] == 'HOST': continue",
         "        if peer['kind'] in ('HOST', 'IDENTITY_PROVIDER_MAC'): continue")
    edit(admission, "if f['peerIngress']['kind'] != 'HOST'}",
         "if f['peerIngress']['kind'] not in ('HOST', 'IDENTITY_PROVIDER_MAC')}")
    native = 'tools/semantic_provider_preexec_native.py'
    edit(native, "if v['peerIngress']['kind'] != 'HOST')",
         "if v['peerIngress']['kind'] not in ('HOST', 'IDENTITY_PROVIDER_MAC'))")
    edit(native, "            if ingress['kind'] == 'HOST': continue",
         "            if ingress['kind'] in ('HOST', 'IDENTITY_PROVIDER_MAC'): continue")
    preparer = 'tools/semantic_provider_admission_v2/preparer_v2.py'
    edit(preparer, '        resolved = resolve(candidate["transport"], peer_declarations, observations, candidate["containerId"])',
         '        from tools.semantic_provider_peer_bindings import verify_identity_flows\n'
         '        verify_identity_flows(candidate["transport"], NodeObservation({}, self.budget).run)\n'
         '        resolved = resolve(candidate["transport"], peer_declarations, observations, candidate["containerId"])')
    edit(preparer, 'if v["peerIngress"]["kind"] != "HOST")',
         'if v["peerIngress"]["kind"] not in ("HOST", "IDENTITY_PROVIDER_MAC"))')
    driver = 'tools/semantic_provider_admission_v2/driver_v7.py'
    if driver_check:
        edit(driver, '    peers = declarations(policy["transport"], value["profile"]["containerId"])',
             '    from tools.semantic_provider_peer_bindings import verify_identity_flows\n'
             '    verify_identity_flows(policy["transport"], run)\n'
             '    peers = declarations(policy["transport"], value["profile"]["containerId"])')
    # Endpoint MAC observations use the same explicit API as A/A2. Preserve the
    # old observer bytes for v1--v12 and keep its hash/custody/time limits.
    edit('tools/semantic_provider_node_observation.py',
         "env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})",
         "env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_API_VERSION':'1.44'})")
    return out
