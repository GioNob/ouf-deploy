"""Compile a Linux bridge-port backend for governed workload attachments.

No installation, discovery, implicit authority or entire shared-bridge guard.
Other deployment backends must enforce the same identity/flow invariants.
This initial backend is static IPv4 only: IPv6/VLAN/other data frames are denied
on selected ports, rather than being silently treated as governed traffic.
"""
import re
import hashlib
import json

from tools.materialize_southbound_kernel import fields, ip, name, port


def materialize(policy):
    composed = policy.get('schema') == 'ouf.semantic-shared-faces.v2'
    fields(policy, ('schema', 'tableName', 'attachments', 'flows', 'globalLeaseGuard') if composed
           else ('schema', 'tableName', 'attachments', 'flows'))
    if policy['schema'] not in ('ouf.semantic-shared-faces.v1', 'ouf.semantic-shared-faces.v2'):
        raise ValueError('explicit shared face schema required')
    table = name(policy['tableName'], 32)
    attachments, flows = policy['attachments'], policy['flows']
    if not isinstance(attachments, list) or not 1 <= len(attachments) <= 32 \
            or not isinstance(flows, list) or not (0 if composed else 1) <= len(flows) <= 128:
        raise ValueError('bounded attachments and approved flows required')
    interfaces, indexes, bindings = set(), set(), set()
    normalized = []
    for attachment in attachments:
        fields(attachment, ('workloadRef', 'interface', 'ifindex', 'bridge', 'mac', 'ipv4', 'bindingRef'))
        for key in ('workloadRef', 'bindingRef'): name(attachment[key], 128)
        interface, bridge = name(attachment['interface'], 15), name(attachment['bridge'], 15)
        address = ip(attachment['ipv4'])
        mac = attachment['mac']
        if address.version != 4 or not isinstance(mac, str) \
                or not re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}', mac) \
                or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00' \
                or type(attachment['ifindex']) is not int or not 1 <= attachment['ifindex'] <= 2147483647 \
                or attachment['ifindex'] in indexes or interface == bridge or interface in interfaces \
                or (bridge, str(address)) in bindings:
            raise ValueError('unique explicit unicast IPv4 port binding required')
        interfaces.add(interface); indexes.add(attachment['ifindex']); bindings.add((bridge, str(address)))
        normalized.append((attachment['ifindex'], bridge, str(address), mac))
    delegated = set()
    if composed:
        guard = policy['globalLeaseGuard']
        fields(guard, ('configurationHash', 'tableName', 'bridges'))
        name(guard['tableName'], 32)
        if guard['tableName'] == table or not isinstance(guard['configurationHash'], str) \
                or not re.fullmatch('[0-9a-f]{64}', guard['configurationHash']) \
                or not isinstance(guard['bridges'], list) or not guard['bridges'] \
                or guard['bridges'] != sorted(set(guard['bridges'])):
            raise ValueError('exact distinct global lease guard required')
        for bridge in guard['bridges']: name(bridge, 15)
        delegated = set(guard['bridges'])
        if not delegated.issubset({v[1] for v in normalized}):
            raise ValueError('delegated bridge has no approved attachment')
    protected = {v[2] for v in normalized}
    checked = []
    seen = set()
    for flow in flows:
        fields(flow, ('purpose', 'authorityRef', 'source', 'destination', 'protocol', 'port', 'peerIngress'))
        name(flow['authorityRef'], 128)
        if flow['purpose'] not in ('WORKLOAD_GATEWAY', 'GATEWAY_ADAPTER', 'IDENTITY', 'DNS', 'TELEMETRY'):
            raise ValueError('explicit infrastructure purpose required')
        source, destination = ip(flow['source']), ip(flow['destination'])
        p = port(flow['port']); proto = flow['protocol']
        if source.version != 4 or destination.version != 4 or source == destination \
                or proto not in ('tcp', 'udp') or (proto == 'udp' and flow['purpose'] != 'DNS') \
                or (flow['purpose'] == 'DNS' and p != 53) \
                or len({str(source), str(destination)} & protected) != 1:
            raise ValueError('exact governed IPv4 transport pair required')
        peer = flow['peerIngress']
        fields(peer, ('kind', 'ifindex'))
        if peer['kind'] not in ('BRIDGE_PORT', 'ROUTED', 'HOST') \
                or type(peer['ifindex']) is not int \
                or (peer['kind'] == 'HOST' and peer['ifindex'] != 0) \
                or (peer['kind'] != 'HOST' and not 1 <= peer['ifindex'] <= 2147483647) \
                or peer['ifindex'] in indexes:
            raise ValueError('explicit peer ingress binding required')
        key = (str(source), str(destination), proto, p)
        if key in seen: raise ValueError('duplicate transport binding')
        seen.add(key); checked.append((*key, peer))
    def transport(address, outgoing, bridge, layer):
        lines = ['  ct state invalid counter drop']
        if bridge in delegated:
            # This layer authenticates the port/MAC/IP and denies non-IPv4.
            # The independently custody-verified global base chains veto all
            # traffic outside their exact static flows and expiring DNS sets.
            # nft accept here does not bypass a later base-chain drop.
            field = 'saddr' if outgoing else 'daddr'
            return [*lines, f'  ip {field} {address} counter accept']

        for source, destination, proto, p, peer in checked:
            incoming = ''
            if not outgoing:
                if layer == 'bridge':
                    incoming = 'meta iif '+str(peer['ifindex'] if peer['kind'] == 'BRIDGE_PORT' else 0)+' '
                else:
                    incoming = ('iifname "'+bridge+'" ' if peer['kind'] == 'BRIDGE_PORT'
                                else 'meta iif '+str(peer['ifindex'])+' ')
            if (outgoing and source == address) or (not outgoing and destination == address):
                lines.append(f'  {incoming}ip saddr {source} ip daddr {destination} {proto} dport {p} ct state {{ new, established }} counter accept')
            if (outgoing and destination == address) or (not outgoing and source == address):
                lines.append(f'  {incoming}ip saddr {destination} ip daddr {source} {proto} sport {p} ct state established counter accept')
        return lines
    bridge_lines = ['table bridge '+table+' {']
    for i, (interface, bridge, address, mac) in enumerate(normalized):
        bridge_lines += [f' chain from_{i} {{',
            f'  meta ibrname != "{bridge}" counter drop',
            f'  ether saddr != {mac} counter drop',
            f'  ether type arp arp saddr ether {mac} arp saddr ip {address} arp operation {{ request, reply }} counter accept',
            *transport(address, True, bridge, 'bridge'), '  counter drop', ' }', f' chain to_{i} {{',
            f'  meta obrname != "{bridge}" counter drop',
            f'  ether type arp arp daddr ip {address} arp operation {{ request, reply }} counter accept',
            *transport(address, False, bridge, 'bridge'), '  counter drop', ' }']
    for hook in ('prerouting', 'input', 'forward', 'output'):
        bridge_lines += [' chain guard_'+hook+' {', f'  type filter hook {hook} priority -150; policy accept;']
        for i, (interface, bridge, _, _) in enumerate(normalized):
            if hook in ('prerouting', 'input', 'forward'):
                bridge_lines.append(f'  meta iif {interface} jump from_{i}')
            if hook in ('forward', 'output'):
                bridge_lines.append(f'  meta oif {interface} jump to_{i}')
        bridge_lines.append(' }')
    bridge_lines.append('}')
    # Routed/host-local L3 traffic is also constrained; port ingress above
    # prevents a selected workload from escaping by spoofing another source IP.
    inet_lines = ['table inet '+table+' {']
    for i, (_, bridge, address, _) in enumerate(normalized):
        inet_lines += [f' chain from_{i} {{', *transport(address, True, bridge, 'inet'), '  counter drop', ' }',
                       f' chain to_{i} {{', *transport(address, False, bridge, 'inet'), '  counter drop', ' }']
    for hook in ('input', 'output', 'forward'):
        inet_lines += [' chain guard_'+hook+' {', f'  type filter hook {hook} priority -150; policy accept;']
        for i, (_, bridge, address, _) in enumerate(normalized):
            if hook != 'output': inet_lines.append(f'  iifname "{bridge}" ip saddr {address} jump from_{i}')
            if hook != 'input': inet_lines.append(f'  oifname "{bridge}" ip daddr {address} jump to_{i}')
        inet_lines.append(' }')
    inet_lines.append('}')
    return {'schema': 'ouf.semantic-shared-faces-plan.v1', 'backend': 'LINUX_BRIDGE_PORT_IPV4',
        'nftRules': '\n'.join(inet_lines+bridge_lines)+'\n', 'tableName': table,
        'tableFamilies': ['inet', 'bridge'], 'installed': False, 'startAuthorized': False,
        'authorityProven': False, 'liveBindingProven': False, 'notReleaseAcceptance': True,
        'attachmentCount': len(normalized), 'flowCount': len(checked), **({'delegatedBridgeCount':len(delegated)} if composed else {}),
        'requirements': ['SEALED_AUTHORITY_REFS', 'LIVE_PORT_IFINDEX_MAC_IP_BINDING',
            'PORT_RECREATION_FAIL_CLOSED_LIFECYCLE', 'SHARED_PEER_AND_ROUTED_PACKET_NEGATIVES',
            'IPV6_DENIAL_PROOF', 'OTHER_TOPOLOGY_BACKEND_ACCEPTANCE']}


def validate_global_guard(policy, kernel):
    """Mandatory under source-bound Coordinator custody, never infer authority."""
    if policy.get('schema') == 'ouf.semantic-shared-faces.v1': return
    materialize(policy)
    guard = policy['globalLeaseGuard']
    expected = hashlib.sha256(json.dumps(kernel,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if guard['configurationHash'] != expected or guard['tableName'] != kernel['tableName'] \
            or not set(guard['bridges']).issubset(set(kernel['guardedInterfaces'])) \
            or set(guard['bridges']) & set(kernel['existingInterfaces']):
        raise ValueError('GLOBAL_LEASE_GUARD_SCOPE_DRIFT')
    governed = {f['source'] for f in kernel['providerFlows']}
    governed.update(f[k] for f in kernel['staticFlows'] for k in ('source','destination'))
    if any(a['bridge'] in guard['bridges'] and a['ipv4'] not in governed for a in policy['attachments']):
        raise ValueError('GLOBAL_LEASE_GUARD_SOURCE_UNBOUND')
