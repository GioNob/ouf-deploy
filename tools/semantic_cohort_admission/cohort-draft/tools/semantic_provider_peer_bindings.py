"""Resolve a sealed cohort declaration after kernel links exist, never authorize.

Expected full OCI hashes and all child NIC bindings are inputs to the installer.
No numeric peer index is guessed or read from caller-supplied Docker metadata.
Production integration must use source-bound IO and reobserve before release.
"""
import copy
import hashlib
import ipaddress
import json
import re
import socket
import time

class PeerNotReady(Exception):
    """Read-only creation barrier may wait; this never grants admission."""

def await_peers(expected,probe,budget,pause=time.sleep):
    require(type(expected) is list and 1 <= len(expected) <= 8,'BOUNDED_PEER_COHORT_REQUIRED')
    while True:
        budget.check()
        try:
            observations={peer['containerId']:probe(peer) for peer in expected}
        except PeerNotReady:
            pause(budget.remaining(0.1))
            continue
        budget.check();return observations

def require(ok, code):
    if not ok: raise ValueError(code)

def creation_pending(row, journal, expected, runtime_root):
    """Classify only a source-owned CREATING window; this is never admission.

    runc list can show stopped/pid=0 before create has finished publishing its
    init process. The caller must custody-read the sibling adapter journal.
    Completed, failed or unrelated records cannot relax the stopped-state check.
    Even a stale CREATING record can only consume the existing bounded wait;
    actual created/running state, full OCI and all live NICs remain mandatory.
    """
    fields = {'schema', 'containerId', 'configurationHash', 'state',
              'runtimeRoot', 'bundleHash', 'driverHash'}
    return (type(row) is dict and row.get('id') == expected['containerId']
            and row.get('status') == 'stopped' and type(row.get('pid')) is int and row['pid'] == 0
            and type(journal) is dict and set(journal) == fields
            and journal['schema'] == 'ouf.semantic-docker-runtime-journal.v1'
            and journal['containerId'] == expected['containerId'] and journal['state'] == 'CREATING'
            and type(journal['configurationHash']) is str
            and re.fullmatch('[0-9a-f]{64}', journal['configurationHash']) is not None
            and journal['runtimeRoot'] == runtime_root and journal['bundleHash'] == expected['applicationHash']
            and journal['driverHash'] is None)

def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
def declaration(value):
    require(type(value) is dict and set(value) == {'containerId', 'applicationHash', 'networkBindings'}, 'EXACT_PEER_DECLARATION_REQUIRED')
    require(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}', value[k]) for k in ('containerId', 'applicationHash')), 'EXACT_PEER_IDENTITY_REQUIRED')
    bindings = value['networkBindings']; require(type(bindings) is list and 1 <= len(bindings) <= 8, 'BOUNDED_PEER_NICS_REQUIRED')
    names = set(); refs = set(); ips = set()
    for item in bindings:
        keys = {'interface', 'bridge', 'mac', 'ipv4', 'workloadRef', 'bindingRef'}
        require(type(item) is dict and set(item) in (keys, keys | {'leaseGuard'}), 'EXACT_PEER_NIC_REQUIRED')
        if 'leaseGuard' in item:
            guard = item['leaseGuard']
            require(type(guard) is dict and set(guard)=={'configurationHash','tableName'}
                and type(guard['configurationHash']) is str and re.fullmatch('[0-9a-f]{64}',guard['configurationHash'])
                and type(guard['tableName']) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}',guard['tableName']),
                'EXACT_PEER_LEASE_GUARD_BINDING_REQUIRED')

        require(all(type(item[k]) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', item[k]) for k in ('interface', 'bridge')), 'PEER_LINK_NAME_INVALID')
        require(all(type(item[k]) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,127}', item[k]) for k in ('workloadRef', 'bindingRef')), 'PEER_REFERENCE_INVALID')
        require(type(item['mac']) is str and re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}', item['mac']) and not int(item['mac'][:2], 16) & 1 and item['mac'] != '00:00:00:00:00:00', 'PEER_MAC_INVALID')
        ip = ipaddress.ip_address(item['ipv4']); require(ip.version == 4 and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved), 'PEER_IP_INVALID')
        require(item['interface'] not in names and item['bindingRef'] not in refs and item['ipv4'] not in ips, 'PEER_NIC_DUPLICATE')
        names.add(item['interface']); refs.add(item['bindingRef']); ips.add(item['ipv4'])
    return copy.deepcopy(value)
def collect(expected, runtime_root, runtime_binding, commands, run, read_bundle, generation, budget):
    """Callbacks must be independently source/custody-bound by the caller.

    No application environment, argv or mount content is returned. All NICs,
    full OCI and reciprocal host/child links are checked twice for stability.
    """
    expected = declaration(expected); cid = expected['containerId']
    require(type(runtime_root) is str and runtime_root.startswith('/') and '..' not in runtime_root.split('/'), 'PEER_RUNTIME_ROOT_INVALID')
    def state():
        budget.check(); row = json.loads(run(runtime_binding, ['--root', runtime_root, 'state', cid], 16384))
        require(row.get('id') == cid and row.get('status') in ('created', 'running') and type(row.get('pid')) is int and row['pid'] > 1, 'LIVE_PEER_STATE_REQUIRED')
        require(type(row.get('bundle')) is str and row['bundle'].startswith('/') and '..' not in row['bundle'].split('/'), 'PEER_BUNDLE_INVALID')
        return row
    before = state(); gen = generation(before['pid']); raw = read_bundle(before['bundle'] + '/config.json')
    oci = json.loads(raw); require(digest(oci) == expected['applicationHash'], 'PEER_COMPLETE_OCI_DRIFT')
    namespace = '/proc/' + str(before['pid']) + '/ns/net'
    def observe_links():
        budget.check()
        children = json.loads(run(commands['nsenter'], ['--net=' + namespace, commands['ip']['path'], '-j', 'addr', 'show'], 131072))
        require(type(children) is list, 'PEER_LINK_RECORD_INVALID'); children = [x for x in children if x.get('ifname') != 'lo']
        require(len(children) <= len(expected['networkBindings']), 'UNAPPROVED_PEER_INTERFACE')
        require(len(children) == len(expected['networkBindings']), 'PEER_INTERFACES_NOT_READY')
        result = []
        for approved in expected['networkBindings']:
            matches = [x for x in children if x.get('ifname') == approved['interface']]
            require(len(matches) == 1, 'PEER_INTERFACE_MISSING'); child = matches[0]
            addresses=[a['local'] for a in child.get('addr_info', []) if a['family'] == 'inet']
            require(child.get('address') == approved['mac'],'PEER_MAC_IP_DRIFT')
            require(bool(addresses),'PEER_ADDRESSES_NOT_READY')
            require(addresses == [approved['ipv4']], 'PEER_MAC_IP_DRIFT')
            require(not any(a['family'] == 'inet6' for a in child.get('addr_info', [])), 'PEER_IPV6_UNAPPROVED')
            index = child.get('link_index'); require(type(index) is int and index > 1 and type(child.get('ifindex')) is int, 'PEER_HOST_INDEX_INVALID')
            name = socket.if_indextoname(index)
            hosts = json.loads(run(commands['ip'], ['-j', 'link', 'show', 'dev', name], 131072))
            require(type(hosts) is list and len(hosts) == 1, 'PEER_HOST_LINK_UNPROVEN'); host = hosts[0]
            require(host.get('ifindex') == index and host.get('ifname') == name and host.get('link_index') == child['ifindex'] and host.get('master') == approved['bridge'], 'PEER_RECIPROCAL_BRIDGE_DRIFT')
            result.append({**approved, 'childIfindex': child['ifindex'], 'hostIfindex': index, 'hostInterface': name})
        return result
    first = observe_links(); second = observe_links()
    require(first == second and state() == before and generation(before['pid']) == gen and read_bundle(before['bundle'] + '/config.json') == raw, 'PEER_OBSERVATION_CHANGED')
    budget.check()
    return {'containerId': cid, 'applicationHash': expected['applicationHash'], 'generation': gen, 'bindings': first}
def declarations(flows, current_cid):
    """Full peer expectations are inside the transport signed by the issuer."""
    require(type(flows) is list and 1 <= len(flows) <= 128, 'BOUNDED_TRANSPORT_REQUIRED')
    found = {}
    for flow in flows:
        peer = flow.get('peerIngress') if type(flow) is dict else None
        require(type(peer) is dict, 'PEER_INGRESS_INVALID')
        if peer.get('kind') != 'CREATED_CANDIDATE': continue
        require(set(peer) == {'kind', 'declaration', 'bindingRef'}, 'EXACT_SYMBOLIC_PEER_REQUIRED')
        expected = declaration(peer['declaration']); cid = expected['containerId']
        require(cid != current_cid, 'PEER_COHORT_INVALID')
        require(cid not in found or found[cid] == expected, 'INCONSISTENT_PEER_DECLARATION')
        found[cid] = expected
    return [found[cid] for cid in sorted(found)]
def resolve(flows, declarations, snapshots, current_cid):
    """Keep declaration hashes separate from materialized kernel indices.

    Existing HOST/ROUTED/BRIDGE_PORT records stay unchanged. Every symbolic
    peer must match an independently collected exact full OCI and NIC binding.
    """
    require(type(flows) is list and 1 <= len(flows) <= 128, 'BOUNDED_TRANSPORT_REQUIRED')
    expected = {row['containerId']: declaration(row) for row in declarations}
    require(len(expected) == len(declarations) and current_cid not in expected, 'PEER_COHORT_INVALID')
    result = []
    for flow in flows:
        require(type(flow) is dict and set(flow) == {'purpose', 'authorityRef', 'source', 'destination', 'protocol', 'port', 'peerIngress'}, 'EXACT_TRANSPORT_REQUIRED')
        peer = flow['peerIngress']; require(type(peer) is dict, 'PEER_INGRESS_INVALID')
        value = copy.deepcopy(flow)
        if peer.get('kind') == 'CREATED_CANDIDATE':
            require(set(peer) == {'kind', 'declaration', 'bindingRef'}, 'EXACT_SYMBOLIC_PEER_REQUIRED')
            embedded = declaration(peer['declaration']); cid = embedded['containerId']; require(cid in expected and cid in snapshots and cid != current_cid, 'PEER_COHORT_MISSING')
            require(expected[cid] == embedded, 'PEER_DECLARATION_SCOPE_DRIFT')
            snap = snapshots[cid]; require(set(snap) == {'containerId', 'applicationHash', 'generation', 'bindings'} and snap['containerId'] == cid and snap['applicationHash'] == expected[cid]['applicationHash'], 'PEER_SNAPSHOT_SCOPE_DRIFT')
            approved = [b for b in expected[cid]['networkBindings'] if b['bindingRef'] == peer['bindingRef']]
            actual = [b for b in snap['bindings'] if b['bindingRef'] == peer['bindingRef']]
            require(len(approved) == len(actual) == 1, 'PEER_BINDING_MISSING')
            require(all(actual[0].get(k) == v for k, v in approved[0].items()) and type(actual[0].get('hostIfindex')) is int and actual[0]['hostIfindex'] > 1, 'PEER_BINDING_DRIFT')
            require(approved[0]['ipv4'] in (flow['source'], flow['destination']), 'PEER_TRANSPORT_ADDRESS_DRIFT')
            value['peerIngress'] = {'kind': 'BRIDGE_PORT', 'ifindex': actual[0]['hostIfindex']}
        else:
            require(set(peer) == {'kind', 'ifindex'} and peer['kind'] in ('HOST', 'ROUTED', 'BRIDGE_PORT') and type(peer['ifindex']) is int and (peer['ifindex'] == 0 if peer['kind'] == 'HOST' else peer['ifindex'] > 1), 'EXACT_LEGACY_PEER_REQUIRED')
        result.append(value)
    return result
