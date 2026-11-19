"""D-051 public identity input and read-only, source-bound Docker observations.

This module is embedded in the sealed peer library for v13 only. No discovery,
DNS request, secret expansion, lifecycle operation or numeric peer index.
"""
import ipaddress
import json
import re
from urllib.parse import urlsplit

IDENTITY_KIND = 'IDENTITY_PROVIDER_MAC'
INSPECT_FORMAT = ('{"Id":{{json .Id}},"Name":{{json .Name}},'
                  '"Running":{{json .State.Running}},'
                  '"Networks":{{json .NetworkSettings.Networks}}}')
NETWORK_FORMAT = ('{"Id":{{json .Id}},"Name":{{json .Name}},'
                  '"Driver":{{json .Driver}},"Options":{{json .Options}}}')
PEER_FIELDS = {'containerId', 'containerName', 'network', 'networkId', 'bridge',
               'ipv4', 'mac', 'alias', 'aliases', 'port', 'dockerBinding', 'dockerSocket'}


class Denied(ValueError):
    """Public bounded denial, recognized by the existing R3 report boundary."""


def identity_require(ok, code='R3_IDENTITY_PROVIDER_INPUT_INVALID'):
    if not ok:
        raise Denied(code)


def identity_json(raw):
    def pairs(rows):
        result = dict(rows)
        identity_require(len(result) == len(rows), 'R3_IDENTITY_PROVIDER_DUPLICATE_FIELD')
        return result
    identity_require(type(raw) is bytes and 0 < len(raw) <= 131072)
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: identity_require(False))


def identity_peer(peer):
    identity_require(type(peer) is dict and set(peer) == PEER_FIELDS)
    for k in ('containerId', 'networkId'):
        identity_require(type(peer[k]) is str and re.fullmatch('[0-9a-f]{64}', peer[k]))
    for k in ('containerName', 'network'):
        identity_require(type(peer[k]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', peer[k]))
    identity_require(type(peer['bridge']) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', peer['bridge']))
    address = ipaddress.ip_address(peer['ipv4'])
    identity_require(address.version == 4 and str(address) == peer['ipv4']
                     and not (address.is_unspecified or address.is_multicast or address.is_loopback))
    mac = peer['mac']
    identity_require(type(mac) is str and re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}', mac)
                     and not int(mac[:2], 16) & 1 and mac != '00:00:00:00:00:00')
    identity_require(type(peer['port']) is int and 1 <= peer['port'] <= 65535)
    alias = peer['alias']
    identity_require(type(alias) is str and len(alias) <= 253
                     and re.fullmatch('[a-z0-9]+(?:[.-][a-z0-9]+)*', alias))
    aliases = peer['aliases']
    identity_require(type(aliases) is list and 1 <= len(aliases) <= 64
                     and all(type(a) is str and 0 < len(a) <= 253 for a in aliases)
                     and aliases == sorted(set(aliases)) and alias in aliases)
    binding = peer['dockerBinding']
    identity_require(type(binding) is dict and set(binding) == {'path', 'sha256'}
                     and type(binding['sha256']) is str and re.fullmatch('[0-9a-f]{64}', binding['sha256']))
    for p in (binding['path'], peer['dockerSocket']):
        identity_require(type(p) is str and re.fullmatch('/[A-Za-z0-9_./-]+', p)
                         and '..' not in p.split('/'))
    return peer


def issuer_endpoint(kernel, candidate):
    """OIDC endpoint from the already bound P-derived coordinator kernel.

    build_target_network_policy.assemble associates the OIDC issuer with the
    southbound source; the provider endpoint belongs to the sibling adapter.
    Select by the signed source NICs, never by the proposed alias or a constant.
    """
    sources = {n['ipv4'] for n in candidate['networkBindings']}
    flows = [f for f in kernel['providerFlows'] if f['source'] in sources]
    identity_require(len(flows) == 1, 'R3_OIDC_ISSUER_AMBIGUOUS')
    try:
        u = urlsplit(flows[0]['endpoint'])
        port = u.port if u.port is not None else 443
        identity_require(u.scheme == 'https' and u.hostname and u.username is None
                         and u.password is None and not u.query and not u.fragment
                         and 1 <= port <= 65535, 'R3_OIDC_ISSUER_REQUIRED')
    except (ValueError, TypeError):
        raise Denied('R3_OIDC_ISSUER_REQUIRED') from None
    return u.hostname, port


def identity_flow(value, candidate, kernel):
    identity_require(type(value) is dict and set(value) ==
                     {'schema', 'peer', 'southbound', 'observationHashes'})
    identity_require(value['schema'] == 'ouf.semantic-identity-provider-peer.v1')
    peer = identity_peer(value['peer'])
    alias, port = issuer_endpoint(kernel, candidate)
    identity_require((peer['alias'], peer['port']) == (alias, port), 'R3_IDENTITY_PROVIDER_ISSUER_DRIFT')
    own = value['southbound']
    identity_require(type(own) is dict and set(own) == {'containerId', 'ipv4', 'network', 'networkId', 'bridge'}
                     and own['containerId'] == candidate['containerId']
                     and own['containerId'] != peer['containerId'], 'R3_IDENTITY_PROVIDER_SOUTHBOUND_DRIFT')
    identity_require(all(own[k] == peer[k] for k in ('network', 'networkId', 'bridge')),
                     'R3_IDENTITY_PROVIDER_NETWORK_NOT_SHARED')
    nics = [n for n in candidate['networkBindings'] if n['bridge'] == peer['bridge']
            and n['ipv4'] == own['ipv4'] and 'leaseGuard' not in n]
    identity_require(len(nics) == 1 and own['ipv4'] != peer['ipv4'], 'R3_IDENTITY_PROVIDER_NETWORK_NOT_SHARED')
    hashes = value['observationHashes']
    identity_require(type(hashes) is dict and set(hashes) == {'identityProvider', 'southbound', 'network'}
                     and all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h) for h in hashes.values()))
    return {'purpose': 'IDENTITY', 'authorityRef': 'oidc-issuer', 'source': own['ipv4'],
            'destination': peer['ipv4'], 'protocol': 'tcp', 'port': port,
            'peerIngress': {'kind': IDENTITY_KIND, 'declaration': peer}}


def identity_projection(row, peer):
    identity_peer(peer)
    code = 'R3_IDENTITY_PROVIDER_LIVE_DRIFT'
    identity_require(row.get('Id') == peer['containerId'] and row.get('Name') == '/' + peer['containerName']
                     and row.get('Running') is True, code)
    networks = row.get('Networks')
    identity_require(type(networks) is dict and peer['network'] in networks, code)
    n = networks[peer['network']]
    identity_require(n.get('NetworkID') == peer['networkId'] and n.get('IPAddress') == peer['ipv4']
                     and n.get('MacAddress') == peer['mac']
                     and type(n.get('Aliases')) is list and sorted(n['Aliases']) == peer['aliases'], code)
    return {k: row[k] for k in ('Id', 'Name', 'Running')} | {'endpoint': n}


def identity_network(row, peer):
    options = row.get('Options') or {}
    identity_require(row.get('Id') == peer['networkId'] and row.get('Name') == peer['network']
                     and row.get('Driver') == 'bridge'
                     and options.get('com.docker.network.bridge.name', 'br-' + peer['networkId'][:12]) == peer['bridge'],
                     'R3_IDENTITY_PROVIDER_LIVE_DRIFT')


def identity_observe(peer, run):
    """run authenticates the executable hash before/after every bounded read."""
    identity_peer(peer)
    base = ['--host', 'unix://' + peer['dockerSocket']]
    def read():
        raw = run(peer['dockerBinding'], base + ['inspect', '--format', INSPECT_FORMAT, peer['containerId']], 131072)
        row = identity_json(raw)
        identity_projection(row, peer)
        network_raw = run(peer['dockerBinding'], base + ['network', 'inspect', '--format', NETWORK_FORMAT,
                                                        peer['networkId']], 131072)
        network = identity_json(network_raw)
        identity_network(network, peer)
        return raw, network_raw
    first, second = read(), read()
    identity_require(first == second, 'R3_IDENTITY_PROVIDER_LIVE_DRIFT')
    return first


def verify_identity_flows(flows, run):
    for flow in flows:
        ingress = flow['peerIngress']
        if ingress.get('kind') == IDENTITY_KIND:
            peer = identity_peer(ingress['declaration'])
            identity_require(set(ingress) == {'kind', 'declaration'} and flow['purpose'] == 'IDENTITY'
                             and flow['destination'] == peer['ipv4'] and flow['protocol'] == 'tcp'
                             and flow['port'] == peer['port'], 'R3_IDENTITY_PROVIDER_FLOW_DRIFT')
            identity_observe(peer, run)
