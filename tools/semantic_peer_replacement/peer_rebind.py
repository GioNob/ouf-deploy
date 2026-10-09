"""Compile a single Semantic ingress replacement; never execute or authorize it.

The caller must authenticate both peer observations and the replacement's full
OCI declaration, and supply the installed profile/journal hashes. A plan cannot
update a consumed signed transport, driver, journal or restart authority.
"""
import copy
import hashlib
import json
import re


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def structure(value):
    if isinstance(value, list):
        return [structure(v) for v in value]
    if isinstance(value, dict):
        if isinstance(value.get('set'), dict) and 'name' in value['set']:
            return {'set': structure({k: v for k, v in value['set'].items() if k != 'elem'})}
        return {k: structure(v) for k, v in value.items() if k not in ('packets', 'bytes', 'expires')}
    return value


def footprint(value):
    if isinstance(value, list):
        return [footprint(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
    if isinstance(value, dict):
        return {k: footprint(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes')}
    return value


def peer(value):
    require(type(value) is dict and set(value) == {'containerId', 'applicationHash', 'generation', 'bindings'},
            'EXACT_COLLECTED_PEER_REQUIRED')
    require(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}', value[k])
                for k in ('containerId', 'applicationHash')), 'FULL_PEER_IDENTITY_REQUIRED')
    generation = value['generation']
    require(type(generation) is dict and set(generation) == {'pid', 'startTicks', 'namespaceInode'}
            and all(type(v) is int and v > 1 for v in generation.values()), 'LIVE_PEER_GENERATION_REQUIRED')
    require(type(value['bindings']) is list and len(value['bindings']) == 1, 'ONE_SEMANTIC_BACKEND_NIC_REQUIRED')
    nic = value['bindings'][0]
    keys = {'interface', 'bridge', 'mac', 'ipv4', 'workloadRef', 'bindingRef',
            'childIfindex', 'hostIfindex', 'hostInterface'}
    require(type(nic) is dict and set(nic) == keys, 'EXACT_COLLECTED_NIC_REQUIRED')
    require(nic['ipv4'] == '172.18.0.6' and nic['mac'] == 'b2:96:a1:e2:c1:8d'
            and nic['bridge'] == 'br-113b5f0a3c53', 'SEMANTIC_ADDRESS_MAC_BRIDGE_DRIFT')
    for key in ('interface', 'hostInterface'):
        require(type(nic[key]) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', nic[key]), 'PEER_LINK_NAME_INVALID')
    for key in ('workloadRef', 'bindingRef'):
        require(type(nic[key]) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,127}', nic[key]), 'PEER_REFERENCE_INVALID')
    require(all(type(nic[k]) is int and 1 < nic[k] < 2147483647
                for k in ('childIfindex', 'hostIfindex')), 'PEER_INDEX_INVALID')
    return nic


def compile_replacement(policy, tables, expected_structure, expected_footprint, old_peer, new_peer, materialize):
    """Only the single bridge iif predicate changes; every other byte/object stays.

    materialize must be the source-bound installed shared-face compiler. Tables
    come from two bounded native reads under the existing common lock. No lease
    set/table is accepted here. Independent before/after observations and signed
    authority remain responsibilities of a future installer, never booleans.
    """
    before, after = peer(old_peer), peer(new_peer)
    require(old_peer['containerId'] != new_peer['containerId']
            and old_peer['applicationHash'] != new_peer['applicationHash']
            and old_peer['generation'] != new_peer['generation'], 'DISTINCT_REPLACEMENT_GENERATION_REQUIRED')
    require(all(before[k] == after[k] for k in ('interface', 'bridge', 'mac', 'ipv4', 'workloadRef', 'bindingRef')),
            'PEER_DECLARATION_SCOPE_CHANGED')
    require(before['hostIfindex'] != after['hostIfindex'], 'NEW_PORT_GENERATION_REQUIRED')
    require(type(tables) is dict and set(tables) == {'inet', 'bridge'}, 'EXACT_OWNED_TABLE_PAIR_REQUIRED')
    require(digest(structure(tables)) == expected_structure and digest(footprint(tables)) == expected_footprint,
            'INSTALLED_NATIVE_STRUCTURE_OR_PROFILE_DRIFT')
    table = policy['tableName']
    require(type(table) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', table)
            and table != 'ouf_sem_provider', 'DISTINCT_SAFE_SHARED_TABLE_REQUIRED')
    materialize(policy)
    require(not any(a['ifindex'] == after['hostIfindex'] for a in policy['attachments']), 'REPLACEMENT_IS_PROTECTED_ATTACHMENT')
    candidates = [i for i, f in enumerate(policy['flows']) if f['peerIngress'] ==
                  {'kind': 'BRIDGE_PORT', 'ifindex': before['hostIfindex']}]
    require(len(candidates) == 1, 'ONE_GOVERNED_SEMANTIC_INGRESS_REQUIRED')
    index = candidates[0]
    flow = policy['flows'][index]
    require(flow['purpose'] == 'WORKLOAD_GATEWAY' and flow['source'] == '172.18.0.6'
            and flow['destination'] == '172.18.0.14' and flow['protocol'] == 'tcp' and flow['port'] == 10443,
            'EXACT_SEMANTIC_SOUTHBOUND_FLOW_REQUIRED')
    selected = [i for i, a in enumerate(policy['attachments']) if a['ipv4'] == flow['destination']]
    require(len(selected) == 1 and policy['attachments'][selected[0]]['bridge'] == before['bridge'],
            'SOUTHBOUND_BACKEND_ATTACHMENT_REQUIRED')
    chain = 'to_' + str(selected[0])
    following = copy.deepcopy(policy)
    following['flows'][index]['peerIngress']['ifindex'] = after['hostIfindex']
    old_lines = materialize(policy)['nftRules'].splitlines()
    new_lines = materialize(following)['nftRules'].splitlines()
    require(len(old_lines) == len(new_lines), 'COMPILER_RULE_COUNT_CHANGED')
    differences = [(a, b) for a, b in zip(old_lines, new_lines) if a != b]
    require(len(differences) == 1, 'ONLY_ONE_INGRESS_RULE_DELTA_ALLOWED')
    old_line, new_line = differences[0]
    require(new_line == old_line.replace('meta iif ' + str(before['hostIfindex']) + ' ',
                                         'meta iif ' + str(after['hostIfindex']) + ' ', 1), 'COMPILER_WIDENED_FLOW')
    actual = copy.deepcopy(tables)
    selector = {'match': {'op': '==', 'left': {'meta': {'key': 'iif'}}, 'right': before['hostIfindex']}}
    changed = []
    for family, pair in actual.items():
        require(type(pair) is dict and set(pair) == {'nftables'} and type(pair['nftables']) is list,
                'BOUNDED_NATIVE_TABLE_SHAPE_REQUIRED')
        require(len(pair['nftables']) <= 2048, 'NATIVE_TABLE_UNBOUNDED')
        for entry in pair['nftables']:
            for kind in ('table', 'chain', 'rule', 'set'):
                if kind in entry:
                    obj = entry[kind]
                    require(obj['family'] == family and (obj['name'] if kind == 'table' else obj['table']) == table,
                            'FOREIGN_NATIVE_OBJECT_DENIED')
            rule = entry.get('rule')
            if rule is not None and selector in rule['expr']:
                require(family == 'bridge' and rule['chain'] == chain and type(rule['handle']) is int
                        and rule['handle'] > 0 and rule['expr'].count(selector) == 1, 'PEER_RULE_SCOPE_DRIFT')
                rule['expr'][rule['expr'].index(selector)]['match']['right'] = after['hostIfindex']
                changed.append(rule)
    require(len(changed) == 1, 'EXACT_NATIVE_PEER_RULE_REQUIRED')
    rule = changed[0]
    transaction = f'replace rule bridge {table} {chain} handle {rule["handle"]} {new_line.strip()}\n'
    reverse = f'replace rule bridge {table} {chain} handle {rule["handle"]} {old_line.strip()}\n'
    return {'schema': 'ouf.semantic-peer-replacement-plan.v1', 'status': 'PLAN_ONLY',
            'previousPolicyHash': digest(policy), 'followingPolicyHash': digest(following),
            'previousStructureHash': expected_structure, 'followingFootprintHash': digest(footprint(actual)),
            'followingPolicy': following, 'nativeTransaction': transaction, 'recoveryTransaction': reverse,
            'changedRuleCount': 1, 'sharedTableName': table, 'changedFamily': 'bridge', 'changedChain': chain,
            'oldPeer': copy.deepcopy(old_peer), 'newPeer': copy.deepcopy(new_peer),
            'leaseTableTouched': False, 'installed': False, 'startAuthorized': False,
            'authorityProven': False, 'releaseAcceptance': False,
            'requirements': ['AUTHENTICATED_REPLACEMENT_FULL_OCI_AND_LIVE_RECIPROCAL_LINKS',
                             'NEW_SEPARATE_HUMAN_TRANSITION_AUTHORITY',
                             'NEW_DRIVER_TRANSPORT_CONSUMPTION_BINDINGS_WITHOUT_R8_REPLAY',
                             'LOCKED_NATIVE_COMPARE_APPLY_READBACK_AND_CONDITIONAL_RECOVERY']}
