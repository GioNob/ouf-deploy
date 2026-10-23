"""Bind the verified snake-case response and preserve the consumed reads."""
from pathlib import Path
from .core import require, digest, hashed
from . import frozen_response


def validate(case):
    value = case['frozenWireRecovery']
    require(type(value) is dict and set(value) == {'resolverSourceClosureHash', 'response', 'observerScriptSha256'}
            and hashed(value['resolverSourceClosureHash']) and hashed(value['observerScriptSha256']),
            'EXACT_FROZEN_WIRE_RECOVERY_BINDING_REQUIRED')
    ref = value['response']
    require(type(ref) is dict and set(ref) == {'path', 'sha256'} and hashed(ref['sha256'])
            and type(ref['path']) is str and ref['path'].startswith(case['privateParent'] + '/')
            and '..' not in Path(ref['path']).parts and str(Path(ref['path'])) == ref['path']
            and Path(ref['path']).name == 'response.json', 'EXACT_PRIVATE_FROZEN_RESPONSE_REQUIRED')


def reconcile(case, files, boot):
    from . import postboot_prepare as p
    validate(case); wire = case['frozenWireRecovery']
    original = {k: v for k, v in case.items() if k != 'frozenWireRecovery'}
    prior = p.reconcile_prior_preparation(original, files, boot)
    require(prior['priorAttemptCounts'] == {'engineGets': 22, 'adminGets': 3, 'frozenConfigurationGets': 0,
        'resolverCalls': 3, 'tlsAttemptMarkers': 3}, 'ALL_RESOLVER_RECOVERY_PREDECESSORS_REQUIRED')
    root = p.prepared_root(original, {}, boot)
    expected = {'schema': p.SCHEMA, 'caseHash': digest(original), 'sourceClosureHash': wire['resolverSourceClosureHash'],
        'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'maximumTlsHandshakes': 1,
        'maximumMetadataReads': 192}
    claim, claim_profile = files.json(str(root / 'claim.json'))
    require(claim == expected, 'EXACT_CONSUMED_RESOLVER_PREPARATION_REQUIRED')
    for n in range(1, 7):
        row, _ = files.json(str(root / ('engine-get-' + str(n) + '.json')))
        require(set(row) == {'requestPathHash', 'attempt'} and row['attempt'] == n and hashed(row['requestPathHash']),
                'EXACT_PRIOR_RESOLVER_PREPARATION_ENGINE_ATTEMPTS_REQUIRED')
    require(files.json(str(root / 'admin-get.json'))[0] == {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1},
            'EXACT_PRIOR_RESOLVER_ADMIN_ATTEMPT_REQUIRED')
    tls, _ = files.json(str(root / 'tls-handshake.json'))
    require(set(tls) == {'originHash', 'caProfileHash', 'maximumAttempts', 'httpRequests', 'bearersSent'}
            and hashed(tls['originHash']) and hashed(tls['caProfileHash']) and tls['maximumAttempts'] == 1
            and tls['httpRequests'] == tls['bearersSent'] == 0, 'EXACT_PRIOR_RESOLVER_TLS_INTENT_REQUIRED')
    reference = original['frozenReference']
    require(files.json(str(root / 'frozen-get.json'))[0] == {'method': 'GET', 'path': p.FROZEN_PATH,
        'referenceHash': digest(reference), 'maximumAttempts': 1}, 'EXACT_CONSUMED_FROZEN_GET_REQUIRED')
    for name in ['engine-get-' + str(n) + '.json' for n in range(7, 13)] + ['frozen-response.json', 'source', 'prepared.json', 'review.json']:
        try: (root / name).lstat()
        except FileNotFoundError: continue
        require(False, 'RESOLVER_PREPARATION_ADVANCED')
    response, response_profile = files.json(wire['response']['path'], wire['response']['sha256'], maximum=2097152)
    require(frozen_response.schema(response) == 'snake_case', 'TARGET_PROVEN_SNAKE_CASE_RESPONSE_REQUIRED')
    # All original reference, state, checksum and semantic-binding checks remain.
    p.frozen_configuration(response, reference)
    probe = Path(wire['response']['path']).parent
    probe_claim, probe_profile = files.json(str(probe / 'claim.json'))
    require(probe_claim == {'schema': 'ouf.semantic-registry-frozen-response-result.v1', 'bootId': boot,
        'retainedPreparationClaimHash': digest(claim), 'scriptSha256': wire['observerScriptSha256'],
        'maximumEngineGets': 2, 'maximumFrozenGets': 1, 'maximumResolverCalls': 1, 'maximumTlsConnections': 1,
        'priorAttemptCounts': {'engineGets': 28, 'adminGets': 4, 'frozenConfigurationGets': 1,
            'resolverCalls': 5, 'tlsIdentityIntentMarkers': 4},
        'cumulativeEngineGetCeiling': 30, 'cumulativeFrozenGetCeiling': 2, 'cumulativeResolverCallCeiling': 6,
        'automaticReplayAllowed': False, 'budgetReset': False}, 'EXACT_CONSUMED_RESPONSE_OBSERVER_REQUIRED')
    for n in (1, 2):
        row, _ = files.json(str(probe / ('engine-get-' + str(n) + '.json')))
        require(set(row) == {'requestPathHash', 'attempt'} and row['attempt'] == n and hashed(row['requestPathHash']),
                'BOTH_RESPONSE_OBSERVER_ENGINE_ATTEMPTS_REQUIRED')
    require(files.json(str(probe / 'frozen-get.json'))[0] == {'method': 'GET', 'path': p.FROZEN_PATH,
        'referenceHash': digest(reference), 'maximumAttempts': 1, 'resolverSource': 'SIGNED_CALLER_FILES',
        'retainedPeerPinUsed': True}, 'EXACT_RESPONSE_OBSERVER_GET_REQUIRED')
    observation, _ = files.json(str(probe / 'observation.json'))
    require(set(observation) == {'responseHash', 'shape', 'referenceHash'}
            and observation['responseHash'] == wire['response']['sha256'] and observation['referenceHash'] == digest(reference),
            'EXACT_RETAINED_RESPONSE_OBSERVATION_REQUIRED')
    return {'resolverPredecessors': prior, 'lastPreparationClaim': claim_profile,
        'responseObserverClaim': probe_profile, 'retainedResponse': response_profile,
        'priorAttemptCounts': {'engineGets': 30, 'adminGets': 4, 'frozenConfigurationGets': 2,
            'resolverCalls': 6, 'tlsAttemptMarkers': 4},
        'newAttemptCeilings': {'engineGets': 12, 'adminGets': 1, 'frozenConfigurationGets': 1,
            'resolverCalls': 2, 'tlsIdentityHandshakes': 1},
        'cumulativeAttemptCeilings': {'engineGets': 42, 'adminGets': 5, 'frozenConfigurationGets': 3,
            'resolverCalls': 8, 'tlsAttemptMarkers': 5},
        'oldPreparationReplayed': False, 'oldPreparationChanged': False, 'budgetReset': False}
