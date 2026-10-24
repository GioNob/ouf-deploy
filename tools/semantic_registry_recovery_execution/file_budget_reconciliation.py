"""Retain the completed read attempts of the byte-budget preparation stop."""
import stat
from .core import require, digest, hashed


def validate(case):
    value = case['fileBudgetRecovery']
    require(type(value) is dict and set(value) == {'wireSourceClosureHash'} and hashed(value['wireSourceClosureHash']),
            'EXACT_FILE_BUDGET_RECOVERY_BINDING_REQUIRED')


def reconcile(case, files, boot):
    from . import postboot_prepare as p
    validate(case)
    original = {k: v for k, v in case.items() if k != 'fileBudgetRecovery'}
    prior = p.reconcile_prior_preparation(original, files, boot)
    require(prior['priorAttemptCounts'] == {'engineGets': 30, 'adminGets': 4, 'frozenConfigurationGets': 2,
        'resolverCalls': 6, 'tlsAttemptMarkers': 4}, 'ALL_FROZEN_WIRE_PREDECESSORS_REQUIRED')
    root = p.prepared_root(original, {}, boot)
    claim, binding = files.json(str(root / 'claim.json'))
    require(claim == {'schema': p.SCHEMA, 'caseHash': digest(original),
        'sourceClosureHash': case['fileBudgetRecovery']['wireSourceClosureHash'], 'bootId': boot,
        'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1, 'maximumTlsHandshakes': 1,
        'maximumMetadataReads': 256, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False},
        'EXACT_CONSUMED_WIRE_PREPARATION_REQUIRED')
    for n in range(1, 13):
        row, _ = files.json(str(root / ('engine-get-' + str(n) + '.json')))
        require(set(row) == {'requestPathHash', 'attempt'} and type(row['attempt']) is int and row['attempt'] == n
                and hashed(row['requestPathHash']), 'ALL_TWELVE_CONSUMED_ENGINE_ATTEMPTS_REQUIRED')
    require(files.json(str(root / 'admin-get.json'))[0] == {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1},
            'EXACT_CONSUMED_WIRE_ADMIN_ATTEMPT_REQUIRED')
    tls, _ = files.json(str(root / 'tls-handshake.json'))
    require(set(tls) == {'originHash', 'caProfileHash', 'maximumAttempts', 'httpRequests', 'bearersSent'}
        and hashed(tls['originHash']) and hashed(tls['caProfileHash']) and tls['maximumAttempts'] == 1
        and tls['httpRequests'] == tls['bearersSent'] == 0, 'EXACT_CONSUMED_WIRE_TLS_INTENT_REQUIRED')
    require(files.json(str(root / 'frozen-get.json'))[0] == {'method': 'GET', 'path': p.FROZEN_PATH,
        'referenceHash': digest(case['frozenReference']), 'maximumAttempts': 1}, 'EXACT_CONSUMED_WIRE_FROZEN_GET_REQUIRED')
    response, response_binding = files.json(str(root / 'frozen-response.json'), maximum=2097152)
    p.frozen_configuration(response, case['frozenReference'])
    source = (root / 'source').lstat()
    require(stat.S_ISDIR(source.st_mode) and source.st_uid == source.st_gid == 0 and stat.S_IMODE(source.st_mode) == 0o500,
            'RETAINED_COMPLETED_SOURCE_COPY_DIRECTORY_REQUIRED')
    for name in ('engine-get-13.json', 'prepared.json', 'review.json'):
        try: (root / name).lstat()
        except FileNotFoundError: continue
        require(False, 'WIRE_PREPARATION_ADVANCED_RECONCILE_REQUIRED')
    return {'wirePredecessors': prior, 'consumedWireClaim': binding, 'consumedWireResponse': response_binding,
        'priorAttemptCounts': {'engineGets': 42, 'adminGets': 5, 'frozenConfigurationGets': 3, 'resolverCalls': 8, 'tlsAttemptMarkers': 5},
        'newAttemptCeilings': {'engineGets': 12, 'adminGets': 1, 'frozenConfigurationGets': 1, 'resolverCalls': 2, 'tlsIdentityHandshakes': 1},
        'cumulativeAttemptCeilings': {'engineGets': 54, 'adminGets': 6, 'frozenConfigurationGets': 4, 'resolverCalls': 10, 'tlsAttemptMarkers': 6},
        'oldPreparationReplayed': False, 'oldPreparationChanged': False, 'budgetReset': False}
