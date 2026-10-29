"""Retain the failed TLS preparation and both completed resolver observations."""
from pathlib import Path
from .core import require, digest, hashed
from .caller_lookup import POLICY


def validate(case):
    value = case['resolverRecovery']
    require(type(value) is dict and set(value) == {'lookupPolicy', 'originalTlsSourceClosureHash',
        'failedObservation', 'correctedObservation'} and value['lookupPolicy'] == POLICY
        and hashed(value['originalTlsSourceClosureHash']), 'EXACT_RESOLVER_RECOVERY_CASE_REQUIRED')
    for key in ('failedObservation', 'correctedObservation'):
        ref = value[key]
        require(type(ref) is dict and set(ref) == {'path', 'sha256'} and hashed(ref['sha256'])
                and type(ref['path']) is str and ref['path'].startswith(case['privateParent'] + '/')
                and str(Path(ref['path'])) == ref['path'] and '..' not in Path(ref['path']).parts
                and Path(ref['path']).name == 'observation.json', 'EXACT_RETAINED_RESOLVER_OBSERVATION_REQUIRED')
    require(value['failedObservation']['path'] != value['correctedObservation']['path'],
            'DISTINCT_RETAINED_RESOLVER_OBSERVATIONS_REQUIRED')


def reconcile(case, files, boot):
    from . import postboot_prepare as p
    validate(case); recovery = case['resolverRecovery']
    original = {k: v for k, v in case.items() if k != 'resolverRecovery'}
    prior = p.reconcile_prior_preparation(original, files, boot)
    require(prior['priorAttemptCounts'] == {'engineGets': 12, 'adminGets': 2, 'frozenConfigurationGets': 0},
            'TWO_EARLIER_PREPARATIONS_REQUIRED')
    root = Path(p.PARENT) / ('semantic-registry-postboot-inputs-' + digest({
        'case': original, 'closure': recovery['originalTlsSourceClosureHash'], 'boot': boot}))
    expected = {'schema': p.SCHEMA, 'caseHash': digest(original),
        'sourceClosureHash': recovery['originalTlsSourceClosureHash'], 'bootId': boot,
        'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1, 'maximumTlsHandshakes': 1,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
    claim, claim_profile = files.json(str(root / 'claim.json'))
    require(claim == expected, 'SAME_CONSUMED_TLS_PREPARATION_REQUIRED')
    for number in range(1, 7):
        row, _ = files.json(str(root / ('engine-get-' + str(number) + '.json')))
        require(set(row) == {'requestPathHash', 'attempt'} and row['attempt'] == number and hashed(row['requestPathHash']),
                'EXACT_PRIOR_TLS_ENGINE_MARKERS_REQUIRED')
    admin, _ = files.json(str(root / 'admin-get.json'))
    require(admin == {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1},
            'EXACT_PRIOR_TLS_ADMIN_MARKER_REQUIRED')
    tls, _ = files.json(str(root / 'tls-handshake.json'))
    require(set(tls) == {'originHash', 'caProfileHash', 'maximumAttempts', 'httpRequests', 'bearersSent'}
            and hashed(tls['originHash']) and hashed(tls['caProfileHash']) and tls['maximumAttempts'] == 1
            and tls['httpRequests'] == tls['bearersSent'] == 0, 'EXACT_PRIOR_TLS_INTENT_REQUIRED')
    for name in ['engine-get-' + str(n) + '.json' for n in range(7, 13)] + ['frozen-get.json', 'source', 'prepared.json', 'review.json']:
        try: (root / name).lstat()
        except FileNotFoundError: continue
        require(False, 'PRIOR_TLS_PREPARATION_ADVANCED')
    old_ref = recovery['failedObservation']; corrected_ref = recovery['correctedObservation']
    old, _ = files.json(old_ref['path'], old_ref['sha256'])
    corrected, corrected_profile = files.json(corrected_ref['path'], corrected_ref['sha256'])
    require(old['oldClaim'] == claim_profile and digest(old['origin']) == tls['originHash']
            and digest(old['ca']) == tls['caProfileHash'] and old['host']['resolverSucceeded'] is True
            and old['caller']['phase'] == 'DNS_RESOLUTION' and old['caller']['gaiCode'] == -3
            and old['caller']['tcpConnectAttempted'] is False and old['caller']['tlsHandshakeAttempted'] is False,
            'SAME_RETAINED_HOST_RESOLVER_CONTEXT_FAILURE_REQUIRED')
    old_root = Path(old_ref['path']).parent; old_claim, old_claim_profile = files.json(str(old_root / 'claim.json'))
    require(old_claim == {'schema': 'ouf.semantic-registry-tls-diagnostic-result.v1',
        'retainedClaimHash': digest(claim), 'bootId': boot,
        'diagnosticScriptSha256': old_claim.get('diagnosticScriptSha256'), 'maximumEngineGets': 2,
        'maximumResolverCalls': 2, 'maximumNewTlsHandshakes': 1, 'retainedTlsAttemptMarkers': 1,
        'cumulativeTlsAttemptCeiling': 2, 'automaticReplayAllowed': False, 'budgetReset': False}
        and hashed(old_claim['diagnosticScriptSha256']), 'EXACT_FAILED_DIAGNOSTIC_CLAIM_REQUIRED')
    require(files.json(str(old_root / 'host-dns-attempt.json'))[0] == {
        'maximumResolverCalls': 1, 'httpRequests': 0, 'tlsHandshakes': 0}
        and files.json(str(old_root / 'caller-probe-attempt.json'))[0] == {
        'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1, 'httpRequests': 0, 'bearersSent': 0},
        'BOTH_PRIOR_RESOLVER_ATTEMPTS_RETAINED_REQUIRED')
    new_root = Path(corrected_ref['path']).parent; new_claim, _ = files.json(str(new_root / 'claim.json'))
    require(new_claim == {'schema': 'ouf.semantic-registry-caller-resolver-result.v1',
        'retainedObservationHash': old_ref['sha256'], 'retainedDiagnosticClaimHash': digest(old_claim), 'bootId': boot,
        'scriptSha256': new_claim.get('scriptSha256'), 'maximumEngineGets': 2, 'maximumResolverCalls': 1,
        'maximumTlsHandshakes': 1, 'priorEngineAttempts': 20, 'priorResolverAttempts': 2, 'priorTlsIntentMarkers': 2,
        'cumulativeEngineGetCeiling': 22, 'cumulativeResolverCallCeiling': 3, 'cumulativeTlsIntentCeiling': 3,
        'automaticReplayAllowed': False, 'budgetReset': False} and hashed(new_claim['scriptSha256']),
        'EXACT_CORRECTED_VIEW_CLAIM_REQUIRED')
    require(files.json(str(new_root / 'network-attempt.json'))[0] == {
        'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1, 'httpRequests': 0, 'bearersSent': 0,
        'resolverSource': 'COPIED_CALLER_FILES', 'privateMountNamespace': True}, 'EXACT_CORRECTED_VIEW_NETWORK_INTENT_REQUIRED')
    for directory in (old_root, new_root):
        for number in (1, 2):
            row, _ = files.json(str(directory / ('engine-get-' + str(number) + '.json')))
            require(set(row) == {'pathHash', 'attempt'} and hashed(row['pathHash']) and row['attempt'] == number,
                    'FOUR_PRIOR_DIAGNOSTIC_ENGINE_MARKERS_REQUIRED')
    require(corrected['retainedObservationHash'] == old_ref['sha256']
            and corrected['originHash'] == tls['originHash'] and corrected['caProfileHash'] == tls['caProfileHash']
            and set(corrected['callerViews']) == {'resolv.conf', 'hosts', 'nsswitch.conf'}
            and corrected['result']['status'] == 'OBSERVED' and corrected['result']['phase'] == 'COMPLETE'
            and all(corrected['result'][key] is True for key in ('privateLookupViewInstalled', 'resolverSucceeded',
                'tcpConnectAttempted', 'tlsHandshakeAttempted', 'certificateChainVerified', 'hostnameVerified')),
            'VERIFIED_CORRECTED_VIEW_TLS_OBSERVATION_REQUIRED')
    return {'priorPreparations': prior, 'priorTlsPreparation': claim_profile,
        'failedDiagnosticClaim': old_claim_profile, 'correctedResolverObservation': corrected_profile,
        'priorAttemptCounts': {'engineGets': 22, 'adminGets': 3, 'frozenConfigurationGets': 0,
                              'resolverCalls': 3, 'tlsAttemptMarkers': 3},
        'newAttemptCeilings': {'engineGets': 12, 'adminGets': 1, 'frozenConfigurationGets': 1,
                               'tlsIdentityHandshakes': 1, 'resolverCalls': 2},
        'cumulativeAttemptCeilings': {'engineGets': 34, 'adminGets': 4, 'frozenConfigurationGets': 1,
                                     'resolverCalls': 5, 'tlsAttemptMarkers': 4},
        'oldPreparationReplayed': False, 'oldPreparationChanged': False, 'budgetReset': False}
