"""Compile a review-only relocation scope; never authenticate or execute it."""
import hashlib
import json

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def compile_plan(custody, correspondence):
    require(type(custody) is dict and type(correspondence) is dict,
            'EXACT_OPERATOR_EVIDENCE_REQUIRED')
    require(custody.get('schema') == 'ouf.semantic-token-secret-reference-metadata.v2'
            and custody.get('status') == 'SECRET_REFERENCE_METADATA_OBSERVED_NOT_ACCEPTED'
            and correspondence.get('schema') == 'ouf.semantic-token-private-output-correspondence-receipt.v2'
            and correspondence.get('status') == 'PRIVATE_OUTPUT_CORRESPONDENCE_OBSERVED_NOT_ACCEPTED',
            'CORRECTED_V2_EVIDENCE_REQUIRED')
    for value in (custody, correspondence):
        require(value.get('evidenceSource') == 'operator_reported_not_independent_live_readback'
                and value.get('stableDoubleRead') is True
                and value.get('notReleaseAcceptance') is True,
                'LIMITED_REPORTED_EVIDENCE_REQUIRED')
        for key in ('baselineRefreshed', 'budgetReset', 'r12Touched', 'producerExecuted',
                    'sourceAuthenticationProven', 'writerAuthorityProven', 'runtimeAuthorityIssued'):
            require(value.get(key) is False, 'NO_RUNTIME_AUTHORITY_OR_EFFECT_ALLOWED')
        for key in ('providerCalls', 'serviceMutations', 'protectedFileWrites'):
            require(type(value.get(key)) is int and value[key] == 0,
                    'ZERO_EFFECT_REPORTED_EVIDENCE_REQUIRED')
    require(correspondence.get('environmentFileCountVerified') == 1
            and type(correspondence.get('environmentFileCountVerified')) is int
            and all(correspondence.get(k) is True for k in (
                'unitPropertyMultiplicityVerified', 'singleDirectProducerCommandVerified',
                'configuredOutputMatchesHistoricalMount0', 'configuredRuntimeDirectoryMatchesHistoricalMount0',
                'configuredRuntimeGidMatchesHistoricalMount0')),
            'EXACT_CURRENT_CONFIGURATION_CORRESPONDENCE_REQUIRED')
    require(custody.get('sharedUnsafeAncestorWithProducer') is True
            and type(custody.get('sharedUnsafeAncestorCount')) is int
            and custody['sharedUnsafeAncestorCount'] == 1, 'ONE_SHARED_CUSTODY_SCOPE_REQUIRED')
    for role, mode in (('producerMetadata', '0755'), ('referenceMetadata', '0400')):
        value = custody.get(role)
        require(type(value) is dict and value.get('ancestorTraversalComplete') is True
                and value.get('rootProtectedAncestors') is False and value.get('regularFile') is True
                and value.get('symlink') is False and value.get('uid') == value.get('gid') == 0
                and type(value.get('uid')) is int and type(value.get('gid')) is int
                and value.get('modeOctal') == mode and type(value.get('linkCount')) is int
                and value.get('linkCount') == 1,
                'EXACT_OBSERVED_LEAF_CUSTODY_REQUIRED')
        ancestors = value.get('ancestors')
        require(type(ancestors) is list and len(ancestors) == 3, 'EXACT_OBSERVED_ANCESTOR_SCOPE_REQUIRED')
        parent = ancestors[1]
        require(parent.get('standardRouteClass') == 'OPT_OUF' and parent.get('depth') == 2
                and parent.get('uid') == parent.get('gid') == 1000
                and parent.get('modeOctal') == '0750' and parent.get('passesRootGuard') is False,
                'SHARED_OPT_OUF_CUSTODY_REQUIRED')
        require(all(type(item.get('uid')) is int and type(item.get('gid')) is int
                    and item.get('directory') is True and item.get('symlink') is False
                    for item in ancestors), 'EXACT_DIRECTORY_METADATA_REQUIRED')
        expected_uid = 0 if role == 'producerMetadata' else 1000
        require(ancestors[2].get('uid') == ancestors[2].get('gid') == expected_uid
                and ancestors[2].get('modeOctal') == '0700'
                and ancestors[2].get('passesRootGuard') is (role == 'producerMetadata'),
                'EXACT_DISTINCT_INNER_DIRECTORY_CUSTODY_REQUIRED')
    def fingerprint(value):
        # Hash only the public fields used by this compiler. Unknown extra
        # fields must not leak through a digest of possible private material.
        safe = {key: value[key] for key in ('schema', 'status', 'stableDoubleRead')}
        if value is custody:
            safe.update(sharedUnsafeAncestorCount=1, sharedUnsafeAncestorWithProducer=True)
            safe['leafModes'] = {'producer': '0755', 'reference': '0400'}
            safe['ancestorOwners'] = {'shared': 1000, 'producerInner': 0, 'referenceInner': 1000}
        else:
            for key in ('environmentFileCountVerified', 'singleDirectProducerCommandVerified',
                        'configuredOutputMatchesHistoricalMount0', 'configuredRuntimeDirectoryMatchesHistoricalMount0',
                        'configuredRuntimeGidMatchesHistoricalMount0'):
                safe[key] = value[key]
        return hashlib.sha256(json.dumps(safe, sort_keys=True, separators=(',', ':'),
                                         allow_nan=False).encode()).hexdigest()
    return {
        'schema': 'ouf.semantic-token-owner-custody-remediation-plan.v1',
        'status': 'REVIEW_ONLY_NOT_APPLY_READY',
        'publicFactProjectionHashes': {'custody': fingerprint(custody), 'correspondence': fingerprint(correspondence)},
        'reportedEvidenceRefs': ['evidence/semantic-token-shared-custody-ancestor-target-20261012.json',
                                 'evidence/semantic-token-private-output-correspondence-v2-target-20261012.json'],
        'preservedIntakeHash': '005f6a7afad7d493a52d9b183816fa0346f1bb1a4de5ab4b63c8b0b39f3fb092',
        'scope': {'unit': 'ouf-policy-token@semantic.service', 'timer': 'ouf-policy-token@semantic.timer',
                  'sharedUnsafeAncestor': '/opt/ouf', 'additionalCredentialDirectoryUnsafe': True},
        'proposedProtectedRoots': {'reviewedCode': '/usr/local/libexec/ouf-policy-token',
                                  'ownerCredential': '/etc/ouf/policy-token/credentials/semantic',
                                  'durableRecovery': '/var/lib/ouf/policy-token/semantic'},
        'requiredBeforeAnyApply': [
            'Independent reviewed producer source and current installation authority',
            'Existing IAM owner proves credential/client/issuer/audience/scope and finite validity',
            'Protected credential re-establishment; no blind copy of unauthenticated material',
            'Persisted fenced incident budgets; reconcile unknown historical accounting',
            'Owner-proven grant idempotency or ambiguity reconciliation before retry',
            'Versioned six-mount policy with renewable token and unchanged static delegation key',
            'Signed current acceptance and scoped HUMAN execution mandate'],
        'recoveryProposal': {'policyVersion': 3, 'backoffSeconds': [5, 15, 60, 300, 900],
                             'maxJitterFraction': 0.2, 'maxAttempts': 128,
                             'maxEpisodeSeconds': 86400, 'previousAccounting': 'UNPROVEN',
                             'newZeroBudgetInvented': False, 'ambiguousGrant': 'RECONCILE_REQUIRED'},
        'preserveCurrentOutputBinding': True, 'preserveStaticDelegationKey': True,
        'globalOptOufPermissionChangeProposed': False, 'sourceCopiedOrApproved': False,
        'credentialCopiedOrRotated': False, 'rootDestinationsObserved': False,
        'rootCustodyEstablishedByPlan': False, 'sixMountClosureProven': False,
        'sourceAuthenticationProven': False, 'writerAuthorityProven': False,
        'productionApplyReady': False, 'applicationCutoverAuthorized': False,
        'runtimeAuthorityIssued': False, 'signaturesIssued': 0, 'providerCalls': 0,
        'serviceMutations': 0, 'protectedFileWrites': 0, 'budgetReset': False,
        'baselineRefreshed': False, 'r12Touched': False, 'notReleaseAcceptance': True}
