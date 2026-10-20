"""Compile an unsigned installation-specific timing proposal before authentication.

The measured JWT lifetime is history, not current IAM policy. This planner has
no authentication, policy mutation, signing or runtime dispatch capability.
It cannot replace provider-policy readback or HUMAN/THS/installer decisions.
"""
import copy


class DurationDenied(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise DurationDenied(code)


def compile_proposal(profile, receipt):
    require(type(profile) is dict and set(profile) == {
        'schema', 'installationProfileRef', 'humanSelectionHash', 'runtimeMaximumSeconds',
        'reviewAndApprovalAllowanceSeconds', 'clockSafetyMarginSeconds',
        'proposedIssuedTokenLifetimeSeconds', 'expectedCumulativeAttempts',
        'maximumCumulativeOAuthAttempts', 'plannedHumanProviderRequests'},
        'EXPLICIT_INSTALLATION_DURATION_PROFILE_REQUIRED')
    require(profile['schema'] == 'ouf.ingestion-human-duration-proposal-profile.v1'
        and type(profile['installationProfileRef']) is str and 0 < len(profile['installationProfileRef']) <= 256
        and type(profile['humanSelectionHash']) is str and len(profile['humanSelectionHash']) == 64
        and all(c in '0123456789abcdef' for c in profile['humanSelectionHash']),
        'EXACT_INSTALLATION_AND_FULL_HUMAN_SELECTION_REQUIRED')
    numeric = set(profile) - {'schema', 'installationProfileRef', 'humanSelectionHash'}
    require(all(type(profile[k]) is int for k in numeric), 'INTEGER_FINITE_DURATION_AND_BUDGET_PROFILE_REQUIRED')
    require(210 <= profile['runtimeMaximumSeconds'] <= 900
        and 30 <= profile['clockSafetyMarginSeconds'] <= 120
        and 60 <= profile['reviewAndApprovalAllowanceSeconds'] <= 900
        and 0 < profile['proposedIssuedTokenLifetimeSeconds'] <= 7200
        and 0 <= profile['expectedCumulativeAttempts'] <= profile['maximumCumulativeOAuthAttempts'] <= 4096
        and profile['plannedHumanProviderRequests'] == 4,
        'FINITE_NATIVE_WINDOW_AND_FOUR_EXPLICIT_PROVIDER_STEPS_REQUIRED')
    require(type(receipt) is dict and receipt.get('schema') == 'ouf.ingestion-human-timing-inspection-result.v1'
        and receipt.get('status') == 'RECORDED_READY_TIMING_RECONCILED_NO_AUTHORITY'
        and receipt.get('complete') is receipt.get('readOnly') is True
        and all(receipt.get(k) is False for k in ('runtimeAuthorityIssued', 'automaticReplayAllowed',
            'budgetReset', 'snapshotIsRuntimeAuthority', 'newLoginPerformed', 'refreshPerformed'))
        and type(receipt.get('attempts')) is type(receipt.get('maximumCumulativeOAuthAttempts')) is int
        and receipt['attempts'] == profile['expectedCumulativeAttempts']
        and receipt['maximumCumulativeOAuthAttempts'] == profile['maximumCumulativeOAuthAttempts']
        and receipt.get('remainingAttempts') == profile['maximumCumulativeOAuthAttempts'] - receipt['attempts'],
        'SAME_RECONCILED_HISTORY_AND_CUMULATIVE_BUDGET_REQUIRED')
    margin = profile['runtimeMaximumSeconds'] + profile['clockSafetyMarginSeconds']
    require(receipt.get('requiredProductionTokenMarginSeconds') == margin,
        'PROFILE_MUST_MATCH_PREPARED_PRODUCTION_GUARD')
    issued, expiry = receipt.get('recordedIssuedAtUnix'), receipt.get('recordedAccessExpiresAtUnix')
    lifetime = receipt.get('recordedIssuedTokenLifetimeSeconds')
    require(type(issued) is type(expiry) is type(lifetime) is int
        and 0 < issued <= expiry and lifetime == expiry - issued
        and receipt.get('recordedIssuedLifetimeCouldCoverMargin') == (lifetime > margin),
        'EXACT_RECORDED_ISSUED_LIFETIME_REQUIRED_NO_DEFAULT')
    projected_attempts = receipt['attempts'] + profile['plannedHumanProviderRequests']
    require(projected_attempts <= profile['maximumCumulativeOAuthAttempts'],
        'CUMULATIVE_AUTHENTICATION_BUDGET_INSUFFICIENT_NO_RESET')
    minimum = margin + profile['reviewAndApprovalAllowanceSeconds']
    require(profile['proposedIssuedTokenLifetimeSeconds'] > minimum,
        'PROPOSED_LIFETIME_MUST_COVER_PREPARATION_AND_NATIVE_WINDOW')
    return {'schema': 'ouf.ingestion-human-duration-proposal.v1',
        'status': 'CURRENT_CLIENT_POLICY_READ_AND_GOVERNED_REVIEW_REQUIRED',
        'profile': copy.deepcopy(profile), 'recordedIssuedLifetimeSeconds': lifetime,
        'requiredProductionTokenMarginSeconds': margin,
        'minimumTotalLifetimeExclusiveSeconds': minimum,
        'proposedIssuedLifetimeSeconds': profile['proposedIssuedTokenLifetimeSeconds'],
        'projectedAttemptsAfterOneFreshFourStepAuthentication': projected_attempts,
        'projectedRemainingAttempts': profile['maximumCumulativeOAuthAttempts'] - projected_attempts,
        'additionalAdministrativeOAuthAttemptsAccounted': False,
        'currentProviderPolicyProven': False, 'existingTokenExtended': False,
        'currentWindowExtended': False, 'newWindowAuthorized': False,
        'freshAuthenticationAuthorized': False, 'iamPolicyMutationAuthorized': False,
        'runtimeAuthorityIssued': False, 'budgetReset': False, 'automaticReplayAllowed': False,
        'sourceOrSemanticApprovalGranted': False, 'notReleaseAcceptance': True}
