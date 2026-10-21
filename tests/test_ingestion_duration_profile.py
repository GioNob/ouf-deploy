"""Budget, expiry and installation choices fail closed before more authentication."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.ingestion_rollout_preparation.duration_profile import compile_proposal, DurationDenied


class DurationProfile(unittest.TestCase):
    def setUp(self):
        self.profile = {'schema': 'ouf.ingestion-human-duration-proposal-profile.v1',
            'installationProfileRef': 'fixture/installation-a', 'humanSelectionHash': 'a' * 64,
            'runtimeMaximumSeconds': 900, 'reviewAndApprovalAllowanceSeconds': 120,
            'clockSafetyMarginSeconds': 30, 'proposedIssuedTokenLifetimeSeconds': 1200,
            'expectedCumulativeAttempts': 282, 'maximumCumulativeOAuthAttempts': 288,
            'plannedHumanProviderRequests': 4}
        self.receipt = {'schema': 'ouf.ingestion-human-timing-inspection-result.v1',
            'status': 'RECORDED_READY_TIMING_RECONCILED_NO_AUTHORITY', 'complete': True, 'readOnly': True,
            'attempts': 282, 'maximumCumulativeOAuthAttempts': 288, 'remainingAttempts': 6,
            'requiredProductionTokenMarginSeconds': 930, 'recordedIssuedAtUnix': 1000,
            'recordedAccessExpiresAtUnix': 1300, 'recordedIssuedTokenLifetimeSeconds': 300,
            'recordedIssuedLifetimeCouldCoverMargin': False, 'runtimeAuthorityIssued': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'snapshotIsRuntimeAuthority': False,
            'newLoginPerformed': False, 'refreshPerformed': False}

    def test_exact300_history_cannot_authorize_new_login_or_policy_change(self):
        before = copy.deepcopy((self.profile, self.receipt))
        result = compile_proposal(self.profile, self.receipt)
        self.assertEqual(result['minimumTotalLifetimeExclusiveSeconds'], 1050)
        self.assertEqual(result['projectedAttemptsAfterOneFreshFourStepAuthentication'], 286)
        self.assertEqual(result['projectedRemainingAttempts'], 2)
        self.assertFalse(result['freshAuthenticationAuthorized'])
        self.assertFalse(result['iamPolicyMutationAuthorized'])
        self.assertFalse(result['additionalAdministrativeOAuthAttemptsAccounted'])
        self.assertEqual(before, (self.profile, self.receipt))

    def test_second_installation_uses_its_own_explicit_duration_profile(self):
        other = {**self.profile, 'installationProfileRef': 'fixture/installation-b',
            'humanSelectionHash': 'b' * 64, 'runtimeMaximumSeconds': 210,
            'reviewAndApprovalAllowanceSeconds': 60, 'proposedIssuedTokenLifetimeSeconds': 600}
        receipt = {**self.receipt, 'requiredProductionTokenMarginSeconds': 240,
            'recordedIssuedLifetimeCouldCoverMargin': True}
        result = compile_proposal(other, receipt)
        self.assertEqual(result['minimumTotalLifetimeExclusiveSeconds'], 300)
        self.assertEqual(result['proposedIssuedLifetimeSeconds'], 600)
        self.assertEqual(result['profile']['humanSelectionHash'], 'b' * 64)

    def test_short_proposal_and_prepared_guard_mismatch_rejected(self):
        for delta in [{'proposedIssuedTokenLifetimeSeconds': 1050}, {'runtimeMaximumSeconds': 210}]:
            with self.subTest(delta=delta), self.assertRaises(DurationDenied):
                compile_proposal({**self.profile, **delta}, self.receipt)

    def test_budget_three_remaining_cannot_silently_reset_or_skip_verification(self):
        p = {**self.profile, 'expectedCumulativeAttempts': 285}
        r = {**self.receipt, 'attempts': 285, 'remainingAttempts': 3}
        with self.assertRaisesRegex(DurationDenied, 'BUDGET_INSUFFICIENT_NO_RESET'):
            compile_proposal(p, r)
        with self.assertRaises(DurationDenied):
            compile_proposal({**p, 'plannedHumanProviderRequests': 3}, r)

    def test_stale_floor_or_fabricated_lifetime_rejected(self):
        for delta in [{'attempts': 278}, {'recordedIssuedTokenLifetimeSeconds': 1800},
                      {'recordedIssuedLifetimeCouldCoverMargin': True}, {'budgetReset': True}]:
            with self.subTest(delta=delta), self.assertRaises(DurationDenied):
                compile_proposal(self.profile, {**self.receipt, **delta})

    def test_unknown_lifetime_missing_profile_and_bool_durations_rejected(self):
        with self.assertRaises(DurationDenied):
            compile_proposal(self.profile, {**self.receipt, 'recordedIssuedAtUnix': None})
        for delta in [{'runtimeMaximumSeconds': True}, {'clockSafetyMarginSeconds': -1},
                      {'proposedIssuedTokenLifetimeSeconds': 7201}]:
            with self.subTest(delta=delta), self.assertRaises(DurationDenied):
                compile_proposal({**self.profile, **delta}, self.receipt)
        p = {**self.profile}
        p.pop('humanSelectionHash')
        with self.assertRaises(DurationDenied):
            compile_proposal(p, self.receipt)


if __name__ == '__main__':
    unittest.main()
