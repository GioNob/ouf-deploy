"""Real retained fixtures, file custody, expiry, no side effects and sealed CLI."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
import test_ingestion_production_control as production_fixture
from tools.ingestion_rollout_preparation import human_timing as t, timing_delivery as delivery

REAL_RUN = subprocess.run


class TimingInspection(unittest.TestCase):
    def setUp(self):
        self.fixture = production_fixture.ProductionControl()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.prepare()
        self.case = {'schema': 'ouf.ingestion-human-timing-case.v1',
            'purpose': 'EXACT_RETAINED_INSTALLATION_DIAGNOSTIC_NOT_PORTABLE_DEFAULT',
            'humanControlPath': f.human_fixture.control, 'humanSourceClosureHash': f.human_fixture.closure,
            'ownerPlanBinding': f.case['ownerPlanBinding'], 'productionContextPath': f.context,
            'productionControlSourceHash': f.control_hash, 'productionCaseHash': t.digest(f.case),
            'expectedAttempts': 282, 'maximumCumulativeOAuthAttempts': 288,
            'requiredTokenMarginSeconds': 930}
        self.profile_path = Path(f.human_path)
        self.profile = json.loads(self.profile_path.read_text())
        self.journal = Path(self.profile['journal']['path'])
        self.bearer = self.profile['expectedBinding']['tokenPath']

    def token(self, lifetime, *, age=42, with_iat=True):
        row = json.loads(self.journal.read_text())
        encoded = row['accessToken'].split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        claims['exp'] = int(self.fixture.human_fixture.now) + lifetime - age
        if with_iat:
            claims['iat'] = claims['exp'] - lifetime
        token = 'fixture.' + base64.urlsafe_b64encode(t.encoded(claims)).decode().rstrip('=') + '.fixture'
        row.update(accessToken=token, publishedAccessToken=token, accessExpiresAt=claims['exp'])
        self.fixture.write(self.journal, row)
        self.profile['journal'] = t.selected(str(self.journal))[1]
        self.fixture.write(self.profile_path, self.profile)
        return claims

    def snapshot(self):
        roots = [self.fixture.root, self.fixture.human_fixture.root]
        return {str(p): p.read_bytes() for root in roots for p in root.rglob('*') if p.is_file()}

    def test_short_issued_token_proves_mismatch_without_login_or_writes(self):
        claims = self.token(300)
        before = self.snapshot()
        with patch.object(os, 'open', wraps=os.open) as opened:
            result = t.inspect(self.case)
        self.assertEqual(result['recordedIssuedTokenLifetimeSeconds'], 300)
        self.assertEqual(result['recordedTokenSecondsRemaining'], 258)
        self.assertFalse(result['recordedIssuedLifetimeCouldCoverMargin'])
        self.assertEqual(result['recordedAccessExpiresAtUnix'], claims['exp'])
        self.assertEqual(result['remainingAttempts'], 6)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(any(call.args[0] == self.bearer for call in opened.call_args_list))
        self.assertEqual(result['oauthRequests'], 0)
        self.assertFalse(result['currentProviderPolicyProven'])
        self.assertNotIn('fixture.', json.dumps(result))

    def test_expired_ready_history_still_reconciles_without_authority(self):
        self.token(300)
        before = self.snapshot()
        value = t.inspect(self.case, now=self.fixture.human_fixture.now + 10000)
        self.assertEqual(value['recordedTokenSecondsRemaining'], 0)
        self.assertTrue(value['complete'])
        self.assertFalse(value['runtimeAuthorityIssued'])
        self.assertFalse(value['snapshotIsRuntimeAuthority'])
        self.assertEqual(before, self.snapshot())

    def test_actual_production_guard_rejects_258_seconds_before_review_write(self):
        self.token(300)
        row = json.loads(self.journal.read_text())
        Path(self.bearer).write_text(row['accessToken'])
        with self.assertRaisesRegex(Exception, 'CURRENT_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH'):
            self.fixture.invoke('review', self.fixture.context, str(self.profile_path))
        self.assertFalse((Path(self.fixture.context) / 'review.json').exists())
        self.assertEqual(self.fixture.invoke('status', self.fixture.context)['state'], 'PRIVATE_READY')
        self.fixture.entry.execute.assert_not_called()

    def test_long_lifetime_and_elapsed_operator_time_are_distinct(self):
        self.token(1800, age=1542)
        value = t.inspect(self.case)
        self.assertEqual(value['recordedTokenSecondsRemaining'], 258)
        self.assertTrue(value['recordedIssuedLifetimeCouldCoverMargin'])
        self.assertFalse(value['observedRemainingCoversMargin'])

    def test_missing_iat_stays_unknown_not_assumed_300_seconds(self):
        self.token(300, with_iat=False)
        value = t.inspect(self.case)
        self.assertIsNone(value['recordedIssuedTokenLifetimeSeconds'])
        self.assertIsNone(value['recordedIssuedLifetimeCouldCoverMargin'])

    def test_wrong_counter_full_selection_or_consumed_claim_stops(self):
        for field, value in [('expectedAttempts', 278), ('humanSourceClosureHash', 'f' * 64),
                             ('productionCaseHash', 'e' * 64)]:
            case = {**self.case, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                t.inspect(case)
        control = Path(self.case['humanControlPath'])
        config = json.loads((control / 'control.json').read_text())
        claim = Path(config['review']['predecessorDirectory']) / 'successor-window.claim.json'
        data = json.loads(claim.read_text())
        data['budgetReset'] = True
        self.fixture.write(claim, data)
        with self.assertRaisesRegex(ValueError, 'EXACT_CONSUMED_WINDOW_CLAIM'):
            t.inspect(self.case)

    def test_changed_ready_bytes_or_unsafe_mode_rejected(self):
        row = json.loads(self.journal.read_text())
        row['attempts'] = 283
        self.fixture.write(self.journal, row)
        with self.assertRaisesRegex(ValueError, 'EXACT_RETAINED_TIMING_SEAL'):
            t.inspect(self.case)
        self.profile_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'EXACT_PRIVATE_TIMING_DOCUMENT'):
            t.inspect(self.case)

    def test_symlink_hardlink_and_duplicate_nonfinite_fields_rejected(self):
        p = self.fixture.root / 'selected.json'
        p.symlink_to(self.journal)
        with self.assertRaises(OSError):
            t.selected(str(p))
        p.unlink()
        os.link(self.journal, p)
        with self.assertRaisesRegex(ValueError, 'EXACT_PRIVATE_TIMING_DOCUMENT'):
            t.selected(str(p))
        p.unlink()
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                t.decode(raw)

    def test_modified_token_identity_rejected_even_if_fixture_reseals_journal(self):
        self.token(300)
        row = json.loads(self.journal.read_text())
        claims = json.loads(base64.urlsafe_b64decode(row['accessToken'].split('.')[1] + '=='))
        claims['sub'] = 'another-human'
        token = 'fixture.' + base64.urlsafe_b64encode(t.encoded(claims)).decode().rstrip('=') + '.fixture'
        row.update(accessToken=token, publishedAccessToken=token)
        self.fixture.write(self.journal, row)
        self.profile['journal'] = t.selected(str(self.journal))[1]
        self.fixture.write(self.profile_path, self.profile)
        with self.assertRaisesRegex(ValueError, 'EXACT_RECORDED_HUMAN_TIMESTAMP_CONTEXT'):
            t.inspect(self.case)

    def test_runtime_already_initialized_cannot_masquerade_as_preparation(self):
        self.fixture.write(Path(self.fixture.context) / 'recovery.json', {'runtime': 'fixture-initialized'})
        with self.assertRaisesRegex(ValueError, 'EXACT_UNDISPATCHED_PRODUCTION'):
            t.inspect(self.case)

    def test_actual_isolated_delivery_is_reproducible_and_redacts_failure(self):
        self.token(300, age=600)
        raw, declaration = delivery.generate(ROOT, self.case)
        self.assertEqual(delivery.generate(ROOT, self.case)[0], raw)
        script = self.fixture.root / 'timing.py'
        script.write_bytes(raw)
        before = self.snapshot()
        run = REAL_RUN([sys.executable, '-I', '-B', '-S', str(script)], capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        value = json.loads(run.stdout)
        self.assertEqual(value['recordedTokenSecondsRemaining'], 0)
        self.assertEqual(value['recordedIssuedTokenLifetimeSeconds'], 300)
        self.assertEqual(before, self.snapshot())
        bad = REAL_RUN([sys.executable, '-I', '-B', '-S', str(script), 'refresh'], capture_output=True, text=True, timeout=30)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(json.loads(bad.stdout)['status'], 'STOP_RECONCILE')
        self.assertNotIn('fixture.', bad.stdout + bad.stderr)
        self.assertNotIn(self.bearer, bad.stdout + bad.stderr)

    def test_published_delivery_and_launcher_match_exact_source_and_case(self):
        case = json.loads((ROOT / 'releases/ingestion-human-timing-case-20261020.json').read_text())
        raw, declaration = delivery.generate(ROOT, case)
        self.assertEqual((ROOT / 'scripts/ingestion-human-timing-inspection-20261020.py').read_bytes(), raw)
        launcher = ROOT / 'scripts/launch-ingestion-human-timing-20261020.sh'
        shell = launcher.read_text()
        self.assertIn(delivery.sha(raw), shell)
        self.assertIn(t.hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), shell)
        check = REAL_RUN(['/bin/bash', '-n', str(launcher)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)


if __name__ == '__main__':
    unittest.main()
