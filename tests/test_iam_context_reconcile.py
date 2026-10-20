"""Reproduce grouped context failure; reconcile two remaining GETs, no replay."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
import test_iam_policy_read as fixture_module
from tools.ingestion_rollout_preparation import iam_policy_read as p, human_timing as files
from tools.ingestion_rollout_preparation import iam_session_context_reconcile as r
from tools.ingestion_rollout_preparation import iam_context_reconcile_delivery as delivery
from tools.semantic_lease_recovery.recovery_journal import Journal


class ContextReconcile(unittest.TestCase):
    def setUp(self):
        self.f = fixture_module.ApiRead()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.uid = 1000 if os.environ.get('GITHUB_ACTIONS') == 'true' else os.geteuid()
        if self.uid != 1000:
            # Local sandbox cannot materialize UID1000. Exercise a consistent
            # root-user installation fixture here; CI additionally requires
            # the real UID1000 Docker filesystem and process-root adapter.
            self.f.container['Config']['User'] = str(self.uid)
            self.f.passwd = (str(self.uid) + ':x:' + str(self.uid) + ':0:Fixture:/home/fixture:/bin/sh\n').encode()
            original_archive = self.f.archive
            self.f.archive = lambda name, raw, uid, mode: original_archive(
                name, raw, self.uid if name == 'kcadm.config' else uid, mode)
        self.f.config = self.modified_config(username=None)
        with patch.object(p, 'EngineRead', self.f.fake_engine()):
            with self.assertRaisesRegex(ValueError, 'EXACT_RECORDED_ADMIN_SESSION_CONTEXT_REQUIRED'):
                self.f.invoke()
        self.context = p.CHECKPOINT['contextPath']
        self.case = {'schema': 'ouf.iam-session-context-reconcile-case.v1',
            'retainedContextPath': self.context, 'originalReadCase': self.f.case,
            'originalReadApiSourceHash': hashlib.sha256((ROOT / 'tools/ingestion_rollout_preparation/iam_policy_read.py').read_bytes()).hexdigest(),
            'maximumEngineRequests': 7, 'expectedEngineRequestsBefore': 5,
            'maximumAdditionalEngineRequests': 2}
        self.image = self.f.root / 'synthetic-container-root'
        self.image.mkdir(mode=0o755)
        (self.image / 'etc').mkdir(mode=0o755)
        (self.image / 'etc/passwd').write_bytes(self.f.passwd)
        (self.image / 'etc/passwd').chmod(0o644)
        (self.image / 'home').mkdir(mode=0o755)
        (self.image / 'home/fixture').mkdir(mode=0o755)
        self.credential_parent = self.image / 'home/fixture/.keycloak'
        self.credential_parent.mkdir(mode=0o700)
        os.chown(self.credential_parent, self.uid, self.uid)
        self.credential = self.credential_parent / 'kcadm.config'
        self.f.write(self.credential, self.f.config)
        os.chown(self.credential, self.uid, self.uid)

    def modified_config(self, username=None, seconds=-10, expiry_kind=None):
        cfg = self.f.config_token(seconds)
        row = cfg['endpoints']['http://localhost:8080']['master']
        part = row['token'].split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        claims['iat'] = claims['exp'] - 60
        if username is None:
            claims.pop('preferred_username', None)
        else:
            claims['preferred_username'] = username
        row['token'] = 'fixture.' + base64.urlsafe_b64encode(p.encoded(claims)).decode().rstrip('=') + '.fixture'
        if expiry_kind is not None:
            row['expiresAt'] = expiry_kind
        return cfg

    @contextmanager
    def process_fixture(self):
        # Actual FD-relative custody is exercised here; process identity is
        # synthetic. The physical Docker process-root path is mandatory below.
        with patch.object(r, 'root_path', return_value=str(self.image)), patch.object(r, 'process_start', return_value=b'fixture-start'):
            yield

    def invoke(self):
        return r.run(self.case, p, files, Journal, 'd' * 64)

    def test_missing_username_is_distinguished_without_identity_values(self):
        old_claim = next(self.f.root.glob('iam-policy-read-*.claim.json'))
        before = old_claim.read_bytes()
        with self.process_fixture(), patch.object(p, 'EngineRead', self.f.fake_engine()), patch.object(p, 'admin_get') as admin:
            value = self.invoke()
        admin.assert_not_called()
        self.assertFalse(value['checks']['preferredUsernameClaimPresent'])
        self.assertFalse(value['checks']['preferredUsernameMatchesExpected'])
        self.assertTrue(value['checks']['issuerMatchesSelectedContext'])
        self.assertTrue(value['checks']['authorizedPartyMatchesSelectedClient'])
        self.assertEqual(value['recordedAdminIssuedLifetimeSeconds'], 60)
        self.assertTrue(value['recordedAdminAccessExpired'])
        self.assertEqual(value['engineRequestsBefore'], 5)
        self.assertEqual(value['engineRequestsReserved'], 7)
        self.assertEqual(value['archiveRequestsThisInvocation'], 0)
        self.assertEqual(old_claim.read_bytes(), before)
        self.assertNotIn('fixture-admin', json.dumps(value))
        self.assertNotIn('PRIVATE-', json.dumps(value))
        self.assertFalse(value['currentProviderPolicyProven'])
        self.assertEqual(Journal(Path(self.context)).read()['state'], 'STOP_RECONCILE')

    def test_different_username_and_expiry_type_remain_separate_checks(self):
        value = r.classify(p, self.modified_config('different-fixture-user', expiry_kind='not-an-epoch'),
            self.f.case['adminReadProfile'], self.f.selection['issuer'], time.time())
        self.assertTrue(value['checks']['preferredUsernameClaimPresent'])
        self.assertFalse(value['checks']['preferredUsernameMatchesExpected'])
        self.assertEqual(value['cliExpiryKind'], 'STRING')
        self.assertIsNone(value['recordedAdminTokenSecondsRemaining'])
        self.assertNotIn('different-fixture-user', json.dumps(value))

    def test_context_matching_later_is_not_claimed_as_original_failure(self):
        value = r.classify(p, self.modified_config('fixture-admin', seconds=3600),
            self.f.case['adminReadProfile'], self.f.selection['issuer'], time.time())
        self.assertFalse(value['originalContextMismatchReproduced'])
        self.assertFalse(value['recordedClaimsAreRuntimeAuthority'])

    def test_wrong_original_counter_cannot_reset_or_extend_budget(self):
        journal = Journal(Path(self.context))
        p.save(journal, engineRequestsReserved=6)
        with patch.object(p, 'EngineRead') as engine:
            with self.assertRaisesRegex(ValueError, 'SAME_STOPPED_READ_WITH_FIVE'):
                self.invoke()
        engine.assert_not_called()
        self.assertFalse((Path(self.context) / 'admin-session-context-reconcile.claim.json').exists())

    def test_consumed_reconcile_claim_status_only_no_credential_or_engine_read(self):
        with self.process_fixture(), patch.object(p, 'EngineRead', self.f.fake_engine()):
            self.invoke()
        with patch.object(p, 'EngineRead') as engine, patch.object(r, 'ProcessFiles') as process:
            with self.assertRaises(ValueError):
                self.invoke()
            status = r.status(self.case, p, files, Journal)
        engine.assert_not_called()
        process.assert_not_called()
        self.assertEqual(status['reconciliationState'], 'COMPLETE_METADATA_ONLY')
        self.assertEqual(status['credentialFilesRead'], 0)
        self.assertEqual(status['engineRequestsReserved'], 7)

    def test_symlink_credential_fails_without_chmod_or_read_replay(self):
        original = self.credential_parent / 'retained-original'
        self.credential.rename(original)
        self.credential.symlink_to(original)
        before = original.read_bytes()
        with self.process_fixture(), patch.object(p, 'EngineRead', self.f.fake_engine()):
            with self.assertRaises(OSError):
                self.invoke()
        self.assertEqual(original.read_bytes(), before)
        row = Journal(Path(self.context)).read()
        self.assertEqual(row['engineRequestsReserved'], 6)
        self.assertEqual(row['adminGetsReserved'], 0)
        self.assertEqual(row['reconciliationState'], 'STOP_RECONCILE')

    def test_selected_process_generation_change_does_not_grant_authority(self):
        engine_base = self.f.fake_engine()
        class Changed(engine_base):
            def request(inner, *args, **kwargs):
                result = super().request(*args, **kwargs)
                if inner.journal.read()['engineRequestsReserved'] == 7:
                    result['State']['StartedAt'] = 'new-process'
                return result
        with self.process_fixture(), patch.object(p, 'EngineRead', Changed):
            with self.assertRaisesRegex(ValueError, 'GENERATION_CHANGED'):
                self.invoke()
        self.assertEqual(Journal(Path(self.context)).read()['engineRequestsReserved'], 7)

    def test_original_code_change_rejected_by_delivery(self):
        case = {**self.case, 'originalReadApiSourceHash': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_STOPPED_IAM_READER_SOURCE'):
            delivery.generate(ROOT, case)

    def test_published_reconciliation_and_launcher_are_reproducible(self):
        case = json.loads((ROOT / 'releases/iam-session-context-reconcile-case-20261020.json').read_text())
        raw, _ = delivery.generate(ROOT, case)
        self.assertEqual((ROOT / 'scripts/iam-session-context-reconcile-20261020.py').read_bytes(), raw)
        launcher = ROOT / 'scripts/launch-iam-session-context-reconcile-20261020.sh'
        shell = launcher.read_text()
        self.assertIn(hashlib.sha256(raw).hexdigest(), shell)
        self.assertIn(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), shell)
        check = subprocess.run(['/bin/bash', '-n', str(launcher)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_actual_docker_process_root_and_isolated_reconciliation(self):
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            self.skipTest('Actual Docker process-root and sealed process are mandatory in CI')
        self.f.test_actual_docker_archive_and_three_namespace_gets_then_expired_sealed_read()
        self.f.case['fixtureObservationRef'] = 'third-explicit-failed-context-fixture'
        config_path = self.f.root / 'container-fixture/.keycloak/kcadm.config'
        self.f.write(config_path, self.modified_config(username=None, seconds=-10))
        with self.assertRaisesRegex(ValueError, 'EXACT_RECORDED_ADMIN_SESSION_CONTEXT_REQUIRED'):
            self.f.invoke()
        self.case['retainedContextPath'] = p.CHECKPOINT['contextPath']
        self.case['originalReadCase'] = self.f.case
        before = config_path.read_bytes()
        raw, _ = delivery.generate(ROOT, self.case)
        script = self.f.root / 'sealed-context-reconcile.py'
        script.write_bytes(raw)
        run = subprocess.run(['/usr/bin/python3', '-I', '-B', '-S', str(script), 'reconcile'],
            capture_output=True, text=True, timeout=90)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        value = json.loads(run.stdout)
        self.assertEqual(value['engineRequestsReserved'], 7)
        self.assertFalse(value['checks']['preferredUsernameClaimPresent'])
        self.assertEqual(value['adminGetsReserved'], 0)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertNotIn('PRIVATE-', run.stdout + run.stderr)
        status = subprocess.run(['/usr/bin/python3', '-I', '-B', '-S', str(script), 'status'],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertEqual(json.loads(status.stdout)['credentialFilesRead'], 0)
        self.assertEqual(json.loads(status.stdout)['reconciliationState'], 'COMPLETE_METADATA_ONLY')


if __name__ == '__main__':
    unittest.main()
