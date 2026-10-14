"""Native directory/signature delivery fixture; no target effects or real HUMAN."""
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tests'), str(ROOT / 'tools/semantic_policy_token_owner')]
import test_policy_token_migration_root_custody as fixtures
import tools
tools.__path__.append(str(ROOT / 'tools'))
import iam_owner_action as owner

spec = importlib.util.spec_from_file_location('root_delivery', ROOT / 'scripts/establish-policy-token-migration-roots.py')
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)


class RootDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.c = fixtures.RootCustodyTest()
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.addCleanup(signal.alarm, 0)
        self.f = self.c.f.f
        body = ast.parse(delivery.ROOT_BODY)
        start = next(i for i, node in enumerate(body.body)
                     if isinstance(node, ast.Import) and node.names[0].name == 'iam_owner_action')
        # Execute the actual operational functions, not a rewritten test driver.
        definitions = ast.Module(body=body.body[start:-1], type_ignores=[])
        self.module = types.ModuleType('root_delivery_fixture')
        self.module.__dict__.update(base64=base64, hashlib=hashlib, json=json, os=os,
            re=__import__('re'), signal=signal, stat=__import__('stat'), sys=sys,
            time=__import__('time'), types=types, CAPSULE_SHA=delivery.CAPSULE_SHA,
            ROOT_BODY_HASH=hashlib.sha256(delivery.ROOT_BODY.encode()).hexdigest(),
            manifest={'syntheticFixture': True})
        exec(compile(definitions, 'actual-root-delivery-functions', 'exec'), self.module.__dict__)
        library = {'syntheticFixtureLibrary': True}
        previous_raw = fixtures.binding.encoded({'stdlib': library})
        previous_hash = fixtures.binding.sha(previous_raw)
        self.f.write(self.f.root / ('policy-token-iam-action-review-' + previous_hash + '.private.json'), previous_raw)
        self.c.f.host['ownerReviewHash'] = previous_hash
        self.c.f.raw = fixtures.binding.encoded(self.c.f.host)
        host_hash = fixtures.binding.sha(self.c.f.raw)
        self.f.write(self.f.root / ('policy-token-migration-host-inputs-' + host_hash + '.private.json'), self.c.f.raw)
        programs = {'openssl': {**self.f.binding(self.f.openssl), 'version': self.f.native('version').decode().split()[1]}}
        profile = {'keyBindings': {'installer': self.f.binding(self.f.key)}, 'keyRefs': {'installer': self.f.grant['keyRef']}}
        for p in (
            patch.object(self.module.legacy, 'HOST_HASH', host_hash),
            patch.object(owner, 'inputs', return_value=({'executablesProposedNotAccepted': programs}, {}, {}, profile)),
            patch.object(owner, 'stdlib_binding', return_value=library),
            patch.object(owner.governance, 'POLICY', self.f.binding(self.f.policy)),
            patch.object(owner.governance, 'CONTEXT', self.f.context),
            patch.object(self.module, 'terminal_decision', side_effect=lambda h, s, scope: 'APPROVO RADICI ' + h),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.report = {'signaturesIssued': 0, 'installationKeyAccessAttempted': False, 'humanIssuanceClaimConsumed': False}

    def test_actual_signing_creates_roots_and_records_real_identities(self):
        self.module.execute(self.report)
        self.assertEqual(self.report['status'], 'ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED')
        self.assertEqual(self.report['signaturesIssued'], 2)
        ledger = json.loads(Path(self.report['rootEvidencePath']).read_bytes())
        self.assertEqual(ledger['mkdirAttempts'], 6)
        for name in self.c.paths.values():
            row = Path(name).stat()
            self.assertEqual(ledger['created'][name]['inode'], row.st_ino)
            self.assertEqual(row.st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(fixtures.binding.CandidateDenied, 'ISSUANCE_ALREADY_CONSUMED'):
            self.module.execute(self.report)

    def test_declined_human_decision_has_no_signature_or_root_effect(self):
        with patch.object(self.module, 'terminal_decision', side_effect=fixtures.binding.CandidateDenied('DECLINED')):
            with self.assertRaisesRegex(fixtures.binding.CandidateDenied, 'DECLINED'):
                self.module.execute(self.report)
        self.assertEqual(self.report['signaturesIssued'], 0)
        self.assertFalse(self.report['humanIssuanceClaimConsumed'])
        for name in self.c.paths.values():
            self.assertFalse(Path(name).exists())

    def test_directory_appearing_during_prompt_prevents_key_access(self):
        def change(h, s, scope):
            Path(scope['directories'][0]).mkdir(mode=0o700)
            return 'APPROVO RADICI ' + h
        with patch.object(self.module, 'terminal_decision', side_effect=change):
            with self.assertRaisesRegex(fixtures.binding.CandidateDenied, 'NO_ADOPTION'):
                self.module.execute(self.report)
        self.assertFalse(self.report['installationKeyAccessAttempted'])
        self.assertFalse(self.report['humanIssuanceClaimConsumed'])

    def test_failed_signing_consumes_issuance_and_never_reissues(self):
        with patch.object(owner.ExistingEd25519Signer, 'sign', side_effect=RuntimeError('FIXTURE_SIGN_FAILURE')):
            with self.assertRaisesRegex(RuntimeError, 'FIXTURE_SIGN_FAILURE'):
                self.module.execute(self.report)
        self.assertTrue(self.report['humanIssuanceClaimConsumed'])
        with patch.object(owner.ExistingEd25519Signer, 'sign', side_effect=AssertionError('no second issuance')), \
             patch.object(self.module, 'terminal_decision', side_effect=AssertionError('no second prompt')):
            with self.assertRaisesRegex(fixtures.binding.CandidateDenied, 'ISSUANCE_ALREADY_CONSUMED'):
                self.module.execute(self.report)

    def test_expired_policy_denies_before_signing_and_root_creation(self):
        policy = json.loads(self.f.policy.read_bytes())
        policy['keys'][0]['expiresAt'] = self.f.now + 20
        self.f.write(self.f.policy, fixtures.binding.encoded(policy))
        with patch.object(owner.governance, 'POLICY', self.f.binding(self.f.policy)):
            with self.assertRaisesRegex(Exception, 'WINDOW_EXCEEDS'):
                self.module.execute(self.report)
        self.assertFalse(self.report['installationKeyAccessAttempted'])
        for name in self.c.paths.values():
            self.assertFalse(Path(name).exists())

    def test_portable_gh_delivery_and_exact_sealed_root_flags(self):
        home = self.f.root / 'home'
        preferred = home / 'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
        preferred.parent.mkdir(parents=True)
        preferred.write_text('fixture')
        preferred.chmod(0o700)
        capsule = (ROOT / delivery.CAPSULE_PATH).read_bytes()
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == str(preferred):
                return subprocess.CompletedProcess(argv, 0, base64.b64encode(capsule))
            self.assertEqual(argv[:7], ['sudo', '--', '/usr/bin/python3', '-I', '-B', '-S', '-c'])
            self.assertEqual(kwargs['input'], capsule)
            self.assertIn(hashlib.sha256(delivery.ROOT_BODY.encode()).hexdigest(), argv[7])
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(delivery.Path, 'home', return_value=home), patch.object(delivery.shutil, 'which', return_value=None), \
             patch.object(delivery.subprocess, 'run', side_effect=run):
            self.assertEqual(delivery.main(), 0)
        self.assertEqual(len(calls), 2)

    def test_capsule_corruption_stops_before_sudo(self):
        with patch.object(delivery.Path, 'home', return_value=self.f.root), \
             patch.object(delivery.shutil, 'which', return_value='/fixture/gh'), \
             patch.object(delivery.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, base64.b64encode(b'corrupt'))) as run:
            with self.assertRaisesRegex(SystemExit, 'HASH_MISMATCH'):
                delivery.main()
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
