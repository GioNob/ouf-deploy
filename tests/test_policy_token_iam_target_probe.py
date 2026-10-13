"""Selected administrative GET boundary and private evidence; synthetic IAM metadata."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/semantic_policy_token_owner/iam_target_probe.py'
spec = importlib.util.spec_from_file_location('qualified_iam_probe', SOURCE)
probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)

class IamTargetProbeTest(unittest.TestCase):
    def config(self):
        values = {'CLIENT_ID': 'DISPOSABLE_SEMANTIC_CLIENT',
                  'ENDPOINT': probe.ISSUER + '/protocol/openid-connect/token',
                  'REQUIRED_SCOPE': 'authorization.bundle.read',
                  'RUNTIME_DIR': '/UNOPENED_OUTPUT', 'RUNTIME_GID': '10001',
                  'SECRET_FILE': '/UNOPENED_SECRET'}
        raw = '\n'.join('OUF_POLICY_TOKEN_' + k + '=' + v for k, v in values.items()).encode()
        return raw, probe.parse_configuration(raw)
    def metadata(self):
        return [[{'id': '11111111-1111-1111-1111-111111111111', 'clientId': 'DISPOSABLE_SEMANTIC_CLIENT',
                  'enabled': True, 'serviceAccountsEnabled': True, 'publicClient': False,
                  'protocol': 'openid-connect', 'clientAuthenticatorType': 'client-secret',
                  'protocolMappers': [{'config': {'claim.value': 'PRIVATE_MAPPER_VALUE'}}]}],
                {'id': '22222222-2222-2222-2222-222222222222', 'enabled': True},
                [{'id': 'scope-id', 'name': 'authorization.bundle.read', 'protocol': 'openid-connect'}], []]
    def test_only_four_exact_existing_client_gets_and_no_credentials_or_grants(self):
        raw, cfg = self.config(); values = self.metadata(); calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[:5], ['/usr/bin/docker', 'exec', 'ouf-keycloak', '/opt/keycloak/bin/kcadm.sh', 'get'])
            self.assertIn('--server', argv); self.assertIn('http://localhost:8080', argv)
            self.assertIs(kwargs['stdin'], subprocess.DEVNULL)
            self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
            self.assertLessEqual(kwargs['timeout'], 15)
            self.assertFalse(any(x in argv for x in ('client-secret', 'credentials', 'create', 'update', 'delete')))
            return subprocess.CompletedProcess(argv, 0, probe.encoded(values[len(calls) - 1]))
        with patch.object(probe.subprocess, 'run', side_effect=run):
            snapshot = probe.observe(cfg)
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0][-2:], ['-q', 'clientId=DISPOSABLE_SEMANTIC_CLIENT'])
        self.assertFalse(snapshot['credentialProvenanceAccepted'])
        self.assertFalse(snapshot['actualTokenIntrospectionProven'])
    def test_ambiguous_disabled_public_client_unassigned_scope_and_session_failure_deny(self):
        _, cfg = self.config()
        for case in ('multiple', 'disabled', 'public', 'scope', 'session'):
            with self.subTest(case=case):
                values = self.metadata()
                if case == 'multiple': values[0] *= 2
                if case == 'disabled': values[0][0]['enabled'] = False
                if case == 'public': values[0][0]['publicClient'] = True
                if case == 'scope': values[2] = []
                if case == 'session':
                    with patch.object(probe.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'')):
                        with self.assertRaisesRegex(probe.ProbeDenied, 'IAM_GET_UNAVAILABLE'): probe.observe(cfg)
                else:
                    with patch.object(probe, 'iam_get', side_effect=values):
                        with self.assertRaises(probe.ProbeDenied): probe.observe(cfg)
    def test_config_cannot_select_unknown_issuer_extra_key_or_duplicate_key(self):
        raw, _ = self.config()
        for changed in (raw.replace(probe.ISSUER.encode(), b'https://foreign.invalid/realms/ouf'),
                        raw + b'\nSECRET=NEVER_ACCEPTED', raw + b'\nOUF_POLICY_TOKEN_CLIENT_ID=duplicate'):
            with self.assertRaises(probe.ProbeDenied): probe.parse_configuration(changed)
    def test_output_contains_safe_summary_and_evidence_location_only(self):
        raw, cfg = self.config(); snapshot = probe.observe
        with patch.object(probe, 'routing', return_value=(probe.CONFIGURATION, {})), \
             patch.object(probe, 'read_configuration', return_value=raw), \
             patch.object(probe, 'iam_get', side_effect=self.metadata() * 2), \
             patch.object(probe, 'save_snapshot', return_value=('/SAFE_PRIVATE_EVIDENCE', 'a' * 64)), \
             patch('builtins.print') as output:
            self.assertEqual(probe.main(), 0)
        text = output.call_args.args[0]
        for private in ('PRIVATE_MAPPER_VALUE', 'PRIVATE_ATTRIBUTE_VALUE', 'UNOPENED_SECRET',
                        'DISPOSABLE_SEMANTIC_CLIENT', '11111111-', '22222222-'):
            self.assertNotIn(private, text)
        self.assertFalse(json.loads(text)['actualTokenIntrospectionProven'])
    def test_private_snapshot_is_exclusive_and_retains_no_original_secret_reference(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            directory = Path(temp); directory.chmod(0o700)
            with patch.object(probe, 'SNAPSHOTS', str(directory)), patch.object(probe, 'iam_get', side_effect=self.metadata()):
                snapshot = probe.observe(self.config()[1]); path, digest = probe.save_snapshot(snapshot)
            saved = Path(path)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('UNOPENED_SECRET', saved.read_text())
            self.assertIn('PRIVATE_MAPPER_VALUE', saved.read_text())
            self.assertEqual(len(digest), 64)
    def test_configuration_route_rejects_other_files_and_environment_overrides(self):
        props = ['EnvironmentFiles', 'Environment', 'UnsetEnvironment', 'RootDirectory', 'RootImage',
                 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem']
        for case in ('foreign', 'duplicate', 'override'):
            lines = [key + '=' + (probe.CONFIGURATION + ' (ignore_errors=no)' if key == 'EnvironmentFiles' else '') for key in props]
            if case == 'foreign': lines[0] = 'EnvironmentFiles=/UNOPENED_SECRET (ignore_errors=no)'
            if case == 'duplicate': lines += [lines[0]]
            if case == 'override': lines[1] = 'Environment=OUF_POLICY_TOKEN_CLIENT_ID=foreign'
            with patch.object(probe.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '\n'.join(lines).encode())):
                with self.assertRaises(probe.ProbeDenied): probe.routing()

if __name__ == '__main__': unittest.main()
