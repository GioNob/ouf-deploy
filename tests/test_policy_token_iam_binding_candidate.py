"""Effective scopes, static claim uncertainty, root evidence and no replay effects."""
import copy
import ast
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/semantic_policy_token_owner/iam_binding_candidate.py'
spec = importlib.util.spec_from_file_location('qualified_binding_candidate', SOURCE)
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)
REF = {'issuer': 'https://iam.fixture.test/realms/fixture', 'tenant': 'fixture-tenant',
       'audience': 'fixture-audience', 'actor': 'SERVICE'}

def claim(name, value):
    return {'protocol': 'openid-connect', 'protocolMapper': 'oidc-hardcoded-claim-mapper',
            'config': {'claim.name': name, 'claim.value': value, 'jsonType.label': 'String',
                       'access.token.claim': 'true', 'introspection.token.claim': 'true'}}

def snapshot():
    return {'schema': 'ouf.policy-token-existing-iam-metadata.v1', 'issuerSelection': REF['issuer'],
            'realm': 'fixture', 'client': {'clientId': 'PRIVATE_FIXTURE_CLIENT', 'enabled': True,
                    'serviceAccountsEnabled': True, 'publicClient': False, 'protocol': 'openid-connect',
                    'clientAuthenticatorType': 'client-secret', 'protocolMappers': [claim('tenant_id', REF['tenant'])]},
            'serviceAccount': {'id': '11111111-1111-1111-1111-111111111111', 'enabled': True},
            'defaultScopes': [{'name': 'default-scope', 'protocolMappers': [claim('ouf_actor_type', 'SERVICE')]}],
            'optionalScopes': [{'name': 'authorization.bundle.read', 'protocolMappers': [{
                    'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
                    'config': {'included.custom.audience': REF['audience'], 'access.token.claim': 'true',
                               'introspection.token.claim': 'true'}}]},
                    {'name': 'UNREQUESTED_PRIVILEGED_SCOPE', 'protocolMappers': [claim('ouf_actor_type', 'HUMAN')]}],
            'requestedScopes': ['authorization.bundle.read'], 'credentialProvenanceAccepted': False,
            'actualTokenIntrospectionProven': False, 'targetHttpsPeerBindingProven': False,
            'historicalAccountingReconciled': False, 'runtimeAuthorityIssued': False, 'notReleaseAcceptance': True}

class BindingCandidateTest(unittest.TestCase):
    def fixture(self, value=None):
        temp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(temp.cleanup)
        parent = Path(temp.name); parent.chmod(0o700)
        path = parent / ('policy-token-iam-metadata-' + 'a' * 32 + '.private.json')
        raw = binding.encoded(value or snapshot()); path.write_bytes(raw); path.chmod(0o600)
        return parent, path, raw

    def test_unrequested_optional_mappers_cannot_change_effective_claims_or_envelope(self):
        candidate, public = binding.compile_binding(snapshot(), 'a' * 64, REF)
        self.assertTrue(public['staticMapperConstraintsComplete'])
        self.assertEqual(public['selectedOptionalScopeCount'], 1)
        self.assertNotIn('UNREQUESTED_PRIVILEGED_SCOPE', candidate['candidateAllowedScopeEnvelope'])
        self.assertFalse(candidate['productionApplyReady'])
        self.assertFalse(candidate['runtimeAuthorityIssued'])
        self.assertFalse(candidate['credentialProvenanceAccepted'])
        self.assertFalse(candidate['historicalAccountingReconciled'])
        self.assertNotIn('PRIVATE_FIXTURE_CLIENT', json.dumps(public))
        self.assertNotIn('11111111-', json.dumps(public))

    def test_requested_optional_conflict_does_not_get_silently_ignored(self):
        value = snapshot(); value['requestedScopes'].append('UNREQUESTED_PRIVILEGED_SCOPE')
        candidate, public = binding.compile_binding(value, 'a' * 64, REF)
        self.assertFalse(public['staticMapperConstraintsComplete'])
        self.assertIn('ACTOR_MAPPER_NOT_PROVEN', candidate['reviewReasons'])

    def test_conflicting_tenant_missing_audience_and_unknown_dynamic_mapper_need_review(self):
        for case in ('tenant', 'audience', 'dynamic', 'subject'):
            value = snapshot()
            if case == 'tenant': value['client']['protocolMappers'].append(claim('tenant_id', 'foreign'))
            if case == 'audience': value['optionalScopes'][0]['protocolMappers'] = []
            if case == 'dynamic': value['client']['protocolMappers'].append({'protocol': 'openid-connect', 'protocolMapper': 'UNSUPPORTED_SCRIPT_MAPPER', 'config': {}})
            if case == 'subject': value['client']['protocolMappers'].append(claim('sub', 'foreign-subject'))
            candidate, public = binding.compile_binding(value, 'a' * 64, REF)
            self.assertFalse(public['staticMapperConstraintsComplete'])
            self.assertTrue(candidate['reviewReasons'])
            self.assertNotIn('foreign', json.dumps(public))

    def test_omitted_introspection_mapper_flag_is_unknown_not_a_valid_bearer(self):
        value = snapshot(); del value['client']['protocolMappers'][0]['config']['introspection.token.claim']
        candidate, public = binding.compile_binding(value, 'a' * 64, REF)
        self.assertTrue(public['tenantStaticMapperMatchesReference'])
        self.assertFalse(public['tenantIntrospectionMappingExplicit'])
        self.assertIn('TENANT_INTROSPECTION_MAPPING_NOT_EXPLICIT', candidate['reviewReasons'])
        self.assertTrue(candidate['metadataOnlyNoBearerAdmission'])

    def test_missing_flags_nested_claims_and_reserved_claim_overrides_are_not_ignored(self):
        for case in ('missing', 'nested', 'scope', 'issuer', 'audience'):
            value = snapshot(); extra = claim('tenant_id', 'foreign')
            if case == 'missing': del extra['config']['access.token.claim']
            if case == 'nested': extra['config']['claim.name'] = 'tenant_id.nested'
            if case == 'scope': extra['config']['claim.name'] = 'scope'
            if case == 'issuer': extra['config']['claim.name'] = 'iss'
            if case == 'audience': extra['config']['claim.name'] = 'aud'
            value['client']['protocolMappers'].append(extra)
            candidate, public = binding.compile_binding(value, 'a' * 64, REF)
            self.assertFalse(public['staticMapperConstraintsComplete'])
            self.assertTrue(candidate['reviewReasons'])

    def test_opaque_mapper_shapes_are_retained_as_review_findings_without_false_matches(self):
        cases = [None, {}, {'protocol': 'foreign', 'protocolMapper': 'PRIVATE_MAPPER_TYPE', 'config': {}},
                 {'protocol': 'openid-connect', 'protocolMapper': 'PRIVATE_MAPPER_TYPE'},
                 {'protocol': 'openid-connect', 'protocolMapper': 'PRIVATE_MAPPER_TYPE', 'config': None}]
        for value in (None, False, 123, ['PRIVATE_VALUE'], {'PRIVATE_KEY': 'PRIVATE_VALUE'}):
            cases.append({'protocol': 'openid-connect', 'protocolMapper': 'PRIVATE_MAPPER_TYPE', 'config': {'PRIVATE_KEY': value}})
        for mapper in cases:
            value = snapshot(); value['client']['protocolMappers'].append(mapper)
            candidate, public = binding.compile_binding(value, 'a' * 64, REF)
            self.assertEqual(candidate['schema'], 'ouf.policy-token-iam-binding-candidate.v2')
            self.assertEqual(public['uninterpretableMapperCount'], 1)
            self.assertTrue(public['mapperSchemaFindings'])
            self.assertFalse(public['staticMapperConstraintsComplete'])
            for key in ('tenantStaticMapperMatchesReference', 'actorStaticMapperMatchesReference',
                        'audienceStaticMapperMatchesReference', 'tenantIntrospectionMappingExplicit'):
                self.assertFalse(public[key])
            self.assertFalse(candidate['productionApplyReady'])
            self.assertFalse(candidate['runtimeAuthorityIssued'])
            self.assertNotIn('PRIVATE_', json.dumps(public))

    def test_incomplete_unrequested_optional_mapper_does_not_affect_selected_set(self):
        value = snapshot(); value['optionalScopes'][1]['protocolMappers'] = [{}]
        candidate, public = binding.compile_binding(value, 'a' * 64, REF)
        self.assertEqual(public['uninterpretableMapperCount'], 0)
        self.assertTrue(public['staticMapperConstraintsComplete'])
        self.assertFalse(candidate['productionApplyReady'])

    def test_exact_hash_root_private_publication_and_identical_reconciliation(self):
        parent, path, raw = self.fixture(); before = path.stat(); report = {'privateEvidenceWrites': 0}
        with patch.object(binding, 'PARENT', parent):
            binding.prepare(str(path), binding.sha(raw), REF, report)
            self.assertEqual(report['privateEvidenceWrites'], 1)
            self.assertTrue(report['newCandidatePublished'])
            saved = Path(report['candidatePath']); self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            inode = saved.stat().st_ino
            again = {'privateEvidenceWrites': 0}; binding.prepare(str(path), binding.sha(raw), REF, again)
            self.assertFalse(again['newCandidatePublished']); self.assertEqual(again['privateEvidenceWrites'], 0)
            self.assertEqual(saved.stat().st_ino, inode)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(path.stat().st_ino, before.st_ino)

    def test_tampered_hash_link_symlink_and_unprotected_file_are_denied_without_candidate(self):
        for case in ('hash', 'mode', 'symlink'):
            with self.subTest(case=case):
                parent, path, raw = self.fixture()
                if case == 'mode': path.chmod(0o644)
                if case == 'symlink':
                    path.unlink(); path.symlink_to(SOURCE)
                report = {'privateEvidenceWrites': 0}
                with patch.object(binding, 'PARENT', parent):
                    with self.assertRaises(binding.CandidateDenied):
                        binding.prepare(str(path), 'b' * 64 if case == 'hash' else binding.sha(raw), REF, report)
                self.assertEqual(report['privateEvidenceWrites'], 0)
                self.assertEqual(len(list(parent.iterdir())), 1)

    def test_partial_existing_candidate_is_not_overwritten_or_bypassed(self):
        parent, path, raw = self.fixture(); candidate, _ = binding.compile_binding(snapshot(), binding.sha(raw), REF)
        output = parent / ('policy-token-iam-binding-' + binding.sha(binding.encoded(candidate)) + '.private.json')
        output.touch(mode=0o600)
        with patch.object(binding, 'PARENT', parent):
            for _ in range(2):
                with self.assertRaises(binding.CandidateDenied):
                    binding.prepare(str(path), binding.sha(raw), REF, {'privateEvidenceWrites': 0})
        self.assertEqual(output.read_bytes(), b'')
        self.assertEqual(len(list(parent.iterdir())), 2)

    def test_altered_scope_schema_fake_acceptance_and_nonmatching_issuer_are_denied(self):
        for case in ('scope', 'acceptance', 'issuer', 'duplicate', 'bounds'):
            value = snapshot()
            if case == 'scope': value['requestedScopes'] = ['unassigned']
            if case == 'acceptance': value['runtimeAuthorityIssued'] = True
            if case == 'issuer': value['issuerSelection'] = 'https://foreign.invalid/realms/fixture'
            if case == 'duplicate': value['optionalScopes'].append(copy.deepcopy(value['optionalScopes'][0]))
            if case == 'bounds': value['client']['protocolMappers'] *= 65
            with self.assertRaises(binding.CandidateDenied): binding.compile_binding(value, 'a' * 64, REF)

    def test_exact_documented_delivery_binds_retained_snapshot_hash_and_memory_source(self):
        text = (ROOT / 'releases/POLICY_TOKEN_IAM_BINDING_COMPILATION_20261013.md').read_text()
        command = text.split("python3 - <<'PY' | tee ouf-policy-token-iam-binding-compilation.json\n", 1)[1].split('\nPY\n', 1)[0]
        raw = SOURCE.read_bytes(); calls = []
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            home = Path(temp); gh = home / 'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
            gh.parent.mkdir(parents=True); gh.write_text('UNEXECUTED_FIXTURE_GH'); gh.chmod(0o700)
            def run(argv, **kwargs):
                calls.append(argv)
                if len(calls) == 1:
                    self.assertEqual(argv[0], str(gh))
                    self.assertIn('bcd20f30085cfdd13276e3af3d1295f7c43eada2', argv[2])
                    return subprocess.CompletedProcess(argv, 0, base64.b64encode(raw))
                self.assertEqual(argv, ['sudo', '/usr/bin/python3', '-I', '-B', '-'])
                tree = ast.parse(kwargs['input'].decode())
                self.assertEqual(base64.b64decode(tree.body[1].value.args[0].value), raw)
                arguments = ast.literal_eval(tree.body[3].value)
                self.assertEqual(arguments[arguments.index('--snapshot-sha256') + 1], '6e37df961443b0c3f95f097865c53af5f8b3b777e626d59c5faaa44973942227')
                self.assertTrue(arguments[arguments.index('--snapshot') + 1].endswith('74e3f02522a741b3919dfe3f06a2cccc.private.json'))
                self.assertEqual(kwargs['timeout'], 45)
                return subprocess.CompletedProcess(argv, 0)
            with patch('pathlib.Path.home', return_value=home), patch('shutil.which', return_value=None), patch('subprocess.run', side_effect=run):
                with self.assertRaises(SystemExit) as result: exec(compile(command, '<documented-binding-command>', 'exec'), {})
            self.assertEqual(result.exception.code, 0); self.assertEqual(len(calls), 2)

if __name__ == '__main__': unittest.main()
