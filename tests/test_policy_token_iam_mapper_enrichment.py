"""Selected owner mapper GETs, drift denial, old evidence preservation and privacy."""
import copy
import ast
import base64
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import test_policy_token_iam_binding_candidate as fixtures
binding = fixtures.binding
sys.modules['iam_binding_candidate'] = binding
spec = importlib.util.spec_from_file_location('qualified_mapper_enrichment', ROOT / 'tools/semantic_policy_token_owner/iam_mapper_enrichment.py')
enrichment = importlib.util.module_from_spec(spec); spec.loader.exec_module(enrichment)

def full_metadata():
    value = fixtures.snapshot(); value['client']['id'] = '22222222-2222-2222-2222-222222222222'
    for index, scope in enumerate(value['defaultScopes'] + value['optionalScopes'], 3):
        scope.update(id=str(index) * 8 + '-' + str(index) * 4 + '-' + str(index) * 4 + '-' + str(index) * 4 + '-' + str(index) * 12,
                     protocol='openid-connect')
    return value

class MapperEnrichmentTest(unittest.TestCase):
    def fixture(self):
        full = full_metadata(); old = copy.deepcopy(full)
        for source in [old['client']] + old['defaultScopes'] + old['optionalScopes']:
            source['protocolMappers'] = [{} for _ in source.get('protocolMappers', [])]
        helper = fixtures.BindingCandidateTest(); self.addCleanup(helper.doCleanups)
        parent, path, raw = helper.fixture(old)
        anchor = enrichment.anchor(full); identifier = full['client']['id']; root = 'clients/' + identifier
        replies = {root: anchor['client'], root + '/service-account-user': anchor['serviceAccount'],
                   root + '/default-client-scopes': anchor['defaultScopes'], root + '/optional-client-scopes': anchor['optionalScopes'],
                   root + '/protocol-mappers/models': full['client']['protocolMappers']}
        for scope in full['defaultScopes'] + full['optionalScopes']:
            replies['client-scopes/' + scope['id'] + '/protocol-mappers/models'] = scope['protocolMappers']
        return full, parent, path, raw, replies

    def test_complete_owner_endpoints_restore_projected_fields_and_preserve_old_snapshot(self):
        full, parent, path, raw, replies = self.fixture(); calls = []; report = {'privateEvidenceWrites': 0}
        def get(reader, resource, fields=None):
            calls.append((resource, fields))
            if resource.endswith('/models'): self.assertIsNone(fields)
            return copy.deepcopy(replies[resource])
        with patch.object(binding, 'PARENT', parent), patch.object(enrichment.Reader, 'get', get):
            enrichment.execute(str(path), binding.sha(raw), fixtures.REF, report)
        self.assertEqual(path.read_bytes(), raw); self.assertEqual(report['privateEvidenceWrites'], 2)
        self.assertEqual(report['status'], 'CLAIM_CONSTRAINTS_COMPILED_REVIEW_ONLY')
        self.assertTrue(report['staticMapperConstraintsComplete']); self.assertEqual(report['uninterpretableMapperCount'], 0)
        self.assertFalse(report['baselineRefreshed'])
        self.assertTrue(report['mapperMetadataReadWithoutFieldsFilter'])
        self.assertEqual(report['parentSnapshotHash'], binding.sha(raw))
        unrequested = full['optionalScopes'][1]['id']
        self.assertFalse(any(unrequested in resource for resource, _ in calls))
        for key in ('enrichedMetadataPath', 'candidatePath'):
            self.assertEqual(Path(report[key]).stat().st_mode & 0o777, 0o600)
        public = binding.encoded(report).decode()
        self.assertNotIn('PRIVATE_FIXTURE_CLIENT', public); self.assertNotIn(full['client']['id'], public)

    def test_core_and_mapper_drift_block_before_publication(self):
        for mode in ('core', 'mapper'):
            full, parent, path, raw, replies = self.fixture(); seen = {}; report = {'privateEvidenceWrites': 0}
            def get(reader, resource, fields=None):
                seen[resource] = seen.get(resource, 0) + 1; result = copy.deepcopy(replies[resource])
                if mode == 'core' and resource == 'clients/' + full['client']['id']: result['enabled'] = False
                if mode == 'mapper' and resource.endswith('/models') and seen[resource] == 2: result.append({})
                return result
            with patch.object(binding, 'PARENT', parent), patch.object(enrichment.Reader, 'get', get):
                with self.assertRaisesRegex(binding.CandidateDenied, 'CURRENT_IAM_.*_DRIFT'):
                    enrichment.execute(str(path), binding.sha(raw), fixtures.REF, report)
            self.assertEqual(report['privateEvidenceWrites'], 0); self.assertEqual(len(list(parent.iterdir())), 1)
            self.assertEqual(path.read_bytes(), raw)

    def test_exact_get_only_cli_does_not_project_mapper_models_or_fetch_credentials(self):
        report = {}; reader = enrichment.Reader(report)
        resource = 'clients/' + full_metadata()['client']['id'] + '/protocol-mappers/models'
        with patch.object(enrichment.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'[]')) as run:
            self.assertEqual(reader.get(resource), [])
        argv = run.call_args.args[0]
        self.assertEqual(argv[:5], ['/usr/bin/docker', 'exec', 'ouf-keycloak', '/opt/keycloak/bin/kcadm.sh', 'get'])
        self.assertNotIn('--fields', argv); self.assertNotIn('client-secret', argv)
        self.assertEqual(report['iamMetadataGetAttempts'], 1)
        for invalid in ('clients/' + full_metadata()['client']['id'] + '/client-secret', 'clients/foreign/protocol-mappers/models'):
            with patch.object(enrichment.subprocess, 'run') as run:
                with self.assertRaises(binding.CandidateDenied): reader.get(invalid)
                run.assert_not_called()

    def test_unavailable_session_and_finite_request_budget_do_not_call_fallback(self):
        report = {}; reader = enrichment.Reader(report); resource = 'clients/' + full_metadata()['client']['id']
        with patch.object(enrichment.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'')) as run:
            with self.assertRaisesRegex(binding.CandidateDenied, 'EXISTING_IAM_GET_UNAVAILABLE'): reader.get(resource, enrichment.CORE_CLIENT_FIELDS)
            self.assertEqual(run.call_count, 1)
        reader.calls = 48
        with patch.object(enrichment.subprocess, 'run') as run:
            with self.assertRaisesRegex(binding.CandidateDenied, 'FINITE_METADATA_OBSERVATION'): reader.get(resource)
            run.assert_not_called()

    def test_wrong_snapshot_hash_denies_before_owner_calls_or_writes(self):
        _, parent, path, raw, replies = self.fixture(); report = {'privateEvidenceWrites': 0}
        with patch.object(binding, 'PARENT', parent), patch.object(enrichment.Reader, 'get') as get:
            with self.assertRaisesRegex(binding.CandidateDenied, 'SNAPSHOT_HASH_MISMATCH'):
                enrichment.execute(str(path), 'f' * 64, fixtures.REF, report)
            get.assert_not_called()
        self.assertEqual(report['privateEvidenceWrites'], 0); self.assertEqual(len(list(parent.iterdir())), 1)

    def test_published_metadata_is_retained_if_candidate_preparation_fails(self):
        _, parent, path, raw, replies = self.fixture(); report = {'privateEvidenceWrites': 0}
        with patch.object(binding, 'PARENT', parent), patch.object(enrichment.Reader, 'get', lambda reader, resource, fields=None: copy.deepcopy(replies[resource])), \
             patch.object(binding, 'prepare', side_effect=binding.CandidateDenied('FIXTURE_CANDIDATE_FAILURE')):
            with self.assertRaises(binding.CandidateDenied): enrichment.execute(str(path), binding.sha(raw), fixtures.REF, report)
        self.assertEqual(report['privateEvidenceWrites'], 1)
        self.assertTrue(Path(report['enrichedMetadataPath']).exists()); self.assertEqual(path.read_bytes(), raw)

    def test_exact_documented_two_source_memory_delivery_checks_both_before_sudo(self):
        text = (ROOT / 'releases/POLICY_TOKEN_IAM_MAPPER_ENRICHMENT_20261013.md').read_text()
        command = text.split("python3 - <<'PY' | tee ouf-policy-token-iam-mapper-enrichment.json\n", 1)[1].split('\nPY\n', 1)[0]
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(dir=ROOT) as temp:
            home = Path(temp); gh = home / 'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
            gh.parent.mkdir(parents=True); gh.write_text('UNEXECUTED_FIXTURE_GH'); gh.chmod(0o700)
            paths = ['iam_binding_candidate.py', 'iam_mapper_enrichment.py']; calls = []
            def run(argv, **kwargs):
                calls.append(argv)
                if len(calls) <= 2:
                    self.assertEqual(argv[0], str(gh)); self.assertIn('c9246f3b211b008dd919f6b5a4b37c7c996453be', argv[2])
                    path = ROOT / 'tools/semantic_policy_token_owner' / paths[len(calls) - 1]
                    return subprocess.CompletedProcess(argv, 0, base64.b64encode(path.read_bytes()))
                self.assertEqual(argv, ['sudo', '/usr/bin/python3', '-I', '-B', '-'])
                tree = ast.parse(kwargs['input'].decode()); records = ast.literal_eval(tree.body[1].value)
                for (_, payload, expected), path in zip(records, paths):
                    raw = (ROOT / 'tools/semantic_policy_token_owner' / path).read_bytes()
                    self.assertEqual(base64.b64decode(payload), raw); self.assertEqual(binding.sha(raw), expected)
                self.assertEqual(kwargs['timeout'], 195)
                return subprocess.CompletedProcess(argv, 0)
            with patch('pathlib.Path.home', return_value=home), patch('shutil.which', return_value=None), patch('subprocess.run', side_effect=run):
                with self.assertRaises(SystemExit) as result: exec(compile(command, '<enrichment-delivery>', 'exec'), {})
            self.assertEqual(result.exception.code, 0); self.assertEqual(len(calls), 3)

if __name__ == '__main__': unittest.main()
