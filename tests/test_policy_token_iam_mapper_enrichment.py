"""Selected owner mapper GETs, drift denial, old evidence preservation and privacy."""
import copy
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

if __name__ == '__main__': unittest.main()
