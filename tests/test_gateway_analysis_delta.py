import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('delta', ROOT / 'scripts/prepare-gateway-analysis-delta-20261108.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
A = m.assets(ROOT / 'releases/gateway-analysis-assets-20261108.json')


def fixture():
    common = dict(zip(m.KEYS, ('FIXTURE_DELEGATION_KEY', 'https://issuer.example.test/realms/fixture',
                             'fixture-gateway', 'fixture-mcp', 'FIXTURE_ONBOARDING_KEY')))
    def route(uri, identifier):
        return {'id': identifier, 'uri': uri, 'methods': ['POST'], 'status': 1, 'labels': {'fixture': 'retained'},
                'plugins': {'openid-connect': {'client_secret': 'DO_NOT_EMIT_SYNTHETIC_SECRET'},
                            'limit-count': {'count': 60}, 'serverless-pre-function': {'functions': ['RETAIN_EXACTLY']},
                            'request-validation': {'max_req_body_size': 65536, 'body_schema': {}},
                            'serverless-post-function': {'phase': 'access', 'functions': ['OLD_FUNCTION']},
                            'proxy-rewrite': {'uri': '/fixture'}},
                'upstream': {'nodes': {'fixture-owner:8080': 1}, 'scheme': 'http', 'retries': 0,
                             'timeout': {'connect': 3, 'send': 3, 'read': 3}}}
    rows = [route('/mcp', 'mcp'), route('/internal/capabilities/v1/execute', 'execute')]
    for mode in ('preview', 'profile', 'create', 'review-prepare'):
        row = route(m.PREFIX + mode, 'file-' + mode)
        row['plugins']['request-validation']['body_schema'] = m.schema(A, 'old', mode)
        row['plugins']['serverless-post-function']['functions'] = [m.function_source(A, 'old', 'execute_managed_file', common)]
        rows.append(row)
    sem = route('/internal/capabilities/v1/execute/semantic/search', 'semantic-search')
    constants = dict(common, OWNER_KEY_ENV='FIXTURE_SEMANTIC_KEY')
    sem['plugins']['serverless-post-function']['functions'] = [m.function_source(A, 'old', 'execute_semantic_read', constants)]
    sem['upstream']['nodes'] = {'existing-semantic:8080': 1}
    rows.append(sem)
    rows += [route('/retained/' + str(i), 'retained-' + str(i)) for i in range(84-len(rows))]
    pins = {row['uri']: m.digest(row) for row in rows if row['uri'] in m.BEFORE}
    return {'total': 84, 'list': [{'value': row} for row in rows]}, pins


class DeltaTests(unittest.TestCase):
    def test_only_five_updates_three_additions_and_no_input_mutation(self):
        data, pins = fixture()
        before = copy.deepcopy(data)
        with patch.object(m, 'BEFORE', pins):
            plan = m.compile_plan(data, A)
        self.assertEqual(data, before)
        self.assertEqual(len(plan['unchangedRoutes']), 79)
        self.assertEqual(sum(c['operation'] == 'UPDATE' for c in plan['changes']), 5)
        self.assertEqual(sum(c['operation'] == 'ADD' for c in plan['changes']), 3)
        self.assertEqual(plan['desiredRouteCount'], 87)
        originals = {str(r['value']['id']): r['value'] for r in before['list']}
        for row in plan['unchangedRoutes']:
            self.assertEqual(row, originals[str(row['id'])])
        for c in plan['changes']:
            if c['operation'] == 'UPDATE':
                old, new = c['before'], c['desired']
                for plugin in ('openid-connect', 'limit-count', 'serverless-pre-function', 'proxy-rewrite'):
                    self.assertEqual(old['plugins'][plugin], new['plugins'][plugin])
                for key in ('nodes', 'scheme', 'retries'):
                    self.assertEqual(old['upstream'][key], new['upstream'][key])
            else:
                self.assertEqual(c['desired']['upstream']['nodes'], {'existing-semantic:8080': 1})
                self.assertNotIn('/internal/providers/', c['uri'])

    def test_reject_unknown_function_even_if_route_hash_matches(self):
        data, pins = fixture()
        row = data['list'][2]['value']
        row['plugins']['serverless-post-function']['functions'][0] += '\n-- unexpected target patch'
        pins[row['uri']] = m.digest(row)
        with patch.object(m, 'BEFORE', pins), self.assertRaisesRegex(RuntimeError, 'NOT_QUALIFIED_BASELINE'):
            m.compile_plan(data, A)

    def test_reject_stale_route_input(self):
        data, pins = fixture()
        data['list'][0]['value']['plugins']['openid-connect']['client_secret'] = 'changed'
        with patch.object(m, 'BEFORE', pins), self.assertRaisesRegex(RuntimeError, 'RETAINED_SELECTED_ROUTE_CHANGED'):
            m.compile_plan(data, A)

    def test_reject_unrecognized_schema_even_with_matching_hash(self):
        data, pins = fixture()
        row = data['list'][2]['value']
        row['plugins']['request-validation']['body_schema'] = {'type': 'object'}
        pins[row['uri']] = m.digest(row)
        with patch.object(m, 'BEFORE', pins), self.assertRaisesRegex(RuntimeError, 'SCHEMA_NOT_QUALIFIED_BASELINE'):
            m.compile_plan(data, A)

    def test_reject_colliding_prefix_route(self):
        data, pins = fixture()
        data['list'][-1]['value']['uri'] = m.DISCOVERY + '*'
        with patch.object(m, 'BEFORE', pins), self.assertRaisesRegex(RuntimeError, 'DISCOVERY_ROUTE_COLLISION'):
            m.compile_plan(data, A)

    def test_reject_cross_installation_semantic_binding(self):
        data, pins = fixture()
        row = data['list'][6]['value']
        constants = dict(zip(m.KEYS, ('OTHER_KEY', 'https://issuer.example.test/realms/fixture',
                                     'fixture-gateway', 'fixture-mcp', 'SEMANTIC_KEY')))
        row['plugins']['serverless-post-function']['functions'] = [m.function_source(A, 'old', 'execute_semantic_read', constants)]
        with patch.object(m, 'BEFORE', pins), self.assertRaisesRegex(RuntimeError, 'SAME_ESTABLISHED_IAM_BINDINGS'):
            m.compile_plan(data, A)

    def test_retained_stderr_is_classified_without_raw_values_or_guess(self):
        for raw, hint in ((b'ERROR: relation "ouf_sem.discovery_request" does not exist', 'MISSING_RELATION'),
                          (b'ERROR: permission denied for table secret_table', 'SQL_PERMISSION_DENIED'),
                          (b'FATAL: password authentication failed for user "private"', 'DATABASE_AUTHENTICATION_FAILED')):
            out = m.classify_error(raw)
            self.assertEqual(out['hints'], [hint])
            self.assertFalse(out['causeProven'])
            self.assertNotIn('secret_table', json.dumps(out))
            self.assertNotIn('"private"', json.dumps(out))
        self.assertEqual(m.classify_error(b'unrecognized error')['hints'], [])

    def test_main_creates_private_proposal_without_emitting_secrets(self):
        data, pins = fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inputs = root / 'retained'
            inputs.mkdir()
            (inputs / 'routes.private.json').write_text(json.dumps(data))
            (inputs / 'semantic-database.stderr.private').write_text('ERROR: permission denied for schema private_schema')
            output = io.StringIO()
            with patch.object(m, 'ROOT', root), patch.object(m, 'INPUT', inputs), patch.object(m, 'BEFORE', pins), \
                    patch.object(m, 'assets', return_value=A), patch.object(m.os, 'geteuid', return_value=0), redirect_stdout(output):
                m.main()
            result = json.loads(output.getvalue())
            self.assertEqual(result['status'], 'GATEWAY_DELTA_PREPARED_NOT_APPLIED')
            self.assertNotIn('DO_NOT_EMIT', output.getvalue())
            proposal = Path(result['privateEvidenceDirectory']) / 'proposal.private.json'
            self.assertEqual(proposal.stat().st_mode & 0o777, 0o600)
            self.assertEqual(proposal.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn('DO_NOT_EMIT', proposal.read_text())

    def test_generated_1024_and_1025_schema_with_real_validator(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema is installed by the dedicated CI')
        data, pins = fixture()
        with patch.object(m, 'BEFORE', pins):
            plan = m.compile_plan(data, A)
        create = next(c['desired'] for c in plan['changes'] if c['uri'] == m.PREFIX + 'create')
        fields = create['plugins']['request-validation']['body_schema']['properties']['Arguments']['properties']['fields']
        validator = jsonschema.Draft7Validator(fields)
        values = [{'fieldName': 'column_' + str(i), 'extractionDecision': 'INCLUDE', 'dataAccessLabel': 'OPEN'} for i in range(1024)]
        self.assertFalse(list(validator.iter_errors(values)))
        self.assertTrue(list(validator.iter_errors(values + [values[0]])))
        for change in plan['changes']:
            jsonschema.Draft7Validator.check_schema(change['desired']['plugins']['request-validation']['body_schema'])


if __name__ == '__main__':
    unittest.main()
