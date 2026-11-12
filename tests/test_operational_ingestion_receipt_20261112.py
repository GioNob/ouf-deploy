"""Synthetic inputs only. Linux file/transport guarantees are required in CI."""
from contextlib import ExitStack, redirect_stdout
import copy
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


q = module('ingestion_receipt', ROOT / 'scripts/apply-operational-ingestion-receipt-20261112.py')
# Windows can exercise pure planning with synthetic files. This does not qualify
# O_NOFOLLOW, directory descriptors, ownership or namespace transport on Windows.
with ExitStack() as bootstrap:
    if os.name == 'nt':
        for flag in ('O_NOFOLLOW', 'O_NONBLOCK'):
            bootstrap.enter_context(patch.object(os, flag, 0, create=True))
    c = q.load_controller()
    old = module('existing_operational_fixture', ROOT / 'tests/test_operational_execute_routes.py')
A, BINDINGS = old.A, old.BINDINGS
NAME = 'SYNTHETIC_NEW_INGESTION_RECEIPT'
ENV_VALUE = 'synthetic-env-value-MUST-NOT-BE-SAVED'


def applied_plan():
    result = old.plan(old.fixture(84))
    result['runtimeBinding'] = {'synthetic': 'previous-transport'}
    return result


def fixture():
    applied = applied_plan()
    return q.expected_map(c, applied, A), applied


def apisix():
    return {'Id': 'a' * 64, 'State': {'Running': True},
            'Config': {'Env': [NAME + '=' + ENV_VALUE, 'PATH=/synthetic/bin']}}


def plan(rows=None, applied=None, name=NAME, doc=None):
    initial, retained = fixture()
    applied = retained if applied is None else applied
    return q.compile_plan(c, initial if rows is None else rows, applied, c.digest(applied), A,
                          BINDINGS, {'synthetic': 'current-binding'}, name, apisix() if doc is None else doc)


def retain(root, applied=None):
    applied = applied_plan() if applied is None else applied
    sha = c.digest(applied)
    work = c.begin_attempt(root, sha)
    c.private(work, 'plan.private.json', applied)
    return work / 'plan.private.json', sha


class SyntheticTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        if os.name == 'nt':
            for flag in ('O_NOFOLLOW', 'O_NONBLOCK'):
                self.stack.enter_context(patch.object(os, flag, 0, create=True))
            self.stack.enter_context(patch.object(c, 'fsync_dir'))

    def test_two_updates_only_post_functions_and_all_other_routes_identical(self):
        proposal = plan()
        rows = copy.deepcopy(proposal['before'])
        self.assertEqual(len(rows), 90)
        self.assertEqual([ch['id'] for ch in proposal['changes']], list(q.TARGETS))
        for ch in proposal['changes']:
            self.assertEqual(ch['operation'], 'UPDATE')
            expected = copy.deepcopy(rows[ch['id']])
            fn = c.field(ch['desired'], 'plugins.serverless-post-function.functions')
            expected['plugins']['serverless-post-function']['functions'] = fn
            self.assertEqual(ch['desired'], expected)
            self.assertNotEqual(ch['before'], ch['desired'])
            self.assertIn('local RECEIPT_KEY_ENV = ' + json.dumps(NAME) + '\n', fn[0])
            self.assertIn("'X-OUF-Operational-Receipt'", fn[0])
            rows[ch['id']] = ch['desired']
        self.assertEqual(len(rows), 90)
        self.assertEqual(sum(rows[rid] == row for rid, row in proposal['before'].items()), 88)
        self.assertEqual(c.digest(rows), c.digest({**proposal['before'], **{
            ch['id']: ch['desired'] for ch in proposal['changes']}}))

    def test_counts_are_observed_and_only_server_timestamps_are_excluded(self):
        for foreign in (0, 5, 84):
            retained = old.plan(old.fixture(foreign))
            retained['runtimeBinding'] = {'synthetic': 'previous-transport'}
            expected = q.expected_map(c, retained, A)
            listing = {'total': len(expected), 'list': [
                {'value': {**row, 'create_time': 100, 'update_time': 200}} for row in expected.values()]}
            proposal = plan(rows=c.route_map(listing), applied=retained)
            public = q.public_plan(c, proposal)
            self.assertEqual((public['sourceRouteCount'], public['desiredRouteCount'], public['unchangedRoutes']),
                             (foreign + 6, foreign + 6, foreign + 4))

    def test_whole_current_map_must_match_including_foreign_route(self):
        original, _ = fixture()
        for rid in original:
            for field in ('id', 'uri', 'plugins', 'upstream', 'schema', 'labels'):
                rows = copy.deepcopy(original)
                rows[rid][field] = {'synthetic': 'divergence'}
                with self.subTest(rid=rid, field=field), self.assertRaisesRegex(
                        RuntimeError, 'CURRENT_MAP_DIFFERS_FROM_APPLIED_PLAN'):
                    plan(rows)
        for mutation in ('add', 'delete'):
            rows = copy.deepcopy(original)
            if mutation == 'add':
                rows['additional'] = {'id': 'additional', 'uri': '/additional'}
            else:
                del rows['foreign-0']
            with self.assertRaisesRegex(RuntimeError, 'CURRENT_MAP_DIFFERS_FROM_APPLIED_PLAN'):
                plan(rows)

    def test_gateway_without_receipt_or_different_references_is_held(self):
        rows, _ = fixture()
        gateways = [rid for rid in rows if rid.startswith('execute-ouf.gateway.')]
        for rid in gateways:
            for replacement in ('missing', 'different'):
                changed = copy.deepcopy(rows)
                fn = changed[rid]['plugins']['serverless-post-function']['functions'][0]
                if replacement == 'missing':
                    cap = rid.removeprefix('execute-')
                    fn = c.function_source(A, cap, {k: old.CONSTANTS[k] for k in c.IAM_KEYS})
                else:
                    fn = fn.replace(old.CONSTANTS['GATEWAY_RECEIPT_KEY_ENV'], 'SYNTHETIC_DIFFERENT_GATEWAY_KEY')
                changed[rid]['plugins']['serverless-post-function']['functions'] = [fn]
                with self.subTest(rid=rid, mutation=replacement), self.assertRaisesRegex(
                        RuntimeError, 'CURRENT_MAP_DIFFERS_FROM_APPLIED_PLAN'):
                    plan(changed)

    def test_retained_plan_itself_must_be_pinned_controller_output(self):
        for field in ('uri', 'upstream', 'plugins'):
            applied = applied_plan()
            applied['changes'][0]['desired'][field] = {'synthetic': 'wrong'}
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PROFILE_DIVERGENT'):
                plan(applied=applied)
        applied = applied_plan()
        applied['changes'][0]['desired']['plugins']['serverless-post-function']['functions'][0] += '\n'
        with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PROFILE_DIVERGENT'):
            plan(applied=applied)

    def test_already_signed_ingestion_is_never_replayed(self):
        for ch in plan()['changes']:
            rows, _ = fixture()
            rows[ch['id']] = ch['desired']
            with self.assertRaisesRegex(RuntimeError, '^ALREADY_APPLIED_OR_DIVERGENT$'):
                plan(rows)

    def test_key_name_valid_distinct_and_exposed(self):
        for name in ('lower', '_START', 'A-B', 'A' * 129, 'A\nB', ''):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'INVALID_INGESTION_RECEIPT_KEY_ENV'):
                plan(name=name)
        for name in (old.CONSTANTS['DELEGATION_KEY_ENV'], old.CONSTANTS['GATEWAY_RECEIPT_KEY_ENV']):
            with self.assertRaisesRegex(RuntimeError, 'DISTINCT_RECEIPT_KEY_REFERENCES_REQUIRED'):
                plan(name=name)
        for doc in ({**apisix(), 'Config': {'Env': []}},
                    {**apisix(), 'Config': {'Env': ['OTHER=' + NAME]}},
                    {**apisix(), 'Config': {'Env': [NAME + '_OTHER=value']}}):
            with self.assertRaisesRegex(RuntimeError, 'INGESTION_RECEIPT_KEY_NOT_EXPOSED_TO_APISIX'):
                plan(doc=doc)
        for name in ('A', 'A' * 128):
            self.assertTrue(plan(name=name, doc={**apisix(), 'Config': {'Env': [name + '=synthetic']}}))

    def test_env_observation_cannot_save_values_and_bad_inspect_is_held(self):
        proposal = plan()
        self.assertNotIn(ENV_VALUE, json.dumps(proposal))
        observation = proposal['environmentObservation']
        self.assertEqual(observation['ingestionReceiptKeyEnvSha256'], c.digest(NAME))
        self.assertTrue(observation['exposedToApisix'])
        for entries in (None, 'string', [NAME], [NAME + '=1', NAME + '=2'], ['=value']):
            with self.subTest(entries=entries), self.assertRaisesRegex(RuntimeError, 'APISIX_ENV_NAMES_UNPROVEN'):
                plan(doc={**apisix(), 'Config': {'Env': entries}})
        with self.assertRaisesRegex(RuntimeError, 'APISIX_RUNNING_REQUIRED'):
            plan(doc={**apisix(), 'State': {'Running': False}})

    def test_public_plan_contains_only_digests_of_private_fields(self):
        proposal = plan()
        public = q.public_plan(c, proposal)
        serialized = json.dumps(public)
        for secret in (*old.SECRETS, *old.CONSTANTS.values(), *BINDINGS.values(), NAME, ENV_VALUE):
            self.assertNotIn(secret, serialized)
        self.assertEqual((public['sourceRouteCount'], public['desiredRouteCount'], public['unchangedRoutes']), (90, 90, 88))
        self.assertEqual(public['planSha256'], c.digest(proposal))
        self.assertTrue(public['currentMapMatchesAppliedPlan'])
        for ch, visible in zip(proposal['changes'], public['changes']):
            self.assertFalse(visible['producerReceiptBefore'])
            self.assertTrue(visible['producerReceiptAfter'])
            self.assertEqual((visible['beforeSha256'], visible['afterSha256']),
                             (c.digest(ch['before']), c.digest(ch['desired'])))

    def test_two_puts_with_exclusive_intents_and_full_readback(self):
        proposal = plan(); counters = old.report()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = old.MemoryAdmin(proposal['before'], work, counters)
            guard = unittest.mock.Mock()
            q.publish(c, proposal, admin, work, counters, guard)
            self.assertEqual((admin.puts, counters['routeWritesVerified'], counters['unchangedRoutesVerified']), (2, 2, 88))
            self.assertEqual(guard.call_count, 2)
            self.assertEqual(counters['adminGetAttempts'], 4)
            self.assertTrue(counters['runtimeChanged'])
            self.assertEqual(len(list(work.glob('*-ack.private.json'))), 2)
            for rid, row in proposal['before'].items():
                if rid not in q.TARGETS:
                    self.assertEqual(admin.rows[rid], row)

    def test_uncertain_first_or_second_write_is_null_without_retry(self):
        for failed in (1, 2):
            proposal = plan(); counters = old.report()
            with tempfile.TemporaryDirectory() as temp:
                admin = old.MemoryAdmin(proposal['before'], Path(temp), counters)
                put = admin.put
                def uncertain(rid, value):
                    result = put(rid, value)
                    if admin.puts == failed:
                        raise RuntimeError('ADMIN_RESPONSE_UNPROVEN')
                    return result
                with patch.object(admin, 'put', side_effect=uncertain), self.assertRaisesRegex(
                        RuntimeError, 'ADMIN_RESPONSE_UNPROVEN'):
                    q.publish(c, proposal, admin, Path(temp), counters, lambda: None)
                self.assertEqual(admin.puts, failed)
                self.assertEqual(counters['routeWritesVerified'], failed - 1)
                self.assertIsNone(counters['runtimeChanged'])

    def test_foreign_map_drift_before_each_write_and_during_readback(self):
        for when in (1, 2, 3, 4):
            proposal = plan(); counters = old.report()
            with tempfile.TemporaryDirectory() as temp:
                admin = old.MemoryAdmin(proposal['before'], Path(temp), counters)
                routes = admin.routes
                def drift():
                    if counters['adminGetAttempts'] + 1 == when:
                        admin.rows['foreign-0']['name'] = 'concurrent-change'
                    return routes()
                with patch.object(admin, 'routes', side_effect=drift), self.assertRaisesRegex(
                        RuntimeError, 'ROUTES_CHANGED_BEFORE_WRITE|ROUTE_WRITE_READBACK_MISMATCH'):
                    q.publish(c, proposal, admin, Path(temp), counters, lambda: None)
                self.assertEqual(admin.puts, when // 2)
                self.assertEqual(counters['runtimeChanged'], None if when % 2 == 0 else when > 1)

    def test_publisher_rejects_any_other_delta_before_writes(self):
        proposal = plan()
        proposal['changes'][0]['desired']['name'] = 'unexpected'
        with tempfile.TemporaryDirectory() as temp:
            admin = old.MemoryAdmin(proposal['before'], Path(temp), old.report())
            with self.assertRaisesRegex(RuntimeError, 'ONLY_POST_FUNCTION_DELTA_REQUIRED'):
                q.publish(c, proposal, admin, Path(temp), old.report(), lambda: None)
            self.assertEqual(admin.puts, 0)

    def test_main_plan_hash_mismatch_and_replay_write_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = ['--runtime-plan', str(root / 'runtime'), '--runtime-plan-sha256', 'a' * 64,
                    '--evidence-root', str(root), '--admin-key-file', str(root / 'key'),
                    '--docker-bin', '/synthetic/docker', '--docker-socket', '/synthetic/socket',
                    '--apisix-config-target', '/synthetic/config', '--applied-plan', str(root / 'retained'),
                    '--applied-plan-sha256', c.digest(applied_plan()), '--ingestion-receipt-key-env', NAME]
            for service, host in BINDINGS.items():
                args.extend(['--service-binding', service + '=' + host])
            admins = []
            def make_admin(_args, counters, _docker):
                work = root / ('apply-' + (_args.plan_sha256 or 'unused'))
                admin = old.MemoryAdmin(fixture()[0], work, counters)
                admin.apisix = apisix()
                admins.append(admin)
                return admin
            with ExitStack() as stack:
                stack.enter_context(patch.object(q, 'load_controller', return_value=c))
                stack.enter_context(patch.object(q, 'private_directory'))
                stack.enter_context(patch.object(q, 'read_applied_plan', return_value=applied_plan()))
                stack.enter_context(patch.object(os, 'geteuid', return_value=0, create=True))
                stack.enter_context(patch.object(c, 'make_admin', side_effect=make_admin))
                stack.enter_context(patch.object(c, 'observe_bindings', return_value={'synthetic': 'current-binding'}))
                docker = stack.enter_context(patch.object(c, 'Docker'))
                docker.return_value.inspect.return_value = apisix()
                def run(*mode):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = q.main(args + list(mode))
                    public = json.loads(output.getvalue())
                    for value in (*old.SECRETS, NAME, ENV_VALUE):
                        self.assertNotIn(value, output.getvalue())
                    return code, public
                code, public = run('--plan')
                self.assertEqual((code, public['reason'], public['adminPutAttempts']), (0, 'HUMAN_HASH_APPROVAL_REQUIRED', 0))
                wrong = '0' * 64
                code, held = run('--apply', '--plan-sha256', wrong)
                self.assertEqual((code, held['reason'], held['adminPutAttempts']), (1, 'FRESH_PLAN_HASH_MISMATCH', 0))
                count = len(admins)
                code, held = run('--apply', '--plan-sha256', wrong)
                self.assertEqual((code, held['reason'], held['adminPutAttempts']),
                                 (1, 'PREVIOUS_ATTEMPT_EXISTS_DO_NOT_REPLAY', 0))
                self.assertEqual(len(admins), count)
                code, done = run('--apply', '--plan-sha256', public['planSha256'])
                self.assertEqual((code, done['routeWritesVerified'], done['unchangedRoutesVerified']), (0, 2, 88))
                self.assertTrue(done['runtimeChanged'])

    def test_controller_hash_is_checked_before_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'scripts').mkdir()
            (root / 'scripts/apply-operational-execute-routes-20261111.py').write_bytes(b'raise Exception("DO_NOT_EXECUTE")\n')
            with patch.object(q, 'ROOT', root), self.assertRaisesRegex(RuntimeError, '^CONTROLLER_HASH_MISMATCH$'):
                q.load_controller()


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'requires Linux root: mandatory without skips in CI')
class AppliedFileTests(unittest.TestCase):
    def assert_main_held(self, path, root, sha, reason):
        args = ['--plan', '--applied-plan', str(path), '--applied-plan-sha256', sha,
                '--ingestion-receipt-key-env', NAME, '--runtime-plan', str(root / 'unused-runtime'),
                '--runtime-plan-sha256', 'a' * 64, '--evidence-root', str(root),
                '--admin-key-file', str(root / 'unused-key'), '--docker-bin', '/synthetic/docker',
                '--docker-socket', '/synthetic/socket', '--apisix-config-target', '/synthetic/config']
        for service, host in BINDINGS.items():
            args.extend(['--service-binding', service + '=' + host])
        output = io.StringIO()
        with patch.object(q, 'load_controller', return_value=c), patch.object(c, 'make_admin') as admin, redirect_stdout(output):
            code = q.main(args)
        public = json.loads(output.getvalue())
        self.assertEqual((code, public['status'], public['reason'], public['adminPutAttempts']), (1, 'HELD', reason, 0))
        self.assertFalse(public['runtimeChanged'])
        admin.assert_not_called()
        for secret in (*old.SECRETS, NAME, ENV_VALUE):
            self.assertNotIn(secret, output.getvalue())

    def test_secure_read_and_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            path, sha = retain(root)
            self.assertEqual(q.read_applied_plan(c, path, root, sha), applied_plan())
            # Digest failure with a correctly named directory, not just bad path.
            value = applied_plan(); value['runtimeBinding']['synthetic'] = 'changed'
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_HASH_MISMATCH'):
                q.read_applied_plan(c, path, root, sha)
            self.assert_main_held(path, root, sha, 'APPLIED_PLAN_HASH_MISMATCH')

    def test_outside_wrong_parent_and_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            path, sha = retain(root)
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_OUTSIDE_EVIDENCE_ROOT'):
                q.read_applied_plan(c, path, root / 'other', sha)
            other_root = root / 'other'; other_root.mkdir(mode=0o700)
            self.assert_main_held(path, other_root, sha, 'APPLIED_PLAN_OUTSIDE_EVIDENCE_ROOT')
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_DIRECTORY_HASH_MISMATCH'):
                q.read_applied_plan(c, path, root, '0' * 64)
            for mode in (0o644, 0o400, 0o666):
                path.chmod(mode)
                with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PRIVATE_FILE_REQUIRED'):
                    q.read_applied_plan(c, path, root, sha)
                self.assert_main_held(path, root, sha, 'APPLIED_PLAN_PRIVATE_FILE_REQUIRED')
            path.chmod(0o600)
            path.parent.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PRIVATE_DIRECTORY_REQUIRED'):
                q.read_applied_plan(c, path, root, sha)
            self.assert_main_held(path, root, sha, 'APPLIED_PLAN_PRIVATE_DIRECTORY_REQUIRED')
            path.parent.chmod(0o700)
            os.chown(path, 65534, 65534)
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PRIVATE_FILE_REQUIRED'):
                q.read_applied_plan(c, path, root, sha)
            os.chown(path, 0, 0)
            os.chown(path.parent, 65534, 65534)
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PRIVATE_DIRECTORY_REQUIRED'):
                q.read_applied_plan(c, path, root, sha)
            os.chown(path.parent, 0, 0)

    def test_symlink_file_and_directory_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            path, sha = retain(root)
            target = root / 'retained'; path.rename(target); path.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, 'APPLIED_PLAN_PRIVATE_FILE_REQUIRED'):
                q.read_applied_plan(c, path, root, sha)
            path.unlink(); target.rename(path)
            real_dir = root / 'real'; path.parent.rename(real_dir); path.parent.symlink_to(real_dir, target_is_directory=True)
            with self.assertRaises(OSError):
                q.read_applied_plan(c, path, root, sha)

    def test_secure_reader_rejects_duplicate_keys_and_changed_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            path, sha = retain(root)
            path.write_text('{"duplicate":1,"duplicate":2}')
            with self.assertRaisesRegex(RuntimeError, 'DUPLICATE_JSON_KEY'):
                q.read_applied_plan(c, path, root, sha)
            path.write_text(json.dumps(applied_plan()))
            read = c.read
            def changed(pinned):
                value = read(pinned)
                path.chmod(0o644)
                return value
            with patch.object(c, 'read', side_effect=changed), self.assertRaisesRegex(
                    RuntimeError, 'APPLIED_PLAN_CHANGED_DURING_READ'):
                q.read_applied_plan(c, path, root, sha)


@unittest.skipUnless(os.environ.get('OUF_OPERATIONAL_GATEWAY_SOURCE'), 'pinned gateway checkout required in CI')
class GatewayEquivalence(unittest.TestCase):
    def test_actual_materializer_with_gateway_and_ingestion_receipt_map(self):
        gateway = Path(os.environ['OUF_OPERATIONAL_GATEWAY_SOURCE']).resolve()
        for path, record in A.files.items():
            self.assertEqual((gateway / path).read_bytes(), record['content'].encode(), path)
        sys.path.insert(0, str(gateway))
        self.addCleanup(lambda: sys.path.remove(str(gateway)))
        m = importlib.import_module('tools.materialize_operational_execute')
        installation = dict(issuerUrl=old.CONSTANTS['ISSUER'], gatewayAudience=old.CONSTANTS['AUDIENCE'],
                            mcpServiceIdentity=old.CONSTANTS['MCP_WORKLOAD'], serviceBindings=BINDINGS,
                            publicApiBaseUrl='https://api.example.test', installationId='fixture',
                            revision=1, checksum='synthetic-checksum')
        bindings = []
        for cap, (owner, service, port, path, scope, seconds) in m.CAPABILITIES.items():
            bindings.append({'labels': {'exposure': 'internal'}, 'service_id': service,
                'x-ouf-backend-binding': {'service': BINDINGS[service]},
                'plugins': {'proxy-rewrite': {'uri': path}},
                'x-ouf-capability': {'capabilityId': cap, 'owner': owner, 'operationType': 'READ',
                                     'humanRequired': False, 'toolEligible': owner == 'mcp'},
                'x-ouf-policy': {'identity': 'M2M', 'allowedServiceIdentities': [old.CONSTANTS['MCP_WORKLOAD']],
                    'allowedActorTypes': ['HUMAN_USER', 'MCP_SERVER'] if owner == 'mcp' else ['MCP_SERVER'],
                    'requiredScope': scope, 'maxRequestBytes': 65536, 'timeoutSeconds': seconds}})
        bindings.extend([
            {'id': 'fixture-ingress', 'uri': '/mcp', 'methods': ['POST'], 'labels': {'exposure': 'public'},
             'x-ouf-protocol': {'name': 'MCP'},
             'x-ouf-policy': {'identity': 'OIDC', 'requiredAudience': old.CONSTANTS['AUDIENCE'],
                             'requiredScope': 'operations.status.read', 'allowedActorTypes': ['HUMAN']},
             'x-ouf-trusted-identity': {'stripClientHeaders': ['X-OUF-Delegation'],
                                      'injectAfterVerification': {'X-OUF-Gateway-Verified': 'true'}},
             'x-ouf-backend-binding': {'service': BINDINGS['ouf-mcp-server'], 'port': 8080, 'path': '/mcp'},
             'plugins': {'limit-count': {'count': 60, 'time_window': 60, 'rejected_code': 429}}},
            {'id': 'fixture-execute', 'uri': '/internal/capabilities/v1/execute', 'methods': ['POST'],
             'x-ouf-policy': {'identity': 'M2M'},
             'x-ouf-mediation': {'serviceIdentity': old.CONSTANTS['MCP_WORKLOAD']}},
            {'id': 'fixture-status', 'labels': {'exposure': 'internal'}, 'service_id': 'ouf-mcp-server',
             'x-ouf-capability': {'capabilityId': 'ouf.system.status', 'owner': 'mcp', 'operationType': 'READ',
                                  'humanRequired': False, 'toolEligible': True},
             'x-ouf-policy': {'identity': 'M2M', 'allowedServiceIdentities': [old.CONSTANTS['MCP_WORKLOAD']],
                             'requiredScope': 'operations.status.read', 'allowedActorTypes': ['HUMAN'],
                             'maxRequestBytes': 65536, 'timeoutSeconds': 3},
             'plugins': {'proxy-rewrite': {'uri': '/api/internal/v1/mcp/operations/status'}}},
        ])
        materialized = m.materialize({'x-ouf-installation': installation, 'routes': bindings},
            '$ENV://SYNTHETIC_OIDC', old.CONSTANTS['DELEGATION_KEY_ENV'],
            producer_receipt_key_envs={'gateway': old.CONSTANTS['GATEWAY_RECEIPT_KEY_ENV'], 'ingestion': NAME})
        actual = {r['uri']: r for r in materialized['routes']}
        proposal = plan()
        expected = {**proposal['before'], **{ch['id']: ch['desired'] for ch in proposal['changes']}}
        for cap in A.capabilities:
            rid = 'execute-' + cap
            for path in c.CHANGED_FIELDS:
                self.assertEqual(c.field(expected[rid], path), c.field(actual[expected[rid]['uri']], path), (rid, path))


if __name__ == '__main__':
    unittest.main()
