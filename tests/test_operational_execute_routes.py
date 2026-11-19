"""Synthetic credentials only; native and gateway checkout qualification are separate."""
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
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('operational_controller', ROOT / 'scripts/apply-operational-execute-routes-20261111.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
A = p.load_assets()
SECRETS = ('synthetic-oidc-secret-DO-NOT-PRINT', 'synthetic-issuer-private', 'SYNTHETIC_PRIVATE_KEY_REFERENCE',
           'SYNTHETIC_INGESTION_RECEIPT_REFERENCE', 'SYNTHETIC_GATEWAY_RECEIPT_REFERENCE')
CONSTANTS = {'DELEGATION_KEY_ENV': SECRETS[2], 'ISSUER': 'https://' + SECRETS[1] + '.example.test',
             'AUDIENCE': 'synthetic-private-audience', 'MCP_WORKLOAD': 'synthetic-private-workload',
             'INGESTION_RECEIPT_KEY_ENV': SECRETS[3], 'GATEWAY_RECEIPT_KEY_ENV': SECRETS[4]}
BINDINGS = {service: 'fixture-peer-' + str(i) for i, service in
            enumerate(sorted({c[1] for c in A.capabilities.values()}))}


def legacy_function():
    # Synthetic September profile: six constants and one function shared by
    # all summaries, selecting its producer by CapabilityID rather than OWNER.
    constants = '\n'.join('local ' + k + ' = ' + json.dumps(CONSTANTS[k]) for k in p.IAM_KEYS + p.RECEIPT_KEYS)
    owners = ',\n'.join('  [' + json.dumps(cap) + '] = ' + json.dumps(c[0])
                        for cap, c in A.capabilities.items() if cap.endswith('.summary'))
    return ('return function(conf, ctx)\n' + constants + '\n'
            'local cjson = require("cjson.safe")\n'
            'local producers = {\n' + owners + '\n}\n'
            'ngx.req.read_body()\n'
            'local envelope = cjson.decode(ngx.req.get_body_data() or "")\n'
            'if type(envelope) ~= "table" or not producers[envelope.CapabilityID] then\n'
            '  return ngx.exit(403)\nend\nend')


def fixture(foreign=85, installed_format='legacy-execute-summary'):
    rows = {'foreign-' + str(i): {'id': 'foreign-' + str(i), 'uri': '/foreign/' + str(i),
                                'methods': ['GET'], 'plugins': {'proxy-rewrite': {'headers': {'X-Fake': SECRETS[0]}}},
                                'upstream': {'type': 'roundrobin', 'nodes': {'fixture-old:8000': 1}}}
            for i in range(foreign)}
    for capability, c in A.capabilities.items():
        if not capability.endswith('.summary'):
            continue
        rid = 'execute-' + capability
        if installed_format == 'legacy-execute-summary':
            old_function = legacy_function()
        else:
            assert installed_format == 'current'
            old_function = p.function_source(A, capability, {k: CONSTANTS[k] for k in p.IAM_KEYS}).replace(
                "    ngx.req.set_header('X-OUF-Delegation-Verified', 'mcp-operational-aggregate-v1')\n", '')
        rows[rid] = {'id': rid, 'uri': p.PREFIX + capability, 'methods': ['POST'],
                     'labels': {'owner': c[0]}, 'name': 'synthetic-' + c[0], 'priority': 10,
                     'plugins': {
                         'openid-connect': {'client_id': 'fixture-client', 'client_secret': SECRETS[0],
                             'discovery': 'https://issuer.example.test/.well-known/openid-configuration',
                             'bearer_only': True, 'use_jwks': True, 'ssl_verify': True},
                         'limit-count': {'count': 60, 'time_window': 60, 'rejected_code': 429},
                         'serverless-pre-function': copy.deepcopy(A.pre),
                         'serverless-post-function': {'phase': 'access', 'functions': [old_function]},
                         'request-validation': {'max_req_body_size': 65536, 'body_schema': {'type': 'object'}},
                         'proxy-rewrite': {'uri': '/synthetic/old-owner'}},
                     'upstream': {'type': 'roundrobin', 'nodes': {'fixture-old-owner:8000': 1}, 'retries': 3}}
    return rows


def plan(rows=None):
    return p.compile_plan(fixture() if rows is None else rows, A, BINDINGS, {'synthetic': 'binding-observation'})


def report():
    return {'adminGetAttempts': 0, 'adminPutAttempts': 0, 'routeWritesVerified': 0, 'runtimeChanged': False,
            'adminCredentialConfigurationsRead': 0, 'externalAdminKeyFilesRead': 0}


class MemoryAdmin:
    def __init__(self, rows, work, counters, lose_ack=False):
        self.rows, self.work, self.counters = copy.deepcopy(rows), work, counters
        self.puts, self.lose_ack = 0, lose_ack
        self.apisix = {'synthetic': True}
        self.h = SimpleNamespace(frame=lambda d: d)

    def routes(self):
        self.counters['adminGetAttempts'] += 1
        return copy.deepcopy(self.rows)

    def put(self, rid, value):
        assert (self.work / f'{self.puts:02d}-intent.private.json').exists(), 'intent before dispatch'
        self.puts += 1
        self.rows[rid] = copy.deepcopy(value)
        if self.lose_ack:
            raise RuntimeError('ADMIN_RESPONSE_UNPROVEN')
        return {'httpStatus': 200, 'body': {'value': value}}

    def guard(self):
        pass

    def plan_frame(self):
        return copy.deepcopy(self.apisix)


class OperationalTests(unittest.TestCase):
    def test_legacy_shared_function_and_gateway_receipt_only(self):
        proposal = plan()
        self.assertEqual(proposal['installedFormat'], 'legacy-execute-summary')
        functions = {r['plugins']['serverless-post-function']['functions'][0]
                     for rid, r in proposal['before'].items() if rid.startswith('execute-')}
        self.assertEqual(functions, {legacy_function()})
        public = p.public_plan(proposal)
        self.assertEqual(public['installedFormat'], 'legacy-execute-summary')
        for change, visible in zip(proposal['changes'], public['changes']):
            cap = change['id'].removeprefix('execute-')
            fn = change['desired']['plugins']['serverless-post-function']['functions'][0]
            if A.capabilities[cap][0] == 'gateway':
                self.assertIn('local RECEIPT_KEY_ENV = ' + json.dumps(CONSTANTS['GATEWAY_RECEIPT_KEY_ENV']) + '\n', fn)
                self.assertIn("'X-OUF-Operational-Receipt'", fn)
                self.assertTrue(visible['producerReceipt'])
            else:
                self.assertNotIn('RECEIPT_KEY_ENV', fn)
                self.assertNotIn("'X-OUF-Operational-Receipt'", fn)
                self.assertNotIn('producerReceipt', visible)
            self.assertNotIn(CONSTANTS['INGESTION_RECEIPT_KEY_ENV'], fn)

    def test_current_header_is_recognized_but_missing_gateway_reference_is_held(self):
        rows = fixture(installed_format='current')
        for cap in A.capabilities:
            if cap.endswith('.summary'):
                self.assertEqual(p.installed_constants(rows['execute-' + cap], cap, A),
                                 ('current', {k: CONSTANTS[k] for k in p.IAM_KEYS}))
        with self.assertRaisesRegex(RuntimeError, '^INSTALLED_GATEWAY_RECEIPT_KEY_REFERENCE_REQUIRED$'):
            plan(rows)

    def test_current_operational_identity_check_is_unchanged(self):
        for key in p.OP_KEYS:
            rows = fixture(installed_format='current')
            route = next(r for k, r in rows.items() if k.startswith('execute-'))
            lines = route['plugins']['serverless-post-function']['functions'][0].split('\n')
            index = 1 + (p.IAM_KEYS + p.OP_KEYS).index(key)
            lines[index] = 'local ' + key + ' = "synthetic-wrong-identity"'
            route['plugins']['serverless-post-function']['functions'] = ['\n'.join(lines)]
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, '^INSTALLED_OPERATIONAL_CONSTANTS_DIVERGE$'):
                plan(rows)

    def test_only_two_closed_ordered_headers_are_accepted(self):
        for fmt, keys in (('current', p.IAM_KEYS + p.OP_KEYS),
                          ('legacy-execute-summary', p.IAM_KEYS + p.RECEIPT_KEYS)):
            base_rows = fixture(installed_format=fmt)
            rid = next(k for k in base_rows if k.startswith('execute-'))
            original = base_rows[rid]['plugins']['serverless-post-function']['functions'][0].split('\n')
            variants = []
            for index in range(1, len(keys) + 1):
                variants.append(('missing-' + str(index), original[:index] + original[index + 1:]))
                for value in ('null', '42', 'true', '{}', '[]', '""', '"x" -- Lua comment', '"x" "y"'):
                    lines = original.copy(); lines[index] = 'local ' + keys[index - 1] + ' = ' + value
                    variants.append(('value-' + str(index) + '-' + value, lines))
            for index in range(1, len(keys)):
                lines = original.copy(); lines[index], lines[index + 1] = lines[index + 1], lines[index]
                variants.append(('reordered-' + str(index), lines))
            for extra in ('EXTRA', 'RECEIPT_KEY_ENV', 'CAPABILITY', 'GATEWAY_RECEIPT_KEY_ENV'):
                variants.append(('extra-' + extra, original[:len(keys) + 1] +
                                 ['local ' + extra + ' = "SYNTHETIC_EXTRA"'] + original[len(keys) + 1:]))
            variants.append(('malformed-extra', original[:len(keys) + 1] +
                             ['local EXTRA'] + original[len(keys) + 1:]))
            lines = original.copy(); lines[0] += ' '
            variants.append(('nonexact-first-line', lines))
            lines = original.copy(); lines[5] = ('local CAPABILITY = "synthetic-hybrid"' if fmt != 'current'
                                                else 'local INGESTION_RECEIPT_KEY_ENV = "SYNTHETIC_HYBRID"')
            variants.append(('hybrid', lines))
            for name, lines in variants:
                rows = copy.deepcopy(base_rows)
                rows[rid]['plugins']['serverless-post-function']['functions'] = ['\n'.join(lines)]
                with self.subTest(format=fmt, mutation=name), self.assertRaisesRegex(
                        RuntimeError, '^(KNOWN_OWNER_HEADER_REQUIRED|KNOWN_OWNER_CONSTANTS_REQUIRED|CLOSED_OWNER_CONSTANT_REQUIRED)$'):
                    plan(rows)

    def test_key_references_are_valid_distinct_and_consistent(self):
        for key in ('DELEGATION_KEY_ENV',) + p.RECEIPT_KEYS:
            for invalid in ('lowercase', '_START', 'A-B', 'A' * 129, 'A\nB'):
                rows = fixture()
                route = next(r for k, r in rows.items() if k.startswith('execute-'))
                post = route['plugins']['serverless-post-function']
                post['functions'][0] = post['functions'][0].replace(json.dumps(CONSTANTS[key]), json.dumps(invalid))
                with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(RuntimeError, '^EXISTING_KEY_REFERENCE_REQUIRED$'):
                    plan(rows)
        for first, second in ((p.IAM_KEYS[0], p.RECEIPT_KEYS[0]), (p.IAM_KEYS[0], p.RECEIPT_KEYS[1]), p.RECEIPT_KEYS):
            rows = fixture()
            route = next(r for k, r in rows.items() if k.startswith('execute-'))
            post = route['plugins']['serverless-post-function']
            post['functions'][0] = post['functions'][0].replace(CONSTANTS[first], CONSTANTS[second])
            with self.assertRaisesRegex(RuntimeError, '^DISTINCT_INSTALLED_KEY_REFERENCES_REQUIRED$'):
                plan(rows)
        for key in p.RECEIPT_KEYS:
            rows = fixture()
            route = next(r for k, r in rows.items() if k.startswith('execute-'))
            post = route['plugins']['serverless-post-function']
            post['functions'][0] = post['functions'][0].replace(CONSTANTS[key], 'SYNTHETIC_DIVERGENT_REFERENCE')
            with self.assertRaisesRegex(RuntimeError, '^INSTALLED_RECEIPT_KEY_REFERENCES_DIVERGE$'):
                plan(rows)

    def test_mixed_installed_formats_are_held(self):
        rows = fixture()
        rid = next(k for k in rows if k.startswith('execute-'))
        rows[rid] = fixture(installed_format='current')[rid]
        with self.assertRaisesRegex(RuntimeError, '^INSTALLED_FORMATS_DIVERGE$'):
            plan(rows)

    def test_exact_delta_and_same_owner_cloning(self):
        proposal = plan()
        self.assertFalse(proposal['unsupportedDifferences'])
        self.assertEqual([c['operation'] for c in proposal['changes']], ['UPDATE'] * 3 + ['ADD'] * 3)
        for change in proposal['changes']:
            new = change['desired']
            cap = new['id'].removeprefix('execute-')
            source = proposal['before']['execute-' + cap.replace('.incidents', '.summary')]
            expected = copy.deepcopy(source)
            for path in p.CHANGED_FIELDS:
                target = expected
                parts = path.split('.')
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = copy.deepcopy(p.field(new, path))
            expected['id'], expected['uri'] = new['id'], new['uri']
            self.assertEqual(new, expected)
            self.assertEqual(new['plugins']['openid-connect'], source['plugins']['openid-connect'])
            self.assertEqual(new['plugins']['serverless-pre-function'], A.pre)
            self.assertEqual(new['plugins']['request-validation']['body_schema'], A.schema(cap))
            self.assertIn('operations.incident.read' if cap.endswith('.incidents') else 'operations.status.read',
                          new['plugins']['serverless-post-function']['functions'][0])

    def test_public_plan_contains_only_digests_for_private_fields(self):
        public = p.public_plan(plan())
        serialized = json.dumps(public)
        for secret in (*SECRETS, CONSTANTS['AUDIENCE'], CONSTANTS['MCP_WORKLOAD']):
            self.assertNotIn(secret, serialized)
        self.assertEqual((public['sourceRouteCount'], public['desiredRouteCount'], public['unchangedRoutes']), (88, 91, 85))
        self.assertTrue(all(c['aggregateMarkerPresent'] for c in public['changes']))
        self.assertEqual(public['planSha256'], p.digest(plan()))
        for change in public['changes'][:3]:
            self.assertEqual({f['field'] for f in change['changedFields']}, set(p.CHANGED_FIELDS))

    def test_bindings_exact_and_hash_bound(self):
        values = [k + '=' + v for k, v in BINDINGS.items()]
        self.assertEqual(p.parse_bindings(values, A), BINDINGS)
        for invalid in (values[:2], values + values[:1], values[:2] + ['unknown=fixture'],
                        [values[0], values[0], values[2]], [values[0].split('=')[0] + '=127.0.0.1', *values[1:]]):
            with self.assertRaises(RuntimeError):
                p.parse_bindings(invalid, A)
        changed = dict(BINDINGS); changed[next(iter(changed))] = 'another-fixture'
        self.assertNotEqual(p.digest(plan()), p.digest(p.compile_plan(fixture(), A, changed, {})))

    def test_divergent_iam_is_held(self):
        rows = fixture()
        route = next(r for k, r in rows.items() if k.startswith('execute-'))
        route['plugins']['serverless-post-function']['functions'][0] = route['plugins']['serverless-post-function']['functions'][0].replace(
            CONSTANTS['AUDIENCE'], 'divergent-fixture')
        with self.assertRaisesRegex(RuntimeError, 'INSTALLED_IAM_CONSTANTS_DIVERGE'):
            plan(rows)

    def test_id_and_uri_collisions_are_held(self):
        for key in ('id', 'uri', 'uris'):
            rows = fixture(); row = rows.pop('foreign-0')
            cap = next(c for c in A.capabilities if c.endswith('.incidents'))
            value = 'execute-' + cap if key == 'id' else p.PREFIX + cap
            row[key] = [value] if key == 'uris' else value
            rows[row['id']] = row
            with self.assertRaisesRegex(RuntimeError, 'INCIDENT_ROUTE_COLLISION'):
                plan(rows)

    def test_other_plugin_changes_require_review_and_are_redacted(self):
        for plugin in ('openid-connect', 'serverless-pre-function'):
            rows = fixture(); route = next(r for k, r in rows.items() if k.startswith('execute-'))
            if plugin == 'openid-connect':
                route['plugins'][plugin]['required_scopes'] = [SECRETS[0]]
            else:
                route['plugins'][plugin]['functions'] = [SECRETS[0]]
            proposal = plan(rows)
            self.assertEqual(len(proposal['unsupportedDifferences']), 1)
            self.assertNotIn(SECRETS[0], json.dumps(p.public_plan(proposal)))

    def test_scope_in_another_preserved_field_requires_review(self):
        rows = fixture(); route = next(r for k, r in rows.items() if k.startswith('execute-'))
        route['plugins']['proxy-rewrite']['headers'] = {'X-Fixture-Scope': 'operations.status.read'}
        proposal = plan(rows)
        self.assertEqual(proposal['unsupportedDifferences'][0]['field'], 'plugins.proxy-rewrite')
        with tempfile.TemporaryDirectory() as temp:
            counters = report(); admin = MemoryAdmin(rows, Path(temp), counters)
            with self.assertRaisesRegex(RuntimeError, 'SUMMARY_PLUGIN_REVIEW_REQUIRED'):
                p.publish(proposal, admin, Path(temp), counters, lambda: None)
            self.assertEqual(admin.puts, 0)

    def test_counts_follow_observed_source_routes(self):
        # Installed VPS shape: 84 foreign routes + 3 summary routes = 87.
        proposal = plan(fixture(84)); counters = report()
        public = p.public_plan(proposal)
        self.assertEqual((public['sourceRouteCount'], public['desiredRouteCount'], public['unchangedRoutes']), (87, 90, 84))
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = MemoryAdmin(proposal['before'], work, counters)
            p.publish(proposal, admin, work, counters, lambda: None)
            self.assertEqual(len(admin.rows), 90)
            self.assertEqual((counters['finalRouteCount'], counters['unchangedRoutesVerified']), (90, 84))
        with self.assertRaisesRegex(RuntimeError, 'EXACT_INSTALLED_SUMMARY_REQUIRED'):
            rows = fixture(5); rows.pop(next(k for k in rows if k.startswith('execute-')))
            plan(rows)
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_SOURCE_ROUTE_COUNT_REQUIRED'):
            plan(dict(list(fixture(0).items())[:2]))

    def test_six_writes_and_85_unchanged_with_private_journal(self):
        proposal = plan(); counters = report()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = MemoryAdmin(proposal['before'], work, counters)
            p.publish(proposal, admin, work, counters, lambda: None)
            self.assertEqual((admin.puts, counters['adminPutAttempts'], counters['routeWritesVerified']), (6, 6, 6))
            self.assertEqual(counters['adminGetAttempts'], 12)
            self.assertEqual(len(admin.rows), 91)
            for rid, row in proposal['before'].items():
                if rid.startswith('foreign-'):
                    self.assertEqual(admin.rows[rid], row)
            for kind in ('intent', 'ack', 'verified'):
                self.assertEqual(len(list(work.glob('*-' + kind + '.private.json'))), 6)
            self.assertTrue(all(f.stat().st_mode & 0o777 == 0o600 for f in work.iterdir()))

    def test_drift_before_write_and_between_writes(self):
        for after_first in (False, True):
            proposal = plan(); counters = report()
            with tempfile.TemporaryDirectory() as temp:
                work = Path(temp); admin = MemoryAdmin(proposal['before'], work, counters)
                if not after_first:
                    admin.rows['foreign-0']['status'] = 0
                def guard():
                    if after_first and admin.puts == 1:
                        admin.rows['foreign-0']['status'] = 0
                with self.assertRaisesRegex(RuntimeError, 'ROUTES_CHANGED_BEFORE_WRITE'):
                    p.publish(proposal, admin, work, counters, guard)
                self.assertEqual(admin.puts, int(after_first))

    def test_uncertain_write_has_null_runtime_changed_and_no_retry(self):
        proposal = plan(); counters = report()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = MemoryAdmin(proposal['before'], work, counters, lose_ack=True)
            with self.assertRaisesRegex(RuntimeError, 'ADMIN_RESPONSE_UNPROVEN'):
                p.publish(proposal, admin, work, counters, lambda: None)
            self.assertEqual(admin.puts, 1)
            self.assertIsNone(counters['runtimeChanged'])
            self.assertTrue((work / '00-intent.private.json').exists())

    def test_binding_guard_stops_before_write(self):
        proposal = plan(); counters = report()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = MemoryAdmin(proposal['before'], work, counters)
            with self.assertRaisesRegex(RuntimeError, 'SERVICE_BINDING_CHANGED'):
                p.publish(proposal, admin, work, counters, lambda: p.need(False, 'SERVICE_BINDING_CHANGED'))
            self.assertEqual(admin.puts, 0)

    def test_foreign_drift_in_readback_stops_after_one_put(self):
        proposal = plan(); counters = report()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = MemoryAdmin(proposal['before'], work, counters)
            original = admin.put
            def put(rid, desired):
                ack = original(rid, desired); admin.rows['foreign-0']['status'] = 0
                return ack
            admin.put = put
            with self.assertRaisesRegex(RuntimeError, 'ROUTE_WRITE_READBACK_MISMATCH'):
                p.publish(proposal, admin, work, counters, lambda: None)
            self.assertEqual(admin.puts, 1)
            self.assertIsNone(counters['runtimeChanged'])

    def test_existing_attempt_never_replays(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = p.begin_attempt(root, 'a' * 64)
            self.assertEqual(work.stat().st_mode & 0o777, 0o700)
            with self.assertRaisesRegex(RuntimeError, 'PREVIOUS_ATTEMPT_EXISTS_DO_NOT_REPLAY'):
                p.begin_attempt(root, 'a' * 64)

    def test_full_cli_fresh_hash_drift_and_json_redaction(self):
        # Exercise main's actual approval comparison, with all runtime I/O synthetic.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            args = SimpleNamespace(plan=True, apply=False, plan_sha256=None, evidence_root=root,
                service_binding=[k + '=' + v for k, v in BINDINGS.items()], docker_bin='fixture-docker',
                docker_socket='/fixture/socket', runtime_plan_sha256='c' * 64,
                apisix_config_target='/fixture/config', admin_key_file=Path('/fixture/key'))
            rows = fixture()
            def make_admin(_args, counters, _docker):
                return MemoryAdmin(rows, root / ('apply-' + str(args.plan_sha256)), counters)
            actual_lstat = Path.lstat
            def synthetic_root_owner(path, *pargs, **kwargs):
                info = actual_lstat(path, *pargs, **kwargs)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0) if path == root else info
            with patch.object(p, 'arguments', return_value=args), patch.object(p.os, 'geteuid', return_value=0), \
                    patch.object(p.sys, 'flags', SimpleNamespace(isolated=True)), \
                    patch.object(Path, 'lstat', synthetic_root_owner), \
                    patch.object(p, 'make_admin', side_effect=make_admin), \
                    patch.object(p, 'observe_bindings', return_value={'fixture': True}):
                def run():
                    output = io.StringIO()
                    with redirect_stdout(output):
                        p.main([])
                    result = json.loads(output.getvalue())
                    for secret in SECRETS:
                        self.assertNotIn(secret, output.getvalue())
                    return result
                rows = fixture(installed_format='current')
                held = run()
                self.assertEqual((held['status'], held['reason'], held['adminPutAttempts']),
                                 ('HELD', 'INSTALLED_GATEWAY_RECEIPT_KEY_REFERENCE_REQUIRED', 0))
                rows = fixture()
                post = next(r for k, r in rows.items() if k.startswith('execute-'))['plugins']['serverless-post-function']
                post['functions'][0] = post['functions'][0].replace('local ISSUER = ', 'local UNKNOWN = ')
                held = run()
                self.assertEqual((held['status'], held['reason'], held['adminPutAttempts']),
                                 ('HELD', 'KNOWN_OWNER_CONSTANTS_REQUIRED', 0))
                rows = fixture()
                first = run()
                self.assertEqual(first['status'], 'OPERATIONAL_ROUTES_PLANNED')
                with patch.object(p, 'observe_bindings', side_effect=RuntimeError('BINDING_UNRESOLVED_OR_AMBIGUOUS')):
                    held = run()
                self.assertEqual((held['status'], held['reason'], held['adminPutAttempts']),
                                 ('HELD', 'BINDING_UNRESOLVED_OR_AMBIGUOUS', 0))
                args.plan, args.apply = False, True
                args.plan_sha256 = '0' * 64
                result = run()
                self.assertEqual(result['reason'], 'FRESH_PLAN_HASH_MISMATCH')
                self.assertEqual(result['adminPutAttempts'], 0)
                args.plan_sha256 = first['planSha256']
                rows['foreign-0']['status'] = 0
                result = run()
                self.assertEqual(result['reason'], 'FRESH_PLAN_HASH_MISMATCH')
                self.assertEqual(result['adminPutAttempts'], 0)
                result = run()
                self.assertEqual(result['reason'], 'PREVIOUS_ATTEMPT_EXISTS_DO_NOT_REPLAY')
                self.assertEqual(result['adminGetAttempts'], 0)
                # Fresh approval of the changed map is a different, explicit
                # proposal; the original attempt remains untouched.
                args.plan, args.apply, args.plan_sha256 = True, False, None
                fresh = run()
                args.plan, args.apply, args.plan_sha256 = False, True, fresh['planSha256']
                result = run()
                self.assertEqual(result['status'], 'OPERATIONAL_ROUTES_APPLIED')
                self.assertEqual(result['adminPutAttempts'], 6)
                self.assertTrue(result['runtimeChanged'])

    def test_only_server_timestamps_excluded(self):
        row = {'id': 'fixture', 'create_time': 1, 'update_time': 2, 'large': 9007199254740991}
        self.assertEqual(p.body(row), {'id': 'fixture', 'large': 9007199254740991})

    def test_asset_tamper_is_held(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'assets.json'; path.write_bytes(p.ASSETS.read_bytes() + b' ')
            with self.assertRaisesRegex(RuntimeError, 'SOURCE_ASSET_HASH_MISMATCH'):
                p.load_assets(path)


class BindingTests(unittest.TestCase):
    def test_unresolved_ambiguous_stopped_or_unshared_peer_is_held(self):
        cid = 'b' * 64; network = 'c' * 64; address = '192.0.2.10'
        apisix = {'Id': 'a' * 64, 'State': {'Running': True},
                  'NetworkSettings': {'Networks': {'fixture': {'NetworkID': network}}}}
        peer = {'Id': cid, 'Image': 'fixture-image', 'State': {'Running': True, 'StartedAt': 'fixture'},
                'NetworkSettings': {'Networks': {'fixture': {'NetworkID': network, 'IPAddress': address}}}}
        class Docker:
            resolution = (address + ' fixture-peer\n').encode()
            def run(self, *args):
                if args[0] == 'network':
                    return json.dumps([{'Id': network, 'Containers': {cid: {}}}]).encode()
                return self.resolution
            def inspect(self, _cid):
                return peer
        docker = Docker()
        self.assertEqual(p.observe_bindings(docker, apisix, {'logical': 'fixture-peer'})['logical']['containerId'], cid)
        for raw in (b'', b'192.0.2.10 fixture\n192.0.2.11 fixture\n'):
            docker.resolution = raw
            with self.assertRaisesRegex(RuntimeError, 'BINDING_UNRESOLVED_OR_AMBIGUOUS'):
                p.observe_bindings(docker, apisix, {'logical': 'fixture-peer'})
        docker.resolution = (address + ' fixture\n').encode()
        peer['State']['Running'] = False
        with self.assertRaisesRegex(RuntimeError, 'BINDING_RUNNING_SHARED_PEER_UNPROVEN'):
            p.observe_bindings(docker, apisix, {'logical': 'fixture-peer'})
        peer['State']['Running'] = True
        peer['NetworkSettings']['Networks']['fixture']['NetworkID'] = 'd' * 64
        with self.assertRaisesRegex(RuntimeError, 'BINDING_RUNNING_SHARED_PEER_UNPROVEN'):
            p.observe_bindings(docker, apisix, {'logical': 'fixture-peer'})


@unittest.skipUnless(os.environ.get('OUF_OPERATIONAL_GATEWAY_SOURCE'), 'pinned gateway checkout required in CI')
class GatewayEquivalence(unittest.TestCase):
    def test_byte_identical_assets_and_actual_materializer(self):
        gateway = Path(os.environ['OUF_OPERATIONAL_GATEWAY_SOURCE']).resolve()
        for path, record in A.files.items():
            self.assertEqual((gateway / path).read_bytes(), record['content'].encode(), path)
        sys.path.insert(0, str(gateway))
        self.addCleanup(lambda: sys.path.remove(str(gateway)))
        m = importlib.import_module('tools.materialize_operational_execute')
        installation = dict(issuerUrl=CONSTANTS['ISSUER'], gatewayAudience=CONSTANTS['AUDIENCE'],
                            mcpServiceIdentity=CONSTANTS['MCP_WORKLOAD'], serviceBindings=BINDINGS,
                            publicApiBaseUrl='https://api.example.test', installationId='fixture',
                            revision=1, checksum='synthetic-checksum')
        bindings = []
        for cap, (owner, service, port, path, scope, seconds) in m.CAPABILITIES.items():
            bindings.append({'labels': {'exposure': 'internal'}, 'service_id': service,
                'x-ouf-backend-binding': {'service': BINDINGS[service]},
                'plugins': {'proxy-rewrite': {'uri': path}},
                'x-ouf-capability': {'capabilityId': cap, 'owner': owner, 'operationType': 'READ',
                                     'humanRequired': False, 'toolEligible': owner == 'mcp'},
                'x-ouf-policy': {'identity': 'M2M', 'allowedServiceIdentities': [CONSTANTS['MCP_WORKLOAD']],
                    'allowedActorTypes': ['HUMAN_USER', 'MCP_SERVER'] if owner == 'mcp' else ['MCP_SERVER'],
                    'requiredScope': scope, 'maxRequestBytes': 65536, 'timeoutSeconds': seconds}})
        bindings.extend([
            {'id': 'fixture-ingress', 'uri': '/mcp', 'methods': ['POST'], 'labels': {'exposure': 'public'},
             'x-ouf-protocol': {'name': 'MCP'},
             'x-ouf-policy': {'identity': 'OIDC', 'requiredAudience': CONSTANTS['AUDIENCE'],
                             'requiredScope': 'operations.status.read', 'allowedActorTypes': ['HUMAN']},
             'x-ouf-trusted-identity': {'stripClientHeaders': ['X-OUF-Delegation'],
                                      'injectAfterVerification': {'X-OUF-Gateway-Verified': 'true'}},
             'x-ouf-backend-binding': {'service': BINDINGS['ouf-mcp-server'], 'port': 8080, 'path': '/mcp'},
             'plugins': {'limit-count': {'count': 60, 'time_window': 60, 'rejected_code': 429}}},
            {'id': 'fixture-execute', 'uri': '/internal/capabilities/v1/execute', 'methods': ['POST'],
             'x-ouf-policy': {'identity': 'M2M'},
             'x-ouf-mediation': {'serviceIdentity': CONSTANTS['MCP_WORKLOAD']}},
            {'id': 'fixture-status', 'labels': {'exposure': 'internal'}, 'service_id': 'ouf-mcp-server',
             'x-ouf-capability': {'capabilityId': 'ouf.system.status', 'owner': 'mcp', 'operationType': 'READ',
                                  'humanRequired': False, 'toolEligible': True},
             'x-ouf-policy': {'identity': 'M2M', 'allowedServiceIdentities': [CONSTANTS['MCP_WORKLOAD']],
                             'requiredScope': 'operations.status.read', 'allowedActorTypes': ['HUMAN'],
                             'maxRequestBytes': 65536, 'timeoutSeconds': 3},
             'plugins': {'proxy-rewrite': {'uri': '/api/internal/v1/mcp/operations/status'}}},
        ])
        # Exercise the complete gateway materializer, including ingress/status
        # construction. No gateway function or source read is mocked.
        for receipt_keys in (None, {'gateway': CONSTANTS['GATEWAY_RECEIPT_KEY_ENV']}):
            with self.subTest(producerReceipt=receipt_keys is not None):
                kwargs = {} if receipt_keys is None else {'producer_receipt_key_envs': receipt_keys}
                materialized = m.materialize({'x-ouf-installation': installation, 'routes': bindings},
                                            '$ENV://SYNTHETIC_OIDC', CONSTANTS['DELEGATION_KEY_ENV'], **kwargs)
                actual = {r['uri']: r for r in materialized['routes']}
                for change in plan()['changes']:
                    expected = copy.deepcopy(change['desired']); route = actual[expected['uri']]
                    if receipt_keys is None:
                        # Renderer compatibility only: a no-receipt installation
                        # is recognized but cannot be admitted by compile_plan.
                        cap = expected['id'].removeprefix('execute-')
                        expected['plugins']['serverless-post-function']['functions'] = [
                            p.function_source(A, cap, {k: CONSTANTS[k] for k in p.IAM_KEYS})]
                    for path in p.CHANGED_FIELDS:
                        self.assertEqual(p.field(expected, path), p.field(route, path), (expected['uri'], path))


if __name__ == '__main__':
    unittest.main()
