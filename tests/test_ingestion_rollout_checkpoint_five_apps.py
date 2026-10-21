"""Real file/socket boundaries and full closed diagnostic with retained receipt."""
import base64
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('checkpoint', ROOT / 'scripts/read-ingestion-rollout-checkpoint-five-apps-20261020.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def application(name):
    return {'Id': hashlib.sha256(name.encode()).hexdigest(), 'Image': 'sha256:' + 'f' * 64,
            'State': {'Running': True, 'Pid': 123, 'StartedAt': 'start'},
            'Config': {'Env': ['PRIVATE=NEVER_PRINT_ME']}, 'HostConfig': {}, 'Mounts': [], 'NetworkSettings': {}}


class FullDiagnostic(unittest.TestCase):
    def setUp(self):
        self.result = json.loads((ROOT / 'evidence/ingestion-owner7-projection-published-target-20261019.json').read_text())
        self.context, self.owner = m.CONTEXT, m.OWNER
        self.apps = {n: application(n) for n in ('onboarding', 'mcp', 'udp', 'ingestion', 'gateway')}
        self.login_review = {'schema': 'ouf.human-ingestion-owner-recovery-budget-review.v7',
                             'priorOAuthAttempts': 272, 'maximumCumulativeOAuthAttempts': 288,
                             'newWindowSeconds': 7200, 'budgetReset': False}
        self.login_decision = {'schema': 'ouf.human-ingestion-owner-recovery-budget-decision.v7',
                              'reviewHash': m.digest(self.login_review), 'approvedAt': m.EXPIRY - 7200,
                              'expiresAt': m.EXPIRY,
                              'decision': 'APPROVE_EXACT288_AND_NEW7200_WINDOW_PROTECTED_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'}
        # Exercise a session under the predecessor's nested root, not a sibling of context.
        session = self.context.parent / 'retained-human-origin' / ('human-ingestion-owner-recovery288-' + m.digest(self.login_review))
        self.session = session
        binding = {'sessionDirectory': str(session), 'createdAt': m.EXPIRY - 7200,
                   'tokenPath': str(session / 'human-access.jwt'), 'expiresAt': m.EXPIRY,
                   'retryProfile': {'id': 'ouf.human.ingestion-owner-recovery288.v7', 'maximumAttempts': 288}}
        self.binding = binding
        self.owner_plan = {'humanBinding': copy.deepcopy(binding),
                           'currentApplications': {n: m.runtime(v, n != 'gateway') for n, v in self.apps.items()}}
        self.login_receipt = {'schema': 'ouf.ingestion-owner-recovery-budget288-receipt.v1', 'directory': str(session),
                              'reviewHash': m.digest(self.login_review), 'expiresAt': m.EXPIRY, 'oauthAttemptsAfter': 276,
                              'maximumCumulativeOAuthAttempts': 288, 'budgetReset': False}
        self.row = {'schema': 'ouf.chatbot-human-session.private.v1', 'binding': binding, 'budgetReset': False,
                    'attempts': 278, 'state': 'READY', 'accessExpiresAt': 100, 'monotonicDeadline': 200,
                    'lastObservedAt': 100, 'bootId': 'boot', 'accessToken': 'SECRET_TOKEN', 'publishedAccessToken': 'SECRET_TOKEN'}
        self.row['governedWindowRenewal'] = {'review': self.login_review, 'decision': self.login_decision}
        self.routes = {str(n): {} for n in range(82)}
        self.plan = {'logicalRef': m.digest({'ownerResultHash': m.OWNER_RESULT, 'oldProjectionHash': m.OLD_PROJECTION, 'newProjectionHash': m.PROJECTION}),
                     'humanBinding': binding, 'engine': getattr(self, 'engine_binding', {}), 'gateway': {'beforeRoutes': self.routes, 'transport': {}},
                     'currentApplications': {n: m.runtime(v, n != 'gateway') for n, v in self.apps.items()}}
        self.scope = {'planHash': m.digest(self.plan), 'projectionHash': m.PROJECTION,
                      'ownerResultHash': m.OWNER_RESULT, 'stages': m.STAGES}
        self.preparation = {'context': str(self.context), 'ownerResultHash': m.OWNER_RESULT, 'automaticReplayAllowed': False}
        case = {'humanBinding': binding, 'preparationClaimBinding': {'path': str(self.context.parent / 'preparation.claim.json'), 'sha256': m.digest(self.preparation)}}
        self.raw = {'case.json': m.encoded(case), 'bootstrap.py': b'not executable', 'runtime.py': b'never loaded', 'reader.py': b'not run'}
        sources = {f'fixture.{i}': b'raise Exception("NEVER_EXECUTE")' for i in range(238)}
        self.pins = {'bootstrap': m.sha(self.raw['bootstrap.py']), 'runtime': m.sha(self.raw['runtime.py'])}
        for n in ('entry', 'authority', 'owner', 'native', 'history', 'session'):
            sources['tools.ingestion_profile_publication.' + n] = b'raise Exception("NEVER_EXECUTE")'
            self.pins[n] = m.sha(sources['tools.ingestion_profile_publication.' + n])
        self.raw['sources.json'] = m.encoded({n: base64.b64encode(v).decode() for n, v in sources.items()})
        declaration = {'moduleCount': 244, 'entryModule': 'tools.ingestion_profile_publication.entry',
                       'sourceHashes': {n: m.sha(v) for n, v in sources.items()}}
        self.package = {'sourceCommit': m.SOURCE, 'fileHashes': {n: m.sha(v) for n, v in self.raw.items()},
                        'closure': {'declaration': declaration}, 'declarationHash': m.digest(declaration),
                        'executionPins': {'caseSha256': m.digest(case)}}
        self.review = {'scopes': {'ingestionActiveProjectionPublication': self.scope}, 'sourceClosureHash': m.digest(self.package['closure'])}
        journal = {'scopeHash': m.digest(self.scope), 'incidentState': 'RECOVERED', 'nextStage': 3, 'authorityHash': 'prior',
                   'effects': [{'stage': s, 'state': 'APPLIED', 'intentHash': m.digest({'planHash': m.digest(self.plan), 'stage': s}),
                                'evidence': {'publishedBinding': self.result['publishedBinding']} if s == 'PUBLISH_ACTIVE_PROJECTION' else {}}
                               for s in m.STAGES]}
        self.values = {str(self.context / 'update-result.json'): self.result,
                       str(self.owner / 'update-result.json'): {'status': 'OWNER_REFERENCE_ACTIVATED_AND_EXPORTED', 'complete': True, 'planHash': m.OWNER_PLAN},
                       str(self.owner / 'execution-plan.json'): self.owner_plan,
                       str(self.owner / 'login-review.json'): self.login_review,
                       str(self.owner / 'login-decision.json'): self.login_decision,
                       str(self.owner / 'login-window-receipt.json'): self.login_receipt,
                       str(self.context / 'package.json'): self.package,
                       str(self.context / 'runtime.claim.json'): {'packageHash': m.digest(self.package), 'automaticReplayAllowed': False},
                       case['preparationClaimBinding']['path']: self.preparation,
                       str(self.context / 'execution-plan.json'): self.plan,
                       str(self.context / 'review.json'): self.review,
                       str(self.context / 'decision.json'): {'reviewHash': m.digest(self.review), 'decision': 'APPROVE_EXACT_FINITE_SCOPED_ACTION'},
                       str(self.context / 'recovery.json'): journal,
                       str(self.context.parent / ('ingestion-active-projection-' + self.plan['logicalRef'] + '.claim.json')):
                           {'context': str(self.context), 'scopeHash': m.digest(self.scope), 'authorityHash': 'prior', 'automaticReplayAllowed': False, 'budgetReset': False},
                       str(Path(binding['sessionDirectory']) / 'recovery.json'): self.row}
        self.reads = []

    def parse(self, path, *_, **__):
        self.reads.append(str(path))
        if str(path) == str(self.owner / 'execution-plan.json'):
            self.assertEqual(_[0], m.OWNER_PLAN)
        return copy.deepcopy(self.values[str(path)])

    def file_read(self, path, expected=None, **kwargs):
        if kwargs.get('projection'):
            return b'projection', self.result['publishedBinding']['metadata']
        raw = self.raw[Path(path).name]
        self.assertEqual(m.sha(raw), expected)
        return raw, []

    def run_diagnostic(self, reader=None):
        apps = self.apps
        class Reader:
            def __init__(inner, *_): inner.calls = 0
            def get(inner, ref):
                inner.calls += 1
                return copy.deepcopy(next(v for v in apps.values() if v['Id'] == ref))
        real_sha = m.sha
        def sha(raw): return m.PROJECTION if raw == b'projection' else real_sha(raw)
        with patch.object(m, 'DELIVERY_PINS', self.pins), patch.object(m, 'ROUTES', m.digest(self.routes)), patch.object(m, 'sha', sha):
            return m.inspect(parse=self.parse, file_read=self.file_read, engine_type=reader or Reader,
                             clock=lambda: (150, 150), boot_read=lambda: 'boot')

    def test_full_diagnostic_redacts_credentials_and_never_executes_sources(self):
        report = self.run_diagnostic()
        self.assertTrue(report['complete'])
        self.assertEqual(report['engineGetRequests'], 10)
        self.assertEqual(report['applicationCount'], 5)
        self.assertEqual(report['human']['remainingAttempts'], 10)
        self.assertTrue(report['human']['recordedAccessTokenExpired'])
        self.assertFalse(report['human']['providerAuthorizationReverified'])
        output = m.encoded(report).decode()
        for secret in ('SECRET_TOKEN', 'NEVER_PRINT_ME', 'retained-human-origin'):
            self.assertNotIn(secret, output)
        self.assertEqual(sum(p == str(self.session / 'recovery.json') for p in self.reads), 2)
        self.assertFalse(report['databaseAdmissionProven'])

    def test_actual_retained_plan_constructor_produces_all_five_applications(self):
        import ast
        from types import SimpleNamespace
        source = (ROOT / 'tools/installation_binding_apply/entry.py').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), '768c65f0c67d33d976387927c488e3f2edb7b193d82c7e2b2caaaa82de78f8d3')
        function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'common')
        namespace = {'copy': copy, 'require': m.require, 'FORBIDDEN': ()}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<pinned-original-plan-common>', 'exec'), namespace)
        pins = self.plan['currentApplications']
        owner = {'unchangedApplications': {n: pins[n] for n in ('mcp', 'udp', 'ingestion')},
                 'gateway': {'transport': {'runtimeBinding': pins['gateway']}, 'afterRoutes': self.routes, 'projectionBinding': {}},
                 'engine': {}, 'retainedMcpMetadata': []}
        result = {'finalEvidence': {'onboarding': {'runtimeBinding': pins['onboarding']}}}
        actual = namespace['common'](owner, result, SimpleNamespace(current=lambda: self.binding), {}, {})
        self.assertEqual(actual['currentApplications'], pins)
        self.assertEqual(m.retained_applications(actual, self.owner_plan), pins)
        self.assertEqual(set(actual['currentApplications']), {'onboarding', 'mcp', 'udp', 'ingestion', 'gateway'})

    def test_missing_extra_and_foreign_application_bindings_are_denied(self):
        for transform in ('missing', 'extra', 'foreign'):
            plan = copy.deepcopy(self.plan)
            if transform == 'missing': del plan['currentApplications']['udp']
            elif transform == 'extra': plan['currentApplications']['other'] = plan['currentApplications']['udp']
            else: plan['currentApplications']['udp']['containerId'] = 'e' * 64
            with self.assertRaises(m.Denied): m.retained_applications(plan, self.owner_plan)

    def test_failed_native_read_keeps_only_redacted_partial_checkpoint(self):
        class Reader:
            def __init__(self, *_): self.calls = 0
            def get(self, _):
                self.calls += 1
                raise m.Denied('BOUNDED_ENGINE_REPLY_REQUIRED')
        with self.assertRaises(m.Denied): self.run_diagnostic(Reader)
        self.assertEqual(m.PUBLIC_PROGRESS['human']['attempts'], 278)
        self.assertFalse(m.PUBLIC_PROGRESS['humanSnapshotRechecked'])
        self.assertEqual(m.PUBLIC_PROGRESS['applicationCount'], 5)
        self.assertEqual(m.PUBLIC_PROGRESS['engineGetAttemptsStarted'], 1)
        self.assertEqual(m.PUBLIC_PROGRESS['currentApplication'], 'onboarding')
        for private in ('SECRET_TOKEN', 'NEVER_PRINT_ME', 'retained-human-origin'):
            self.assertNotIn(private, m.encoded(m.PUBLIC_PROGRESS).decode())

    def test_duplicate_container_identities_are_denied_before_socket_use(self):
        with self.assertRaises(m.Denied):
            m.EngineReader({'socketPath': '/retained.sock', 'socketBinding': [1, 2, 0, 0, 0o600]}, ['e' * 64] * 5)

    def test_session_parent_is_inherited_from_actual_v7_creator(self):
        import ast
        from types import SimpleNamespace
        source = (ROOT / 'tools/ingestion_owner_recovery/login.py').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), '2bc05f5f89d95d27d1580b1d10591d7748642dad8336ba236000ec3fd2a61c59')
        tree = ast.parse(source)
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'destination' for t in node.targets)]
        self.assertEqual(len(assignments), 1)
        expression = ast.Expression(assignments[0].value)
        predecessor = self.session.parent / 'human-ingestion-owner-rollout272-retained'
        actual = eval(compile(expression, '<pinned-v7-destination-expression>', 'eval'),
                      {'__builtins__': {}, 'human': SimpleNamespace(directory=predecessor),
                       'digest': m.digest, 'review': self.login_review})
        self.assertEqual(actual, self.session)
        self.assertNotEqual(actual.parent, self.context.parent)
        report = self.run_diagnostic()
        self.assertTrue(report['successfulSessionBoundToPinnedOwnerPlan'])
        self.assertEqual(report['human']['attempts'], 278)

    def test_foreign_same_basename_is_denied_by_pinned_owner_binding(self):
        binding = copy.deepcopy(self.binding)
        path = Path('/root/foreign') / self.session.name
        binding.update(sessionDirectory=str(path), tokenPath=str(path / 'human-access.jwt'))
        with self.assertRaises(m.Denied):
            m.session_directory(binding, self.owner_plan, self.login_review, self.login_decision, self.login_receipt)

    def test_foreign_login_receipt_is_denied(self):
        self.login_receipt['directory'] = '/root/other'
        with self.assertRaises(m.Denied): self.run_diagnostic()

    def test_session_path_traversal_and_wrong_basename_are_denied(self):
        for path in (str(self.session.parent / '..' / self.session.name), str(self.session.parent / 'wrong')):
            binding = copy.deepcopy(self.binding)
            binding.update(sessionDirectory=path, tokenPath=path + '/human-access.jwt')
            with self.assertRaises(m.Denied):
                m.session_directory(binding, {'humanBinding': binding}, self.login_review, self.login_decision,
                                    dict(self.login_receipt, directory=path))

    def test_token_path_outside_proven_directory_is_denied(self):
        binding = copy.deepcopy(self.binding)
        binding['tokenPath'] = '/root/foreign/human-access.jwt'
        with self.assertRaises(m.Denied):
            m.session_directory(binding, {'humanBinding': binding}, self.login_review, self.login_decision, self.login_receipt)

    def test_session_row_lineage_substitution_is_denied(self):
        self.row['governedWindowRenewal'] = {}
        with self.assertRaises(m.Denied): self.run_diagnostic()

    def test_native_clock_after_actual_window_expiry_keeps_counter_and_no_authority(self):
        with patch.object(m, 'DELIVERY_PINS', self.pins), patch.object(m, 'ROUTES', m.digest(self.routes)):
            snapshot = m.human_snapshot(self.row, self.binding, m.EXPIRY + 19940, 201, 'boot')
        self.assertFalse(snapshot['windowOpenOnRecordedClocks'])
        self.assertEqual(snapshot['attempts'], 278)
        self.assertEqual(snapshot['remainingAttempts'], 10)
        self.assertFalse(snapshot['snapshotIsRuntimeAuthority'])

    def test_changed_publication_receipt_stops(self):
        self.result['oauthAttemptsAfter'] = 279
        with self.assertRaises(m.Denied): self.run_diagnostic()

    def test_claimed_ambiguous_effect_never_replayed(self):
        self.values[str(self.context / 'recovery.json')]['effects'][1]['state'] = 'CLAIMED'
        with self.assertRaises(m.Denied): self.run_diagnostic()

    def test_deleted_claim_stops(self):
        self.values[str(self.context / 'runtime.claim.json')] = {}
        with self.assertRaises(m.Denied): self.run_diagnostic()

    def test_human_change_during_inspection_stops(self):
        outer = self
        class Reader:
            def __init__(self, *_): self.calls = 0
            def get(self, ref):
                self.calls += 1
                outer.row['attempts'] += 1
                return next(v for v in outer.apps.values() if v['Id'] == ref)
        with self.assertRaises(m.Denied): self.run_diagnostic(Reader)

    def test_stable_changed_runtime_is_reported_as_drift(self):
        self.apps['ingestion']['State']['StartedAt'] = 'different'
        self.assertFalse(self.run_diagnostic()['runtimeBindingsMatchRetained']['ingestion'])

    def test_expired_window_is_reported_without_renewal(self):
        report = m.human_snapshot(self.row, self.binding, m.EXPIRY + 1, 201, 'boot')
        self.assertFalse(report['windowOpenOnRecordedClocks'])
        self.assertEqual(self.row['attempts'], 278)

    def test_counter_rewind_rejected(self):
        self.row['attempts'] = 277
        with self.assertRaises(m.Denied): self.run_diagnostic()

    def test_new_boot_is_not_fresh_authority(self):
        self.assertFalse(m.human_snapshot(self.row, self.binding, 150, 150, 'other')['windowOpenOnRecordedClocks'])

    def test_duplicate_and_nonfinite_json_denied(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(m.Denied): m.decode(raw)


class NativeBoundaries(unittest.TestCase):
    def setUp(self):
        # Never use /tmp: the production reader intentionally rejects writable ancestry.
        self.work = tempfile.TemporaryDirectory(prefix='ouf-checkpoint-', dir=os.environ.get('OUF_TEST_ROOT', str(ROOT)))
        self.root = Path(self.work.name)

    def tearDown(self): self.work.cleanup()

    def test_nested_successful_session_can_be_read_without_mutation_after_expiry(self):
        fixture = FullDiagnostic()
        fixture.setUp()
        directory = self.root / 'prior-session-origin' / fixture.session.name
        directory.mkdir(parents=True, mode=0o700)
        binding = dict(fixture.binding, sessionDirectory=str(directory), tokenPath=str(directory / 'human-access.jwt'))
        receipt = dict(fixture.login_receipt, directory=str(directory))
        selected = m.session_directory(binding, {'humanBinding': binding}, fixture.login_review, fixture.login_decision, receipt)
        row = dict(fixture.row, binding=binding)
        path = selected / 'recovery.json'
        path.write_bytes(m.encoded(row)); path.chmod(0o600)
        before = (path.read_bytes(), m.metadata(path.stat()))
        current = m.parsed(path, maximum=65536)
        snapshot = m.human_snapshot(current, binding, m.EXPIRY + 19940, 201, 'boot')
        self.assertFalse(snapshot['windowOpenOnRecordedClocks'])
        self.assertEqual(snapshot['attempts'], 278)
        self.assertEqual((path.read_bytes(), m.metadata(path.stat())), before)
        self.assertFalse((directory / 'human-access.jwt').exists())

    def test_private_file_bytes_custody_and_large_integer_preserved(self):
        path = self.root / 'fact.json'
        raw = b'{"ns":1792445329071520839}'
        path.write_bytes(raw); path.chmod(0o600)
        self.assertEqual(m.read(path, m.sha(raw))[0], raw)
        self.assertEqual(m.parsed(path)['ns'], 1792445329071520839)
        path.chmod(0o640)
        with self.assertRaises(m.Denied): m.read(path)

    def test_symlink_and_hardlink_denied(self):
        path = self.root / 'private'; path.write_text('private'); path.chmod(0o600)
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(OSError): m.read(link)
        link.unlink(); os.link(path, link)
        with self.assertRaises(m.Denied): m.read(path)

    def test_hash_drift_and_oversize_denied(self):
        path = self.root / 'private'; path.write_bytes(b'12345'); path.chmod(0o600)
        with self.assertRaises(m.Denied): m.read(path, '0' * 64)
        with self.assertRaises(m.Denied): m.read(path, maximum=4)

    def test_parent_symlink_denied(self):
        folder = self.root / 'folder'; folder.mkdir()
        path = folder / 'private'; path.write_text('bytes'); path.chmod(0o600)
        link = self.root / 'link'; link.symlink_to(folder, target_is_directory=True)
        with self.assertRaises(OSError): m.read(link / 'private')

    def test_complete_five_application_diagnostic_uses_ten_real_unix_gets(self):
        fixture = FullDiagnostic()
        fixture.setUp()
        values = {a['Id']: a for a in fixture.apps.values()}
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command, self.path))
                reference = self.path.split('/')[3]
                raw = m.encoded(values[reference])
                self.send_response(200); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *_): pass
        path = self.root / 'full.sock'
        server = socketserver.UnixStreamServer(str(path), Handler); path.chmod(0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        info = path.lstat()
        fixture.engine_binding = {'socketPath': str(path), 'socketBinding': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]}
        fixture.setUp()
        try:
            report = fixture.run_diagnostic(m.EngineReader)
            self.assertEqual(report['engineGetRequests'], 10)
            self.assertEqual(report['applicationCount'], 5)
            self.assertTrue(all(report['runtimeBindingsMatchRetained'].values()))
            self.assertEqual(len(requests), 10)
            for name in m.APPLICATION_NAMES:
                expected = ('GET', '/v1.44/containers/' + fixture.apps[name]['Id'] + '/json')
                self.assertEqual(requests.count(expected), 2)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_real_unix_http_get_allowlist_limit_and_socket_drift(self):
        calls = []
        value = application('ingestion')
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.command, self.path)); raw = m.encoded(value)
                self.send_response(200); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *_): pass
        class Server(socketserver.UnixStreamServer): pass
        path = self.root / 'engine.sock'
        server = Server(str(path), Handler); path.chmod(0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        info = path.lstat()
        binding = {'socketPath': str(path), 'socketBinding': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]}
        try:
            reader = m.EngineReader(binding, [value['Id']])
            self.assertEqual(reader.get(value['Id']), value)
            with self.assertRaises(m.Denied): reader.get('e' * 64)
            self.assertEqual(reader.get(value['Id']), value)
            with self.assertRaises(m.Denied): reader.get(value['Id'])
            self.assertEqual(calls, [('GET', '/v1.44/containers/' + value['Id'] + '/json')] * 2)
            reader = m.EngineReader(binding, [value['Id']]); path.chmod(0o666)
            with self.assertRaises(m.Denied): reader.get(value['Id'])
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__': unittest.main()
