import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools/semantic_policy_token_owner'),
               str(ROOT / 'tools/semantic_application_cutover'),
               str(ROOT / 'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_preparation import continuation_inputs as m, continuation_inputs_delivery as delivery, frames
from tools.ingestion_rollout_execution import contract as c, runtime_guard as guard, replacement, runtime_bindings as bindings
MODULES = [c, guard, replacement, bindings]


def fixture():
    image = {'User': '10002:10002', 'Entrypoint': ['java', '-jar', '/app/app.jar'],
             'WorkingDir': '/app', 'Env': ['JAVA_HOME=/opt/java']}
    initial = {}
    for module, cid, networks in [('ingestion', 'a' * 64, 1), ('gateway', 'd' * 64, 2)]:
        endpoints = {}
        for i in range(networks):
            endpoints['fixture' + str(i)] = {'NetworkID': str(i + 1) * 64,
                'IPAddress': '192.0.2.' + str(i + 8), 'GlobalIPv6Address': '',
                'MacAddress': '02:00:00:00:00:0' + str(i + 8), 'Aliases': [module, cid[:12], cid],
                'IPAMConfig': None, 'Links': None, 'DriverOpts': {}, 'GwPriority': 0}
        actual = {'Id': cid, 'Name': '/' + module, 'Image': 'sha256:' + 'b' * 64,
            'Config': {'User': '10002:10002', 'Entrypoint': image['Entrypoint'], 'Cmd': [],
                'WorkingDir': '/app', 'Env': ['PATH=/opt/java/bin:/bin', 'CANARY_PRIVATE=NEVER_PRINT'],
                'Labels': {'keep': 'yes'}, 'Hostname': cid[:12], 'Image': 'sha256:' + 'b' * 64,
                'MacAddress': endpoints['fixture0']['MacAddress']},
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
                'Binds': ['/old:/old:ro'], 'OomKillDisable': None, 'Memory': 1234567,
                'CapDrop': ['ALL'], 'ReadonlyRootfs': True, 'NetworkMode': 'fixture0'},
            'Mounts': [{'Destination': '/old', 'Source': '/old', 'Type': 'bind', 'RW': False}],
            'NetworkSettings': {'Networks': endpoints, 'SandboxID': 'old-sandbox'},
            'RestartCount': 0, 'State': {'Running': True, 'Status': 'running', 'Paused': False,
                'Restarting': False, 'Pid': 41, 'StartedAt': 'fixture-original-process'}}
        if module == 'gateway':
            actual['Mounts'] = [{'Type': 'bind', 'Source': '/old.yaml', 'Destination': frames.CONFIG_DESTINATION, 'RW': False}]
            actual['HostConfig']['Binds'] = ['/old.yaml:' + frames.CONFIG_DESTINATION + ':ro']
        initial[module] = actual
    draft = {'candidate': {'sourceCommit': '1' * 40}, 'ingestion': {'bootstrapCmd': ['--spring.flyway.enabled=false', '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
        'ownerReadEnvironmentAdditions': {'OUF_ING_GATEWAY_READ_ENABLED': 'true'},
        'startupEnvironmentAddition': {'SPRING_FLYWAY_ENABLED': 'false'},
        'readOnlyBindAddition': {'Type': 'bind', 'RW': False, 'Source': '/key', 'Destination': '/run/secrets/key'}}}
    compiled = {mod: frames.frame(mod, actual, 'sha256:' + ('e' if mod == 'ingestion' else 'b') * 64,
                   image, draft, '/new.yaml' if mod == 'gateway' else None) for mod, actual in initial.items()}
    before = {k: {'id': k} for k in ['mcp-ingestion-status', 'mcp-ingestion-history', *[str(i) for i in range(80)]]}
    after = copy.deepcopy(before)
    for k in ('mcp-ingestion-status', 'mcp-ingestion-history'): after[k]['fixture'] = True
    inputs = {'candidate': {'nativeImageId': 'sha256:' + 'e' * 64, 'configurationImageId': 'sha256:' + 'f' * 64,
        'nativeArchiveBinding': {'path': '/archive', 'sha256': 'c' * 64}, 'imageConfig': image, 'rootfs': {'type': 'layers', 'diff_ids': []}},
        'expectedRuntimeBindings': {k: bindings.observed(v, bindings.SORTED) for k, v in initial.items()},
        'gatewayConfigBefore': {'path': '/old.yaml', 'sha256': '1' * 64},
        'retainedGatewayConfig': {'path': '/new.yaml', 'sha256': '2' * 64},
        'dedicatedOwnerKey': {'path': '/key', 'state': 'MISSING_AT_EXISTING_CUSTODIED_PARENT'}, 'retainedClaims': {}}
    packet = {'schema': 'ouf.ingestion-rollout-private-packet.v3', 'kind': 'PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY',
        **inputs, 'verifiedInputsHash': c.digest(inputs), 'frames': compiled,
        'routeDraft': {'beforeRoutes': before, 'afterRoutes': after, 'retainedOtherRoutes': 80, 'maximumPutRequests': 2},
        **dict.fromkeys(('runtimeAuthorityIssued', 'runtimeExecutorQualified', 'databaseAdmissionProven',
                        'targetApplyAuthorized', 'automaticReplayAllowed', 'budgetReset', 'newLoginAllowed'), False)}
    native = c.compile_review(packet, {'path': '/packet', 'sha256': c.digest(packet)}, inputs,
        {'sessionId': 'fixture', 'issuer': 'https://fixture.invalid', 'tenant': 'fixture', 'subject': 'fixture'}, '/execution')
    profile = {'schema': guard.__dict__.get('PROFILE', 'ouf.ingestion-rollout-runtime-guard.v1'),
               'beforeContainers': copy.deepcopy(initial), 'unchangedApplications': {}}
    rows = {}
    for i, module in enumerate(('onboarding', 'mcp', 'udp', 'postgres'), 3):
        actual = copy.deepcopy(initial['ingestion']); actual['Id'] = str(i) * 64
        pin = {'binding': bindings.observed(actual, bindings.SORTED), 'restartCount': 0, 'bindingProfile': bindings.SORTED}
        rows[actual['Id']] = actual
        if module != 'postgres': profile['unchangedApplications'][module] = pin
        else: native['databaseControlProfile'] = {'postgresRuntimeBinding': pin['binding'],
                'postgresRestartCount': 0, 'runtimeBindingProfile': bindings.SORTED}
    native['runtimeGuardProfile'] = profile
    native['ownerControlProfile'] = {'runtimeBinding': profile['unchangedApplications']['onboarding']['binding'],
                                    'networkNamespace': {'device': 1, 'inode': 2}}
    native['retainedGatewayNamespace'] = {'device': 2, 'inode': 3}
    row = {'nextStage': 18, 'effects': [{'stage': s['name'], 'intentHash': s['intentHash'], 'state': 'APPLIED'}
                                     for s in native['stages'][:18]]}
    for module, cid, pid in [('ingestion', '8' * 64, 1001), ('gateway', '9' * 64, 1002)]:
        old = copy.deepcopy(initial[module]); old['State'].update(Running=False, Pid=0)
        old['HostConfig']['RestartPolicy'] = copy.deepcopy(frames.NO_RESTART)
        old['NetworkSettings'] = {'Networks': {}, 'SandboxID': ''}
        old['Name'] = '/' + next(s['intent']['retainedName'] for s in native['stages'] if s['name'] == module + '.RENAME_OLD')
        rows[old['Id']] = old
        frame = compiled[module]; request = frame['requestTemplate']
        config = {**copy.deepcopy(image), **{k: copy.deepcopy(v) for k, v in request.items() if k not in ('HostConfig', 'NetworkingConfig')}}
        env = {**frames.environment(image['Env']), **frames.environment(request['Env'])}
        if module == 'gateway': env[frames.OWNER_ENV] = 'f' * 64
        config['Env'] = [k + '=' + v for k, v in env.items()]; config['Hostname'] = cid[:12]
        networks = copy.deepcopy(request['NetworkingConfig']['EndpointsConfig'])
        for ep in networks.values():
            ep['IPAddress'] = (ep.get('IPAMConfig') or {}).get('IPv4Address', '')
            ep['GlobalIPv6Address'] = (ep.get('IPAMConfig') or {}).get('IPv6Address', '')
        actual = {'Id': cid, 'Name': '/' + frame['name'], 'Image': request['Image'], 'Config': config,
            'HostConfig': copy.deepcopy(request['HostConfig']), 'Mounts': list(replacement._mounts(frame).values()),
            'NetworkSettings': {'Networks': networks}, 'RestartCount': 0, 'Platform': 'linux',
            'State': {'Running': True, 'Status': 'running', 'Paused': False, 'Restarting': False,
                      'Pid': pid, 'StartedAt': 'fixture-first-start'}}
        rows[cid] = actual
        for kind, resource in [('CREATE_REPLACEMENT', {'containerId': cid}),
                               ('START_REPLACEMENT', replacement.generation(actual))]:
            i = next(i for i, s in enumerate(native['stages']) if s['name'] == module + '.' + kind)
            row['effects'][i]['nativeResource'] = resource
    return native, packet, row, rows, {'Id': packet['expectedRuntimeBindings']['gateway']['imageId'], 'Config': image}


class Predicates(unittest.TestCase):
    def setUp(self):
        self.native, self.packet, self.row, self.rows, self.image = fixture()
        case = self
        class Engine:
            image_path = '/image'
            def __init__(self): self.calls = 0
            def container(self, cid): self.calls += 1; return copy.deepcopy(case.rows[cid])
            def get(self, path): self.calls += 1; return copy.deepcopy(case.image)
        self.engine = Engine()
        self.ns = lambda pid: {'device': 1, 'inode': 2} if pid == 41 else {'device': 3, 'inode': 4}

    def read(self):
        return m.runtime_snapshot(self.native, self.packet, self.row, MODULES, self.engine, namespace_read=self.ns)

    def test_both_retained_and_new_generations_with_three_unchanged_and_postgres(self):
        result = self.read()
        self.assertEqual(self.engine.calls, 9)
        self.assertEqual(set(result), {'unchanged.onboarding', 'unchanged.mcp', 'unchanged.udp', 'unchanged.postgres',
                                     'retained.ingestion', 'retained.gateway', 'replacement.ingestion', 'replacement.gateway', 'namespaces'})
        self.assertNotIn('NEVER_PRINT', json.dumps({k: v for k, v in result.items() if k.startswith('replacement.')}))

    def test_replacement_restart_or_new_process_drift(self):
        for change in ('pid', 'restart', 'policy', 'mac', 'image'):
            with self.subTest(change=change):
                old = copy.deepcopy(self.rows)
                actual = self.rows['9' * 64]
                if change == 'pid': actual['State']['Pid'] += 1
                if change == 'restart': actual['RestartCount'] = 1
                if change == 'policy': actual['HostConfig']['RestartPolicy']['Name'] = 'always'
                if change == 'mac': next(iter(actual['NetworkSettings']['Networks'].values()))['MacAddress'] = '02:00:00:ff:ff:ff'
                if change == 'image': actual['Image'] = 'sha256:' + '0' * 64
                with self.assertRaises((m.Denied, c.Denied)): self.read()
                self.rows = old

    def test_retained_predecessor_cannot_reappear_or_restart(self):
        self.rows['a' * 64]['State'].update(Running=True, Pid=77)
        with self.assertRaises(c.Denied): self.read()

    def test_unchanged_postgres_or_application_changes(self):
        for cid in ('3' * 64, '4' * 64, '5' * 64, '6' * 64):
            with self.subTest(cid=cid):
                self.rows[cid]['RestartCount'] += 1
                with self.assertRaises(c.Denied): self.read()
                self.rows[cid]['RestartCount'] -= 1

    def test_namespace_must_be_current_and_different_from_old_gateway(self):
        self.ns = lambda pid: self.native['retainedGatewayNamespace']
        with self.assertRaises(m.Denied): self.read()

    def test_creation_resource_must_equal_first_process_resource(self):
        i = next(i for i, s in enumerate(self.native['stages']) if s['name'] == 'gateway.CREATE_REPLACEMENT')
        self.row['effects'][i]['nativeResource']['containerId'] = '7' * 64
        with self.assertRaises(m.Denied): self.read()


class Composition(unittest.TestCase):
    def setUp(self):
        Predicates.setUp(self)
        self.native['engineBinding'] = {'socketPath': '/fixture/engine.sock', 'socketBinding': [1, 2, 0, 0, 0o660]}
        self.row['effects'][1]['nativeFinalMetadata'] = [1, 2, 10002, 10002, 0o100400, 1, 64, 1, 2]
        self.review = {'executionReview': self.native}
        self.case = {'journalHash': c.digest(self.row), 'reviewHash': c.digest(self.review),
                     'logicalOperationRef': self.native['logicalOperationRef']}
        self.documents = {'/execution/review.json': c.encoded(self.review),
                          '/execution/recovery.json': c.encoded(self.row), '/packet': c.encoded(self.packet)}
        self.read_paths = []
        self.metadata_calls = []
        def read(path): self.read_paths.append(path); return self.documents[path]
        self.read = read
        self.public = {'journalHash': self.case['journalHash'], 'reviewHash': self.case['reviewHash'],
            'logicalOperationRef': self.case['logicalOperationRef'], 'sameBoot': True, 'wallClockConsistent': True,
            'recordedSecondsRemaining': 0, 'recordedMonotonicSecondsRemaining': 0, 'pendingStageClaim': False,
            'contextPath': '/execution', 'remainingStages': [{'name': s['name'], 'kind': s['kind']} for s in self.native['stages'][18:]]}
        self.snapshot = {'CASE': {}, 'inspect': lambda _: copy.deepcopy(self.public),
                         'private_read': read, 'decode': json.loads, 'digest': c.digest}
        outer = self
        class Engine:
            def __new__(cls, binding, ids, image, decode):
                if len(set(ids)) != 8: raise AssertionError('exact eight IDs required')
                return outer.engine
        self.engine_type = Engine
        self.key_stat = lambda path, metadata: self.metadata_calls.append((path, metadata)) or True

    def composed(self):
        return m.inspect(self.case, self.snapshot, MODULES, engine_type=self.engine_type,
                         namespace_read=self.ns, key_stat=self.key_stat, clock=lambda: 2000)

    def test_exact_two_passes_do_not_grant_new_budget_or_current_health(self):
        result = self.composed()
        self.assertEqual(result['engineRequests'], 18)
        self.assertEqual(result['nextStage'], 18)
        self.assertFalse(result['additionalOAuthBudgetGranted'])
        self.assertFalse(result['applicationReadinessReverified'])
        self.assertFalse(result['gatewayKeyValueReverified'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertEqual(set(self.read_paths), set(self.documents))
        self.assertEqual(len(self.metadata_calls), 2)
        for canary in ('NEVER_PRINT', 'CANARY_PRIVATE', 'ffffffffffffffff'):
            self.assertNotIn(canary, json.dumps(result))

    def test_nonexpired_unknown_boot_or_changed_prefix_blocks_before_engine(self):
        for k, v in [('sameBoot', False), ('wallClockConsistent', False), ('recordedSecondsRemaining', 1),
                     ('pendingStageClaim', True), ('journalHash', '0' * 64)]:
            with self.subTest(key=k):
                previous = copy.deepcopy(self.public); self.public[k] = v
                with self.assertRaises(m.Denied): self.composed()
                self.public = previous
        self.assertEqual(self.engine.calls, 0)

    def test_restarted_process_between_passes_is_not_a_matching_snapshot(self):
        original = self.engine.container
        def race(cid):
            if self.engine.calls >= 9 and cid == '9' * 64: self.rows[cid]['State']['Pid'] += 1
            return original(cid)
        self.engine.container = race
        with self.assertRaises(c.Denied): self.composed()

    def test_changed_predecessor_journal_after_live_gets_is_denied(self):
        def read(path):
            if path.endswith('/recovery.json') and self.engine.calls:
                return self.documents[path] + b'\n'
            return self.documents[path]
        self.snapshot['private_read'] = read
        with self.assertRaises(m.Denied): self.composed()

    def test_key_metadata_change_between_passes_is_denied(self):
        calls = []
        def change(path, metadata): calls.append(path); return len(calls) == 1
        self.key_stat = change
        with self.assertRaises(m.Denied): self.composed()


@unittest.skipUnless(os.geteuid() == 0, 'physical root custody qualification')
class PhysicalReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT)))
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)

    def test_key_stat_never_opens_content_and_rejects_replacement_or_symlink(self):
        key = self.root / 'key'; key.write_bytes(b'f' * 64); key.chmod(0o400)
        metadata = lambda s: [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                             s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        pin = metadata(key.stat())
        self.assertTrue(m.key_metadata(str(key), pin))
        key.chmod(0o600)
        with self.assertRaises(m.Denied): m.key_metadata(str(key), pin)
        key.chmod(0o400); link = self.root / 'link'; link.symlink_to(key)
        with self.assertRaises(m.Denied): m.key_metadata(str(link), pin)

    def test_real_unix_http_channel_is_closed_bounded_get_only(self):
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); probe.close()
        except PermissionError:
            if os.environ.get('GITHUB_ACTIONS') == 'true': raise
            self.skipTest('local sandbox disallows Unix sockets; required in root CI')
        observed = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                observed.append((self.command, self.path)); self.send_response(200); self.end_headers()
                self.wfile.write(json.dumps({'Id': '1' * 64}).encode())
            def do_POST(self): raise AssertionError('mutation forbidden')
        sock = self.root / 'engine.sock'
        server = UnixStreamServer(str(sock), Handler); sock.chmod(0o660)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            s = sock.stat(); binding = {'socketPath': str(sock), 'socketBinding': [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat_mode(s)]}
            reader = m.EngineMetadata(binding, [str(i) * 64 for i in range(1, 9)], 'sha256:' + 'b' * 64, json.loads)
            for _ in range(18): self.assertEqual(reader.container('1' * 64)['Id'], '1' * 64)
            with self.assertRaises(m.Denied): reader.container('1' * 64)
            with self.assertRaises(m.Denied): reader.get('/v1.44/containers/1/start')
            self.assertEqual(len(observed), 18)
            self.assertTrue(all(method == 'GET' for method, _ in observed))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_sealed_artifact_imports_frozen_graph_then_stops_without_target(self):
        case = json.loads((ROOT / 'releases/ingestion-rollout-continuation-input-case-20261021.json').read_text())
        artifact, declaration = delivery.generate(ROOT, case)
        source = self.root / 'reader.py'; source.write_bytes(artifact)
        result = subprocess.run([sys.executable, '-I', '-B', '-S', str(source)], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output['phase'], 'READ_RETAINED_PREFIX_AND_LIVE_METADATA')
        self.assertFalse(output['runtimeAuthorityIssued'])
        self.assertNotIn('Traceback', result.stderr.decode())
        self.assertEqual(declaration['nativeDeclaration']['moduleCount'], 114)

    def test_actual_process_namespace_identity(self):
        try:
            value = m.namespace(os.getpid())
        except FileNotFoundError:
            if os.environ.get('GITHUB_ACTIONS') == 'true': raise
            self.skipTest('local proc namespace unavailable; required in root CI')
        self.assertEqual(set(value), {'device', 'inode'})
        self.assertTrue(all(type(v) is int and v > 0 for v in value.values()))


def stat_mode(info):
    import stat
    return stat.S_IMODE(info.st_mode)


if __name__ == '__main__': unittest.main()
