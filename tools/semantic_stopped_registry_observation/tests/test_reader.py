import copy
import importlib.util
import json
from pathlib import Path
import io
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('observation', ROOT / 'reader.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def setUp(self):
        self.case = json.loads((ROOT / 'case.json').read_text())
        self.gateway_id, self.registry_id = 'a' * 64, self.case['historicalRegistryId']
        state = {'Status': 'running', 'Running': True, 'Paused': False, 'Restarting': False,
                 'Dead': False, 'OOMKilled': False, 'Pid': 12, 'ExitCode': 0, 'Error': '',
                 'StartedAt': '2026-10-21T01:00:00Z', 'FinishedAt': '0001-01-01T00:00:00Z'}
        self.gateway = {'Id': self.gateway_id, 'State': state, 'Config': {'Tty': False},
                        'Image': 'sha256:fixture', 'RestartCount': 0,
                        'NetworkSettings': {'Networks': {'fixture': {'IPAddress': '192.0.2.1'}}}}
        self.registry = copy.deepcopy(self.gateway)
        self.registry.update(Id=self.registry_id, Config={'Env': ['SECRET_FIXTURE_VALUE']})
        self.registry['State'].update(Status='exited', Running=False, Pid=0, ExitCode=137,
                                      Error='SECRET_FIXTURE_VALUE http://192.0.2.2/',
                                      FinishedAt='2026-10-22T12:00:00Z')
        self.registry['NetworkSettings'] = {'Networks': {}}
        self.pin = {'containerId': self.gateway_id, 'pid': 12,
                    'startedAt': self.gateway['State']['StartedAt']}
        self.review = {'executionReview': {'stages': [{}] * 12, 'engineBinding': {},
                       'runtimeGuardProfile': {'unchangedApplications': {'gateway': {'binding': self.pin}}}}}
        self.journal = {'nextStage': 12, 'effects': [{'state': 'APPLIED'}] * 12}
        self.requests = []

    def line(self, request=None, date='2026-10-22T13:13:24.123456789Z', upstream=None):
        request = request or m.OPERATION + '?token=SECRET_FIXTURE_VALUE'
        upstream = upstream or 'http://192.0.2.2:8080' + m.OPERATION + '?secret=SECRET_FIXTURE_VALUE'
        return (date + ' connect() failed (113: No route to host), request: "GET ' + request
                + ' HTTP/1.1", upstream: "' + upstream + '"\n').encode()

    def framed(self, raw):
        return struct.pack('>BBBBI', 2, 0, 0, 0, len(raw)) + raw

    def execute_fixture(self, mutation=None, read_mutation=None):
        owner = self

        class Engine:
            def __init__(self, binding, gateway_id, registry_id, since, until):
                self.calls = 0
                self.log_path = 'fixture-log'

            def inspect(self, cid):
                self.calls += 1
                owner.requests.append(('GET', cid))
                value = copy.deepcopy(owner.gateway if cid == owner.gateway_id else owner.registry)
                if mutation:
                    mutation(self.calls, value)
                return value

            def get(self, path):
                self.calls += 1
                owner.requests.append(('GET', path))
                return owner.framed(owner.line())

        count = [0]

        def read(path):
            count[0] += 1
            value, raw = ((owner.review, b'review') if path.endswith('review.json')
                          else (owner.journal, b'journal'))
            if read_mutation and count[0] > 2:
                raw = b'changed'
            return value, raw

        with patch.object(m, 'Engine', Engine), patch.object(m, 'private_json', read):
            return m.run(self.case)

    def test_stopped_registry_and_same_line_without_current_binding_claim(self):
        result = self.execute_fixture()
        self.assertEqual(result['engineGets'], 5)
        self.assertEqual(len(self.requests), 5)
        self.assertEqual(result['historicalRegistry']['status'], 'exited')
        self.assertFalse(result['historicalRegistry']['running'])
        row = result['sameLineSemanticReferenceFailures'][0]
        self.assertTrue(row['upstreamOperationMatches'])
        self.assertTrue(row['atOrAfterObservedRegistryFinish'])
        self.assertIsNone(row['upstreamAddressMatchesCurrentRegistry'])
        for key in ('currentRegistryIdentityEstablished', 'rootCauseEstablished',
                    'serviceReadinessEstablished', 'registrySubstituted', 'automaticReplayAllowed',
                    'activationResubmitted', 'budgetReset', 'releaseAcceptance'):
            self.assertFalse(result[key], key)
        for secret in ('SECRET_FIXTURE_VALUE', '192.0.2.', 'http://', self.registry_id, 'Env'):
            self.assertNotIn(secret, json.dumps(result))

    def test_running_registry_does_not_assert_endpoint_or_root_cause(self):
        self.registry['State'] = copy.deepcopy(self.gateway['State'])
        result = self.execute_fixture()
        self.assertTrue(result['historicalRegistry']['running'])
        self.assertIsNone(result['historicalRegistry']['finishedAt'])
        self.assertIsNone(result['sameLineSemanticReferenceFailures'][0]['atOrAfterObservedRegistryFinish'])
        self.assertFalse(result['rootCauseEstablished'])

    def test_same_line_is_required_and_exact_request_path(self):
        raw = (b'No route to host\n' + b'request: "GET ' + m.OPERATION.encode() + b' HTTP/1.1"\n'
               + self.line(request=m.OPERATION + '-other')
               + self.line(request='/unrelated?x=' + m.OPERATION))
        result = m.observe_logs(raw, self.registry, self.case['since'], self.case['until'])
        self.assertEqual(result['sameLineSemanticReferenceFailures'], [])
        self.assertTrue(result['absenceOfMatchIsNotProofOfHealth'])

    def test_upstream_operation_mismatch_and_unknown_are_distinct(self):
        for upstream, expected in [('http://fixture.invalid/unrelated', False), ('http://[broken', None)]:
            result = m.observe_logs(self.line(upstream=upstream), self.registry,
                                    self.case['since'], self.case['until'])
            self.assertIs(result['sameLineSemanticReferenceFailures'][0]['upstreamOperationMatches'], expected)

    def test_window_nanoseconds_and_invalid_date(self):
        ns = m.timestamp('2026-10-22T13:13:24.123456789Z')
        self.assertEqual(ns % 1_000_000_000, 123456789)
        self.assertIsNone(m.timestamp('2026-99-22T13:13:24Z'))
        for date in ('2026-10-22T13:15:00Z', '2026-10-22T13:11:59Z', 'malformed'):
            with self.assertRaisesRegex(m.Stop, 'MATCHING_LOG_TIMESTAMP'):
                m.observe_logs(self.line(date=date), self.registry, self.case['since'], self.case['until'])

    def test_lifecycle_config_and_network_drift_stop(self):
        def change_state(call, value):
            if call == 5:
                value['State']['StartedAt'] = '2026-10-22T14:00:00Z'
        def change_network(call, value):
            if call == 4:
                value['NetworkSettings'] = {}
        def change_config(call, value):
            if call == 5:
                value['Config']['Env'] = ['changed']
        for mutation in (change_state, change_network, change_config):
            with self.assertRaisesRegex(m.Stop, 'LIFECYCLE_CONFIG_OR_NETWORK_CHANGED'):
                self.execute_fixture(mutation)
        def change_gateway(call, value):
            if call == 4:
                value['State']['Pid'] += 1
        with self.assertRaisesRegex(m.Stop, 'GATEWAY_GENERATION_CHANGED'):
            self.execute_fixture(change_gateway)

    def test_completed_patch_and_retained_context_guard(self):
        with self.assertRaisesRegex(m.Stop, 'RETAINED_CONTEXT_CHANGED'):
            self.execute_fixture(read_mutation=True)
        self.journal['effects'][0] = {'state': 'CLAIMED'}
        with self.assertRaisesRegex(m.Stop, 'COMPLETED_PATCH_REQUIRED'):
            self.execute_fixture()

    def test_closed_budget_no_discovery_or_registry_logs(self):
        engine = m.Engine({}, self.gateway_id, self.registry_id, self.case['since'], self.case['until'])
        for path in ('/v1.44/containers/json', '/v1.44/containers/' + 'c' * 64 + '/json',
                     engine.log_path.replace(self.gateway_id, self.registry_id)):
            with self.assertRaisesRegex(m.Stop, 'CLOSED_FIVE_GET_BUDGET'):
                engine.get(path)
        engine.calls = 5
        with self.assertRaisesRegex(m.Stop, 'CLOSED_FIVE_GET_BUDGET'):
            engine.get(next(iter(engine.inspects)))

    def test_frame_and_public_error_redaction(self):
        self.assertEqual(m.unframe(self.framed(self.line()), True), self.line())
        for raw in (b'x', struct.pack('>BBBBI', 3, 0, 0, 0, 0), self.framed(b'abc')[:-1]):
            with self.assertRaises(m.Stop):
                m.unframe(raw, True)
        for error in (ValueError('SECRET_FIXTURE_VALUE'), m.Stop('SECRET_FIXTURE_VALUE http://secret')):
            self.assertNotIn('SECRET_FIXTURE_VALUE', json.dumps(m.stopped(error)))

    def test_duplicate_json_and_case_shape(self):
        with self.assertRaisesRegex(m.Stop, 'DUPLICATE_JSON_KEY'):
            m.decode(b'{"schema":1,"schema":2}')
        for key, value in [('extra', 'secret'), ('schema', 'wrong')]:
            case = {**self.case, key: value}
            with self.assertRaisesRegex(m.Stop, 'EXACT_CASE_REQUIRED'):
                m.run(case)

    def test_engine_http_wire_contract_and_404_without_fallback(self):
        sent, selected = [], []
        body = b'{"message":"SECRET_FIXTURE_VALUE"}'
        response = (b'HTTP/1.1 404 Not Found\r\nContent-Length: ' + str(len(body)).encode()
                    + b'\r\nConnection: close\r\n\r\n' + body)

        class WireSocket:
            def settimeout(self, value):
                self.timeout = value
            def connect(self, path):
                selected.append(path)
            def sendall(self, data):
                sent.append(data)
            def makefile(self, *args):
                return io.BytesIO(response)
            def close(self):
                pass

        engine = m.Engine({'socketPath': '/fixture/approved-engine.sock'}, self.gateway_id,
                          self.registry_id, self.case['since'], self.case['until'])
        with patch.object(engine, 'check'), patch.object(m.socket, 'socket', return_value=WireSocket()):
            with self.assertRaisesRegex(m.Stop, 'ENGINE_GET_STATUS_404'):
                engine.inspect(self.registry_id)
        self.assertEqual(engine.calls, 1)
        self.assertEqual(selected, ['/fixture/approved-engine.sock'])
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0].startswith(('GET /v1.44/containers/' + self.registry_id
                                         + '/json HTTP/1.1\r\n').encode()))
        self.assertNotIn(b'SECRET_FIXTURE_VALUE', sent[0])

    def test_private_file_custody_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            path.write_bytes(b'{"fixture":true}')
            path.chmod(0o600)
            value, raw = m.private_json(str(path))
            self.assertEqual(value, {'fixture': True})
            self.assertEqual(raw, path.read_bytes())
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaisesRegex(m.Stop, 'EXACT_PRIVATE_PATH_REQUIRED'):
                m.private_json(str(alias))
            path.chmod(0o666)
            with self.assertRaisesRegex(m.Stop, 'ROOT_OWNED_BOUNDED_METADATA_REQUIRED'):
                m.private_json(str(path))

    def test_engine_socket_binding_inode_and_mode(self):
        from types import SimpleNamespace
        inode = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0,
                                st_gid=1, st_dev=2, st_ino=3)
        binding = {'socketPath': '/fixture/engine.sock', 'socketBinding': [2, 3, 0, 1, 0o600]}
        engine = m.Engine(binding, self.gateway_id, self.registry_id,
                          self.case['since'], self.case['until'])
        with patch.object(Path, 'resolve', lambda p: p), patch.object(Path, 'lstat', return_value=inode):
            engine.check()
            inode.st_ino = 4
            with self.assertRaisesRegex(m.Stop, 'ENGINE_BINDING_CHANGED'):
                engine.check()
            inode.st_ino = 3
            inode.st_mode = stat.S_IFSOCK | 0o666
            with self.assertRaisesRegex(m.Stop, 'ENGINE_BINDING_CHANGED'):
                engine.check()


if __name__ == '__main__':
    unittest.main()
