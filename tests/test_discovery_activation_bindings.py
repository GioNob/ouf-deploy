import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reader', ROOT / 'scripts/read-discovery-activation-bindings-20261109.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
h, c = r.load_helpers()


def doc(cid, image, name, env=None):
    return {'Id': cid, 'Name': '/' + name, 'Image': image, 'Config': {'Env': env or []},
            'HostConfig': {'PortBindings': {}}, 'Mounts': [], 'Path': 'java', 'Args': [],
            'NetworkSettings': {'Networks': {'ouf-backend': {'MacAddress': '02:42:ac:00:00:02'}}},
            'State': {'Running': True, 'Status': 'running', 'Pid': 123, 'StartedAt': '2026-11-09T01:00:00Z'}}


class BindingReadTest(unittest.TestCase):
    def setUp(self):
        self.docs = {role: doc(cid, image, role) for role, (cid, image) in r.APPLICATIONS.items()}
        self.docs['semantic']['Config']['Env'] = [
            'OUF_SCHEMA_GOV_ENABLED=false', 'OUF_DISCOVERY_WORKER_ENABLED=false',
            'OUF_SCHEMA_GOV_GATEWAY_BASE_URL=https://ouf-semantic-southbound-v2:10443',
            'OUF_SCHEMA_GOV_CLIENT_SECRET_FILE=/run/secrets/provider.key',
            'OUF_SCHEMA_GOV_CLIENT_ID=PRIVATE_CLIENT_MARKER',
            'OUF_SCHEMA_GOV_WORKLOAD_SCOPE=PRIVATE_SCOPE_MARKER',
            'UNRELATED_PASSWORD=SECRET_MUST_NOT_APPEAR',
            'OUF_SCHEMA_GOV_TOKEN_ENDPOINT=https://auth.ouf-lab.it/realms/ouf/protocol/openid-connect/token']
        self.calls = []

    def get(self, key):
        self.calls.append(key)
        return next((copy.deepcopy(v) for v in self.docs.values() if key in (v['Id'], v['Name'][1:])), None)

    def collect(self):
        report = {}
        with tempfile.TemporaryDirectory() as td:
            with patch.object(c, 'mount_file', return_value=(None, {'status': 'NO_DECLARED_MOUNT', 'contentsRead': False})) as mounted:
                r.collect(report, Path(td), h, c, get=self.get, processes=lambda d: {'status': 'MOCKED_NOT_LIVE'})
                for call in mounted.call_args_list:
                    self.assertIs(call.kwargs['read_content'], False)
            raw = json.dumps(report)
            for secret in ('SECRET_MUST_NOT_APPEAR', 'PRIVATE_CLIENT_MARKER', 'PRIVATE_SCOPE_MARKER'):
                self.assertNotIn(secret, raw)
            files = list(Path(td).glob('*.private.json'))
            self.assertGreaterEqual(len(files), 2)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in files))
        return report

    def test_absent_dependencies_return_useful_read_not_false_readiness(self):
        report = self.collect()
        self.assertEqual(report['status'], 'DISCOVERY_ACTIVATION_BINDINGS_READ')
        self.assertEqual(report['components']['ouf-semantic-southbound-v2']['status'], 'NAMED_CONTAINER_NOT_FOUND')
        self.assertEqual(report['components']['semantic']['credentialMount']['status'], 'NO_DECLARED_MOUNT')
        self.assertFalse(report['components']['ouf-semantic-provider']['absenceOfOtherProvidersProven'])
        self.assertEqual(len(self.calls), 10)

    def test_declared_dependency_networks_are_compared_without_connectivity_claim(self):
        for i, name in enumerate(r.DEPENDENCIES):
            self.docs[name] = doc(str(i + 1) * 64, 'sha256:' + 'a' * 64, name)
        self.docs['ouf-semantic-provider-v2']['NetworkSettings']['Networks'] = {'private': {}}
        report = self.collect()
        self.assertTrue(report['components']['ouf-semantic-southbound-v2']['sharesNetworkWithSemantic'])
        self.assertFalse(report['components']['ouf-semantic-provider-v2']['sharesNetworkWithSouthbound'])
        self.assertEqual(len(self.calls), 13)

    def test_current_application_image_drift_stops_before_dependency_inspection(self):
        self.docs['semantic']['Image'] = 'sha256:' + 'b' * 64
        with self.assertRaisesRegex(RuntimeError, 'CURRENT_APPLICATION_GENERATION_CHANGED'):
            self.collect()
        self.assertEqual(len(self.calls), 1)

    def test_observation_drift_is_not_hidden_by_mac_normalization(self):
        first = self.get
        def changing(key):
            value = first(key)
            if key == r.APPLICATIONS['semantic'][0] and len(self.calls) > 5:
                value['Config']['MacAddress'] = '02:42:ac:00:00:03'
            return value
        self.get = changing
        with self.assertRaisesRegex(RuntimeError, 'CONTAINER_CHANGED_DURING_READ'):
            self.collect()

    def test_invalid_token_endpoint_is_redacted(self):
        for url in ('https://user:SECRET@auth.ouf-lab.it/token', 'https://auth.ouf-lab.it/token?secret=SECRET', 'https://auth.ouf-lab.it:99999/token'):
            result = r.endpoint(url)
            self.assertFalse(result['validWithoutCredentialsOrExtraParts'])
            self.assertNotIn('SECRET', json.dumps(result))

    def test_metadata_never_opens_file_in_stopped_container(self):
        d = self.docs['semantic']
        d['State'].update(Running=False, Pid=0)
        module = Mock()
        self.assertEqual(r.metadata(d, '/run/key', module)['status'], 'APPLICATION_VIEW_UNAVAILABLE_STOPPED')
        module.mount_file.assert_not_called()

    def test_engine_transport_only_get_and_narrow_id_scope(self):
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_DOCKER_ID_REQUIRED'):
            r.docker_get('unrelated-container')
        response = Mock(status=404)
        response.read.return_value = b'{}'
        with patch.object(r.http.client.HTTPConnection, 'request') as request, patch.object(r.http.client.HTTPConnection, 'getresponse', return_value=response):
            self.assertIsNone(r.docker_get('ouf-semantic-provider-v2'))
            request.assert_called_once_with('GET', '/v1.44/containers/ouf-semantic-provider-v2/json')

    def test_proc_parser_and_exact_helper_hashes(self):
        import io
        r.load_helpers()
        d = self.docs['semantic']
        rows = [b'java\n', b'header\n 0: 00000000:28CB 00000000:0000 0A\n', b'header\n']
        with patch('builtins.open', side_effect=lambda *a, **k: io.BytesIO(rows.pop(0))):
            report = r.process_and_listeners(d)
        self.assertEqual(report['status'], 'READ')
        self.assertEqual(report['listeners'], [{'family': 'tcp', 'port': 10443, 'bindScope': 'wildcard'}])
        self.assertTrue(report['contentsAreNotApplicationHealth'])

    def test_proc_unavailable_is_explicit_without_raw_error(self):
        with patch('builtins.open', side_effect=FileNotFoundError('PRIVATE_DETAIL')):
            report = r.process_and_listeners(self.docs['semantic'])
        self.assertEqual(report['status'], 'READ_INCOMPLETE')
        self.assertEqual(report['reason'], 'FileNotFoundError')
        self.assertNotIn('PRIVATE_DETAIL', json.dumps(report))


if __name__ == '__main__':
    unittest.main()
