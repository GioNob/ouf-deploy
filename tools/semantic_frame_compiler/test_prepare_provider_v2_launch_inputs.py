import copy
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import Mock

import prepare_provider_v2_launch_inputs as p


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.spec = {'role': 'adapter', 'uid': 10006, 'gid': 10006, 'user': '10006:10006',
                     'command': ['--configuration', '/run/adapter.json'], 'readOnlyRoot': True,
                     'memoryBytes': 268435456, 'pidsLimit': 128,
                     'mounts': [{'source': '/sealed/config.json', 'target': '/run/adapter.json',
                                 'uid': 10006, 'gid': 10006, 'mode': 0o600, 'sha256': 'a' * 64}]}
        self.image = {'Entrypoint': ['python3', '-B', '-m', 'tools.semantic_provider_adapter'],
                      'Cmd': ['unexpected-image-default'], 'WorkingDir': '/app'}

    def test_image_entrypoint_and_explicit_command_override(self):
        result = p.launch_from_spec(self.spec, self.image, {'PATH': '/image/path', 'SECRET': 'PRIVATE_VALUE'})
        self.assertEqual(result['startup']['args'], self.image['Entrypoint'] + self.spec['command'])
        self.assertEqual(result['startup']['env'], ['PATH=/image/path', 'HOSTNAME=$OUF_HOSTNAME', 'SECRET=PRIVATE_VALUE'])
        self.assertTrue(result['sources'][0]['readOnly'])
        self.assertEqual(self.image['Cmd'], ['unexpected-image-default'])

    def test_image_hostname_cannot_override_transaction_identity(self):
        with self.assertRaisesRegex(p.Denied, 'HOSTNAME'):
            p.launch_from_spec(self.spec, self.image, {'HOSTNAME': 'other-candidate'})

    def test_root_user_and_relative_workdir_rejected(self):
        for spec, image in [({**self.spec, 'uid': 0, 'user': '0:10006'}, self.image),
                            (self.spec, {**self.image, 'WorkingDir': 'relative'})]:
            with self.assertRaises(p.Denied):
                p.launch_from_spec(spec, image, {})

    def test_writable_source_custody_and_unbounded_secret_rejected(self):
        bad = copy.deepcopy(self.spec); bad['mounts'][0]['mode'] = 0o666
        with self.assertRaises(p.Denied):
            p.launch_from_spec(bad, self.image, {})
        with self.assertRaisesRegex(p.Denied, 'UNBOUNDED'):
            p.launch_from_spec(self.spec, self.image, {'SECRET': 'x' * 131073})

    def fixture(self):
        specs = [copy.deepcopy(self.spec), {**copy.deepcopy(self.spec), 'role': 'southbound'}]
        receipt = {'status': 'CREATED_STOPPED_AND_READBACK_VERIFIED', 'sourceHash': p.READER_HASH,
                   'startAuthorized': False, 'candidates': [
                       {'role': role, 'containerId': cid, 'imageId': image} for role, (cid, image) in p.TARGETS.items()]}
        raw = p.encoded(receipt); source = b'private application configuration'
        for spec in specs:
            spec['mounts'][0]['sha256'] = p.digest(source)
        def private(path, *args):
            return raw if Path(path).name == 'creation-receipt.json' else source
        reader = types.SimpleNamespace(snapshot=Mock(return_value={'existing': 'running', 'candidates': 'created'}),
            private=Mock(side_effect=private), prepare=Mock(return_value=(specs, {})),
            namespace=Mock(), TRUST=Path('/sealed/trust'), ACCOUNT_HASH='a' * 64,
            verify_retained=Mock(return_value={role: {'configuration': {'config': self.image}} for role in p.TARGETS}),
            resolved_image=Mock(side_effect=lambda ns, spec, proof: {**spec, 'imageId': p.TARGETS[spec['role']][1]}),
            image=Mock(return_value={'Config': self.image}), verify_container=Mock(), environment=Mock(return_value={'SECRET': 'PRIVATE'}))
        ns = types.SimpleNamespace(parse=json.loads)
        return reader, ns

    def test_collect_is_read_only_and_uses_exact_successful_transaction(self):
        reader, ns = self.fixture()
        result = p.collect(reader, ns)
        self.assertEqual(set(result), {'adapter', 'southbound'})
        self.assertEqual(reader.verify_container.call_count, 2)
        for call in reader.verify_container.call_args_list:
            self.assertEqual(call.args[-1], 'semantic-provider-v2-stopped-resume-k5mmsudx')
            self.assertIn(call.args[2], [x[0] for x in p.TARGETS.values()])

    def test_collect_rejects_existing_container_state_drift(self):
        reader, ns = self.fixture(); reader.snapshot.side_effect = [{'old': 'running'}, {'old': 'exited'}]
        with self.assertRaisesRegex(p.Denied, 'CONTAINER_STATE_CHANGED'):
            p.collect(reader, ns)

    def test_collect_rejects_mount_byte_drift_before_return(self):
        reader, ns = self.fixture()
        original = reader.private.side_effect
        calls = 0
        def drift(path, *args):
            nonlocal calls
            if str(path) == '/sealed/config.json':
                calls += 1
                if calls > 2:
                    return b'changed'
            return original(path, *args)
        reader.private.side_effect = drift
        with self.assertRaisesRegex(p.Denied, 'MOUNT_SOURCE_CHANGED'):
            p.collect(reader, ns)


if __name__ == '__main__':
    unittest.main()
