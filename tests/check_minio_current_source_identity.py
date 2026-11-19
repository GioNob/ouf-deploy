"""Current-copy source credential selection: synthetic files only, no service calls."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('copy_command', Path(sys.argv[1]))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ExistingSourceIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'work').mkdir()
        root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        cwd = os.open(self.root / 'work', os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.binding = m.InputBinding(0, root, cwd)
        finally:
            os.close(root); os.close(cwd)
        self.addCleanup(self.binding.close)

    def file(self, name, body):
        p = self.root / name
        p.parent.mkdir(exist_ok=True, parents=True)
        p.write_bytes(body)
        return p

    def resolve(self, env):
        self.binding.preflight(env)
        return self.binding.resolve(env)

    def test_declared_env_survives_missing_image_default_files(self):
        values, meta = self.resolve({'MINIO_ROOT_USER': 'existing-admin',
            'MINIO_ROOT_PASSWORD': 'existing-secret', 'MINIO_ROOT_USER_FILE': 'access_key',
            'MINIO_ROOT_PASSWORD_FILE': 'secret_key', 'MINIO_CONFIG_ENV_FILE': 'config.env'})
        self.assertEqual(values, [b'existing-admin', b'existing-secret'])
        self.assertNotIn('existing-secret', json.dumps(meta))

    def test_current_secret_files_then_literal_config_win(self):
        self.file('run/secrets/legacy', b'legacy-user')
        self.file('run/secrets/keys/user', b'current-user\n').chmod(0o644)
        self.file('keys/user', b'fallback-user')
        self.file('work/config.env', b'export MINIO_ROOT_USER="config-user"\n'
            b'MINIO_ROOT_PASSWORD=$(literal-only)\nMINIO_REGION_NAME=eu-west-1\n'
            b'MINIO_API_ROOT_ACCESS=off\n')
        values, meta = self.resolve({'MINIO_ACCESS_KEY_FILE': 'legacy',
            'MINIO_ROOT_USER_FILE': '/keys/user', 'MINIO_ROOT_PASSWORD': 'env-secret',
            'MINIO_CONFIG_ENV_FILE': 'config.env'})
        self.assertEqual(values, [b'config-user', b'$(literal-only)'])
        self.assertEqual(self.binding.region, 'eu-west-1')
        self.assertEqual(self.binding.root_access, 'off')
        self.assertEqual(meta['selectedSources'], ['DECLARED_CONFIG_ENV'] * 2)
        self.assertFalse((self.root / 'work/literal-only').exists())

    def test_no_default_credentials_or_partial_pair(self):
        for env in ({}, {'MINIO_ROOT_USER': 'only-user'}):
            with self.assertRaises(RuntimeError):
                self.resolve(env)

    def test_symlink_rejected(self):
        real = self.file('keys/user', b'synthetic')
        (self.root / 'work/link').symlink_to(real)
        with self.assertRaises(RuntimeError):
            self.resolve({'MINIO_ROOT_USER_FILE': 'link', 'MINIO_ROOT_PASSWORD': 'synthetic'})

    def test_changed_file_rejected(self):
        p = self.file('keys/user', b'synthetic')
        self.resolve({'MINIO_ROOT_USER_FILE': '/keys/user', 'MINIO_ROOT_PASSWORD': 'synthetic'})
        p.write_bytes(b'changed')
        with self.assertRaises(RuntimeError):
            self.binding.stable()

    def test_public_wrapper_uses_minio_configuration_and_stops_if_disabled(self):
        # The local sandbox has no /proc/<pid>/root. Only replace that filesystem anchor.
        original = m.InputBinding
        def fixture_binding(pid):
            self.assertEqual(pid, 12345)
            return original(0, self.binding.root, self.binding.cwd)
        m.InputBinding = fixture_binding
        self.addCleanup(setattr, m, 'InputBinding', original)
        container = {'State': {'Pid': 12345}, 'Config': {'Env': [
            'MINIO_ROOT_USER=synthetic-existing', 'MINIO_ROOT_PASSWORD=synthetic-secret',
            'MINIO_API_ROOT_ACCESS=on']}}
        report = {}
        values, region = m.source_credentials(container, report)
        self.assertEqual(values, ('synthetic-existing', 'synthetic-secret'))
        self.assertEqual(region, 'us-east-1')
        self.assertNotIn('synthetic', json.dumps(report))
        container['Config']['Env'][-1] = 'MINIO_API_ROOT_ACCESS=off'
        with self.assertRaisesRegex(RuntimeError, '^MINIO_ROOT_API_NOT_ENABLED_BY_DECLARATION$'):
            m.source_credentials(container, {})


unittest.main(argv=[sys.argv[0]])
