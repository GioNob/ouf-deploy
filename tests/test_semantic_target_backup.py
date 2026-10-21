import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

script = Path(__file__).resolve().parent / 'backup-semantic-target.py'
if not script.exists():
    script = Path(__file__).resolve().parents[1] / 'scripts/backup-semantic-target.py'
spec = importlib.util.spec_from_file_location('backup', script)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def fixture():
    semantic = {'Image': backup.SEMANTIC_IMAGE, 'State': {'Running': True},
                'Mounts': [{'Destination': p, 'RW': False} for p in ('/run/ouf-semantic-auth', '/run/secrets/semantic-read-owner.key')],
                'Config': {'Env': ['OUF_SEM_DB_URL=jdbc:postgresql://ouf-postgres:5432/test_db',
                                   'OUF_SEM_DB_USER=semantic', 'OUF_SEM_DB_PASSWORD=fixture-secret']},
                'NetworkSettings': {'Networks': {'backend': {'NetworkID': 'net'}}}}
    postgres = {'Image': backup.POSTGRES_IMAGE, 'State': {'Running': True},
                'NetworkSettings': {'Networks': {'backend': {'NetworkID': 'net', 'Aliases': ['ouf-postgres'], 'IPAddress': '172.31.1.2'}}}}
    return semantic, postgres


class BoundBackupTests(unittest.TestCase):
    def test_installed_binding(self):
        self.assertEqual(backup.binding(*fixture()), ('test_db', 'semantic', b'fixture-secret\n'))

    def test_foreign_endpoint_and_network_rejected(self):
        for endpoint in ('foreign', 'ouf-postgres:5555', 'user:password@ouf-postgres', 'ouf-postgres/test/extra'):
            s, p = fixture()
            s['Config']['Env'][0] = 'OUF_SEM_DB_URL=jdbc:postgresql://' + endpoint + '/test_db'
            with self.assertRaises(RuntimeError):
                backup.binding(s, p)
        s, p = fixture()
        p['NetworkSettings']['Networks']['backend']['NetworkID'] = 'foreign'
        with self.assertRaises(RuntimeError):
            backup.binding(s, p)

    def test_changed_image_and_writable_mount_rejected(self):
        s, p = fixture()
        for target, key, value in ((s, 'Image', 'foreign'), (p, 'Image', 'foreign')):
            old = target[key]; target[key] = value
            with self.assertRaises(RuntimeError):
                backup.binding(s, p)
            target[key] = old
        s['Mounts'][0]['RW'] = True
        with self.assertRaises(RuntimeError):
            backup.binding(s, p)

    def test_credential_is_stdin_only_and_read_only_transaction(self):
        with patch.object(backup, 'call', return_value=b'') as invoke:
            backup.pg('container', 'pg_dump', ['--schema=ouf_sem'], b'fixture-secret\n')
        argv, credential, _, _ = invoke.call_args.args
        self.assertNotIn('fixture-secret', ' '.join(argv))
        self.assertEqual(credential, b'fixture-secret\n')
        self.assertIn('default_transaction_read_only=on', ' '.join(argv))

    def test_multiline_credentials_rejected(self):
        s, p = fixture()
        s['Config']['Env'][-1] = 'OUF_SEM_DB_PASSWORD=one\ntwo'
        with self.assertRaises(RuntimeError):
            backup.binding(s, p)


if __name__ == '__main__':
    unittest.main()
