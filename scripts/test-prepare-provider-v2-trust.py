import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import ssl
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('trust', Path(__file__).with_name('prepare-provider-v2-trust.py'))
trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)

class Tests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'Run this bounded root-file fixture as root.')
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.public = Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
        self.openssl = Path(shutil.which('openssl'))
        self.roles = [{'role': role, 'uid': ids[0], 'gid': ids[1], 'layerBytesVerified': True} for role, ids in trust.IDS.items()]
    def test_real_keys_leaf_pairs_hostname_refusal_and_role_owned_files(self):
        hashes = trust.make_trust(self.root, self.roles, self.public, self.openssl)
        self.assertEqual(len(hashes), 9)
        keys = []
        for row in self.roles:
            for name in ('server.key', 'server.crt', 'provider-receipt.key'):
                path = self.root/row['role']/name; info = path.stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (row['uid'], row['gid'], 0o600))
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), hashes[row['role']+'/'+name])
            keys.append((self.root/row['role']/'provider-receipt.key').read_bytes())
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(len(keys[0]), 64)
        self.assertEqual(stat.S_IMODE((self.root/'trust-bundle.pem').stat().st_mode), 0o644)
        self.assertNotIn(b'PRIVATE KEY', (self.root/'trust-bundle.pem').read_bytes())
        ssl.create_default_context(cadata=(self.root/'trust-bundle.pem').read_text())
    def test_existing_key_preserved_before_any_new_certificate(self):
        trust.write(self.root/'ca.key', b'preserved')
        with self.assertRaises(ValueError):
            trust.make_trust(self.root, self.roles, self.public, self.openssl)
        self.assertEqual((self.root/'ca.key').read_bytes(), b'preserved')
        self.assertFalse((self.root/'ca.crt').exists())
    def test_wrong_southbound_uid_refused_before_key_generation(self):
        self.roles[1]['uid'] = 10006
        with self.assertRaises(ValueError):
            trust.make_trust(self.root, self.roles, self.public, self.openssl)
        self.assertEqual(list(self.root.iterdir()), [])
    def test_private_key_in_public_input_refused_without_publication(self):
        with self.assertRaises(ValueError):
            trust.make_trust(self.root, self.roles, self.public+b'PRIVATE KEY', self.openssl)
        self.assertEqual(list(self.root.iterdir()), [])
    def test_existing_symbolic_output_refused_without_following(self):
        (self.root/'ca.key').symlink_to('/nonexistent-ouffile')
        with self.assertRaises(ValueError):
            trust.make_trust(self.root, self.roles, self.public, self.openssl)
        self.assertTrue((self.root/'ca.key').is_symlink())
        self.assertFalse((self.root/'ca.crt').exists())
    def test_read_rejects_world_readable_private_file(self):
        trust.write(self.root/'private', b'no-secret-fixture', mode=0o644)
        with self.assertRaises(ValueError):
            trust.read(self.root/'private')
    def test_replay_does_not_replace_first_tls_generation(self):
        first = trust.make_trust(self.root, self.roles, self.public, self.openssl)
        with self.assertRaises(ValueError):
            trust.make_trust(self.root, self.roles, self.public, self.openssl)
        self.assertEqual(hashlib.sha256((self.root/'ca.key').read_bytes()).hexdigest(), first['ca.key'])

if __name__ == '__main__':
    unittest.main()
