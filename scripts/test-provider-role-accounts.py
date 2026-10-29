import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

spec = importlib.util.spec_from_file_location('role_accounts', Path(__file__).with_name('provider-role-accounts.py'))
accounts = importlib.util.module_from_spec(spec); spec.loader.exec_module(accounts)

def tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, raw in entries:
            item = tarfile.TarInfo(name); item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return output.getvalue()

def fixture(layers, user='apisix', corrupt_diff=False):
    cfg = {'os': 'linux', 'architecture': 'amd64', 'config': {'User': user},
           'rootfs': {'type': 'layers', 'diff_ids': ['sha256:'+hashlib.sha256(raw).hexdigest() for raw in layers]}}
    if corrupt_diff:
        cfg['rootfs']['diff_ids'][0] = 'sha256:'+'0'*64
    raw = json.dumps(cfg).encode(); sha = hashlib.sha256(raw).hexdigest()
    paths = [f'{i}/layer.tar' for i in range(len(layers))]
    manifest = [{'Config': sha+'.json', 'Layers': paths}]
    archive = gzip.compress(tar([(sha+'.json', raw), ('manifest.json', json.dumps(manifest).encode())]+list(zip(paths, layers))))
    return io.BytesIO(archive), hashlib.sha256(archive).hexdigest(), sha

class Tests(unittest.TestCase):
    def test_named_runtime_from_verified_ordered_overlay(self):
        old = tar([('etc/passwd', b'apisix:x:636:636:old:/tmp:/bin/sh\n')])
        new = tar([('etc/passwd', b'apisix:x:10007:10008:new:/tmp:/bin/sh\n')])
        result = accounts.inspect_stream(*fixture([old, new]))
        self.assertEqual(result['runtimeUser'], '10007:10008')
        self.assertTrue(result['layerBytesVerified'])
    def test_whiteout_not_replaced_must_not_reuse_old_account(self):
        old = tar([('etc/passwd', b'apisix:x:636:636::/:/bin/sh\n')])
        gone = tar([('etc/.wh.passwd', b'')])
        with self.assertRaises(ValueError):
            accounts.inspect_stream(*fixture([old, gone]))
    def test_same_layer_whiteout_replacement(self):
        old = tar([('etc/passwd', b'apisix:x:636:636::/:/bin/sh\n')])
        new = tar([('etc/passwd', b'apisix:x:10007:10008::/:/bin/sh\n'), ('etc/.wh.passwd', b'')])
        self.assertEqual(accounts.inspect_stream(*fixture([old, new]))['runtimeUser'], '10007:10008')
    def test_wrong_diff_id_rejected_even_when_archive_config_hashes_match(self):
        with self.assertRaises(ValueError):
            accounts.inspect_stream(*fixture([tar([('etc/passwd', b'apisix:x:636:636::/:/bin/sh\n')])], corrupt_diff=True))
    def test_root_identity_rejected(self):
        with self.assertRaises(ValueError):
            accounts.inspect_stream(*fixture([tar([])], user='0:0'))
    def test_explicit_numeric_identity(self):
        self.assertEqual(accounts.inspect_stream(*fixture([tar([])], user='10006:10006'))['uid'], 10006)
    def test_opaque_directory_removes_previous_account(self):
        old = tar([('etc/passwd', b'apisix:x:636:636::/:/bin/sh\n')])
        with self.assertRaises(ValueError):
            accounts.inspect_stream(*fixture([old, tar([('etc/.wh..wh..opq', b'')])]))
    def test_duplicate_named_account_rejected(self):
        raw = b'apisix:x:636:636::/:/bin/sh\napisix:x:700:700::/:/bin/sh\n'
        with self.assertRaises(ValueError):
            accounts.inspect_stream(*fixture([tar([('etc/passwd', raw)])]))

if __name__ == '__main__':
    unittest.main()
