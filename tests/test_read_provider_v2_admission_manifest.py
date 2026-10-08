import contextlib
import io
import json
import unittest
from unittest.mock import patch
import read_provider_v2_admission_manifest as m

class Tests(unittest.TestCase):
    def test_report_never_emits_environment_arguments_or_mount_file_contents(self):
        secret = 'PRIVATE_OIDC_SENTINEL_DO_NOT_PRINT'
        policy = {'schema': 'ouf.semantic-configured-creation-frame-policy.v1',
            'expectedOci': {'process': {'user': {'uid': 10006, 'gid': 10006}, 'env': ['TOKEN=' + secret], 'args': [secret]},
                'root': {'path': '/var/lib/docker/rootfs/overlayfs/cid', 'readonly': True},
                'linux': {'resources': {'memory': {'limit': 268435456}, 'pids': {'limit': 128}}}, 'mounts': []},
            'manifest': {}, 'startup': {'args': [secret]}, 'approvedHooks': {}, 'sources': [{'content': secret}]}
        files = {m.PROFILE: {'schema': 'ouf.semantic-existing-installation-authority-bindings.v1', 'authorities': {}, 'keyRefs': {}, 'keyBindings': {}, 'policyBinding': {}}}
        for role in m.HASHES:
            files[m.ROOT / (role + '.policy.json')] = policy
            files[m.ROOT / (role + '.template.json')] = {'expectedOci': policy['expectedOci']}
            files[m.ROOT / (role + '.context.json')] = {'containerId': role}
        reads = []
        def read(path, sha): reads.append(path); return m.encoded(files[path])
        out = io.StringIO()
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'read', side_effect=read), contextlib.redirect_stdout(out): m.main()
        self.assertNotIn(secret, out.getvalue())
        self.assertEqual(set(reads), set(files))
        value = json.loads(out.getvalue().split('=', 1)[1])
        self.assertFalse(value['startAuthorized']); self.assertFalse(value['acceptanceGranted'])
        self.assertEqual(value['privateKeyFilesRead'], 0)
    def test_nonroot_rejected_before_any_file_read(self):
        with patch.object(m.os, 'geteuid', return_value=1000), patch.object(m, 'read') as read:
            with self.assertRaisesRegex(ValueError, 'ROOT_REQUIRED'): m.main()
            read.assert_not_called()
    def test_snapshot_changed_during_second_read_rejected(self):
        # Fails on the first bound policy read, never moves on to authority/key IO.
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'read', side_effect=ValueError('PRIVATE_FILE_HASH_DRIFT')) as read:
            with self.assertRaisesRegex(ValueError, 'PRIVATE_FILE_HASH_DRIFT'): m.main()
            self.assertEqual(read.call_count, 1)
if __name__ == '__main__': unittest.main()
