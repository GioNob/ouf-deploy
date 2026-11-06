import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/storage-cold-backup.py'
spec = importlib.util.spec_from_file_location('cold_backup', SCRIPT)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def container(cid, root, running=False):
    return {'Id': cid, 'Image': 'sha256:' + 'b' * 64, 'Config': {'Labels': {}, 'Env': ['SECRET=private']},
            'Path': '/server', 'Args': [], 'Mounts': [{'Type': 'bind', 'Source': str(root), 'Destination': '/data', 'RW': True}],
            'HostConfig': {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'AutoRemove': False},
            'State': {'StartedAt': '2026-11-06T00:00:00Z', 'Running': running, 'Pid': 1 if running else 0,
                      'Status': 'running' if running else 'exited', 'ExitCode': 0, 'OOMKilled': False,
                      'Error': '', 'Paused': False, 'Restarting': False}}


class ColdBackupTests(unittest.TestCase):
    def setUp(self):
        # Stay under the workspace: /tmp is deliberately rejected as a durable source.
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.data.mkdir()
        (self.data / 'content').write_bytes(b'private backup fixture\x00' * 50)
        self.area = self.root / 'output'
        self.area.mkdir()
        self.cid = 'a' * 64
        self.host = {self.cid: container(self.cid, self.data)}
        self.bindings = {'postgres': {'containerId': self.cid, 'nativeImage': 'sha256:' + 'b' * 64}}
        self.plan = b.build_plan(self.bindings, self.host, self.area, 'c' * 64)
        self.until = time.monotonic() + 30

    def tearDown(self):
        self.temp.cleanup()

    def test_plan_does_not_contain_environment_or_mutation_commands(self):
        self.assertNotIn('SECRET', json.dumps(self.plan))
        self.assertEqual(self.plan['runtimeMutationCommands'], [])
        b.offline(self.plan, self.host)

    def test_active_or_unclean_provider_is_rejected(self):
        for field, value in [('Running', True), ('ExitCode', 137), ('OOMKilled', True), ('Pid', 8)]:
            with self.subTest(field=field):
                host = copy.deepcopy(self.host)
                host[self.cid]['State'][field] = value
                with self.assertRaises(b.Held):
                    b.offline(self.plan, host)

    def test_restart_policy_and_generation_are_not_admission(self):
        host = copy.deepcopy(self.host)
        host[self.cid]['HostConfig']['RestartPolicy']['Name'] = 'always'
        with self.assertRaises(b.Held):
            b.offline(self.plan, host)

    def test_sigterm_application_exit_is_not_clean_provider_or_drain_proof(self):
        host = copy.deepcopy(self.host)
        host[self.cid]['State']['ExitCode'] = 143
        with self.assertRaises(b.Held):
            b.offline(self.plan, host)
        plan = copy.deepcopy(self.plan)
        plan['roles']['onboarding'] = plan['roles'].pop('postgres')
        b.offline(plan, host)
        self.assertFalse(plan['runtimeAuthorityIssued'])
        host = copy.deepcopy(self.host)
        host[self.cid]['State']['StartedAt'] = 'changed-generation'
        with self.assertRaises(b.Held):
            b.offline(self.plan, host)

    def test_new_or_shared_writer_rejected(self):
        other = container('d' * 64, self.data, running=True)
        with self.assertRaises(b.Held):
            b.build_plan(self.bindings, self.host | {other['Id']: other}, self.area, 'c' * 64)
        other['State']['Running'] = False
        with self.assertRaises(b.Held):
            b.build_plan(self.bindings, self.host | {other['Id']: other}, self.area, 'c' * 64)

    def test_writable_layer_config_change_rejected(self):
        host = copy.deepcopy(self.host)
        host[self.cid]['Config']['Env'].append('OVERRIDE=changed')
        with self.assertRaises(b.Held):
            b.offline(self.plan, host)

    def test_archive_bytes_metadata_and_symlinks_read_back(self):
        os.symlink('content', self.data / 'internal-link')
        os.link(self.data / 'content', self.data / 'hardlink')
        os.setxattr(self.data / 'content', 'user.ouf', b'custody')
        expected = b.tree_manifest(self.data, self.until)
        archive = self.area / 'source.tar'
        subprocess.run(['tar', '--create', '--format=pax', '--numeric-owner', '--acls', '--xattrs',
                        '--xattrs-include=*', '--sparse', '-f', str(archive), '-C', str(self.data.parent), self.data.name], check=True)
        b.verify_source_archive(archive, self.data.name, expected, self.until)
        self.assertEqual(expected, b.tree_manifest(self.data, self.until))
        restored = self.area / 'restore'
        restored.mkdir()
        subprocess.run(['tar', '--extract', '--acls', '--xattrs', '--xattrs-include=*', '-f', str(archive), '-C', str(restored)], check=True)
        self.assertEqual((restored / 'data/content').read_bytes(), (self.data / 'content').read_bytes())
        self.assertEqual(os.getxattr(restored / 'data/content', 'user.ouf'), b'custody')
        self.assertEqual(os.readlink(restored / 'data/internal-link'), 'content')

    def test_archive_tampering_rejected_even_with_valid_tar(self):
        expected = b.tree_manifest(self.data, self.until)
        (self.data / 'content').write_bytes(b'substitution')
        archive = self.area / 'source.tar'
        subprocess.run(['tar', '-cf', str(archive), '-C', str(self.data.parent), self.data.name], check=True)
        with self.assertRaises(b.Held):
            b.verify_source_archive(archive, self.data.name, expected, self.until)

    def test_external_symlink_fifo_and_backup_recursion_rejected(self):
        os.symlink('/etc/passwd', self.data / 'external')
        with self.assertRaises(b.Held):
            b.tree_manifest(self.data, self.until)
        (self.data / 'external').unlink()
        os.mkfifo(self.data / 'fifo')
        with self.assertRaises(b.Held):
            b.tree_manifest(self.data, self.until)
        with self.assertRaises(b.Held):
            b.build_plan(self.bindings, self.host, self.data / 'backup', 'c' * 64)

    def test_durable_claim_cannot_be_replayed_or_overwritten(self):
        path = self.area / 'claim'
        b.new(path, b'first')
        with self.assertRaises(FileExistsError):
            b.new(path, b'second')
        self.assertEqual(path.read_bytes(), b'first')

    def test_recipient_is_single_public_key_not_private_key(self):
        self.assertTrue(b.recipient(b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICf/Mm fixture').startswith('ssh-ed25519'))
        for raw in [b'-----BEGIN OPENSSH PRIVATE KEY-----', b'ssh-ed25519 AAAA\nssh-rsa BBBB', b'ecdsa-sha2-nistp256 AAAA']:
            with self.assertRaises(b.Held):
                b.recipient(raw)

    def test_expired_plan_denied_before_any_provider_request(self):
        self.plan['validUntilEpoch'] = 1
        with self.assertRaises(b.Held):
            b.capture(self.plan, b.digest(b.canonical(self.plan)), self.area, None, 'recipient', 'decision')
        self.assertFalse((self.area / 'capture-claim.private.json').exists())


if __name__ == '__main__':
    unittest.main()
