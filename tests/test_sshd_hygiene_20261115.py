"""Portable fault tests; real sshd only with OUF_SSHD_HYGIENE_NATIVE=1 and root."""
from contextlib import ExitStack, nullcontext
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/apply-sshd-hygiene-20261115.py'
SPEC = importlib.util.spec_from_file_location('sshd_hygiene', SCRIPT)
h = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = h
SPEC.loader.exec_module(h)
REAL_RUN = subprocess.run


def fixture(root, binary, native=False):
    dropdir = root / 'sshd_config.d'
    dropdir.mkdir()
    dropin = dropdir / '00-ouf-hardening.conf'
    dropin.write_bytes(b'PermitRootLogin no\nPasswordAuthentication no\n'
                       b'KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n')
    include = ('Include ' + dropdir.as_posix() + '/*.conf\n').encode()
    lines = [b'# fixture\n'] * 125
    lines[11] = include
    lines[122:] = [b'\n', b'PasswordAuthentication yes\n', b'PermitRootLogin yes\n']
    if native:
        key = root / 'host_key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        lines[0] = f'HostKey {key}\n'.encode()
        lines[1] = f'PidFile {root}/sshd.pid\n'.encode()
    config = root / 'sshd_config'
    config.write_bytes(b''.join(lines))
    config.chmod(0o644)
    dropin.chmod(0o644)
    return h.Settings(config=config, dropin=dropin, sshd=binary,
                      snapshot=root / 'snapshots' / 'sshd-hygiene-20261115',
                      base_sha256=h.sha(config.read_bytes()), dropin_sha256=h.sha(dropin.read_bytes()),
                      sshd_sha256=h.sha(binary.read_bytes()), include=include)


class Portable(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        binary = root / 'fake-sshd'
        binary.write_bytes(b'fake sshd executable\n')
        self.s = fixture(root, binary)
        self.original = self.s.config.read_bytes()
        self.events = []
        self.diverge = False
        self.real_checked = h.checked_file
        self.stack.enter_context(patch.object(h.os, 'geteuid', return_value=0, create=True))
        self.stack.enter_context(patch.object(h.os, 'fchown', create=True))
        if not hasattr(h.os, 'fchmod'):
            self.stack.enter_context(patch.object(h.os, 'fchmod', create=True))
        self.stack.enter_context(patch.object(h, 'safe_parents'))
        self.stack.enter_context(patch.object(h, 'private_directory'))
        self.stack.enter_context(patch.object(h, 'fsync_directory'))
        self.stack.enter_context(patch.object(h, 'apply_lock', return_value=nullcontext()))
        self.stack.enter_context(patch.object(h, 'checked_file', side_effect=self.checked))
        self.stack.enter_context(patch.object(h.subprocess, 'run', side_effect=self.fake_sshd))
        real_save = h.save
        real_replace = h.atomic_replace

        def save(path, data):
            self.events.append('snapshot' if path.name == 'original' else path.name)
            return real_save(path, data)

        def rename(settings, data):
            self.events.append('rename')
            return real_replace(settings, data)

        self.stack.enter_context(patch.object(h, 'save', side_effect=save))
        self.stack.enter_context(patch.object(h, 'atomic_replace', side_effect=rename))

    def checked(self, path, digest, mode):
        if path == self.s.config and 'rename' in self.events:
            self.events.append('readback')
        data = path.read_bytes()
        h.require(h.sha(data) == digest, 'FILE_HASH_DRIFT')
        return data

    def fake_sshd(self, args, **kwargs):
        self.assertEqual(args[0], str(self.s.sshd))
        self.assertEqual(args[2], '-f')
        self.assertEqual(kwargs['timeout'], 30)
        data = Path(args[3]).read_bytes()
        output = b'passwordauthentication no\npermitrootlogin no\n'
        if self.diverge and b'(ouf task-45)' in data:
            output += b'drift\n'
        return subprocess.CompletedProcess(args, 0, output if args[1] == '-T' else b'', b'')

    def plan(self, restore=False):
        result, code = h.execute(self.s, restore=restore)
        self.assertEqual(code, 0, result)
        return result

    def apply(self):
        return h.execute(self.s, True, self.plan()['planSha256'])

    def test_plan_deterministic_and_byte_preservation(self):
        first = self.plan()
        self.assertEqual(first, self.plan())
        self.assertTrue(first['effectiveEqual'])
        self.assertEqual(first['targetSha256'], h.sha(b''.join(self.original.splitlines(True)[:123]) + h.COMMENTS))
        self.assertIn('-PasswordAuthentication yes', first['diff'])
        self.assertFalse(self.s.snapshot.exists())
        self.assertEqual(self.s.config.read_bytes(), self.original)

    def test_all_pins_deny_without_snapshot(self):
        for name in ('base_sha256', 'dropin_sha256', 'sshd_sha256'):
            with self.subTest(name=name):
                result, code = h.execute(replace(self.s, **{name: '0' * 64}), True, '0' * 64)
                self.assertEqual(code, 1)
                self.assertEqual(result['code'], 'FILE_HASH_DRIFT')
                self.assertFalse(result['doNotRerunApply'])
                self.assertFalse(self.s.snapshot.exists())

    def test_layout_include_and_match_deny_even_with_injected_hash(self):
        for old, new in ((b'PermitRootLogin yes', b'PermitRootLogin no'),
                         (self.s.include, b'# no include\n'),
                         (b'# fixture\n', b'Match all\n')):
            with self.subTest(new=new):
                data = self.original.replace(old, new, 1)
                self.s.config.write_bytes(data)
                result, code = h.execute(replace(self.s, base_sha256=h.sha(data)))
                self.assertEqual(code, 1)
                self.assertIn(result['code'], ('CONFIG_LAYOUT_DRIFT', 'MATCH_NOT_ALLOWED'))
        self.assertFalse(self.s.snapshot.exists())

    def test_effective_drift(self):
        self.diverge = True
        result, code = h.execute(self.s)
        self.assertEqual((code, result['code']), (1, 'EFFECTIVE_CONFIG_CHANGED'))
        self.assertFalse(self.s.snapshot.exists())

    def test_digest_drift(self):
        result, code = h.execute(self.s, True, '0' * 64)
        self.assertEqual((code, result['code']), (1, 'PLAN_DIGEST_MISMATCH'))
        self.assertFalse(result['doNotRerunApply'])
        self.assertFalse(self.s.snapshot.exists())

    def test_apply_order_and_restore(self):
        result, code = self.apply()
        self.assertEqual(code, 0, result)
        self.assertLess(self.events.index('snapshot'), self.events.index('rename'))
        self.assertLess(self.events.index('rename'), self.events.index('readback'))
        self.assertEqual((self.s.snapshot / 'original').read_bytes(), self.original)
        self.assertEqual(json.loads((self.s.snapshot / 'result.json').read_bytes())['status'], 'APPLIED')
        digest = self.plan(restore=True)['planSha256']
        result, code = h.execute(self.s, True, digest, True)
        self.assertEqual((code, result['status']), (0, 'RESTORED'))
        self.assertEqual(self.s.config.read_bytes(), self.original)
        self.assertEqual(h.execute(self.s, True, self.plan()['planSha256'])[0]['code'], 'OPERATION_ALREADY_CLAIMED')

    def test_ambiguous_failure_and_restart_fence(self):
        digest = self.plan()['planSha256']
        with patch.object(h, 'atomic_replace', side_effect=OSError('private details')):
            result, code = h.execute(self.s, True, digest)
        self.assertEqual(code, 1)
        self.assertTrue(result['doNotRerunApply'])
        self.assertNotIn('private details', json.dumps(result))
        self.assertTrue((self.s.snapshot / 'failure.json').exists())
        result, code = h.execute(self.s, True, digest)
        self.assertEqual(result['code'], 'OPERATION_ALREADY_CLAIMED')
        self.assertTrue(result['doNotRerunApply'])

    def test_failure_after_rename_can_be_restored(self):
        digest = self.plan()['planSha256']
        real = h.atomic_replace

        def late_error(settings, data):
            real(settings, data)
            raise OSError('fsync uncertain')

        with patch.object(h, 'atomic_replace', side_effect=late_error):
            result, code = h.execute(self.s, True, digest)
        self.assertEqual(code, 1)
        self.assertTrue(result['doNotRerunApply'])
        result, code = h.execute(self.s, True, self.plan(True)['planSha256'], True)
        self.assertEqual((code, result['status']), (0, 'RESTORED'))

    def test_restore_snapshot_corruption(self):
        self.assertEqual(self.apply()[1], 0)
        (self.s.snapshot / 'original').write_bytes(b'corrupt')
        result, code = h.execute(self.s, restore=True)
        self.assertEqual((code, result['code']), (1, 'FILE_HASH_DRIFT'))

    def test_root_required(self):
        with patch.object(h.os, 'geteuid', return_value=1000):
            result, code = h.execute(self.s)
        self.assertEqual((code, result['code']), (1, 'ROOT_REQUIRED'))

    def test_metadata_denials_portable(self):
        from stat import S_IFREG, S_IFLNK
        for mode, uid, gid, links in ((S_IFREG | 0o666, 0, 0, 1),
                                      (S_IFREG | 0o644, 1, 0, 1),
                                      (S_IFREG | 0o644, 0, 1, 1),
                                      (S_IFREG | 0o644, 0, 0, 2),
                                      (S_IFLNK | 0o644, 0, 0, 1)):
            info = SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_nlink=links)
            with patch.object(Path, 'lstat', return_value=info):
                with self.assertRaisesRegex(h.Denied, 'FILE_METADATA_DRIFT'):
                    self.real_checked(self.s.config, self.s.base_sha256, 0o644)

    def test_revalidation_after_snapshot_before_rename(self):
        digest = self.plan()['planSha256']
        real_save = h.save

        def changed(path, data):
            real_save(path, data)
            if path.name == 'original':
                self.s.dropin.write_bytes(b'# drift\n')

        with patch.object(h, 'save', side_effect=changed):
            result, code = h.execute(self.s, True, digest)
        self.assertEqual((code, result['code']), (1, 'FILE_HASH_DRIFT'))
        self.assertTrue(result['doNotRerunApply'])
        self.assertNotIn('rename', self.events)
        self.assertEqual(self.s.config.read_bytes(), self.original)

    def test_sshd_timeout_and_syntax_failure_are_safe(self):
        for failure in (subprocess.TimeoutExpired('sshd', 30),
                        subprocess.CompletedProcess([], 1, b'', b'sensitive detail')):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(h.subprocess, 'run', **({'side_effect': failure} if isinstance(failure, Exception)
                                                        else {'return_value': failure})):
                    result, code = h.execute(self.s)
                self.assertEqual(code, 1)
                self.assertIn(result['code'], ('SSHD_TIMEOUT', 'SSHD_VALIDATION_FAILED'))
                self.assertFalse(result['doNotRerunApply'])
                self.assertNotIn('sensitive', json.dumps(result))

    def test_readback_effective_failure_is_durable(self):
        digest = self.plan()['planSha256']
        real_call = h.sshd_call

        def readback_drift(settings, flag, config):
            if 'rename' in self.events and flag == '-T':
                return b'changed\n'
            return real_call(settings, flag, config)

        with patch.object(h, 'sshd_call', side_effect=readback_drift):
            result, code = h.execute(self.s, True, digest)
        self.assertEqual((code, result['code']), (1, 'READBACK_EFFECTIVE_CHANGED'))
        self.assertTrue(result['doNotRerunApply'])
        self.assertFalse((self.s.snapshot / 'result.json').exists())
        self.assertTrue((self.s.snapshot / 'failure.json').exists())

    def test_cli_invalid_arguments_public_json(self):
        for args in ([], ['--plan', '--apply'], ['--apply', '--plan-sha256', 'bad']):
            result = REAL_RUN([sys.executable, '-B', str(SCRIPT), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(json.loads(result.stdout)['code'], ('INVALID_ARGUMENTS', 'INVALID_PLAN_DIGEST'))
            self.assertEqual(result.stderr, b'')


@unittest.skipUnless(os.environ.get('OUF_SSHD_HYGIENE_NATIVE') == '1', 'native gate disabled')
class Native(unittest.TestCase):
    def test_real_sshd_roundtrip(self):
        self.assertEqual(os.geteuid(), 0, 'native test requires sudo')
        binary = Path(shutil.which('sshd') or '/usr/sbin/sshd')
        self.assertTrue(binary.is_file(), 'install openssh-server')
        with tempfile.TemporaryDirectory(prefix='ouf-sshd-hygiene-', dir='/var/lib') as directory:
            s = fixture(Path(directory), binary, native=True)
            original = s.config.read_bytes()
            before = h.sshd_call(s, '-T', s.config)
            plan, code = h.execute(s)
            self.assertEqual(code, 0, plan)
            result, code = h.execute(s, True, plan['planSha256'])
            self.assertEqual((code, result['status']), (0, 'APPLIED'))
            self.assertEqual(h.sshd_call(s, '-T', s.config), before)
            self.assertEqual(s.config.stat().st_mode & 0o777, 0o644)
            self.assertEqual(s.snapshot.stat().st_mode & 0o777, 0o700)
            self.assertEqual((s.snapshot / 'original').stat().st_mode & 0o777, 0o600)
            plan, code = h.execute(s, restore=True)
            self.assertEqual(code, 0, plan)
            result, code = h.execute(s, True, plan['planSha256'], True)
            self.assertEqual((code, result['status']), (0, 'RESTORED'))
            self.assertEqual(s.config.read_bytes(), original)
            self.assertEqual(h.sshd_call(s, '-T', s.config), before)
            # Real metadata and symlink denials, beyond the portable fake OS seam.
            s.dropin.chmod(0o666)
            self.assertEqual(h.execute(s)[0]['code'], 'FILE_METADATA_DRIFT')
            s.dropin.chmod(0o644)
            alias = s.config.with_name('alias')
            alias.symlink_to(s.config)
            self.assertEqual(h.execute(replace(s, config=alias))[0]['code'], 'FILE_METADATA_DRIFT')


if __name__ == '__main__':
    unittest.main()
