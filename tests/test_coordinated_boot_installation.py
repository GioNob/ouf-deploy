import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
if not (ROOT/'install-coordinated-boot-guard.py').exists(): ROOT = ROOT.parent/'scripts'
spec = importlib.util.spec_from_file_location('installation', ROOT/'install-coordinated-boot-guard.py')
install = importlib.util.module_from_spec(spec); spec.loader.exec_module(install)
v3spec = importlib.util.spec_from_file_location('v3', ROOT/'privileged-discovery-preflight-v3.py')
v3 = importlib.util.module_from_spec(v3spec); v3spec.loader.exec_module(v3)


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.temp = tempfile.TemporaryDirectory(prefix='ouf-unit-publication-', dir='/root')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.entries = []
        for name in ('guard', 'dropin', 'helper'):
            path = self.root/name; mode = 0o755 if name == 'helper' else 0o600
            install.write_new(path, b'previous-'+name.encode(), mode)
            self.entries.append({'path': path, 'old': path.read_bytes(), 'new': b'new-'+name.encode(), 'mode': mode})
        self.events = []

    def test_success_publishes_all_files_before_reload_and_readback(self):
        def reload():
            self.events.append('reload')
            self.assertTrue(all(e['path'].read_bytes() == e['new'] for e in self.entries))
        def verify(): self.events.append('readback')
        install.transaction(self.entries, reload, verify, lambda: self.fail('unexpected rollback'), self.events.append)
        self.assertEqual(self.events, ['INSTALLING', 'reload', 'readback', 'INSTALLED'])
        for e in self.entries: self.assertEqual(e['path'].stat().st_mode & 0o777, e['mode'])

    def test_failed_reload_restores_bytes_and_verifies_previous_profile(self):
        calls = []
        def reload():
            calls.append(True)
            if len(calls) == 1: raise RuntimeError('failed reload')
        def verify_old():
            self.assertTrue(all(e['path'].read_bytes() == e['old'] for e in self.entries))
            self.events.append('old verified')
        with self.assertRaisesRegex(RuntimeError, 'rolled back'):
            install.transaction(self.entries, reload, lambda: None, verify_old, self.events.append)
        self.assertEqual(self.events[-1], 'ROLLED_BACK')
        self.assertIn('old verified', self.events)

    def test_readback_failure_also_rolls_back(self):
        def denied(): raise RuntimeError('loaded unit mismatch')
        with self.assertRaisesRegex(RuntimeError, 'rolled back'):
            install.transaction(self.entries, lambda: None, denied, lambda: None, self.events.append)
        self.assertTrue(all(e['path'].read_bytes() == e['old'] for e in self.entries))

    def test_foreign_file_before_publication_is_never_overwritten(self):
        e = self.entries[1]; e['path'].write_bytes(b'foreign')
        with self.assertRaises(RuntimeError):
            install.transaction(self.entries, lambda: None, lambda: None, lambda: None, self.events.append)
        self.assertEqual(e['path'].read_bytes(), b'foreign')
        self.assertEqual(self.entries[0]['path'].read_bytes(), self.entries[0]['old'])

    def test_foreign_file_during_failure_blocks_rollback_without_overwrite(self):
        def failed():
            self.entries[0]['path'].write_bytes(b'foreign')
            raise RuntimeError('external change')
        with self.assertRaisesRegex(RuntimeError, 'partial transition'):
            install.transaction(self.entries, lambda: None, failed, lambda: None, self.events.append)
        self.assertEqual(self.entries[0]['path'].read_bytes(), b'foreign')
        self.assertEqual(self.events[-1], 'ROLLBACK_BLOCKED')

    def test_symlink_and_hardlink_denied(self):
        e = self.entries[0]
        link = self.root/'symlink'; link.symlink_to(e['path'])
        with self.assertRaises(OSError): install.replace(link, e['old'], e['new'])
        hard = self.root/'hardlink'; os.link(e['path'], hard)
        with self.assertRaises(ValueError): install.replace(e['path'], e['old'], e['new'])
        self.assertEqual(e['path'].read_bytes(), e['old'])

    def test_render_changes_only_the_single_exec_line(self):
        before = b'[Unit]\nAfter=network.target\n[Service]\nType=oneshot\nExecStart=/old guarded-command\nRemainAfterExit=yes\n'
        after = install.rewrite_command(before, 'ExecStart', '/usr/bin/python3 -I -B /new')
        self.assertEqual(after, before.replace(b'ExecStart=/old guarded-command', b'ExecStart=/usr/bin/python3 -I -B /new'))
        for bad in (b'ExecStart=\n', b'ExecStart=/a\nExecStart=/b\n', b'[Service]\n'):
            with self.assertRaises(ValueError): install.rewrite_command(bad, 'ExecStart', '/new')

    def test_v3_refuses_unsafe_source_before_import(self):
        path = self.root/'evil.py'; path.write_text('raise AssertionError("must never execute")'); path.chmod(0o644)
        with self.assertRaises(ValueError): v3.load(path, install.digest(path.read_bytes()))
        path.chmod(0o600)
        with self.assertRaises(ValueError): v3.load(path, '0'*64)

    def test_existing_pointer_refuses_replay_before_helper_access(self):
        pointer = self.root/'active.json'; install.write_new(pointer, b'{}')
        with patch.object(install, 'POINTER', pointer), patch.object(install, 'sealed') as read:
            with self.assertRaisesRegex(ValueError, 'no replay'): install.install(self.root, b'source')
            read.assert_not_called()

    def test_v3_routes_only_the_sealed_selected_observer(self):
        root = Path('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-fixture')
        raw = install.encoded({'state': 'INSTALLED'})
        pointer = {'schema': 'ouf.semantic-coordinated-boot-pointer.v1', 'receiptFile': str(root/'installation-receipt.json'),
            'receiptHash': install.digest(raw), 'observerFile': str(root/'transition-source.py'), 'observerHash': 'a'*64}
        legacy = SimpleNamespace()
        legacy.collect = lambda: {'runtimeReadiness': legacy.selected_runtime_readiness(), 'readOnly': True}
        runtime = SimpleNamespace(observe=lambda receipt, received: {'runtimeCustodyVerified': received is legacy})
        def loaded(path, expected, executable=False):
            if path == v3.BACKUP: return legacy
            self.assertEqual(path, root/'transition-source.py'); self.assertEqual(expected, 'a'*64)
            return runtime
        def protected(path, executable=False):
            return install.encoded(pointer) if path == v3.POINTER else raw
        with patch.object(v3, 'load', side_effect=loaded), patch.object(v3, 'protected', side_effect=protected):
            report = v3.collect()
            self.assertTrue(report['runtimeReadiness']['runtimeCustodyVerified'])
            self.assertEqual(report['schema'], 'ouf.discovery.privileged-preflight.v3')
            pointer['receiptHash'] = '0'*64
            with self.assertRaises(ValueError): v3.collect()
            pointer['receiptHash'] = install.digest(raw); pointer['observerFile'] = '/tmp/untrusted.py'
            with self.assertRaises(ValueError): v3.collect()


if __name__ == '__main__': unittest.main()
