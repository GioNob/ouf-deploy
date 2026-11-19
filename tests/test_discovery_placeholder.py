import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/reconcile-discovery-placeholder-20261109.py'
spec = importlib.util.spec_from_file_location('placeholder_recovery', PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Conditions(unittest.TestCase):
    def base(self):
        generations = {k: {'recordedGenerationAlive': False, 'recordedPidPresent': False} for k in ('admission', 'preexec')}
        row = {'runc': {'present': False}, 'runcDirectory': {'present': False}, 'containerdTask': {'present': False},
               'shimCount': 0, 'ownedTableFamilies': [], 'generations': generations}
        return {'status': 'DISCOVERY_LIFECYCLE_READ_COMPLETE', 'components': {
            'adapter': dict(copy.deepcopy(row), journalStates={'adapter': 'DELETED', 'admission': 'CLEANED', 'broker': 'CLEANED', 'preexec': 'ROLLED_BACK'}, namespaceHandle={'present': False}),
            'southbound': dict(copy.deepcopy(row), journalStates={'adapter': 'DELETING', 'admission': 'PROTECTED', 'broker': 'PROTECTED', 'preexec': 'PROTECTED'}, namespaceHandle={'present': True, 'inode': 4040196, 'matchesRecordedInode': False})},
            'coordination': {'state': 'BLOCKED', 'leaseAuthorized': False, 'tableFamiliesPresent': ['bridge', 'inet'],
                             'bridge': {'setCount': 2, 'elementCount': 0}, 'inet': {'setCount': 2, 'elementCount': 0}}}

    def test_exact_observed_terminal_state_is_eligible_for_placeholder_inspection(self):
        m.terminal_conditions(self.base())

    def test_running_process_task_rule_or_authorized_lease_is_denied(self):
        for field, changed in (('runc', {'present': True}), ('containerdTask', {'present': True}),
                               ('shimCount', 1), ('ownedTableFamilies', ['inet']),
                               ('generations', {'admission': {'recordedGenerationAlive': True, 'recordedPidPresent': True}})):
            value = self.base(); value['components']['southbound'][field] = changed
            with self.subTest(field=field), self.assertRaises(RuntimeError): m.terminal_conditions(value)
        for field, changed in (('leaseAuthorized', True), ('state', 'LEASE_READY'), ('inet', {'setCount': 2, 'elementCount': 1})):
            value = self.base(); value['coordination'][field] = changed
            with self.subTest(field=field), self.assertRaises(RuntimeError): m.terminal_conditions(value)

    def test_different_inode_is_preserved(self):
        value = self.base(); value['components']['southbound']['namespaceHandle']['inode'] += 1
        with self.assertRaisesRegex(RuntimeError, 'EXACT_OBSERVED_NAMESPACE_PATH_REQUIRED'): m.terminal_conditions(value)


class PlaceholderFiles(unittest.TestCase):
    def setUp(self):
        # /proc is intentionally unavailable in the scratch executor. Native CI
        # exercises real fdinfo/mountinfo/nsfs; these tests isolate file races.
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'netns'
        self.path.write_bytes(b'{}'); self.path.chmod(0o600)
        self.inode = self.path.stat().st_ino
        self.patches = [patch.object(m, 'open_parent', side_effect=lambda p: os.open(Path(p).parent, os.O_RDONLY | os.O_DIRECTORY)),
                        patch.object(m, 'mount_id', return_value=10), patch.object(m, 'mountpoint_present', return_value=False),
                        patch.object(m, 'filesystem_type', return_value=0xEF53)]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()

    def test_exact_unmounted_placeholder_is_backed_up_before_unlink(self):
        saved = []
        m.remove_placeholder(self.path, self.inode, lambda info, raw: saved.append((info.st_ino, raw)))
        self.assertEqual([(self.inode, b'{}')], saved)
        self.assertFalse(self.path.exists())

    def test_nsfs_handle_never_reaches_data_read_or_unlink(self):
        with patch.object(m, 'filesystem_type', return_value=m.NSFS_MAGIC), patch.object(m, 'read_private') as read:
            with self.assertRaisesRegex(RuntimeError, 'MOUNTED_NAMESPACE_PRESERVED'):
                m.remove_placeholder(self.path, self.inode, lambda *_: self.fail('intent called'))
            read.assert_not_called()
        self.assertTrue(self.path.exists())

    def test_mount_even_on_regular_filesystem_is_preserved(self):
        with patch.object(m, 'mountpoint_present', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'MOUNTPOINT_PRESERVED'):
                m.remove_placeholder(self.path, self.inode, lambda *_: self.fail('intent called'))

    def test_different_bytes_mode_hardlink_or_symlink_are_preserved(self):
        self.path.write_bytes(b'xx')
        with self.assertRaisesRegex(RuntimeError, 'EXACT_PREPARER_PLACEHOLDER_BYTES_REQUIRED'):
            m.remove_placeholder(self.path, self.inode, lambda *_: self.fail('intent called'))
        self.path.write_bytes(b'{}'); self.path.chmod(0o644)
        with self.assertRaises(RuntimeError): m.remove_placeholder(self.path, self.inode, lambda *_: None)
        self.path.chmod(0o600); os.link(self.path, self.path.with_name('another'))
        with self.assertRaises(RuntimeError): m.remove_placeholder(self.path, self.inode, lambda *_: None)
        self.path.unlink(); self.path.symlink_to(self.path.with_name('another'))
        with self.assertRaisesRegex(RuntimeError, 'REGULAR_PLACEHOLDER_REQUIRED'):
            m.remove_placeholder(self.path, self.inode, lambda *_: None)
        self.assertTrue(self.path.is_symlink())

    def test_failed_intent_preserves_file(self):
        def failed(*_): raise RuntimeError('INTENT_SAVE_FAILED')
        with self.assertRaisesRegex(RuntimeError, 'INTENT_SAVE_FAILED'):
            m.remove_placeholder(self.path, self.inode, failed)
        self.assertEqual(b'{}', self.path.read_bytes())

    def test_replacement_after_intent_is_not_removed(self):
        def replace(*_):
            self.path.rename(self.path.with_name('original'))
            self.path.write_bytes(b'{}'); self.path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'OBSERVED_PLACEHOLDER_INODE_CHANGED'):
            m.remove_placeholder(self.path, self.inode, replace)
        self.assertTrue(self.path.exists()); self.assertTrue(self.path.with_name('original').exists())


if __name__ == '__main__': unittest.main()
