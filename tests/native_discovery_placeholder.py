"""Run only in a disposable, private Linux mount+network namespace on CI."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('placeholder_native', ROOT / 'scripts/reconcile-discovery-placeholder-20261109.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class NativeNamespaceHandle(unittest.TestCase):
    def setUp(self):
        self.assertEqual(0, os.geteuid())
        self.tmp = tempfile.TemporaryDirectory(prefix='ouf-placeholder-native-', dir='/run')
        self.path = Path(self.tmp.name) / 'netns'; self.path.write_bytes(b'{}'); self.path.chmod(0o600)
        self.inode = self.path.stat().st_ino
        self.mounted = False

    def tearDown(self):
        if self.mounted: subprocess.run(['umount', str(self.path)], check=True)
        self.tmp.cleanup()

    def test_actual_nsfs_is_preserved_then_original_placeholder_removed(self):
        subprocess.run(['mount', '--bind', '/proc/self/ns/net', str(self.path)], check=True)
        self.mounted = True
        self.assertTrue(m.mountpoint_present(self.path))
        with self.assertRaisesRegex(RuntimeError, 'MOUNTED_NAMESPACE_PRESERVED'):
            m.remove_placeholder(self.path, self.inode, lambda *_: self.fail('intent must not run'))
        subprocess.run(['umount', str(self.path)], check=True); self.mounted = False
        self.assertEqual(self.inode, self.path.stat().st_ino)
        saved = []
        m.remove_placeholder(self.path, self.inode, lambda info, raw: saved.append((info.st_ino, raw)))
        self.assertEqual([(self.inode, b'{}')], saved)
        self.assertFalse(self.path.exists())

    def test_actual_regular_bind_mount_is_preserved(self):
        source = self.path.with_name('source'); source.write_bytes(b'{}'); source.chmod(0o600)
        subprocess.run(['mount', '--bind', str(source), str(self.path)], check=True); self.mounted = True
        with self.assertRaisesRegex(RuntimeError, 'MOUNTPOINT_PRESERVED'):
            m.remove_placeholder(self.path, source.stat().st_ino, lambda *_: self.fail('intent must not run'))
        self.assertEqual(b'{}', source.read_bytes())


if __name__ == '__main__': unittest.main(verbosity=2)
