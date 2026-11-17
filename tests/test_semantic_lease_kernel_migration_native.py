"""Explicit opt-in Linux root gate; CI cannot silently skip missing native tools."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import unittest

NATIVE = os.environ.get('OUF_LEASE_KERNEL_MIGRATION_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('native qualification requires Linux root:root')


@unittest.skipUnless(NATIVE, 'requires explicit Linux root/native opt-in')
class NativeMigration(unittest.TestCase):
    def test_blue_green_restore_finalize_atomicity_and_boot(self):
        for command in ('nft', 'unshare'):
            self.assertIsNotNone(shutil.which(command))
        child = subprocess.Popen([shutil.which('unshare'), '--net', '--fork', sys.executable, '-I', '-B',
            str(Path(__file__).with_name('native_semantic_lease_kernel_migration.py'))],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=150)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate()
            self.fail('native timeout: ' + (stdout + stderr).decode())
        self.assertEqual(child.returncode, 0, (stdout + stderr).decode())
        result = json.loads(stdout)
        self.assertEqual(result['status'], 'NATIVE_BLUE_GREEN_QUALIFIED')
        for key in ('atomicFailurePreservedN', 'restorePreservedExactN', 'finalizeRemovedN', 'dispatcherRebuiltG2'):
            self.assertTrue(result[key])
        print(stdout.decode(), end='')


if __name__ == '__main__':
    unittest.main(verbosity=2)
