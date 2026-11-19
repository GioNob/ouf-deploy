"""Opt-in Linux root witness. A green test is NOT migration qualification."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import unittest

NATIVE = os.environ.get('OUF_LEASE_RESTORE_SEAL_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('OUF_LEASE_RESTORE_SEAL_NATIVE requires Linux root:root; refusing to skip')


@unittest.skipUnless(NATIVE, 'requires explicit Linux root/native opt-in')
class NativeRestoreSealFeasibility(unittest.TestCase):
    def test_real_atomic_replacement_and_exact_restore_seal(self):
        for command in ('unshare', 'nft'):
            self.assertIsNotNone(shutil.which(command), command)
        child = subprocess.Popen([
            shutil.which('unshare'), '--net', '--fork', sys.executable, '-I', '-B',
            str(Path(__file__).with_name('qualify_semantic_lease_restore_seal.py')),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate()
            self.fail('native feasibility witness timed out\n' + stdout + stderr)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        result = json.loads(stdout)
        self.assertTrue(result['atomicFailurePreservedGenerationN'])
        self.assertTrue(result['bootFootprintPreserved'])
        # Witness the blocker, never present a different structure as restored.
        self.assertEqual(result['status'], 'HELD', stdout)
        self.assertEqual(result['reason'], 'LEASE_KERNEL_RESTORE_SEAL_UNPROVEN')
        self.assertNotEqual(result['expectedStructureHash'], result['restoredStructureHash'])
        self.assertNotEqual(result['tableHandles']['before'], result['tableHandles']['restored'])
        self.assertNotEqual(result['restoredStructureHash'], result['repeatedStructureHash'])
        print(stdout, end='')


if __name__ == '__main__':
    unittest.main(verbosity=2)
