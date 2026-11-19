"""Explicit Linux root gate: real v13 tables, bridge TCP and ARP traffic."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import unittest

NATIVE = os.environ.get('OUF_R3_V13_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('OUF_R3_V13_NATIVE requires Linux root:root; refusing to skip')


@unittest.skipUnless(NATIVE, 'requires explicit Linux root/native opt-in')
class IdentityBridge(unittest.TestCase):
    def test_declared_idp_flow_and_semantic_regression(self):
        for command in ('unshare', 'mount', 'ip', 'nft'):
            self.assertIsNotNone(shutil.which(command), command)
        child = subprocess.Popen(['unshare', '--mount', '--net', '--fork', sys.executable, '-I', '-B',
            str(Path(__file__).with_name('native_semantic_provider_r3_v13.py'))],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate()
            self.fail('native v13 proof timed out\n' + stdout + stderr)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        print(stdout, end='')


if __name__ == '__main__': unittest.main()
