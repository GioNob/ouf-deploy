"""Opt-in, real nft/ip/conntrack proof. Explicit opt-in failures never skip."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import unittest

NATIVE = os.environ.get('OUF_LEASE_KERNEL_V2_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('OUF_LEASE_KERNEL_V2_NATIVE requires Linux root:root; refusing to skip')


@unittest.skipUnless(NATIVE, 'requires explicit Linux root/native opt-in')
class NativeLeaseKernel(unittest.TestCase):
    def test_real_dnat_routing_bridge_and_established_revocation(self):
        for command in ('unshare', 'mount', 'ip', 'nft'):
            self.assertIsNotNone(shutil.which(command), command)
        child = subprocess.Popen([
            shutil.which('unshare'), '--mount', '--net', '--fork',
            sys.executable, '-I', '-B', str(Path(__file__).with_name('native_semantic_lease_kernel_v2.py')),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=150)
        except subprocess.TimeoutExpired:
            # Kill the namespace worker AND its servers/clients if it hangs.
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate()
            self.fail('native namespace proof timed out\n' + stdout + stderr)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        print(stdout, end='')


if __name__ == '__main__': unittest.main(verbosity=2)
