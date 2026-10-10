import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCRIPT = REPO/'releases/provider-dns-recovery-preflight-20261010.sh'
if not SCRIPT.exists():
    SCRIPT = HERE/'dns-recovery-preflight.sh'


class DeliveryBoundary(unittest.TestCase):
    def test_download_corruption_stops_before_sudo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root/'bin'
            commands.mkdir()
            (commands/'gh').write_text('#!/bin/sh\nprintf CORRUPT\n')
            (commands/'sudo').write_text('#!/bin/sh\ntouch "$HOME/sudo-called"\nexit 0\n')
            for name in ('gh', 'sudo'):
                (commands/name).chmod(0o700)
            result = subprocess.run(['/usr/bin/bash', str(SCRIPT)], capture_output=True, text=True,
                timeout=10, env={**os.environ, 'HOME': str(root), 'PATH': str(commands)+':/usr/bin:/bin'})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root/'sudo-called').exists())
            self.assertIn('OUF_DNS_RECOVERY_PLAN_EXIT=1', result.stdout)

    def test_root_bootstrap_rechecks_entrypoint_bytes(self):
        script = SCRIPT.read_text()
        bootstrap = script.split("sudo /usr/bin/python3 -I -B -c '\n", 1)[1].split("\n' ", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'entry.py'
            path.write_text('raise SystemExit("UNVERIFIED_CODE_EXECUTED")')
            result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', bootstrap, str(path)],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('OUF_DNS_RECOVERY_ENTRYPOINT_HASH_MISMATCH', result.stderr)
            self.assertNotIn('UNVERIFIED_CODE_EXECUTED', result.stderr)

    def test_only_plan_is_exposed_by_launcher(self):
        script = SCRIPT.read_text()
        self.assertIn('sys.argv=[str(p),"--plan"]', script)
        self.assertNotIn('"--apply"', script)
        self.assertNotIn('"--supervise"', script)
        self.assertIn('"__verified_source_bytes__":raw', script)


if __name__ == '__main__':
    unittest.main()
