import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'releases/resilient-worker-current-intake-20261011.sh'


class Tests(unittest.TestCase):
    def test_shell_syntax_and_exact_isolated_hash_verification(self):
        subprocess.run(['bash', '-n', str(LAUNCHER)], check=True)
        text = LAUNCHER.read_text()
        self.assertIn('sudo /usr/bin/python3 -I -B -c', text)
        self.assertIn('hashlib.sha256(raw).hexdigest()', text)
        self.assertNotIn('systemctl', text)

    def test_download_or_hash_failure_never_reaches_sudo(self):
        for download_exit in [1, 0]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                gh = root / 'gh'
                gh.write_text('#!/bin/bash\n' + ('exit 1\n' if download_exit else 'echo dGFtcGVyZWQ=\n'))
                sudo = root / 'sudo'
                sudo.write_text('#!/bin/bash\ntouch "$OUF_TEST_MARKER"\nexit 0\n')
                gh.chmod(0o700); sudo.chmod(0o700)
                marker = root / 'sudo-reached'
                env = {**os.environ, 'HOME': tmp, 'PATH': tmp + ':' + os.environ['PATH'],
                       'OUF_TEST_MARKER': str(marker)}
                result = subprocess.run(['bash', str(LAUNCHER)], env=env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())


if __name__ == '__main__': unittest.main()
