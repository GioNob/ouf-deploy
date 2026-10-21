"""Exercise the pinned launcher with fake GitHub/sudo, never a VPS actuator."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
LAUNCHER = ROOT.parents[1] / 'releases/provider-r8-worker-read-20261010.sh'
READER = ROOT / 'read_r8_worker_quiescence.py'


class DeliveryTest(unittest.TestCase):
    def scenario(self, raw, sudo_code=0):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bin').mkdir()
            (root / 'download.py').write_bytes(raw)
            (root / 'bin/gh').write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$FIXTURE_ROOT/gh-args"\ncat "$FIXTURE_ROOT/download.py"\n')
            (root / 'bin/sudo').write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$FIXTURE_ROOT/sudo-args"\nprintf "FIXTURE_ONLY_NO_TARGET_READ\\n"\nexit "$FIXTURE_SUDO_CODE"\n')
            for name in ('gh', 'sudo'):
                (root / 'bin' / name).chmod(0o700)
            env = {**os.environ, 'HOME': temp, 'PATH': str(root / 'bin') + ':' + os.environ['PATH'],
                   'FIXTURE_ROOT': temp, 'FIXTURE_SUDO_CODE': str(sudo_code)}
            result = subprocess.run(['bash', str(LAUNCHER)], env=env, capture_output=True, text=True, timeout=10)
            return result, (root / 'gh-args').read_text(), ((root / 'sudo-args').read_text() if (root / 'sudo-args').exists() else None)

    def test_exact_source_delivery_and_isolated_reader_flags(self):
        result, gh, sudo = self.scenario(READER.read_bytes())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('WORKER_QUIESCENCE_READ_EXIT=0', result.stdout)
        self.assertRegex(gh, r'read_r8_worker_quiescence.py\?ref=[0-9a-f]{40}')
        self.assertTrue(sudo.startswith('/usr/bin/python3\n-I\n-B\n-c\n'))
        self.assertIn(hashlib.sha256(READER.read_bytes()).hexdigest(), sudo)

    def test_download_tamper_stops_before_sudo(self):
        result, _, sudo = self.scenario(READER.read_bytes() + b'\n# tampered\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(sudo)
        self.assertIn('WORKER_QUIESCENCE_READ_EXIT=1', result.stdout)

    def test_reader_failure_propagates_through_tee(self):
        result, _, _ = self.scenario(READER.read_bytes(), 7)
        self.assertEqual(result.returncode, 7)
        self.assertIn('WORKER_QUIESCENCE_READ_EXIT=7', result.stdout)

    def test_privileged_hash_gate_rejects_changed_bytes_before_compile(self):
        wrapper = re.search("sudo /usr/bin/python3 -I -B -c '(.*?)' ", LAUNCHER.read_text(), re.S).group(1)
        with tempfile.TemporaryDirectory() as temp:
            reader = Path(temp) / 'reader.py'
            reader.write_text('raise RuntimeError("MUST_NOT_EXECUTE")\n')
            result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', wrapper, str(reader)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('OUF_R8_WORKER_QUIESCENCE_READER_HASH_MISMATCH', result.stderr)
            self.assertNotIn('MUST_NOT_EXECUTE', result.stderr)


if __name__ == '__main__':
    unittest.main()
