"""Sealed downloads and root rechecks must fail before source execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATHS = {'program': 'scripts/read-retained-v11-metadata-drift.py',
         'planner': 'scripts/prepare-retained-v11-source-expectations.py',
         'atomic': 'tools/semantic_application_cutover/atomic_review_intake.py'}


class Delivery(unittest.TestCase):
    def fixture(self, root):
        binary = root / 'bin'
        binary.mkdir()
        marker = root / 'sudo-called'
        gh = '''#!/usr/bin/env python3
import json,os,pathlib,sys
files=json.loads(os.environ["OUF_TEST_FILES"])
routes=json.loads(os.environ["OUF_TEST_ROUTES"])
key=next(k for k,v in routes.items() if v in sys.argv[-1])
if os.environ.get("OUF_TEST_DOWNLOAD_FAIL")==key:raise SystemExit(71)
raw=pathlib.Path(files[key]).read_bytes()
if os.environ.get("OUF_TEST_TAMPER")==key:raw+=b"#drift"
sys.stdout.buffer.write(raw)
'''
        (binary / 'gh').write_text(gh)
        (binary / 'gh').chmod(0o700)
        (binary / 'sudo').write_text('#!/bin/sh\nprintf called > "' + str(marker) + '"\nexit 97\n')
        (binary / 'sudo').chmod(0o700)
        launcher = root / 'launcher.sh'
        launcher.write_text((ROOT / 'releases/retained-v11-metadata-diagnostic-20261012.sh').read_text().replace('$HOME', str(root)))
        files = {name: str(ROOT / path) for name, path in PATHS.items()}
        env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'],
                   OUF_TEST_FILES=json.dumps(files), OUF_TEST_ROUTES=json.dumps(PATHS))
        return launcher, env, marker, files

    def test_download_and_digest_denials_never_reach_sudo(self):
        for variable in ('OUF_TEST_DOWNLOAD_FAIL', 'OUF_TEST_TAMPER'):
            for name in PATHS:
                with self.subTest(variable=variable, name=name), tempfile.TemporaryDirectory(dir=ROOT) as path:
                    launcher, env, marker, _ = self.fixture(Path(path))
                    env[variable] = name
                    result = subprocess.run(['bash', str(launcher)], env=env, capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())

    def test_valid_downloads_propagate_sudo_exit(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as path:
            launcher, env, marker, _ = self.fixture(Path(path))
            result = subprocess.run(['bash', str(launcher)], env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 97)
            self.assertTrue(marker.exists())
            self.assertIn(b'OUF_RETAINED_V11_METADATA_DIAGNOSTIC_EXIT=97', result.stdout)

    def test_root_recheck_rejects_each_changed_source_before_exec(self):
        shell = (ROOT / 'releases/retained-v11-metadata-diagnostic-20261012.sh').read_text()
        code = shell.split("sudo /usr/bin/python3 -I -B -c '\n", 1)[1].split("\n' \"$OUF_DIR/program.py\"", 1)[0]
        compile(code, 'root-bootstrap', 'exec')
        for target in PATHS:
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir=ROOT) as path:
                root = Path(path)
                paths = []
                for name, source in PATHS.items():
                    file = root / (name + '.py')
                    file.write_bytes((ROOT / source).read_bytes() + (b'#drift' if name == target else b''))
                    paths.append(str(file))
                result = subprocess.run(['python3', '-I', '-B', '-c', code, *paths],
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'OUF_METADATA_DIAGNOSTIC_SOURCE_HASH_MISMATCH', result.stderr)

    def test_portable_client_precedes_fallback_and_shell_is_valid(self):
        path = ROOT / 'releases/retained-v11-metadata-diagnostic-20261012.sh'
        shell = path.read_text()
        self.assertLess(shell.index('ouf-gh-2.102.0.PNoFbF'), shell.index('command -v gh'))
        subprocess.run(['bash', '-n', str(path)], check=True)


if __name__ == '__main__':
    unittest.main()
