"""Delivery regression for the documented gh outside PATH; never contacts VPS."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT/'releases/provider-r8-post-start-read-20261009.sh'
READER = ROOT/'tools/semantic_target_review/read_r8_post_start.py'


class Delivery(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory(dir=Path.cwd(), prefix='r8-post-delivery-') as tmp:
            root = Path(tmp)
            home, bins = root/'home', root/'bin'
            home.mkdir()
            bins.mkdir()
            gh = home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
            gh.parent.mkdir(parents=True)
            gh.write_text('#!/bin/bash\ncase "$OUF_TEST_MODE" in\n download-fails) exit 22;;\n bad-hash) echo changed;;\n *) /bin/cat "$OUF_TEST_READER";;\nesac\n')
            gh.chmod(0o755)
            for name in ('mktemp', 'sha256sum', 'tee'):
                (bins/name).symlink_to(Path('/usr/bin')/name)
            sudo = bins/'sudo'
            sudo.write_text('#!/bin/bash\nprintf reached > "$OUF_TEST_MARKER"\nif [ "$OUF_TEST_MODE" = root-fails ]; then exit 7; fi\nprintf "OUF_TEST_READER_NOT_EXECUTED=FIXTURE_ONLY\\n"\n')
            sudo.chmod(0o755)
            marker = root/'sudo-marker'
            env = {**os.environ, 'HOME': str(home), 'PATH': str(bins), 'OUF_TEST_MODE': mode,
                   'OUF_TEST_READER': str(READER), 'OUF_TEST_MARKER': str(marker)}
            result = subprocess.run(['/bin/bash', str(SCRIPT)], env=env, capture_output=True, text=True)
            return result, marker.exists()

    def test_gh_outside_path_is_reused(self):
        result, reached = self.exercise('ok')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(reached)
        self.assertIn('OUF_R8_POST_START_EXIT=0', result.stdout)

    def test_download_failure_and_hash_mismatch_never_reach_sudo(self):
        for mode in ('download-fails', 'bad-hash'):
            result, reached = self.exercise(mode)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(reached)

    def test_root_failure_is_not_hidden_by_tee(self):
        result, reached = self.exercise('root-fails')
        self.assertTrue(reached)
        self.assertEqual(result.returncode, 7)
        self.assertIn('OUF_R8_POST_START_EXIT=7 PHASE=READ_EXISTING_R8_AND_LEASE_STATE_ONLY', result.stdout)


if __name__ == '__main__':
    unittest.main()
