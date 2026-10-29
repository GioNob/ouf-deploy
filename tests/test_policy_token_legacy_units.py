"""Exact systemd fence, only in the explicitly disposable hosted runner."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
import test_installed_token_owner as native
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence

class LegacyUnitsTest(unittest.TestCase):
    def test_actual_systemd_requires_both_exact_units_masked_and_inactive(self):
        if os.environ.get('OUF_NATIVE_UIDS')!='1':self.skipTest('Disposable hosted systemd fixture required')
        self.assertEqual(os.environ.get('GITHUB_ACTIONS'),'true')
        units=LegacyWriterFence.UNITS;paths=[Path('/etc/systemd/system')/name for name in units]
        def command(*args):return subprocess.run(['/usr/bin/systemctl',*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        for unit,path in zip(units,paths):
            self.assertFalse(path.exists() or path.is_symlink())
            self.assertEqual(command('show',unit,'--property=LoadState','--value').stdout.strip(),b'not-found')
        try:
            with self.assertRaises(Exception):LegacyWriterFence().guard()
            for path in paths:path.symlink_to('/dev/null')
            command('daemon-reload');self.assertTrue(LegacyWriterFence().guard())
            paths[1].unlink();command('daemon-reload')
            with self.assertRaises(Exception):LegacyWriterFence().guard()
        finally:
            for path in paths:
                if path.is_symlink() and os.readlink(path)=='/dev/null':path.unlink()
            command('daemon-reload')

if __name__=='__main__':unittest.main()
