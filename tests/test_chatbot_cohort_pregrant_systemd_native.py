"""Disposable systemd units only; never addresses any real OUF service."""
import os
from pathlib import Path
import subprocess
import unittest
import uuid
from unittest.mock import patch
import test_file_only_preparation
import legacy_retirement as legacy
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence

@unittest.skipUnless(os.environ.get('OUF_NATIVE_SYSTEMD')=='1','explicit disposable host-systemd CI only')
class NativeMaskedTimer(unittest.TestCase):
    def test_real_failed_resources_timer_remains_masked_quiescent_without_reset_failed(self):
        self.assertEqual(os.geteuid(),0)
        name='ouf-pregrant-qualification-'+uuid.uuid4().hex
        units=(name+'.timer',name+'.service')
        files=[Path('/run/systemd/system')/u for u in units]
        masks=[Path('/etc/systemd/system')/u for u in units]
        self.assertTrue(all(not os.path.lexists(p) for p in (*files,*masks)))
        def command(*args):
            return subprocess.run(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        try:
            files[1].write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
            files[0].write_text('[Timer]\nOnActiveSec=1h\nUnit='+units[1]+'\n')
            for path in files:path.chmod(0o644)
            self.assertEqual(command('daemon-reload').returncode,0)
            self.assertEqual(command('mask',units[1]).returncode,0)
            # A timer whose trigger cannot load fails with resources. This does
            # not invoke its service or require resource exhaustion on the host.
            self.assertNotEqual(command('start',units[0]).returncode,0)
            self.assertEqual(command('mask','--now',*units).returncode,0)
            with patch.object(legacy,'UNITS',units):
                observed=legacy.read_units()
                self.assertEqual(observed[units[0]]['ActiveState'],'failed')
                self.assertEqual(observed[units[0]]['SubState'],'failed')
                self.assertTrue(legacy.quiescent(observed))
                self.assertTrue(LegacyWriterFence().guard())
                self.assertEqual(legacy.read_units(),observed)
            # Result is queried separately because it is diagnostic, not a
            # substitute for the mask/Job/PID security conditions.
            result=subprocess.run(['/usr/bin/systemctl','show',units[0],'--property=Result','--value'],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=True)
            self.assertEqual(result.stdout.strip(),b'resources')
        finally:
            command('stop',*units)
            command('reset-failed',*units) # fixture cleanup only, after assertions
            for path in masks:
                if path.is_symlink() and os.readlink(path)=='/dev/null':path.unlink()
            for path in files:
                if path.is_file() and not path.is_symlink():path.unlink()
            command('daemon-reload')

if __name__=='__main__':unittest.main()
