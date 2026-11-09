"""Disposable CI host only: exercise real systemd empty command arrays."""
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('boot_fixture',Path(__file__).with_name('test_discovery_boot_activation.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
m=b.m
UNIT='ouf-semantic-boot-guard.service'
PATH=Path('/run/systemd/system')/UNIT


def ctl(*args):
    return subprocess.run(['/usr/bin/systemctl',*args],check=True,capture_output=True,text=True,timeout=20).stdout


class NativeSystemd(unittest.TestCase):
    def test_real_empty_array_and_populated_array(self):
        self.assertEqual('true',os.environ.get('GITHUB_ACTIONS'))
        self.assertEqual('not-found',ctl('show',UNIT,'--property=LoadState','--value').strip())
        self.assertFalse(PATH.exists())
        body='[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n'
        with PATH.open('x') as f: f.write(body)
        try:
            ctl('daemon-reload');ctl('start',UNIT)
            raw=m.systemctl(['show',UNIT,'--property='+','.join(m.PROPERTIES),'--no-pager'])
            self.assertIn('LoadState=loaded',raw)
            m.empty_guard_prestart()
            print('REAL_SYSTEMD_EMPTY_PRESTART_VERIFIED; systemctl_omitted='+str('ExecStartPre=' not in raw))
            PATH.write_text(body+'ExecStartPre=/usr/bin/true\n');ctl('daemon-reload')
            with self.assertRaisesRegex(RuntimeError,'EMPTY_GUARD_PRESTART_NOT_PROVEN'):
                m.empty_guard_prestart()
            print('REAL_SYSTEMD_NONEMPTY_PRESTART_REFUSED')
        finally:
            ctl('stop',UNIT);PATH.unlink();ctl('daemon-reload')


if __name__=='__main__':unittest.main(verbosity=2)
