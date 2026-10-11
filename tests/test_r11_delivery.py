import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
LAUNCHER=ROOT/'releases/provider-resilient-r11-approved-20261011.sh'

class Tests(unittest.TestCase):
    def harness(self, failure=None, tamper=False, sudo_exit=0):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            client=base/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
            client.parent.mkdir(parents=True)
            client.write_text('''#!/usr/bin/python3
import os,pathlib,sys
count=pathlib.Path(os.environ['OUF_TEST_COUNT'])
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
if n==int(os.environ['OUF_TEST_FAILURE']):
    if os.environ['OUF_TEST_TAMPER']=='1':sys.stdout.buffer.write(b'corrupted');sys.exit(0)
    sys.exit(1)
url=sys.argv[-1]
assert '?ref=' in url
name=url.split('/contents/',1)[1].split('?ref=',1)[0]
sys.stdout.buffer.write((pathlib.Path(os.environ['OUF_TEST_SOURCE'])/name).read_bytes())
''')
            client.chmod(0o700)
            sudo=base/'sudo'
            sudo.write_text('#!/bin/bash\ntouch "$OUF_TEST_MARKER"\nexit "$OUF_TEST_SUDO_EXIT"\n')
            sudo.chmod(0o700)
            marker=base/'sudo-reached'
            env={**os.environ,'HOME':tmp,'PATH':tmp+':/usr/bin:/bin',
                'OUF_TEST_COUNT':str(base/'count'),'OUF_TEST_FAILURE':str(failure or 0),
                'OUF_TEST_TAMPER':str(int(tamper)),'OUF_TEST_SOURCE':str(ROOT),
                'OUF_TEST_MARKER':str(marker),'OUF_TEST_SUDO_EXIT':str(sudo_exit)}
            result=subprocess.run(['bash',str(LAUNCHER)],env=env,capture_output=True)
            return result,marker.exists()

    def test_portable_client_outside_path_and_all_hashes(self):
        result,reached=self.harness()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertTrue(reached)
        self.assertEqual(result.stdout.count(b': OK'),14)

    def test_each_download_failure_or_tampered_component_denies_before_sudo(self):
        for n in range(1,15):
            for tamper in (False,True):
                with self.subTest(position=n,tamper=tamper):
                    result,reached=self.harness(n,tamper)
                    self.assertNotEqual(result.returncode,0)
                    self.assertFalse(reached)

    def test_target_failure_is_not_hidden_by_tee(self):
        result,reached=self.harness(sudo_exit=23)
        self.assertTrue(reached)
        self.assertEqual(result.returncode,23)
        self.assertIn(b'OUF_RESILIENT_R11_APPLY_EXIT=23',result.stdout)

    def test_fixed_single_source_pin_and_root_memory_hash(self):
        subprocess.run(['bash','-n',str(LAUNCHER)],check=True)
        source=LAUNCHER.read_text()
        self.assertEqual(len(set(re.findall(r'\?ref=([0-9a-f]{40})',source))),1)
        self.assertIn('sudo /usr/bin/python3 -I -B -c',source)
        self.assertIn('"__verified_source_bytes__":raw',source)
        digest=hashlib.sha256((ROOT/'tools/semantic_lease_recovery/activate_resilient_r11.py').read_bytes()).hexdigest()
        self.assertEqual(source.count(digest),2)

if __name__=='__main__':unittest.main()
