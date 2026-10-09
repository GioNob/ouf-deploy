"""R8 pinned delivery; gh lives outside PATH and sudo records argv only."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]

class PreparedDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.bin=self.root/'bin';self.bin.mkdir()
        self.gh=self.root/'retained-gh'
        self.gh.write_text('#!'+sys.executable+'''\nimport base64,os,pathlib,sys
route=next(x for x in sys.argv if x.startswith('repos/'))
assert route.endswith('?ref=378c882379502f5b9809e0f24f6a3a64cdacef56')
relative=route.split('/contents/',1)[1].split('?ref=',1)[0]
if os.environ.get('CI_FAIL')==relative:raise SystemExit(22)
raw=(pathlib.Path(os.environ['CI_ROOT'])/relative).read_bytes()
if os.environ.get('CI_TAMPER')==relative:raw+=b'\\n'
print(base64.b64encode(raw).decode())
''');self.gh.chmod(0o755)
        sudo=self.bin/'sudo';sudo.write_text('#!'+sys.executable+'''\nimport json,os,pathlib,sys
pathlib.Path(os.environ['CI_MARKER']).write_text(json.dumps(sys.argv[1:]))
raise SystemExit(int(os.environ.get('CI_EXIT','0')))
''');sudo.chmod(0o755)
        for name in ('mktemp','base64','sha256sum'):(self.bin/name).symlink_to('/usr/bin/'+name)
        self.env={**os.environ,'PATH':str(self.bin),'CI_ROOT':str(ROOT),'CI_MARKER':str(self.root/'sudo.json'),'OUF_R8_WORK_ROOT':str(self.root)}

    def run_launcher(self,approved=False,**overrides):
        script=(ROOT/'releases/provider-prepared-mountpoint-recovery-20261009.sh').read_text()
        approval='DISPOSABLE_CI_ONLY' if approved else 'PENDING_PREPARED_MOUNTPOINT_RECOVERY_APPROVAL'
        script=re.sub(r'^OUF_R8_APPROVAL=.*$','OUF_R8_APPROVAL='+approval,script,flags=re.MULTILINE)
        script=script.replace('$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh',str(self.gh))
        return subprocess.run(['/bin/bash','-c',script],env={**self.env,**overrides},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)

    def test_pending_is_inert_before_download_and_sudo(self):
        r=self.run_launcher();self.assertEqual(r.returncode,79)
        self.assertFalse((self.root/'sudo.json').exists());self.assertEqual(list(self.root.glob('ouf-r8-recovery.*')),[])

    def test_known_cli_outside_path_delivers_only_three_pinned_files(self):
        r=self.run_launcher(True);self.assertEqual(r.returncode,0,r.stdout.decode()+r.stderr.decode())
        args=json.loads((self.root/'sudo.json').read_text());self.assertEqual(args[:4],['/usr/bin/python3.13','-I','-B','-c'])
        self.assertEqual(args[-2],'DISPOSABLE_CI_ONLY')
        directory=Path(args[-1]);self.assertEqual({p.name for p in directory.iterdir() if not p.name.endswith('.base64')},
            {'execute.py','prepare_mountpoint_acceptance.py','scope.json'})

    def test_failed_or_changed_download_cannot_reach_root(self):
        for env in ({'CI_FAIL':'tools/semantic_target_review/execute_prepared_mountpoint_recovery.py'},
                    {'CI_TAMPER':'evidence/provider-r8-mountpoint-recovery-scope-20261009.json'}):
            r=self.run_launcher(True,**env);self.assertNotEqual(r.returncode,0)
            self.assertFalse((self.root/'sudo.json').exists())

    def test_missing_known_cli_or_root_error_is_reported_without_retry(self):
        r=self.run_launcher(True,CI_EXIT='37');self.assertEqual(r.returncode,37)
        self.assertIn(b'OUF_R8_RECOVERY_EXIT=37',r.stdout)
        self.assertEqual(len(list(self.root.glob('ouf-r8-recovery.*'))),1)
        self.gh.unlink();r=self.run_launcher(True);self.assertNotEqual(r.returncode,0)
        self.assertIn(b'EXISTING_GH_NOT_EXECUTABLE',r.stdout)
        self.assertEqual(len(list(self.root.glob('ouf-r8-recovery.*'))),1)

if __name__=='__main__':unittest.main()
