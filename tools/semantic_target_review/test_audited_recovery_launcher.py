"""Pinned delivery failure injection; sudo is a recorder, never privilege use."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class AuditedLauncherTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.bin=self.root/'bin';self.bin.mkdir()
        gh='#!'+sys.executable+'''\nimport base64,os,pathlib,sys
route=next(x for x in sys.argv if x.startswith('repos/'))
relative=route.split('/contents/',1)[1].split('?ref=',1)[0]
if os.environ.get('CI_FAIL_REMOTE')==relative:raise SystemExit(22)
raw=(pathlib.Path(os.environ['CI_SOURCE_ROOT'])/relative).read_bytes()
if os.environ.get('CI_TAMPER_REMOTE')==relative:raw+=b'\\n'
print(base64.b64encode(raw).decode())
'''
        sudo='#!'+sys.executable+'''\nimport json,os,pathlib,sys
pathlib.Path(os.environ['CI_SUDO_MARKER']).write_text(json.dumps(sys.argv[1:]))
raise SystemExit(int(os.environ.get('CI_SUDO_EXIT','0')))
'''
        for name,raw in [('gh',gh),('sudo',sudo)]:
            path=self.bin/name;path.write_text(raw);path.chmod(0o755)
        self.env={**os.environ,'PATH':str(self.bin)+':/usr/bin:/bin','CI_SOURCE_ROOT':str(ROOT),
            'CI_SUDO_MARKER':str(self.root/'sudo-marker'),'OUF_AUDIT_WORK_ROOT':str(self.root)}

    def launch(self,approve=False,**env):
        text=(ROOT/'releases/provider-audited-recovery-20261009.sh').read_text()
        if approve:text=text.replace('OUF_AUDIT_APPROVAL=PENDING_AUDITED_PROVIDER_RECOVERY_APPROVAL',
                                     'OUF_AUDIT_APPROVAL=DISPOSABLE_DELIVERY_TEST_ONLY')
        return subprocess.run(['bash','-c',text],env={**self.env,**env},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)

    def test_pending_approval_never_downloads_or_reaches_sudo(self):
        result=self.launch()
        self.assertEqual(result.returncode,79)
        self.assertFalse((self.root/'sudo-marker').exists())
        self.assertEqual(list(self.root.glob('ouf-audited-recovery.*')),[])

    def test_complete_pinned_delivery_reaches_exact_isolated_command_once(self):
        result=self.launch(True)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        argv=json.loads((self.root/'sudo-marker').read_text())
        self.assertEqual(argv[:4],['/usr/bin/python3.13','-I','-B','-c'])
        self.assertEqual(argv[-2],'DISPOSABLE_DELIVERY_TEST_ONLY')
        directory=Path(argv[-1]);self.assertTrue((directory/'scope.json').exists())
        self.assertEqual(len(list(self.root.glob('ouf-audited-recovery.*'))),1)

    def test_first_and_last_download_failures_never_reach_sudo(self):
        for remote in ('tools/semantic_target_review/execute_audited_provider_recovery.py',
                       'evidence/provider-audited-recovery-scope-20261009.json'):
            with self.subTest(remote=remote):
                result=self.launch(True,CI_FAIL_REMOTE=remote)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse((self.root/'sudo-marker').exists())

    def test_changed_source_bytes_never_reach_sudo(self):
        result=self.launch(True,CI_TAMPER_REMOTE='tools/semantic_transaction_profiles/publish_provider_transaction.py')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'sudo-marker').exists())

    def test_root_failure_is_returned_without_automatic_retry(self):
        result=self.launch(True,CI_SUDO_EXIT='37')
        self.assertEqual(result.returncode,37)
        self.assertIn(b'OUF_AUDITED_RECOVERY_EXIT=37',result.stdout)
        self.assertEqual(len(list(self.root.glob('ouf-audited-recovery.*'))),1)


if __name__=='__main__':unittest.main()
