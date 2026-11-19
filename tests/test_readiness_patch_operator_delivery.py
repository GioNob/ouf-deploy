"""Actual verified-memory controller capsule, real issuer and pseudo-terminal.

A synthetic HUMAN/qualification and non-invoked Python Docker slot are explicit
fixture inputs. No real provider, Docker runtime or production authority here.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_operator_control as fixture
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_readiness_patch_execution import operator_delivery as d,entry as e

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root private capsule/TTY fixtures required')
class OperatorDelivery(unittest.TestCase):
    def setUp(self):
        fixture.OperatorControl.setUpClass()
        self.fixture=fixture.OperatorControl();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.case=copy.deepcopy(self.fixture.case);self.bundle=copy.deepcopy(self.fixture.bundle)
        # All executable and stdlib checks remain real in the isolated child.
        program=e.authority.governance.executable('/usr/bin/python3')
        for k in ('ownerControlProfile','unchangedGatewayTransportProfile','ingestionReadinessProfile'):
            self.bundle[k]['pythonExecutable']=copy.deepcopy(program)
        for k in ('databaseControlProfile','imageImportProfile'):self.bundle[k]['dockerExecutable']=copy.deepcopy(program)
        payload,manifest=d.core(ROOT);self.case['nativeDeclarationHash']=d.sha(d.encoded(manifest))
        self.case['qualification']['sourceCommit']=manifest['sourceCommit']
        self.case['qualification']['sourceHashes']=manifest['sourceHashes']
        p=Path(self.case['nativeInputsPath']);p.chmod(0o600);p.write_bytes(e.c.encoded(self.bundle));p.chmod(0o400)
        self.case['nativeInputsHash']=e.c.digest(self.bundle)
        receipt=copy.deepcopy(self.fixture.receipt);receipt['bundleHash']=self.case['nativeInputsHash']
        p=p.parent/'complete.json';p.chmod(0o600);p.write_bytes(e.c.encoded(receipt));p.chmod(0o400)
        self.case['nativeReceiptHash']=e.c.digest(receipt)
        human=self.fixture.fixture.human;row=human.journal.read();renewal=copy.deepcopy(row['governedWindowRenewal'])
        renewal['review']['operationBinding']={'runtimeCaseHash':e.c.digest(self.case),'nativeInputsHash':self.case['nativeInputsHash'],
            'logicalOperationRef':self.case['logicalOperationRef'],'controlSourceHash':self.case['controlSourceHash']}
        renewal['decision']['reviewHash']=e.c.digest(renewal['review'])
        # The child's real boot ID is used; the synthetic provider receipt stays
        # an explicit fixture. No authentication is performed by this test.
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        human.journal.compare_and_save(row,{**row,'bootId':boot,'governedWindowRenewal':renewal,'version':row['version']+1})
        profile=copy.deepcopy(self.fixture.fixture.profile);profile.update(expectedBootId=boot,journal=binding(human.journal.record),
            governedWindowReceiptHash=e.c.digest(renewal))
        self.profile=self.root/'read-profile.json';self.profile.write_bytes(e.c.encoded(profile));self.profile.chmod(0o400)
        self.raw,self.declaration=d.generate(ROOT,self.case)
        self.path=self.root/'operator.py';self.path.write_bytes(self.raw);self.path.chmod(0o400)
        self.target=self.root/('ingestion-readiness-execution-'+e.c.digest(self.case))
    def call(self,*args):
        return subprocess.run(['/usr/bin/python3','-I','-B','-S',str(self.path),*args],capture_output=True,text=True,timeout=60)
    def result(self,*args):
        value=self.call(*args);self.assertEqual(value.returncode,0,value.stderr+value.stdout)
        return json.loads(value.stdout)
    def tty_approve(self,phrase):
        import fcntl
        import termios
        master,slave=os.openpty()
        def setup():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        child=subprocess.Popen(['/usr/bin/python3','-I','-B','-S',str(self.path),'approve'],
            stdin=slave,stdout=slave,stderr=slave,preexec_fn=setup,close_fds=True)
        os.close(slave);output=bytearray();sent=False;deadline=time.monotonic()+60
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],.1)
                if ready:
                    try:raw=os.read(master,65536)
                    except OSError:break
                    if not raw:break
                    output.extend(raw)
                    if not sent and b'> ' in output:os.write(master,phrase.encode()+b'\n');sent=True
                if child.poll()is not None and not ready:break
            self.assertTrue(sent,'exact real TTY prompt was not reached')
            self.assertEqual(child.wait(timeout=5),0,output.decode(errors='replace'))
            return output.decode()
        finally:
            if child.poll()is None:child.kill();child.wait(timeout=5)
            os.close(master)
    def test_real_capsule_preflight_review_tty_two_roles_and_initialize_no_effects(self):
        self.assertEqual(d.generate(ROOT,self.case)[0],self.raw)
        self.assertEqual(self.result('preflight')['status'],'PATCH_RUNTIME_PREFLIGHT_NO_AUTHORITY')
        self.assertFalse(self.target.exists())
        self.assertEqual(self.result('review',str(self.profile))['status'],'PATCH_RUNTIME_REVIEW_READY_EXPLICIT_APPROVAL_REQUIRED')
        review=json.loads((self.target/'review.json').read_bytes())
        output=self.tty_approve('APPROVO '+e.c.digest(review))
        self.assertIn('PATCH_AUTHORITY_ISSUED_EXPLICIT_INITIALIZE_REQUIRED',output)
        self.assertTrue(self.result('initialize')['initialized'])
        self.assertEqual(len(list(self.target.glob('*.DEPLOYMENT_INTENT.json'))),1)
        self.assertEqual(len(list(self.target.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
        status=self.result('status');self.assertEqual(status['nextStage'],0);self.assertEqual(status['runtimeEffectsRecorded'],0)
        again=self.call('initialize');self.assertEqual(again.returncode,2)
        self.assertEqual(json.loads(again.stdout)['status'],'STOP_RECONCILE')
    def test_changed_case_and_invalid_mode_fail_before_any_context(self):
        changed=copy.deepcopy(self.case);changed['nativeInputsHash']='0'*64
        self.path.chmod(0o600);self.path.write_text(self.raw.decode().replace('CASE='+repr(self.case),'CASE='+repr(changed),1));self.path.chmod(0o400)
        result=self.call('preflight');self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['reasonCode'],'PATCH_OPERATOR_CASE_CHANGED')
        self.assertFalse(self.target.exists())
        result=self.call('auto');self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['reasonCode'],'ONE_EXPLICIT_PATCH_OPERATOR_MODE_REQUIRED')

if __name__=='__main__':unittest.main()
