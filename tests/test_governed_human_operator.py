"""Foreground operator, synthetic consent/provider, actual isolated loader."""
import ast
import hashlib
import json
import os
import pty
import re
import select
import time
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_governed_human_successor as fixtures
from tools.governed_human_successor import operator as op,inspection,auth_delivery
from tools.governed_human_successor import window
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.ingestion_rollout_execution.contract import Denied,digest

class OperatorControl(unittest.TestCase):
    compile=fixtures.GovernedSuccessor.compile
    retained_case=fixtures.GovernedSuccessor.retained_case
    token=fixtures.GovernedSuccessor.token
    discovery=fixtures.GovernedSuccessor.discovery
    device=fixtures.GovernedSuccessor.device
    def setUp(self):
        fixtures.GovernedSuccessor.setUp(self)
        self.case=self.retained_case();self.previous_closure='9'*64;self.closure='8'*64
        self.case['humanOperatorTransportProfile']=dict(op.TRANSPORT)
        clean=os.environ.copy()
        for key in('SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','https_proxy','http_proxy','all_proxy'):
            clean.pop(key,None)
        environment=patch.dict(os.environ,clean,clear=True);environment.start();self.addCleanup(environment.stop)
        notice=patch.object(op,'terminal_notice');notice.start();self.addCleanup(notice.stop)
        prior,_=inspection.inspect_retained(self.case,self.previous_closure)
        self.confirmed={'reviewHash':digest(prior),'sourceClosureHash':self.previous_closure}
    def open(self):
        with patch.object(op,'terminal_confirm',return_value=True):
            result=op.execute('open-window',None,self.case,self.confirmed,self.closure)
        self.control=result['controlPath'];return result
    def test_denied_window_consent_has_zero_writes_and_no_oauth(self):
        before={p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        with patch.object(op,'terminal_confirm',return_value=False),patch.object(ExplicitFreshSession,'_http')as http:
            with self.assertRaises(Denied):op.execute('open-window',None,self.case,self.confirmed,self.closure)
            http.assert_not_called()
        self.assertEqual({p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()},before)
    def test_changed_successful_read_stops_before_consent_or_new_claim(self):
        row={**self.row,'attempts':279};self.old.compare_and_save(self.row,row)
        with patch.object(op,'terminal_confirm')as consent:
            with self.assertRaisesRegex(Denied,'SUCCESSFUL_READ_HISTORY_CHANGED'):
                op.execute('open-window',None,self.case,self.confirmed,self.closure)
            consent.assert_not_called()
        self.assertFalse((self.previous/'successor-window.claim.json').exists())
    def test_unreviewed_tls_or_proxy_override_blocks_before_consent(self):
        for field,value in [('SSL_CERT_FILE','/fixture/foreign-ca.pem'),('HTTPS_PROXY','https://fixture-proxy.invalid')]:
            with self.subTest(field=field),patch.dict(os.environ,{field:value}),patch.object(op,'terminal_confirm')as consent:
                with self.assertRaisesRegex(Denied,'UNREVIEWED_TLS_OR_PROXY_ENVIRONMENT_OVERRIDE_FORBIDDEN'):
                    op.execute('open-window',None,self.case,self.confirmed,self.closure)
                consent.assert_not_called()
        self.assertFalse((self.previous/'successor-window.claim.json').exists())
    def test_open_is_one_claim_no_request_and_cannot_be_reopened(self):
        with patch.object(ExplicitFreshSession,'_http')as http:result=self.open();http.assert_not_called()
        self.assertEqual((result['state'],result['attempts'],result['remainingAttempts']),('NEW',278,10))
        self.assertEqual(result['oauthRequestsReservedThisInvocation'],0);self.assertFalse(result['complete'])
        with patch.object(op,'terminal_confirm')as consent:
            with self.assertRaisesRegex(Denied,'REQUIRES_RECONCILIATION_NO_REOPEN'):
                op.execute('open-window',None,self.case,self.confirmed,self.closure)
            consent.assert_not_called()
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
    def test_denied_provider_confirmation_never_reserves_or_dispatches(self):
        self.open()
        with patch.object(op,'terminal_confirm',return_value=False),patch.object(ExplicitFreshSession,'_http')as http:
            with self.assertRaises(Denied):op.execute('step',self.control,self.case,self.confirmed,self.closure)
            http.assert_not_called()
        result=op.execute('status',self.control,self.case,self.confirmed,self.closure)
        self.assertEqual((result['state'],result['attempts']),('NEW',278))
    def test_four_confirmed_steps_create_only_private_human_reader(self):
        self.open();token=self.token()
        replies=[self.discovery(),self.device(),(200,{'access_token':token,'refresh_token':'fixture-refresh','token_type':'Bearer'},0),
            (200,{'sub':self.selection['subject']},0)]
        with patch.object(op,'terminal_confirm',return_value=True)as consent,patch.object(ExplicitFreshSession,'_http',side_effect=replies)as http:
            one=op.execute('step',self.control,self.case,self.confirmed,self.closure)
            two=op.execute('step',self.control,self.case,self.confirmed,self.closure)
            self.assertEqual((one['state'],two['state']),('DEVICE_START','DEVICE_POLL'))
            paused=op.execute('step',self.control,self.case,self.confirmed,self.closure)
            self.assertEqual(paused['status'],'WAIT_EXPLICIT_STEP');self.assertEqual(http.call_count,2)
            self.assertEqual(consent.call_count,2);self.now+=6
            three=op.execute('step',self.control,self.case,self.confirmed,self.closure)
            four=op.execute('step',self.control,self.case,self.confirmed,self.closure)
            self.assertEqual(three['state'],'VERIFYING');self.assertEqual(four['state'],'READY')
            self.assertEqual((four['attempts'],four['remainingAttempts']),(282,6))
            self.assertTrue(four['complete']);self.assertTrue(four['providerVerificationCompleted'])
            self.assertFalse(four['nativeClientProfilePublished']);self.assertEqual(http.call_count,4)
            self.assertEqual(consent.call_count,4)
            again=op.execute('step',self.control,self.case,self.confirmed,self.closure)
            self.assertEqual(again['state'],'READY');self.assertEqual(http.call_count,4);self.assertEqual(consent.call_count,4)
        self.assertTrue(Path(four['privateHumanReadProfilePath']).is_file())
        self.assertNotIn(token,json.dumps(four));self.assertNotIn('fixture-refresh',json.dumps(four))
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
    def test_control_source_case_or_claim_drift_blocks_before_provider(self):
        self.open()
        with patch.object(ExplicitFreshSession,'_http')as http:
            for closure,case in [('7'*64,self.case),(self.closure,{**self.case,'changed':True})]:
                with self.subTest(closure=closure,caseChanged=case!=self.case),self.assertRaises(Denied):
                    op.execute('step',self.control,case,self.confirmed,closure)
            claim=self.previous/'successor-window.claim.json';value=json.loads(claim.read_text())
            value['maximumCumulativeOAuthAttempts']=999;claim.write_text(json.dumps(value))
            with self.assertRaisesRegex(Denied,'EXACT_CONSUMED_WINDOW_CLAIM_REQUIRED'):
                op.execute('step',self.control,self.case,self.confirmed,self.closure)
            http.assert_not_called()
    def test_partial_control_after_window_claim_retained_without_reopen(self):
        write=op.write_new
        def interrupted(directory,name,value):
            if name=='binding.json':raise OSError('synthetic failure after initialization')
            return write(directory,name,value)
        with patch.object(op,'terminal_confirm',return_value=True),patch.object(op,'write_new',side_effect=interrupted):
            with self.assertRaises(OSError):op.execute('open-window',None,self.case,self.confirmed,self.closure)
        control=Path(op.CHECKPOINT['controlPath']);self.assertTrue((control/'control.json').is_file())
        self.assertFalse((control/'binding.json').exists());self.assertTrue((self.previous/'successor-window.claim.json').is_file())
        with patch.object(op,'terminal_confirm')as consent:
            with self.assertRaisesRegex(Denied,'REQUIRES_RECONCILIATION_NO_REOPEN'):
                op.execute('open-window',None,self.case,self.confirmed,self.closure)
            consent.assert_not_called()
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
    def test_actual_isolated_sealed_operator_status_and_tamper_rejection(self):
        raw,declaration=auth_delivery.generate(ROOT,self.case,self.confirmed)
        self.closure=digest(declaration);self.open()
        script=self.root/'operator.py';script.write_bytes(raw);script.chmod(0o600)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(script),'status',self.control],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        result=json.loads(run.stdout);self.assertEqual((result['state'],result['attempts']),('NEW',278))
        self.assertEqual(result['oauthRequestsReservedThisInvocation'],0);self.assertFalse(result['complete'])
        self.assertNotIn('old-access',run.stdout);self.assertNotIn('old-refresh',run.stdout)
        modified=raw.replace(b"'foregroundOnly': True",b"'foregroundOnly': False",1)
        self.assertNotEqual(modified,raw);script.write_bytes(modified)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(script),'status',self.control],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,2);self.assertEqual(json.loads(run.stdout)['status'],'STOP_RECONCILE')
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
    def test_operator_delivery_reproducible_from_closed_sources(self):
        script=ROOT/'scripts/human-successor-explicit-operator-20261020.py'
        values={}
        for node in ast.parse(script.read_bytes()).body:
            if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in('CASE','CONFIRMED_READ'):
                values[node.targets[0].id]=ast.literal_eval(node.value)
        raw,_=auth_delivery.generate(ROOT,values['CASE'],values['CONFIRMED_READ'])
        self.assertEqual(script.read_bytes(),raw)
    def real_boot_sealed_fixture(self):
        boot=Path('/proc/sys/kernel/random/boot_id')
        if not boot.is_file():self.skipTest('Actual Linux boot identifier and controlling terminal qualified in root CI')
        value=boot.read_text().strip();row={**self.row,'bootId':value}
        self.old.compare_and_save(self.row,row);self.row=row;self.old_bytes=self.old.record.read_bytes()
        with patch.object(window,'boot_id',return_value=value):
            prior,_=inspection.inspect_retained(self.case,self.previous_closure)
        self.confirmed={'reviewHash':digest(prior),'sourceClosureHash':self.previous_closure}
        raw,_=auth_delivery.generate(ROOT,self.case,self.confirmed)
        script=self.root/'sealed-real-terminal.py';script.write_bytes(raw);script.chmod(0o600)
        return script
    def test_actual_sealed_window_requires_real_tty_and_consumes_one_claim_without_oauth(self):
        script=self.real_boot_sealed_fixture();pid,fd=pty.fork()
        if pid==0:
            os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(script),'open-window'])
        output=b'';sent=False;status=None;deadline=time.monotonic()+20
        try:
            while time.monotonic()<deadline:
                if select.select([fd],[],[],0.1)[0]:
                    try:part=os.read(fd,65536)
                    except OSError:part=b''
                    output+=part
                    match=re.search(rb'Scrivi esattamente: (APRO FINESTRA HUMAN [0-9a-f]{64})',output)
                    if match and not sent:os.write(fd,match[1]+b'\n');sent=True
                ended,status=os.waitpid(pid,os.WNOHANG)
                if ended:
                    for _ in range(32):
                        if not select.select([fd],[],[],0)[0]:break
                        try:part=os.read(fd,65536)
                        except OSError:break
                        if not part:break
                        output+=part
                    break
            else:
                os.kill(pid,9);os.waitpid(pid,0);self.fail('Bounded synthetic terminal fixture exceeded20seconds')
        finally:os.close(fd)
        self.assertTrue(sent);self.assertEqual(os.waitstatus_to_exitcode(status),0,output.decode(errors='replace'))
        results=[json.loads(line)for line in output.decode().splitlines()if line.startswith('{')]
        self.assertTrue(results,output.decode());result=results[-1]
        self.assertEqual((result['state'],result['attempts'],result['remainingAttempts']),('NEW',278,10))
        self.assertEqual(result['oauthRequestsReservedThisInvocation'],0)
        claim=self.previous/'successor-window.claim.json';before=claim.read_bytes()
        self.assertFalse((Path(result['controlPath'])/'human-read-profile.json').exists())
        retry=subprocess.run([sys.executable,'-I','-B','-S',str(script),'open-window'],capture_output=True,text=True,timeout=20)
        self.assertEqual(retry.returncode,2);self.assertEqual(json.loads(retry.stdout)['status'],'STOP_RECONCILE')
        self.assertEqual(claim.read_bytes(),before);self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
    def test_piped_answer_cannot_approve_sealed_window(self):
        script=self.real_boot_sealed_fixture()
        result=subprocess.run([sys.executable,'-I','-B','-S',str(script),'open-window'],
            input='APRO FINESTRA HUMAN '+'0'*64+'\n',capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['status'],'STOP_RECONCILE')
        self.assertFalse((self.previous/'successor-window.claim.json').exists())
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)

if __name__=='__main__':unittest.main()
