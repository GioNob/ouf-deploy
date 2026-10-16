"""Real private metadata fixture; no credential contents, network or writes by reader."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('interruption_reader',ROOT/'scripts/read-chatbot-semantic-token-interruption-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Reader(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.prior=self.root/'prior';self.prior.mkdir(mode=0o700)
        records={'recovery.json':{'state':'CANCELLED','controlledCumulativeGrantAttempts':69},
            'owner-session.json':{'private':'NEVER_PRINT_PRIVATE'},'owner-admission.json':{'state':'BLOCKED'},
            'owner-status.json':{'state':'CANCELLED'}}
        pins={k:m.digest(v)for k,v in records.items()}
        for name,value in records.items():self.write(self.prior/name,value)
        proposal={'predecessorJournalDirectory':str(self.prior)}
        review=self.root/'proposal.json';self.write(review,proposal)
        self.pb={'path':str(review),'sha256':m.digest(proposal)}
        self.journal=self.root/('semantic-functional-worker-'+self.pb['sha256']);self.journal.mkdir(mode=0o700)
        self.fence=self.root/'scope.fence.json'
        candidate={'privateReviewHash':self.pb['sha256'],'compiledSessionScope':{'reviewHash':self.pb['sha256'],
            'predecessorRecordHashes':pins,'fenceBinding':{'path':str(self.fence),'value':{'journalPath':str(self.journal)}}}}
        cp=self.root/'candidate.json';self.write(cp,candidate)
        self.context=self.root/'retained';self.context.mkdir(mode=0o700)
        old={'scopes':{'policyTokenOwnerInstallation':{'journalPath':str(self.prior)}}}
        self.write(self.context/'review.json',old);self.write(self.context/'authority.json',{'expired':True})
        self.active=self.root/'semantic-token-execution-abcdefgh';self.active.mkdir(mode=0o700)
        human=self.active/'human-session';human.mkdir(mode=0o700)
        for name in ('recovery.json','human-access.jwt'):
            (human/name).write_bytes(b'INVALID_JSON_PRIVATE_CREDENTIAL_DO_NOT_OPEN');(human/name).chmod(0o600)
        self.rows=[]
        for target,name,value in ((m,'PARENT',self.root),(m,'CONTEXT',self.context),(m,'PRIVATE_REVIEW',self.pb),
                (m,'CANDIDATE',{'path':str(cp),'sha256':m.digest(candidate)}),(m,'REVIEW',m.digest(old)),
                (m,'AUTHORITY',m.digest({'expired':True})),(m,'RETAINED',pins),
                (m.sys,'flags',types.SimpleNamespace(isolated=True)),(m.signal,'alarm',lambda _:None)):
            p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(m,'emit',side_effect=lambda check,**values:self.rows.append({'check':check,**values}));p.start();self.addCleanup(p.stop)
        for name in ('engine_get','stopped'):
            p=patch.object(m,name,side_effect=AssertionError('no native service/API call'));p.start();self.addCleanup(p.stop)
    def write(self,path,value):path.write_bytes(m.encoded(value));path.chmod(0o600)
    def run_reader(self,pids=None):
        with patch.object(m,'processes',return_value=[]if pids is None else pids):m.main()
        return self.rows[-1]
    def test_pre_authority_metadata_is_projected_without_reading_oauth_or_printing_secrets(self):
        original=m.read
        def bound_read(path,*a,**k):
            self.assertNotIn('human-session',str(path));return original(path,*a,**k)
        with patch.object(m,'read',side_effect=bound_read):result=self.run_reader()
        self.assertEqual(result['classification'],'PRE_AUTHORITY_PREPARATION_ONLY_OBSERVED')
        self.assertTrue(result['newAuthorityArtifactsAbsent']);self.assertFalse(result['newWorkerInitialized'])
        self.assertFalse(result['humanSessionCumulativeBudgetProven'])
        self.assertNotIn('PRIVATE',json.dumps(self.rows))
    def test_live_executor_blocks_pre_authority_classification(self):
        result=self.run_reader([123]);self.assertEqual(result['classification'],'RECONCILIATION_REQUIRED')
        self.assertEqual(result['matchingProcessCount'],1)
    def test_each_authority_artifact_fence_and_partial_worker_is_not_safe_to_restart(self):
        paths=[self.active/name for name in ('authority.json','human.json','decision.json','review.json','issuance.claim.json')]
        paths+=[self.active/('a'*64+'.DEPLOYMENT_INTENT.json'),self.active/'unknown.partial',self.fence,self.journal/'recovery.lock']
        for path in paths:
            with self.subTest(path=path.name):
                self.write(path,{'PRIVATE_DO_NOT_READ':True})
                result=self.run_reader();self.assertEqual(result['classification'],'RECONCILIATION_REQUIRED')
                path.unlink()
    def test_changed_predecessor_is_rejected_before_projection(self):
        self.write(self.prior/'owner-status.json',{'state':'ACTIVE'})
        with self.assertRaisesRegex(m.ReadDenied,'CANCELLED_PREDECESSOR_RECORD_CHANGED'):self.run_reader()
    def test_metadata_drift_is_not_reported_as_stable(self):
        with patch.object(m,'new_journal_metadata',side_effect=[{'entryCount':0,'workerInitialized':False},{'entryCount':1}]):
            with self.assertRaisesRegex(m.ReadDenied,'INTERRUPTION_STATE_CHANGED_DURING_READ'):self.run_reader()
    def test_matcher_uses_exact_retained_stage_or_code_namespace(self):
        self.assertTrue(m.process_matches(['python3','-I','-',m.STAGE]))
        self.assertTrue(m.process_matches(['python3','/etc/ouf/deploy-snapshots/semantic-token-executor-code-abcdefgh/execute.py']))
        self.assertFalse(m.process_matches(['python3','/unrelated/execute.py']))
        self.assertFalse(m.process_matches(['python3',m.STAGE+'-different']))

    def test_native_process_scan_finds_only_the_bound_synthetic_child(self):
        if not Path('/proc/self/cmdline').exists():
            if os.environ.get('OUF_NATIVE_UIDS')=='1':self.fail('native procfs required')
            self.skipTest('Work procfs unavailable; native CI requires actual process scan')
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)',m.STAGE],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:self.assertIn(child.pid,m.processes())
        finally:child.terminate();child.wait(timeout=3)

if __name__=='__main__':unittest.main()
