"""Disposable composed owner/signature/TLS/fencing qualification.

Uses only synthetic roles, credentials, token responses and Docker metadata.
Systemctl/IAM admin are simulated by the existing installation fixture.
Requires native root/group10001; Work may use the explicitly separate local
metadata adapter. It is never production deployment acceptance.
"""
import copy
import dataclasses
import json
import os
from pathlib import Path
import socketserver
import sys
import threading
import time
import traceback
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT)]
import test_policy_token_owner_installation as fixture
from tools.chatbot_file_cohort.continued_owner import GovernedSemanticOwnerContinuation
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_lease_recovery.bounded_recovery import fingerprint

class Composed(unittest.TestCase):
    def setUp(self):
        base=fixture.OwnerInstallationTest();base.setUp();self.addCleanup(base.doCleanups)
        self.base=base;self.f=base.f;self.installed=base.installation
        self.installed.install()
        i=self.installed
        self.first=json.loads((i.journal.root/'owner-first-grant.json').read_bytes())
        old_session=json.loads((i.journal.root/'owner-session.json').read_bytes())
        old_session.update(schema='ouf.policy-token-new-finite-worker-session.v10',predecessorGrantAttempts=10,
            policy={'delays':[5,15,60,300,900],'max_attempts':128,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2})
        old=json.loads((i.journal.root/'recovery.json').read_bytes())
        old.update(state='CANCELLED',reason='CANCELLED_BY_OWNER',attempts=59,
            controlledPredecessorGrantAttempts=10,controlledCumulativeGrantAttempts=69,
            workerSessionHash=fingerprint(old_session),policyHash=fingerprint(old_session['policy']))
        self.records={'recovery.json':old,'owner-session.json':old_session,
            'owner-admission.json':{**json.loads((i.journal.root/'owner-admission.json').read_bytes()),'state':'BLOCKED'},
            'owner-status.json':{'state':'CANCELLED','reason':'CANCELLED_BY_OWNER'}}
        for name,value in self.records.items():self.f.f.write(i.journal.root/name,fixture.fixture.binding.encoded(value))
        self.before={name:(i.journal.root/name).read_bytes()for name in self.records}
        self.actual={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Running':True,'Pid':123,'StartedAt':'fixture'},
            'Mounts':[],'Config':{},'HostConfig':{},'NetworkSettings':{}}
        generation={'containerId':self.actual['Id'],'imageId':self.actual['Image'],'pid':123,'startedAt':'fixture',
            'mountsHash':fingerprint([]),'configHash':fingerprint({}),'hostConfigHash':fingerprint({}),
            'networkSettingsHash':fingerprint({})}
        self.engine_calls=[];owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                owner.engine_calls.append(('GET',self.path))
                raw=fixture.fixture.binding.encoded(owner.actual)
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        import tempfile
        self.socket_dir=Path(tempfile.mkdtemp(prefix='sock-',dir=ROOT));self.addCleanup(__import__('shutil').rmtree,self.socket_dir)
        socket=self.socket_dir/'d';self.engine=socketserver.UnixStreamServer(str(socket),Handler);socket.chmod(0o600)
        thread=threading.Thread(target=self.engine.serve_forever,daemon=True);thread.start()
        def stop():self.engine.shutdown();thread.join(2);self.engine.server_close()
        self.addCleanup(stop)
        s=socket.stat();self.engine_binding={'socketPath':str(socket),
            'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777]}
        host=self.f.root/'copied-host.json';self.f.f.write(host,i.host_raw)
        profile=dataclasses.asdict(i.first.profile)
        self.value={'hostInputBinding':{'path':str(host),'sha256':fixture.fixture.binding.sha(i.host_raw)},
            'rootEvidenceHash':i.root_hash,'rootCreationSourceClosureHash':i.root_source,
            'binding':dataclasses.asdict(i.first.binding),'iamProfile':profile,
            'tlsTrustSetHash':i.first.transport.trust_digest()}
        self.review={'schema':'ouf.chatbot-semantic-functional-session-review.v1','readyForExecution':False,
            'runtimeAuthorityIssued':False,'humanApprovalGranted':False,'retainedOwnerInputsHash':fingerprint(self.value),
            'predecessorRecordHashes':{k:fingerprint(v)for k,v in self.records.items()},
            'predecessorJournalDirectory':str(i.journal.root),'registryGeneration':generation,
            'proposedFiniteBudget':{'priorControlledGrantAttempts':69,'predecessorWorkerAttempts':59,
                'maximumNewTokenGrantAttempts':128,'maximumCumulativeGrantAttempts':197,
                'maximumSeconds':3600,'renewalIntervalSeconds':60,'automaticRenewalAllowed':False},
            'requiredOwnerDecision':{'explicitContinuationAfterOwnerCancellationRequired':True,
                'freshAuthenticatedHumanDecisionRequired':True,'newJournalAndPersistentFencingRequired':True},
            'requestedHumanActor':{'issuer':'fixture','tenant':'fixture','subject':'fixture'},
            'commandKey':'stable-command','proposalHash':'f'*64,'logicalOperation':'fixture-semantic-session'}
        self.review_path=self.f.root/'semantic-review.json';self.f.f.write(self.review_path,fixture.fixture.binding.encoded(self.review))
        scope=compile_governed_session(self.review,self.records,self.first,old_session['policy'],
            fingerprint({'operation':self.review['logicalOperation'],'reviewHash':fingerprint(self.review)}),fingerprint(generation),60)
        self.journal=Path(scope['fenceBinding']['value']['journalPath']);self.journal.mkdir(mode=0o700)
        self.sign(self.make().scopes())

    def make(self):
        action=AggregateAction(self.f.f.gate(),self.f.f.authority,self.f.f.expected['sourceClosureHash'])
        return GovernedSemanticOwnerContinuation(action,self.value,self.base.files,'a'*40,self.review,self.records,
            self.first,{'path':str(self.review_path),'sha256':fingerprint(self.review)},self.engine_binding,self.journal,
            self.f.clock,transport=self.installed.first.transport)

    def sign(self,scopes):
        f=self.f.f;raw=json.loads(f.authority);raw.update(scopes)
        f.authority=fixture.fixture.binding.encoded(raw);f.approval['executionAuthorityHash']=fixture.fixture.binding.sha(f.authority)
        f.write(f.mandate,fixture.fixture.binding.encoded(f.approval));f.approved=fixture.fixture.binding.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)

    def grants(self):return self.base.grants()

    def test_new_session_install_has_no_grant_rotation_or_old_record_mutation(self):
        before=(self.grants(),len(self.f.calls),len(self.f.commands));installer=self.make();worker=installer.install()
        self.assertEqual(before,(self.grants(),len(self.f.calls),len(self.f.commands)))
        self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'],69)
        self.assertFalse(worker.active_here)
        row=worker.tick();self.assertEqual(row['state'],'ACTIVE')
        self.assertEqual(row['controlledCumulativeGrantAttempts'],70);self.assertEqual(row['attempts'],1)
        self.assertEqual(self.grants(),before[0]+1)
        for name,raw in self.before.items():self.assertEqual((self.installed.journal.root/name).read_bytes(),raw)
        with self.assertRaises(Exception):self.make().install()
        self.assertEqual(self.grants(),before[0]+1)
        self.assertTrue(all(method=='GET'for method,path in self.engine_calls))

    def test_missing_scope_and_generation_drift_deny_before_claim_or_grant(self):
        installer=self.make();before=self.grants();raw=json.loads(self.f.f.authority);raw.pop('semanticFunctionalRuntime')
        self.f.f.authority=fixture.fixture.binding.encoded(raw)
        with self.assertRaises(Exception):self.make().install()
        self.assertEqual(self.grants(),before)
        self.sign(installer.scopes());self.actual['State']['Pid']=124
        with self.assertRaises(Exception):self.make().install()
        self.assertEqual(self.grants(),before)
        self.assertFalse(Path(installer.worker_scope['fenceBinding']['path']).exists())

    def test_revoked_authority_and_missing_fence_stop_without_grant(self):
        installer=self.make();worker=installer.install();before=self.grants()
        fence=Path(installer.worker_scope['fenceBinding']['path']);fence.unlink()
        self.assertEqual(worker.tick()['state'],'BLOCKED');self.assertEqual(self.grants(),before)
        self.f.f.approval['state']='REVOKED';self.f.f.write(self.f.f.mandate,fixture.fixture.binding.encoded(self.f.f.approval))
        with self.assertRaises(Exception):self.make().install()
        self.assertEqual(self.grants(),before)

    def test_two_operator_installations_share_one_exclusive_global_claim(self):
        from tools.semantic_policy_token_owner.owner_installation import OwnerInstallation
        first,second=self.make(),self.make();before=self.grants();barrier=threading.Barrier(2)
        original=OwnerInstallation._write_once;outcomes=[];diagnostics=[]
        def write(installer,directory,name,raw):
            if name.endswith('.fence.json'):barrier.wait(timeout=20)
            return original(installer,directory,name,raw)
        def run(installer):
            try:installer.install();outcomes.append('INSTALLED')
            except FileExistsError:outcomes.append('ALREADY_CLAIMED')
            except Exception as error:
                outcomes.append(type(error).__name__);diagnostics.append(traceback.format_exc())
        with patch.object(OwnerInstallation,'_write_once',write):
            threads=[threading.Thread(target=run,args=(i,))for i in(first,second)]
            for thread in threads:thread.start()
            for thread in threads:thread.join(40)
        self.assertEqual(sorted(outcomes),['ALREADY_CLAIMED','INSTALLED'],'\n'.join(diagnostics))
        self.assertEqual(self.grants(),before)

    def test_exhausted_cumulative_budget_cannot_issue_an_extra_grant(self):
        installer=self.make();worker=installer.install();row=worker.tick()
        self.assertEqual(row['state'],'ACTIVE');before=self.grants()
        exhausted={**row,'attempts':128,'controlledCumulativeGrantAttempts':197}
        worker.r.journal.compare_and_save(row,exhausted)
        after=worker.tick()
        self.assertEqual(after['state'],'PAUSED_EXHAUSTED')
        self.assertEqual(after['controlledCumulativeGrantAttempts'],197)
        self.assertEqual(self.grants(),before)

if __name__=='__main__':unittest.main()
