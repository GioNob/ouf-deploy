"""Readiness profile and actual sealed child HTTP in a root Linux fixture.

Signatures, CAS, namespace FD and loopback HTTP are actual. The lifecycle image
and Engine generation observations are synthetic; this is not full G2 evidence.
"""
import copy
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import readiness as r,contract as c
from tools.chat_recovery_update.readiness import ReadinessDenied

class ReadinessProfile(unittest.TestCase):
    def profile(self):return {'schema':'ouf.ingestion-rollout-ingestion-readiness-local-ns.v1',
        'endpoint':{'host':'127.0.0.2','port':18080},'pythonExecutable':{'path':'/ente-fixture/python','sha256':'a'*64}}
    def test_explicit_ente_port_and_program_without_configurable_api_semantics(self):
        p=self.profile();self.assertEqual(r.validate_profile(p),p)
        p['endpoint']={'host':'::1','port':28080};p['pythonExecutable']['path']='/other-ente/python'
        self.assertEqual(r.validate_profile(p),p)
        p['path']='/arbitrary'
        with self.assertRaises(c.Denied):r.validate_profile(p)
    def test_remote_endpoint_relative_program_or_implicit_port_is_rejected(self):
        for mutation in(lambda p:p['endpoint'].update(host='192.0.2.1'),
                        lambda p:p['endpoint'].pop('port'),lambda p:p['endpoint'].update(port=True),
                        lambda p:p['pythonExecutable'].update(path='python')):
            p=self.profile();mutation(p)
            with self.assertRaises(c.Denied):r.validate_profile(p)
    def test_closed_child_rejects_extra_path_before_namespace_or_network(self):
        for request in({'host':'127.0.0.1','port':18080,'path':'/any'},
                        {'host':'192.0.2.1','port':18080},{'host':'127.0.0.1','port':True}):
            reply=subprocess.run([sys.executable,'-I','-B','-S','-c',r.CHILD_SOURCE,'0'],
                input=c.encoded(request),capture_output=True,timeout=5,check=False)
            self.assertNotEqual(reply.returncode,0);self.assertEqual(reply.stdout,b'');self.assertEqual(reply.stderr,b'')

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root Linux namespace/setns required')
class NativeChildReadiness(unittest.TestCase):
    def setUp(self):
        import test_ingestion_rollout_execution as core
        case=self;self.status=200;self.body=b'{"status":"UP"}';self.retry=None;self.paths=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                case.paths.append(self.path);self.send_response(case.status)
                if case.retry is not None:self.send_header('Retry-After',case.retry)
                self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(case.body)
            def log_message(self,*args):pass
        self.server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
        def close():self.server.shutdown();self.thread.join(5);self.server.server_close()
        self.addCleanup(close)
        self.profile={'schema':'ouf.ingestion-rollout-ingestion-readiness-local-ns.v1',
            'endpoint':{'host':'127.0.0.1','port':self.server.server_port},
            'pythonExecutable':r.governance.executable(os.environ.get('OUF_TEST_PYTHON',sys.executable))}
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            review['ingestionReadinessProfile']=copy.deepcopy(self.profile);review['maximumIngestionReadinessGets']=r.MAX_GETS
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        indices={s['name']:i for i,s in enumerate(self.review['stages'])}
        while self.runner.record()['nextStage']<indices['ingestion.READINESS']:self.runner.step()
        from tools.ingestion_rollout_execution.lifecycle import NativeLifecycle
        from tools.chatbot_file_cohort.human_session import HumanSession
        lifecycle=NativeLifecycle.__new__(NativeLifecycle);lifecycle.action=self.action;lifecycle.journal=self.runner.journal
        lifecycle.review=copy.deepcopy(self.review);lifecycle.scope=self.scope;lifecycle.indices=indices
        human=HumanSession.__new__(HumanSession);human.current=lambda:self.scope['humanBinding'];lifecycle.human=human
        self.first={'containerId':'f'*64,'pid':os.getpid(),'startedAt':'synthetic-first-generation'}
        row=self.runner.record();effects=copy.deepcopy(row['effects'])
        effects[indices['ingestion.START_REPLACEMENT']]['nativeResource']=copy.deepcopy(self.first)
        self.runner.journal.compare_and_save(row,{**row,'effects':effects,'expiresMonotonic':time.monotonic()+240,'version':row['version']+1})
        self.current=True
        def replacement(module,*,phase,process,restored):
            c.require(self.current and process==self.first,'SYNTHETIC_INGESTION_GENERATION_CHANGED')
            return {'State':{'Pid':self.first['pid']}},copy.deepcopy(self.first)
        lifecycle.replacement=replacement
        self.native=r.NativeIngestionReadiness(lifecycle)
    def test_actual_namespace_child_reads_fixed_api_and_persists_attempt(self):
        status,proof=self.native.observe();self.assertEqual(status,'APPLIED')
        self.assertEqual(self.paths,['/actuator/health/readiness']);self.assertTrue(proof['readinessNamespaceBound'])
        self.assertEqual(self.runner.record()['nativeIngestionReadinessGets'],1)
    def test_actual_503_respects_retry_after_without_child_retry(self):
        self.status=503;self.body=b'not ready';self.retry='1000'
        status,proof=self.native.observe();self.assertEqual(status,'TRANSIENT');self.assertEqual(proof['retryAfterSeconds'],1000)
        self.assertEqual(len(self.paths),1)
    def test_actual_unready_200_and_wrong_media_bytes_do_not_prove_readiness(self):
        self.body=b'{"status":"DOWN"}'
        with self.assertRaises(ReadinessDenied):self.native.observe()
        self.assertEqual(self.runner.record()['nativeIngestionReadinessGets'],1)
    def test_generation_change_or_exhausted_budget_blocks_before_http(self):
        self.current=False
        with self.assertRaises(c.Denied):self.native.observe()
        self.assertEqual(self.paths,[]);self.current=True
        row=self.runner.record();self.runner.journal.compare_and_save(row,{**row,'nativeIngestionReadinessGets':128,'version':row['version']+1})
        with self.assertRaises(c.Denied):self.native.observe()
        self.assertEqual(self.paths,[])
    def test_applied_restart_restore_cannot_fall_back_to_disabled_policy(self):
        row=self.runner.record();effects=copy.deepcopy(row['effects'])
        # A direct malformed port must not fabricate another policy fallback.
        original=self.native.lifecycle.replacement
        def replacement(module,*,phase,process,restored):
            if restored:raise c.Denied('SYNTHETIC_RESTORED_RESTART_MISMATCH')
            return original(module,phase=phase,process=process,restored=restored)
        self.native.lifecycle.replacement=replacement
        # Drive the fixture Runner to its final read, retaining every stage.
        while self.runner.record()['nextStage']<len(self.review['stages'])-1:self.runner.step()
        with self.assertRaises(c.Denied):self.native.observe()
        self.assertEqual(self.paths,[])

if __name__=='__main__':unittest.main()
