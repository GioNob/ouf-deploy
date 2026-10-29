"""Actual namespace HTTP child; synthetic Owner generation/HUMAN, real role CAS."""
import http.server
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_owner_read as fixture
from tools.ingestion_rollout_execution import owner_read as o,contract as c

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root namespace/role/CAS required')
class OwnerHttpTransient(unittest.TestCase):
    def setUp(self):
        case=self;self.status=503;self.retry='17';self.requests=0
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                case.requests+=1;self.send_response(case.status);self.send_header('Retry-After',case.retry)
                self.send_header('Content-Length','0');self.end_headers()
            def log_message(self,*args):pass
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        original=fixture.profile
        def profile(file,program=None):
            value=original(file,program);value['endpoint']={'host':'127.0.0.1','port':self.server.server_port};return value
        with patch.object(fixture,'profile',profile):fixture.SignedOwnerControl.setUp(self)
        fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC);self.addCleanup(os.close,fd);self.pin.fd=fd
        self.native.token=lambda:'fixture.bearer.value'
        row=self.runner.record()
        self.runner.journal.compare_and_save(row,{**row,'expiresMonotonic':time.monotonic()+240,'version':row['version']+1})
    def test_real_503_child_discards_body_and_returns_finite_retry_floor(self):
        with self.assertRaises(c.ReadTransient)as error:o.NativeOwnerRead.get(self.native,'/active')
        self.assertEqual(error.exception.retry_after_seconds,17)
        self.assertEqual(self.requests,1);self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],1)
    def test_revoked_http_401_is_permanent_and_never_retries(self):
        self.status=401
        with self.assertRaises(c.Denied):o.NativeOwnerRead.get(self.native,'/active')
        self.assertEqual(self.requests,1);self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],1)
    def test_invalid_retry_after_cannot_authorize_an_implicit_retry(self):
        self.retry='not-a-date'
        with self.assertRaises(c.Denied):o.NativeOwnerRead.get(self.native,'/active')
        self.assertEqual(self.requests,1);self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],1)

if __name__=='__main__':unittest.main()
