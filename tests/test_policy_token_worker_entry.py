"""Executable loop qualification; genuine source/signatures/TLS, disposable authority."""
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT)]
import test_installed_token_owner as native
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence
from tools.semantic_policy_token_owner.worker_entry import build_worker,serve
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery,RenewalWorker

class WorkerEntryTest(unittest.TestCase):
    def fixture(self):
        case=native.InstalledOwnerTest();self.addCleanup(case.doCleanups)
        f,server,owner,recovery,source,out=case.fixture(scheduled=True)
        worker=build_worker(owner.binding,owner.credential,owner.admission.profile,owner.admission.transport,
            owner.journal,recovery.policy,owner.context,owner.generation,owner.manifest,f.gate(),f.authority,interval_seconds=60)
        return server,owner,worker
    def test_real_factory_loop_publishes_then_cancels_preserving_history(self):
        server,owner,worker=self.fixture();stop=threading.Event();messages=[]
        def emit(value):
            messages.append(value)
            if '"state":"ACTIVE"' in value:stop.set()
        with patch.object(LegacyWriterFence,'guard',return_value=True):serve(worker,stop,OwnerReporter(owner.journal,emit))
        row=owner.journal.read();self.assertEqual(row['state'],'CANCELLED');self.assertEqual(row['attempts'],1)
        self.assertEqual(row['publicationCount'],1);self.assertEqual(owner.store.read()['state'],'BLOCKED')
        self.assertEqual(sum(p.endswith('/token') for p,_ in server.calls),1)
        status=json.loads((owner.journal.root/'owner-status.json').read_text());self.assertEqual(status['state'],'CANCELLED')
        self.assertFalse(status['applicationReady']);self.assertTrue(status['live'])
        self.assertNotIn('FIXTURE_TOKEN',''.join(messages));self.assertNotIn('tokenHash',''.join(messages))
    def test_broken_sink_parks_alive_until_explicit_stop_no_replay(self):
        server,owner,worker=self.fixture();stop=threading.Event();seen=threading.Event();errors=[]
        def broken(_):seen.set();raise OSError('PRIVATE_FIXTURE_SINK')
        def target():
            try:serve(worker,stop,OwnerReporter(owner.journal,broken))
            except Exception as error:errors.append(error)
        with patch.object(LegacyWriterFence,'guard',return_value=True):
            thread=threading.Thread(target=target);thread.start()
            try:
                self.assertTrue(seen.wait(5));time.sleep(.1);self.assertTrue(thread.is_alive())
                self.assertEqual(owner.store.read()['state'],'BLOCKED')
                self.assertEqual(sum(p.endswith('/token') for p,_ in server.calls),1)
            finally:stop.set();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.assertEqual(owner.journal.read()['attempts'],1)
    def test_retained_active_restart_requires_reconciliation_without_new_grant(self):
        server,owner,worker=self.fixture()
        with patch.object(LegacyWriterFence,'guard',return_value=True):
            first=worker.tick();self.assertEqual(first['state'],'ACTIVE')
            restarted=RenewalWorker(worker.r);stop=threading.Event();messages=[]
            def emit(value):messages.append(value);stop.set()
            serve(restarted,stop,OwnerReporter(owner.journal,emit))
        self.assertIn('RECONCILE_REQUIRED',''.join(messages));self.assertEqual(owner.journal.read()['attempts'],1)
        self.assertEqual(sum(p.endswith('/token') for p,_ in server.calls),1)
    def test_factory_rejects_schedule_drift_without_initialization_or_request(self):
        server,owner,worker=self.fixture();before=owner.journal.read()
        with self.assertRaises(Exception):build_worker(owner.binding,owner.credential,owner.admission.profile,owner.admission.transport,
            owner.journal,worker.r.policy,owner.context,owner.generation,owner.manifest,owner.authority,owner.raw,interval_seconds=61)
        self.assertEqual(owner.journal.read(),before);self.assertEqual(server.calls,[])
    def test_status_rejects_extra_private_fields_and_deduplicates_writes(self):
        server,owner,worker=self.fixture();reporter=OwnerReporter(owner.journal,lambda _:None)
        status=worker.status(owner.journal.read());reporter.report(status)
        path=owner.journal.root/'owner-status.json';before=path.stat();reporter.report(status)
        self.assertEqual(path.stat().st_ino,before.st_ino)
        with self.assertRaises(Exception):reporter.report({**status,'token':'PRIVATE_FIXTURE'})
        self.assertNotIn('PRIVATE_FIXTURE',path.read_text());self.assertEqual(server.calls,[])

if __name__=='__main__':unittest.main()
