"""Actual flock race, bounded wait and durable redaction; CI only, no Docker."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from repair_broker_sources import BROKER,RUNTIME,repair

DRAFT=Path(__file__).resolve().parents[1]/'semantic_cohort_admission/cohort-draft'
sys.path.insert(0,str(DRAFT))
from tools.semantic_provider_lease_coordination import hold_common_lock
from tools.semantic_provider_deployment_authentication import VerificationBudget

class BrokerSourceRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()))
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'lock';self.path.write_bytes(b'');self.path.chmod(0o600)
        sources={n:(DRAFT/n).read_bytes() for n in (BROKER,RUNTIME)}
        self.repaired=repair(sources)
        self.module={'__name__':'broker_repair_test','__file__':str(DRAFT/BROKER)}
        exec(compile(self.repaired[BROKER],str(DRAFT/BROKER),'exec'),self.module)

    def test_original_lock_denies_concurrent_creator_then_bounded_lock_waits(self):
        with hold_common_lock(self.path):
            with self.assertRaises(BlockingIOError):
                with hold_common_lock(self.path):self.fail('old lock unexpectedly entered')
            entered=[];started=threading.Event();errors=[]
            def worker():
                started.set()
                try:
                    with self.module['bounded_broker_lock'](self.path,VerificationBudget(2)):
                        entered.append(self.path.stat().st_ino)
                except Exception as error:errors.append(error)
            thread=threading.Thread(target=worker);thread.start();started.wait(timeout=1)
            time.sleep(.05);self.assertEqual(entered,[])
        thread.join(timeout=2);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.assertEqual(entered,[self.path.stat().st_ino])

    def test_lock_timeout_grants_nothing_and_keeps_same_inode(self):
        inode=self.path.stat().st_ino
        with hold_common_lock(self.path):
            with self.assertRaisesRegex(Exception,'AUTHENTICATION_DEADLINE_MISSED'):
                with self.module['bounded_broker_lock'](self.path,VerificationBudget(1)):
                    self.fail('blocked lock granted authority')
        self.assertEqual(self.path.stat().st_ino,inode)

    def test_body_error_is_never_retried(self):
        entered=[]
        with self.assertRaises(BlockingIOError):
            with self.module['bounded_broker_lock'](self.path,VerificationBudget(2)):
                entered.append(1);raise BlockingIOError('inside operation')
        self.assertEqual(entered,[1])
        with hold_common_lock(self.path):pass

    def test_denial_saved_redacted_and_first_evidence_never_overwritten(self):
        cid='a'*64;root=self.root/cid;root.mkdir(mode=0o700)
        journal=root/'broker-state.json';journal.write_text(json.dumps({'containerId':cid}));journal.chmod(0o600)
        args=SimpleNamespace(mode='authorize-create',container_id=cid)
        value=self.module['retained_denial'](BlockingIOError('TOKEN=SECRET'),args,{'candidateRoot':str(root)})
        p=root/'broker-denial-authorize-create.json';raw=p.read_bytes()
        self.assertTrue(value['diagnosisSaved']);self.assertNotIn(b'SECRET',raw)
        self.assertEqual(json.loads(raw)['reason'],'BROKER_COMMON_LOCK_BUSY')
        second=self.module['retained_denial'](ValueError('NEW_SECRET'),args,{'candidateRoot':str(root)})
        self.assertFalse(second['diagnosisSaved']);self.assertEqual(p.read_bytes(),raw)

    def test_only_exact_original_sources_repaired(self):
        sources={n:(DRAFT/n).read_bytes() for n in (BROKER,RUNTIME)}
        sources[BROKER]+=b'\n'
        with self.assertRaisesRegex(ValueError,'ORIGINAL_BROKER_SOURCE_HASH_DRIFT'):repair(sources)

if __name__=='__main__':unittest.main()
