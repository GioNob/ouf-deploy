"""Signed native composition boundaries with synthetic external services.

No Docker/APISIX/JVM qualification is inferred. Existing component tests prove
the actual FD, role, CAS and sealed-child boundaries separately.
"""
import copy
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_execution as core
import test_ingestion_rollout_native_review as review_fixture
from tools.ingestion_rollout_execution import native as n,contract as c
from tools.chatbot_file_cohort.human_session import HumanSession

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual role signatures and CAS required')
class NativeComposition(unittest.TestCase):
    def setUp(self):
        self.fixture=review_fixture.NativeReview();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        def fixture(context='/fixture/execution',key_path=None):
            review=self.fixture.compile();review['executionContext']=context
            return review,self.fixture.packet,self.fixture.inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        row=self.runner.journal.read();mono=time.monotonic()
        self.runner.journal.compare_and_save(row,{**row,'expiresMonotonic':mono+480,'version':row['version']+1})
        self.human=HumanSession.__new__(HumanSession);self.human.current=lambda:self.scope['humanBinding']
        self.native=n.NativePorts(self.action,self.runner.journal,self.review,self.fixture.packet,self.human)
        self.addCleanup(self.native.close)
        self.stage=self.review['stages'][0]
    def facts(self):
        return {'observedAtUnix':int(time.time()),'databaseReadPrerequisitesProven':True}
    def configured_services(self):
        self.native.prepare=Mock();self.native.generations=Mock()
        self.native.owner=Mock();self.native.owner.verify.return_value={'ownerActiveAndStrongEtagMatched':True}
        self.native.database=Mock();self.native.database.snapshot.side_effect=self.facts
    def claim(self,name):
        i=self.native.indices[name];stages=self.review['stages']
        effects=[{'stage':s['name'],'intentHash':s['intentHash'],'state':'APPLIED'if j<i else'CLAIMED'}
                 for j,s in enumerate(stages[:i+1])]
        row=self.runner.journal.read()
        self.runner.journal.compare_and_save(row,{**row,'nextStage':i,'effects':effects,'version':row['version']+1})
        return stages[i]
    def test_constructor_is_inert_and_human_drift_blocks_before_engine_io(self):
        self.assertIsNone(self.native.engine)
        self.human.current=lambda:{**self.scope['humanBinding'],'sessionId':'foreign'}
        with patch.object(n,'Engine')as engine:
            with self.assertRaises(c.Denied):self.native.guard_current(self.stage)
            engine.assert_not_called()
    def test_current_guards_order_database_last_and_reject_stale_snapshot(self):
        self.configured_services();events=[]
        self.native.generations.side_effect=lambda:events.append('generations')
        self.native.owner.verify.side_effect=lambda:events.append('owner')or{'ownerActiveAndStrongEtagMatched':True}
        self.native.database.snapshot.side_effect=lambda:events.append('database')or self.facts()
        self.native.guard_current(self.stage);self.assertEqual(events,['generations','owner','database'])
        self.native.database.snapshot.side_effect=lambda:{**self.facts(),'observedAtUnix':int(time.time())-6}
        with self.assertRaises(c.Denied):self.native.guard_current(self.stage)
        with self.assertRaises(c.Denied):self.native.fresh(self.stage)
    def test_failed_owner_recheck_invalidates_previous_fresh_proof(self):
        self.configured_services();self.native.guard_current(self.stage)
        self.native.owner.verify.side_effect=c.Denied('synthetic owner changed')
        with self.assertRaises(c.Denied):self.native.guard_current(self.stage)
        self.assertIsNone(self.native.last_gates)
    def test_each_effect_requires_fresh_gates_and_consumes_the_proof_even_on_failure(self):
        self.configured_services();stage=self.review['stages'][1];self.native.key=Mock()
        with self.assertRaises(c.Denied):self.native.apply(stage)
        self.native.key.create.assert_not_called()
        self.native.guard_current(stage);self.native.key.create.side_effect=RuntimeError('synthetic lost outcome')
        with self.assertRaises(RuntimeError):self.native.apply(stage)
        self.assertIsNone(self.native.last_gates)
        with self.assertRaises(c.Denied):self.native.apply(stage)
        self.assertEqual(self.native.key.create.call_count,1)
    def test_restore_policy_can_change_only_after_owned_attempt_or_applied_stage(self):
        stage=self.claim('gateway.RESTORE_RESTART');row=self.runner.journal.read()
        actual={'HostConfig':{'RestartPolicy':self.fixture.packet['frames']['gateway']['restoreRestartPolicy']}}
        self.assertFalse(self.native.restored(row,'gateway',actual))
        row['effects'][-1]['nativeRequestAttempted']=True
        self.assertTrue(self.native.restored(row,'gateway',actual))
        row['effects'][-1]['state']='APPLIED'
        self.assertTrue(self.native.restored(row,'gateway',{'HostConfig':{'RestartPolicy':{'Name':'no'}}}))
        # APPLIED fixes the expectation to restored; it never permits a fallback.
    def test_rebind_read_persists_exact_resource_without_replaying_any_effect(self):
        stage=self.claim('REBIND_GATEWAY_TRANSPORT');self.configured_services();self.native.guard_current(stage)
        pin=Mock();pin.created_id='9'*64;pin.process={'pid':99,'startedAt':'new-process'}
        pin.binding={'device':1,'inode':29};pin.check.return_value={'containerId':pin.created_id,'namespace':pin.binding}
        gateway=Mock();gateway.pin=pin;self.native.new_gateway=Mock(return_value=gateway)
        status,_=self.native.observe(stage);self.assertEqual(status,'APPLIED')
        first=self.runner.journal.read()['effects'][-1]['nativeResource']
        self.assertEqual(first,{'containerId':pin.created_id,'process':pin.process,'namespace':pin.binding})
        self.native.observe(stage)
        self.assertEqual(self.runner.journal.read()['effects'][-1]['nativeResource'],first)
        pin.binding={'device':1,'inode':30}
        with self.assertRaises(c.Denied):self.native.observe(stage)
        gateway.put.assert_not_called()
    def test_explicit_gateway_transient_remains_a_read_retry_without_effect_dispatch(self):
        stage=self.claim('gateway.READINESS');self.configured_services();self.native.guard_current(stage)
        gateway=Mock();gateway.routes.side_effect=n.GatewayTransient(17)
        self.native.new_gateway=Mock(return_value=gateway)
        self.assertEqual(self.native.observe(stage),('TRANSIENT',{'retryAfterSeconds':17}))
        gateway.put.assert_not_called()

if __name__=='__main__':unittest.main()
