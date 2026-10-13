"""Real role crypto and native persistence; no grant/runtime integration implied."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_cutover_authority_native as fixtures
import accounting_gap_session as sessions
binding=sessions.binding

class GapSessionTest(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.SignedCutover();self.f.setUp();self.addCleanup(self.f.doCleanups)
        gap=binding.encoded({'schema':'ouf.policy-token-accounting-source-observation.v1','auditConfiguration':{'eventsEnabled':False},
            'historicalGrantAttemptCount':None,'historicalAccountingReconciled':False})
        self.gap_hash=binding.sha(gap)
        self.f.write(self.f.root/('policy-token-owner-accounting-observation-'+self.gap_hash+'.private.json'),gap)
        for p in (patch.object(binding,'PARENT',self.f.root),patch.object(sessions,'GAP_HASH',self.gap_hash)):
            p.start();self.addCleanup(p.stop)
        if not Path('/proc/sys/kernel/random/boot_id').is_file():
            p=patch.object(sessions,'boot_identity',return_value='11111111-1111-1111-1111-111111111111');p.start();self.addCleanup(p.stop)
        self.scope=sessions.scope('f'*64,self.f.expected['sourceClosureHash']);self.sign()
    def sign(self,alter=None):
        authority=json.loads(self.f.authority);authority['policyTokenAccountingGapMigration']=dict(self.scope)
        if alter:alter(authority)
        self.f.authority=binding.encoded(authority);self.f.approval['executionAuthorityHash']=binding.sha(self.f.authority)
        self.f.write(self.f.mandate,binding.encoded(self.f.approval));self.f.approved=binding.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
    def session(self):return sessions.FirstGapSession(self.f.gate(),self.f.authority,'f'*64,self.f.expected['sourceClosureHash'],self.f.clock)
    def test_explicit_finite_session_preserves_unknown_and_consumes_before_any_caller_effect(self):
        s=self.session();row=s.open();self.assertEqual(row['attemptSlotsConsumed'],0)
        self.assertIsNone(row['historicalCumulativeGrantAttemptCount']);self.assertTrue(row['legacyHistory']['gapRemainsOpen'])
        consumed=s.consume_attempt_slot();self.assertEqual(consumed['attemptSlotsConsumed'],1)
        self.assertEqual(consumed['state'],'ATTEMPT_SLOT_CONSUMED_OUTCOME_UNPROVEN')
        self.assertEqual(json.loads((self.f.root/s.name).read_bytes()),consumed)
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_REPLAY'):self.session().consume_attempt_slot()
    def test_restart_or_new_approval_never_refunds_first_slot(self):
        s=self.session();s.open();s.consume_attempt_slot();self.f.approval['approvalRef']='SYNTHETIC_NEW_APPROVAL'
        self.sign();new=self.session();self.assertEqual(new.operation,s.operation)
        self.assertEqual(new.open()['attemptSlotsConsumed'],1)
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_REPLAY'):new.consume_attempt_slot()
    def test_no_implicit_initialization_and_expired_or_regressed_clock_blocks(self):
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_IMPLICIT_CREATION'):self.session().consume_attempt_slot()
        s=self.session();s.open();self.f.now-=2
        with self.assertRaises(Exception):self.session().consume_attempt_slot()
        self.f.now+=122
        with self.assertRaises(Exception):self.session().open()
    def test_new_contract_chat_approval_is_not_execution_authority_or_noop_gate(self):
        with self.assertRaisesRegex(binding.CandidateDenied,'DUAL_ROLE'):sessions.FirstGapSession(lambda raw:True,self.f.authority,'f'*64,self.f.expected['sourceClosureHash'])
        self.sign(lambda a:a.pop('policyTokenAccountingGapMigration'))
        with self.assertRaisesRegex(binding.CandidateDenied,'SIGNED_GAP'):self.session().open()
        self.scope['maximumGrantAttempts']=2;self.sign()
        with self.assertRaisesRegex(binding.CandidateDenied,'SIGNED_GAP'):self.session().open()
    def test_gap_drift_cannot_be_turned_into_zero(self):
        s=self.session();s.open();p=self.f.root/s.name;row=json.loads(p.read_bytes());row['historicalCumulativeGrantAttemptCount']=0
        self.f.write(p,binding.encoded(row))
        with self.assertRaisesRegex(binding.CandidateDenied,'SESSION_DRIFT'):self.session().consume_attempt_slot()
        gap=self.f.root/('policy-token-owner-accounting-observation-'+self.gap_hash+'.private.json')
        self.f.write(gap,binding.encoded({'historicalGrantAttemptCount':0}))
        with self.assertRaisesRegex(binding.CandidateDenied,'GAP_HASH'):self.session().open()
    def test_revoked_human_denies_consumption_and_exclusive_fence_blocks_parallel_operator(self):
        import fcntl
        s=self.session();s.open();fd=os.open(self.f.root/(s.name+'.lock'),os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.session().consume_attempt_slot()
        finally:os.close(fd)
        self.f.approval['state']='REVOKED';self.f.write(self.f.mandate,binding.encoded(self.f.approval))
        with self.assertRaises(Exception):self.session().consume_attempt_slot()
        self.assertEqual(json.loads((self.f.root/s.name).read_bytes())['attemptSlotsConsumed'],0)

    def test_crash_after_durable_reservation_cannot_replay_or_create_another_slot(self):
        s=self.session();s.open();pid=os.fork()
        if pid==0:
            try:self.session().consume_attempt_slot();os._exit(0)
            except Exception:os._exit(91)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        row=json.loads((self.f.root/s.name).read_bytes());self.assertEqual(row['attemptSlotsConsumed'],1)
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_REPLAY'):self.session().consume_attempt_slot()
    def test_boot_change_or_monotonic_regression_never_extends_session(self):
        s=self.session();row=s.open();s.monotonic=lambda:row['lastMonotonic']-1
        with self.assertRaisesRegex(binding.CandidateDenied,'MONOTONIC_DRIFT'):s.consume_attempt_slot()
        with patch.object(sessions,'boot_identity',return_value='22222222-2222-2222-2222-222222222222'):
            with self.assertRaisesRegex(binding.CandidateDenied,'BOOT_OR_MONOTONIC'):self.session().open()
        self.assertEqual(json.loads((self.f.root/s.name).read_bytes())['attemptSlotsConsumed'],0)

if __name__=='__main__':unittest.main()
