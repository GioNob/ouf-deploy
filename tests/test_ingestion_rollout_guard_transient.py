"""Persistent finite precondition pauses, real role/CAS and synthetic HTTP loss."""
import os
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_execution as core
from tools.ingestion_rollout_execution import contract as c

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual role signatures/CAS required')
class GuardTransient(unittest.TestCase):
    def setUp(self):
        core.SignedFiniteRunner.setUp(self)
        self.calls=0;self.fail_on=None;self.always=False;original=self.ports.guard_current
        def guard(stage):
            original(stage);self.calls+=1
            if self.always or self.calls==self.fail_on:
                row=self.runner.journal.read()
                self.runner.journal.compare_and_save(row,{**row,'nativeOwnerGetAttempts':row.get('nativeOwnerGetAttempts',0)+1,
                    'version':row['version']+1})
                raise c.ReadTransient(17)
        self.ports.guard_current=guard
    def advance(self,seconds):core.SignedFiniteRunner.advance(self,seconds)
    def test_preclaim_read_pause_preserves_budget_retry_after_and_does_not_reprobe_early(self):
        self.always=True
        with self.assertRaises(c.Paused):self.runner.step()
        row=self.runner.record();self.assertEqual(row['effects'],[]);self.assertEqual(row['readAttempts'],1)
        self.assertEqual(row['nativeOwnerGetAttempts'],1);self.assertEqual(row['readState'],'RETRY_WAIT')
        self.assertGreaterEqual(row['nextReadAt']-self.crypto.now,17)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.calls,1);self.assertEqual(row,self.runner.record())
        self.advance(18);self.always=False;self.runner.step()
        self.assertEqual(self.runner.record()['nextStage'],1);self.assertEqual(self.runner.record()['readAttempts'],2)
    def test_posteffect_precondition_transient_permits_read_reconcile_only_after_floor(self):
        self.runner.step();self.calls=0;self.fail_on=3
        with self.assertRaises(c.Paused):self.runner.step()
        row=self.runner.record();self.assertEqual(row['readState'],'RECONCILE_REQUIRED')
        self.assertEqual(len(self.ports.effects),1)
        with self.assertRaises(c.Paused):self.runner.step()
        with self.assertRaises(c.Paused):self.runner.reconcile()
        self.assertEqual(len(self.ports.effects),1)
        self.advance(18);self.fail_on=None;proof=self.runner.reconcile()
        self.assertFalse(proof['effectReplayed']);self.assertEqual(len(self.ports.effects),1)
    def test_claimed_but_undispatched_effect_is_never_automatically_applied(self):
        self.runner.step();self.calls=0;self.fail_on=2
        with self.assertRaises(c.Paused):self.runner.step()
        row=self.runner.record();self.assertEqual(row['readState'],'RECONCILE_REQUIRED')
        self.assertEqual(self.ports.effects,[]);self.advance(18)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.ports.effects,[])
    def test_expiry_while_paused_blocks_without_reprobe_or_budget_reset(self):
        self.always=True
        with self.assertRaises(c.Paused):self.runner.step()
        before=self.runner.record();self.advance(481)
        with self.assertRaises(Exception):self.runner.step()
        self.assertEqual(self.calls,1);self.assertEqual(self.runner.record(),before)
    def test_last_cumulative_attempt_exhausts_and_cannot_be_renewed_by_step(self):
        row=self.runner.record();self.runner.save(row,readAttempts=127);self.always=True
        with self.assertRaises(c.Paused):self.runner.step()
        row=self.runner.record();self.assertEqual(row['readAttempts'],128);self.assertEqual(row['readState'],'EXHAUSTED')
        self.advance(18)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.calls,1);self.assertEqual(row,self.runner.record())

if __name__=='__main__':unittest.main()
