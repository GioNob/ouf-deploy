"""Real signatures/CAS with ports that persist counters and resource metadata.

Regression for composition: native bookkeeping must not stale the Runner's CAS,
advance progress, rewrite a completed effect or reset any finite budget.
"""
import copy
import os
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_execution as core
from tools.ingestion_rollout_execution import contract as c

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual role signatures/private CAS required')
class NativeJournalComposition(unittest.TestCase):
    def setUp(self):
        core.SignedFiniteRunner.setUp(self)
        original_guard=self.ports.guard_current;original_observe=self.ports.observe;original_apply=self.ports.apply
        def tick(name):
            row=self.runner.journal.read()
            self.runner.journal.compare_and_save(row,{**row,name:row.get(name,0)+1,'version':row['version']+1})
        self.tick=tick
        def guard(stage):original_guard(stage);tick('nativeGuardCalls')
        def observe(stage):tick('nativeObservationCalls');return original_observe(stage)
        def apply(stage):
            row=self.runner.journal.read();effects=copy.deepcopy(row['effects'])
            effects[-1]['nativeResource']={'fixtureStage':stage['name']}
            self.runner.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
            tick('nativeEffectCalls');return original_apply(stage)
        self.ports.guard_current=guard;self.ports.observe=observe;self.ports.apply=apply
    def test_complete_sequence_preserves_all_native_counters_and_current_claim_resource(self):
        for stage in self.review['stages']:self.runner.step()
        row=self.runner.record();self.assertEqual(row['nextStage'],len(self.review['stages']))
        self.assertEqual(row['nativeObservationCalls'],len(self.review['stages']))
        self.assertEqual(row['nativeEffectCalls'],len([s for s in self.review['stages']if s['kind']=='EFFECT']))
        self.assertTrue(all('nativeResource'in e for e in row['effects']if next(s for s in self.review['stages']if s['name']==e['stage'])['kind']=='EFFECT'))
        self.assertTrue(self.runner.step()['complete'])
    def test_lost_effect_then_reconcile_retains_resource_and_never_probes_or_dispatches_replay(self):
        self.runner.step();self.ports.crash=True
        with self.assertRaises(RuntimeError):self.runner.step()
        before=self.runner.record();count=len(self.ports.effects)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(before,self.runner.record())
        self.ports.crash=False;result=self.runner.reconcile()
        self.assertFalse(result['effectReplayed']);self.assertEqual(len(self.ports.effects),count)
        self.assertIn('nativeResource',self.runner.record()['effects'][-1])
    def test_retry_wait_never_reprobes_native_dependencies_before_the_same_deadline(self):
        self.ports.transient=True
        with self.assertRaises(c.Paused):self.runner.step()
        before=self.runner.record()
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.runner.record(),before)
        core.SignedFiniteRunner.advance(self,8);self.ports.transient=False;self.runner.step()
        self.assertEqual(self.runner.record()['readAttempts'],2)
    def test_no_observation_budget_blocks_before_dependency_probe_or_effect(self):
        self.runner.step();row=self.runner.record();self.runner.save(row,readAttempts=128)
        before=self.runner.record();effects=list(self.ports.effects)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.runner.record(),before);self.assertEqual(self.ports.effects,effects)
    def test_native_guard_cannot_advance_the_stage_even_with_valid_row_shape(self):
        def guard(stage):
            row=self.runner.record();s=self.review['stages'][0]
            effects=[{'stage':s['name'],'intentHash':s['intentHash'],'state':'APPLIED','evidence':{'fixture':True}}]
            self.runner.journal.compare_and_save(row,{**row,'effects':effects,'nextStage':1,'version':row['version']+1})
        self.ports.guard_current=guard
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.ports.effects,[])
    def test_native_guard_cannot_extend_deadline_or_spend_runner_observation_budget(self):
        for field in('expiresAt','readAttempts'):
            row=self.runner.record()
            def guard(stage,field=field):
                current=self.runner.record()
                self.runner.journal.compare_and_save(current,{**current,field:current[field]+1,'version':current['version']+1})
            self.ports.guard_current=guard
            with self.subTest(field=field),self.assertRaises(c.Denied):self.runner.step()
            self.assertEqual(self.ports.effects,[])
    def test_existing_native_counter_cannot_decrease(self):
        row=self.runner.record();self.runner.journal.compare_and_save(row,{**row,'nativeGuardCalls':3,'version':row['version']+1})
        def guard(stage):
            row=self.runner.record()
            self.runner.journal.compare_and_save(row,{**row,'nativeGuardCalls':2,'version':row['version']+1})
        self.ports.guard_current=guard
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.ports.effects,[])
    def test_native_port_cannot_rewrite_previously_applied_evidence(self):
        self.runner.step()
        def guard(stage):
            row=self.runner.record();effects=copy.deepcopy(row['effects']);effects[0]['evidence']={'foreign':True}
            self.runner.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
        self.ports.guard_current=guard
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.ports.effects,[])

if __name__=='__main__':unittest.main()
