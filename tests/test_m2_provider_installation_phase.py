"""Actual typed owners/CAS/crypto/files; native Engine/nft/admission modeled."""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_provider_runtime_installation as runtime
from tools.m2_discovery_installation_profile import provider_installation_phase as m

class Sequence(unittest.TestCase):
    def fixture(self,**options):
        case=runtime.Runtime();owner,w,auth,state,calls,*_=case.fixture(sequenced=True,**options)
        self.addCleanup(case.doCleanups)
        return m.ProviderInstallationPhase(owner),w,auth,state,calls
    def test_composed_sequence_closes_gate_and_reconciles_lost_start_without_replay(self):
        owner,w,auth,state,calls=self.fixture(lost=True)
        owner.apply();outcome,evidence=owner.observe()
        self.assertEqual(outcome,'APPLIED');self.assertTrue(evidence['registryGateClosedBeforeReturn'])
        self.assertEqual(w.observe_closed()['state'],'CLOSED')
        row=owner.read();self.assertEqual(row['state'],'DONE')
        self.assertEqual([e['stage'] for e in row['effects']],list(m.STAGES))
        self.assertEqual([e['dispatches'] for e in row['effects']],[1]*5)
        self.assertEqual(sum(method=='POST' and path.endswith('/start') for method,path,_ in calls),1)
        count=len(calls)
        with patch.object(owner,'dispatch',side_effect=AssertionError('READ_ONLY_OBSERVATION')):
            self.assertEqual(owner.observe()[0],'APPLIED')
            with self.assertRaises(FileExistsError):owner.apply()
        self.assertTrue(all(method=='GET' for method,_,_ in calls[count:]))
    def test_unknown_start_exhausts_only_observations_and_closes_without_replay(self):
        owner,w,auth,state,calls=self.fixture();native=owner.creation.engine.request
        def unknown(method,path,body=None):
            if method=='POST' and path.endswith('/start'):calls.append((method,path,None));raise TimeoutError('CI_UNKNOWN_START')
            return native(method,path,body)
        owner.creation.engine.request=unknown
        with self.assertRaisesRegex(ValueError,'OBSERVATION_BUDGET_EXHAUSTED'):owner.apply()
        row=owner.read();self.assertEqual(row['state'],'IN_FLIGHT');self.assertEqual(row['stageIndex'],4)
        self.assertEqual(row['effects'][-1]['observations'],3);self.assertEqual(w.observe_closed()['state'],'CLOSED')
        self.assertEqual(sum(method=='POST' and path.endswith('/start') for method,path,_ in calls),1)
        with self.assertRaisesRegex(ValueError,'OBSERVATION_BUDGET_EXHAUSTED'):owner.observe()
        self.assertEqual(owner.read(),row)
    def test_permanent_failure_after_create_blocks_remaining_stages_and_closes_gate(self):
        owner,w,auth,state,calls=self.fixture()
        with patch.object(owner.issuer.signers['live'],'sign',side_effect=RuntimeError('CI_PERMANENT_KEY_DENIAL')):
            with self.assertRaisesRegex(RuntimeError,'PERMANENT_KEY_DENIAL'):owner.apply()
        self.assertEqual(w.observe_closed()['state'],'CLOSED')
        row=owner.read();self.assertEqual(row['stageIndex'],1);self.assertEqual(row['effects'][-1]['observations'],0)
        self.assertFalse((owner.runtime.root/'publication-claim.json').exists())
        self.assertFalse(any(path.endswith('/start') for _,path,_ in calls))
        self.assertEqual(owner.observe()[0],'UNKNOWN')
    def test_dispatch_journal_regression_is_detected_before_any_provider_create(self):
        owner,w,auth,state,calls=self.fixture();save=owner.journal.compare_and_save
        def regress(previous,value):
            # Simulates a valid old retained row reappearing after a committed
            # dispatch; exact readback must fail before the Engine sees POST.
            save(previous,value)
            if value['state']=='IN_FLIGHT':save(value,previous)
        with patch.object(owner.journal,'compare_and_save',side_effect=regress):
            with self.assertRaisesRegex(ValueError,'COMMIT_READBACK_DRIFT'):owner.apply()
        self.assertFalse(any(method=='POST' for method,_,_ in calls))
        self.assertEqual(w.observe_closed()['state'],'CLOSED')
    def test_unreviewed_sequence_or_stage_budget_cannot_be_silently_added(self):
        case=runtime.Runtime();owner,w,auth,*_=case.fixture();self.addCleanup(case.doCleanups)
        with self.assertRaisesRegex(ValueError,'PARENT_REVIEWED_PROVIDER_SEQUENCE'):m.ProviderInstallationPhase(owner)
        sequence,w,auth,*_=self.fixture();sequence.scope['observationPolicy']['maximumObservationsPerStage']=4
        with self.assertRaisesRegex(ValueError,'SEQUENCE_SCOPE_OR_OWNER_DRIFT'):sequence.apply()

if __name__=='__main__':unittest.main()
