import copy, importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('plan',ROOT/'tools/semantic_application_cutover/token_owner_custody_plan.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ReviewPlan(unittest.TestCase):
    def setUp(self):
        self.custody=json.loads((ROOT/'evidence/semantic-token-shared-custody-ancestor-target-20261012.json').read_text())
        self.correspondence=json.loads((ROOT/'evidence/semantic-token-private-output-correspondence-v2-target-20261012.json').read_text())

    def test_reported_evidence_never_establishes_authority_or_effects(self):
        before=copy.deepcopy((self.custody,self.correspondence))
        result=module.compile_plan(self.custody,self.correspondence)
        self.assertEqual(result['status'],'REVIEW_ONLY_NOT_APPLY_READY')
        for key in ('productionApplyReady','runtimeAuthorityIssued','writerAuthorityProven',
                    'rootCustodyEstablishedByPlan','budgetReset','r12Touched','sourceCopiedOrApproved'):
            self.assertFalse(result[key])
        self.assertEqual(result['recoveryProposal']['previousAccounting'],'UNPROVEN')
        self.assertEqual(before,(self.custody,self.correspondence))

    def test_legacy_incomplete_routing_and_ambiguous_scope_blocked(self):
        for change in ({'schema':'ouf.semantic-token-private-output-correspondence-receipt.v1'},
                       {'environmentFileCountVerified':2}, {'configuredOutputMatchesHistoricalMount0':False}):
            bad=self.correspondence|change
            with self.assertRaises(ValueError):module.compile_plan(self.custody,bad)
        for change in ({'sharedUnsafeAncestorCount':True}, {'sharedUnsafeAncestorWithProducer':False}):
            with self.assertRaises(ValueError):module.compile_plan(self.custody|change,self.correspondence)

    def test_contradictory_credentials_and_effects_are_not_reinterpreted(self):
        bad=copy.deepcopy(self.custody)
        bad['referenceMetadata']['ancestors'][2]['uid']=0
        with self.assertRaises(ValueError):module.compile_plan(bad,self.correspondence)
        for change in ({'providerCalls':1},{'runtimeAuthorityIssued':True},{'baselineRefreshed':True}):
            with self.assertRaises(ValueError):module.compile_plan(self.custody|change,self.correspondence)

    def test_unknown_private_fields_never_echo_or_influence_output_hash(self):
        plain=module.compile_plan(self.custody,self.correspondence)
        private=module.compile_plan(self.custody|{'unknownSecret':'DO_NOT_PRINT'},self.correspondence)
        self.assertEqual(plain,private)
        self.assertNotIn('DO_NOT_PRINT',json.dumps(private))

if __name__=='__main__':unittest.main()
