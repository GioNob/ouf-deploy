import ast,copy,importlib.util,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('repair_read',ROOT/'scripts/read-chatbot-semantic-upstream-repair-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Readback(unittest.TestCase):
    def fixture(self):
        before={'selected':{'id':'selected','upstream':{'nodes':{'old:8080':1}}},'unrelated':{'id':'unrelated'}}
        after=copy.deepcopy(before);after['selected']['upstream']['nodes']={'127.0.0.1:8080':1}
        change={'routeId':'selected','before':before['selected'],'after':after['selected']}
        repair={'changes':[change],'proposedRoutes':after,'afterMapHash':r.digest(after)}
        journal={'schema':'ouf.semantic-upstream-route-repair-journal.v1','reviewHash':r.BASE_REVIEW_HASH,'executionAuthorityHash':r.REPAIR_AUTHORITY,
            'budgetReset':False,'automaticReplayAllowed':False,'nextStep':0,
            'effects':[{'step':0,'routeIdHash':r.digest('selected'),'intentHash':r.digest(change),'state':'CLAIMED'}]}
        return before,after,repair,journal
    def test_applied_but_unacknowledged_is_only_observed_not_reconciled(self):
        before,after,repair,journal=self.fixture();saved=copy.deepcopy(journal)
        result=r.repair_progress(repair,before,after,journal)
        self.assertTrue(result['matchesAfterClaim']);self.assertFalse(result['matchesBeforeClaim']);self.assertFalse(result['reconciliationPerformed']);self.assertEqual(journal,saved)
    def test_unapplied_claim_is_not_retried(self):
        before,after,repair,journal=self.fixture();result=r.repair_progress(repair,before,before,journal)
        self.assertTrue(result['matchesBeforeClaim']);self.assertFalse(result['matchesAfterClaim'])
    def test_unrelated_drift_is_distinguished(self):
        before,after,repair,journal=self.fixture();after['unrelated']['changed']=True
        result=r.repair_progress(repair,before,after,journal);self.assertFalse(result['matchesBeforeClaim']);self.assertFalse(result['matchesAfterClaim'])
    def test_foreign_authority_claim_rejected(self):
        before,after,repair,journal=self.fixture();journal['executionAuthorityHash']='wrong'
        with self.assertRaisesRegex(r.ReadDenied,'EXACT_REPAIR_JOURNAL_REQUIRED'):r.repair_progress(repair,before,after,journal)
    def test_namespace_http_get_only_and_main_has_no_mutation_or_live_window_requirement(self):
        source=Path(r.__file__).read_text()
        for text in (source,r.GET_CHILD):
            for node in ast.walk(ast.parse(text)):
                if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='request':self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        main=next(x for x in ast.parse(source).body if isinstance(x,ast.FunctionDef)and x.name=='main')
        names={v.func.id for v in ast.walk(main)if isinstance(v,ast.Call)and isinstance(v.func,ast.Name)}
        self.assertFalse(names&{'live_process','stage_binding_review','atomic_record','sign_and_verify','gateway_put','apply_route_changes'})
if __name__=='__main__':unittest.main()
