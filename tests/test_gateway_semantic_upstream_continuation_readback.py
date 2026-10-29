import ast,copy,importlib.util,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('continued_upstream',ROOT/'scripts/continue-chatbot-semantic-upstream-repair-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
spec=importlib.util.spec_from_file_location('prior_apply_tests_for_continuation',ROOT/'tests/test_gateway_semantic_upstream_application_readback.py')
prior_tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior_tests)
class Continuation(prior_tests.Application):
    def setUp(self):self.previous=prior_tests.r;prior_tests.r=r
    def tearDown(self):prior_tests.r=self.previous
    def continuation_fixture(self):
        before={str(i):{'id':str(i),'upstream':{'nodes':{'old:8080':1}}}for i in range(15)}
        after=copy.deepcopy(before);changes=[]
        for rid in before:
            after[rid]['upstream']['nodes']={'127.0.0.1:8080':1}
            changes.append({'routeId':rid,'before':before[rid],'after':after[rid]})
        repair={'changes':changes,'proposedRoutes':after,'afterMapHash':r.digest(after)}
        journal={'schema':'ouf.semantic-upstream-route-repair-journal.v1','reviewHash':r.BASE_REVIEW_HASH,'executionAuthorityHash':r.REPAIR_AUTHORITY,
            'budgetReset':False,'automaticReplayAllowed':False,'nextStep':0,'effects':[{'step':0,'routeIdHash':r.digest('0'),'intentHash':r.digest(changes[0]),'state':'CLAIMED'}]}
        observed=copy.deepcopy(before);observed['0']=copy.deepcopy(after['0'])
        return repair,before,journal,observed
    def test_first_claim_is_adopted_without_replay_or_old_journal_mutation(self):
        repair,before,journal,observed=self.continuation_fixture();saved=copy.deepcopy(journal)
        remaining,prefix=r.continuation_prefix(repair,before,journal,observed)
        self.assertEqual(prefix,observed);self.assertEqual(len(remaining['changes']),14)
        self.assertNotIn('0',[v['routeId']for v in remaining['changes']]);self.assertEqual(journal,saved)
        self.assertEqual(remaining['proposedRoutes'],repair['proposedRoutes'])
    def test_before_claim_state_cannot_be_replayed_as_continuation(self):
        repair,before,journal,observed=self.continuation_fixture()
        with self.assertRaisesRegex(r.ReadDenied,'FIRST_WRITE_APPLICATION_NOT_PROVEN'):r.continuation_prefix(repair,before,journal,before)
    def test_new_repair_session_does_not_renew_original_application_window(self):
        source=Path(r.__file__).read_text();main=next(v for v in ast.parse(source).body if isinstance(v,ast.FunctionDef)and v.name=='apply_main')
        names={v.func.id for v in ast.walk(main)if isinstance(v,ast.Call)and isinstance(v.func,ast.Name)}
        self.assertNotIn('live_process',names);self.assertIn("'renewOriginalApplicationWindow':False",source)
        self.assertIn("'predecessorWriteAttempts':1",source);self.assertIn("'maximumCumulativeWriteAttempts':15",source)
        self.assertIn("'repair-continuation-v2.json'",source)
if __name__=='__main__':unittest.main()
