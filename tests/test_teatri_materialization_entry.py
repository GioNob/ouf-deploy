import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.teatri_materialization_update import entry
class CurrentPredecessor(unittest.TestCase):
 def fixture(self):
  path=Path('/fixture/current');case={'rolloutContext':str(path),'rolloutSourceCommit':'d'*40}
  plan={'current':'fixture'};stages=['STAGE'+str(n)for n in range(21)];scope={'planHash':entry.digest(plan),'stages':stages}
  closure={'declaration':{'sourceCommit':'d'*40}};review={'kind':'RESOLUTION_COMPARISON_UPDATE','authorityDirectory':str(path),'sourceClosure':closure,'sourceClosureHash':entry.digest(closure),'scopes':{'resolutionComparisonUpdate':scope}}
  issued={'sourceClosureHash':entry.digest(closure),'resolutionComparisonUpdate':scope};case['rolloutReviewSha256']=entry.digest(review)
  record={'version':57,'incidentState':'RECOVERED','authorityHash':entry.digest(issued),'scopeHash':entry.digest(scope),'nextStage':21,'effects':[{'stage':s,'state':'APPLIED','intentHash':entry.digest({'planHash':scope['planHash'],'stage':s})}for s in stages]}
  rows={'review.json':review,'execution-plan.json':plan,'recovery.json':record,'authority.json':issued}
  def read(p,limit,expected=None):
   value=copy.deepcopy(rows[Path(p).name])
   if expected is not None:entry.require(entry.digest(value)==expected,'REVIEW_CHANGED')
   return value
  return case,rows,read
 def test_current57_21step_hash_bound_predecessor_and_tamper_rejection(self):
  case,rows,read=self.fixture();self.assertEqual(entry.predecessor(case,read)[0],rows['review.json'])
  for key in('version','source','intent','authority','plan'):
   case,rows,read=self.fixture()
   if key=='version':rows['recovery.json']['version']=51
   if key=='source':case['rolloutSourceCommit']='f'*40
   if key=='intent':rows['recovery.json']['effects'][1]['intentHash']='f'*64
   if key=='authority':rows['authority.json']['extra']=True
   if key=='plan':rows['execution-plan.json']['extra']=True
   with self.subTest(key=key),self.assertRaises(Exception):entry.predecessor(case,read)
 def test_preparation_entry_has_no_reachable_login_issuance_or_update_execution(self):
  import ast
  tree=ast.parse((ROOT/'tools/teatri_materialization_update/entry.py').read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');calls=[ast.unparse(n.func)for n in ast.walk(main)if isinstance(n,ast.Call)]
  for name in('HumanSession','authority.issue_action','authority.terminal_consent','ReadinessUpdate','human.refresh_if_due','human.login','serve'):
   self.assertNotIn(name,calls)
  self.assertIn('preflight.collect',calls);self.assertIn('preparation.candidate',calls)
if __name__=='__main__':unittest.main()
