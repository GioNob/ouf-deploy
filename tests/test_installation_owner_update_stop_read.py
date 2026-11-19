import ast,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/read-installation-owner-update-stop.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name(SCRIPT.name)
spec=importlib.util.spec_from_file_location('qualified_mcp_stop_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Projection(unittest.TestCase):
 def fixture(self,state='READY'):
  binding={'expiresAt':1792425259,'retryProfile':{'maximumAttempts':256}}
  row={'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'attempts':244,'budgetReset':False,
   'state':state,'monotonicDeadline':900,'accessToken':'SECRET_BEARER','refreshToken':'SECRET_REFRESH',
   'publishedAccessToken':'SECRET_PUBLISHED','accessExpiresAt':100,'operation':'REFRESH','refreshAt':90}
  return row,binding
 def test_permanent_reason_and_current_cumulative_count_without_credentials(self):
  row,b=self.fixture('BLOCKED');row['reason']='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'
  result=m.project(row,b,{row['reason']},110,10)
  self.assertEqual(result['reasonCode'],row['reason']);self.assertEqual(result['attempts'],244)
  self.assertFalse(result['recordedAccessStillCurrent']);self.assertNotIn('SECRET',json.dumps(result))
 def test_transient_retry_is_observed_without_resuming(self):
  row,b=self.fixture('RETRY_WAIT');row.update(resumeState='READY',nextAttemptAt=140,reason='HUMAN_OAUTH_TEMPORARILY_UNAVAILABLE')
  result=m.project(row,b,{row['reason']},110,10);self.assertEqual(result['nextAttemptAt'],140)
  self.assertEqual(result['resumeState'],'READY');self.assertEqual(row['state'],'RETRY_WAIT')
 def test_unknown_details_do_not_escape_public_projection(self):
  row,b=self.fixture();row.update(reason='SECRET_REASON',operation='SECRET_OPERATION',nextAttemptAt='SECRET_DATE',resumeState='SECRET_RESUME')
  result=m.project(row,b,set(),110,10);self.assertNotIn('SECRET',json.dumps(result))
  self.assertEqual(result['reasonCode'],'NO_SAFE_RECORDED_REASON');self.assertIsNone(result['nextAttemptAt'])
 def test_budget_and_binding_drift_are_denied(self):
  for key,value in [('attempts',257),('budgetReset',True),('binding',{})]:
   row,b=self.fixture();row[key]=value
   with self.subTest(key=key),self.assertRaises(Exception):m.project(row,b,set(),110,10)
 def test_reader_has_no_dispatch_write_imported_owner_or_secret_token_file_read(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.refresh_if_due','.login','.issue_action','.request','.execv','.write','.mkdir','.main'))for c in calls))
  self.assertFalse(any(isinstance(n,ast.ImportFrom)and n.module.startswith('tools.')for n in ast.walk(tree)))
  opens=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='os.open']
  self.assertEqual(len(opens),1);self.assertIn('os.O_RDONLY',ast.unparse(opens[0].args[1]))
if __name__=='__main__':unittest.main()
