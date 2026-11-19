import ast,base64,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/read-mcp-reauthentication-stop.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name(SCRIPT.name)
spec=importlib.util.spec_from_file_location('qualified_reauth_stop_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Reader(unittest.TestCase):
 def test_secret_bearing_human_row_projects_only_enums_numbers_and_presence(self):
  row={'schema':'ouf.chatbot-human-session.private.v1','state':'REQUESTING','attempts':222,'operation':'DEVICE_POLL',
   'reason':'SECRET-ERROR','resumeState':'SECRET-STATE','binding':{'expiresAt':100},'budgetReset':False,
   'accessToken':'SECRET-ACCESS','refreshToken':'SECRET-REFRESH','publishedAccessToken':'SECRET-PUBLISHED'}
  result=m.human_projection(row,set());self.assertNotIn('SECRET',json.dumps(result))
  self.assertEqual(result['attempts'],222);self.assertEqual(result['operation'],'DEVICE_POLL')
 def test_only_literal_sealed_guard_codes_are_public(self):
  codes=m.safe_codes({'fixture':b'raise ValueError("EXACT_FIXTURE_REQUIRED")\n'})
  def denied():raise ValueError('EXACT_FIXTURE_REQUIRED')
  def secret():raise ValueError('SECRET-VALUE')
  self.assertEqual(m.check('fixture',denied,codes)['reasonCode'],'EXACT_FIXTURE_REQUIRED')
  self.assertEqual(m.check('fixture',secret,codes)['reasonCode'],'PRIVATE_DETAILS_REDACTED')
 def test_native_claimed_stage_is_observed_without_replay_or_raw_evidence(self):
  row={'schema':'ouf.mcp-ingestion-read-transport-update-journal.v1','effects':[{'stage':'VERIFY_INPUTS','state':'CLAIMED','evidence':'SECRET'}],
   'nextStage':0,'readinessAttempts':0,'cumulativeReadinessAttempts':0,'budgetReset':False}
  result=m.native_projection(row);self.assertEqual(result['effects'],[{'stage':'VERIFY_INPUTS','state':'CLAIMED'}])
  self.assertNotIn('SECRET',json.dumps(result));row['effects'][0]['stage']='OTHER_EFFECT'
  with self.assertRaises(Exception):m.native_projection(row)
 def test_jwt_context_exposes_predicates_and_known_missing_scopes_only(self):
  binding={'issuer':'issuer','subject':'human','tenant':'tenant','scopes':['SECRET-SCOPE']}
  claims={'iss':'other-SECRET','sub':'other-SECRET','tenant_id':'tenant','scope':'openid','exp':200,'aud':'SECRET-AUDIENCE','private':'SECRET'}
  token='h.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.s'
  result=m.jwt_projection(token,binding,100);self.assertNotIn('SECRET',json.dumps(result))
  self.assertFalse(result['subjectMatched']);self.assertFalse(result['bindingScopeProfileMatched'])
  self.assertIn('mcp.connect',result['missingRequiredScopes'])
 def test_absent_or_malformed_token_does_not_trigger_any_refresh(self):
  self.assertEqual(m.jwt_projection(None,{},0),{'durableJwtContextAvailable':False})
  self.assertEqual(m.jwt_projection('not-a-jwt',{},0),{'durableJwtContextAvailable':False})
 def test_unsafe_budget_or_native_counters_fail_closed(self):
  row={'schema':'ouf.chatbot-human-session.private.v1','state':'READY','budgetReset':False,'attempts':257}
  with self.assertRaises(Exception):m.human_projection(row,set())
  row={'schema':'ouf.mcp-ingestion-read-transport-update-journal.v1','effects':[],'nextStage':'SECRET',
   'readinessAttempts':0,'cumulativeReadinessAttempts':0,'budgetReset':False}
  with self.assertRaises(Exception):m.native_projection(row)
 def test_reader_has_no_live_calls_or_writes_and_does_not_replay_any_main(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(v.endswith(('.refresh_if_due','.login','.authenticate','.issue_action','.compile_current','.current','.request','.start_refresh','.write','.mkdir','.execv','.main'))for v in calls))
  opens=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='os.open']
  self.assertEqual(len(opens),1);self.assertIn('os.O_RDONLY',ast.unparse(opens[0].args[1]))
if __name__=='__main__':unittest.main()
