import ast,base64,copy,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
SCRIPT=HERE/'read.py'
if not SCRIPT.exists():SCRIPT=ROOT/'scripts/read-ingestion401-auth-contract.py'
spec=importlib.util.spec_from_file_location('auth_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RECEIPT=ROOT/'evidence/installation-route-reconciliation-target-20261019.json'
if not RECEIPT.exists():RECEIPT=ROOT/'completed-target.json'
def routes():
 result={str(n):{'id':str(n)}for n in range(80)}
 for mode in('status','history'):
  result['mcp-ingestion-'+mode]={'uri':'/internal/capabilities/v1/execute/ouf.ingestion.'+mode,'methods':['POST'],'plugins':{
   'openid-connect':{'bearer_only':True,'ssl_verify':True},'serverless-post-function':{'phase':'access','functions':["if lower == 'authorization' then ngx.req.clear_header(name) end\n"]}}}
 return result
class Contract(unittest.TestCase):
 def test_environment_and_approved_code_are_safe_projection_not_cause_proof(self):
  owner={'Config':{'Env':['OUF_ING_IAM_ENABLED=true','OUF_ING_IAM_ISSUER=https://private.invalid','OUF_ING_IAM_AUDIENCE=private-aud','PASSWORD=NEVER_PRINT']}}
  result=m.auth_contract(routes(),owner);self.assertTrue(result['ownerIamEnabledEnvironment']);self.assertTrue(all(r['candidateBearerBoundaryConflict']for r in result['routeContracts']))
  self.assertFalse(result['specific401CauseProven']);text=m.encoded(result).decode()
  for value in('private.invalid','private-aud','NEVER_PRINT'):self.assertNotIn(value,text)
 def test_disabled_iam_and_explicit_bearer_assignment_are_distinct(self):
  rs=routes();owner={'Config':{'Env':[]}};self.assertFalse(any(r['candidateBearerBoundaryConflict']for r in m.auth_contract(rs,owner)['routeContracts']))
  owner['Config']['Env']=['OUF_ING_IAM_ENABLED=true']
  for mode in('status','history'):rs['mcp-ingestion-'+mode]['plugins']['serverless-post-function']['functions'][0]+="ngx.req.set_header('Authorization', token)\n"
  self.assertFalse(any(r['candidateBearerBoundaryConflict']for r in m.auth_contract(rs,owner)['routeContracts']))
 def test_ambiguous_environment_or_routes_denied(self):
  for env in(['OUF_ING_IAM_ENABLED=unknown'],['OUF_ING_IAM_ENABLED=true']*2):
   with self.assertRaises(Exception):m.auth_contract(routes(),{'Config':{'Env':env}})
  rs=routes();rs['duplicate']=copy.deepcopy(rs['mcp-ingestion-status'])
  with self.assertRaises(Exception):m.auth_contract(rs,{'Config':{'Env':[]}})
 def records(self):
  rs=routes();plan={'kind':'INSTALLATION_ROUTE_RECONCILIATION','gateway':{'afterRoutes':rs}};scope={'planHash':m.digest(plan),'stages':['VERIFY_INPUTS','RECONCILE_PUBLISHED_PROJECTION','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','RECONCILE_PREDECESSOR_COMPLETION','VERIFY_FINAL']}
  sources={str(i):base64.b64encode(b'raise RuntimeError("NEVER_EXECUTE")').decode()for i in range(226)}
  closure={'declaration':{'moduleCount':226,'entryModule':'tools.installation_route_reconcile.entry','sourceHashes':{n:m.sha(base64.b64decode(v))for n,v in sources.items()}}}
  package={'sourceCommit':m.NEW_SOURCE,'closure':closure,'declarationHash':m.digest(closure['declaration']),'fileHashes':{'sources.json':m.digest(sources)}}
  review={'scopes':{'installationRouteReconciliation':scope},'sourceClosureHash':m.digest(closure)}
  journal={'schema':'ouf.installation-binding-native-journal.v1','scopeHash':m.digest(scope),'nextStage':6,'incidentState':'RECOVERED','budgetReset':False,'effects':[{'stage':s,'state':'APPLIED','intentHash':m.digest({'planHash':m.digest(plan),'stage':s})}for s in scope['stages']]}
  return {'update-result.json':json.loads(RECEIPT.read_bytes()),'package.json':package,'sources.json':sources,'runtime.claim.json':{'packageHash':m.digest(package),'automaticReplayAllowed':False},'execution-plan.json':plan,'review.json':review,'decision.json':{'reviewHash':m.digest(review)},'recovery.json':journal},m.digest(rs)
 def test_exact_completed_history_is_only_read_without_source_execution(self):
  data,h=self.records();before=copy.deepcopy(data)
  def parse(path,expected=None):
   v=data[Path(path).name]
   if expected is not None:self.assertEqual(m.digest(v),expected)
   return v
  with patch.object(m,'NEW_ROUTES',h):rs,_,_=m.completed_routes(parse)
  self.assertEqual(len(rs),82);self.assertEqual(data,before)
 def test_changed_receipt_claim_or_claimed_stage_denies(self):
  for kind in('receipt','claim','stage'):
   data,h=self.records()
   if kind=='receipt':data['update-result.json']['oauthAttemptsAfter']=260
   if kind=='claim':data['runtime.claim.json']['packageHash']='0'*64
   if kind=='stage':data['recovery.json']['effects'][2]['state']='CLAIMED'
   with self.subTest(kind=kind),patch.object(m,'NEW_ROUTES',h),self.assertRaises(Exception):m.completed_routes(lambda path,expected=None:data[Path(path).name])
 def test_engine_whitelist_rejects_logs_exec_and_seventh_read(self):
  reader=m.Reader({'socketPath':'/not-used','socketBinding':[]},['a'*64,'b'*64,'c'*64])
  for path in('/v1.44/containers/json','/v1.44/containers/'+'a'*64+'/logs','/v1.44/containers/'+'a'*64+'/exec'):
   with self.assertRaises(Exception):reader.get(path)
  reader.calls=6
  with self.assertRaises(Exception):reader.get('/v1.44/containers/'+'a'*64+'/json')
 def test_no_source_execution_oauth_login_or_mutation_primitives(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  for suffix in('.login','.refresh_if_due','.write_text','.write_bytes','.Popen','.execv','.setns','.migrate'):
   self.assertFalse(any(v.endswith(suffix)for v in calls))
  self.assertNotIn('exec',calls);self.assertNotIn('eval',calls)
if __name__=='__main__':unittest.main()
