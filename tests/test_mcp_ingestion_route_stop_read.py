import ast,base64,copy,hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/read-mcp-ingestion-route-stop.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).parent/SCRIPT.name
spec=importlib.util.spec_from_file_location('route_stop_reader',SCRIPT);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
ENTRY=ROOT/'tools/mcp_read_transport_compatibility/entry.py'
if not ENTRY.exists():ENTRY=Path(__file__).parents[1]/'compatibility/entry.py'
def routes():
 rows={str(i):{'id':str(i),'private':'NEVER_PRINT_THIS'}for i in range(78)}
 for cap in r.CAPABILITIES:
  rid='mcp-ingestion-'+cap.rsplit('.',1)[1]
  rows[rid]={'id':rid,'uri':'/internal/capabilities/v1/execute/'+cap,'methods':['POST']}
 return rows
class Shapes(unittest.TestCase):
 def test_reproduces_uris_and_extra_method_failure_without_claiming_gateway_missing(self):
  values=routes();row=values['mcp-ingestion-status'];row['uris']=[row.pop('uri')];row['methods']=['POST','OPTIONS']
  found=r.route_shapes(values)[0];self.assertFalse(found['currentGuardPass'])
  projection=found['selectedRoutes'][0];self.assertTrue(projection['urisContainsExactExecutePath']);self.assertEqual(projection['knownMethods'],['POST','OPTIONS'])
 def test_exact_routes_pass_and_private_plugin_values_are_not_serialized(self):
  values=routes();values['mcp-ingestion-status']['plugins']={'secret':'NEVER_PRINT_THIS'}
  got=r.route_shapes(values);self.assertTrue(all(v['currentGuardPass']for v in got));self.assertNotIn('NEVER_PRINT_THIS',json.dumps(got))
 def test_owner_path_and_method_singular_are_reported_as_distinct_not_accepted(self):
  values=routes();values['mcp-ingestion-status'].update(uri='/api/internal/v1/ingestion/operations/status',methods=None,method='POST')
  row=r.route_shapes(values)[0]['selectedRoutes'][0];self.assertEqual(row['uriClass'],'OWNER_INTERNAL');self.assertTrue(row['methodIsPost']);self.assertFalse(row['currentGuardPass'])
 def test_absent_route_and_bad_cardinality_remain_fail_closed(self):
  values=routes();values['mcp-ingestion-status']={'id':'mcp-ingestion-status'}
  self.assertFalse(r.route_shapes(values)[0]['currentGuardPass'])
  values.pop('0')
  with self.assertRaises(ValueError):r.route_shapes(values)
 def test_unknown_methods_and_arbitrary_paths_never_leak(self):
  values=routes();values['mcp-ingestion-status'].update(uri='https://private/NEVER_PRINT_THIS',methods=['SECRET_METHOD'])
  result=r.route_shapes(values);self.assertNotIn('NEVER_PRINT_THIS',json.dumps(result));self.assertNotIn('SECRET_METHOD',json.dumps(result))
class Diagnostic(unittest.TestCase):
 def fixture(self):
  fence=r.CONTEXT.parent/('mcp-read-transport-compatibility-preparation-'+r.digest({'originPackageHash':r.ORIGIN_PACKAGE,'humanSourceSha256':'2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285','windowExpiresAt':1792415703})+'.claim.json')
  claim={'context':str(r.CONTEXT),'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False}
  compatibility={'originalLoginReviewHash':r.LOGIN_REVIEW};compat_hash=r.digest(compatibility)
  receipt={'schema':'ouf.mcp-read-transport-human-reauthentication-receipt.v1','compatibilityReviewHash':compat_hash,'reviewHash':r.LOGIN_REVIEW,'priorOAuthAttempts':217,'oauthAttemptsAfter':225,'expiresAt':1792415703,'newLoginWindowOpened':False,'originalLoginConsentPreserved':True,'budgetReset':False,'runtimeAuthorityIssued':False}
  case={'preparationClaimBinding':{'path':str(fence),'sha256':r.digest(claim)},'existingWindowCompatibility':{'originPackageHash':r.ORIGIN_PACKAGE,'originClosureHash':r.CLOSURE,'originalLoginReviewHash':r.LOGIN_REVIEW,'windowExpiresAt':1792415703,'newLoginWindowAllowed':False,'approvedLoginConsentChanged':False,'budgetReset':False},'installedPlanBinding':{'path':'/private/plan.json','sha256':'a'*64},'installedJournalBinding':{'path':'/private/history.json','sha256':'b'*64}}
  raw={str(i):b'pass\n'for i in range(190)};raw['tools.mcp_read_transport_compatibility.entry']=ENTRY.read_bytes()
  package={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':r.SOURCE,'runtimeAuthorityIssued':False,'closure':{'declaration':{'moduleCount':191,'entryModule':'tools.mcp_read_transport_compatibility.entry','sourceHashes':{k:r.sha(v)for k,v in raw.items()}}},'fileHashes':{'case.json':r.digest(case),'sources.json':r.digest({k:base64.b64encode(v).decode()for k,v in raw.items()})}}
  docs={fence:claim,r.CONTEXT/'package.json':package,r.CONTEXT/'runtime.claim.json':{'packageHash':r.digest(package),'automaticReplayAllowed':False},r.CONTEXT/'case.json':case,r.CONTEXT/'compatibility-review.json':compatibility,r.CONTEXT/'compatibility-decision.json':{'reviewHash':compat_hash},r.CONTEXT/'login-window-receipt.json':receipt,r.CONTEXT/'sources.json':{k:base64.b64encode(v).decode()for k,v in raw.items()},Path('/private/plan.json'):{'gateway':{'afterRoutes':routes()}},Path('/private/history.json'):{'effects':[{'stage':'VERIFY_FINAL','state':'APPLIED'}],'budgetReset':False}}
  self.calls=[]
  def parse(path,expected=None):
   path=Path(path);self.calls.append(path);value=docs[path]
   if expected and path not in(Path('/private/plan.json'),Path('/private/history.json')):self.assertEqual(r.digest(value),expected)
   return copy.deepcopy(value)
  return docs,parse,compat_hash
 def test_complete_diagnostic_reads_only_exact_public_artifacts_no_credential_or_key(self):
  docs,parse,compat=self.fixture()
  with patch.object(r,'COMPATIBILITY_REVIEW',compat):result=r.diagnose(parse,lambda _:False)
  self.assertTrue(result['complete']);self.assertTrue(result['retainedGuardWouldPass']);self.assertEqual(result['engineCalls'],0)
  self.assertFalse(any(p.name in('recovery.json','human-access.jwt','authority.json')or p.suffix=='.pem'for p in self.calls))
 def test_later_artifact_or_changed_receipt_denies_before_retained_plan(self):
  docs,parse,compat=self.fixture()
  with patch.object(r,'COMPATIBILITY_REVIEW',compat),self.assertRaises(ValueError):r.diagnose(parse,lambda p:p.name=='authority.json')
  self.assertNotIn(Path('/private/plan.json'),self.calls)
  docs[r.CONTEXT/'login-window-receipt.json']['oauthAttemptsAfter']=226
  with patch.object(r,'COMPATIBILITY_REVIEW',compat),self.assertRaises(ValueError):r.diagnose(parse,lambda _:False)
  self.assertNotIn(Path('/private/plan.json'),self.calls)
 def test_reader_has_no_target_exec_network_mutation_or_dispatch_surface(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(set(calls)&{'exec','eval','compile','subprocess.run','subprocess.Popen','os.execv','os.system','os.write','socket.socket'})
  for text in calls:self.assertFalse(text.endswith(('.login','.refresh_if_due','.current','.ensure','.authenticate','.write_text','.write_bytes')))
if __name__=='__main__':unittest.main()
