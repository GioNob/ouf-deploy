import io,zipfile,tarfile,struct,http.client
import ast,base64,copy,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch,Mock
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
SCRIPT=HERE/'read.py'
if not SCRIPT.exists():SCRIPT=ROOT/'scripts/read-ingestion401-deployed-jar.py'
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

def java_class(*strings):
 raw=b'\xca\xfe\xba\xbe'+struct.pack('!HHH',0,65,len(strings)+1)
 for text in strings:
  text=text.encode();raw+=b'\x01'+struct.pack('!H',len(text))+text
 return raw+b'\0'*6
def jar_bytes(entries):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w')as z:
  for path,value in entries:z.writestr(path,value)
 return b.getvalue()
def archive_bytes(raw,link=False):
 b=io.BytesIO()
 with tarfile.open(fileobj=b,mode='w')as t:
  info=tarfile.TarInfo('app.jar');info.size=len(raw)
  if link:info.type=tarfile.SYMTYPE;info.linkname='/private';info.size=0;t.addfile(info)
  else:t.addfile(info,io.BytesIO(raw))
 return b.getvalue()
class Jar(unittest.TestCase):
 def test_selected_deployed_classes_and_config_are_bounded_safe_projection(self):
  nested=jar_bytes([('org/springframework/boot/security/autoconfigure/servlet/SpringBootWebSecurityConfiguration.class',java_class('SecurityFilterChain','authenticated'))])
  raw=jar_bytes([(m.APP_CLASS+'IngestionIamSecurityConfiguration.class',java_class('ouf.ingestion.iam.enabled','ConditionalOnProperty','SecurityFilterChain')),
   ('BOOT-INF/classes/application.yml',b'ouf.ingestion.iam:\n enabled: ${OUF_ING_IAM_ENABLED:false}\n password: NEVER_PRINT'),
   ('BOOT-INF/lib/spring-boot-security-4.0.8.jar',nested)])
  r=m.jar_projection(raw);self.assertTrue(r['applicationClasses'][0]['present']);self.assertFalse(r['applicationClasses'][1]['present']);self.assertTrue(r['selectedApplicationConfiguration'][0]['iamEnabledEnvironmentDefaultFalse'])
  self.assertEqual(len(r['securityLibraries'][0]['autoConfigurationClasses']),1);self.assertFalse(r['jarCodeExecuted']);self.assertFalse(r['specific401CauseProven']);self.assertNotIn('NEVER_PRINT',m.encoded(r).decode())
 def test_absent_application_iam_filter_is_not_manufactured(self):
  r=m.jar_projection(jar_bytes([('unrelated',b'not code')]))
  self.assertTrue(all(not c['present']for c in r['applicationClasses']));self.assertFalse(r['classesLoadedByCurrentJvmProven'])
 def test_duplicate_zip_and_malformed_class_denied(self):
  import warnings
  with warnings.catch_warnings():
   warnings.simplefilter('ignore');raw=jar_bytes([('same',b'a'),('same',b'b')])
  with self.assertRaises(Exception):m.jar_projection(raw)
  for raw in(b'not class',java_class('a')[:-8],b'\xca\xfe\xba\xbe'+struct.pack('!HHH',0,65,2)+b'\xff'):
   with self.assertRaises(Exception):m.class_markers(raw)
 def test_only_verified_dockerfile_jar_path_without_mount_overlay(self):
  owner={'Config':{'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[]},'Mounts':[]}
  self.assertEqual(m.qualified_jar_path(owner),'/app/app.jar')
  for destination in('/app','/app/app.jar','/'):
   changed=copy.deepcopy(owner);changed['Mounts']=[{'Destination':destination}]
   with self.assertRaises(Exception):m.qualified_jar_path(changed)
  owner['Config']['Entrypoint']=['sh','-c','java -jar /app/app.jar']
  with self.assertRaises(Exception):m.qualified_jar_path(owner)
 def test_one_exact_archive_get_no_process_or_second_dispatch(self):
  raw=jar_bytes([('unrelated',b'a')]);reply=io.BytesIO(archive_bytes(raw));reply.status=200;reply.getheader=lambda *args:'application/x-tar'
  reader=Mock();reader.path=Path('/unused/socket');owner={'Id':m.INGESTION,'Config':{'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[]},'Mounts':[]}
  a=m.ArchiveRead(reader,owner)
  with patch.object(http.client.HTTPConnection,'request')as request,patch.object(http.client.HTTPConnection,'getresponse',return_value=reply):
   self.assertEqual(a.get(),raw);request.assert_called_once_with('GET','/v1.44/containers/'+m.INGESTION+'/archive?path=%2Fapp%2Fapp.jar')
   with self.assertRaises(Exception):a.get()
  self.assertEqual(reader.check.call_count,2)
 def test_archive_symlink_and_wrong_container_denied(self):
  owner={'Id':m.INGESTION,'Config':{'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[]},'Mounts':[]};reader=Mock();reader.path=Path('/unused/socket')
  reply=io.BytesIO(archive_bytes(b'x',link=True));reply.status=200;reply.getheader=lambda *args:'application/x-tar'
  with patch.object(http.client.HTTPConnection,'request'),patch.object(http.client.HTTPConnection,'getresponse',return_value=reply):
   with self.assertRaises(Exception):m.ArchiveRead(reader,owner).get()
  owner['Id']='wrong'
  with self.assertRaises(Exception):m.ArchiveRead(reader,owner)
if __name__=='__main__':unittest.main()
