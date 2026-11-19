import os,sys,tempfile,zipfile,hashlib
from types import SimpleNamespace
import ast,base64,copy,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
SCRIPT=HERE/'read.py'
if not SCRIPT.exists():SCRIPT=ROOT/'scripts/prepare-ingestion-read-owner-inputs.py'
spec=importlib.util.spec_from_file_location('auth_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RECEIPT=ROOT/'evidence/installation-route-reconciliation-target-20261019.json'
if not RECEIPT.exists():RECEIPT=ROOT.parent/'installation_route_reconcile/completed-target.json'
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

def container(char):
 return {'Id':char*64,'Image':'sha256:'+char*64,'State':{'Running':True,'Pid':101,'StartedAt':'start'},
  'Config':{'Env':['OUF_AUTH_OWNER_KEY=NEVER_PRINT_SECRET','OUF_GATEWAY_DELEGATION_KEY=NEVER_PRINT_OTHER','OUF_ING_IAM_ENABLED=false']},'HostConfig':{},
  'Mounts':[{'Type':'bind','Source':'/private/secret-ref','Destination':'/run/secrets/known','RW':False,'Propagation':'rprivate'}],'NetworkSettings':{}}
def owner_inputs():
 projection={'installationId':'ouf-lab-netcup-01','revision':6,'checksum':'ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98',
  'gateway':{'issuerUrl':'https://issuer.invalid','requiredAudience':'gateway'},'iam':{'workloadClients':{'mcpServer':'workload'}}}
 payload={'installationId':projection['installationId'],'iam':{'issuerUrl':'https://issuer.invalid','gatewayAudience':'gateway','workloadClients':{'mcpServer':'workload'}},
  'secrets':{'provider':'FILES','references':{'mcpClientSecret':'/private/mcp-ref','mcpFingerprintKey':'/private/fingerprint-ref'}}}
 plan={'bindingPlan':{'candidatePayload':payload},'gateway':{'transport':{'runtimeBindingProfile':'ouf.apisix-runtime-binding.mount-set.v1'}}}
 return plan,projection
class Preparation(unittest.TestCase):
 def test_private_input_contains_only_reference_metadata_and_safe_summary(self):
  plan,projection=owner_inputs();inputs,summary=m.prepare_inputs(plan,projection,container('a'),container('b'))
  self.assertTrue(summary['gatewayEnvironmentAdditionRequired']);self.assertFalse(summary['secretReferenceAlreadyPresent']);self.assertEqual(summary['secretValuesReadFromFiles'],0)
  for doc in(inputs,summary):
   text=m.encoded(doc).decode();self.assertNotIn('NEVER_PRINT_SECRET',text);self.assertNotIn('NEVER_PRINT_OTHER',text)
  self.assertNotIn('/private/',m.encoded(summary).decode());self.assertIn('OUF_AUTH_OWNER_KEY',summary['gatewayAuthEnvironmentNames'])
 def test_owner_profile_provider_or_environment_ambiguity_denied(self):
  for kind in('revision','issuer','provider','environment'):
   plan,p=owner_inputs();g=container('a')
   if kind=='revision':p['revision']=7
   if kind=='issuer':p['gateway']['issuerUrl']='https://other.invalid'
   if kind=='provider':plan['bindingPlan']['candidatePayload']['secrets']['provider']='EXTERNAL_SECRET_STORE'
   if kind=='environment':g['Config']['Env'].append(g['Config']['Env'][0])
   with self.subTest(kind=kind),self.assertRaises(Exception):m.prepare_inputs(plan,p,g,container('b'))
 def test_actual_no_follow_profile_custody_and_no_overwrite_file(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   p=Path(d)/'profile.json';p.write_bytes(b'{}');p.chmod(0o600)
   with patch.object(m,'_EXISTING_CONFIG_CUSTODY',{str(p):{'parents':{},'file':(0,0,0o600)}}):
    raw,binding=m.private_config(p);self.assertEqual(raw,b'{}');self.assertEqual(m.private_config(p,binding)[0],raw)
    link=p.parent/'link';link.symlink_to(p)
    with self.assertRaises(Exception):m.private_config(link)
    p.chmod(0o440)
    with self.assertRaises(Exception):m.private_config(p)
   out=p.parent/'new.json';m.write_new(out,b'unchanged')
   with self.assertRaises(FileExistsError):m.write_new(out,b'replaced')
   self.assertEqual(out.read_bytes(),b'unchanged')
 def test_real_private_preparation_preserves_profile_and_denies_second_claim(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);plan,projection=owner_inputs();path=root/'projection.json';path.write_bytes(m.encoded(projection));path.chmod(0o600)
   raw,binding=m.private_config(path);plan.update(projectionBinding={'path':str(path)},projectionHash=m.sha(raw),currentPublishedProjectionBinding=binding)
   g,o,c=container('a'),container('b'),container('c');expected={'gateway':m.runtime(g),'ingestion':m.runtime(o),'mcp':m.runtime(c)}
   old={'engine':{},'gateway':{'transport':{'runtimeBinding':expected['gateway'],'runtimeBindingProfile':'ouf.apisix-runtime-binding.mount-set.v1'}},'unchangedApplications':{'ingestion':expected['ingestion']}}
   completed={'finalEvidence':{'mcp':{'runtimeBinding':expected['mcp']}}};records={v['Id']:v for v in(g,o,c)}
   class Reader:
    def __init__(self,*args):self.calls=0
    def get(self,path):self.calls+=1;return copy.deepcopy(records[path.split('/')[-2]])
   flags={key:getattr(sys.flags,key)for key in dir(sys.flags)if not key.startswith('_')and not callable(getattr(sys.flags,key))};flags.update(isolated=True,no_site=True)
   candidate,metadata,zipsha=artifact(root)
   with (patch.object(m,'CANDIDATE',metadata),patch.object(m,'CANDIDATE_ZIP_SHA256',zipsha),patch.object(m,'NEW_CONTEXT',root/'completed'),patch.object(m,'ACTIVE_PATH',str(path)),patch.object(m,'history',return_value=(old,completed,'fixture')),
        patch.object(m,'completed_routes',return_value=(routes(),'4b21a5733ccd6212432e3aa69dc08b8ad0f4f402d50044fa8c442da585130f82','1191c3817a2c152b4070ec9c946fae29746b6f2b155e54d9dba504e3803bd965')),
        patch.object(m,'parsed',return_value=plan),patch.object(m,'Reader',Reader),patch.object(m.sys,'flags',SimpleNamespace(**flags))):
    report=m.main(candidate);self.assertTrue(report['complete']);self.assertEqual(report['privatePreparationWrites'],4);self.assertEqual(report['engineGetRequests'],6)
    context=Path(report['contextPath']);inputs=json.loads((context/'inputs.json').read_bytes());self.assertEqual(m.digest(inputs),report['inputsHash']);self.assertEqual(path.read_bytes(),raw)
    self.assertEqual(stat_mode(context),0o700);self.assertEqual(stat_mode(context/'inputs.json'),0o600)
    with self.assertRaisesRegex(ValueError,'INPUT_PREPARATION_ALREADY_CLAIMED_NO_REPLAY'):m.main(candidate)
   m.signal.alarm(0)
def stat_mode(path):return path.stat().st_mode&0o777

def artifact(root,extra=False):
 image=b'public fixture image archive';scan=b'{"Results":[]}'
 metadata={'imageId':'sha256:'+'a'*64,'imageArchiveSha256':m.sha(image),'imageArchiveBytes':len(image),'trivyReportSha256':m.sha(scan)}
 path=root/'candidate.zip'
 with zipfile.ZipFile(path,'w')as z:
  z.writestr('image.tar.gz',image);z.writestr('metadata.json',m.encoded(metadata));z.writestr('trivy-image.json',scan)
  if extra:z.writestr('../outside',b'denied')
 path.chmod(0o600);return path,metadata,m.sha(path.read_bytes())
class Candidate(unittest.TestCase):
 def test_exact_candidate_artifact_staged_without_extraction_or_import(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);path,metadata,digest=artifact(root)
   with patch.object(m,'CANDIDATE',metadata),patch.object(m,'CANDIDATE_ZIP_SHA256',digest),m.candidate_bundle(path)as bundle:
    out=root/'image.tar.gz';binding=m.copy_candidate(bundle,out)
    self.assertEqual(binding['sha256'],metadata['imageArchiveSha256']);self.assertEqual(stat_mode(out),0o600)
   self.assertEqual(path.read_bytes()[:2],b'PK')
 def test_tampered_artifact_extra_member_and_image_hash_drift_denied(self):
  for kind in('outer','entry','image'):
   with tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d);path,metadata,digest=artifact(root,extra=kind=='entry')
    if kind=='outer':digest='0'*64
    if kind=='image':
     metadata['imageArchiveSha256']='0'*64
     with zipfile.ZipFile(path,'w')as z:
      z.writestr('image.tar.gz',b'public fixture image archive');z.writestr('metadata.json',m.encoded(metadata));z.writestr('trivy-image.json',b'{"Results":[]}')
     digest=m.sha(path.read_bytes())
    with self.subTest(kind=kind),patch.object(m,'CANDIDATE',metadata),patch.object(m,'CANDIDATE_ZIP_SHA256',digest),self.assertRaises(Exception):
     with m.candidate_bundle(path)as bundle:m.copy_candidate(bundle,root/'out')
 def test_production_candidate_pins_exact_push_artifact(self):
  self.assertEqual(m.CANDIDATE['sourceCommit'],'663faa03288f9ad7775382b9757e44eaba4f51ca')
  self.assertEqual(m.CANDIDATE['imageId'],'sha256:51a514d8e07ad7448f98a3886e0c9c6d5b50829f85d320785038a2c76eae46f3')
  self.assertEqual(m.CANDIDATE_ZIP_SHA256,'1a26522ab9507bb85fbd6924c0c48c67720493516ec4471a4b3577a8f853ec3f')

if __name__=='__main__':unittest.main()
