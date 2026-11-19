import ast,copy,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
SCRIPT=HERE/'compile.py'
if not SCRIPT.exists():SCRIPT=HERE/'compile-ingestion-read-owner-draft.py'
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=module('draft',SCRIPT)
BASE=HERE.parent/'plan_inputs/read.py'
if not BASE.exists():BASE=HERE/'base.py'
b=module('draft_base',BASE)
GATEWAY=HERE.parent/'gateway'
if not GATEWAY.exists():GATEWAY=HERE/'gateway-source'
renderer=module('qualified_renderer',GATEWAY/'tools/delegation_functions.py')
lua={n:(GATEWAY/'tools/lua'/n).read_text()for n in('delegation.lua','execute_ingestion_read.lua')}
def fixture():
 iam={'issuerUrl':'https://issuer.invalid/realm','gatewayAudience':'gateway','workloadClients':{'mcpServer':'mcp'}}
 payload={'installationId':'test-installation','iam':iam,'secrets':{'provider':'FILES','references':{'existing':'/private/old'}},'networking':{'serviceBindings':{'ouf-ingestion-runtime':'owner-alias'}}}
 checksum=m.canonical_owner(payload)
 inputs={'schema':'ouf.ingestion-read-owner-installation-inputs.private.v1','installationId':'test-installation',
  'gatewaySourceCommit':'6bcb28906eee08e0ebe3507b8b58dd987012c8e6','ingestionCandidateSourceCommit':'663faa03288f9ad7775382b9757e44eaba4f51ca',
  'lastReportedOAuthAttempts':259,'maximumCumulativeOAuthAttempts':264,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
  'retainedOwnerRevision':6,'retainedOwnerGeneration':6,'retainedOwnerPayload':payload,
  'retainedProjection':{'installationId':'test-installation','revision':6,'checksum':checksum,'gateway':{'issuerUrl':iam['issuerUrl'],'requiredAudience':'gateway'},'iam':{'workloadClients':{'mcpServer':'mcp'}}},
  'gatewayEnvironmentNames':['OUF_GATEWAY_DELEGATION_KEY'],'gatewayEnvironmentAdditionRequired':True,'secretReferenceAlreadyPresent':False,
  'ingestionEnvironmentNames':['SPRING_CONFIG_ADDITIONAL_LOCATION'],'ingestionMountReferences':[{'Destination':'/known-config'}],
  'runtimeBindings':{'gateway':{'containerId':'a'*64},'ingestion':{'containerId':'b'*64}},'candidateMetadata':b.CANDIDATE,
  'candidateImageBinding':{},'publishedProjectionBinding':{'path':'/private/profile','sha256':'0'*64}}
 routes={str(i):{'id':str(i),'unchanged':[i]}for i in range(80)}
 constants={'DELEGATION_KEY_ENV':'OUF_GATEWAY_DELEGATION_KEY','ISSUER':iam['issuerUrl'],'AUDIENCE':'gateway','MCP_WORKLOAD':'mcp','OWNER':'ingestion','REQUIRED_SCOPE':'ingestion.operations.read'}
 for mode in('status','history'):
  cap='ouf.ingestion.'+mode
  routes['mcp-ingestion-'+mode]={'uri':'/internal/capabilities/v1/execute/'+cap,'methods':['POST'],'upstream':{'nodes':{'owner-alias:8080':1}},
   'labels':{'old':'preserved'},'plugins':{'openid-connect':{'bearer_only':True,'ssl_verify':True},
   'proxy-rewrite':{'uri':'/api/internal/v1/ingestion/operations/'+mode},'serverless-post-function':{'phase':'access','functions':['\n'.join('local '+k+' = '+json.dumps(v)for k,v in dict(constants,CAPABILITY=cap).items())]}}}
 inputs['retainedGatewayRouteMapHash']=m.digest(routes)
 return inputs,routes,checksum
class Draft(unittest.TestCase):
 def compile(self,inputs,routes,checksum,context=Path('/private/proposal')):
  with patch.object(m,'OWNER_CHECKSUM',checksum):return m.compile_plan(inputs,routes,lua,context)
 def test_exact_qualified_renderer_output(self):
  installation={'issuerUrl':'https://issuer.invalid/realm','gatewayAudience':'gateway','mcpServiceIdentity':'mcp'}
  for mode in('status','history'):
   cap='ouf.ingestion.'+mode
   expected=renderer.function('execute_ingestion_read',installation,'OUF_GATEWAY_DELEGATION_KEY',owner_key_env=m.KEY_ENV,operational_binding={'capability':cap,'owner':'ingestion','scope':'ingestion.operations.read'})
   self.assertEqual(m.render_function(lua,installation,cap),expected)
 def test_owner_one_reference_delta_two_closed_routes_and_no_authority(self):
  inputs,routes,checksum=fixture();saved=copy.deepcopy((inputs,routes));p=self.compile(inputs,routes,checksum)
  self.assertEqual((inputs,routes),saved);new=copy.deepcopy(p['owner']['candidatePayload']);del new['secrets']['references'][m.KEY_REF]
  self.assertEqual(new,inputs['retainedOwnerPayload']);self.assertEqual(p['gateway']['afterRoutes']['0'],routes['0'])
  self.assertEqual(p['gateway']['afterRoutes']['mcp-ingestion-status']['upstream'],routes['mcp-ingestion-status']['upstream'])
  self.assertEqual(len(p['gateway']['changes']),2);self.assertFalse(p['runtimeAuthorityIssued']);self.assertFalse(p['ownerApplyAuthorized'])
  self.assertFalse(p['human']['newBudgetAuthorized']);self.assertTrue(p['unprovenAdmissions']);self.assertEqual(p['runtime']['ingestion']['environmentAdditions']['OUF_ING_GATEWAY_READ_KEY_FILE'],m.CONTAINER_KEY)
  self.assertNotIn('SPRING_CONFIG_ADDITIONAL_LOCATION',p['runtime']['ingestion']['environmentAdditions'])
 def test_owner_identity_reference_provider_and_trust_drift_deny(self):
  for kind in('checksum','provider','key','issuer','generation'):
   inputs,routes,checksum=fixture()
   if kind=='checksum':inputs['retainedOwnerPayload']['installationId']='other'
   if kind=='provider':inputs['retainedOwnerPayload']['secrets']['provider']='other'
   if kind=='key':inputs['retainedOwnerPayload']['secrets']['references'][m.KEY_REF]='already'
   if kind=='issuer':inputs['retainedProjection']['gateway']['issuerUrl']='https://other.invalid'
   if kind=='generation':inputs['retainedOwnerGeneration']=7
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.compile(inputs,routes,checksum)
 def test_collision_or_consumed_input_deny(self):
  for kind in('gateway','env','mount','budget','authority','commit'):
   i,r,c=fixture()
   if kind=='gateway':i['gatewayEnvironmentNames'].append(m.KEY_ENV)
   if kind=='env':i['ingestionEnvironmentNames'].append('OUF_ING_GATEWAY_READ_ENABLED')
   if kind=='mount':i['ingestionMountReferences'].append({'Destination':m.CONTAINER_KEY})
   if kind=='budget':i['maximumCumulativeOAuthAttempts']=272
   if kind=='authority':i['runtimeAuthorityIssued']=True
   if kind=='commit':i['gatewaySourceCommit']='0'*40
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.compile(i,r,c)
 def test_changed_routes_or_trust_constants_deny(self):
  for kind in('extra','oidc','path','constant','newreceipt'):
   i,r,c=fixture();route=r['mcp-ingestion-status']
   if kind=='extra':r['extra']={}
   if kind=='oidc':route['plugins']['openid-connect']['ssl_verify']=False
   if kind=='path':route['plugins']['proxy-rewrite']['uri']='/another'
   if kind=='constant':route['plugins']['serverless-post-function']['functions'][0]+='\nlocal ISSUER = "https://spoof.invalid"'
   if kind=='newreceipt':route['plugins']['serverless-post-function']['functions'][0]+='\nlocal OWNER_KEY_ENV = "EXISTING"'
   i['retainedGatewayRouteMapHash']=m.digest(r)
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.compile(i,r,c)
 def test_canonical_owner_rejects_ambiguous_values(self):
  for value in(1.0,'astral\U0001f600',2**63,{'bad':'line\nfeed'}):
   with self.assertRaises(ValueError):m.canonical_owner(value)
 def test_actual_image_custody_symlink_hardlink_mode_and_hash(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   path=Path(d)/'image';path.write_bytes(b'public-image-fixture');path.chmod(0o600)
   binding={'path':str(path),'sha256':m.sha(path.read_bytes()),'bytes':path.stat().st_size};m.check_image_file(path,binding)
   link=Path(d)/'symlink';link.symlink_to(path)
   with self.assertRaises(OSError):m.check_image_file(link,{**binding,'path':str(link)})
   hard=Path(d)/'hardlink';os.link(path,hard)
   with self.assertRaises(ValueError):m.check_image_file(path,binding)
   hard.unlink();path.chmod(0o644)
   with self.assertRaises(ValueError):m.check_image_file(path,binding)
   path.chmod(0o600)
   with self.assertRaises(ValueError):m.check_image_file(path,{**binding,'sha256':'0'*64})
 def test_real_preparation_is_private_preserves_predecessor_and_denies_replay(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);context=root/'inputs';context.mkdir(mode=0o700);i,r,c=fixture();image=context/'candidate-image.tar.gz';image.write_bytes(b'public-fixture');image.chmod(0o600)
   i['candidateImageBinding']={'path':str(image),'sha256':m.sha(image.read_bytes()),'bytes':image.stat().st_size}
   metadata={**b.CANDIDATE,'imageArchiveBytes':image.stat().st_size,'imageArchiveSha256':m.sha(image.read_bytes())};i['candidateMetadata']=metadata
   b.write_new(context/'inputs.json',m.encoded(i));h=m.digest(i)
   receipt={'complete':True,'contextPath':str(context),'inputsHash':h,'logicalRef':m.LOGICAL,'candidateImageImported':False}
   b.write_new(context/'preparation-result.json',m.encoded(receipt));before=(context/'inputs.json').read_bytes()
   completed=root/'completed';completed.mkdir(mode=0o700);b.write_new(completed/'execution-plan.json',m.encoded({'gateway':{'afterRoutes':r}}))
   flags=SimpleNamespace(isolated=True,no_site=True)
   with (patch.object(m,'INPUT_CONTEXT',context),patch.object(m,'INPUT_HASH',h),patch.object(m,'OWNER_CHECKSUM',c),
    patch.object(b,'CANDIDATE',metadata),patch.object(b,'NEW_CONTEXT',completed),patch.object(b,'private_config',return_value=(b'{}',{})),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True)):
    auditor=lambda *_:{'candidateImageImported':False,'currentRuntimeGenerationsVerified':True,'candidateJar':{'migrationFilesUnchanged':True},'installedJar':{'migrationFilesUnchanged':True},'databaseAdmissionProven':False,'runtimeAuthorityIssued':False,'engineGetRequests':6,'engineArchiveGetRequests':1}
    report=m.main(b,lua,auditor);self.assertTrue(report['complete']);self.assertEqual(report['engineGetRequests'],6);self.assertEqual(report['privatePreparationWrites'],4)
    out=Path(report['contextPath']);self.assertEqual(out.stat().st_mode&0o777,0o700);self.assertEqual((out/'draft-plan.json').stat().st_mode&0o777,0o600)
    self.assertEqual((context/'inputs.json').read_bytes(),before);self.assertEqual(m.digest(b.parsed(out/'draft-plan.json')),report['draftPlanHash'])
    with self.assertRaisesRegex(ValueError,'DRAFT_ALREADY_CLAIMED_NO_REPLAY'):m.main(b,lua,auditor)
   m.signal.alarm(0)
 def test_no_network_token_authority_or_process_primitives(self):
  tree=ast.parse(SCRIPT.read_bytes());calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
  self.assertFalse(calls&{'exec','eval','os.execv','os.system'})
  self.assertFalse(any(any(v.endswith(s)for s in('.request','.refresh_if_due','.login','.token','.setns','.Popen','.issue_action'))for v in calls))
  imports={n.names[0].name.split('.')[0]for n in ast.walk(tree)if isinstance(n,ast.Import)}
  self.assertFalse(imports&{'socket','http','urllib','subprocess','requests'})
if __name__=='__main__':unittest.main()
