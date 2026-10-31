"""Synthetic metadata only; production Engine/Capture/contract functions are exercised."""
import ast,copy,hashlib,importlib.util,json,os,sys,tempfile,unittest,urllib.request
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('scope_capture',ROOT/'scripts/read-managed-profile-ths-scopes-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def owner_config(scopes=None):
 scopes=['openid','resolution.issue.read','resolution.match.approve']if scopes is None else scopes
 obj={'spring.security.oauth2.client.registration.ouf-ths.scope':scopes,
      'spring.security.oauth2.client.registration.ouf-ths.client-id':'ouf-ths',
      'unchanged.secret-canary':'PRIVATE_TEST_CANARY','ouf.authorization.ths.enabled':True}
 return {'Config':{'Env':['UNCHANGED=PRIVATE_ENV_CANARY','SPRING_APPLICATION_JSON='+json.dumps(obj)],'Entrypoint':['java'],'Cmd':['-jar','app.jar']}}

class ContractTests(unittest.TestCase):
 def test_additive_request_preserves_every_other_property_environment_and_original(self):
  actual=owner_config();old=copy.deepcopy(actual);summary,env=m.scope_patch(actual)
  self.assertEqual(actual,old);self.assertEqual(summary['missingRequestScopes'],list(m.REQUIRED));self.assertEqual(summary['retainedScopeCount'],3)
  self.assertEqual(summary['requestedScopes'],['openid','resolution.issue.read','resolution.match.approve'])
  parsed=json.loads(env[1].split('=',1)[1]);self.assertEqual(parsed[m.SCOPE_PROPERTY],summary['requestedScopes']+list(m.REQUIRED))
  self.assertEqual(parsed['unchanged.secret-canary'],'PRIVATE_TEST_CANARY');self.assertEqual(env[0],old['Config']['Env'][0])
  self.assertNotIn('PRIVATE_',json.dumps(summary));self.assertFalse(summary['iamBindingObserved']);self.assertFalse(summary['browserTokenInspected'])
 def test_partial_scope_request_adds_only_missing_requirements(self):
  summary,_=m.scope_patch(owner_config(['openid',m.REQUIRED[0]]));self.assertEqual(summary['missingRequestScopes'],list(m.REQUIRED[1:]))
 def test_already_requested_is_observed_without_noop_rewrite_or_authority(self):
  actual=owner_config(['openid']+list(m.REQUIRED));summary,env=m.scope_patch(actual)
  self.assertFalse(summary['conditionalConfigurationPatchPrepared']);self.assertEqual(env,actual['Config']['Env']);self.assertEqual(summary['missingRequestScopes'],[])
 def test_reusable_contract_module_import_executes_actual_runtime_dependency(self):
  sys.path.insert(0,str(ROOT))
  try:
   from tools.managed_profile_ths_scopes import contract
   summary,env=contract.scope_patch(owner_config())
   self.assertEqual(summary['missingRequestScopes'],list(m.REQUIRED))
  finally:sys.path.pop(0)
 def test_scope_string_accepts_spring_comma_whitespace_without_losing_existing_scopes(self):
  summary,env=m.scope_patch(owner_config('openid, resolution.issue.read resolution.match.approve'))
  self.assertEqual(summary['retainedScopeCount'],3);self.assertEqual(m.scope_list(json.loads(env[1].split('=',1)[1])[m.SCOPE_PROPERTY]),summary['requestedScopes']+list(m.REQUIRED))
 def test_nested_and_flat_scope_properties_cannot_shadow_each_other(self):
  actual=owner_config();obj=json.loads(actual['Config']['Env'][1].split('=',1)[1]);obj['spring']={'security':{'oauth2':{'client':{'registration':{'ouf-ths':{'scope':['openid']}}}}}}
  actual['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(obj)
  with self.assertRaisesRegex(m.Stop,'AMBIGUOUS_SPRING_JSON_PROPERTY'):m.scope_patch(actual)
 def test_nested_properties_are_patched_without_reformatting_other_values(self):
  actual=owner_config();obj={'spring':{'security':{'oauth2':{'client':{'registration':{'ouf-ths':{'scope':['openid'],'client-id':'ouf-ths'}}}}}},'retained':[1,2,3]}
  actual['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(obj);summary,env=m.scope_patch(actual)
  self.assertEqual(summary['clientIdObservedFromJson'],'ouf-ths');self.assertEqual(json.loads(env[1].split('=',1)[1])['retained'],[1,2,3])
 def test_duplicate_env_is_rejected(self):
  actual=owner_config();actual['Config']['Env'].append('UNCHANGED=x')
  with self.assertRaisesRegex(m.Stop,'UNIQUE_ENVIRONMENT_REQUIRED'):m.scope_patch(actual)
 def test_duplicate_json_key_is_rejected(self):
  actual=owner_config();actual['Config']['Env'][1]='SPRING_APPLICATION_JSON={"a":1,"a":2}'
  with self.assertRaisesRegex(m.Stop,'DUPLICATE_PRIVATE_KEY'):m.scope_patch(actual)
 def test_direct_oauth_environment_override_needs_explicit_review(self):
  actual=owner_config();actual['Config']['Env'].append('SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OUF_THS_SCOPE=openid')
  with self.assertRaisesRegex(m.Stop,'DIRECT_OAUTH_ENV_OVERRIDE_REQUIRES_REVIEW'):m.scope_patch(actual)
 def test_jvm_system_property_override_is_not_assumed_absent(self):
  actual=owner_config();actual['Config']['Cmd'].append('-Dspring.test=override')
  with self.assertRaisesRegex(m.Stop,'UNREVIEWED_OAUTH_REQUEST_ARGUMENT_OVERRIDE'):m.scope_patch(actual)
 def test_missing_explicit_json_does_not_trigger_secret_file_fallback(self):
  actual=owner_config();actual['Config']['Env']=['SPRING_CONFIG_IMPORT=file:/private/secret.yaml']
  with self.assertRaisesRegex(m.Stop,'BOUNDED_EXISTING_SPRING_JSON_REQUIRED'):m.scope_patch(actual)
 def test_unobserved_client_id_is_not_invented(self):
  actual=owner_config();obj=json.loads(actual['Config']['Env'][1].split('=',1)[1]);del obj[m.CLIENT_PROPERTY];actual['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(obj)
  summary,_=m.scope_patch(actual);self.assertIsNone(summary['clientIdObservedFromJson']);self.assertFalse(summary['clientIdFromLowerPriorityFileRead'])
 def test_duplicate_or_dynamic_scopes_rejected(self):
  for scopes in [['openid','openid'],['${SECRET_SCOPE}'],[],['openid',5]]:
   with self.subTest(scopes=scopes),self.assertRaises((m.Stop,TypeError)):m.scope_patch(owner_config(scopes))
 def test_reusable_contract_and_sealed_capture_have_identical_function_bodies(self):
  contract=ast.parse((ROOT/'tools/managed_profile_ths_scopes/contract.py').read_text());reader=ast.parse((ROOT/'scripts/read-managed-profile-ths-scopes-20261028.py').read_text())
  defs={n.name:ast.dump(n,include_attributes=False)for n in reader.body if isinstance(n,ast.FunctionDef)}
  for n in contract.body:
   if isinstance(n,ast.FunctionDef):self.assertEqual(ast.dump(n,include_attributes=False),defs[n.name])
 def test_no_tty_stops_before_private_scope_or_iam(self):
  flags=type('Flags',(),{'isolated':1,'no_site':1})()
  with patch.object(m.sys,'argv',['reader']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=type('User',(),{'pw_uid':1001})()),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Capture')as cap,patch('urllib.request.urlopen',side_effect=AssertionError('network forbidden')):
   with patch('builtins.print')as output:self.assertEqual(m.main(),2)
  cap.assert_not_called();self.assertIn('INTERACTIVE_OPERATOR_TERMINAL_REQUIRED',str(output.call_args))

# Producer-shaped complete two-owner history, with fixed denominator13 including both updated owners.
def fixture():
 observations={};cohort={};generations={}
 for n,role in enumerate(['onboarding','mcp']+['peer-'+str(n)for n in range(11)],1):
  cid=('%064x'%n);pid=100+n;value={'Id':cid,'Name':'/'+role,'Image':'sha256:'+('%064x'%(n+30)),
    'State':{'Pid':pid,'StartedAt':'start-'+str(n),'Running':True,'Paused':False,'Restarting':False},
    'Config':owner_config()['Config']if role=='onboarding'else{'Env':[]},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
  observations[cid]=value;cohort[role]=m.stable_binding(value);generations[role]={'pid':pid,'startTicks':n,'namespaces':{'mnt':[4,n],'net':[4,n+20]}}
 case=copy.deepcopy(m.CASE);case['nativeImageIds']={r:observations[cohort[r]['containerId']]['Image']for r in('onboarding','mcp')};case['nativeBindingHashes']={r:m.digest(cohort[r])for r in('onboarding','mcp')}
 # Prior owners differ from their replacement IDs; the actual journal supplies replacement IDs.
 old_cohort=copy.deepcopy(cohort)
 for n,r in enumerate(('onboarding','mcp'),90):old_cohort[r]['containerId']='%064x'%n
 stages=['CREATE_ONBOARDING_OWNER','CREATE_MCP_OWNER','VERIFY_FINAL','VERIFY_FINAL_STATE']
 review={'schema':'ouf.managed-csv-control-update-review.v1','executionRoot':case['installedRoot'],'bootId':'fixture-boot','stages':stages,
         'nativePlan':{'proposal':{'existingApplications':old_cohort,'engineBinding':{'peerCredentials':[77,0,0]}}}}
 case['frozenPlanHash']=m.digest(review['nativePlan']['proposal']);review['frozenPlanHash']=case['frozenPlanHash'];case['reviewHash']=m.digest(review)
 proofs={r:{'nativeBindingHash':case['nativeBindingHashes'][r],'generation':generations[r],'readinessProven':True,'oldRetainedStopped':True}for r in('onboarding','mcp')}
 result={'schema':'ouf.managed-csv-control-update-result.v1','status':'MANAGED_CSV_CONTROL_UPDATE_INSTALLED_E2E_NOT_ACCEPTED','complete':True,'componentReadinessProven':True,
         **{k:case[k]for k in('reviewHash','authorityHash','executionInputsHash','frozenPlanHash','nativeImageIds')},'candidateSourceCommits':case['sourceCommits'],
         'humanBudgetsGranted':0,'resumes':0,'acquisitionsExecuted':0,'sourceActivations':0,'registryWorkerTouched':False,'ownerProofs':proofs}
 journal={'schema':'ouf.managed-csv-control-update-journal.v1','state':'COMPLETE','reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],'quarantine':None,
          'automaticReplayAllowed':False,'budgetReset':False,'nextStage':len(stages),'effects':[],
          'candidates':{r:{'id':cohort[r]['containerId'],'configurationVerified':True,'readinessProven':True,'generation':generations[r]}for r in('onboarding','mcp')}}
 for stage in stages:journal['effects'].append({'stage':stage,'state':'APPLIED','intentHash':m.digest({'reviewHash':case['reviewHash'],'stage':stage}),'proof':{'ownerProofs':proofs}if stage=='VERIFY_FINAL'else{}})
 return case,review,result,journal,cohort,observations,generations

class CaptureTests(unittest.TestCase):
 def setUp(self):self.case,self.review,self.result,self.journal,self.cohort,self.observations,self.generations=fixture()
 def test_completed_history_resolves_exact_two_replacements_and_all13_peers(self):
  cohort=m.completed_history(self.review,self.result,self.journal,self.case);self.assertEqual(len(cohort),13)
  self.assertEqual(cohort['onboarding']['containerId'],self.journal['candidates']['onboarding']['id']);self.assertEqual(cohort['mcp']['containerId'],self.journal['candidates']['mcp']['id'])
 def test_ambiguous_old_effect_or_incomplete_journal_is_not_reopened(self):
  for change in ['state','effect']:
   j=copy.deepcopy(self.journal)
   if change=='state':j['state']='OPEN'
   else:j['effects'][0]['state']='CLAIMED'
   with self.subTest(change=change),self.assertRaises(m.Stop):m.completed_history(self.review,self.result,j,self.case)
 def test_wrong_native_binding_and_history_hash_are_denied(self):
  for key in ['reviewHash','nativeBindingHashes']:
   case=copy.deepcopy(self.case)
   if key=='reviewHash':case[key]='0'*64
   else:case[key]['onboarding']='0'*64
   with self.subTest(key=key),self.assertRaises(m.Stop):m.completed_history(self.review,self.result,self.journal,case)
 def test_duplicate_cohort_id_cannot_be_adopted(self):
  j=copy.deepcopy(self.journal);j['candidates']['mcp']['id']=j['candidates']['onboarding']['id']
  with self.assertRaisesRegex(m.Stop,'DISTINCT_RETAINED_COHORT_REQUIRED'):m.completed_history(self.review,self.result,j,self.case)
 def test_actual_capture_sequence_and_counts_no_writes_or_secret_file_fallback(self):
  outer=self;reads=[];writes={}
  class Capture:
   root=Path('/fixture/new-scope');counts={'engineGets':0,'privateMetadataReads':0,'bytes':0};seals={}
   def private(s,path,expected=None):
    s.counts['privateMetadataReads']+=1;return {'review.json':outer.review,'result.json':outer.result,'recovery.json':outer.journal}[path.name]
   def put(s,name,value):writes[name]=copy.deepcopy(value)
  class Engine:
   def __init__(s,c,binding,ids):s.c=c;outer.assertEqual(len(ids),13)
   def get(s,path):
    reads.append(path);s.c.counts['engineGets']+=1
    return {'ServerVersion':'29.8.1'}if path=='/v1.44/info'else copy.deepcopy(outer.observations[path.split('/')[-2]])
  pins={v['pid']:v for v in self.generations.values()};pins[1]={'pid':1};pins[77]={'pid':77}
  boot=type('Boot',(),{'read_text':lambda s:'fixture-boot'})()
  result=m.inspect_current(Capture(),self.case,engine_factory=Engine,pin=lambda pid:pins[pid],boot_path=boot)
  self.assertEqual(result['counts']['engineGets'],27);self.assertEqual(result['counts']['privateMetadataReads'],3)
  self.assertEqual(len(reads),27);self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['runtimeAuthorityIssued'])
  self.assertEqual(result['configurationFileContentReads'],0);self.assertNotIn('PRIVATE_',json.dumps(result));self.assertIn('PRIVATE_',json.dumps(writes['inputs.json']))
 def test_engine_port_is_get_only_exact_ids_before_socket_access(self):
  capture=type('C',(),{'counts':{'engineGets':0},'maximums':{'engineGets':27}})()
  engine=m.Engine(capture,{},['1'*64])
  for path in ['/v1.44/containers/json','/v1.44/containers/'+'2'*64+'/json','/v1.44/containers/'+'1'*64+'/start']:
   with self.subTest(path=path),self.assertRaisesRegex(m.Stop,'CLOSED_READ_ONLY_ENGINE_CAPTURE_REQUIRED'):engine.get(path)
if __name__=='__main__':unittest.main()
