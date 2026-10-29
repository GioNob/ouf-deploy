"""Finite HUMAN scope successor, actual frozen guard and immutable owner baseline."""
import ast,base64,copy,hashlib,importlib.util,json,os,sys,tempfile,time,types,unittest,urllib.error
from pathlib import Path
from unittest.mock import Mock,MagicMock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chatbot_file_cohort import human_session as h
PREVIOUS=['openid','authorization.policy.admin','mcp.connect','authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read','udp.materialization.retry']
h.LEGACY_SCOPES=PREVIOUS
from tools.installation_binding_plan import plan as p,login as m,runtime as loader
SPEC=importlib.util.spec_from_file_location('scope_constants',ROOT/'scripts/installation-binding-scope-constants.py');t=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(t)
FROZEN=ROOT/'tests/fixtures/mcp-human-renewal-guard-2e96cfc5.py'
def full_fixture():
 tree=ast.parse((ROOT/'tools/chatbot_file_cohort/human_session.py').read_bytes());guard=ast.parse(FROZEN.read_bytes()).body[1].body[0]
 cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='HumanSession')
 cls.body=[copy.deepcopy(guard)if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget'else n for n in cls.body]
 tree.body+=ast.parse('LEGACY_SCOPES='+repr(t.BASE)+'\nSCOPES=LEGACY_SCOPES+["udp.materialization.retry"]\nPROFILE={**PROFILE,"id":"ouf.chatbot-human-session.finite-test.v2","maximumAttempts":256}\n').body
 return ast.unparse(tree).encode()
class ScopeConstants(unittest.TestCase):
 def test_only_two_constants_change_all_functions_and_guard_are_identical(self):
  before=ast.parse(full_fixture());after=ast.parse(t.transform(full_fixture()))
  for tree in(before,after):
   tree.body=[n for n in tree.body if not(isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('SCOPES','LEGACY_SCOPES'))]
  self.assertEqual(ast.dump(before,include_attributes=False),ast.dump(after,include_attributes=False))
 def test_unknown_scope_budget_and_missing_guard_stop_before_transform(self):
  for raw in(full_fixture().replace(b'256',b'384'),full_fixture().replace(b'udp.materialization.retry',b'unknown.scope'),full_fixture().replace(b'ouf.human-explicit-capability-scope-review.v4',b'unknown-schema')):
   with self.subTest(raw=raw[-80:]),self.assertRaises(Exception):t.transform(raw)
 def test_closed209_loader_accepts_real_new_sources_and_denies_unlisted_import(self):
  sources={n:b'pass\n'for n in loader.MODULES}
  for name in('entry','login','plan','discovery'):sources['tools.installation_binding_plan.'+name]=(ROOT/'tools/installation_binding_plan'/(name+'.py')).read_bytes()
  self.assertEqual(len(loader.compile_sources(sources)),209)
  sources['tools.installation_binding_plan.entry']=b'import unapproved_dynamic_dependency\n'
  with self.assertRaises(Exception):loader.compile_sources(sources)
class OwnerPlan(unittest.TestCase):
 def setUp(self):
  self.payload={'installationId':'fixture','networking':{'backendNetwork':'backend','serviceBindings':{'existing':'owner-2'}},'secrets':{'references':{'mcpClientSecret':'/reference/path'}},'preserved':[1,'è',True]}
  self.projection={'installationId':'fixture','revision':4,'checksum':p.canonical_owner(self.payload),'services':{'bindings':{'existing':'owner-2'}}}
  self.active={k:self.projection[k]for k in('installationId','revision','checksum')}
  self.revision={**self.active,'payload':self.payload,'validationState':'VALIDATED','validationFindings':[]}
 def compile(self):return p.compile_plan(self.active,self.revision,self.active,self.projection,'verified-owner',{'fixture':'binding'})
 def test_only_one_binding_is_added_and_input_all_other_fields_remain_unchanged(self):
  before=copy.deepcopy(self.payload);plan=self.compile();expected=copy.deepcopy(before);expected['networking']['serviceBindings'][p.KEY]='verified-owner'
  self.assertEqual(plan['candidatePayload'],expected);self.assertEqual(self.payload,before)
  self.assertFalse(plan['ownerApplyAuthorized']);self.assertFalse(plan['atomicOwnerActivePreconditionSupportProven']);self.assertFalse(plan['gatewayWritesAllowed'])
 def test_missing_bindings_object_is_added_without_other_changes(self):
  del self.payload['networking']['serviceBindings'];result=p.candidate(self.payload,'verified-owner')
  self.assertEqual(result['networking']['serviceBindings'],{p.KEY:'verified-owner'});self.assertNotIn('serviceBindings',self.payload['networking'])
 def test_active_drift_before_or_after_read_and_payload_tamper_are_denied(self):
  for index in range(3):
   active=copy.deepcopy(self.active);after=copy.deepcopy(self.active);revision=copy.deepcopy(self.revision)
   if index==0:active['revision']+=1
   if index==1:after['revision']+=1
   if index==2:revision['payload']['preserved'][0]=2
   with self.subTest(index=index),self.assertRaises(Exception):p.compile_plan(active,revision,after,self.projection,'verified-owner',{})
 def test_conflicting_binding_invalid_alias_and_lossy_canonical_values_are_denied(self):
  for alias in('ouf-ingestion-runtime','https://owner/','owner:8080','owner/a',''):
   with self.subTest(alias=alias),self.assertRaises(Exception):p.candidate(self.payload,alias)
  self.payload['networking']['serviceBindings'][p.KEY]='previous'
  with self.assertRaises(Exception):p.candidate(self.payload,'verified-owner')
  for value in(1.2,2**64,'\n','😀'):
   with self.subTest(value=value),self.assertRaises(Exception):p.canonical_owner({'value':value})
 def test_invalid_validation_or_projection_bindings_fail_closed(self):
  self.revision['validationState']='REJECTED'
  with self.assertRaises(Exception):self.compile()
  self.revision['validationState']='VALIDATED';self.projection['services']['bindings']={}
  with self.assertRaises(Exception):self.compile()
 def test_reader_only_three_exact_gets_and_no_retry_after_failure(self):
  human=Mock(token_path=Path('/fixture/human-access.jwt'));selection={'origin':'https://fixture.invalid'}
  with patch.object(p,'OwnerTransport')as credentials:
   credentials.return_value.token.return_value='fixture-token'
   reader=p.InstallationReader(selection,human,'fixture',4);reader.opener=MagicMock()
   reply=Mock(status=200);reply.read.return_value=b'{"revision":4}'
   reader.opener.open.return_value.__enter__.return_value=reply
   for _ in range(3):self.assertEqual(reader.get_next(),{'revision':4})
   requests=[c.args[0]for c in reader.opener.open.call_args_list]
   self.assertEqual([r.get_method()for r in requests],['GET']*3)
   self.assertEqual([r.full_url for r in requests],['https://fixture.invalid/api/trusted-human/v1/installations/fixture/'+x for x in('active','revisions/4','active')])
   with self.assertRaises(Exception):reader.get_next()
   self.assertEqual(reader.opener.open.call_count,3)
   reader=p.InstallationReader(selection,human,'fixture',4);reader.opener=MagicMock();reader.opener.open.side_effect=urllib.error.URLError('private-details')
   with self.assertRaisesRegex(ValueError,'INSTALLATION_OWNER_READ_STOP_NO_RETRY'):reader.get_next()
   self.assertEqual(reader.calls,1);self.assertEqual(reader.opener.open.call_count,1)
 def test_plan_entry_contains_no_mutating_owner_or_engine_dispatch(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse((ROOT/'tools/installation_binding_plan/entry.py').read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(x.endswith(('.request','.activate','.create','.ensure','.export','.refresh_if_due','.start_refresh','.issue_action'))for x in calls))

class NativeScopeLogin(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.context=self.root/'installation-ingestion-binding-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.directory=self.root/'old-human';self.directory.mkdir(mode=0o700)
  self.profile={**h.PROFILE,'id':'ouf.chatbot-human-session.finite-test.v2','maximumAttempts':256}
  for obj,key,value in((p,'PARENT',self.root),(h,'PROFILE',self.profile),(m,'PROFILE',self.profile),(h,'LEGACY_SCOPES',t.PREVIOUS),(m,'LEGACY_SCOPES',t.PREVIOUS),(h,'SCOPES',t.REQUESTED),(m,'SCOPES',t.REQUESTED)):
   pa=patch.object(obj,key,value);pa.start();self.addCleanup(pa.stop)
  env={**h.__dict__,'SCOPES':t.REQUESTED,'LEGACY_SCOPES':t.PREVIOUS,'PROFILE':self.profile};exec(compile(FROZEN.read_bytes(),'<actual-frozen-renewal-guard>','exec'),env)
  pa=patch.object(h.HumanSession,'_check_identity_and_budget',env['HumanSession']._check_identity_and_budget);pa.start();self.addCleanup(pa.stop)
  self.wall=time.time();self.mono=time.monotonic();self.elapsed=0
  for key,fn in(('time',lambda:self.wall+self.elapsed),('monotonic',lambda:self.mono+self.elapsed)):
   pa=patch.object(h.time,key,fn);pa.start();self.addCleanup(pa.stop)
  self.selection={'issuer':'https://issuer.fixture.invalid','tenant':'fixture','subject':'human'}
  self.human=h.HumanSession(self.selection,self.directory,self.directory/'human-access.jwt',int(self.wall)-100)
  self.binding={'sessionId':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','selectionHash':p.digest(self.selection),**self.selection,
   'clientId':h.CLIENT,'scopes':t.PREVIOUS,'tokenPath':str(self.human.token_path),'sessionDirectory':str(self.directory),
   'createdAt':self.human.expires_at-7200,'expiresAt':self.human.expires_at,'retryProfile':self.profile}
  review={'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION',
   'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':256,'priorOAuthAttempts':229,
   'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'budgetReset':False}
  decision={'reviewHash':p.digest(review),'approvedAt':self.binding['createdAt'],'expiresAt':self.binding['expiresAt']}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':self.binding,'bootId':self.human._boot(),
   'monotonicDeadline':self.mono-100,'lastObservedAt':self.wall-1,'attempts':236,'state':'READY','budgetReset':False,
   'refreshToken':'DO_NOT_REPLAY_OLD_REFRESH','accessToken':'DO_NOT_REUSE_OLD_ACCESS','governedWindowRenewal':{'review':review,'decision':decision}}
  self.human.journal.initialize(self.row);self.case={'humanBinding':self.binding,'completedMcpPackageHash':'a'*64};self.closure={'declaration':{'moduleCount':209}}
  self.calls=[];self.emits=[]
  def consent(review,*args,**kwargs):
   self.assertTrue(kwargs['login']);now=int(time.time());return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':p.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
  pa=patch.object(m.terminal,'terminal_consent',side_effect=consent);self.consent=pa.start();self.addCleanup(pa.stop)
  pa=patch.object(h.HumanSession,'refresh_if_due',side_effect=AssertionError('NO_OLD_REFRESH'));pa.start();self.addCleanup(pa.stop)
 def provider(self,instance,url,values=None,bearer=None):
  self.calls.append((url,values,bearer));issuer=self.selection['issuer'];base=issuer+'/protocol/openid-connect/'
  if url==issuer+'/.well-known/openid-configuration':return 200,{'issuer':issuer,'device_authorization_endpoint':base+'device','token_endpoint':base+'token','userinfo_endpoint':base+'userinfo'},0
  if url==base+'device':return 200,{'verification_uri':issuer+'/device','user_code':'FIXTURE-CODE','device_code':'FRESH_DEVICE','expires_in':600,'interval':5},0
  if url==base+'token':
   self.assertEqual(values['grant_type'],'urn:ietf:params:oauth:grant-type:device_code')
   claims={'iss':issuer,'sub':self.selection['subject'],'tenant_id':self.selection['tenant'],'ouf_actor_type':'HUMAN','azp':h.CLIENT,'acr':'1','aud':'ouf-api-gateway','scope':' '.join(h.SCOPES),'exp':int(time.time())+600}
   jwt='header.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
   return 200,{'access_token':jwt,'refresh_token':'FRESH_REFRESH_ONLY','token_type':'Bearer'},0
  if url==base+'userinfo':return 200,{'sub':self.selection['subject']},0
  raise AssertionError('UNEXPECTED_PROVIDER_OPERATION')
 def actual_login(self):
  parent=self
  class Stopper:
   def is_set(self):return False
   def wait(self,seconds):parent.elapsed+=seconds
  original=h.HumanSession.login
  return patch.object(h.HumanSession,'login',lambda instance,**kwargs:original(instance,stop=Stopper(),**kwargs))
 def authenticate(self):return m.authenticate(self.selection,self.case,self.context,self.closure,self.emits.append)
 def test_actual_device_login_frozen_guard_retains236_and_opens_new11_scope_session(self):
  with patch.object(h.HumanSession,'_http',lambda instance,*args,**kwargs:self.provider(instance,*args,**kwargs)),self.actual_login():following=self.authenticate()
  self.assertEqual(following._read()['attempts'],240);self.assertEqual(len(self.calls),4);self.assertEqual(following.current()['scopes'],t.REQUESTED)
  self.assertEqual(self.human._read(),self.row);following._check_identity_and_budget(following._read())
  self.assertNotIn('DO_NOT_',str(self.calls));self.assertNotIn('FRESH_REFRESH_ONLY','\n'.join(self.emits));self.assertFalse((self.context/'authority.json').exists())
 def test_declined_consent_no_provider_or_successor(self):
  self.consent.side_effect=ValueError('DECLINED')
  with self.assertRaises(Exception):self.authenticate()
  self.assertEqual(self.calls,[]);self.assertFalse((self.directory/'successor-window.claim.json').exists());self.assertEqual(self.human._read(),self.row)
 def test_bad_history_exhaustion_and_scope_drift_denied_before_consent(self):
  for changes in({'attempts':256},{'attempts':235},{'state':'BLOCKED'},{'budgetReset':True},{'binding':{}}):
   with self.subTest(changes=changes),self.assertRaises(Exception):m.qualify(self.human,{**self.row,**changes},self.case,self.closure)
  self.consent.assert_not_called()
 def test_counter_drift_during_consent_denies_without_successor(self):
  original=self.consent.side_effect
  def consent(*args,**kwargs):
   decision=original(*args,**kwargs);path=self.directory/'recovery.json';path.write_bytes(p.encoded({**self.row,'attempts':237}));return decision
  self.consent.side_effect=consent
  with self.assertRaises(Exception):self.authenticate()
  self.assertEqual(self.calls,[]);self.assertFalse((self.directory/'successor-window.claim.json').exists())
 def test_provider_denial_keeps_cumulative238_and_blocks_replay(self):
  def provider(instance,url,values=None,bearer=None):
   if url.endswith('/device'):return 400,{'error':'unauthorized_client'},0
   return self.provider(instance,url,values,bearer)
  with patch.object(h.HumanSession,'_http',provider),self.actual_login(),self.assertRaises(h.HumanSessionPaused):self.authenticate()
  claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());row=json.loads((Path(claim['destination'])/'recovery.json').read_bytes())
  self.assertEqual(row['attempts'],238);self.assertEqual(row['state'],'BLOCKED')
  with self.assertRaises(Exception):self.authenticate()
  self.assertFalse((self.context/'authority.json').exists())
 def test_guard_rejects_widened_budget_or_unbound_successor_receipt(self):
  review=m.qualify(self.human,self.row,self.case,self.closure)
  self.assertEqual(review['maximumRemainingOAuthAttempts'],20);self.assertFalse(review['followup']['ownerMutationAllowed'])
  for change in('receipt','attempts','boot'):
   row=copy.deepcopy(self.row)
   if change=='receipt':row.pop('governedWindowRenewal')
   if change=='attempts':row['attempts']=257
   if change=='boot':row['bootId']='other'
   with self.subTest(change=change),self.assertRaises(Exception):self.human._check_identity_and_budget(row)
if __name__=='__main__':unittest.main()

class PreparedCapsule(unittest.TestCase):
 def setUp(self):
  from tools.mcp_read_transport_gateway82_continuation import runtime as old_loader
  import test_mcp_ingestion503_topology_read as prior
  spec=importlib.util.spec_from_file_location('installation_preparer',ROOT/'scripts/prepare-installation-ingestion-binding-plan.py');self.prep=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.prep)
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.completed=self.root/'completed205';self.completed.mkdir(mode=0o700);human=self.root/'actual-new-human';human.mkdir(mode=0o700)
  self.binding={'sessionDirectory':str(human),'scopes':t.PREVIOUS,'expiresAt':int(time.time())+100}
  self.row={'binding':self.binding,'attempts':236,'state':'READY','budgetReset':False,'lastObservedAt':time.time()-1}
  self.write(human/'recovery.json',self.row)
  data,routes=prior.CompletedHistory().records();self.data=data
  plan=data['execution-plan.json'];plan['humanBinding']=self.binding
  data['case.json']['humanBinding']={'sessionDirectory':'/DO_NOT_USE_OLD_CASE'}
  data['case.json']['preparationClaimBinding']['path']=str(self.completed/'preparation-fence.json')
  data['preparation-fence.json']['context']=str(self.completed)
  data['case.json']['preparationClaimBinding']['sha256']=self.prep.digest(data['preparation-fence.json'])
  data['update-result.json']['contextPath']=str(self.completed)
  sources={n:b'pass\n'for n in old_loader.MODULES};sources['tools.chatbot_file_cohort.human_session']=full_fixture()
  data['sources.json']={n:base64.b64encode(raw).decode()for n,raw in sources.items()}
  package=data['package.json'];package['closure']['declaration']['sourceHashes']={n:self.prep.sha(raw)for n,raw in sources.items()}
  package['closure'].update(executables={},stdlibHash='b'*64,stdlibFileCount=0)
  package['sourcePins']={'ouf-deploy':package['sourceCommit'],'ouf-onboarding':'c'*40,'ouf-mcp-server':'d'*40}
  scope={'planHash':self.prep.digest(plan)};data['review.json']['scopes']['mcpReadTransportUpdate']=scope;data['review.json']['sourceClosureHash']=self.prep.digest(package['closure'])
  data['decision.json']['reviewHash']=self.prep.digest(data['review.json']);journal=data['recovery.json'];journal['scopeHash']=self.prep.digest(scope)
  for effect in journal['effects']:effect['intentHash']=self.prep.digest({'planHash':self.prep.digest(plan),'stage':effect['stage']})
  package['fileHashes']={n:self.prep.digest(data[n])for n in('case.json','sources.json')};package['fileHashes']['reader.py']=self.prep.sha(b'raise RuntimeError("NO_COMPLETED_MAIN")\n')
  data['runtime.claim.json']['packageHash']=self.prep.digest(package)
  for name,value in data.items():self.write(self.completed/name,value)
  (self.completed/'reader.py').write_bytes(b'raise RuntimeError("NO_COMPLETED_MAIN")\n');(self.completed/'reader.py').chmod(0o600)
  self.delivery={n:(ROOT/'tools/installation_binding_plan'/(n+'.py')).read_bytes()for n in('entry','login','plan','discovery','runtime')}
  self.delivery.update(prepare=(ROOT/'scripts/prepare-installation-ingestion-binding-plan.py').read_bytes(),bootstrap=(ROOT/'scripts/execute-installation-ingestion-binding-plan.py').read_bytes(),transform=(ROOT/'scripts/installation-binding-scope-constants.py').read_bytes())
  text=self.delivery['discovery'].decode().replace("CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-srz6__wf')",'CONTEXT=Path('+repr(str(self.completed))+')')
  text=text.replace("ROUTES='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'",'ROUTES='+repr(routes)).replace("PACKAGE='d5e2be3a877c33c082d52fb0180a7a4a8cc10c9f4385c4064713417b366c4d38'",'PACKAGE='+repr(self.prep.digest(package)))
  self.delivery['discovery']=text.encode()
  pa=patch.object(self.prep.os,'execv',side_effect=RuntimeError('EXEC_REACHED'));self.execv=pa.start();self.addCleanup(pa.stop)
 def write(self,path,value):path.write_bytes(self.prep.encoded(value));path.chmod(0o600)
 def test_preparation_uses_plan_actual_human_preserves_completed_bytes_and_claims_once(self):
  before={path:path.read_bytes()for path in self.completed.iterdir()}
  with self.assertRaisesRegex(RuntimeError,'EXEC_REACHED'):self.prep.main(self.delivery,'e'*40)
  self.assertTrue(all(path.read_bytes()==raw for path,raw in before.items()))
  claims=list(self.root.glob('installation-ingestion-binding-plan-*.claim.json'));self.assertEqual(len(claims),1)
  context=Path(json.loads(claims[0].read_bytes())['context']);case=json.loads((context/'case.json').read_bytes())
  self.assertEqual(case['humanBinding'],self.binding);self.assertEqual(case['priorOAuthAttempts'],236)
  self.assertEqual(json.loads((context/'preparation-result.json').read_bytes())['sourceModuleCount'],209)
  self.assertFalse((context/'authority.json').exists());self.assertFalse((context/'login-review.json').exists())
  self.execv.reset_mock()
  with self.assertRaisesRegex(ValueError,'ALREADY_PREPARED'):self.prep.main(self.delivery,'e'*40)
  self.execv.assert_not_called()
 def test_bad_counter_or_incomplete_completed_history_denies_without_claim(self):
  self.write(Path(self.binding['sessionDirectory'])/'recovery.json',{**self.row,'attempts':256})
  with self.assertRaises(Exception):self.prep.main(self.delivery,'e'*40)
  self.assertEqual(list(self.root.glob('installation-ingestion-binding-plan-*')),[]);self.execv.assert_not_called()
 def test_no_preparer_owner_oauth_container_or_historical_main_dispatch(self):
  tree=ast.parse(self.delivery['prepare']);calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(x.endswith(('.request','.login','.refresh_if_due','.authenticate','.main','.archive','.ensure'))for x in calls))
