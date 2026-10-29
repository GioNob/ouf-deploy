"""Real HUMAN login state machine, private publisher and cumulative CAS journals."""
import base64,copy,hashlib,importlib.util,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.mcp_read_transport_reauthentication import login as m,entry as e,authority as a
from tools.chatbot_file_cohort import human_session as h
from tools.semantic_lease_recovery.recovery_journal import Journal
PREP=ROOT/'scripts/prepare-mcp-ingestion-read-transport-reauthentication.py'
spec=importlib.util.spec_from_file_location('reauth_private_read',PREP);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Reauthentication(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.context=self.root/'mcp-ingestion-read-transport-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.stopped=self.root/'stopped';self.stopped.mkdir(mode=0o700)
  self.directory=self.root/'old-human';self.directory.mkdir(mode=0o700)
  profile={**h.PROFILE,'id':'ouf.chatbot-human-session.finite-test.v2','maximumAttempts':256}
  scopes=['openid','authorization.policy.admin','mcp.connect','authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read','udp.materialization.retry']
  for target,name,value in((m,'STOPPED',self.stopped),(a.evidence,'PARENT',self.root),
   (h,'PROFILE',profile),(m,'PROFILE',profile),(h,'SCOPES',scopes),(m,'SCOPES',scopes)):
   pa=patch.object(target,name,value);pa.start();self.addCleanup(pa.stop)
  self.wall=time.time();self.mono=time.monotonic();self.elapsed=0
  for name,fn in(('time',lambda:self.wall+self.elapsed),('monotonic',lambda:self.mono+self.elapsed)):
   pa=patch.object(h.time,name,fn);pa.start();self.addCleanup(pa.stop)
  self.selection={'issuer':'https://issuer.fixture.invalid','tenant':'fixture','subject':'human'}
  self.human=h.HumanSession(self.selection,self.directory,self.directory/'human-access.jwt',int(self.wall)+200)
  self.binding={'sessionId':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','selectionHash':m.digest(self.selection),**self.selection,
   'clientId':h.CLIENT,'scopes':scopes,'tokenPath':str(self.human.token_path),'sessionDirectory':str(self.directory),
   'createdAt':int(self.wall)+200-7200,'expiresAt':self.human.expires_at,'retryProfile':profile}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':self.binding,'bootId':self.human._boot(),
   'monotonicDeadline':self.mono+200,'lastObservedAt':self.wall-5,'attempts':217,'state':'BLOCKED','operation':'REFRESH',
   'reason':'HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN','budgetReset':False,
   'refreshToken':'DO_NOT_REPLAY_OLD_REFRESH','accessToken':'DO_NOT_REUSE_OLD_ACCESS'}
  self.human.journal.initialize(self.row)
  self.old_case={'originalBinding':{'path':'/fixture/original','sha256':'a'*64},'humanBinding':self.binding,
   'installedPlanBinding':{'path':'/fixture/plan','sha256':'b'*64},'installedJournalBinding':{'path':'/fixture/history','sha256':'c'*64},
   'imageBinding':{'path':'/fixture/image','sha256':'d'*64}}
  self.write(self.stopped/'case.json',self.old_case)
  self.package={'fileHashes':{'case.json':m.digest(self.old_case)}}
  self.write(self.stopped/'package.json',self.package);package_hash=m.digest(self.package)
  pa=patch.object(m,'PACKAGE',package_hash);pa.start();self.addCleanup(pa.stop)
  self.write(self.stopped/'runtime.claim.json',{'packageHash':package_hash,'automaticReplayAllowed':False})
  self.case={**self.old_case,'reauthentication':{'schema':'ouf.mcp-read-transport-blocked217-reauthentication.v1',
   'stoppedContext':str(self.stopped),'stoppedPackageHash':package_hash,'priorOAuthAttempts':217,
   'maximumCumulativeOAuthAttempts':256,'newWindowSeconds':7200,'newLoginRequiresNativeConsent':True,
   'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,'automaticRenewalAllowed':False,'budgetReset':False}}
  self.closure={'declaration':{'moduleCount':188}}
  self.calls=[];self.emits=[]
  pa=patch.object(a,'current_authorities',return_value=({},{}));pa.start();self.addCleanup(pa.stop)
  def consent(review,*args,**kwargs):
   self.assertTrue(kwargs['login']);now=int(time.time())
   return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':m.digest(review),
    'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
  pa=patch.object(m.terminal,'terminal_consent',side_effect=consent);self.consent=pa.start();self.addCleanup(pa.stop)
  pa=patch.object(h.HumanSession,'refresh_if_due',side_effect=AssertionError('OLD_REFRESH_MUST_NEVER_RUN'));pa.start();self.addCleanup(pa.stop)
 def write(self,path,value):path.write_bytes(m.encoded(value));path.chmod(0o600)
 def provider(self,instance,url,values=None,bearer=None):
  self.calls.append((url,values,bearer));issuer=self.selection['issuer'];base=issuer+'/protocol/openid-connect/'
  if url==issuer+'/.well-known/openid-configuration':return 200,{'issuer':issuer,'device_authorization_endpoint':base+'device','token_endpoint':base+'token','userinfo_endpoint':base+'userinfo'},0
  if url==base+'device':return 200,{'verification_uri':issuer+'/device','user_code':'FIXTURE-CODE','device_code':'FRESH_DEVICE','expires_in':600,'interval':5},0
  if url==base+'token':
   self.assertEqual(values['grant_type'],'urn:ietf:params:oauth:grant-type:device_code');self.assertEqual(values['device_code'],'FRESH_DEVICE')
   claims={'iss':issuer,'sub':self.selection['subject'],'tenant_id':self.selection['tenant'],'ouf_actor_type':'HUMAN',
    'azp':h.CLIENT,'acr':'1','aud':'ouf-api-gateway','scope':' '.join(h.SCOPES),'exp':int(time.time())+600}
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
  def login(instance,**kwargs):return original(instance,stop=Stopper(),**kwargs)
  return patch.object(h.HumanSession,'login',login)
 def authenticate(self):return m.authenticate(self.selection,self.case,self.context,self.closure,p.parsed,self.emits.append)
 def test_actual_device_login_verification_bearer_publication_and_counter_start_at217(self):
  def http(instance,*args,**kwargs):return self.provider(instance,*args,**kwargs)
  with patch.object(h.HumanSession,'_http',http),self.actual_login():following=self.authenticate()
  self.assertEqual(len(self.calls),4);self.assertEqual(following._read()['attempts'],221)
  self.assertEqual(following._read()['state'],'READY');self.assertTrue(following.token_path.exists())
  self.assertEqual(self.human._read(),self.row);self.assertTrue((self.directory/'successor-window.claim.json').exists())
  self.assertEqual(following.expires_at-following.current()['createdAt'],7200)
  self.assertNotIn('DO_NOT_',str(self.calls));self.assertNotIn('FRESH_REFRESH_ONLY','\n'.join(self.emits))
  self.assertFalse((self.context/'authority.json').exists());self.assertFalse((self.context/'execution-plan.json').exists())
 def test_no_consent_no_successor_or_provider_requests(self):
  self.consent.side_effect=ValueError('CONSENT_DECLINED')
  with self.assertRaises(Exception):self.authenticate()
  self.assertFalse((self.directory/'successor-window.claim.json').exists());self.assertEqual(self.calls,[])
  self.assertEqual(self.human._read(),self.row)
 def test_changed_old_counter_binding_reason_or_preexisting_successor_fail_before_consent(self):
  for changes in({'attempts':218},{'binding':{}},{'reason':'other'},{'state':'READY'}):
   with self.subTest(changes=changes),self.assertRaises(Exception):m.qualify(self.human,{**self.row,**changes},self.case,self.closure)
  (self.directory/'successor-window.claim.json').write_text('consumed')
  with self.assertRaises(Exception):m.qualify(self.human,self.row,self.case,self.closure)
  self.consent.assert_not_called()
 def test_widened_window_budget_or_followup_source_is_not_admitted(self):
  for key,value in(('newWindowSeconds',14400),('maximumCumulativeOAuthAttempts',384),('failedRefreshReplayAllowed',True)):
   case=copy.deepcopy(self.case);case['reauthentication'][key]=value
   with self.subTest(key=key),self.assertRaises(Exception):m.predecessor(case,self.closure,p.parsed)
  case=copy.deepcopy(self.case);case['imageBinding']['sha256']='e'*64
  with self.assertRaises(Exception):m.predecessor(case,self.closure,p.parsed)
 def test_old_action_with_later_effect_or_authority_is_denied(self):
  (self.stopped/'authority.json').write_text('later')
  with self.assertRaises(Exception):self.authenticate()
  self.consent.assert_not_called();self.assertEqual(self.calls,[])
 def test_predecessor_drift_after_consent_does_not_create_successor(self):
  original=self.consent.side_effect
  def consent(*args,**kwargs):
   decision=original(*args,**kwargs);self.write(self.directory/'recovery.json',{**self.row,'attempts':218});return decision
  self.consent.side_effect=consent
  with self.assertRaises(Exception):self.authenticate()
  self.assertFalse((self.directory/'successor-window.claim.json').exists());self.assertEqual(self.calls,[])
 def test_provider_denial_preserves_old_journal_and_new_attempts_without_grant_or_runtime_authority(self):
  def http(instance,url,values=None,bearer=None):
   if url.endswith('/device'):return 400,{'error':'unauthorized_client'},0
   return self.provider(instance,url,values,bearer)
  with patch.object(h.HumanSession,'_http',http),self.actual_login(),self.assertRaises(h.HumanSessionPaused):self.authenticate()
  claim=p.parsed(self.directory/'successor-window.claim.json');new=p.parsed(Path(claim['destination'])/'recovery.json')
  self.assertEqual(new['attempts'],219);self.assertEqual(new['state'],'BLOCKED');self.assertEqual(self.human._read(),self.row)
  self.assertFalse((self.context/'authority.json').exists())
 def test_second_authentication_never_replays_consumed_login_successor(self):
  def http(instance,*args,**kwargs):return self.provider(instance,*args,**kwargs)
  with patch.object(h.HumanSession,'_http',http),self.actual_login():self.authenticate()
  count=len(self.calls)
  with self.assertRaises(Exception):self.authenticate()
  self.assertEqual(len(self.calls),count)
if __name__=='__main__':unittest.main()

class SealedProfile(unittest.TestCase):
 def test_new_loader_retains_all185_modules_and_adds_only_three_reauth_modules(self):
  from tools.mcp_read_transport_reauthentication import runtime as loader
  from tools.ingestion_read_transport_update import runtime as previous
  self.assertEqual(len(loader.MODULES),188);self.assertEqual(len(previous.MODULES),185)
  self.assertTrue(previous.MODULES<loader.MODULES)
  self.assertEqual(loader.MODULES-previous.MODULES,{'tools.mcp_read_transport_reauthentication.'+n for n in('entry','authority','login')})
  sources={n:b'pass\n'for n in loader.MODULES}
  for n in('entry','authority','login'):sources['tools.mcp_read_transport_reauthentication.'+n]=(ROOT/'tools/mcp_read_transport_reauthentication'/(n+'.py')).read_bytes()
  pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40};execution={'executorSha256':'d'*64,'caseSha256':'e'*64,'mode':'MCP_READ_TRANSPORT_UPDATE'}
  declaration=loader.declaration('a'*40,sources,(ROOT/'tools/mcp_read_transport_reauthentication/runtime.py').read_bytes(),pins,execution)
  self.assertEqual(declaration['entryModule'],'tools.mcp_read_transport_reauthentication.entry')
 def test_preparer_and_login_do_not_call_old_main_or_refresh(self):
  import ast
  paths=(PREP,ROOT/'tools/mcp_read_transport_reauthentication/login.py')
  for path in paths:
   calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(path.read_bytes()))if isinstance(n,ast.Call)]
   self.assertFalse(any(v.endswith(('.refresh_if_due','.main','.authenticate','.ensure','.backup','.migrate'))for v in calls))

class RealReauthenticationAuthority(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  import test_mcp_ingestion_read_transport_update as core
  core.CryptoAndJournal.setUpClass()
 def setUp(self):
  import test_mcp_ingestion_read_transport_update as core
  self.prior=core.CryptoAndJournal();self.prior.setUp();self.addCleanup(self.prior.doCleanups)
  self.closure=copy.deepcopy(self.prior.closure);self.closure['declaration']['entryModule']='tools.mcp_read_transport_reauthentication.entry'
  self.closure['declaration']['moduleCount']=188
  self.review=a.compile_action_review('MCP_READ_TRANSPORT_UPDATE',self.closure,self.prior.scopes,self.prior.hb,
   self.prior.context,{'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':self.prior.plan['logicalUpdateRef']},480)
  self.prior.c.write(self.prior.context/'review.json',a.encoded(self.review))
 def decision(self):
  self.prior.review=self.review;return self.prior.decision()
 def test_real_two_role_signatures_for_new_entry_preserve_exact_mcp_only_scope(self):
  action=a.issue_action(self.review,self.decision(),self.prior.human)
  self.assertTrue(action.guard('mcpReadTransportUpdate',self.prior.scopes['mcpReadTransportUpdate']))
  self.assertEqual(len(list(self.prior.context.glob('*.DEPLOYMENT_INTENT.json'))),1)
  self.assertEqual(len(list(self.prior.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  self.assertFalse((self.prior.c.root/'UNREAD-ATTESTOR.pem').exists())
 def test_login_scope_or_wrong_entry_cannot_become_runtime_authority(self):
  with self.assertRaises(Exception):a.compile_action_review('MCP_READ_TRANSPORT_UPDATE',self.closure,
   {**self.prior.scopes,'reauthentication':{'allowed':True}},self.prior.hb,self.prior.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
  closure=copy.deepcopy(self.closure);closure['declaration']['entryModule']='tools.ingestion_read_transport_update.entry'
  with self.assertRaises(Exception):a.closure_valid(closure)
