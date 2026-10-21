import ast,base64,contextlib,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=HERE/'fixtures'
if not(ROOT/'human_source.py').exists():ROOT=HERE.parent/'tests/fixtures/installation-route-budget264'
PACKAGE=HERE
if not(PACKAGE/'login.py').exists():PACKAGE=HERE.parent/'tools/installation_route_reconcile'

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def selected(path,names,env=None):
 tree=ast.parse(path.read_bytes());nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
 ns={'os':os,'stat':stat,'Path':Path,'contextmanager':contextlib.contextmanager,'Permanent':RuntimeError,**(env or{})}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns);return types.SimpleNamespace(**ns)

def register(name,obj=None):
 if obj is None:obj=types.ModuleType(name);obj.__path__=[]
 sys.modules[name]=obj;return obj
for name in('tools','tools.chatbot_file_cohort','tools.semantic_lease_recovery','tools.semantic_policy_token_owner','tools.installation_route_reconcile'):register(name)
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
register('tools.chatbot_file_cohort.plan',types.SimpleNamespace(require=require,digest=digest))
journal=load('tools.semantic_lease_recovery.recovery_journal',ROOT/'journal_source.py')
# No privileged aggregate action is requested in these login tests.
register('tools.semantic_policy_token_owner.owner_installation',types.SimpleNamespace(AggregateAction=type('UnusedAggregateAction',(),{})))
producer=selected(ROOT/'producer_source.py',{'check','identity','protected_directory'})
register('tools.semantic_policy_token_owner.producer',producer)
binding=selected(ROOT/'binding_source.py',{'CandidateDenied','require','identity','read_member'})
publisher=selected(ROOT/'publish_source.py',{'publish'},{'binding':binding})
register('iam_owner_action',publisher)
h=load('tools.chatbot_file_cohort.human_session',ROOT/'human_source.py')
h.LEGACY_SCOPES=list(h.SCOPES)+['udp.materialization.retry'];h.SCOPES=h.LEGACY_SCOPES+['installation.configuration.read','installation.configuration.write','installation.configuration.activate','installation.configuration.export']
h.PROFILE={**h.PROFILE,'id':'ouf.chatbot-human-session.finite-test.v2','maximumAttempts':256}
frozen=ROOT/'frozen_guard_fixture.py'
env={**h.__dict__};exec(compile(frozen.read_bytes(),str(frozen),'exec'),env);h.HumanSession._check_identity_and_budget=env['HumanSession']._check_identity_and_budget
register('tools.chatbot_file_cohort.review',types.SimpleNamespace(terminal_line=lambda *_:None,terminal_answer=lambda *_:None))
register('tools.installation_route_reconcile.owner',types.SimpleNamespace(require=require,encoded=encoded,digest=digest))
LEGACY_PROFILE=copy.deepcopy(h.PROFILE)
exec(compile((PACKAGE/'human_extension.py').read_bytes(),'<sealed-budget264-extension>','exec'),h.__dict__)
l=load('qualified_login',PACKAGE/'login.py')

class Budget(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.directory=self.root/'predecessor';self.directory.mkdir(mode=0o700);self.context=self.root/'context';self.context.mkdir(mode=0o700)
  if not Path('/proc/sys/kernel/random/boot_id').exists():
   p=patch.object(h.HumanSession,'_boot',return_value='fixture-boot');p.start();self.addCleanup(p.stop)
  self.wall=1792430000.;self.mono=time.monotonic();self.elapsed=0
  for key,fn in(('time',lambda:self.wall+self.elapsed),('monotonic',lambda:self.mono+self.elapsed)):
   p=patch.object(h.time,key,fn);p.start();self.addCleanup(p.stop)
  self.selection={'issuer':'https://issuer.fixture.invalid','subject':'human','tenant':'fixture'};expiry=1792436155
  self.human=h.HumanSession(self.selection,self.directory,self.directory/'human-access.jwt',expiry)
  b={'sessionId':'fixture','selectionHash':digest(self.selection),**self.selection,'clientId':h.CLIENT,'scopes':list(h.SCOPES),'tokenPath':str(self.human.token_path),
   'sessionDirectory':str(self.directory),'createdAt':expiry-7200,'expiresAt':expiry,'retryProfile':copy.deepcopy(LEGACY_PROFILE)}
  review={'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION','predecessorMaximumCumulativeOAuthAttempts':256,
   'priorOAuthAttempts':251,'maximumCumulativeOAuthAttempts':256,'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'budgetReset':False}
  decision={'reviewHash':digest(review),'approvedAt':b['createdAt'],'expiresAt':expiry}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':b,'bootId':self.human._boot(),'monotonicDeadline':self.mono+5000,'lastObservedAt':self.wall-1,
   'attempts':255,'state':'READY','budgetReset':False,'accessExpiresAt':self.wall-1,'refreshToken':'NEVER_REPLAY_REFRESH','accessToken':'NEVER_REUSE_ACCESS',
   'governedWindowRenewal':{'review':review,'decision':decision}}
  self.human.journal.initialize(self.row);self.calls=[];self.ack=0;self.emits=[];self.case={'humanBinding':b,'predecessorLogicalRef':'a'*64};self.pending=0;self.deny=False
  for obj,key,value in((l,'ORIGINAL_REVIEW',digest(review)),(l,'PROFILE',h.PROFILE),(l,'SCOPES',h.SCOPES)):
   p=patch.object(obj,key,value);p.start();self.addCleanup(p.stop)
  p=patch.object(h.HumanSession,'refresh_if_due',side_effect=AssertionError('NO_OLD_REFRESH'));p.start();self.addCleanup(p.stop)
  p=patch.object(l,'terminal_phrase',side_effect=self.phrase);self.prompt=p.start();self.addCleanup(p.stop)
 def phrase(self,summary,phrase):
  if phrase.startswith('APPROVO BUDGET264 '):self.assertIn('256 a264',summary)
  elif phrase.startswith('LOGIN COMPLETATO '):
   self.ack+=1;claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());d=Path(claim['destination']);following=h.HumanSession(self.selection,d,d/'human-access.jwt',1792436155)
   with following.journal.invocation():self.assertEqual(following._read()['attempts'],257)
   self.assertFalse(any(url.endswith('/token')for url,_,_ in self.calls))
  else:raise AssertionError('UNEXPECTED_TERMINAL_PHRASE')
 def provider(self,instance,url,values=None,bearer=None):
  self.calls.append((url,values,bearer));base=self.selection['issuer']+'/protocol/openid-connect/'
  if url.endswith('/.well-known/openid-configuration'):return 200,{'issuer':self.selection['issuer'],'device_authorization_endpoint':base+'device','token_endpoint':base+'token','userinfo_endpoint':base+'userinfo'},0
  if url==base+'device':
   if self.deny:return 400,{'error':'unauthorized_client'},0
   return 200,{'verification_uri':self.selection['issuer']+'/device','user_code':'SAFE-CODE','device_code':'NEW_DEVICE','expires_in':600,'interval':5},0
  if url==base+'token':
   self.assertEqual(values['grant_type'],'urn:ietf:params:oauth:grant-type:device_code')
   if self.pending:self.pending-=1;return 400,{'error':'authorization_pending'},0
   claims={'iss':self.selection['issuer'],'sub':'human','tenant_id':'fixture','ouf_actor_type':'HUMAN','azp':h.CLIENT,'acr':'1','aud':'ouf-api-gateway','scope':' '.join(h.SCOPES),'exp':int(time.time())+600}
   token='header.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
   return 200,{'access_token':token,'refresh_token':'NEW_REFRESH','token_type':'Bearer'},0
  if url==base+'userinfo':return 200,{'sub':'human'},0
  raise AssertionError('UNEXPECTED_PROVIDER')
 def publish(self,context,name,value):
  path=Path(context)/name;fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  try:os.write(fd,encoded(value));os.fsync(fd)
  finally:os.close(fd)
 def run_flow(self):
  parent=self
  class Stopper:
   def is_set(self):return False
   def wait(self,seconds):parent.elapsed+=seconds
  original=h.HumanSession.login
  with patch.object(h.HumanSession,'_http',lambda instance,*args,**kwargs:self.provider(instance,*args,**kwargs)),patch.object(h.HumanSession,'login',lambda instance,**kw:original(instance,stop=Stopper(),**kw)):
   return l.authenticate(self.selection,self.row['binding'],self.context,{'declaration':{'moduleCount':226}},self.publish,self.emits.append,self.case)
 def test_actual_fresh_device_flow255_to259_preserves_wall_and_monotonic_deadlines_and_parent(self):
  following=self.run_flow();row=following._read();self.assertEqual(row['attempts'],259);self.assertEqual(len(self.calls),4);self.assertEqual(self.ack,1)
  self.assertEqual(row['binding']['expiresAt'],self.row['binding']['expiresAt']);self.assertEqual(row['monotonicDeadline'],self.row['monotonicDeadline'])
  self.assertEqual(row['binding']['retryProfile']['maximumAttempts'],264);self.assertEqual(self.human._read(),self.row)
  self.assertNotIn('NEVER_',str(self.calls));self.assertFalse((self.context/'authority.json').exists())
  with self.assertRaises(Exception):self.run_flow()
 def test_declined_budget_consent_has_no_request_or_successor(self):
  self.prompt.side_effect=ValueError('DECLINED')
  with self.assertRaises(Exception):self.run_flow()
  self.assertEqual(self.calls,[]);self.assertFalse((self.directory/'successor-window.claim.json').exists());self.assertEqual(self.human._read(),self.row)
 def test_legacy256_session_cannot_spend_last_request_through_new_profile(self):
  self.human._check_identity_and_budget(self.row)
  with self.assertRaises(Exception):self.human._request(self.row,'REFRESH','https://issuer.fixture.invalid/token')
  self.assertEqual(self.human._read(),self.row);self.assertEqual(self.calls,[])
 def test_pending_consumes_same_cumulative_budget_without_extending_deadlines(self):
  self.pending=2;following=self.run_flow();self.assertEqual(following._read()['attempts'],261);self.assertEqual(following.expires_at,1792436155)
 def test_exhaustion_stops_at264_without_runtime_authority_or_reset(self):
  self.pending=20
  with self.assertRaises(Exception):self.run_flow()
  claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());row=json.loads((Path(claim['destination'])/'recovery.json').read_bytes());self.assertEqual(row['attempts'],264);self.assertFalse((self.context/'authority.json').exists())
 def test_provider_denial_retains257_and_no_credential_replay(self):
  self.deny=True
  with self.assertRaises(h.HumanSessionPaused):self.run_flow()
  claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());row=json.loads((Path(claim['destination'])/'recovery.json').read_bytes());self.assertEqual(row['attempts'],257);self.assertEqual(row['state'],'BLOCKED')
 def test_v5_guard_rejects_reset_expiry_counter_and_consent_drift(self):
  following=self.run_flow();row=following._read()
  for key,value in(('attempts',265),('attempts',0),('budgetReset',True),('bootId','changed')):
   changed=copy.deepcopy(row);changed[key]=value
   with self.subTest(key=key),self.assertRaises(Exception):following._check_identity_and_budget(changed)
  changed=copy.deepcopy(row);changed['governedWindowRenewal']['decision']['decision']='NOT_APPROVED'
  with self.assertRaises(Exception):following._check_identity_and_budget(changed)
 def test_expired_or_too_short_window_stops_before_consent_and_requests(self):
  self.elapsed=6000
  with self.assertRaises(Exception):self.run_flow()
  self.assertEqual(self.calls,[]);self.prompt.assert_not_called()
if __name__=='__main__':unittest.main()
