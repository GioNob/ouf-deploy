"""Real frozen device state machine with mocked issuer replies, not mocked token accounting."""
import base64,copy,importlib.util,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
OLD=ROOT/'installation_route_reconcile/test_budget.py'
if not OLD.exists():OLD=ROOT/'tests/test_installation_route_budget264.py'
spec=importlib.util.spec_from_file_location('retained_budget264_fixture',OLD);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
h=old.h
PKG=HERE
if not(PKG/'human_extension.py').exists():PKG=ROOT/'tools/ingestion_read_owner_reference'
RETAINED_PROFILE=copy.deepcopy(h.PROFILE)
exec(compile((PKG/'human_extension.py').read_bytes(),'<explicit-budget272-v6>','exec'),h.__dict__)
old.register('tools.ingestion_read_owner_reference')
old.register('tools.ingestion_read_owner_reference.owner',types.SimpleNamespace(require=old.require,encoded=old.encoded,digest=old.digest))
l=old.load('qualified_owner_reference_login',PKG/'login.py')
class Budget(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.directory=self.root/'expired-predecessor';self.directory.mkdir(mode=0o700);self.context=self.root/'context';self.context.mkdir(mode=0o700)
  if not Path('/proc/sys/kernel/random/boot_id').exists():
   p=patch.object(h.HumanSession,'_boot',return_value='fixture-boot');p.start();self.addCleanup(p.stop)
  self.wall=1792437000.;self.mono=time.monotonic();self.elapsed=0
  for key,fn in(('time',lambda:self.wall+self.elapsed),('monotonic',lambda:self.mono+self.elapsed)):
   p=patch.object(h.time,key,fn);p.start();self.addCleanup(p.stop)
  self.selection={'issuer':'https://issuer.fixture.invalid','subject':'human','tenant':'fixture'};expiry=1792436155
  self.human=h.HumanSession(self.selection,self.directory,self.directory/'human-access.jwt',expiry)
  b={'sessionId':'fixture','selectionHash':old.digest(self.selection),**self.selection,'clientId':h.CLIENT,'scopes':list(h.SCOPES),
   'tokenPath':str(self.human.token_path),'sessionDirectory':str(self.directory),'createdAt':expiry-1000,'expiresAt':expiry,'retryProfile':copy.deepcopy(RETAINED_PROFILE)}
  review={'schema':'ouf.human-installation-route-budget-review.v5','purpose':'CONFIGURATION_AND_VALIDATION','predecessorMaximumCumulativeOAuthAttempts':256,
   'priorOAuthAttempts':255,'maximumCumulativeOAuthAttempts':264,'requestedScopes':h.SCOPES,'preservedWindowExpiresAt':expiry,'budgetReset':False,
   'oldCredentialsReusable':False,'automaticRenewalAllowed':False,'freshIssuerAuthenticationRequired':True,'remainingBudgetInsufficientForVerifiedRefresh':True}
  decision={'schema':'ouf.human-installation-route-budget-decision.v5','reviewHash':old.digest(review),'approvedAt':b['createdAt'],'expiresAt':expiry,
   'decision':'APPROVE_EXACT264_BUDGET_WITH_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':b,'bootId':self.human._boot(),'monotonicDeadline':self.mono-845,
   'lastObservedAt':expiry-1,'attempts':259,'state':'READY','budgetReset':False,'accessExpiresAt':expiry-1000,
   'refreshToken':'NEVER_REPLAY_REFRESH','accessToken':'NEVER_REUSE_ACCESS','publishedAccessToken':'NEVER_REUSE_PUBLISHED',
   'governedWindowRenewal':{'review':review,'decision':decision}}
  self.human.journal.initialize(self.row);self.calls=[];self.ack=0;self.emits=[];self.case={'humanBinding':b,'logicalRef':'a'*64};self.pending=0;self.deny=False
  p=patch.object(l,'terminal_phrase',side_effect=self.phrase);self.prompt=p.start();self.addCleanup(p.stop)
 def phrase(self,summary,phrase):
  if phrase.startswith('APPROVO BUDGET272 '):self.assertIn('NUOVA finestra7200',summary)
  elif phrase.startswith('LOGIN COMPLETATO '):
   self.ack+=1;claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());d=Path(claim['destination'])
   following=h.HumanSession(self.selection,d,d/'human-access.jwt',claim['windowExpiresAt'])
   with following.journal.invocation():self.assertEqual(following._read()['attempts'],261)
   self.assertFalse(any(url.endswith('/token')for url,_,_ in self.calls))
  else:raise AssertionError('UNEXPECTED_TERMINAL_PHRASE')
 def provider(self,instance,url,values=None,bearer=None):
  self.calls.append((url,values,bearer));base=self.selection['issuer']+'/protocol/openid-connect/'
  if url.endswith('/.well-known/openid-configuration'):return 200,{'issuer':self.selection['issuer'],'device_authorization_endpoint':base+'device','token_endpoint':base+'token','userinfo_endpoint':base+'userinfo'},0
  if url==base+'device':
   if self.deny:return 400,{'error':'unauthorized_client'},0
   return 200,{'verification_uri':self.selection['issuer']+'/device','user_code':'SAFE-CODE','device_code':'NEW_DEVICE','expires_in':600,'interval':5},0
  if url==base+'token':
   self.assertEqual(values['grant_type'],'urn:ietf:params:oauth:grant-type:device_code');self.assertGreater(self.ack,0)
   if self.pending:self.pending-=1;return 400,{'error':'authorization_pending'},0
   claims={'iss':self.selection['issuer'],'sub':'human','tenant_id':'fixture','ouf_actor_type':'HUMAN','azp':h.CLIENT,'acr':'1',
    'aud':'ouf-api-gateway','scope':' '.join(h.SCOPES),'exp':int(time.time())+600}
   token='header.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
   return 200,{'access_token':token,'refresh_token':'NEW_REFRESH','token_type':'Bearer'},0
  if url==base+'userinfo':return 200,{'sub':'human'},0
  raise AssertionError('UNEXPECTED_PROVIDER')
 def publish(self,context,name,value):
  fd=os.open(Path(context)/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  try:os.write(fd,old.encoded(value));os.fsync(fd)
  finally:os.close(fd)
 def run_flow(self):
  parent=self
  class Stopper:
   def is_set(self):return False
   def wait(self,seconds):parent.elapsed+=seconds
  original=h.HumanSession.login
  with patch.object(h.HumanSession,'_http',lambda instance,*a,**kw:self.provider(instance,*a,**kw)),patch.object(h.HumanSession,'login',lambda instance,**kw:original(instance,stop=Stopper(),**kw)):
   return l.authenticate(self.selection,self.row['binding'],self.context,{'declaration':{'moduleCount':232}},self.publish,self.emits.append,self.case)
 def test_fresh259_to263_opens_only_explicit_new_window_and_keeps_expired_history(self):
  following=self.run_flow();row=following._read();self.assertEqual(row['attempts'],263);self.assertEqual(len(self.calls),4);self.assertEqual(self.ack,1)
  self.assertEqual(following.expires_at,int(self.wall)+7200);self.assertAlmostEqual(row['monotonicDeadline'],self.mono+7200,places=6)
  self.assertEqual(self.human._read(),self.row);self.assertNotIn('NEVER_',str(self.calls));self.assertFalse((self.context/'authority.json').exists())
  self.assertEqual(self.case['humanBinding'],row['binding'])
  with self.assertRaises(Exception):self.run_flow()
 def test_declined_budget_or_ack_has_no_unauthorized_token_request(self):
  self.prompt.side_effect=ValueError('DECLINED')
  with self.assertRaises(Exception):self.run_flow()
  self.assertEqual(self.calls,[]);self.assertFalse((self.directory/'successor-window.claim.json').exists())
 def test_predecessor_cannot_refresh_or_spend_even_with_remaining_budget(self):
  self.human._check_identity_and_budget(self.row)
  with self.assertRaises(Exception):self.human._request(self.row,'REFRESH','https://issuer.fixture.invalid/token')
  self.assertEqual(self.human._read(),self.row);self.assertEqual(self.calls,[])
 def test_pending_counts_do_not_reset_or_prolong_new_window(self):
  self.pending=2;following=self.run_flow();self.assertEqual(following._read()['attempts'],265);self.assertEqual(following.expires_at,int(self.wall)+7200)
 def test_exhaustion_stops_exactly272_and_keeps_history_without_authority(self):
  self.pending=30
  with self.assertRaises(Exception):self.run_flow()
  claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());row=json.loads((Path(claim['destination'])/'recovery.json').read_bytes())
  self.assertEqual(row['attempts'],272);self.assertFalse((self.context/'authority.json').exists());self.assertEqual(self.human._read(),self.row)
 def test_provider_denial_blocks_at261_without_token_or_old_credential_replay(self):
  self.deny=True
  with self.assertRaises(h.HumanSessionPaused):self.run_flow()
  claim=json.loads((self.directory/'successor-window.claim.json').read_bytes());row=json.loads((Path(claim['destination'])/'recovery.json').read_bytes())
  self.assertEqual(row['attempts'],261);self.assertEqual(row['state'],'BLOCKED');self.assertEqual(self.ack,0)
 def test_counter_state_or_history_drift_blocks_before_consent(self):
  for change in({'attempts':260},{'state':'BLOCKED'},{'budgetReset':True}):
   row={**self.row,**change};(self.directory/'recovery.json').write_bytes(old.encoded(row))
   with self.subTest(change=change),self.assertRaises(Exception):self.run_flow()
  self.assertEqual(self.calls,[]);self.prompt.assert_not_called()
 def test_new_validator_rejects_budget_scope_window_identity_or_decision_drift(self):
  following=self.run_flow();row=following._read()
  for change in({'attempts':273},{'attempts':0},{'bootId':'other'},{'budgetReset':True}):
   with self.subTest(change=change),self.assertRaises(Exception):following._check_identity_and_budget({**row,**change})
  for kind in('window','consent','scopes','predecessor','draft'):
   value=copy.deepcopy(row)
   if kind=='window':value['governedWindowRenewal']['decision']['expiresAt']+=1
   if kind=='consent':value['governedWindowRenewal']['decision']['decision']='NOT_APPROVED'
   if kind=='scopes':value['binding']['scopes']=['extra']
   if kind=='predecessor':value['governedWindowRenewal']['review']['priorOAuthAttempts']=0
   if kind=='draft':value['governedWindowRenewal']['review']['draftPlanHash']='0'*64
   with self.subTest(kind=kind),self.assertRaises(Exception):following._check_identity_and_budget(value)
if __name__=='__main__':unittest.main()
