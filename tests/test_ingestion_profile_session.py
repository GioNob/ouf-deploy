"""Successful v7 machine, real rotation state changes, simulated provider replies only."""
import base64,copy,importlib.util,json,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PKG=HERE
if not(PKG/'session.py').exists():PKG=ROOT/'tools/ingestion_profile_publication'
F=ROOT/'ingestion_owner_recovery/test_budget.py'
if not F.exists():F=ROOT/'tests/test_ingestion_owner_recovery_budget288.py'
class ExistingSession(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('successful_v7_fixture',F);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
  t=f.Budget('test_success_preserves_exhausted272_and_spends_four_new_requests');t.setUp();self.t=t;self.addCleanup(t.doCleanups)
  t.t.wall=1792443464.;t.t.elapsed=0;self.human=t.run_flow();self.h=t.f.h;self.before=self.human._read();self.assertEqual(self.before['attempts'],276)
  self.assertEqual(self.before['binding']['expiresAt'],1792450664)
  t.f.old.register('tools.ingestion_profile_publication');t.f.old.register('tools.ingestion_profile_publication.owner',types.SimpleNamespace(require=t.f.old.require,digest=t.f.old.digest,encoded=t.f.old.encoded))
  self.module=t.f.old.load('existing_projection_session',PKG/'session.py');self.context=t.t.root/'projection';self.context.mkdir(mode=0o700)
  self.calls=[];self.deny=False;self.ambiguous=False;self.ttl=300
  p=patch.object(self.module,'terminal_phrase',side_effect=self.consent);self.prompt=p.start();self.addCleanup(p.stop)
 def consent(self,summary,phrase):
  self.assertTrue(phrase.startswith('VERIFICO SESSIONE '));self.assertIn('Nessun nuovo login o budget',summary)
  with self.human.journal.invocation():self.human._read()
 def provider(self,instance,url,values=None,bearer=None):
  self.calls.append((url,values,bearer))
  if url.endswith('/token'):
   self.assertEqual(values['grant_type'],'refresh_token');self.assertEqual(values['refresh_token'],self.before['refreshToken'])
   if self.ambiguous:raise self.h.HumanSessionPaused('HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN')
   if self.deny:return 400,{'error':'invalid_grant'},0
   claims={'iss':self.human.selection['issuer'],'sub':self.human.selection['subject'],'tenant_id':self.human.selection['tenant'],
    'ouf_actor_type':'HUMAN','azp':self.h.CLIENT,'acr':'1','aud':'ouf-api-gateway','scope':' '.join(self.h.SCOPES),'exp':int(time.time())+self.ttl}
   token='header.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
   return 200,{'access_token':token,'refresh_token':'NEW_VERIFIED_SESSION_REFRESH','token_type':'Bearer'},0
  if url.endswith('/userinfo'):return 200,{'sub':self.human.selection['subject']},0
  raise AssertionError('NO_DISCOVERY_DEVICE_OR_OWNER_REQUEST_ALLOWED')
 def run_flow(self):
  with patch.object(self.h.HumanSession,'_http',lambda instance,*a,**kw:self.provider(instance,*a,**kw)):
   return self.module.authenticate(self.human.selection,self.before['binding'],self.context,self.t.t.publish,self.t.t.emits.append)
 def expire(self):self.t.t.elapsed+=601
 def test_still_fresh_verified_session_needs_no_oauth(self):
  human=self.run_flow();self.assertEqual(human._read()['attempts'],276);self.assertEqual(self.calls,[])
 def test_expired_bearer_renews_once_verifies_and_preserves_window_at278(self):
  self.expire();human=self.run_flow();row=human._read();self.assertEqual(row['attempts'],278);self.assertEqual(row['state'],'READY')
  self.assertEqual(len(self.calls),2);self.assertEqual(row['binding'],self.before['binding']);self.assertEqual(row['monotonicDeadline'],self.before['monotonicDeadline'])
  self.assertGreater(row['accessExpiresAt']-time.time(),240);self.assertFalse((self.context/'authority.json').exists())
 def test_declined_reuse_has_no_network_or_journal_change(self):
  self.expire();self.prompt.side_effect=ValueError('DECLINED')
  with self.assertRaisesRegex(ValueError,'DECLINED'):self.run_flow()
  self.assertEqual(self.calls,[]);self.assertEqual(self.human._read(),self.before)
 def test_revoked_refresh_blocks_without_replay_or_new_login(self):
  self.expire();self.deny=True
  with self.assertRaises(self.h.HumanSessionPaused):self.run_flow()
  self.assertEqual(self.human._read()['state'],'BLOCKED');self.assertEqual(self.human._read()['attempts'],277)
  with self.assertRaises(Exception):self.run_flow()
  self.assertEqual(len(self.calls),1)
 def test_ambiguous_rotation_remains_blocked_and_never_replayed(self):
  self.expire();self.ambiguous=True
  with self.assertRaises(self.h.HumanSessionPaused):self.run_flow()
  with self.assertRaises(Exception):self.run_flow()
  self.assertEqual(len(self.calls),1);self.assertEqual(self.human._read()['attempts'],277)
 def test_insufficient_remaining_budget_preserves_last_attempt(self):
  self.expire();self.human._save(self.human._read(),attempts=287)
  with self.assertRaisesRegex(ValueError,'VERIFIED_REFRESH_BUDGET_INSUFFICIENT_NO_LOGIN'):self.run_flow()
  self.assertEqual(self.calls,[]);self.assertEqual(self.human._read()['attempts'],287)
 def test_concurrent_session_change_denied_before_provider_dispatch(self):
  self.expire()
  def consent(*_):self.human._save(self.human._read(),state='BLOCKED',reason='EXPLICIT_REVOKED')
  self.prompt.side_effect=consent
  with self.assertRaisesRegex(ValueError,'SUCCESSFUL_HUMAN_CHANGED_DURING_SESSION_REVIEW'):self.run_flow()
  self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main()
