"""Actual frozen272 journal -> appended guarded288 machine; mock issuer only."""
import base64,copy,importlib.util,json,os,sys,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PKG=HERE
if not(PKG/'login.py').exists():PKG=ROOT/'tools/ingestion_owner_recovery'
F=ROOT/'ingestion_owner_reference/test_budget.py'
if not F.exists():F=ROOT/'tests/test_ingestion_owner_budget272.py'
class Budget(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('frozen272_fixture_for_recovery',F);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);self.f=f
  t=f.Budget('test_exhaustion_stops_exactly272_and_keeps_history_without_authority');t.setUp();self.t=t;self.addCleanup(t.doCleanups)
  t.wall=1792439008.;t.pending=10
  with self.assertRaisesRegex(ValueError,'HUMAN_SESSION_BUDGET_EXHAUSTED'):t.run_flow()
  claim=json.loads((t.directory/'successor-window.claim.json').read_bytes());self.predecessor=Path(claim['destination'])
  self.before=(self.predecessor/'recovery.json').read_bytes();self.row=json.loads(self.before);self.assertEqual(self.row['state'],'VERIFYING')
  self.binding=self.row['binding'];self.assertEqual(self.binding['expiresAt'],1792446208)
  t.calls.clear();t.pending=0;t.ack=0
  for name in ('confirmation_patch','human_extension'):exec(compile((PKG/(name+'.py')).read_bytes(),'<new-sealed-'+name+'>','exec'),f.h.__dict__)
  f.old.register('tools.ingestion_owner_recovery');f.old.register('tools.ingestion_owner_recovery.owner',types.SimpleNamespace(require=f.old.require,digest=f.old.digest,encoded=f.old.encoded))
  f.old.register('tools.ingestion_read_owner_reference.login',types.SimpleNamespace(terminal_phrase=lambda *_:None))
  f.old.register('tools.ingestion_owner_recovery.reconcile',types.SimpleNamespace(PACKAGE='afff187c6c97fe697ab448b6d88bdd24092c1fd00b0aef01f268e9982e96b5a5',CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-owner-reference-execution-tr33g8bg')))
  self.l=f.old.load('guarded_recovery_login',PKG/'login.py');self.context=t.root/'new-context';self.context.mkdir(mode=0o700)
  self.case={'humanBinding':self.binding,'logicalRef':'b'*64};self.confirmations=0;self.abort_after=None
  p=patch.object(self.l,'terminal_phrase',side_effect=self.phrase);self.prompt=p.start();self.addCleanup(p.stop)
 def phrase(self,summary,phrase):
  if phrase.startswith('APPROVO BUDGET288 '):self.assertIn('16richieste',summary)
  elif phrase.startswith('LOGIN COMPLETATO '):
   self.assertIn('Apri QUESTO indirizzo:',summary);self.assertIn('Inserisci QUESTO codice:',summary)
   self.assertIn('UNA richiesta token',summary)
   if self.abort_after is not None and self.confirmations>=self.abort_after:raise ValueError('OPERATOR_STILL_IN_BROWSER')
   self.confirmations+=1;self.t.ack+=1
   claim=json.loads((self.predecessor/'successor-window.claim.json').read_bytes());d=Path(claim['destination'])
   following=self.f.h.HumanSession(self.t.selection,d,d/'human-access.jwt',claim['windowExpiresAt'])
   with following.journal.invocation():following._read()
  else:raise AssertionError('UNEXPECTED_CONSENT')
 def following(self):
  claim=json.loads((self.predecessor/'successor-window.claim.json').read_bytes());d=Path(claim['destination'])
  return self.f.h.HumanSession(self.t.selection,d,d/'human-access.jwt',claim['windowExpiresAt'])
 def run_flow(self):
  outer=self;t=self.t;h=self.f.h
  class Stopper:
   def is_set(self):return False
   def wait(self,seconds):
    with outer.following().journal.invocation():pass
    t.elapsed+=seconds
  original=h.HumanSession.login
  with patch.object(h.HumanSession,'_http',lambda instance,*a,**kw:t.provider(instance,*a,**kw)),patch.object(h.HumanSession,'login',lambda instance,**kw:original(instance,stop=Stopper(),**kw)):
   return self.l.authenticate(t.selection,self.binding,self.context,{'declaration':{'moduleCount':238}},t.publish,t.emits.append,self.case)
 def test_success_preserves_exhausted272_and_spends_four_new_requests(self):
  human=self.run_flow();self.assertEqual(human._read()['attempts'],276);self.assertEqual(self.confirmations,1)
  self.assertEqual((self.predecessor/'recovery.json').read_bytes(),self.before);self.assertNotIn(self.row['accessToken'],str(self.t.calls))
  self.assertFalse((self.context/'authority.json').exists());self.assertEqual(human._read()['state'],'READY')
 def test_premature_ack_returns_to_visible_same_challenge_and_completes(self):
  self.t.pending=1;human=self.run_flow();self.assertEqual(human._read()['attempts'],277);self.assertEqual(self.confirmations,2)
  self.assertEqual(sum(u.endswith('/device')for u,_,_ in self.t.calls),1)
  self.assertEqual((self.predecessor/'recovery.json').read_bytes(),self.before)
 def test_premature_ack_then_browser_wait_never_drains_budget(self):
  self.t.pending=30;self.abort_after=1
  with self.assertRaisesRegex(ValueError,'OPERATOR_STILL_IN_BROWSER'):self.run_flow()
  row=self.following()._read();self.assertEqual((row['state'],row['attempts']),('DEVICE_POLL',275))
  self.assertFalse(self.following().token_path.exists());self.assertEqual(sum(u.endswith('/token')for u,_,_ in self.t.calls),1)
 def test_repeated_premature_confirmations_preserve_final_verification_request(self):
  self.t.pending=30
  with self.assertRaisesRegex(ValueError,'HUMAN_VERIFICATION_BUDGET_RESERVED'):self.run_flow()
  row=self.following()._read();self.assertEqual(row['attempts'],287);self.assertFalse(self.following().token_path.exists())
  self.assertEqual((self.predecessor/'recovery.json').read_bytes(),self.before)
 def test_no_new_budget_without_exact_native_consent(self):
  self.prompt.side_effect=ValueError('DECLINED')
  with self.assertRaisesRegex(ValueError,'DECLINED'):self.run_flow()
  self.assertEqual(self.t.calls,[]);self.assertFalse((self.predecessor/'successor-window.claim.json').exists())
 def test_stopped272_oauth_dispatch_denied_in_new_package(self):
  human=self.f.h.HumanSession(self.t.selection,self.predecessor,self.predecessor/'human-access.jwt',self.binding['expiresAt'])
  human._check_identity_and_budget(self.row)
  with self.assertRaisesRegex(ValueError,'PREDECESSOR272_OAUTH_DISPATCH_FORBIDDEN'):human._request(self.row,'REFRESH','https://issuer.fixture.invalid/token')
  self.assertEqual(self.t.calls,[]);self.assertEqual((self.predecessor/'recovery.json').read_bytes(),self.before)
 def test_new_profile_rejects_identity_budget_window_and_decision_drift(self):
  human=self.run_flow();row=human._read()
  for change in ({'attempts':271},{'attempts':289},{'budgetReset':True},{'bootId':'different'}):
   with self.subTest(change=change),self.assertRaises(Exception):human._check_identity_and_budget({**row,**change})
  changed=copy.deepcopy(row);changed['governedWindowRenewal']['decision']['decision']='NOT_APPROVED'
  with self.assertRaises(Exception):human._check_identity_and_budget(changed)
 def test_second_authentication_cannot_create_another_successor_or_spend(self):
  self.run_flow();calls=len(self.t.calls)
  with self.assertRaises(Exception):self.run_flow()
  self.assertEqual(len(self.t.calls),calls)
if __name__=='__main__':unittest.main()
