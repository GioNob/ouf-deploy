"""Actual durable HUMAN state machine; issuer is isolated and fully simulated."""
import copy,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
fixture=ROOT/'ingestion_owner_reference/test_budget.py'
if not fixture.exists():fixture=ROOT/'tests/test_ingestion_owner_budget272.py'
spec=importlib.util.spec_from_file_location('browser_repair_fixture',fixture);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
source=HERE/'human_session.py'
if not source.exists():source=ROOT/'tools/chatbot_file_cohort/human_session.py'
spec=importlib.util.spec_from_file_location('corrected_human_machine',source);h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
h.PROFILE=copy.deepcopy(f.h.PROFILE);h.SCOPES=copy.deepcopy(f.h.SCOPES)
h.HumanSession._check_identity_and_budget=f.h.HumanSession._check_identity_and_budget
class Confirmation(unittest.TestCase):
 def setUp(self):
  self.fixture=f.Budget('test_pending_counts_do_not_reset_or_prolong_new_window');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  t=self.fixture;original=t.phrase
  def pause(summary,phrase):
   if phrase.startswith('LOGIN COMPLETATO '):raise ValueError('STOP_BEFORE_FIRST_TOKEN')
   original(summary,phrase)
  t.prompt.side_effect=pause
  with self.assertRaisesRegex(ValueError,'STOP_BEFORE_FIRST_TOKEN'):t.run_flow()
  claim=json.loads((t.directory/'successor-window.claim.json').read_bytes());d=Path(claim['destination'])
  self.session=h.HumanSession(t.selection,d,d/'human-access.jwt',claim['windowExpiresAt']);self.confirmations=0
  if not Path('/proc/sys/kernel/random/boot_id').exists():
   p=patch.object(h.HumanSession,'_boot',return_value='fixture-boot');p.start();self.addCleanup(p.stop)
 def run_login(self,callback=None,session=None):
  t=self.fixture;target=session or self.session
  class Stopper:
   def is_set(self):return False
   def wait(self,seconds):
    with target.journal.invocation():pass
    t.elapsed+=seconds
  with patch.object(h.HumanSession,'_http',lambda instance,*a,**kw:t.provider(instance,*a,**kw)):
   return target.login(emit=t.emits.append,stop=Stopper(),confirm_browser=callback)
 def confirm(self,challenge):
  self.confirmations+=1;self.fixture.ack+=1
  self.assertEqual(set(challenge),{'verificationUri','userCode','deviceDeadline','attempts'})
  with self.session.journal.invocation():self.session._read()
  return True
 def test_premature_ack_one_pending_reply_then_pause_no_budget_drain(self):
  self.fixture.pending=40
  def callback(challenge):
   if self.confirmations:raise ValueError('OPERATOR_WAITING_IN_BROWSER')
   return self.confirm(challenge)
  with self.assertRaisesRegex(ValueError,'OPERATOR_WAITING_IN_BROWSER'):self.run_login(callback)
  row=self.session._read();self.assertEqual((row['state'],row['attempts']),('DEVICE_POLL',262))
  self.assertEqual(sum(u.endswith('/token')for u,_,_ in self.fixture.calls),1)
  self.assertFalse(self.session.token_path.exists())
 def test_second_confirmation_uses_same_challenge_and_completes(self):
  self.fixture.pending=1;before=self.session._read();binding=self.run_login(self.confirm);after=self.session._read()
  self.assertEqual(self.confirmations,2);self.assertEqual(after['state'],'READY');self.assertEqual(after['attempts'],264)
  self.assertEqual(binding,before['binding']);self.assertEqual(after['monotonicDeadline'],before['monotonicDeadline'])
  self.assertEqual(self.fixture.human._read(),self.fixture.row)
  self.assertGreaterEqual(sum(e.startswith('ENTER_DEVICE_CODE=')for e in self.fixture.emits),3)
 def test_missing_callback_and_restart_cannot_poll(self):
  for _ in range(2):
   with self.assertRaises(h.HumanBrowserConfirmationRequired):self.run_login()
  self.assertEqual(self.session._read()['attempts'],261)
  self.assertFalse(any(u.endswith('/token')for u,_,_ in self.fixture.calls))
 def test_no_confirmation_does_not_send_token_request(self):
  with self.assertRaisesRegex(ValueError,'HUMAN_BROWSER_CONFIRMATION_NOT_GIVEN'):self.run_login(lambda _:False)
  self.assertEqual(self.session._read()['attempts'],261)
 def test_reserve_prevents_token_acquisition_with_one_request_left(self):
  row=self.session._read();self.session._save(row,attempts=271)
  with self.assertRaisesRegex(ValueError,'HUMAN_VERIFICATION_BUDGET_RESERVED'):self.run_login(self.confirm)
  self.assertEqual(self.session._read()['attempts'],271);self.assertEqual(self.confirmations,0)
  self.assertFalse(any(u.endswith('/token')for u,_,_ in self.fixture.calls))
 def test_two_remaining_requests_finish_verification_at_limit(self):
  self.session._save(self.session._read(),attempts=270);self.run_login(self.confirm)
  row=self.session._read();self.assertEqual((row['state'],row['attempts']),('READY',272));self.assertTrue(self.session.token_path.exists())
 def test_exhausted_verifying_is_not_reused_or_published(self):
  self.session._save(self.session._read(),state='VERIFYING',attempts=272,accessToken='UNVERIFIED')
  # No parsing, dispatch, publication or refresh from an already exhausted session.
  with self.assertRaisesRegex(ValueError,'HUMAN_SESSION_BUDGET_EXHAUSTED'):
   self.session._request(self.session._read(),'USERINFO','https://issuer.fixture.invalid/userinfo')
  self.assertFalse(self.session.token_path.exists())
 def test_confirmation_bound_to_exact_row_rejects_concurrent_change(self):
  def callback(challenge):
   self.confirm(challenge);self.session._save(self.session._read(),state='BLOCKED',reason='EXPLICIT_REVOKED');return True
  with self.assertRaises(h.HumanSessionPaused):self.run_login(callback)
  self.assertFalse(any(u.endswith('/token')for u,_,_ in self.fixture.calls))
 def test_same_row_confirmation_cannot_be_replayed_after_pending(self):
  self.fixture.pending=2
  def callback(challenge):
   if self.confirmations:raise ValueError('SECOND_CONFIRMATION_REQUIRED')
   return self.confirm(challenge)
  with self.assertRaisesRegex(ValueError,'SECOND_CONFIRMATION_REQUIRED'):self.run_login(callback)
  self.assertEqual(self.session._read()['attempts'],262)
if __name__=='__main__':unittest.main()
