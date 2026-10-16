"""Same OAuth journal/budget continuation against actual local HTTP fixture."""
import copy
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import test_chatbot_cohort_human_session as fixture
m=fixture.module

class Continuation(unittest.TestCase):
    def setUp(self):
        f=fixture.HumanSessionTest();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        f.fixture.approve_after=100
        class StopAfterPending:
            def is_set(self):return f.fixture.polls>=1
            def wait(self,delay):f.clock.advance(delay)
        with self.assertRaises(m.HumanSessionPaused):f.session.login(f.output.append,StopAfterPending())
        self.before=f.session.journal.read()
        self.assertEqual(self.before['state'],'DEVICE_POLL')
    def expired(self):self.f.clock.advance(601)
    def replace(self,**updates):
        current=self.f.session.journal.read();following={**current,**updates}
        self.f.session.journal.compare_and_save(current,following);return following
    def test_expired_challenge_continues_same_budget_deadlines_and_real_login(self):
        self.expired();f=self.f;before=f.session.journal.read();calls=len(f.fixture.calls)
        metadata=f.session.prepare_interrupted_login(f.output.append)
        after=f.session.journal.read()
        self.assertEqual(metadata['state'],'DEVICE_START');self.assertEqual(len(f.fixture.calls),calls)
        for key in ('attempts','binding','monotonicDeadline','bootId'):self.assertEqual(after[key],before[key])
        self.assertEqual(after['expiredDeviceChallengeHistory'][-1]['previousRowHash'],m.digest(before))
        f.fixture.approve_after=f.fixture.polls+1;binding=f.login()
        self.assertEqual(binding,before['binding']);self.assertEqual(f.session.current(),binding)
        self.assertGreater(f.session.journal.read()['attempts'],before['attempts'])
        self.assertNotIn('private-device-fixture',' '.join(f.output))
        self.assertNotIn('private-fixture-refresh',' '.join(f.output))
    def test_pending_mutation_is_blocked_without_request_or_counter_reset(self):
        before=self.replace(state='REQUESTING',operation='DEVICE_POLL');calls=len(self.f.fixture.calls)
        with self.assertRaisesRegex(m.HumanSessionPaused,'OUTCOME_UNPROVEN'):self.f.session.prepare_interrupted_login()
        after=self.f.session.journal.read();self.assertEqual(after['state'],'BLOCKED')
        self.assertEqual(after['attempts'],before['attempts']);self.assertEqual(after['binding'],before['binding'])
        self.assertEqual(len(self.f.fixture.calls),calls)
    def test_unexpired_retained_prompt_is_reprinted_without_new_request(self):
        f=self.f;calls=len(f.fixture.calls);output=[]
        f.session.prepare_interrupted_login(output.append)
        self.assertIn('OPEN_IN_BROWSER='+fixture.ISSUER+'/device',output)
        self.assertIn('ENTER_DEVICE_CODE=USER-1234',output)
        self.assertEqual(len(f.fixture.calls),calls);self.assertEqual(f.session.journal.read(),self.before)
    def test_old_missing_prompt_waits_for_challenge_expiry_without_replacement(self):
        before=self.replace(verificationUri=None,userCode=None)
        with self.assertRaises(m.HumanSessionPaused)as error:self.f.session.prepare_interrupted_login()
        self.assertEqual(error.exception.retry_at,before['deviceDeadline'])
        self.assertEqual(self.f.session.journal.read(),before)
    def test_retry_after_survives_expired_challenge(self):
        self.expired();f=self.f
        before=self.replace(state='RETRY_WAIT',resumeState='DEVICE_POLL',nextAttemptAt=f.clock.time()+120,
            consecutiveFailures=3)
        with self.assertRaises(m.HumanSessionPaused)as error:f.session.prepare_interrupted_login()
        self.assertEqual(error.exception.retry_at,before['nextAttemptAt']);self.assertEqual(f.session.journal.read(),before)
        f.clock.advance(120);f.session.prepare_interrupted_login()
        after=f.session.journal.read();self.assertEqual(after['consecutiveFailures'],3)
        self.assertEqual(after['attempts'],before['attempts'])
    def test_exhausted_or_expired_original_session_is_never_renewed(self):
        self.expired();before=self.replace(attempts=m.PROFILE['maximumAttempts'])
        with self.assertRaises(Exception):self.f.session.prepare_interrupted_login()
        self.assertEqual(self.f.session.journal.read(),before)
        self.f.clock.advance(4000)
        with self.assertRaises(Exception):self.f.session.prepare_interrupted_login()
        self.assertEqual(self.f.session.journal.read(),before)
    def test_received_credentials_or_blocked_state_do_not_start_new_challenge(self):
        self.expired();before=self.replace(accessToken='PRIVATE_RECEIVED_VALUE')
        with self.assertRaises(Exception):self.f.session.prepare_interrupted_login()
        self.assertEqual(self.f.session.journal.read(),before)
        before=self.replace(state='BLOCKED')
        with self.assertRaises(m.HumanSessionPaused):self.f.session.prepare_interrupted_login()
        self.assertEqual(self.f.session.journal.read(),before)

if __name__=='__main__':unittest.main()
