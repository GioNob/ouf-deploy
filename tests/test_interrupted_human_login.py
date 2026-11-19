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
        if getattr(self,'sealed_parent',False):
            f.directory=f.directory/'human-session';f.directory.mkdir(mode=0o700);f.session=f.new_session()
        f.fixture.approve_after=100
        class StopAfterPending:
            def is_set(self):return f.fixture.polls>=1
            def wait(self,delay):f.clock.advance(delay)
        with self.assertRaises(m.HumanSessionPaused):f.session.login(f.output.append,StopAfterPending(),confirm_browser=lambda _:True)
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

class ExpiredWindow(unittest.TestCase):
    sealed_parent=True
    replace=Continuation.replace
    def setUp(self):
        Continuation.setUp(self);self.replace(attempts=42)
        self.f.clock.advance(4000)
        self.binding={'sourceClosureHash':'a'*64,'preparationHash':'b'*64}
        self.destination=self.f.session.directory.parent/'human-session-window2'
    def review(self):return self.f.session.expired_window_review(self.binding)
    def decision(self,review):
        now=int(self.f.clock.time())
        return {'schema':'ouf.human-login-window-terminal-consent.v1',
            'reviewHash':m.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY',
            'approvedAt':now,'expiresAt':now+7200}
    def test_new_window_preserves_old_journal_and_counts_all_real_http_requests(self):
        f=self.f;before=f.session.journal.record.read_bytes();review=self.review();calls=len(f.fixture.calls)
        self.assertEqual(review['priorOAuthAttempts'],42)
        self.assertEqual(review['maximumRemainingOAuthAttempts'],86)
        self.assertEqual(len(f.fixture.calls),calls);self.assertFalse(self.destination.exists())
        renewed=f.session.start_approved_window(review,self.decision(review),self.destination)
        self.assertEqual(renewed.journal.read()['attempts'],42)
        self.assertEqual(f.session.journal.record.read_bytes(),before)
        renewed.opener=f.session.opener;f.fixture.approve_after=f.fixture.polls+1
        output=[];renewed.login(output.append,fixture.ImmediateFixtureWait(f.clock),confirm_browser=lambda _:True)
        self.assertEqual(renewed.journal.read()['attempts'],42+len(f.fixture.calls)-calls)
        self.assertEqual(f.session.journal.record.read_bytes(),before)
        self.assertNotIn('private-device-fixture',' '.join(output))
        with self.assertRaises(Exception):f.session.start_approved_window(review,self.decision(review),self.destination)
    def test_changed_predecessor_wrong_consent_and_stale_decision_refuse_without_new_journal(self):
        review=self.review();decision=self.decision(review)
        for key,value in [('reviewHash','f'*64),('approvedAt',decision['approvedAt']-61),
                          ('decision','APPROVE_RUNTIME'),('expiresAt',decision['expiresAt']+1)]:
            with self.assertRaises(Exception):
                self.f.session.start_approved_window(review,{**decision,key:value},self.destination)
            self.assertFalse(self.destination.exists())
        self.replace(attempts=43)
        with self.assertRaises(Exception):self.f.session.start_approved_window(review,decision,self.destination)
        self.assertFalse(self.destination.exists())
    def test_exhaustion_ambiguous_effect_received_credential_and_boot_drift_stay_blocked(self):
        before=self.f.session.journal.read();calls=len(self.f.fixture.calls)
        for updates in ({'attempts':128},{'state':'REQUESTING','operation':'DEVICE_POLL'},
                {'accessToken':'SECRET_ALREADY_RECEIVED'},{'bootId':'different-boot'}):
            self.replace(**updates)
            with self.assertRaises(Exception):self.review()
            row=self.f.session.journal.read();self.f.session.journal.compare_and_save(row,before)
        self.assertEqual(len(self.f.fixture.calls),calls);self.assertFalse(self.destination.exists())
    def test_renewed_counter_cannot_drop_below_predecessor_and_window_never_auto_renews(self):
        review=self.review();new=self.f.session.start_approved_window(review,self.decision(review),self.destination)
        row=new.journal.read()
        with self.assertRaises(Exception):new._check({**row,'attempts':41})
        self.f.clock.advance(7201)
        with self.assertRaises(Exception):new.expired_window_review(self.binding)

if __name__=='__main__':unittest.main()
