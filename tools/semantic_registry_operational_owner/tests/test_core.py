import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from tools.semantic_registry_operational_owner import core as c


POLICY=c.RenewalPolicy(60,90,15,60,3,30,(5,15,60,300))


class Memory:
    def __init__(self,row):self.value=copy.deepcopy(row);self.saved=[]
    def read(self):return copy.deepcopy(self.value)
    def assert_invocation(self):pass  # Explicit store collaborator; real flocks tested separately.
    def cas(self,before,after):
        if before!=self.value:raise c.Denied('CAS_CONFLICT')
        self.value=copy.deepcopy(after);self.saved.append(copy.deepcopy(after))


class Clock:
    def __init__(self):self.boot='boot-a';self.wall=10000;self.mono=1000
    def __call__(self):return self.boot,self.wall,self.mono
    def advance(self,n):self.wall+=n;self.mono+=n


class Adapter:
    def __init__(self,clock):self.clock=clock;self.grants=0;self.publications=0;self.token_hash=None;self.error=None;self.guard_error=None
    def guard(self):
        if self.guard_error:raise self.guard_error
    def grant_and_admit(self,deadline):
        self.grants+=1
        if self.error:raise self.error
        return 'fixture-token-'+str(self.grants),self.clock.wall+300
    def publish(self,token,attempt_id,token_hash):self.publications+=1;self.token_hash=token_hash
    def verify_publication(self,token_hash):
        if token_hash!=self.token_hash:raise c.Denied('PUBLICATION_REPLACED')
    def readmit_existing(self,token_hash):self.verify_publication(token_hash);return self.clock.wall+100


class Core(unittest.TestCase):
    def setUp(self):
        self.clock=Clock();self.store=Memory(c.initial('a'*64,'b'*64,321,POLICY,'boot-a',(10000,1000)))
        self.adapter=Adapter(self.clock);self.worker=self.build()
    def build(self):return c.Worker(self.store,self.adapter,POLICY,'a'*64,'b'*64,321,self.clock)
    def active(self):self.worker.start();return self.worker.step()
    def test_reserve_and_dispatch_durable_before_one_grant_publication(self):
        r=self.active();self.assertEqual(r['cumulativeAttempts'],322);self.assertEqual(r['attempts'],1)
        self.assertEqual([r['state']for r in self.store.saved],['RESERVED','DISPATCHING','PUBLISHING','ACTIVE'])
        self.assertEqual((self.adapter.grants,self.adapter.publications),(1,1));self.assertEqual(r['nextWall'],10210)
    def test_continuous_renewal_is_new_attempt_preserving_prior_and_counts(self):
        first=self.active();self.clock.advance(210);r=self.worker.step()
        self.assertEqual(r['cumulativeAttempts'],323);self.assertEqual(r['priorControlledAttempts'],321)
        self.assertEqual(r['publications'],2);self.assertNotEqual(first['attemptId'],r['attemptId'])
    def test_unknown_grant_outcome_parks_and_restart_never_redispatches(self):
        self.adapter.error=TimeoutError();self.worker.start()
        with self.assertRaises(TimeoutError):self.worker.step()
        self.assertEqual(self.store.value['state'],'BLOCKED');self.assertEqual(self.store.value['cumulativeAttempts'],322)
        self.build().start();self.assertEqual(self.adapter.grants,1)
    def test_unknown_publishing_crash_blocks_without_adopting_token(self):
        r=self.active();r.update(state='PUBLISHING',reason='CRASH');self.store.value=r
        result=self.build().start();self.assertEqual(result['state'],'BLOCKED');self.assertEqual(self.adapter.grants,1)
    def test_undispatched_reservation_is_abandoned_not_refunded_after_reboot(self):
        self.worker.start();self.adapter.guard_error=None
        row=self.store.read();attempt=322
        self.worker.save(row,state='RESERVED',attempts=1,cumulativeAttempts=attempt,
                         attemptId=c.digest({'installationHash':'a'*64,'cumulativeAttempt':attempt}))
        self.clock.boot='boot-b';self.clock.wall+=60;self.clock.mono=10
        worker=self.build();r=worker.start();self.assertEqual(r['attempts'],1);self.assertEqual(r['nextMono'],10)
        r=worker.step();self.assertEqual(r['cumulativeAttempts'],323);self.assertEqual(self.adapter.grants,1)
    def test_safe_no_submission_uses_bounded_backoff_and_distinct_next_attempt(self):
        self.worker.start();self.adapter.error=c.NotSubmitted();r=self.worker.step()
        self.assertEqual(r['state'],'RETRY_WAIT');self.assertEqual(r['cumulativeAttempts'],322)
        self.assertEqual(r['nextWall'],10005);self.worker.step();self.assertEqual(self.adapter.grants,1)
        self.clock.advance(5);self.adapter.error=None;r=self.worker.step()
        self.assertEqual(r['cumulativeAttempts'],323);self.assertEqual(r['consecutiveFailures'],0)
    def test_hourly_rate_limit_does_not_reset_total_or_issue_grant(self):
        row=self.store.read();row['hourlyAttemptsWall']=[10000]*60;self.store.value=row
        self.worker.start();r=self.worker.step();self.assertEqual(r['state'],'RETRY_WAIT')
        self.assertEqual(r['cumulativeAttempts'],321);self.assertEqual(self.adapter.grants,0)
    def test_restart_active_requires_online_readmission_and_same_token(self):
        r=self.active();worker=self.build();result=worker.start()
        self.assertEqual(result['state'],'ACTIVE');self.assertEqual(result['tokenExpiresWall'],10100)
        self.assertEqual(result['cumulativeAttempts'],322);self.assertEqual(self.adapter.grants,1)
    def test_restart_does_not_readmit_near_expired_lease_or_refresh_same_attempt(self):
        self.active();self.clock.advance(220);worker=self.build();self.assertEqual(worker.start()['state'],'READY')
        self.assertEqual(worker.step()['cumulativeAttempts'],323)
    def test_foreign_token_replacement_cannot_be_adopted(self):
        self.active();self.adapter.token_hash='c'*64
        with self.assertRaisesRegex(c.Denied,'PUBLICATION_REPLACED'):self.build().start()
        self.assertEqual(self.adapter.grants,1)
    def test_clock_regression_or_divergence_never_dispatches(self):
        self.worker.start();self.clock.wall-=1
        with self.assertRaises(c.Denied):self.worker.step()
        self.clock.wall=10020
        with self.assertRaisesRegex(c.Denied,'CLOCK_DIVERGENCE'):self.worker.step()
        self.assertEqual(self.adapter.grants,0)
    def test_history_reset_and_bool_attempts_denied_before_guard(self):
        self.store.value['attempts']=False
        with self.assertRaises(c.Denied):self.worker.start()
        self.assertEqual(self.adapter.grants,0)
    def test_stop_or_admission_failures_do_not_unlink_current_token(self):
        r=self.active();self.clock.advance(210);self.adapter.error=PermissionError('fixture')
        with self.assertRaises(PermissionError):self.worker.step()
        self.assertEqual(self.adapter.token_hash,r['tokenHash']);self.assertEqual(self.adapter.publications,1)

if __name__=='__main__':unittest.main()
