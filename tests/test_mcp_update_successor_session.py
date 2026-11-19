"""Actual root custody, locks and Ed25519 fixture; no IAM/target calls."""
import copy,fcntl,hashlib,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
import test_governed_semantic_session_contract as contract
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.semantic_mcp_update import session as m
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal

class Successor(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.directory=self.root/'human-session-window2';self.directory.mkdir(mode=0o700)
  self.actor={'issuer':'https://fixture.invalid/realms/fixture','subject':'fixture-human','tenant':'fixture'}
  now=int(time.time());expiry=now-1
  self.human=HumanSession(self.actor,self.directory,self.directory/'human-access.jwt',expiry)
  bootfile=Path('/proc/sys/kernel/random/boot_id')
  self.boot=bootfile.read_text().strip()if bootfile.exists()else'fixture-boot'
  p=patch.object(HumanSession,'_boot',return_value=self.boot);p.start();self.addCleanup(p.stop)
  binding={'sessionId':'fixture-old-session','selectionHash':m.digest(self.actor),**self.actor,'clientId':CLIENT,
   'scopes':SCOPES,'tokenPath':str(self.human.token_path),'sessionDirectory':str(self.directory),
   'createdAt':expiry-7200,'expiresAt':expiry,'retryProfile':PROFILE}
  earlier={'maximumCumulativeOAuthAttempts':128,'priorOAuthAttempts':42}
  self.human.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
   'bootId':self.boot,'monotonicDeadline':time.monotonic()-1,'lastObservedAt':now-2,'attempts':49,
   'state':'READY','operation':'USERINFO','budgetReset':False,'accessToken':'PRIVATE_DO_NOT_COPY',
   'refreshToken':'PRIVATE_DO_NOT_COPY','publishedAccessToken':'PRIVATE_DO_NOT_COPY',
   'governedWindowRenewal':{'review':earlier,'decision':{'reviewHash':m.digest(earlier),
    'approvedAt':binding['createdAt'],'expiresAt':expiry}}})
  self.operation={'candidateReviewHash':'a'*64};self.before=self.human.journal.record.read_bytes()
 def decision(self,review):
  now=int(time.time());return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':m.digest(review),
   'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
 def test_explicit_window_preserves49_and_never_copies_old_credentials(self):
  review=m.expired_login_review(self.human,self.operation);self.assertEqual(review['maximumRemainingOAuthAttempts'],79)
  following=m.open_approved_login(self.human,review,self.decision(review));row=following._read()
  self.assertEqual(row['attempts'],49);self.assertEqual(row['state'],'NEW');self.assertNotIn('PRIVATE',json.dumps(row))
  self.assertEqual(self.human.journal.record.read_bytes(),self.before)
  with self.assertRaises(Exception):m.open_approved_login(self.human,review,self.decision(review))
 def test_ambiguous_refresh_blocked_and_exhausted_state_never_reopens(self):
  for changes in ({'state':'REQUESTING','operation':'REFRESH'},{'state':'BLOCKED'},{'attempts':128}):
   row=self.human._read();altered={**row,**changes};self.human.journal.record.write_bytes(m.encoded(altered))
   with self.subTest(changes=changes),self.assertRaises(Exception):m.expired_login_review(self.human,self.operation)
   self.human.journal.record.write_bytes(self.before)
 def test_review_drift_wrong_consent_and_parallel_invocation_fail_before_claim(self):
  review=m.expired_login_review(self.human,self.operation);bad=self.decision(review);bad['reviewHash']='b'*64
  with self.assertRaises(Exception):m.open_approved_login(self.human,review,bad)
  fd=os.open(self.directory/'invocation.lock',os.O_RDONLY)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(Exception):m.open_approved_login(self.human,review,self.decision(review))
  finally:os.close(fd)
  self.assertFalse((self.directory/'successor-window.claim.json').exists())

class BoundedContract(unittest.TestCase):
 def fixture(self):
  review,records,first,policy=contract.fixture()
  old=records['recovery.json'];session=records['owner-session.json']
  session.update(schema='ouf.policy-token-governed-worker-session.v1',predecessorGrantAttempts=69,maximumCumulativeGrantAttempts=197,
   fenceBinding={'path':'/fixture/parent/global.fence.json','value':{'logicalOwnerScopeHash':'5'*64,'journalPath':review['predecessorJournalDirectory'],'reviewHash':'a'*64,'active':True}})
  old.update(controlledPredecessorGrantAttempts=69,controlledCumulativeGrantAttempts=128,workerSessionHash=contract.fingerprint(session))
  review.update(schema='ouf.chatbot-semantic-functional-session-review.v2',predecessorFenceBinding=copy.deepcopy(session['fenceBinding']),
   predecessorRecordHashes={k:contract.fingerprint(v)for k,v in records.items()})
  review['proposedFiniteBudget'].update(priorControlledGrantAttempts=128,maximumNewTokenGrantAttempts=69,maximumCumulativeGrantAttempts=197)
  policy=copy.deepcopy(policy);policy['max_attempts']=69
  return review,records,first,policy
 def test_remaining_ceiling_is69_and_total197_without_reopening_old_scope(self):
  fixture=self.fixture();before=copy.deepcopy(fixture);scope=contract.compile_fixture(fixture)
  self.assertEqual(scope['predecessorGrantAttempts'],128);self.assertEqual(scope['maximumCumulativeGrantAttempts'],197)
  self.assertEqual(scope['policy']['max_attempts'],69);self.assertEqual(fixture,before)
  self.assertEqual(scope['predecessorFenceBinding'],fixture[1]['owner-session.json']['fenceBinding'])
 def test_no_expansion_boolean_budget_or_substituted_fence(self):
  for key,value in [('maximumNewTokenGrantAttempts',128),('maximumCumulativeGrantAttempts',256),('maximumNewTokenGrantAttempts',True)]:
   fixture=self.fixture();fixture[0]['proposedFiniteBudget'][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(Exception):contract.compile_fixture(fixture)
  fixture=self.fixture();fixture[0]['predecessorFenceBinding']['value']['active']=False
  with self.assertRaises(Exception):contract.compile_fixture(fixture)

class Fence(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.root.chmod(0o700);self.c=crypto.SignedCutover()
  with patch.object(crypto,'ROOT',self.root):self.c.setUp()
  self.addCleanup(self.c.doCleanups)
  self.prior=self.root/'previous';self.prior.mkdir(mode=0o700)
  self.row={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':59,'controlledCumulativeGrantAttempts':128}
  Journal(self.prior).initialize(self.row)
  self.path=self.root/'global.fence.json'
  previous={'logicalOwnerScopeHash':'5'*64,'journalPath':str(self.prior),'reviewHash':'a'*64,'active':True}
  following={**previous,'journalPath':str(self.root/'successor'),'reviewHash':'b'*64}
  self.scope={'predecessorFenceBinding':{'path':str(self.path),'value':previous},
   'fenceBinding':{'path':str(self.path),'value':following},'predecessorRecordHashes':{'recovery.json':m.digest(self.row)}}
  self.path.write_bytes(m.encoded(previous));self.path.chmod(0o600)
  c=self.c;c.authority=crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',
   **{k:v for k,v in c.expected.items()if k!='intakeHash'},'issuedAt':c.now,'expiresAt':c.now+120,
   'policyTokenFiniteWorkerSession':self.scope})
  c.approval['executionAuthorityHash']=crypto.sha(c.authority);c.write(c.mandate,crypto.encoded(c.approval));c.approved=crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  self.action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash'])
 def test_signed_handoff_keeps_old_journal_and_one_persistent_claim(self):
  before=(self.prior/'recovery.json').read_bytes();m.advance_worker_fence(self.action,self.scope,self.prior)
  self.assertEqual(json.loads(self.path.read_bytes()),self.scope['fenceBinding']['value'])
  self.assertEqual((self.prior/'recovery.json').read_bytes(),before)
  self.assertEqual(len(list(self.root.glob('*.claim.json'))),1)
  with self.assertRaises(Exception):m.advance_worker_fence(self.action,self.scope,self.prior)
 def test_live_prior_lock_and_revoked_human_are_denied(self):
  fd=os.open(self.prior/'invocation.lock',os.O_RDONLY)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(Exception):m.advance_worker_fence(self.action,self.scope,self.prior)
  finally:os.close(fd)
  self.c.approval['state']='REVOKED';self.c.write(self.c.mandate,crypto.encoded(self.c.approval))
  with self.assertRaises(Exception):m.advance_worker_fence(self.action,self.scope,self.prior)
  self.assertEqual(len(list(self.root.glob('*.claim.json'))),0)
 def test_partial_claim_never_gets_replayed_or_replaced(self):
  name=self.path.name+'.successor-'+m.digest(self.scope['predecessorFenceBinding']['value'])+'.claim.json'
  p=self.root/name;p.write_bytes(b'{}');p.chmod(0o600);before=self.path.read_bytes()
  with self.assertRaises(Exception):m.advance_worker_fence(self.action,self.scope,self.prior)
  self.assertEqual(self.path.read_bytes(),before);self.assertEqual(p.read_bytes(),b'{}')
if __name__=='__main__':unittest.main()
