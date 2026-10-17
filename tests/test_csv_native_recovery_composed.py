"""Real signatures, atomic fence handoff, source stage and synthetic TLS IAM.

This fixture never contacts a real issuer or changes target services.
"""
import copy,json,os,unittest,threading
from tools.csv_materialization_recovery.journal import synchronize
from tools.csv_materialization_recovery.continuation import review_after_zero,review_after_cancelled
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from pathlib import Path
import test_governed_owner_composed as composed
import test_policy_token_owner_installation as installation_fixture
from tools.teatri_recovery_review.entry import worker_review as review_function
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_lease_recovery.bounded_recovery import fingerprint

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','requires native root/group10001 fixture')
class RemainderComposed(unittest.TestCase):
 def test_316_to317_handoff_has_no_first_grant_replay_and_no_old_journal_mutation(self):
  c=composed.Composed();c.setUp();self.addCleanup(c.doCleanups)
  previous=c.records['owner-session.json'];logical=previous['logicalOwnerScopeHash'];parent=c.installed.journal.root.parent
  previous.update(schema='ouf.policy-token-governed-worker-session.v1',predecessorGrantAttempts=308,maximumCumulativeGrantAttempts=316)
  previous['fenceBinding']={'path':str(parent/('semantic-functional-session-'+logical+'.fence.json')),
   'value':{'schema':'ouf.semantic-functional-session-fence.v1','logicalOwnerScopeHash':logical,'reviewHash':'c'*64,'journalPath':str(c.installed.journal.root),'predecessorWorkerHash':'d'*64,'active':True}}
  previous['policy']['max_attempts']=8
  old=c.records['recovery.json'];old.update(state='CANCELLED',reason='CANCELLED_BY_OWNER',attempts=8,publicationCount=8,
   controlledPredecessorGrantAttempts=308,controlledCumulativeGrantAttempts=316,workerSessionHash=fingerprint(previous),
   policyHash=fingerprint(previous['policy']),controlledHistoryProfile='ouf.policy-token-governed-worker-continuation.v1')
  for name,value in c.records.items():c.f.f.write(c.installed.journal.root/name,installation_fixture.fixture.binding.encoded(value))
  c.f.f.write(Path(previous['fenceBinding']['path']),installation_fixture.fixture.binding.encoded(previous['fenceBinding']['value']))
  before={name:(c.installed.journal.root/name).read_bytes()for name in c.records}
  c.review=review_function(c.review,c.records,c.installed.journal.root)
  c.f.f.write(c.review_path,installation_fixture.fixture.binding.encoded(c.review))
  policy={**previous['policy'],'max_attempts':128}
  scope=compile_governed_session(c.review,c.records,c.first,policy,fingerprint({'operation':c.review['logicalOperation'],'reviewHash':fingerprint(c.review)}),fingerprint(c.review['registryGeneration']),60)
  c.journal=Path(scope['fenceBinding']['value']['journalPath']);c.journal.mkdir(mode=0o700)
  c.sign(c.make().scopes());before_grants=c.grants()
  worker=c.make().install()
  self.assertEqual(c.grants(),before_grants)
  self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'],316)
  # Reconcile the real zero-attempt cancellation and install its bounded
  # successor. This must retain 444, rather than add another 128 to that cap.
  cancelled=worker.r.step(cancelled=True)
  OwnerReporter(worker.r.journal,lambda value:None).report(worker.status(cancelled))
  zero_root=worker.r.journal.root
  zero_records={name:json.loads((zero_root/name).read_bytes())for name in c.records}
  zero_before={name:(zero_root/name).read_bytes()for name in zero_records}
  c.review=review_after_zero(c.review,zero_records,zero_root);c.records=zero_records
  c.review_path=c.f.root/'zero-continuation-review.json'
  c.f.f.write(c.review_path,installation_fixture.fixture.binding.encoded(c.review))
  scope=compile_governed_session(c.review,c.records,c.first,policy,fingerprint({'operation':c.review['logicalOperation'],'reviewHash':fingerprint(c.review)}),fingerprint(c.review['registryGeneration']),60)
  self.assertEqual(scope['maximumCumulativeGrantAttempts'],444)
  c.journal=Path(scope['fenceBinding']['value']['journalPath']);c.journal.mkdir(mode=0o700)
  c.sign(c.make().scopes());worker=c.make().install();synchronize(worker.r.journal)
  self.assertEqual(c.grants(),before_grants)
  stop=threading.Event();published=threading.Event();statuses=[]
  def emit(value):
   statuses.append(value)
   if '"state":"ACTIVE"' in value:published.set()
  thread=threading.Thread(target=serve,args=(worker,stop,OwnerReporter(worker.r.journal,emit)))
  # Hold the observer transaction while the actual background loop enters its
  # guard. This used to turn local lock contention into BLOCKED at attempt zero.
  with worker.r.journal.transaction():
   thread.start();self.assertFalse(published.wait(.1))
  try:
   self.assertTrue(published.wait(20),statuses)
   row=worker.r.journal.read();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['controlledCumulativeGrantAttempts'],317)
  finally:stop.set();thread.join(10)
  self.assertFalse(thread.is_alive())
  self.assertFalse(any('LOCAL_AUTHORITY_UNPROVEN' in value for value in statuses))
  self.assertEqual(c.grants(),before_grants+1)
  self.assertEqual(json.loads(Path(scope['fenceBinding']['path']).read_bytes()),scope['fenceBinding']['value'])
  for name,raw in zero_before.items():self.assertEqual((zero_root/name).read_bytes(),raw)
  for name,raw in before.items():self.assertEqual((c.installed.journal.root/name).read_bytes(),raw)
  with self.assertRaises(Exception):c.make().install()
  self.assertEqual(c.grants(),before_grants+1)

  # The real first publication was consumed before cancellation. Its successor
  # has only 127 slots and must preserve this journal byte-for-byte as well.
  one_root=worker.r.journal.root
  one_records={name:json.loads((one_root/name).read_bytes())for name in c.records}
  one_before={name:(one_root/name).read_bytes()for name in one_records}
  self.assertEqual(one_records['recovery.json']['attempts'],1)
  c.review=review_after_cancelled(c.review,one_records,one_root,1,317);c.records=one_records
  c.review_path=c.f.root/'one-publication-continuation-review.json'
  c.f.f.write(c.review_path,installation_fixture.fixture.binding.encoded(c.review))
  policy={**policy,'max_attempts':127}
  scope=compile_governed_session(c.review,c.records,c.first,policy,fingerprint({'operation':c.review['logicalOperation'],'reviewHash':fingerprint(c.review)}),fingerprint(c.review['registryGeneration']),60)
  self.assertEqual(scope['predecessorGrantAttempts'],317);self.assertEqual(scope['maximumCumulativeGrantAttempts'],444)
  c.journal=Path(scope['fenceBinding']['value']['journalPath']);c.journal.mkdir(mode=0o700)
  c.sign(c.make().scopes());worker=c.make().install();synchronize(worker.r.journal)
  row=worker.tick();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['controlledCumulativeGrantAttempts'],318)
  self.assertEqual(c.grants(),before_grants+2)
  for name,raw in one_before.items():self.assertEqual((one_root/name).read_bytes(),raw)
  with self.assertRaises(Exception):c.make().install()
