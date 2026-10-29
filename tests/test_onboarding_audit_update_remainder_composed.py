"""Real signatures, atomic fence handoff, source stage and synthetic TLS IAM.

This fixture never contacts a real issuer or changes target services.
"""
import copy,json,os,unittest
from pathlib import Path
import test_governed_owner_composed as composed
import test_policy_token_owner_installation as installation_fixture
from test_onboarding_audit_update_remainder import review_function
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_lease_recovery.bounded_recovery import fingerprint

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','requires native root/group10001 fixture')
class RemainderComposed(unittest.TestCase):
 def test_248_to249_handoff_has_no_first_grant_replay_and_no_old_journal_mutation(self):
  c=composed.Composed();c.setUp();self.addCleanup(c.doCleanups)
  previous=c.records['owner-session.json'];logical=previous['logicalOwnerScopeHash'];parent=c.installed.journal.root.parent
  previous.update(schema='ouf.policy-token-governed-worker-session.v1',predecessorGrantAttempts=188,maximumCumulativeGrantAttempts=316)
  previous['fenceBinding']={'path':str(parent/('semantic-functional-session-'+logical+'.fence.json')),
   'value':{'schema':'ouf.semantic-functional-session-fence.v1','logicalOwnerScopeHash':logical,'reviewHash':'c'*64,'journalPath':str(c.installed.journal.root),'predecessorWorkerHash':'d'*64,'active':True}}
  old=c.records['recovery.json'];old.update(state='CANCELLED',reason='CANCELLED_BY_OWNER',attempts=60,publicationCount=60,
   controlledPredecessorGrantAttempts=188,controlledCumulativeGrantAttempts=248,workerSessionHash=fingerprint(previous),
   policyHash=fingerprint(previous['policy']),controlledHistoryProfile='ouf.policy-token-governed-worker-continuation.v1')
  for name,value in c.records.items():c.f.f.write(c.installed.journal.root/name,installation_fixture.fixture.binding.encoded(value))
  c.f.f.write(Path(previous['fenceBinding']['path']),installation_fixture.fixture.binding.encoded(previous['fenceBinding']['value']))
  before={name:(c.installed.journal.root/name).read_bytes()for name in c.records}
  c.review=review_function(c.review,c.records,c.installed.journal.root)
  c.f.f.write(c.review_path,installation_fixture.fixture.binding.encoded(c.review))
  policy={**previous['policy'],'max_attempts':68}
  scope=compile_governed_session(c.review,c.records,c.first,policy,fingerprint({'operation':c.review['logicalOperation'],'reviewHash':fingerprint(c.review)}),fingerprint(c.review['registryGeneration']),60)
  c.journal=Path(scope['fenceBinding']['value']['journalPath']);c.journal.mkdir(mode=0o700)
  c.sign(c.make().scopes());before_grants=c.grants()
  worker=c.make().install()
  self.assertEqual(c.grants(),before_grants)
  self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'],248)
  row=worker.tick();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['controlledCumulativeGrantAttempts'],249)
  self.assertEqual(c.grants(),before_grants+1)
  self.assertEqual(json.loads(Path(scope['fenceBinding']['path']).read_bytes()),scope['fenceBinding']['value'])
  for name,raw in before.items():self.assertEqual((c.installed.journal.root/name).read_bytes(),raw)
  with self.assertRaises(Exception):c.make().install()
  self.assertEqual(c.grants(),before_grants+1)
