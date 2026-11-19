"""Real signed owner, first TLS grant and persistent fence for a new test budget."""
import copy,json,unittest
from pathlib import Path
from test_governed_owner_composed import Composed,fixture
from test_governed_semantic_session_contract import fingerprint
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session

class ExplicitTestBudgetNative(unittest.TestCase):
 def test_new_budget_uses_actual_owner_signatures_and_one_tls_grant_without_reset(self):
  f=Composed();f.setUp();self.addCleanup(f.doCleanups)
  previous=f.records['owner-session.json'];old=f.records['recovery.json']
  fence=f.installed.journal.root.parent/('semantic-functional-session-'+previous['logicalOwnerScopeHash']+'.fence.json')
  old_value={'schema':'ouf.semantic-functional-session-fence.v1','logicalOwnerScopeHash':previous['logicalOwnerScopeHash'],
   'reviewHash':'a'*64,'journalPath':str(f.installed.journal.root),'active':True}
  previous.update(schema='ouf.policy-token-governed-worker-session.v1',predecessorGrantAttempts=128,
   maximumCumulativeGrantAttempts=197,policy={**copy.deepcopy(previous['policy']),'max_attempts':69},
   fenceBinding={'path':str(fence),'value':old_value})
  old.update(attempts=60,publicationCount=60,controlledPredecessorGrantAttempts=128,controlledCumulativeGrantAttempts=188,
   workerSessionHash=fingerprint(previous),policyHash=fingerprint(previous['policy']))
  f.records['owner-status.json'].update(attempts=60,publications=60)
  for name,value in f.records.items():f.f.f.write(f.installed.journal.root/name,fixture.fixture.binding.encoded(value))
  f.before={name:(f.installed.journal.root/name).read_bytes()for name in f.records}
  f.f.f.write(fence,fixture.fixture.binding.encoded(old_value))
  profile=json.loads((Path(__file__).resolve().parents[1]/'releases/policy-token-test-session-profile-20261017.json').read_text())
  f.review.update(schema='ouf.chatbot-semantic-functional-session-review.v3',finiteTestProfile=profile,
   predecessorRecordHashes={k:fingerprint(v)for k,v in f.records.items()},predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']))
  f.review['proposedFiniteBudget'].update(priorControlledGrantAttempts=188,predecessorWorkerAttempts=60,
   maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=316)
  f.review['requiredOwnerDecision'].update(explicitNewTestBudgetRequired=True,newCumulativeCeilingRequiresFreshHumanDecision=True)
  f.f.f.write(f.review_path,fixture.fixture.binding.encoded(f.review))
  policy={**copy.deepcopy(previous['policy']),'max_attempts':128}
  scope=compile_governed_session(f.review,f.records,f.first,policy,
   fingerprint({'operation':f.review['logicalOperation'],'reviewHash':fingerprint(f.review)}),fingerprint(f.review['registryGeneration']),60)
  f.journal=Path(scope['fenceBinding']['value']['journalPath']);f.journal.mkdir(mode=0o700)
  f.sign(f.make().scopes());before=f.grants();installer=f.make();worker=installer.install()
  self.assertEqual(f.grants(),before)
  self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'],188)
  self.assertEqual(installer.worker_scope['maximumCumulativeGrantAttempts'],316)
  self.assertEqual(installer.worker_scope['predecessorCumulativeCeiling'],197)
  self.assertEqual(json.loads(fence.read_bytes()),installer.worker_scope['fenceBinding']['value'])
  row=worker.tick()
  self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['attempts'],1)
  self.assertEqual(row['controlledCumulativeGrantAttempts'],189);self.assertEqual(f.grants(),before+1)
  for name,raw in f.before.items():self.assertEqual((f.installed.journal.root/name).read_bytes(),raw)
  with self.assertRaises(Exception):f.make().install()
  self.assertEqual(f.grants(),before+1)
if __name__=='__main__':unittest.main()

