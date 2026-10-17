"""Pure new-test-budget contract; runtime authority remains a separate signed HUMAN action."""
import copy,json,unittest
from pathlib import Path
from test_governed_semantic_session_contract import fixture,compile_fixture,fingerprint

def renewed():
 review,records,first,policy=fixture()
 session=records['owner-session.json'];old=records['recovery.json']
 session.update(schema='ouf.policy-token-governed-worker-session.v1',predecessorGrantAttempts=128,
  maximumCumulativeGrantAttempts=197,policy={**copy.deepcopy(policy),'max_attempts':69},
  fenceBinding={'path':'/fixture/session-parent/semantic-functional-session-'+session['logicalOwnerScopeHash']+'.fence.json','value':{
   'logicalOwnerScopeHash':session['logicalOwnerScopeHash'],'journalPath':review['predecessorJournalDirectory'],
   'reviewHash':'a'*64,'active':True}})
 old.update(attempts=60,controlledPredecessorGrantAttempts=128,controlledCumulativeGrantAttempts=188,
  workerSessionHash=fingerprint(session),policyHash=fingerprint(session['policy']))
 profile=json.loads((Path(__file__).resolve().parents[1]/'releases/policy-token-test-session-profile-20261017.json').read_text())
 review.update(schema='ouf.chatbot-semantic-functional-session-review.v3',finiteTestProfile=profile,
  predecessorFenceBinding=copy.deepcopy(session['fenceBinding']),
  predecessorRecordHashes={k:fingerprint(v)for k,v in records.items()})
 review['proposedFiniteBudget'].update(priorControlledGrantAttempts=188,predecessorWorkerAttempts=60,
  maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=316)
 review['requiredOwnerDecision'].update(explicitNewTestBudgetRequired=True,newCumulativeCeilingRequiresFreshHumanDecision=True)
 return review,records,first,policy

class TestBudget(unittest.TestCase):
 def test_new128_retains188_and_original197_ceiling_without_mutating_history(self):
  f=renewed();before=copy.deepcopy(f);scope=compile_fixture(f)
  self.assertEqual(f,before);self.assertEqual(scope['predecessorGrantAttempts'],188)
  self.assertEqual(scope['maximumCumulativeGrantAttempts'],316)
  self.assertEqual(scope['predecessorCumulativeCeiling'],197)
  self.assertEqual(scope['testBudgetProfileHash'],fingerprint(f[0]['finiteTestProfile']))
  self.assertEqual(scope['predecessorFenceBinding'],f[1]['owner-session.json']['fenceBinding'])
  self.assertFalse(scope['automaticBudgetRenewalAllowed']);self.assertFalse(scope['consumedClaimReplayAllowed'])
 def test_original_remainder_contract_does_not_silently_increase_its_ceiling(self):
  f=renewed();f[0]['schema']='ouf.chatbot-semantic-functional-session-review.v2'
  with self.assertRaises(ValueError):compile_fixture(f)
 def test_fresh_explicit_test_budget_and_exact_profile_are_required(self):
  for key in ('explicitNewTestBudgetRequired','newCumulativeCeilingRequiresFreshHumanDecision'):
   f=renewed();f[0]['requiredOwnerDecision'][key]=False
   with self.subTest(key=key),self.assertRaises(ValueError):compile_fixture(f)
  for key,value in [('maximumNewTokenGrantAttempts',True),('maximumSeconds',3601),('automaticRenewalAllowed',True),('preserveCumulativeHistory',False)]:
   f=renewed();f[0]['finiteTestProfile'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):compile_fixture(f)
 def test_wrong_counts_hashes_fence_and_inherited_approval_are_denied(self):
  for target,key,value in [('budget','maximumCumulativeGrantAttempts',317),('budget','priorControlledGrantAttempts',0),('review','humanApprovalGranted',True)]:
   f=renewed();obj=f[0]['proposedFiniteBudget']if target=='budget'else f[0];obj[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):compile_fixture(f)
  f=renewed();f[0]['predecessorFenceBinding']['value']['active']=False
  with self.assertRaises(ValueError):compile_fixture(f)
  f=renewed();f[1]['recovery.json']['attempts']=0
  with self.assertRaises(ValueError):compile_fixture(f)
if __name__=='__main__':unittest.main()

