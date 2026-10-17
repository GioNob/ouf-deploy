"""No widening of the new generic test worker scope or predecessor history."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.csv_materialization_recovery import authority
import test_teatri_policy_restore_remainder as remainder
from tools.teatri_recovery_review.entry import worker_review

class Authority(unittest.TestCase):
 def test_exact316_to444_only_without_permission_or_database_scope(self):
  base,records,first,worker=remainder.fixture();records['owner-session.json']=worker;f=remainder.original.fingerprint
  records['recovery.json'].update(attempts=8,publicationCount=8,controlledPredecessorGrantAttempts=308,
   controlledCumulativeGrantAttempts=316,workerSessionHash=f(worker),policyHash=f(worker['policy']),contextRef=worker['contextRef'],generationRef=worker['generationRef'])
  review=worker_review(base,records,worker['fenceBinding']['value']['journalPath'])
  worker=remainder.original.C['compile_governed_session'](review,records,first,{**worker['policy'],'max_attempts':128},'7'*64,'8'*64,60)
  scopes=remainder.scopes(worker,'a'*64);authority.scopes_valid('POLICY_TEST_SESSION',scopes,'a'*64)
  for section,key,value in [('policyTokenFiniteWorkerSession','maximumCumulativeGrantAttempts',445),('policyTokenFiniteWorkerSession','predecessorGrantAttempts',315),('tokenOwnerRuntime','automaticBudgetResetAllowed',True),('policyTokenOwnerInstallation','automaticReplayAllowed',True)]:
   changed=copy.deepcopy(scopes);changed[section][key]=value
   with self.assertRaises(Exception):authority.scopes_valid('POLICY_TEST_SESSION',changed,'a'*64)
  with self.assertRaises(Exception):authority.scopes_valid('POLICY_TEST_SESSION',{**scopes,'databaseWrite':{}},'a'*64)
