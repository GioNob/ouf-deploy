"""Exact 248+68=316 compiler and authority limits; no grants or target effects."""
import ast,copy,time,unittest
from pathlib import Path
import test_governed_semantic_session_contract as original
ROOT=Path(__file__).resolve().parents[1]
def require(ok,reason):
 if not ok:raise ValueError(reason)
def load_function(path,name):
 tree=ast.parse((ROOT/path).read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
 ns={'copy':copy,'time':time,'digest':original.fingerprint,'require':require}
 exec(compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec'),ns);return ns[name]
review_function=load_function(Path('tools/onboarding_audit_update/entry.py'),'remainder_worker_review')
validate=load_function(Path('tools/onboarding_audit_update/authority.py'),'scopes_valid')
def fixture():
 base,records,first,old_policy=original.fixture();previous=records['owner-session.json'];old=records['recovery.json']
 previous.update(schema=original.C['GOVERNED_SESSION'],predecessorGrantAttempts=188,maximumCumulativeGrantAttempts=316,
  fenceBinding={'path':'/fixture/session-parent/semantic-functional-session-'+('5'*64)+'.fence.json','value':{'logicalOwnerScopeHash':'5'*64,'active':True,'journalPath':'/fixture/session-parent/old-worker'}})
 old.update(attempts=60,publicationCount=60,controlledPredecessorGrantAttempts=188,controlledCumulativeGrantAttempts=248,workerSessionHash=original.fingerprint(previous))
 review=review_function(base,records,'/fixture/session-parent/old-worker');policy={**old_policy,'max_attempts':68}
 worker=original.C['compile_governed_session'](review,records,first,policy,'7'*64,'8'*64,60)
 return review,records,first,worker

def scopes(worker,closure_hash):
 owner={'sourceClosureHash':closure_hash,'workerSessionScopeHash':original.fingerprint(worker),'ownerBindingHash':'9'*64,
  'operation':'INSTALL_TOKEN_ONLY_GOVERNED_CONTINUATION_NO_FIRST_GRANT','initializeJournalOnlyIfAbsent':True,'automaticReplayAllowed':False,'applicationAcceptanceGranted':False}
 return {'policyTokenOwnerInstallation':owner,'policyTokenFiniteWorkerSession':worker,
  'tokenOwnerRuntime':{'ownerBindingHash':'9'*64,'operation':'RENEW_EXISTING_POLICY_READ_CREDENTIAL','automaticBudgetResetAllowed':False,'legacyWriterMustBeMasked':True,'credentialReestablishmentRequired':True},
  'semanticFunctionalRuntime':{'reviewHash':worker['reviewHash']}}

class Remainder(unittest.TestCase):
 def test_real_compiler_preserves248_and_same316_ceiling_with68_residual(self):
  review,records,first,worker=fixture();self.assertEqual(worker['predecessorGrantAttempts'],248);self.assertEqual(worker['maximumCumulativeGrantAttempts'],316);self.assertEqual(worker['policy']['max_attempts'],68)
  self.assertEqual(records['recovery.json']['attempts'],60);self.assertEqual(first['attemptSlotsConsumed'],1)
  self.assertFalse(worker['consumedClaimReplayAllowed']);self.assertFalse(worker['automaticBudgetRenewalAllowed'])
  self.assertEqual(worker['predecessorFenceBinding'],records['owner-session.json']['fenceBinding'])
  validate('POLICY_TEST_SESSION',scopes(worker,'a'*64),'a'*64)
 def test_changed_cumulative_count_or_nonterminal_predecessor_is_rejected(self):
  review,records,first,worker=fixture()
  for change in ({'controlledCumulativeGrantAttempts':249},{'state':'ACTIVE'},{'attempts':59},{'publicationCount':59}):
   changed=copy.deepcopy(records);changed['recovery.json'].update(change)
   with self.assertRaises(ValueError):review_function(review,changed,'/fixture/session-parent/old-worker')
 def test_scope_widening_replay_and_budget_reset_are_rejected(self):
  _,_,_,worker=fixture()
  for section,key,value in [('policyTokenFiniteWorkerSession','maximumCumulativeGrantAttempts',317),('policyTokenFiniteWorkerSession','predecessorGrantAttempts',247),('tokenOwnerRuntime','automaticBudgetResetAllowed',True),('tokenOwnerRuntime','operation','OTHER_OPERATION'),('policyTokenOwnerInstallation','automaticReplayAllowed',True),('semanticFunctionalRuntime','reviewHash','b'*64)]:
   changed=copy.deepcopy(scopes(worker,'a'*64));changed[section][key]=value
   with self.assertRaises(ValueError):validate('POLICY_TEST_SESSION',changed,'a'*64)
 def test_policy_above68_and_wrong_profile_cannot_be_signed(self):
  _,_,_,worker=fixture()
  for change in ({'max_attempts':69},{'max_elapsed':3601},{'jitter':0}):
   changed=copy.deepcopy(scopes(worker,'a'*64));changed['policyTokenFiniteWorkerSession']['policy'].update(change)
   with self.assertRaises(ValueError):validate('POLICY_TEST_SESSION',changed,'a'*64)
 def test_active248_snapshot_matches_signed_successor_scope(self):
  _,_,_,worker=fixture();read=load_function(Path('tools/onboarding_audit_update/entry.py'),'read_active_publication')
  class Journal:
   def private_read(self):return {'workerSessionHash':original.fingerprint(worker),'state':'ACTIVE','attempts':1,'controlledPredecessorGrantAttempts':248,'controlledCumulativeGrantAttempts':249,'publicationCount':1,'tokenExpiresWall':1300.,'lastWall':999.}
  self.assertEqual(read(Journal(),worker,lambda:None,clock=lambda:1000.,monotonic=lambda:1000.,wait=lambda _:self.fail('no wait'),jitter=lambda:0.5)['controlledCumulativeGrantAttempts'],249)
if __name__=='__main__':unittest.main()
