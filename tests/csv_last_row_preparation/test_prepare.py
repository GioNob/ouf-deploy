import importlib.util,copy,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('prepare',ROOT/'scripts/prepare-csv-last-row-recovery-20261018.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class NativeScope(unittest.TestCase):
 def fixture(self):
  policy={'delays':[5,15,60,300,900],'max_attempts':127,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
  parent=Path('/etc/ouf/deploy-snapshots/fixture');journal=parent/'semantic-functional-worker-fixture';logical='c'*64
  first={'state':'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED','attemptSlotsConsumed':1,'gapRemainsOpen':True,'historicalAccountingReconciled':False,'legacyHistoricalGrantAttempts':None,'operation':'first','scopeHash':'scope','bootId':'boot'}
  session={'schema':'ouf.policy-token-governed-worker-session.v1','predecessorGrantAttempts':317,'maximumCumulativeGrantAttempts':444,'policy':policy,'contextRef':'a'*64,'generationRef':'b'*64,'logicalOwnerScopeHash':logical,'predecessorFirstGrantOperation':'first','predecessorFirstGrantScopeHash':'scope','fenceBinding':{'path':str(parent/('semantic-functional-session-'+logical+'.fence.json')),'value':{'journalPath':str(journal),'logicalOwnerScopeHash':logical,'active':True}}}
  old={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':1,'publicationCount':1,'controlledPredecessorGrantAttempts':317,'controlledCumulativeGrantAttempts':318,'workerSessionHash':m.digest(session),'policyHash':m.digest(policy),'contextRef':'a'*64,'generationRef':'b'*64,'firstGrantReceiptHash':m.digest(first),'bootId':'boot','legacyHistory':{'state':'UNKNOWN','cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True}}
  records={'recovery.json':old,'owner-session.json':session,'owner-admission.json':{'state':'BLOCKED'},'owner-status.json':{}}
  base={'proposedFiniteBudget':{'maximumSeconds':3600,'renewalIntervalSeconds':60,'automaticRenewalAllowed':False},'requiredOwnerDecision':{'explicitContinuationAfterOwnerCancellationRequired':True,'freshAuthenticatedHumanDecisionRequired':True,'newJournalAndPersistentFencingRequired':True},'requestedHumanActor':{'subject':'fixture'},'commandKey':'fixture','proposalHash':'fixture'}
  return base,records,first,journal
 def compile(self):
  return m.native_compiler((ROOT/'tools/semantic_policy_token_owner/installed_owner.py').read_bytes())
 def test_existing_native_compiler_preserves318_and444_without_budget_increase(self):
  base,records,first,journal=self.fixture();before=copy.deepcopy(records)
  review=m.successor_review(base,records,journal,1);policy=copy.deepcopy(records['owner-session.json']['policy']);policy['max_attempts']=126
  result=self.compile()(review,records,first,policy,'d'*64,'e'*64,60)
  self.assertEqual(result['predecessorGrantAttempts'],318);self.assertEqual(result['maximumCumulativeGrantAttempts'],444)
  self.assertEqual(result['policy']['max_attempts'],126);self.assertFalse(result['automaticBudgetRenewalAllowed'])
  self.assertIn('predecessorFenceBinding',result);self.assertEqual(records,before)
 def test_cancelled_scope_cannot_be_reused_as_live_authority(self):
  base,records,first,journal=self.fixture();records['recovery.json']['state']='ACTIVE'
  with self.assertRaisesRegex(ValueError,'EXACT_CANCELLED_WORKER_HISTORY_REQUIRED'):m.successor_review(base,records,journal,1)
 def test_modified_counts_and_admission_are_rejected(self):
  for key,value in [('controlledCumulativeGrantAttempts',317),('controlledPredecessorGrantAttempts',316),('publicationCount',0)]:
   base,records,first,journal=self.fixture();records['recovery.json'][key]=value
   with self.assertRaises(ValueError):m.successor_review(base,records,journal,1)
  base,records,first,journal=self.fixture();records['owner-admission.json']['state']='ACTIVE'
  with self.assertRaises(ValueError):m.successor_review(base,records,journal,1)
 def test_native_compiler_input_hash_cannot_be_substituted(self):
  with self.assertRaisesRegex(ValueError,'NATIVE_COMPILER_SOURCE_CHANGED'):m.native_compiler(b'PRIVATE_INJECTED_CODE')
 def test_native_compiler_rejects_changed_first_grant_and_legacy_history(self):
  base,records,first,journal=self.fixture();review=m.successor_review(base,records,journal,1);policy=copy.deepcopy(records['owner-session.json']['policy']);policy['max_attempts']=126;first['attemptSlotsConsumed']=0
  with self.assertRaises(ValueError):self.compile()(review,records,first,policy,'d'*64,'e'*64,60)
 def test_only_exact_reviewed_job_is_eligible_for_preparation(self):
  row=copy.deepcopy(m.CASE['job']);facts={'selectedJobCount':1,'jobs':[row]}
  self.assertEqual(m.exact_job(facts),row)
  for key,value in [('state_version',12),('binding_count',1),('source_id','other'),('latest_action','APPROVE')]:
   changed=copy.deepcopy(row);changed[key]=value
   with self.assertRaises(ValueError):m.exact_job({'selectedJobCount':1,'jobs':[changed]})
 def test_readiness_is_never_runtime_authority(self):
  import contextlib,io
  with contextlib.redirect_stdout(io.StringIO())as out:m.emit('PREPARATION',readyForExecution=False,runtimeAuthorityIssued=False)
  value=json.loads(out.getvalue());self.assertFalse(value['runtimeAuthorityIssued']);self.assertTrue(value['runtimeReadOnly']);self.assertTrue(value['preparationOnly'])
  self.assertEqual(value['jobsRetried'],0);self.assertEqual(value['oauthRequests'],0)
if __name__=='__main__':unittest.main()
