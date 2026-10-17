"""Prepare a bounded successor from an exactly reconciled zero-attempt session.

No grant, fence advance or mutation of predecessor records happens here. The
native v2 compiler retains the existing cumulative ceiling, rather than issuing
another test-budget increase. Installation still needs fresh exact consent.
"""
import copy,fcntl,os,stat,time
from pathlib import Path
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.teatri_materialization_apply.owner import require,digest

def review_after_zero(base,records,journal):
 old=records['recovery.json'];previous=records['owner-session.json']
 require(old['state']=='CANCELLED'and old['reason']=='CANCELLED_BY_OWNER'
  and old['attempts']==old['publicationCount']==0
  and old['controlledPredecessorGrantAttempts']==old['controlledCumulativeGrantAttempts']==316
  and old['workerSessionHash']==digest(previous)and previous['predecessorGrantAttempts']==316
  and previous['maximumCumulativeGrantAttempts']==444 and records['owner-admission.json']['state']=='BLOCKED',
  'EXACT_CANCELLED_ZERO_ATTEMPT316_OF444_REQUIRED')
 review=copy.deepcopy(base);review.update(schema='ouf.chatbot-semantic-functional-session-review.v2',preparedAt=int(time.time()),
  predecessorRecordHashes={name:digest(value)for name,value in records.items()},
  predecessorJournalDirectory=str(journal),predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']),
  runtimeAuthorityIssued=False,humanApprovalGranted=False,readyForExecution=False)
 review.pop('finiteTestProfile',None)
 review['proposedFiniteBudget'].update(priorControlledGrantAttempts=316,predecessorWorkerAttempts=0,
  maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=444)
 review['requiredOwnerDecision'].pop('explicitNewTestBudgetRequired',None)
 review['requiredOwnerDecision'].pop('newCumulativeCeilingRequiresFreshHumanDecision',None)
 return review

def prepare(plan,selected,read):
 root=Path(selected['contextPath']);journal=Path(selected['workerJournal'])
 approved=read(root/'review.json',8388608,selected['reviewHash'])
 issued=read(root/'authority.json',131072,selected['authorityHash'])
 require(approved['authorityDirectory']==str(root)and approved['scopes']['policyTokenFiniteWorkerSession']==issued['policyTokenFiniteWorkerSession'],
  'EXACT_RECONCILED_INTERRUPTED_AUTHORITY_REQUIRED')
 names=('recovery.json','owner-session.json','owner-admission.json','owner-status.json')
 records={name:read(journal/name,131072,selected['recordHashes'][name])for name in names}
 require(records['owner-session.json']==issued['policyTokenFiniteWorkerSession'], 'EXACT_INTERRUPTED_WORKER_SCOPE_REQUIRED')
 base=read(journal/'owner-session-review.json',131072,selected['recordHashes']['owner-session-review.json'])
 first=read(journal/'owner-first-grant.json',16384,selected['recordHashes']['owner-first-grant.json'])
 require(base==plan['workerReview']and records['owner-session.json']==plan['workerScope'], 'INTERRUPTED_SESSION_MUST_MATCH_ORIGINAL_PREPARATION')
 require(not any((root/name).exists()for name in('native-retry-review.json','native-retry-decision.json','materialization-proof.json')),
  'INTERRUPTED_SESSION_MUST_PRECEDE_NATIVE_RETRY')
 fd=os.open(journal/'invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,
   'NATIVE_INVOCATION_LOCK_CUSTODY_REQUIRED')
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  future=review_after_zero(base,records,journal)
  prior=records['owner-session.json']['fenceBinding']
  require(read(Path(prior['path']),16384)==prior['value'],'CURRENT_RECONCILED_FENCE_REQUIRED')
  require(all(read(journal/name,131072,selected['recordHashes'][name])==value for name,value in records.items()),
   'RECONCILED_RECORDS_CHANGED')
 finally:os.close(fd)
 policy=copy.deepcopy(records['owner-session.json']['policy'])
 compiled=compile_governed_session(future,records,first,policy,
  digest({'operation':future['logicalOperation'],'reviewHash':digest(future)}),digest(future['registryGeneration']),60)
 require(compiled['predecessorGrantAttempts']==316 and compiled['maximumCumulativeGrantAttempts']==444,
  'EXISTING_CUMULATIVE_CEILING_MUST_BE_PRESERVED')
 result=copy.deepcopy(plan);result.update(workerReview=future,workerScope=compiled)
 return result
