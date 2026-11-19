#!/usr/bin/env python3
"""Installation-specific readonly rollout bindings and terminated-worker reconciliation."""
import fcntl,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-execution-9xl_yy2c')
REVIEW='9e2d9aa969abe97feacd2f91b374d1c3fc6d7120b51c1f3c71ce04f68a6b23a6'
AUTHORITY='5a0ed5855aecfa9ed509839c7fa37398918c08ff6dd094fb4070f77e78f4e5c8'
JOURNAL=Path('/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-f9d572dde0b549b11f7a704e765e9568dbfef9525b58d085efcf0459ee158d84')
NAMES=('recovery.json','owner-session.json','owner-admission.json','owner-status.json')
def require(ok,reason):
 if not ok:raise ValueError(reason)
def emit(check,**data):
 print(json.dumps(dict(schema='ouf.ingestion-readiness-rollout-binding-read.v1',check=check,readOnly=True,
  credentialFilesRead=0,humanSessionStateRead=False,grantRequests=0,serviceMutations=0,gatewayWrites=0,
  automaticRestart=False,automaticRetry=False,budgetReset=False,completedTechnicalPhases=8,
  functionalMilestonesProven=1,**data),sort_keys=True),flush=True)
def source():
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 try:
  for part in BOOT.parts[1:-1]:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
   info=os.fstat(fds[-1]);require(info.st_uid==0 and not info.st_mode&0o022,'ROOT_SOURCE_ANCESTRY_REQUIRED')
  fds.append(os.open(BOOT.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]))
  info=os.fstat(fds[-1]);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1
   and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=131072,'PRIVATE_HELPER_REQUIRED')
  raw=os.read(fds[-1],131073)
  pin=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  require(len(raw)==info.st_size and pin(info)==pin(os.fstat(fds[-1])) and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'HELPER_DRIFT')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)
def main():
 require(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('READ_DEADLINE')));signal.alarm(45)
 ns={'__name__':'read_only_helper'};exec(compile(source(),'<verified-helper>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW'])
 binding=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](binding['path'],8388608,binding['sha256'])['prepared'];engine=prepared['engine']
 current={name:ns['engine_get'](engine,'containers',name)for name in ('ouf-onboarding','ouf-ingestion','ouf-apisix')}
 require(all(v is not None and v['State']['Running'] for v in current.values()),'REQUIRED_CURRENT_CONTAINERS_UNAVAILABLE')
 pins={name:ns['runtime_pin'](v)for name,v in current.items()}
 require(all(pins[name]==ns['runtime_pin'](ns['engine_get'](engine,'containers',name))for name in current),'RUNTIME_GENERATION_CHANGED')
 emit('RUNTIME_BINDINGS',generationStableAcrossReads=True,containers=[
  dict(name=name,binding=pins[name],sourceCommitLabel=(v['Config'].get('Labels')or{}).get('org.opencontainers.image.revision'))
  for name,v in current.items()])
 review=ns['read'](CONTEXT/'review.json',8388608,REVIEW);authority=ns['read'](CONTEXT/'authority.json',131072,AUTHORITY)
 require(review.get('kind')=='POLICY_TOKEN_REMAINDER','EXACT_REMAINDER_REVIEW_REQUIRED')
 session=review['scopes']['policyTokenFiniteWorkerSession']
 require(authority.get('policyTokenFiniteWorkerSession')==session and session.get('fenceBinding',{}).get('value',{}).get('journalPath')==str(JOURNAL),'SIGNED_WORKER_SCOPE_DRIFT')
 require(JOURNAL.resolve()==JOURNAL,'EXACT_WORKER_JOURNAL_REQUIRED')
 for parent in (JOURNAL,*JOURNAL.parents):
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'JOURNAL_ANCESTRY_DRIFT')
 fd=os.open(JOURNAL/'invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1
   and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==0,'LOCK_CUSTODY_REQUIRED')
  try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
  except BlockingIOError:raise ValueError('WORKER_INVOCATION_STILL_HELD')from None
  rows={name:ns['read'](JOURNAL/name,131072)for name in NAMES}
  require(rows=={name:ns['read'](JOURNAL/name,131072)for name in NAMES},'JOURNAL_CHANGED')
  row=rows['recovery.json'];last=rows['owner-status.json'];attempts=row.get('attempts');total=row.get('controlledCumulativeGrantAttempts')
  require(rows['owner-session.json']==session and row.get('workerSessionHash')==ns['digest'](session),'WORKER_SESSION_HASH_DRIFT')
  require(session.get('predecessorGrantAttempts')==128 and session.get('maximumCumulativeGrantAttempts')==197
   and session.get('policy',{}).get('max_attempts')==69 and row.get('controlledPredecessorGrantAttempts')==128
   and type(attempts)is int and 0<=attempts<=69 and type(total)is int and total==128+attempts<=197,'CUMULATIVE_WORKER_BUDGET_DRIFT')
  require(row.get('state')=='CANCELLED'and row.get('reason')=='CANCELLED_BY_OWNER'
   and last.get('state')==row['state']and last.get('reason')==row['reason']
   and last.get('attempts')==attempts and last.get('publications')==row.get('publicationCount')
   and rows['owner-admission.json'].get('state')=='BLOCKED','TERMINATED_WORKER_STATE_UNPROVEN')
  ns['read'](CONTEXT/'review.json',8388608,REVIEW);ns['read'](CONTEXT/'authority.json',131072,AUTHORITY)
  emit('TERMINATED_WORKER',state=row['state'],reason=row['reason'],attempts=attempts,
   publications=row['publicationCount'],priorControlledGrantAttempts=128,controlledCumulativeGrantAttempts=total,
   maximumCumulativeGrantAttempts=197,remainingControlledGrantAttempts=197-total,cumulativeCountProven=True,
   authorityExpiredAtRead=time.time()>=authority['expiresAt'],invocationLockUnheldAtRead=True,
   recordsStableAcrossReads=True,recordHashes={k:ns['digest'](v)for k,v in rows.items()})
 finally:os.close(fd)
 emit('END',complete=True,runtimeAuthorityIssued=False,reconciliationPerformed=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=45,maximumEngineReads=6,maximumDistinctJsonRecords=8)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)

