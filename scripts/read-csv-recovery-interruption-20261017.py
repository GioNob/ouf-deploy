"""Bounded readback of the exact zero-attempt CSV recovery interruption."""
import fcntl,hashlib,json,os,stat,time
from pathlib import Path
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_SHA='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/csv-materialization-recovery-grdk3ael')
WORKER=Path('/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-2af1928d087c14a1215b19e34ea916ea28fcf91a3426caf6ab326bf4d0491fd6')
def require(ok):
 if not ok:raise ValueError('EXACT_INTERRUPTED_CONTEXT_REQUIRED')
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def main():
 require(os.geteuid()==os.getegid()==0)
 raw=BOOT.read_bytes();require(hashlib.sha256(raw).hexdigest()==BOOT_SHA)
 ns={'__name__':'verified_interruption_reader'};exec(compile(raw,'<verified-interruption-reader>','exec'),ns)
 read=ns['read'];review=read(CONTEXT/'review.json',8388608);authority=read(CONTEXT/'authority.json',131072)
 decision=read(CONTEXT/'decision.json',131072)
 require(review['authorityDirectory']==str(CONTEXT)and review['kind']=='POLICY_TEST_SESSION'
  and review['sourceClosure']['declaration']['sourceCommit']=='61f4d977756a0c9622124af763f064dda79ef4a5'
  and decision['reviewHash']==digest(review))
 names=('recovery.json','owner-session.json','owner-admission.json','owner-status.json','owner-session-review.json','owner-first-grant.json')
 rows={name:read(WORKER/name,131072)for name in names}
 session=rows['owner-session.json'];recovery=rows['recovery.json'];fence=session['fenceBinding']
 require(session==authority['policyTokenFiniteWorkerSession']==review['scopes']['policyTokenFiniteWorkerSession']
  and fence['value']['journalPath']==str(WORKER)
  and session['reviewHash']=='2af1928d087c14a1215b19e34ea916ea28fcf91a3426caf6ab326bf4d0491fd6')
 live_fence=read(Path(fence['path']),16384)
 fd=os.open(WORKER/'invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600)
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);unheld=True
  except BlockingIOError:unheld=False
 finally:os.close(fd)
 stable=all(read(WORKER/name,131072)==value for name,value in rows.items())
 print(json.dumps({'schema':'ouf.csv-recovery-interruption-read.v1','readOnly':True,'complete':True,
  'contextPath':str(CONTEXT),'state':recovery['state'],'reason':recovery['reason'],
  'attempts':recovery['attempts'],'publications':recovery['publicationCount'],
  'prior':recovery['controlledPredecessorGrantAttempts'],'cumulative':recovery['controlledCumulativeGrantAttempts'],
  'maximumCumulativeGrantAttempts':session['maximumCumulativeGrantAttempts'],
  'scopeMatchesSignedAuthority':True,'fenceMatchesThisSession':live_fence==fence['value'],
  'invocationLockUnheld':unheld,'recordsStable':stable,'authorityExpiredAtRead':time.time()>=decision['expiresAt'],
  'recordHashes':{name:digest(value)for name,value in rows.items()},
  'reviewHash':digest(review),'authorityHash':digest(authority),
  'grantRequests':0,'jobsRetriedByReader':0,'credentialFilesRead':0,'serviceMutations':0,
  'automaticRestart':False,'budgetReset':False},sort_keys=True))
if __name__=='__main__':main()
