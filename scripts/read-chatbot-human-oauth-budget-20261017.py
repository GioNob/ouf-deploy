#!/usr/bin/env python3
"""Installation-specific safe projection of the retained HUMAN OAuth budget.
The existing private journal contains credentials. Never emit its raw fields,
bearers, device codes, refresh responses, or hashes of credential-bearing rows.
No login, network, reset, file creation, or service mutation.
"""
import fcntl,hashlib,json,math,os,re,signal,stat,sys,time
from pathlib import Path


class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def unique(rows):
    d={}
    for k,v in rows:require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
    return d

def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'READ_DRIFT')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'READ_HASH_DRIFT')
        return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)


CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem')
HUMAN=CONTEXT/'human-session-window2'
BOOT_FILE=Path('/proc/sys/kernel/random/boot_id')
AUTHORITY='ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed'
REVIEW='3c5eab698b2ed59f5a454b6bf93a4eba54a8cea0198c968401e09ad8784d4c63'
STATES={'NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'}
OPERATIONS={'DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO','REFRESH'}

def emit(check,**values):
 print(json.dumps(dict(schema='ouf.chatbot-human-oauth-budget-readback.v1',check=check,
  readOnly=True,automaticRetry=False,automaticRenewal=False,budgetReset=False,
  acceptanceGranted=False,**values),sort_keys=True),flush=True)

def project(authority,row,now,mono,boot):
 require(authority.get('semanticTokenOnlyExecution',{}).get('reviewHash')==REVIEW,
  'EXACT_TOKEN_AUTHORITY_REQUIRED')
 binding=row.get('binding');require(type(binding)is dict,'EXACT_HUMAN_BINDING_REQUIRED')
 require(authority['semanticTokenOnlyExecution'].get('humanSessionHash')==digest(binding)
  and binding.get('sessionDirectory')==str(HUMAN)and binding.get('tokenPath')==str(HUMAN/'human-access.jwt')
  and binding.get('clientId')=='ouf-human-admin'
  and binding.get('subject')=='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500', 'HUMAN_SESSION_BINDING_DRIFT')
 require(row.get('schema')=='ouf.chatbot-human-session.private.v1'and row.get('budgetReset')is False,
  'EXACT_RETAINED_HUMAN_JOURNAL_REQUIRED')
 receipt=row.get('governedWindowRenewal',{});review=receipt.get('review',{});decision=receipt.get('decision',{})
 require(review.get('priorOAuthAttempts')==42 and review.get('maximumCumulativeOAuthAttempts')==128
  and review.get('predecessorDirectory')==str(CONTEXT/'human-session')
  and decision.get('reviewHash')==digest(review)
  and decision.get('approvedAt')==binding.get('createdAt')
  and decision.get('expiresAt')==binding.get('expiresAt'),'OAUTH_RENEWAL_HISTORY_DRIFT')
 count=row.get('attempts');expiry=binding.get('expiresAt');deadline=row.get('monotonicDeadline')
 require(type(count)is int and 42<=count<=128 and type(expiry)is int
  and type(deadline)in(int,float)and math.isfinite(deadline)and deadline>0,
  'FINITE_OAUTH_COUNTS_AND_WINDOW_REQUIRED')
 state=row.get('state');operation=row.get('operation');require(state in STATES,'HUMAN_STATE_INVALID')
 if operation is not None:require(operation in OPERATIONS,'HUMAN_OPERATION_INVALID')
 require(type(row.get('bootId'))is str and re.fullmatch('[0-9a-f-]{36}',row['bootId']), 'BOOT_BINDING_INVALID')
 ambiguous=state=='REQUESTING'and operation not in('DISCOVERY','USERINFO')
 return {'state':state,'operation':operation,'attempts':count,'priorOAuthAttempts':42,
  'maximumCumulativeOAuthAttempts':128,'remainingOAuthAttempts':128-count,
  'expiredAtRead':now>=expiry,'expiresAt':expiry,'sameBoot':row['bootId']==boot,
  'monotonicExpired':row['bootId']==boot and mono>=deadline,
  'ambiguousRequestObserved':ambiguous,'blockedStateObserved':state=='BLOCKED',
  'newLoginAuthorized':False,'runtimeAuthorityIssued':False,'humanSessionCumulativeBudgetProven':True}

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site,'ROOT_ISOLATED_READBACK_REQUIRED')
 signal.alarm(30)
 emit('BEGIN',maximumSeconds=30,maximumDistinctJsonRecords=2,credentialBearingJournalsReadMaximum=1,
  bearerFilesRead=0,credentialValuesPrinted=False,grantRequests=0,iamCalls=0,mcpCalls=0,
  databaseCalls=0,serviceMutations=0)
 authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
 path=HUMAN/'invocation.lock'
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,
   'PRIVATE_HUMAN_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0
   and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size==0,'HUMAN_LOCK_CUSTODY_INVALID')
  try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
  except BlockingIOError:raise ReadDenied('HUMAN_INVOCATION_STILL_HELD')from None
  row=read(HUMAN/'recovery.json',65536)
  boot=BOOT_FILE.read_text().strip()
  result=project(authority,row,time.time(),time.monotonic(),boot)
  require(row==read(HUMAN/'recovery.json',65536)
   and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),'HUMAN_JOURNAL_CHANGED_DURING_READ')
  read(CONTEXT/'authority.json',131072,AUTHORITY)
  emit('PERSISTED_HUMAN_BUDGET',**result,recordsStableAcrossReads=True,invocationLockUnheldAtRead=True,
   credentialBearingJournalsRead=1,bearerFilesRead=0,credentialValuesPrinted=False)
 finally:os.close(fd)
 emit('END',complete=True,reconciliationPerformed=False,completedTechnicalPhases=8,functionalMilestonesProven=0)

if __name__=='__main__':
 try:main()
 except ReadDenied as error:emit('STOP',reason=str(error),exceptionMessagePrinted=False);sys.exit(2)
 except Exception:emit('STOP',reason='LOCAL_HUMAN_READ_UNPROVEN',exceptionMessagePrinted=False);sys.exit(2)
