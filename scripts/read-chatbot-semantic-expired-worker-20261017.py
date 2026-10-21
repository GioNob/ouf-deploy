#!/usr/bin/env python3
"""Installation-specific, bounded readback of the retained expired token worker.
No credential/HUMAN journal reads, network, restart, or persistent writes.
"""
import fcntl, hashlib, json, os, re, signal, stat, sys, time
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
AUTHORITY='ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed'
REVIEW='3c5eab698b2ed59f5a454b6bf93a4eba54a8cea0198c968401e09ad8784d4c63'
JOURNAL=Path('/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803')
NAMES=('recovery.json','owner-session.json','owner-admission.json','owner-status.json')
STATES={'NEW','ACTIVE','RETRY_WAIT','PAUSED_EXHAUSTED','BLOCKED','RECONCILE_REQUIRED','CANCELLED','ATTEMPTING','PUBLISHING'}

def emit(check,**values):
    print(json.dumps(dict(schema='ouf.chatbot-semantic-expired-worker-readback.v1',
        check=check,readOnly=True,automaticRetry=False,automaticRestart=False,
        budgetReset=False,acceptanceGranted=False,**values),sort_keys=True),flush=True)

def projection(row,status=False):
    require(type(row)is dict and row.get('state')in STATES,'WORKER_STATE_INVALID')
    require(type(row.get('reason'))is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',row['reason']),
        'WORKER_REASON_INVALID')
    count=row.get('attempts');pub=row.get('publications'if status else 'publicationCount')
    require(type(count)is int and 0<=count<=128 and type(pub)is int and 0<=pub<=count,
        'WORKER_COUNTS_INVALID')
    return dict(state=row['state'],reason=row['reason'],attempts=count,publications=pub)

def validate(authority,records):
    require(authority.get('semanticTokenOnlyExecution',{}).get('reviewHash')==REVIEW,
        'EXACT_TOKEN_REVIEW_REQUIRED')
    signed=authority.get('policyTokenFiniteWorkerSession');row=records['recovery.json']
    require(type(signed)is dict and signed==records['owner-session.json']
        and signed.get('fenceBinding',{}).get('value',{}).get('journalPath')==str(JOURNAL),
        'EXACT_WORKER_SESSION_REQUIRED')
    require(row.get('workerSessionHash')==digest(signed),'WORKER_SESSION_HASH_DRIFT')
    require(signed.get('predecessorGrantAttempts')==69 and signed.get('maximumCumulativeGrantAttempts')==197
        and signed.get('policy',{}).get('max_attempts')==128
        and row.get('controlledPredecessorGrantAttempts')==69,'CONTROLLED_HISTORY_BINDING_DRIFT')
    projected=projection(row);total=row.get('controlledCumulativeGrantAttempts')
    require(type(total)is int and total==69+projected['attempts']<=197,'CONTROLLED_COUNT_DRIFT')
    require(type(authority.get('expiresAt'))is int and authority['expiresAt']==1792169238,
        'EXACT_AUTHORITY_EXPIRY_REQUIRED')
    last=projection(records['owner-status.json'],True)
    admission=records['owner-admission.json'].get('state')
    require(admission in ('ACTIVE','BLOCKED'),'ADMISSION_STATE_INVALID')
    return projected,last,total,admission

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site,
        'ROOT_ISOLATED_READBACK_REQUIRED')
    signal.alarm(30)
    emit('BEGIN',maximumSeconds=30,maximumDistinctJsonRecords=5,credentialFilesRead=0,
        humanSessionStateRead=False,grantRequests=0,databaseCalls=0,serviceMutations=0,mcpCalls=0)
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    # Opening an existing lock read-only and taking a nonblocking shared lock
    # never creates/truncates a file. An active native worker holds EX exclusively.
    require(JOURNAL.resolve()==JOURNAL,'EXACT_JOURNAL_PATH_REQUIRED')
    for parent in (JOURNAL,*JOURNAL.parents):
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,
            'JOURNAL_ANCESTRY_INVALID')
    require(stat.S_IMODE(JOURNAL.stat().st_mode)==0o700,'PRIVATE_JOURNAL_REQUIRED')
    path=JOURNAL/'invocation.lock';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==0,'INVOCATION_LOCK_CUSTODY_INVALID')
        try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError:raise ReadDenied('WORKER_INVOCATION_STILL_HELD')from None
        records={name:read(JOURNAL/name,131072)for name in NAMES}
        projected,last,total,admission=validate(authority,records)
        again={name:read(JOURNAL/name,131072)for name in NAMES}
        require(records==again and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),
            'WORKER_SNAPSHOT_DRIFT')
        read(CONTEXT/'authority.json',131072,AUTHORITY)
        emit('PERSISTED_WORKER',**projected,priorControlledGrantAttempts=69,
            controlledCumulativeGrantAttempts=total,cumulativeCountProven=True,
            maximumCumulativeGrantAttempts=197,recordsStableAcrossReads=True,
            invocationLockUnheldAtRead=True,liveStateProven=False,
            admissionState=admission,lastReportedStatus=last,
            lastReportedStatusMatchesJournal=last==projected,
            authorityExpiredAtRead=time.time()>=authority['expiresAt'],expiresAt=authority['expiresAt'],
            recordHashes={name:digest(value)for name,value in records.items()})
    finally:os.close(fd)
    emit('END',complete=True,completedTechnicalPhases=8,functionalMilestonesProven=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,humanSessionCumulativeBudgetProven=False,
        recordsMayChangeIndependently=True)

if __name__=='__main__':
    try:main()
    except ReadDenied as error:
        emit('STOP',reason=str(error),exceptionMessagePrinted=False);sys.exit(2)
    except Exception:
        emit('STOP',reason='LOCAL_READ_UNPROVEN',exceptionMessagePrinted=False);sys.exit(2)
