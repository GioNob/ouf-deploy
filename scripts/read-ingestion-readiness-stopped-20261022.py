CASE={'contextPath': '/etc/ouf/deploy-snapshots/ingestion-readiness-execution-21a26b94a94a69b138215affea313b59771bac170ab0e6bf37a443a2a1a4dfc9', 'nextStage': 8, 'readAttempts': 8, 'recordedExpiresAt': 1792664043.0, 'runtimeCaseHash': '21a26b94a94a69b138215affea313b59771bac170ab0e6bf37a443a2a1a4dfc9'}
"""Read-only reconciliation of one retained ISSUING/no-authority patch review.

No journal update, claim deletion, token read, signing, runtime or network call.
Only exact named metadata documents are read; output contains public bindings.
"""
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import signal
import stat
import sys

ROW='ouf.ingestion-readiness-patch-operator-control.v1'


def require(ok,code):
    if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def hashed(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None
def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def unique(pairs):
    value={}
    for key,item in pairs:require(key not in value,'DUPLICATE_UNISSUED_METADATA_FIELD');value[key]=item
    return value


class Directory:
    def __init__(self,path):
        p=PurePosixPath(path)
        require(type(path)is str and p.is_absolute()and str(p)==path and '..'not in p.parts,
            'EXACT_UNISSUED_DIRECTORY_PATH_REQUIRED')
        self.fds=[];self.pins=[]
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.fds.append(fd)
            for part in p.parts[1:]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                self.fds.append(child);s=os.fstat(child)
                require(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_UNISSUED_ANCESTRY_REQUIRED')
                self.pins.append((fd,part,child,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)));fd=child
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'PRIVATE_UNISSUED_CONTEXT_REQUIRED')
            self.fd=fd;self.check()
        except BaseException:self.close();raise
    def check(self):
        for parent,name,child,pin in self.pins:
            for s in (os.fstat(child),os.stat(name,dir_fd=parent,follow_symlinks=False)):
                require(pin==(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode),'UNISSUED_ANCESTRY_CHANGED')
    def close(self):
        for fd in reversed(self.fds):os.close(fd)
        self.fds=[]
    def names(self):
        names=[]
        with os.scandir(self.fd)as entries:
            for entry in entries:
                require(len(names)<64,'UNISSUED_DIRECTORY_MEMBER_BOUND_EXCEEDED');names.append(entry.name)
        return set(names)
    def read(self,name,maximum):
        require(type(name)is str and '/'not in name and name not in ('','.','..'),'EXACT_UNISSUED_MEMBER_REQUIRED')
        self.check();s=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'UNISSUED_MEMBER_CUSTODY_UNPROVEN')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
        try:
            pin=identity(s);require(identity(os.fstat(fd))==pin,'UNISSUED_MEMBER_CHANGED')
            parts=[];count=0
            while count<=maximum:
                raw=os.read(fd,min(65536,maximum+1-count))
                if not raw:break
                parts.append(raw);count+=len(raw)
            require(count==s.st_size and identity(os.fstat(fd))==pin
                ==identity(os.stat(name,dir_fd=self.fd,follow_symlinks=False)),'UNISSUED_MEMBER_CHANGED')
            raw=b''.join(parts);value=json.loads(raw,object_pairs_hook=unique,
                parse_constant=lambda _:require(False,'NONFINITE_UNISSUED_METADATA'))
            require(encoded(value)==raw,'CANONICAL_UNISSUED_METADATA_REQUIRED');self.check()
            return value,len(raw),pin
        finally:os.close(fd)


"""Read-only stopped patch metadata; no credentials, signing or service calls."""
import fcntl
import os
import stat
from pathlib import Path
import time


def inspect(case):
    require(type(case)is dict and set(case)=={'contextPath','runtimeCaseHash','nextStage','readAttempts','recordedExpiresAt'},
        'EXACT_STOPPED_PATCH_METADATA_CASE_REQUIRED')
    root=Path(case['contextPath']);require(root.name=='ingestion-readiness-execution-'+case['runtimeCaseHash']
        and hashed(case['runtimeCaseHash']),'EXACT_STOPPED_PATCH_CONTEXT_REQUIRED')
    dirs=[];locks=[]
    try:
        target=Directory(str(root));dirs.append(target)
        control=Directory(str(root/'operator-control'));dirs.append(control)
        parent=Directory(str(root.parent));dirs.append(parent)
        for directory in (control,target):
            fd=os.open('invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory.fd)
            locks.append(fd);info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'STOPPED_LOCK_CUSTODY_REQUIRED')
            fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        row,_,_=control.read('recovery.json',65536)
        native,_,_=target.read('recovery.json',4194304)
        review,_,_=target.read('review.json',2097152)
        require(row['schema']=='ouf.ingestion-readiness-patch-operator-control.v1'
            and row['caseHash']==case['runtimeCaseHash']and row['state']=='RECONCILE_REQUIRED'
            and row['complete']is False and row['budgetReset']is False
            and row['runtimeAuthorityIssued']is True,'EXACT_STOPPED_PATCH_CONTROL_REQUIRED')
        require(digest(review)==row['reviewHash']and review['authorityDirectory']==str(root)
            and review['operatorControlBinding']['caseHash']==case['runtimeCaseHash']
            and review['automaticReplayAllowed']is review['budgetReset']is False,
            'EXACT_RETAINED_STOPPED_REVIEW_REQUIRED')
        execution=review['executionReview'];scope=review['scopes']['ingestionReadinessPatch'];stages=execution['stages']
        require(execution['executionContext']==str(root)and scope['reviewHash']==digest(execution)
            and native['schema']=='ouf.ingestion-readiness-patch-finite-journal.v1'
            and native['scopeHash']==digest(scope)and native['budgetReset']is False,
            'SAME_RETAINED_PATCH_SCOPE_AND_NATIVE_JOURNAL_REQUIRED')
        n=native['nextStage'];effects=native['effects']
        require(type(n)is int and n==case['nextStage']and len(effects)==n and 0<n<len(stages)
            and native['readAttempts']==case['readAttempts']and native['readState']=='IDLE'
            and native['expiresAt']==case['recordedExpiresAt']
            and all(v['state']=='APPLIED'and v['stage']==stages[i]['name']and v['intentHash']==stages[i]['intentHash']
                for i,v in enumerate(effects)),'EXACT_APPLIED_PREFIX_NO_PENDING_STAGE_REQUIRED')
        authority,_,_=target.read('authority.json',131072)
        require(digest(authority)==native['authorityHash'],'SAME_RETAINED_NATIVE_AUTHORITY_HASH_REQUIRED')
        claim_name='ingestion-readiness-patch-'+execution['logicalOperationRef']+'.claim.json'
        claim,_,_=parent.read(claim_name,65536)
        require(claim=={'reviewHash':scope['reviewHash'],'authorityHash':native['authorityHash'],
            'context':str(root),'automaticReplayAllowed':False,'budgetReset':False},'SAME_PERSISTENT_NATIVE_CLAIM_REQUIRED')
        require(control.read('recovery.json',65536)[0]==row and target.read('recovery.json',4194304)[0]==native
            and target.read('review.json',2097152)[0]==review and parent.read(claim_name,65536)[0]==claim,
            'STOPPED_PATCH_CHANGED_DURING_READ')
        return {'schema':'ouf.ingestion-readiness-stopped-snapshot.v1',
            'status':'STOPPED_PATCH_PREFIX_RECONCILED_NO_AUTHORITY','complete':True,'readOnly':True,
            'contextPath':str(root),'runtimeCaseHash':case['runtimeCaseHash'],'controlState':row['state'],
            'reviewHash':row['reviewHash'],'controlJournalHash':digest(row),'nativeJournalHash':digest(native),
            'logicalOperationRef':execution['logicalOperationRef'],'prefixHash':digest(effects),
            'appliedStageCount':n,'nextStage':n,'nextStageName':stages[n]['name'],
            'remainingStages':[{'name':v['name'],'kind':v['kind']}for v in stages[n:]],
            'pendingStageClaim':False,'readAttempts':native['readAttempts'],'readState':native['readState'],
            'recordedExpiresAt':native['expiresAt'],'recordedWallSecondsRemaining':max(0,native['expiresAt']-time.time()),
            'liveRuntimeObserved':False,'roleSignaturesReverified':False,'providerAuthorizationReverified':False,
            'humanCredentialJournalsRead':0,'engineRequests':0,'databaseCalls':0,'oauthRequests':0,
            'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
            'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
    finally:
        for fd in reversed(locks):os.close(fd)
        for directory in reversed(dirs):directory.close()

try:
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_STOPPED_PATCH_READER_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_STOPPED_PATCH_READER_DEADLINE'));signal.alarm(60)
    print(encoded(inspect(CASE)).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
    reason=str(error)
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)is None:reason='STOPPED_PATCH_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED'
    print(encoded({'schema':'ouf.ingestion-readiness-stopped-snapshot.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'readOnly':True,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'oauthRequests':0}).decode(),flush=True)
    raise SystemExit(2)
