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


def inspect(case):
    require(os.geteuid()==os.getegid()==0,'ROOT_UNISSUED_INSPECTION_REQUIRED')
    require(type(case)is dict and set(case)=={'schema','runtimeCase','reviewHash','reviewBytes','packetBytes'}
        and case['schema']=='ouf.ingestion-readiness-unissued-reconcile-case.v1'
        and hashed(case['reviewHash'])and type(case['reviewBytes'])is type(case['packetBytes'])is int,
        'EXACT_UNISSUED_RECONCILIATION_CASE_REQUIRED')
    runtime=case['runtimeCase'];case_hash=digest(runtime);logical=runtime['logicalOperationRef']
    require(runtime['schema']=='ouf.ingestion-readiness-patch-control-case.v1'and hashed(logical),
        'EXACT_STOPPED_PATCH_CASE_REQUIRED')
    context=runtime['snapshotRoot']+'/ingestion-readiness-execution-'+case_hash
    dirs=[];lock=None
    try:
        root=Directory(runtime['snapshotRoot']);dirs.append(root)
        target=Directory(context);dirs.append(target)
        control=Directory(context+'/operator-control');dirs.append(control)
        require(control.names()=={'recovery.json','recovery.lock','invocation.lock'},'UNISSUED_CONTROL_EXTRA_MEMBERS')
        lock=os.open('invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=control.fd)
        s=os.fstat(lock)
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1,'UNISSUED_INVOCATION_LOCK_CUSTODY_REQUIRED')
        fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        expected_names={'review.json','packet.json','material.json','human-profile.json','operator-control'}
        require(target.names()==expected_names,'UNISSUED_CONTEXT_HAS_AUTHORITY_OR_OTHER_MEMBERS')
        row,_,row_pin=control.read('recovery.json',65536)
        require(row.get('schema')==ROW and row.get('caseHash')==case_hash and row.get('state')=='ISSUING'
            and row.get('complete')is False and row.get('budgetReset')is False
            and row.get('runtimeAuthorityIssued')is False and hashed(row.get('decisionHash'))
            and row.get('reviewHash')==case['reviewHash'],'EXACT_STOPPED_ISSUING_CONTROL_REQUIRED')
        review,review_size,review_pin=target.read('review.json',2097152)
        packet,packet_size,packet_pin=target.read('packet.json',4194304)
        material,_,material_pin=target.read('material.json',4194304)
        binding={'caseHash':case_hash,'controlSourceHash':runtime['controlSourceHash'],
            'nativeInputsHash':runtime['nativeInputsHash'],'modeContract':'EXPLICIT_ONE_PATCH_STAGE_NO_REPLAY_V1'}
        require(digest(review)==row['reviewHash'] and digest(packet)==row['packetHash']==review['packetHash']
            and digest(material)==row['materialHash'] and review_size==case['reviewBytes']
            and packet_size==case['packetBytes'],'EXACT_STOPPED_DOCUMENTS_AND_REPORTED_SIZES_REQUIRED')
        require(material['caseHash']==case_hash and material['nativeInputsHash']==runtime['nativeInputsHash']
            and material['operatorControlBinding']==review['operatorControlBinding']==binding
            and material['sourceClosure']==review['sourceClosure']
            and digest(material['sourceClosure']['declaration'])==runtime['nativeDeclarationHash']
            and review['authorityDirectory']==context
            and review['executionReview']['executionContext']==context
            and review['executionReview']['logicalOperationRef']==logical
            and review['executionReview']['preparedInputsHash']==digest(packet['nativeInputs'])==runtime['nativeInputsHash']
            and digest(review['executionReview']['humanReadProfile'])==material['humanProfileHash'],
            'SAME_STOPPED_REVIEW_PACKET_SOURCE_AND_LOGICAL_OPERATION_REQUIRED')
        claim_name='ingestion-readiness-review-'+logical+'.claim.json'
        claim,_,claim_pin=root.read(claim_name,65536)
        require(claim=={'schema':ROW,'caseHash':case_hash,'logicalOperationRef':logical,'contextPath':context,
            'reviewHash':case['reviewHash'],'automaticReplayAllowed':False,'budgetReset':False},
            'ORIGINAL_REVIEW_CLAIM_MUST_REMAIN_UNCHANGED')
        native_claim='ingestion-readiness-patch-'+logical+'.claim.json'
        try:os.stat(native_claim,dir_fd=root.fd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:require(False,'NATIVE_INITIALIZATION_CLAIM_PRESENT_REQUIRES_DIFFERENT_RECONCILIATION')
        for directory,name,pin in ((target,'review.json',review_pin),(target,'packet.json',packet_pin),
            (target,'material.json',material_pin),(root,claim_name,claim_pin),(control,'recovery.json',row_pin)):
            require(identity(os.stat(name,dir_fd=directory.fd,follow_symlinks=False))==pin,'UNISSUED_SNAPSHOT_CHANGED')
            directory.check()
        require(target.names()==expected_names,'UNISSUED_CONTEXT_CHANGED_DURING_INSPECTION')
        return {'schema':'ouf.ingestion-readiness-unissued-reconcile-result.v1',
            'status':'STOPPED_UNISSUED_PATCH_REVIEW_RECONCILED_NO_AUTHORITY','complete':True,'readOnly':True,
            'contextPath':context,'runtimeCaseHash':case_hash,'reviewHash':case['reviewHash'],
            'retainedControlJournalHash':digest(row),'retainedDecisionHash':row['decisionHash'],
            'retainedState':'ISSUING','reviewBytes':review_size,'packetBytes':packet_size,
            'legacyReaderMaximumBytes':524288,'legacyReviewSizeExceeded':review_size>524288,
            'originalReviewClaimRetained':True,'issuanceClaimPresent':False,'authorityArtifactsPresent':False,
            'roleSignatureArtifactsPresent':False,'nativeInitializationClaimPresent':False,
            'nativeJournalPresent':False,'humanCredentialJournalsRead':0,'credentialValuesPrinted':False,
            'oauthRequests':0,'engineRequests':0,'databaseCalls':0,'runtimeAuthorityIssued':False,
            'runtimeEffectsDispatched':0,'budgetReset':False,'automaticReplayAllowed':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
    finally:
        if lock is not None:os.close(lock)
        for directory in reversed(dirs):directory.close()


def main(case):
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_UNISSUED_READER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_UNISSUED_RECONCILIATION_DEADLINE'))
        signal.alarm(60)
        print(encoded(inspect(case)).decode(),flush=True)
    except (Exception,KeyboardInterrupt)as error:
        code=str(error);reason=code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'UNISSUED_SNAPSHOT_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        print(encoded({'schema':'ouf.ingestion-readiness-unissued-reconcile-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'complete':False,'readOnly':True,'contextsAndClaimsRetained':True,
            'oauthRequests':0,'engineRequests':0,'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,
            'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True)
        raise SystemExit(2)
