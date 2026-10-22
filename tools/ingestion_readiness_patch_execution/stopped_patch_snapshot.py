"""Read-only stopped patch metadata; no credentials, signing or service calls."""
import fcntl
import os
import stat
from pathlib import Path
import time
from tools.ingestion_readiness_patch_execution.unissued_reconcile import Directory,require,digest,hashed


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
