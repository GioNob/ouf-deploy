#!/usr/bin/env python3
"""Classify a stopped historical/current Engine binding comparison using files.

No Engine connections, SQL, subprocesses, service calls, credentials, signing,
counter changes, old entry invocation or acceptance. All observations private.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types

DATABASE_READER='/etc/ouf/deploy-snapshots/onboarding-finite-database-97212fa426ac13ad/read.py'
DATABASE_READER_HASH='97212fa426ac13ad353f67dc0dd9e8be903bf75d09b2203e2dddac84131dbca7'
SCOPE='engine-binding-reconciliation-v1'
ENGINE_FIELDS={'socketPath','socketBinding'}
SOCKET_FIELDS=('device','inode','uid','gid','mode')
RUNTIME_FIELDS={'containerId','imageId','pid','startedAt','configHash','hostConfigHash','mountsHash','networkSettingsHash'}


class Stop(RuntimeError):pass


def require(ok,code):
    if not ok:raise Stop(code)


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def frame(s):return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]
def file_pin(s):return frame(s)+[s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def bootstrap():
    path=Path(DATABASE_READER)
    require(path.is_absolute() and path.resolve()==path,'EXACT_STOPPED_READER_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'PROTECTED_READER_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
            and stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=131072,'PRIVATE_STOPPED_READER_REQUIRED')
        source=os.read(fd,131073)
        require(len(source)==before.st_size and hashlib.sha256(source).hexdigest()==DATABASE_READER_HASH
            and file_pin(before)==file_pin(os.fstat(fd))==file_pin(path.lstat()),'STOPPED_READER_BYTES_CHANGED')
    finally:os.close(fd)
    d=types.ModuleType('ouf_stopped_reader_definitions_only');d.__file__=str(path)
    exec(compile(source,str(path),'exec'),d.__dict__)
    # Only the original hash-checked dependency bootstrap; never d.prepare/main.
    m,r=d.seed();m.raw(str(Path(__file__).resolve()),131072)
    return d,m,r


def validate_engine(value):
    require(type(value)is dict and set(value)==ENGINE_FIELDS,'EXACT_RETAINED_ENGINE_METADATA_SHAPE_REQUIRED')
    p=value['socketPath'];b=value['socketBinding']
    require(type(p)is str and 0<len(p)<=4096 and Path(p).is_absolute() and '..'not in Path(p).parts
        and type(b)is list and len(b)==5 and all(type(v)is int and v>=0 for v in b)
        and b[2]==0 and b[4]in(0o600,0o660),'CLOSED_CUSTODIED_ENGINE_METADATA_REQUIRED')
    return value


def difference(left,right):
    validate_engine(left);validate_engine(right)
    return {'equal':left==right,'changedFields':sorted(k for k in ENGINE_FIELDS if left[k]!=right[k]),
        'socketBindingChanges':[name for i,name in enumerate(SOCKET_FIELDS)if left['socketBinding'][i]!=right['socketBinding'][i]]}


def protected_directory(path):
    for parent in [path,*path.parents]:
        s=parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_SOCKET_ANCESTRY_REQUIRED')


def socket_view(binding):
    validate_engine(binding);selected=Path(binding['socketPath'])
    # Unix filesystem metadata ONLY. No open/connect/request on the socket.
    try:resolved=selected.resolve(strict=True)
    except FileNotFoundError:return {'present':False,'status':'ABSENT','selectedPath':str(selected)}
    ancestry=[];walk=Path('/')
    for part in selected.parts[1:-1]:
        walk=walk/part;s=walk.lstat()
        if stat.S_ISLNK(s.st_mode):
            require(s.st_uid==0,'ROOT_SOCKET_ALIAS_REQUIRED');protected_directory(walk.resolve(strict=True))
        else:require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_SOCKET_ANCESTRY_REQUIRED')
        ancestry.append({'path':str(walk),'identity':frame(s)})
    protected_directory(resolved.parent)
    leaf=selected.lstat();require(leaf.st_uid==0,'ROOT_SOCKET_LEAF_REQUIRED')
    s=resolved.lstat()
    require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)in(0o600,0o660),'PROTECTED_LOCAL_SOCKET_METADATA_REQUIRED')
    observed=[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]
    return {'present':True,'status':'OBSERVED_FILESYSTEM_METADATA_ONLY','selectedPath':str(selected),
        'canonicalPath':str(resolved),'selectedLeafIdentity':frame(leaf),'ancestry':ancestry,
        'observedSocketBinding':observed,'selectedPathIsCanonical':selected==resolved,
        'retainedSocketBindingMatchesObserved':binding['socketBinding']==observed}


def classify(engines,views):
    pairs={name:difference(engines[a],engines[b])for name,a,b in
        [('preparedVsPlan','prepared','plan'),('preparedVsCurrent','prepared','current'),('planVsCurrent','plan','current')]}
    current=views['current']
    require(current['present'] and current['selectedPathIsCanonical'] and current['retainedSocketBindingMatchesObserved'],
            'CURRENT_CAPTURED_SOCKET_CUSTODY_NOT_PROVEN')
    equal=all(row['equal']for row in pairs.values())
    same_path=all(v['present'] and v['canonicalPath']==current['canonicalPath']for v in views.values())
    same_actual=all(v['present'] and v['observedSocketBinding']==current['observedSocketBinding']for v in views.values())
    if equal:category='STOP_NOT_REPRODUCED_FROM_RETAINED_METADATA'
    elif not pairs['preparedVsPlan']['equal']:category='HISTORICAL_PREPARED_AND_PLAN_ENGINE_DIFFER'
    elif same_path and same_actual and pairs['preparedVsCurrent']['changedFields']==['socketPath']:
        category='PATH_ALIAS_ONLY_SAME_CURRENT_SOCKET'
    elif same_path and same_actual and engines['prepared']['socketBinding']!=engines['current']['socketBinding']:
        category='HISTORICAL_SOCKET_BINDING_DIFFERS_FROM_CURRENT'
    else:category='ENGINE_METADATA_DIFFERENCE_REQUIRES_REVIEW'
    return {'classification':category,'failedComparisonReproduced':not equal,'comparisons':pairs,
        'allSelectedPathsResolveToCurrentSocket':same_path,'allSelectedPathsObserveSameCurrentSocket':same_actual,
        'currentCapturedSocketBindingMatchesObserved':True,
        'historicalSocketBindingsMatchObserved':{k:v.get('retainedSocketBindingMatchesObserved',False)for k,v in views.items()if k!='current'},
        'metadataClassificationDoesNotAuthorizeReplacement':True,'engineApiIdentityProvenByThisReader':False}


def runtime_comparison(retained,actual,runtime_bindings):
    require(type(retained)is dict and set(retained)==RUNTIME_FIELDS,'EXACT_HISTORICAL_RUNTIME_METADATA_REQUIRED')
    observed={name:runtime_bindings.observed(actual,profile)for name,profile in
        [('native',runtime_bindings.NATIVE),('sortedMounts',runtime_bindings.SORTED)]}
    return {name:{'equal':retained==row,'changedFields':sorted(k for k in RUNTIME_FIELDS if retained[k]!=row[k])}
            for name,row in observed.items()}


def process_comparison(m,inputs,observations):
    result={}
    for name,row in observations.items():
        try:value=m.process(row);result[name]={'observable':True,'matchesCaptured':value==inputs['currentProcessIdentities'][name]}
        except (OSError,ValueError,RuntimeError):result[name]={'observable':False,'matchesCaptured':False}
    return result


def prior_scope_state(m,d):
    root=Path(m.PACKAGE)/d.SCOPE
    return {'databaseScopeExists':os.path.lexists(root),
        'sqlAttemptMarkerPresent':os.path.lexists(root/'sql-attempt-01.json'),
        'databaseCompleteMarkerPresent':os.path.lexists(root/'complete.json')}


def prepare(d,m,r):
    from tools.ingestion_readiness_patch_execution import runtime_bindings
    require(not os.path.lexists(Path(m.PACKAGE)/SCOPE),'ENGINE_RECONCILIATION_ALREADY_CLAIMED_NO_REPLAY')
    root=r.exclusive_root(m.PACKAGE,SCOPE)
    m.new_file(root,'claim.json',{'schema':'ouf.onboarding-engine-metadata-claim.v1',
        'priorReasonCode':'SAME_RETAINED_ONBOARDING_ENGINE_REQUIRED','stoppedReaderHash':DATABASE_READER_HASH,
        'inputHash':d.INPUT_HASH,'maximumSeconds':45,'engineRequestsAllowed':False,'sqlAllowed':False,
        'subprocessesAllowed':False,'serviceCredentialFilesAllowed':False,'automaticReplayAllowed':False,'budgetReset':False})
    facts=m.Facts();inputs=facts.json(d.INPUT,d.INPUT_HASH)
    require(inputs['schema']=='ouf.onboarding-finite-session-private-inputs.v1'
        and inputs['kind']=='INPUTS_NOT_EXECUTABLE_AUTHORITY' and inputs['targetApplyAuthorized']is False
        and inputs['automaticReplayAllowed']is False and inputs['budgetReset']is False
        and inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'EXACT_CURRENT_CAPTURED_INPUTS_REQUIRED')
    complete=facts.json(Path(d.INPUT).parent/'complete.json')
    require(complete['complete']is True and complete['privateInputsHash']==d.INPUT_HASH
        and complete['engineGetAttempts']==14 and complete['currentCohortStable']is True,'COMPLETE_RETAINED_INPUT_CAPTURE_REQUIRED')
    for reference in inputs['retainedFacts']:facts.json(reference['path'],reference['sha256'])
    base=facts.json(Path(d.BASE)/'review.json',d.BASE_REVIEW)
    ref=base['scopes']['finiteActionProcess']['bundle'];prepared=facts.json(ref['path'],ref['sha256'])['prepared']
    require(digest(prepared)==base['privateInputHashes']['preparedInputs'],'RETAINED_PREPARED_METADATA_CHANGED')
    review=facts.json(Path(d.OWNER)/'review.json',d.OWNER_REVIEW)
    plan=facts.json(Path(d.OWNER)/'execution-plan.json');journal=facts.json(Path(d.OWNER)/'recovery.json')
    scope=review['scopes']['onboardingAuditUpdate']
    require(digest(plan)==scope['planHash'] and journal['scopeHash']==digest(scope)
        and journal['incidentState']=='RECOVERED' and journal['version']==29
        and journal['nextStage']==len(journal['effects'])==len(scope['stages'])==11
        and [e['stage']for e in journal['effects']]==scope['stages']and all(e['state']=='APPLIED'for e in journal['effects'])
        and journal['effects'][-1]['stage']=='VERIFY_FINAL','EXACT_COMPLETED_HISTORICAL_OWNER_METADATA_REQUIRED')
    engines={'prepared':validate_engine(prepared['engine']),'plan':validate_engine(plan['engine']),
        'current':validate_engine(inputs['engineBinding'])}
    observations={}
    for name in('onboarding','postgres'):
        ref=inputs['runtimeObservations'][name];observations[name]=facts.json(ref['path'],ref['sha256'])
        require(runtime_bindings.observed(observations[name],runtime_bindings.NATIVE)==inputs['currentBindings'][name],
            'EXACT_CAPTURED_RUNTIME_METADATA_REQUIRED')
    old_pg=prepared['databasePlan']['postgresRuntimeBinding']
    old_onboarding=journal['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding']
    runtime={'onboarding':runtime_comparison(old_onboarding,observations['onboarding'],runtime_bindings),
        'postgres':runtime_comparison(old_pg,observations['postgres'],runtime_bindings)}
    prior=prior_scope_state(m,d);processes=process_comparison(m,inputs,observations)
    views={k:socket_view(v)for k,v in engines.items()};classification=classify(engines,views)
    facts.recheck()
    require(views=={k:socket_view(v)for k,v in engines.items()},'SOCKET_METADATA_CHANGED_DURING_RECONCILIATION')
    require(processes==process_comparison(m,inputs,observations),'PROCESS_METADATA_CHANGED_DURING_RECONCILIATION')
    require(prior==prior_scope_state(m,d),'PRIOR_DATABASE_SCOPE_CHANGED_DURING_RECONCILIATION')
    require(inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'BOOT_CHANGED_DURING_RECONCILIATION')
    bundle={'schema':'ouf.onboarding-engine-metadata-private-reconciliation.v1','inputHash':d.INPUT_HASH,
        'stoppedReaderHash':DATABASE_READER_HASH,'retainedFiles':list(facts.files.values()),
        'engineMetadata':engines,'socketViews':views,'classification':classification,
        'historicalVsCapturedRuntime':runtime,'capturedProcessPins':processes,'priorScopeState':prior,
        'noCurrentDockerContainerStateRead':True,'newSqlAttemptAuthorized':False,'newBindingAcceptedForRuntime':False,
        'originalRequestRepeated':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'reconciliation.json',bundle)
    result={'schema':'ouf.onboarding-engine-metadata-reconciliation-result.v1',
        'status':'ONBOARDING_ENGINE_METADATA_RECONCILED','complete':True,
        'privateReconciliationPath':str(root/'reconciliation.json'),'privateReconciliationHash':digest(bundle),
        **classification,'historicalVsCapturedRuntime':runtime,'capturedProcessPins':processes,'priorScopeState':prior,
        'engineGetAttempts':0,'engineConnections':0,'sqlSessionAttempts':0,'containerExecAttempts':0,
        'subprocessesDispatched':0,'serviceCredentialFilesOpened':0,'bearerFilesOpened':0,'privateSigningKeysRead':0,
        'containerWrites':0,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'retainedFileWrites':0,
        'privateEvidenceWrites':True,'readOnlyRuntime':True,'credentialValuesPrinted':False,'addressesPrinted':False,
        'originalRequestRepeated':False,'original502RootCauseNewlyEstablished':False,'newSqlAttemptAuthorized':False,
        'newBindingAcceptedForRuntime':False,'lifecycleMutationAuthorized':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'complete.json',result);return result


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ONE_ISOLATED_ROOT_METADATA_RECONCILIATION_REQUIRED')
        def expired(*_):raise Stop('ENGINE_METADATA_RECONCILIATION_DEADLINE')
        signal.signal(signal.SIGALRM,expired);signal.alarm(45)
        result=prepare(*bootstrap())
    except Exception as error:
        reason=str(error)if type(error).__name__in('Stop','Denied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'ENGINE_METADATA_RECONCILIATION_UNPROVEN'
        result={'schema':'ouf.onboarding-engine-metadata-reconciliation-result.v1','status':'STOP_RECONCILE','complete':False,
            'reasonCode':reason,'privateReconciliationMayBePartial':True,'engineGetAttempts':0,'sqlSessionAttempts':0,
            'containerExecAttempts':0,'containerWrites':0,'databaseMigrations':0,'humanBudgetsGranted':0,
            'originalRequestRepeated':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,
            'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True)
    return 0 if result.get('complete')is True else 2


if __name__=='__main__':raise SystemExit(main())
