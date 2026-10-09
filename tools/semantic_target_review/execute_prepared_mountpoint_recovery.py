"""R8: fresh explicit acceptance of nine empty bind placeholders, then one cohort.

Inert until exact human approval. Reuse existing readers, delete-only gate and
signed-intake implementation. Preserve R7 and all older evidence. No seal-check
bypass, in-place acceptance change, direct Docker start or automatic retry.
"""
import contextlib
import copy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import types

APPROVAL_REF='PENDING_PREPARED_MOUNTPOINT_RECOVERY_APPROVAL'
APPROVED_AT=None
APPROVAL_EXPIRES_AT=None
REVIEW_REF='OUF_PROVIDER_PREPARED_MOUNTPOINT_REVIEW_20261009_R8'
BASE=Path('/etc/ouf/deploy-snapshots')
CONTEXT=BASE/'semantic-provider-v2-approved-context-cbuyoyo2'
OUTPUT=BASE/'semantic-provider-v2-transaction-cbuyoyo2'
ORIGINAL=BASE/'semantic-provider-v2-transaction-source-ff13uh3n'
CLAIM=BASE/'semantic-provider-prepared-mountpoint-r8-claim.json'
WRAPPER=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
OWNER='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
ORIGINAL_ENTRY='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
R7_ENTRY='a4e9c02915cc32ab839456de57f88e57d42aa607922ba6db8a320fd27bfdc240'
READER_HASH='f496b2f20e1ac88c694ad16c0a3a3e529463297d8b10b565013903d6df3c55e4'
DELTA={'prepare_mountpoint_acceptance.py':'143112ab4051ca166f6d7609c107787f2be3ce35ce7946002dfec755ff1fdd98',
       'scope.json':'24f6c5a25893e1757bb903b74b90155e39d19864d377ed3a31a94e80bfce1a86'}
HELPERS={
 'r7':('/home/oufadmin/ouf-audited-recovery.mM44KYJx/execute.py','6ce5addae1df8a418bc3dfead347c5d6acbd51d5607c436260aadef741cbcfc0'),
 'cleanup':('/home/oufadmin/ouf-r6-cleanup.fcFFvDtX/execute.py','1904926c751851b599e7eab33063d7b9a94d34388b363d4853c831c8834cddaa'),
 'gate':('/home/oufadmin/ouf-r6-cleanup.fcFFvDtX/gate.py','a23f71e7fbe29fc3df4f138f41d35b4b5a3c63f14f1f15bc1c9e3d62644c9cfe'),
 'arguments':('/home/oufadmin/ouf-r6-cleanup.fcFFvDtX/arguments.py','d81fe4518b452c130b1c8c0fef14ffff6cc7a09ab3c92e29d28441786e52b5c7')}
NEW_CONTEXT=None
NEW_OUTPUT=None
PHASE='REQUIRE_EXPLICIT_PREPARED_ROOTFS_APPROVAL'
REPORT={'schema':'ouf.semantic-prepared-mountpoint-recovery.v1','privateKeysRead':0,'signaturesIssued':0,
    'containerLifecycleOperations':0,'dockerStartRequests':0,'taskDeleteRequests':0,'automaticRetryPerformed':False,
    'privateValuesPrinted':False,'providerCalls':0,'daemonRestarted':False,'doNotRerunApply':False,
    'startAuthorized':False,'notReleaseAcceptance':True}


def require(ok,reason):
    if not ok:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def definitions(name,raw,path):
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module.__dict__
def source(path,wanted):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_size<=131072,'BOUNDED_REVIEWED_SOURCE_REQUIRED')
        raw=os.read(fd,131073)
    finally:os.close(fd)
    require(sha(raw)==wanted,'REVIEWED_SOURCE_HASH_DRIFT');return raw
def phase(value):
    global PHASE
    PHASE=value;print('OUF_R8_PHASE='+value,flush=True)
def live_approval(ref,now):
    require(APPROVAL_REF!='PENDING_PREPARED_MOUNTPOINT_RECOVERY_APPROVAL' and ref==APPROVAL_REF
        and type(APPROVED_AT) is int and type(APPROVAL_EXPIRES_AT) is int,
        'EXPLICIT_PREPARED_ROOTFS_APPROVAL_REQUIRED')
    require(APPROVED_AT<=now<APPROVAL_EXPIRES_AT,'LIVE_PREPARED_ROOTFS_APPROVAL_REQUIRED')


def private_map(path,entry):
    """The fixed reader's private complete maps exceed the small JSON limit."""
    path=Path(path)
    for parent in (path.parent,*path.parent.parents):
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'PRIVATE_MAP_PARENT_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
            and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=33554432,'BOUNDED_PRIVATE_MAP_REQUIRED')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(33554433)
        require(len(raw)==before.st_size and entry['attributes'](before)==entry['attributes'](os.fstat(fd))==entry['attributes'](path.lstat()),'PRIVATE_MAP_CHANGED')
    finally:os.close(fd)
    return entry['parse'](raw)


def validate_fresh(scope,report):
    require(report.get('status')=='R7_CURRENT_ROOTFS_DIFFERENCES_CAPTURED' and report['retainedEvidencePreserved'] is True
        and report['allRecordedTaskPidsAbsent'] is True,'COMPLETE_FRESH_ROOTFS_AND_TASK_REVIEW_REQUIRED')
    require(report['installedWrapperHash']==scope['priorWrapperHash']
        and report['nativeEmptyGuardObservation']['configurationHash']==OWNER
        and report['nativeEmptyGuardObservation']['providerSetsEmpty'] is True
        and report['nativeEmptyGuardObservation']['candidateStateHashes']==scope['states'],'EXACT_R7_GUARD_AND_WRAPPER_REQUIRED')
    require(report['containerdRequestedTasks']==scope['tasks'] and report['terminalTaskReview']==scope['shims'],
        'EXACT_REVIEWED_TERMINAL_GENERATIONS_REQUIRED')
    for role,target in scope['roles'].items():
        cid=target['containerId'];task=scope['tasks'][cid]
        require(task['status']=='STOPPED' and task['taskPresent'] is True and task['taskPidPresent'] is False
            and report['requestedNativeEntries'][cid]==[],'STOPPED_RESIDUAL_TASK_WITHOUT_NATIVE_PROCESS_REQUIRED')
        require(report['roles'][role]['currentV1Seal']==target['runtimeSeal'],'EXACT_PROPOSED_CURRENT_ROOTFS_REQUIRED')
        require(len(scope['shims'][cid]['shims'])==1,'EXACT_REVIEWED_SHIM_REQUIRED')


def build_mandates(scope,records,now,ref):
    live_approval(ref,now)
    require(scope['reviewRef']==REVIEW_REF and set(records)==set(scope['roles'])=={'adapter','southbound'},'EXACT_REVIEWED_ROLE_PAIR_REQUIRED')
    from datetime import datetime
    expiry=int(datetime.fromisoformat(scope['dependencyValidUntil'].replace('Z','+00:00')).timestamp())
    require(now+240<=expiry,'DEPENDENCY_VALIDITY_DOES_NOT_COVER_TRANSACTION')
    result={}
    for role,values in records.items():
        require({n:sha(v) for n,v in values.items()}==scope['roles'][role]['inputHashes'],'ACCEPTED_INPUTS_CHANGED')
        result[role]={**copy.deepcopy(scope['roles'][role]),'schema':'ouf.semantic-provider-transaction-role-mandate.v1',
            'state':'ACTIVE','decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION',
            'approvalRef':ref,'issuedAt':now,'expiresAt':now+240}
    return result


def frozen_publication(entry,scope,fresh):
    hashes=entry['parse'](entry['read'](Path(fresh['evidenceDirectory'])/'retained-input-hashes.json'))
    receipt=entry['parse'](entry['read'](OUTPUT/'installation-receipt.json'))
    frozen={}
    for path,wanted in receipt['fileHashes'].items():
        require(Path(path).is_relative_to(OUTPUT) and '..' not in Path(path).parts,'RETAINED_PUBLICATION_PATH_ESCAPE')
        if Path(path).name in ('adapter.json','broker-state.json','deployment.json'):
            require(path in hashes,'FRESH_MUTABLE_JOURNAL_HASH_REQUIRED');wanted=hashes[path]
        frozen[path]=sha(entry['bound']({'path':path,'sha256':wanted}))
    for path,wanted in hashes.items():frozen[path]=sha(entry['bound']({'path':path,'sha256':wanted}))
    for path in [CONTEXT/'execution-claim.json',OUTPUT/'cohort-activation-claim.json',OUTPUT/'cohort-activation-denial.json',OUTPUT/'runtime-switch-claim.json']:
        frozen[str(path)]=sha(entry['read'](path))
    require(not (OUTPUT/'cohort-activation-receipt.json').exists(),'R7_SUCCESS_CONFLICTS_WITH_RECOVERY')
    return frozen


def cleanup_pair(entry,cfg,scope,fresh,helpers,frozen,publish):
    """Reuse the already successful alias-aware terminal-only deletion route."""
    from transaction_guard_observation import executable_binding,observe_locked
    retained=helpers['cleanup'];gate=helpers['gate'];arguments=helpers['arguments']
    cids=[scope['roles'][role]['containerId'] for role in ('southbound','adapter')]
    old=entry['read'](WRAPPER,True);require(sha(old)==scope['priorWrapperHash'],'EXACT_R7_WRAPPER_REQUIRED')
    runtime_root=entry['parse'](entry['read'](OUTPUT/'registry'/cids[0]/'adapter.json'))['runtimeRoot']
    require(sha(runtime_root.encode())==fresh['runtimeRootHash'],'EXACT_RETAINED_RUNTIME_ROOT_REQUIRED')
    supplied,option_hashes=retained['retained_alias'](entry,arguments,gate,runtime_root)
    template=entry['parse'](entry['bound'](cfg['recordsByRole']['adapter']['preparerTemplate']))
    pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']));binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
    owner=entry['parse'](entry['bound']({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':OWNER}))
    candidates={v['containerId']:{'imageManifestDigest':v['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for v in scope['roles'].values()}
    ctr={'path':'/usr/bin/ctr','sha256':'8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e'}
    identity=executable_binding(ctr)
    def command(args):
        require(executable_binding(ctr)==identity,'CTR_EXECUTABLE_DRIFT')
        with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
            p=subprocess.run([ctr['path'],'--address','/run/containerd/containerd.sock','--namespace','moby',*args],
                stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=30,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            out.seek(0);err.seek(0);stdout=out.read(131073);stderr=err.read(131073)
        require(len(stdout)<=131072 and len(stderr)<=131072,'BOUNDED_TASK_COMMAND_REQUIRED')
        return p.returncode,stdout,stderr
    directory=NEW_CONTEXT/'terminal-maintenance';directory.mkdir(mode=0o700)
    publish(directory/'prior-wrapper.sh',old);publish(directory/'retained-hashes.json',encoded(frozen))
    publish(directory/'gate.py',helpers['gateRaw'])
    fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK);switched=False
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(observe_locked(fd,binding,OWNER,candidates,cfg['commandBindings'])==fresh['nativeEmptyGuardObservation'],'CURRENT_GUARD_CHANGED')
        now=int(time.time());live_approval(APPROVAL_REF,now)
        window={'schema':'ouf.semantic-terminal-task-delete-window.v2','approvalRef':APPROVAL_REF,'issuedAt':now,
            'expiresAt':min(now+120,APPROVAL_EXPIRES_AT),'tasks':{cid:{'pid':scope['tasks'][cid]['pid']} for cid in cids},
            'runtimeRoot':runtime_root,'runtimeArgumentRoot':supplied,'runcBinding':template['candidate']['runtimeBinding']}
        publish(directory/'window.json',encoded(window))
        executable_binding(cfg['pythonBinding'])
        new=('#!/bin/sh\nexec '+cfg['pythonBinding']['path']+' -I -B '+str(directory/'gate.py')+' --configuration '+str(directory/'window.json')+' "$@"\n').encode()
        phase('REMOVE_EXACT_TWO_R7_TERMINAL_TASKS')
        try:retained['replace_wrapper'](entry,old,new,WRAPPER.parent/('.ouf-r8-maintenance-'+sha(new)))
        finally:switched=entry['read'](WRAPPER,True)==new
        require(switched,'DELETE_ONLY_WRAPPER_UNPROVEN')
        for cid in cids:
            require(time.time()<window['expiresAt'],'MAINTENANCE_WINDOW_EXPIRED')
            require(not os.path.lexists('/proc/'+str(scope['tasks'][cid]['pid'])),'TASK_PID_REAP_REQUIRED')
            bundle=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid
            require(all(sha(entry['read'](bundle/name))==option_hashes[str(bundle/name)] for name in ('options.json','runtime')),'SHIM_RUNTIME_OPTIONS_DRIFT')
            shim=scope['shims'][cid]['shims'][0];proc=Path('/proc')/str(shim['pid'])
            state=(proc/'stat').read_bytes();tail=state[state.rfind(b')')+2:].split()
            require(int(tail[19])==shim['startTicks'] and sha((proc/'cmdline').read_bytes())==shim['argvHash']
                and os.readlink(proc/'cwd')==str(bundle),'SHIM_GENERATION_CHANGED')
            code,raw,_=command(['containers','info',cid]);require(code==0 and sha(raw)==scope['tasks'][cid]['containerMetadataHash'],'CONTAINER_METADATA_CHANGED')
            code,raw,_=command(['tasks','list']);require(code==0,'TASK_INVENTORY_UNPROVEN')
            rows=[r.split() for r in raw.decode().splitlines()[1:] if r.split()[0]==cid]
            require(rows==[[cid,str(scope['tasks'][cid]['pid']),'STOPPED']],'EXACT_STOPPED_TASK_REQUIRED')
            gate['validate_root_binding'](window)
            REPORT['taskDeleteRequests']+=1;REPORT['containerLifecycleOperations']=None
            code,out,err=command(['tasks','delete',cid])
            publish(directory/(cid+'-delete.json'),encoded({'exitCode':code,'stdoutHash':sha(out),'stderrHash':sha(err),'forceUsed':False}))
            publish(directory/(cid+'-delete.stderr'),err)
            require(code==0,'TERMINAL_TASK_DELETE_FAILED_READ_RETAINED_STDERR')
        code,raw,_=command(['tasks','list']);require(code==0,'POST_DELETE_INVENTORY_UNPROVEN')
        require(not any(r.split()[0] in cids for r in raw.decode().splitlines()[1:]),'RESIDUAL_TASKS_STILL_PRESENT')
        for cid in cids:
            code,raw,_=command(['containers','info',cid]);require(code==0 and sha(raw)==scope['tasks'][cid]['containerMetadataHash'],'CONTAINER_METADATA_NOT_PRESERVED')
        require(all(sha(entry['read'](p))==h for p,h in frozen.items()),'R7_RETAINED_EVIDENCE_CHANGED')
    finally:
        try:
            if switched:
                retained['replace_wrapper'](entry,new,old,WRAPPER.parent/('.ouf-r8-restore-'+sha(new)))
                REPORT['maintenanceWrapperRestored']=True
            if REPORT.get('maintenanceWrapperRestored'):
                REPORT['postMaintenanceGuard']=observe_locked(fd,binding,OWNER,candidates,cfg['commandBindings'])
        finally:os.close(fd)
    require(REPORT.get('maintenanceWrapperRestored') is True,'R7_WRAPPER_RESTORATION_REQUIRED')
    publish(directory/'receipt.json',encoded({'status':'TWO_STOPPED_TASKS_REMOVED_CONTAINERS_PRESERVED',
        'taskDeleteRequests':REPORT['taskDeleteRequests'],'wrapperRestored':True,'retainedEvidencePreserved':True,
        'dockerStartRequests':0,'privateKeysRead':0,'startAuthorized':False}))


def main(ref,delta_directory):
    global NEW_CONTEXT,NEW_OUTPUT
    live_approval(ref,int(time.time()))
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
    require(not os.path.lexists(CLAIM),'DO_NOT_REPLAY_R8_RECOVERY')
    os.umask(0o077)
    delta={name:source(Path(delta_directory)/name,digest) for name,digest in DELTA.items()}
    scope=json.loads(delta['scope.json'])
    require(scope['reviewRef']==REVIEW_REF and scope['priorContext']==str(CONTEXT) and scope['priorOutput']==str(OUTPUT),
        'EXACT_R8_REVIEW_REQUIRED')
    helper_bytes={name:source(path,digest) for name,(path,digest) in HELPERS.items()}
    helpers={name:definitions('r8_retained_'+name,raw,HELPERS[name][0]) for name,raw in helper_bytes.items()}
    helpers['gateRaw']=helper_bytes['gate'];publish=helpers['r7']['publish']
    original=source(ORIGINAL/'provider_transaction_intake.py',ORIGINAL_ENTRY)
    entry=definitions('r8_private_reader',original,ORIGINAL/'provider_transaction_intake.py')
    require(entry['read'](ORIGINAL/'provider_transaction_intake.py')==original,'PRIVATE_READER_CUSTODY_DRIFT')
    retained=entry['parse'](entry['bound']({'path':scope['retainedDiagnosis']+'/diagnosis.json','sha256':scope['diagnosisHash']}))
    validate_fresh(scope,retained)
    phase('VERIFY_CURRENT_NINE_EMPTY_PLACEHOLDERS_AND_TERMINAL_GENERATIONS')
    readers=[]
    for path in Path('/home/oufadmin').glob('ouf-r7-rootfs-read.*/read.py'):
        try:raw=source(path,READER_HASH)
        except (OSError,ValueError):continue
        readers.append((path,raw))
    require(readers,'EXISTING_PINNED_R7_READER_REQUIRED')
    path,raw=sorted(readers)[0];reader=definitions('r8_existing_read_only',raw,path)
    argv=sys.argv
    try:
        sys.argv=[str(path)]
        with contextlib.redirect_stdout(io.StringIO()) as output:code=reader['main']()
    finally:sys.argv=argv
    text=output.getvalue();require('OUF_R7_ROOTFS_READ_ONLY=' in text,'READ_ONLY_DIAGNOSIS_OUTPUT_MISSING')
    fresh=json.loads(text.split('OUF_R7_ROOTFS_READ_ONLY=',1)[1])
    REPORT['freshReviewDirectory']=fresh.get('evidenceDirectory')
    if code!=0:REPORT['readOnlyDiagnosis']=fresh
    require(code==0,'FRESH_READ_ONLY_REVIEW_FAILED')
    try:validate_fresh(scope,fresh)
    except Exception:
        REPORT['readOnlyDiagnosis']=fresh
        raise
    approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
    cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
    require(cfg['outputRoot']==str(OUTPUT) and approval['sourceClosureHash']==scope['package']['sourceClosureHash'],'R7_CONTEXT_BINDING_DRIFT')
    package=Path(approval['sourcePackage']);old_entry=entry['bound']({'path':str(package/'provider_transaction_intake.py'),'sha256':R7_ENTRY})
    builder=definitions('r8_prepared_rootfs_proposal',delta['prepare_mountpoint_acceptance.py'],Path(delta_directory)/'prepare_mountpoint_acceptance.py')
    manifest=entry['bound']({'path':str(package/'intake-source-closure.json'),'sha256':builder['R7_MANIFEST']})
    files={name:entry['bound']({'path':str(package/name),'sha256':h}) for name,h in entry['parse'](manifest)['sourceHashes'].items()}
    built=builder['build_package'](manifest,files,old_entry)
    require({k:v for k,v in built.items() if k!='files'}==scope['package'],'EXACT_REVIEWED_R8_PACKAGE_REQUIRED')
    records={role:{name:entry['bound'](binding) for name,binding in values.items()} for role,values in cfg['recordsByRole'].items()}
    now=int(time.time());build_mandates(scope,records,now,ref)
    proofs={}
    for role in records:
        value=private_map(Path(fresh['evidenceDirectory'])/(role+'-entry-comparison.json'),entry)
        proofs[role]=builder['validate_comparison'](role,value,entry['parse'](records[role]['framePolicy'])['expectedOci'])
    from authenticate_provider_transaction import preflight_input_pair,validate_dependency_evidence
    preflight_input_pair(records)
    for role in records:validate_dependency_evidence(entry['parse'](records[role]['dependencyEvidence']),role,now,now+360)
    frozen=frozen_publication(entry,scope,fresh)
    phase('RESERVE_APPROVED_R8_CONTEXT_WITH_PRIOR_EVIDENCE_PRESERVED')
    live_approval(ref,int(time.time()))
    NEW_CONTEXT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-approved-context-',dir=BASE));NEW_CONTEXT.chmod(0o700)
    NEW_OUTPUT=BASE/('semantic-provider-v2-transaction-'+NEW_CONTEXT.name.removeprefix('semantic-provider-v2-approved-context-'))
    publish(CLAIM,encoded({'schema':'ouf.semantic-prepared-mountpoint-recovery-claim.v1','approvalRef':ref,
        'reviewRef':REVIEW_REF,'contextDirectory':str(NEW_CONTEXT),'scopeHash':DELTA['scope.json'],
        'retainedDiagnosisHash':scope['diagnosisHash'],'notReleaseAcceptance':True}))
    REPORT['doNotRerunApply']=True
    publish(NEW_CONTEXT/'scope.json',delta['scope.json']);publish(NEW_CONTEXT/'rootfs-review-proofs.json',encoded(proofs))
    publish(NEW_CONTEXT/'prior-evidence-hashes.json',encoded(frozen))
    package=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-transaction-source-prepared-',dir=BASE));package.chmod(0o700)
    helpers['r7']['install_package'](package,built['files'])
    current=definitions('r8_current_intake',built['files']['provider_transaction_intake.py'],package/'provider_transaction_intake.py')
    sources,observer=current['load'](package)
    phase('PREFLIGHT_BOTH_NEW_ACCEPTANCES_WITHOUT_SIGNING_BEFORE_MAINTENANCE')
    require(cfg['authorityProfileBinding']==current['AUTHORITY'] and cfg['runtimeAdapterBinding']==current['EMPTY_ADAPTER']
        and cfg['pythonBinding']==current['PYTHON']
        and {k:cfg['opensslBinding'][k] for k in ('path','sha256')}==current['OPENSSL'],'EXISTING_TARGET_BINDINGS_DRIFT')
    profile=current['parse'](current['bound'](current['AUTHORITY']))
    require(profile['policyBinding']==current['POLICY'],'EXISTING_AUTHORITY_POLICY_DRIFT')
    authority={k:profile[k] for k in ('authorities','keyBindings','keyRefs')}
    preflight=NEW_CONTEXT/'acceptance-preflight';preflight.mkdir(mode=0o700)
    proposals=build_mandates(scope,records,int(time.time()),ref);bindings={}
    for role,value in proposals.items():
        path=preflight/(role+'-mandate.json');raw=encoded(value);publish(path,raw)
        bindings[role]={'path':str(path),'sha256':sha(raw)}
    current['preflight_root_mandates'](preflight,{**cfg,'mandatesByRole':bindings},records,authority,sources,observer)
    cleanup_pair(entry,cfg,scope,fresh,helpers,frozen,publish)
    phase('PUBLISH_FRESH_EXPLICIT_ROOTFS_ACCEPTANCE_AND_CONTROLLED_COHORT_ONCE')
    now=int(time.time());mandates=build_mandates(scope,records,now,ref)
    bindings={}
    for role,value in mandates.items():
        path=NEW_CONTEXT/(role+'-mandate.json');raw=encoded(value);publish(path,raw)
        bindings[role]={'path':str(path),'sha256':sha(raw)}
    next_cfg={**cfg,'mandatesByRole':bindings,'outputRoot':str(NEW_OUTPUT)}
    raw=encoded(next_cfg);configuration=NEW_CONTEXT/'execution-configuration.json';publish(configuration,raw)
    publish(NEW_CONTEXT/'human-approval-binding.json',encoded({'schema':'ouf.semantic-provider-approved-root-context.v1',
        'approvalRef':ref,'reviewRef':REVIEW_REF,'configurationHash':sha(raw),'sourcePackage':str(package),
        'sourceClosureHash':built['sourceClosureHash'],'scopeHash':DELTA['scope.json'],
        'issuedAt':now,'expiresAt':now+240,'notReleaseAcceptance':True}))
    try:result=current['execute_transaction'](NEW_CONTEXT,configuration,sha(raw),sources,observer)
    finally:
        require(all(sha(entry['read'](p))==h for p,h in frozen.items()),'PRIOR_R7_EVIDENCE_CHANGED')
    REPORT.update(result,contextDirectory=str(NEW_CONTEXT),sourcePackage=str(package),
        acceptedEmptyMountPlaceholders={'adapter':6,'southbound':3},priorR7EvidencePreserved=True)
    publish(NEW_CONTEXT/'prepared-mountpoint-recovery-receipt.json',encoded(REPORT))
    return REPORT


if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'EXACT_APPROVAL_AND_REVIEWED_DIRECTORY_REQUIRED')
        result=main(*sys.argv[1:]);print('OUF_PREPARED_MOUNTPOINT_RECOVERY='+encoded(result).decode())
    except Exception as error:
        REPORT.update(getattr(error,'diagnosis',{}))
        attempted=NEW_CONTEXT is not None and os.path.lexists(NEW_CONTEXT/'execution-claim.json')
        REPORT.update(status='BLOCKED',phase=PHASE,errorType=type(error).__name__,
            reason=REPORT.get('reason') or (str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'R8_RECOVERY_UNPROVEN'),
            contextDirectory=str(NEW_CONTEXT) if NEW_CONTEXT else None,evidenceDirectory=str(NEW_OUTPUT) if NEW_OUTPUT else None,
            doNotRerunApply=NEW_CONTEXT is not None or os.path.lexists(CLAIM),startAuthorized=False,
            privateKeysRead=None if attempted else 0,signaturesIssued=None if attempted else 0,
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
        if attempted:REPORT['containerLifecycleOperations']=None
        if isinstance(error,OSError):REPORT['errno']=error.errno
        if NEW_CONTEXT:
            try:
                helper=definitions('r8_failure_retention',source(*HELPERS['r7']),HELPERS['r7'][0])
                REPORT['retainedPhaseDiagnostics']=helper['collected_diagnostics'](NEW_OUTPUT)
                helper['publish'](NEW_CONTEXT/'operator-denial.json',encoded(REPORT))
            except Exception:REPORT['diagnosisSaved']=False
        print('OUF_PREPARED_MOUNTPOINT_RECOVERY='+encoded(REPORT).decode());raise SystemExit(1)
