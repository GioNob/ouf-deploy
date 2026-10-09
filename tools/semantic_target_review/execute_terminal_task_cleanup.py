"""Inert until scoped human approval: remove only two stopped residual tasks.

Temporary delete-only gate; no application start, kill/force, key access,
container/image/snapshot deletion, journal reset or automatic retry.
"""
import contextlib,fcntl,hashlib,io,json,os,re,stat,subprocess,sys,tempfile,time,traceback
from pathlib import Path
APPROVAL_REF='PENDING_TERMINAL_TASK_CLEANUP_APPROVAL'
APPROVED_AT=None
REVIEW_SHA='4269551bed61bb437697cc6d38fb4f782264ba1dfb2bb6109347676fe2f95e27'
GATE_SHA='b30fb108a72f6aaa008789a6af8b9801ca23dce3dd5f6bd62eb799496cf07027'
PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-155oj3tc'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-155oj3tc'
WRAPPER=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
WRAPPER_SHA='4bd86d0c27039a238ac4894cf0c151745c92814c94af7b5a2f2ed173b70d685a'
A='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
S='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
EXPECTED_SHIMS={S:(1687756,187652001,'f2a0198b8e06603b3daa6530a927e41e11184fbdae125a1018d81fe9dab3eebf'),A:(1722469,188620013,'762364382f44d3e488899586852dac34e4e1c0118d91239a4d178ff9e75825b1')}
ADVANCED={str(ROOT/'registry'/A/'adapter.json'):'845f651d465db7371b0323dff59e34a1fa7eb745ce4187d77dce5c2432eb013f',str(ROOT/'registry'/A/'broker-state.json'):'30d5f37959ae01e4f96bb5c8a7bffa172945188a360df29f16dc7d64f5256f58',str(ROOT/'registry'/A/'deployment.json'):'129a99edc87e48537ff0337f2e517718faf416682b3e6a02d6ec1568563f9442'}
OWNER_SHA='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
class Denied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Denied(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def load(path,expected,name):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:raw=os.read(fd,131073)
    finally:os.close(fd)
    require(sha(raw)==expected,'REVIEWED_HELPER_HASH_DRIFT')
    result={'__name__':name,'__file__':str(path)};exec(compile(raw,str(path),'exec'),result);return result,raw

def publish(path,raw,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def replace_wrapper(entry,expected,new,stage):
    require(entry['read'](WRAPPER,True)==expected,'EXACT_WRAPPER_CAS_REQUIRED')
    publish(stage,new,0o755)
    require(entry['read'](WRAPPER,True)==expected,'WRAPPER_CHANGED_BEFORE_RENAME')
    os.replace(stage,WRAPPER)
    fd=os.open(WRAPPER.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(entry['read'](WRAPPER,True)==new,'WRAPPER_REPLACEMENT_UNPROVEN')

def validate_review(report):
    require(report.get('status')=='R5_TERMINAL_REVIEW_CAPTURED' and report.get('allRecordedTaskPidsAbsent') is True,'EXACT_TERMINAL_ABSENCE_REVIEW_REQUIRED')
    require(report.get('containerdVersions')=={'Client':'v2.3.5','Server':'v2.3.5'},'REVIEWED_CONTAINERD_VERSION_REQUIRED')
    require(report.get('installedWrapperHash')==WRAPPER_SHA,'EXACT_R5_WRAPPER_REQUIRED')
    require(report['nativeEmptyGuardObservation']['providerSetsEmpty'] is True,'CURRENT_EMPTY_GUARD_REQUIRED')
    for cid,expected in EXPECTED_SHIMS.items():
        shims=report['terminalTaskReview'][cid]['shims'];require(len(shims)==1,'EXACT_RETAINED_SHIM_REQUIRED');shim=shims[0]
        require((shim['pid'],shim['startTicks'],shim['argvHash'])==expected and shim['executableHash']=='e873923a2d5361f14494a8434543b5bb218aa15736b1ac5bb73dbce5ac9ea1cb','EXACT_RETAINED_SHIM_GENERATION_REQUIRED')

def main(approval_ref,review_path,gate_path):
    report={'schema':'ouf.semantic-terminal-task-cleanup.v1','status':'BLOCKED','privateKeysRead':0,'signaturesIssued':0,'dockerStartRequests':0,'providerCalls':0,'daemonRestarted':False,'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,'automaticRetryPerformed':False,'taskDeleteRequests':0,'wrapperRestored':False,'priorJournalsPreserved':False,'doNotRerunApply':False}
    phase='VERIFY_SCOPED_HUMAN_MAINTENANCE_APPROVAL';output=None;entry=None;old=None;new=None;fd=None;switched=False
    try:
        require(APPROVAL_REF!='PENDING_TERMINAL_TASK_CLEANUP_APPROVAL' and approval_ref==APPROVAL_REF and type(APPROVED_AT) is int,'EXPLICIT_TERMINAL_CLEANUP_APPROVAL_REQUIRED')
        require(APPROVED_AT<=int(time.time())<APPROVED_AT+3600,'LIVE_HUMAN_MAINTENANCE_APPROVAL_REQUIRED')
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
        reader,_=load(review_path,REVIEW_SHA,'terminal_review');_,gate_raw=load(gate_path,GATE_SHA,'terminal_gate')
        phase='FRESH_TERMINAL_REVIEW_BEFORE_MUTATION'
        with contextlib.redirect_stdout(io.StringIO()) as capture:exit_code=reader['main']()
        line=capture.getvalue();require(line.startswith('OUF_R5_TERMINAL_CLEANUP_REVIEW='),'TERMINAL_REVIEW_OUTPUT_UNPROVEN')
        reviewed=json.loads(line.split('=',1)[1])
        if exit_code!=0:report['preflightReadOnlyDiagnosis']=reviewed
        require(exit_code==0,'TERMINAL_REVIEW_UNPROVEN');validate_review(reviewed)
        entry,_=load(PACKAGE/'provider_transaction_intake.py','edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5','terminal_cleanup_entry');entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        require(approval['approvalRef']=='OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_HUMAN_APPROVAL_20261009_130246','EXACT_RETAINED_R5_APPROVAL_REQUIRED')
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}));require(cfg['outputRoot']==str(ROOT),'EXACT_R5_OUTPUT_REQUIRED')
        require(not os.path.lexists(CONTEXT/'terminal-task-cleanup-claim.json'),'DO_NOT_REPLAY_TERMINAL_CLEANUP')
        denial=entry['parse'](entry['read'](ROOT/'cohort-activation-denial.json'))
        require(denial['reason']=='COHORT_ADMITTED_RUNNING_STATE_UNPROVEN' and denial['dockerStartRequests']==2 and not os.path.lexists(ROOT/'cohort-activation-receipt.json'),'EXACT_FAILED_R5_REQUIRED')
        receipt=entry['parse'](entry['read'](ROOT/'installation-receipt.json'));frozen={}
        require(len(receipt['fileHashes'])==81,'EXACT_RETAINED_PUBLICATION_REQUIRED')
        for path,digest in receipt['fileHashes'].items():
            require(Path(path).is_relative_to(ROOT) and '..' not in Path(path).parts,'RETAINED_PATH_ESCAPE')
            frozen[path]=sha(entry['bound']({'path':path,'sha256':ADVANCED.get(path,digest)}))
        for cid in (A,S):
            for name in reader['NAMES'] if 'NAMES' in reader else ('adapter.json','broker-state.json','deployment.json','bundle/config.json','broker-denial-cohort-ready.json'):
                path=ROOT/'registry'/cid/name
                if os.path.lexists(path):frozen[str(path)]=sha(entry['read'](path))
        old=entry['read'](WRAPPER,True);require(sha(old)==WRAPPER_SHA,'EXACT_RETAINED_WRAPPER_REQUIRED')
        runtime_root=entry['parse'](entry['read'](ROOT/'registry'/A/'adapter.json'))['runtimeRoot']
        require(sha(runtime_root.encode())==reviewed['runtimeRootHash'],'EXACT_RETAINED_RUNC_ROOT_REQUIRED')
        template=entry['parse'](entry['bound'](cfg['recordsByRole']['adapter']['preparerTemplate']));runc=template['candidate']['runtimeBinding']
        from transaction_guard_observation import observe_locked,executable_binding
        from authenticate_provider_transaction import TARGETS
        pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']));binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
        owner=entry['parse'](entry['bound']({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':OWNER_SHA}))
        candidates={t['containerId']:{'imageManifestDigest':t['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for t in TARGETS.values()}
        fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        phase='LOCKED_RECHECK_AND_RESERVE_SINGLE_MAINTENANCE_WINDOW'
        observed=observe_locked(fd,binding,OWNER_SHA,candidates,cfg['commandBindings'])
        require(observed['candidateStateHashes']==reviewed['nativeEmptyGuardObservation']['candidateStateHashes'],'CANDIDATE_CHANGED_BEFORE_MAINTENANCE')
        for cid,row in reviewed['containerdRequestedTasks'].items():require(not os.path.lexists('/proc/'+str(row['pid'])),'TASK_PID_REAP_REQUIRED')
        output=Path(tempfile.mkdtemp(prefix='semantic-terminal-task-cleanup-',dir=ROOT.parent));output.chmod(0o700);report['evidenceDirectory']=str(output)
        publish(output/'reviewed-terminal-facts.json',encoded(reviewed));publish(output/'retained-file-hashes.json',encoded(frozen));publish(output/'prior-wrapper.sh',old)
        now=int(time.time());window={'schema':'ouf.semantic-terminal-task-delete-window.v1','approvalRef':APPROVAL_REF,'issuedAt':now,'expiresAt':now+120,'tasks':{cid:{'pid':row['pid']} for cid,row in reviewed['containerdRequestedTasks'].items()},'runtimeRoot':runtime_root,'runcBinding':runc}
        publish(output/'gate.py',gate_raw);publish(output/'window.json',encoded(window))
        python=cfg['pythonBinding'];executable_binding(python)
        new=('#!/bin/sh\nexec '+python['path']+' -I -B '+str(output/'gate.py')+' --configuration '+str(output/'window.json')+' "$@"\n').encode()
        publish(CONTEXT/'terminal-task-cleanup-claim.json',encoded({'schema':'ouf.semantic-terminal-cleanup-claim.v1','approvalRef':APPROVAL_REF,'approvedAt':APPROVED_AT,'evidenceDirectory':str(output),'retainedWrapperHash':WRAPPER_SHA,'maintenanceWrapperHash':sha(new),'windowHash':sha(encoded(window)),'tasks':window['tasks'],'startAuthorized':False,'notReleaseAcceptance':True}));report['doNotRerunApply']=True
        phase='INSTALL_TEMPORARY_DELETE_ONLY_WRAPPER'
        # Track replacement even if the post-rename custody check fails.
        try:replace_wrapper(entry,old,new,WRAPPER.parent/('.ouf-terminal-install-'+sha(new)))
        finally:switched=entry['read'](WRAPPER,True)==new
        require(switched,'MAINTENANCE_WRAPPER_NOT_INSTALLED')
        ctr={'path':'/usr/bin/ctr','sha256':reviewed['ctrExecutableHash']};binary=executable_binding(ctr)
        def command(args):
            require(executable_binding(ctr)==binary,'CTR_EXECUTABLE_DRIFT')
            result=subprocess.run([ctr['path'],'--address','/run/containerd/containerd.sock','--namespace','moby',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            require(len(result.stdout)<=131072 and len(result.stderr)<=131072,'CTR_MAINTENANCE_OUTPUT_UNBOUNDED')
            return result
        phase='DELETE_EXACT_STOPPED_TASKS_WITHOUT_FORCE'
        for cid in (S,A):
            require(time.time()<window['expiresAt'],'MAINTENANCE_WINDOW_EXPIRED')
            shim=reviewed['terminalTaskReview'][cid]['shims'][0];proc=Path('/proc')/str(shim['pid'])
            stat_raw=(proc/'stat').read_bytes();tail=stat_raw[stat_raw.rfind(b')')+2:].split()
            require(int(tail[19])==shim['startTicks'] and sha((proc/'cmdline').read_bytes())==shim['argvHash']
                and os.readlink(proc/'cwd')=='/run/containerd/io.containerd.runtime.v2.task/moby/'+cid,'SHIM_GENERATION_CHANGED_BEFORE_DELETE')
            info=command(['containers','info',cid]);require(info.returncode==0 and sha(info.stdout)==reviewed['containerdRequestedTasks'][cid]['containerMetadataHash'],'CONTAINER_METADATA_CHANGED_BEFORE_DELETE')
            task_rows=command(['tasks','list']);require(task_rows.returncode==0,'TASK_PREDELETE_READ_FAILED')
            rows=[row.split() for row in task_rows.stdout.decode().splitlines()[1:] if row.split()[0]==cid]
            require(len(rows)==1 and rows[0][1:]==[str(window['tasks'][cid]['pid']),'STOPPED'],'EXACT_STOPPED_TASK_REQUIRED')
            report['taskDeleteRequests']+=1
            result=command(['tasks','delete',cid]);publish(output/('task-delete-'+cid+'.json'),encoded({'containerId':cid,'exitCode':result.returncode,'stdoutHash':sha(result.stdout),'stderrHash':sha(result.stderr),'forceUsed':False,'rawOutputPrinted':False}))
            require(result.returncode==0,'TERMINAL_TASK_DELETE_UNPROVEN')
        phase='VERIFY_TASK_ABSENCE_AND_RETAINED_CONTAINER_METADATA'
        rows=command(['tasks','list']);require(rows.returncode==0,'POSTDELETE_TASK_READ_FAILED')
        require(not any(line.split()[0] in (A,S) for line in rows.stdout.decode().splitlines()[1:]),'TERMINAL_TASKS_STILL_PRESENT')
        for cid in (A,S):
            info=command(['containers','info',cid]);require(info.returncode==0 and sha(info.stdout)==reviewed['containerdRequestedTasks'][cid]['containerMetadataHash'],'CONTAINER_METADATA_NOT_PRESERVED')
        require(all(sha(entry['read'](path))==digest for path,digest in frozen.items()),'RETAINED_JOURNAL_OR_SOURCE_CHANGED');report['priorJournalsPreserved']=True
        report['status']='TWO_TERMINAL_TASKS_REMOVED_CONTAINERS_PRESERVED'
    except Exception as error:
        report.update(status='BLOCKED',phase=phase,errorType=type(error).__name__,reason=str(error) if isinstance(error,Denied) else 'TERMINAL_CLEANUP_UNPROVEN',exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    finally:
        if switched:
            try:
                replace_wrapper(entry,new,old,WRAPPER.parent/('.ouf-terminal-restore-'+sha(new)));report['wrapperRestored']=True
            except Exception as error:report.update(status='BLOCKED',wrapperRestorationError=type(error).__name__,reason='EXACT_R5_WRAPPER_RESTORATION_UNPROVEN')
        if fd is not None:
            try:
                if report['wrapperRestored']:report['postMaintenanceEmptyGuard']=observe_locked(fd,binding,OWNER_SHA,candidates,cfg['commandBindings'])
            except Exception as error:report.update(status='BLOCKED',postGuardError=type(error).__name__,reason='POST_MAINTENANCE_EMPTY_GUARD_UNPROVEN')
            finally:os.close(fd)
        report.setdefault('phase',phase)
        report['containerLifecycleOperations']=None if report['taskDeleteRequests'] else 0
        if output is not None:
            try:publish(output/'maintenance-result.json',encoded(report))
            except Exception:report.update(status='BLOCKED',diagnosisSaved=False)
    report['containerLifecycleOperations']=None if report['taskDeleteRequests'] else 0
    print('OUF_TERMINAL_TASK_CLEANUP='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='TWO_TERMINAL_TASKS_REMOVED_CONTAINERS_PRESERVED' else 1
if __name__=='__main__':
    if len(sys.argv)!=4:raise SystemExit('EXACT_TERMINAL_CLEANUP_CLI_REQUIRED')
    sys.exit(main(*sys.argv[1:]))
