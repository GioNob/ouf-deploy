"""Inert until scoped human approval: remove only two stopped residual tasks.

Temporary delete-only gate; no application start, kill/force, key access,
container/image/snapshot deletion, journal reset or automatic retry.
"""
import contextlib,fcntl,hashlib,io,json,os,re,stat,subprocess,sys,tempfile,time,traceback
from pathlib import Path
APPROVAL_REF='PENDING_R6_TERMINAL_CLEANUP_APPROVAL'
APPROVED_AT=None
APPROVAL_EXPIRES_AT=None
REVIEW_SHA='21c10d32b9acbc80a044a14e87501d060bd273e3aa87b32ce9337b8ef1da66cb'
GATE_SHA='a23f71e7fbe29fc3df4f138f41d35b4b5a3c63f14f1f15bc1c9e3d62644c9cfe'
ARGUMENT_READER_SHA='d81fe4518b452c130b1c8c0fef14ffff6cc7a09ab3c92e29d28441786e52b5c7'
ROOT_SHA='c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342'
PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-aj1j95xl'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-aj1j95xl'
WRAPPER=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
WRAPPER_SHA='cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b'
A='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
S='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
EXPECTED_SHIMS={S:(1770676,189951186,'f2a0198b8e06603b3daa6530a927e41e11184fbdae125a1018d81fe9dab3eebf'),A:(1770658,189951185,'762364382f44d3e488899586852dac34e4e1c0118d91239a4d178ff9e75825b1')}
ADVANCED={
    str(ROOT/'registry'/A/'adapter.json'):'5b850802dbc61cd8d9d1ccbfe9c75b57917c52222f9d65d43ffc24930c560198',
    str(ROOT/'registry'/A/'broker-state.json'):'969d92716fcc40ef1387befaec2d567c5a8aefbc22de785ac46da78f8a1f87a8',
    str(ROOT/'registry'/A/'deployment.json'):'0aefa18a2c5becdfdecd0405516e80040512c964e6f8298ec58eb3e788016319',
    str(ROOT/'registry'/S/'adapter.json'):'498be28e1ef00614afbc03214c522e73269fbe54ed5b34a0e88a805d32f1ef6b',
    str(ROOT/'registry'/S/'broker-state.json'):'dd805e96973f8576a6548077e211597520a0047c296d488bbbdb37b49d2d3a36',
    str(ROOT/'registry'/S/'deployment.json'):'c58496f3ee17a74b0204054eaf1d3d1da7be11b7608f17ccb4d5c549acec9617'}
TASKS={S:(1770730,'a2f5559ede95345286407a66a7dc8206ba39a7cab93cf66a666f4a64ec082b0a'),
       A:(1770715,'32c634d6dc131f577be32caf8d80f8662437f6fb3521ed52bc3cae7bdd0e73ff')}
STATES={S:'7674a0e65ecc160881ecaa65c30c61c1d64b91a3dab78c3c5c9a9183acb762bc',
        A:'90ad7da25dd59e78566b06512e8bf57e4b7022bb101b6e701585ed7a79fcab58'}
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
    require(report.get('status')=='R6_TERMINAL_REVIEW_CAPTURED' and report.get('allRecordedTaskPidsAbsent') is True,'EXACT_TERMINAL_ABSENCE_REVIEW_REQUIRED')
    require(report.get('containerdVersions')=={'Client':'v2.3.5','Server':'v2.3.5'},'REVIEWED_CONTAINERD_VERSION_REQUIRED')
    require(report.get('installedWrapperHash')==WRAPPER_SHA,'EXACT_R6_WRAPPER_REQUIRED')
    guard=report['nativeEmptyGuardObservation']
    require(guard['providerSetsEmpty'] is True and guard['lockInodePreserved'] is True
        and guard['configurationHash']==OWNER_SHA and guard['candidateStateHashes']==STATES,'CURRENT_EMPTY_GUARD_REQUIRED')
    require(set(report['containerdRequestedTasks'])=={A,S},'EXACT_TWO_TASKS_REQUIRED')
    for cid,(pid,metadata) in TASKS.items():
        row=report['containerdRequestedTasks'][cid]
        require(row['taskPresent'] is True and row['status']=='STOPPED' and row['pid']==pid
            and row['containerMetadataHash']==metadata and row['runtimeKind']=='io.containerd.runc.v2','EXACT_R6_TASK_GENERATION_REQUIRED')
        require(not report['requestedEntriesAtRetainedRoot'][cid]['entryPresent'],'R6_NATIVE_TASK_ABSENCE_REQUIRED')
    for cid,expected in EXPECTED_SHIMS.items():
        shims=report['terminalTaskReview'][cid]['shims'];require(len(shims)==1,'EXACT_RETAINED_SHIM_REQUIRED');shim=shims[0]
        require((shim['pid'],shim['startTicks'],shim['argvHash'])==expected and shim['executableHash']=='e873923a2d5361f14494a8434543b5bb218aa15736b1ac5bb73dbce5ac9ea1cb','EXACT_RETAINED_SHIM_GENERATION_REQUIRED')

def retain_failed_attempt(entry):
    paths=['execution-claim.json','human-approval-binding.json','execution-configuration.json']
    frozen={str(CONTEXT/name):sha(entry['read'](CONTEXT/name)) for name in paths}
    raw=entry['read'](ROOT/'cohort-activation-denial.json')
    require(sha(raw)=='a87bc84ef93af80fb8bd871daae77979604eea9ab77fa352ceca35e828c0bf3d','EXACT_CONSUMED_R6_DENIAL_REQUIRED')
    frozen[str(ROOT/'cohort-activation-denial.json')]=sha(raw)
    claim=entry['parse'](entry['read'](CONTEXT/'execution-claim.json'))
    require(claim['outputRoot']==str(ROOT),'EXACT_CONSUMED_R6_CLAIM_REQUIRED')
    for name in ('runtime-switch-claim.json','runtime-switch-receipt.json','cohort-activation-claim.json','installation-receipt.json'):
        frozen[str(ROOT/name)]=sha(entry['read'](ROOT/name))
    for cid in (A,S):
        require(all(not os.path.lexists(ROOT/'registry'/cid/name) for name in
            ('attestation-emission.json','approval-emission.json','attestation.json','approval.json','preexec.json')),
            'R6_POST_PREPARE_RECORD_CONFLICT')
    return frozen

def retained_alias(entry,arguments,gate,runtime_root):
    require(sha(runtime_root.encode())==ROOT_SHA,'EXACT_RETAINED_CANONICAL_ROOT_REQUIRED')
    frozen={};supplied_roots=set()
    for cid in (S,A):
        bundle=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid
        raw=entry['read'](bundle/'options.json')
        binary,supplied,argv=arguments['reconstruct'](entry['parse'](raw),bundle,cid)
        runtime_raw=entry['read'](bundle/'runtime')
        require(binary==str(WRAPPER) and runtime_raw.decode()==binary,'EXACT_RETAINED_RUNTIME_REQUIRED')
        gate['validate_root_binding']({'runtimeArgumentRoot':supplied,'runtimeRoot':runtime_root})
        require(gate['parse_delete'](argv,(S,A),supplied)==cid,'EXACT_ALIAS_DELETE_PREDICATE_REQUIRED')
        supplied_roots.add(supplied)
        frozen[str(bundle/'options.json')]=sha(raw);frozen[str(bundle/'runtime')]=sha(runtime_raw)
    require(len(supplied_roots)==1,'EXACT_SHARED_ALIAS_REQUIRED')
    return supplied_roots.pop(),frozen

def main(approval_ref,review_path,gate_path,argument_reader_path):
    report={'schema':'ouf.semantic-r6-terminal-cleanup.v1','status':'BLOCKED','privateKeysRead':0,'signaturesIssued':0,'dockerStartRequests':0,'providerCalls':0,'daemonRestarted':False,'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,'automaticRetryPerformed':False,'taskDeleteRequests':0,'wrapperRestored':False,'priorJournalsPreserved':False,'doNotRerunApply':False}
    phase='VERIFY_SCOPED_HUMAN_MAINTENANCE_APPROVAL';output=None;entry=None;old=None;new=None;fd=None;switched=False
    try:
        require(APPROVAL_REF!='PENDING_R6_TERMINAL_CLEANUP_APPROVAL' and approval_ref==APPROVAL_REF and type(APPROVED_AT) is int and type(APPROVAL_EXPIRES_AT) is int,'EXPLICIT_TERMINAL_CLEANUP_APPROVAL_REQUIRED')
        require(APPROVED_AT<=int(time.time())<APPROVAL_EXPIRES_AT,'LIVE_HUMAN_MAINTENANCE_APPROVAL_REQUIRED')
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
        reader,_=load(review_path,REVIEW_SHA,'terminal_review');gate,gate_raw=load(gate_path,GATE_SHA,'terminal_gate')
        arguments,_=load(argument_reader_path,ARGUMENT_READER_SHA,'retained_argument_reader')
        phase='FRESH_TERMINAL_REVIEW_BEFORE_MUTATION'
        with contextlib.redirect_stdout(io.StringIO()) as capture:exit_code=reader['main']()
        line=capture.getvalue();require(line.startswith('OUF_R6_TERMINAL_STATE_READ_ONLY='),'TERMINAL_REVIEW_OUTPUT_UNPROVEN')
        reviewed=json.loads(line.split('=',1)[1])
        if exit_code!=0:report['preflightReadOnlyDiagnosis']=reviewed
        require(exit_code==0,'TERMINAL_REVIEW_UNPROVEN');validate_review(reviewed)
        entry,_=load(PACKAGE/'provider_transaction_intake.py','edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5','terminal_cleanup_entry');entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        require(approval['approvalRef']=='OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_APPROVED_20261009T165118_CEST_R6','EXACT_RETAINED_R6_APPROVAL_REQUIRED')
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}));require(cfg['outputRoot']==str(ROOT),'EXACT_R6_OUTPUT_REQUIRED')
        require(not os.path.lexists(CONTEXT/'r6-terminal-task-cleanup-claim.json'),'DO_NOT_REPLAY_TERMINAL_ALIAS_RECOVERY')
        retained_failure=retain_failed_attempt(entry)
        denial=entry['parse'](entry['read'](ROOT/'cohort-activation-denial.json'))
        require(denial['reason']=='COHORT_ADMITTED_RUNNING_STATE_UNPROVEN' and denial['dockerStartRequests']==2 and not os.path.lexists(ROOT/'cohort-activation-receipt.json'),'EXACT_FAILED_R6_REQUIRED')
        receipt=entry['parse'](entry['read'](ROOT/'installation-receipt.json'));frozen={}
        require(len(receipt['fileHashes'])==81,'EXACT_RETAINED_PUBLICATION_REQUIRED')
        for path,digest in receipt['fileHashes'].items():
            require(Path(path).is_relative_to(ROOT) and '..' not in Path(path).parts,'RETAINED_PATH_ESCAPE')
            frozen[path]=sha(entry['bound']({'path':path,'sha256':ADVANCED.get(path,digest)}))
        for cid in (A,S):
            for name in reader['NAMES'] if 'NAMES' in reader else ('adapter.json','broker-state.json','deployment.json','bundle/config.json','broker-denial-prepare.json'):
                path=ROOT/'registry'/cid/name
                if os.path.lexists(path):frozen[str(path)]=sha(entry['read'](path))
        frozen.update(retained_failure)
        old=entry['read'](WRAPPER,True);require(sha(old)==WRAPPER_SHA,'EXACT_RETAINED_WRAPPER_REQUIRED')
        runtime_root=entry['parse'](entry['read'](ROOT/'registry'/A/'adapter.json'))['runtimeRoot']
        require(sha(runtime_root.encode())==reviewed['runtimeRootHash'],'EXACT_RETAINED_RUNC_ROOT_REQUIRED')
        runtime_argument_root,option_hashes=retained_alias(entry,arguments,gate,runtime_root)
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
        output=Path(tempfile.mkdtemp(prefix='semantic-r6-terminal-cleanup-',dir=ROOT.parent));output.chmod(0o700);report['evidenceDirectory']=str(output)
        publish(output/'reviewed-terminal-facts.json',encoded(reviewed));publish(output/'retained-file-hashes.json',encoded(frozen));publish(output/'prior-wrapper.sh',old)
        now=int(time.time());window={'schema':'ouf.semantic-terminal-task-delete-window.v2','approvalRef':APPROVAL_REF,'issuedAt':now,'expiresAt':min(now+120,APPROVAL_EXPIRES_AT),'tasks':{cid:{'pid':row['pid']} for cid,row in reviewed['containerdRequestedTasks'].items()},'runtimeRoot':runtime_root,'runtimeArgumentRoot':runtime_argument_root,'runcBinding':runc}
        publish(output/'gate.py',gate_raw);publish(output/'window.json',encoded(window))
        python=cfg['pythonBinding'];executable_binding(python)
        new=('#!/bin/sh\nexec '+python['path']+' -I -B '+str(output/'gate.py')+' --configuration '+str(output/'window.json')+' "$@"\n').encode()
        require(all(sha(entry['read'](path))==digest for path,digest in frozen.items()),'RETAINED_EVIDENCE_CHANGED_BEFORE_CLAIM')
        require(retained_alias(entry,arguments,gate,runtime_root)==(runtime_argument_root,option_hashes),'RETAINED_ALIAS_CHANGED_BEFORE_CLAIM')
        publish(CONTEXT/'r6-terminal-task-cleanup-claim.json',encoded({'schema':'ouf.semantic-r6-terminal-cleanup-claim.v1','approvalRef':APPROVAL_REF,'approvedAt':APPROVED_AT,'evidenceDirectory':str(output),'retainedWrapperHash':WRAPPER_SHA,'maintenanceWrapperHash':sha(new),'windowHash':sha(encoded(window)),'tasks':window['tasks'],'startAuthorized':False,'notReleaseAcceptance':True}));report['doNotRerunApply']=True
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
            # The first deleted task's bundle disappears: recheck only this CID.
            bundle=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid
            require(all(sha(entry['read'](bundle/name))==option_hashes[str(bundle/name)] for name in ('options.json','runtime')),'SHIM_OPTIONS_CHANGED_BEFORE_DELETE')
            gate['validate_root_binding'](window)
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
            publish(output/('task-delete-'+cid+'.stderr'),result.stderr)
            publish(output/('task-delete-'+cid+'.stdout'),result.stdout)
            require(result.returncode==0,'TERMINAL_TASK_DELETE_UNPROVEN')
        phase='VERIFY_TASK_ABSENCE_AND_RETAINED_CONTAINER_METADATA'
        rows=command(['tasks','list']);require(rows.returncode==0,'POSTDELETE_TASK_READ_FAILED')
        require(not any(line.split()[0] in (A,S) for line in rows.stdout.decode().splitlines()[1:]),'TERMINAL_TASKS_STILL_PRESENT')
        for cid in (A,S):
            info=command(['containers','info',cid]);require(info.returncode==0 and sha(info.stdout)==reviewed['containerdRequestedTasks'][cid]['containerMetadataHash'],'CONTAINER_METADATA_NOT_PRESERVED')
        require(all(sha(entry['read'](path))==digest for path,digest in frozen.items()),'RETAINED_JOURNAL_OR_SOURCE_CHANGED');report['priorJournalsPreserved']=True
        report['status']='TWO_TERMINAL_TASKS_REMOVED_ALIAS_RECOVERY_CONTAINERS_PRESERVED'
    except Exception as error:
        report.update(status='BLOCKED',phase=phase,errorType=type(error).__name__,reason=str(error) if isinstance(error,Denied) else 'TERMINAL_CLEANUP_UNPROVEN',exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    finally:
        if switched:
            try:
                replace_wrapper(entry,new,old,WRAPPER.parent/('.ouf-terminal-restore-'+sha(new)));report['wrapperRestored']=True
            except Exception as error:report.update(status='BLOCKED',wrapperRestorationError=type(error).__name__,reason='EXACT_R6_WRAPPER_RESTORATION_UNPROVEN')
        if fd is not None:
            try:
                if report['wrapperRestored']:report['postMaintenanceEmptyGuard']=observe_locked(fd,binding,OWNER_SHA,candidates,cfg['commandBindings'])
            except Exception as error:report.update(status='BLOCKED',postGuardError=type(error).__name__,reason='POST_MAINTENANCE_EMPTY_GUARD_UNPROVEN')
            finally:os.close(fd)
        if entry is not None and 'frozen' in locals():
            try:
                report['priorJournalsPreserved']=all(sha(entry['read'](path))==digest for path,digest in frozen.items())
                if not report['priorJournalsPreserved']:report.update(status='BLOCKED',reason='RETAINED_JOURNAL_OR_SOURCE_CHANGED')
            except Exception:report.update(status='BLOCKED',priorJournalsPreserved=False,reason='RETAINED_PRESERVATION_UNPROVEN')
        report.setdefault('phase',phase)
        report['containerLifecycleOperations']=None if report['taskDeleteRequests'] else 0
        if output is not None:
            try:publish(output/'maintenance-result.json',encoded(report))
            except Exception:report.update(status='BLOCKED',diagnosisSaved=False)
    report['containerLifecycleOperations']=None if report['taskDeleteRequests'] else 0
    print('OUF_R6_TERMINAL_CLEANUP='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='TWO_TERMINAL_TASKS_REMOVED_ALIAS_RECOVERY_CONTAINERS_PRESERVED' else 1
if __name__=='__main__':
    if len(sys.argv)!=5:raise SystemExit('EXACT_TERMINAL_CLEANUP_CLI_REQUIRED')
    sys.exit(main(*sys.argv[1:]))
