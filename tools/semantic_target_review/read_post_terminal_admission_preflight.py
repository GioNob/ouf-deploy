"""Read current admission prerequisites after the exact successful terminal recovery.

No lifecycle, keys, signatures, claims, configuration writes or approval creation.
Old R5 mandates are evidence only, never validated as current start authority.
"""
import fcntl,hashlib,json,os,re,subprocess,sys,time,traceback
from pathlib import Path
PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-155oj3tc'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-155oj3tc'
MAINTENANCE=PACKAGE.parent/'semantic-terminal-alias-recovery-3d6pbi16'
FAILED=PACKAGE.parent/'semantic-terminal-task-cleanup-uoq_m_o7'
APPROVAL='OUF_TERMINAL_ALIAS_RECOVERY_HUMAN_APPROVAL_20261009_160745'
WRAPPER_SHA='4bd86d0c27039a238ac4894cf0c151745c92814c94af7b5a2f2ed173b70d685a'
ROOT_SHA='c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342'
CLOSURE_SHA='702403e9cd99ddc4ddeed7166f3f408c55657fc690e475e0b35bb5d2c2242bb3'
OWNER_SHA='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
A='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
S='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
STATES={S:'02d11a458636fedb4377f8a191e696589b1d0b92e0c272b471f0b03f2f8d92ad',A:'daa3f41b98479f443d597bbebb28154a16db0192751feec466db843755be35b1'}
METADATA={S:'6a39de17aa02d0358dcac7b931645ac84004bbec013443eec29447c6d772f767',A:'45b95bc5610c03f5db63d48c52070c5d1302d8bde6a5f22c1ef978bb6bcf2868'}
class Denied(ValueError):
    def __init__(self,reason,observation=None):
        super().__init__(reason);self.observation=observation
def require(ok,reason):
    if not ok:raise Denied(reason)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def validate_success(value,claim):
    require(value.get('schema')=='ouf.semantic-terminal-alias-recovery.v1'
        and value.get('status')=='TWO_TERMINAL_TASKS_REMOVED_ALIAS_RECOVERY_CONTAINERS_PRESERVED'
        and value.get('taskDeleteRequests')==2 and value.get('wrapperRestored') is True
        and value.get('priorJournalsPreserved') is True and value.get('doNotRerunApply') is True
        and value.get('evidenceDirectory')==str(MAINTENANCE),'EXACT_SUCCESSFUL_TERMINAL_RECOVERY_REQUIRED')
    require(all(value.get(k)==0 for k in ('dockerStartRequests','providerCalls','privateKeysRead','signaturesIssued'))
        and value.get('automaticRetryPerformed') is False and value.get('startAuthorized') is False,
        'EXACT_TERMINAL_NO_START_RESULT_REQUIRED')
    guard=value.get('postMaintenanceEmptyGuard',{})
    require(guard.get('providerSetsEmpty') is True and guard.get('lockInodePreserved') is True
        and guard.get('candidateStateHashes')==STATES and guard.get('configurationHash')==OWNER_SHA,
        'EXACT_RETAINED_EMPTY_GUARD_REQUIRED')
    require(claim.get('schema')=='ouf.semantic-terminal-alias-recovery-claim.v1'
        and claim.get('approvalRef')==APPROVAL and claim.get('approvedAt')==1791554865
        and claim.get('evidenceDirectory')==str(MAINTENANCE)
        and claim.get('retainedWrapperHash')==WRAPPER_SHA and set(claim.get('tasks',{}))=={S,A},
        'EXACT_CONSUMED_ALIAS_CLAIM_REQUIRED')
def allowed_frozen_path(path):
    p=Path(path)
    return p.is_absolute() and '..' not in p.parts and str(p)==path and (
        p.is_relative_to(ROOT) or p.is_relative_to(FAILED) or p==CONTEXT/'terminal-task-cleanup-claim.json')
def absent_tasks(raw):
    lines=raw.decode().splitlines();require(bool(lines) and lines[0].split()==['TASK','PID','STATUS'],'TASK_LIST_HEADER_UNPROVEN')
    for line in lines[1:]:
        fields=line.split();require(len(fields)==3 and fields[1].isdigit(),'TASK_LIST_FORMAT_UNPROVEN')
        require(fields[0] not in STATES,'TERMINAL_TASK_REAPPEARED')
def published_closure(installation,frozen,expected_names,encoded):
    files=installation['fileHashes'];require(type(files) is dict,'PUBLICATION_FILE_MAP_REQUIRED')
    for name,h in files.items():
        p=Path(name)
        require(p.is_relative_to(ROOT) and '..' not in p.parts and str(p)==name
            and type(h) is str and re.fullmatch('[0-9a-f]{64}',h),'PUBLICATION_PATH_OR_HASH_DRIFT')
    hashes={str(Path(p).relative_to(ROOT/'source')):h for p,h in files.items() if Path(p).is_relative_to(ROOT/'source')}
    observation={'publicationFileCount':len(files),'expectedSourceCount':len(expected_names),
        'publishedSourceCount':len(hashes),'exactSourceNames':set(hashes)==set(expected_names),
        'sourceClosureHash':digest(encoded(hashes))}
    if not (len(files)==81 and observation['exactSourceNames']
            and observation['sourceClosureHash']==CLOSURE_SHA):
        raise Denied('EXACT_RETAINED_R5_SOURCE_CLOSURE_REQUIRED',observation)
    require(all(frozen.get(str(ROOT/'source'/name))==h for name,h in hashes.items()),'PUBLISHED_SOURCE_NOT_FROZEN')
    return observation
def run_read(binding,args,executable_binding):
    identity=executable_binding(binding)
    result=subprocess.run([binding['path'],*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock'})
    require(result.returncode==0 and len(result.stdout)<=131072,'BOUNDED_NATIVE_READ_REQUIRED')
    require(executable_binding(binding)==identity,'NATIVE_READ_EXECUTABLE_DRIFT')
    return result.stdout
def main():
    report={'schema':'ouf.semantic-post-terminal-admission-preflight-read-only.v1','privateKeysRead':0,
        'signaturesIssued':0,'containerLifecycleOperations':0,'existingConfigurationWrites':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'claimsCreated':0,'priorMandatesUsedAsCurrentAuthority':False,'roles':{}}
    phase='VERIFY_SUCCESSFUL_MAINTENANCE_CUSTODY';fd=None
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_READER_REQUIRED')
        path=PACKAGE/'provider_transaction_intake.py';handle=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:raw=os.read(handle,131073)
        finally:os.close(handle)
        require(digest(raw)=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5','SEALED_ENTRY_HASH_DRIFT')
        entry={'__name__':'post_terminal_reader','__file__':str(path)}
        exec(compile(raw,str(path),'exec'),entry)
        require(entry['read'](path)==raw,'SEALED_ENTRY_CUSTODY_CHANGED')
        sealed_sources,sealed_observer=entry['load'](PACKAGE)
        success_raw=entry['read'](MAINTENANCE/'maintenance-result.json')
        claim_raw=entry['read'](CONTEXT/'terminal-task-alias-recovery-claim.json')
        success=entry['parse'](success_raw);claim=entry['parse'](claim_raw);validate_success(success,claim)
        window_raw=entry['bound']({'path':str(MAINTENANCE/'window.json'),'sha256':claim['windowHash']})
        window=entry['parse'](window_raw)
        require(window['approvalRef']==APPROVAL and window['tasks']==claim['tasks'],'CONSUMED_WINDOW_BINDING_DRIFT')
        frozen_raw=entry['read'](MAINTENANCE/'retained-file-hashes.json');frozen=entry['parse'](frozen_raw)
        require(type(frozen) is dict and 83<=len(frozen)<=256,'BOUNDED_RETAINED_FILE_MAP_REQUIRED')
        for p,h in frozen.items():
            require(allowed_frozen_path(p) and re.fullmatch('[0-9a-f]{64}',h),'FROZEN_PATH_OR_HASH_DRIFT')
            entry['bound']({'path':p,'sha256':h})
        require(digest(entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True))==WRAPPER_SHA,'RESTORED_R5_WRAPPER_REQUIRED')
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        require(approval['approvalRef']=='OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_HUMAN_APPROVAL_20261009_130246','EXACT_R5_CONTEXT_REQUIRED')
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        require(cfg['outputRoot']==str(ROOT),'EXACT_R5_OUTPUT_REQUIRED')
        phase='REVIEW_ACCEPTED_INPUTS_AND_PUBLISHED_SOURCE_CLOSURE'
        records={role:{name:entry['bound'](binding) for name,binding in values.items()} for role,values in cfg['recordsByRole'].items()}
        from authenticate_provider_transaction import TARGETS,preflight_input_pair,validate_dependency_evidence
        from issue_provider_transaction_authority import INPUTS
        require(set(records)=={'adapter','southbound'} and all(set(v)==set(INPUTS) for v in records.values()),'EXACT_SIXTEEN_ACCEPTED_INPUTS_REQUIRED')
        preflight_input_pair(records)
        now=int(time.time())
        for role,values in records.items():
            validate_dependency_evidence(entry['parse'](values['dependencyEvidence']),role,now,now+240)
        report['reviewedDependencyMetadataCovers240Seconds']=True
        installation=entry['parse'](entry['read'](ROOT/'installation-receipt.json'))
        report['sourceClosureObservation']=published_closure(installation,frozen,
            {*sealed_sources,'frame-observer.py'},entry['encoded'])
        report.update(acceptedInputCount=sum(len(v) for v in records.values()),sourceClosureHash=CLOSURE_SHA,
            retainedFilesVerified=len(frozen),successfulMaintenanceResultHash=digest(success_raw),consumedAliasClaimHash=digest(claim_raw))
        phase='READ_CURRENT_TASK_ABSENCE_AND_METADATA_UNDER_COMMON_LOCK'
        from transaction_guard_observation import executable_binding,observe_locked
        pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']))
        guard_binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
        owner=entry['parse'](entry['bound']({'path':str(Path(guard_binding['path']).parent/'coordinated-configuration.json'),'sha256':OWNER_SHA}))
        fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ctr={'path':'/usr/bin/ctr','sha256':'8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e'}
        prefix=['--address','/run/containerd/containerd.sock','--namespace','moby']
        # Endpoint is fixed by the retained successful terminal review; no inferred defaults.
        reviewed=entry['parse'](entry['read'](MAINTENANCE/'reviewed-terminal-facts.json'))
        require(reviewed['containerdEndpointSource']=='LIVE_DOCKER_EXPLICIT_ARGV','RETAINED_EXPLICIT_ENDPOINT_REQUIRED')
        absent_tasks(run_read(ctr,prefix+['tasks','list'],executable_binding))
        journal=entry['parse'](entry['read'](ROOT/'registry'/A/'adapter.json'));runtime_root=journal['runtimeRoot']
        p=Path(runtime_root)
        require(digest(runtime_root.encode())==ROOT_SHA and p.is_relative_to('/run') and '..' not in p.parts
            and str(p.resolve())==runtime_root,'EXACT_RETAINED_NATIVE_ROOT_REQUIRED')
        runtime=entry['parse'](records['adapter']['preparerTemplate'])['candidate']['runtimeBinding']
        rows=entry['parse'](run_read(runtime,['--root',runtime_root,'list','--format','json'],executable_binding))
        require(type(rows) is list and len(rows)<=1024 and all(v.get('id') not in STATES for v in rows),'RUNC_RESIDUAL_REAPPEARED')
        for role,target in TARGETS.items():
            cid=target['containerId'];meta=run_read(ctr,prefix+['containers','info',cid],executable_binding)
            require(digest(meta)==METADATA[cid],'RETAINED_CONTAINER_METADATA_DRIFT')
            report['roles'][role]={'containerId':cid,'taskAbsent':True,'nativeEntryAbsentAtRetainedRoot':True,
                'containerMetadataHash':digest(meta),'inputHashes':{k:digest(v) for k,v in records[role].items()}}
        candidates={t['containerId']:{'imageManifestDigest':t['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for t in TARGETS.values()}
        observed=observe_locked(fd,guard_binding,OWNER_SHA,candidates,cfg['commandBindings'])
        require(observed['providerSetsEmpty'] is True and observed['candidateStateHashes']==STATES,'CURRENT_EMPTY_CANDIDATE_GUARD_DRIFT')
        report['currentEmptyGuard']=observed
        phase='RECHECK_RETAINED_BYTES_AFTER_READS'
        for p,h in frozen.items():entry['bound']({'path':p,'sha256':h})
        require(entry['read'](MAINTENANCE/'maintenance-result.json')==success_raw
            and entry['read'](CONTEXT/'terminal-task-alias-recovery-claim.json')==claim_raw
            and entry['read'](MAINTENANCE/'retained-file-hashes.json')==frozen_raw
            and digest(entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True))==WRAPPER_SHA,'READ_ONLY_CUSTODY_CHANGED')
        report.update(status='POST_TERMINAL_ADMISSION_PREREQUISITES_CAPTURED',phase=phase,
            freshAdmissionApprovalRequired=True,oldContextsPreserved=True)
    except Exception as error:
        if isinstance(error,Denied) and error.observation is not None:
            report['sourceClosureObservation']=error.observation
        reason=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'POST_TERMINAL_PREFLIGHT_UNPROVEN'
        report.update(status='BLOCKED',phase=phase,errorType=type(error).__name__,reason=reason,
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    finally:
        if fd is not None:os.close(fd)
    print('OUF_POST_TERMINAL_ADMISSION_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='POST_TERMINAL_ADMISSION_PREREQUISITES_CAPTURED' else 1
if __name__=='__main__':sys.exit(main())
