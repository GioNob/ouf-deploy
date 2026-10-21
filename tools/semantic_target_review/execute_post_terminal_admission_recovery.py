"""One fresh admission after proven terminal maintenance; inert pending approval.

Preserve consumed R5 and maintenance claims, source closure and sixteen inputs.
A new context owns fresh short-lived authority and one controlled cohort attempt.
"""
import copy
import contextlib
import io
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import time
import traceback

APPROVAL_REF='OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_APPROVED_20261009T165118_CEST_R6'
APPROVED_AT=1791557478
REVIEW_REF='OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_REVIEW_20261009_R6'
BASE_SHA='e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4'
R3_SHA='5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328'
OLD_CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-155oj3tc')
OLD_OUTPUT=OLD_CONTEXT.parent/'semantic-provider-v2-transaction-155oj3tc'
PRIOR_WRAPPER='4bd86d0c27039a238ac4894cf0c151745c92814c94af7b5a2f2ed173b70d685a'
EMPTY_WRAPPER='4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd'
OLD_PARENT='/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'
NEW_PARENT='/run/containerd/io.containerd.runtime.v2.task/moby'
NEW_HASHES={'adapter':'cfc1bfc12855dc49bfe0bf3eef22d0b2fb1f376d017a5cf68a4e77822dc9dfc6',
    'southbound':'ce46668d3652eeb1fbf45ebba78c6fdc15aefa9af62801b536b616635a0f4246'}
EXPECTED_OBSERVATIONS={
    '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916':{
        'stateHash':'02d11a458636fedb4377f8a191e696589b1d0b92e0c272b471f0b03f2f8d92ad',
        'adapterJournalHash':'9be024ee97cba53348bf9ab320681bdef63a0cd4f68b183b09c8381788f16c1c'},
    'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67':{
        'stateHash':'daa3f41b98479f443d597bbebb28154a16db0192751feec466db843755be35b1',
        'adapterJournalHash':'845f651d465db7371b0323dff59e34a1fa7eb745ce4187d77dce5c2432eb013f'}}
ADAPTER='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
PREFLIGHT_SHA='025e3280abf18ee53e20acea2006f63ffd2ba4d80a8549924772d3372c56b958'
MAINTENANCE=OLD_CONTEXT.parent/'semantic-terminal-alias-recovery-3d6pbi16'
SUCCESS_SHA='e020175756e905f15c7c03fca34e3ee5b674adab62c760319cada4483c9e43e9'
ALIAS_CLAIM_SHA='f797624258939272581dd1d11422d58474e33181bc35a62a3d3dd161c51c6595'
SOUTH='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
NEW_CLOSURE='702403e9cd99ddc4ddeed7166f3f408c55657fc690e475e0b35bb5d2c2242bb3'
REPAIR_SHA='c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f'
RETAINED_ROOT_HASH='c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342'
RETAINED_ADVANCED_HASHES={
    'registry/'+ADAPTER+'/adapter.json':'845f651d465db7371b0323dff59e34a1fa7eb745ce4187d77dce5c2432eb013f',
    'registry/'+ADAPTER+'/broker-state.json':'30d5f37959ae01e4f96bb5c8a7bffa172945188a360df29f16dc7d64f5256f58',
    'registry/'+ADAPTER+'/deployment.json':'129a99edc87e48537ff0337f2e517718faf416682b3e6a02d6ec1568563f9442'}
CONTEXT=None
PHASE='REQUIRE_EXPLICIT_POST_TERMINAL_ADMISSION_APPROVAL'
ATTEMPTED=False

def require(ok,reason):
    if not ok:raise ValueError(reason)

def load_definitions(path,expected,name):
    require(Path(path).is_absolute(),'PINNED_PRIOR_BRIDGE_PATH_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:raw=os.read(fd,131073)
    finally:os.close(fd)
    require(hashlib.sha256(raw).hexdigest()==expected,'RETAINED_BRIDGE_HASH_DRIFT')
    value={'__name__':name,'__file__':str(path)}
    exec(compile(raw,str(path),'exec'),value)
    return value

def validate_failure(denial):
    require(denial.get('stage')=='VERIFY_CONTROLLED_DOCKER_COHORT_READBACK'
        and denial.get('reason')=='COHORT_ADMITTED_RUNNING_STATE_UNPROVEN'
        and denial.get('dockerStartRequests')==2 and denial.get('automaticRetryPerformed') is False,
        'EXACT_RETAINED_R5_COHORT_DENIAL_REQUIRED')
    observations=denial.get('candidateObservations',{})
    require(set(observations)==set(EXPECTED_OBSERVATIONS)
        and set(denial.get('dockerResults',{}))==set(EXPECTED_OBSERVATIONS),
        'BOTH_RETAINED_CANDIDATE_OBSERVATIONS_REQUIRED')
    for cid,expected in EXPECTED_OBSERVATIONS.items():
        require(observations[cid].get('adapterState')==('DELETING' if cid==ADAPTER else 'STAGED')
            and observations[cid].get('nativeDenialReason')==('BROKER_PHASE_COHORT_READY_DENIED' if cid==ADAPTER else None)
            and all(observations[cid].get(k)==v for k,v in expected.items())
            and denial['dockerResults'][cid]=={'exitCode':1,'exactCidAcknowledged':False,'errorType':None},
            'EXACT_RETAINED_R5_COHORT_DENIAL_REQUIRED')

def accepted_scope(records,scope,parse,encoded,sha,compile_policy):
    result=copy.deepcopy(scope)
    require(set(records)==set(NEW_HASHES),'EXACT_TWO_ACCEPTED_ROLES_REQUIRED')
    for role,values in records.items():
        expected={**scope['roleProposals'][role]['inputHashes'],'context':NEW_HASHES[role]}
        require({k:sha(v) for k,v in values.items()}==expected,'ACCEPTED_R5_SIXTEEN_INPUTS_DRIFT')
        context=parse(values['context'])
        require(context['bundleParent']==NEW_PARENT and context['containerId']==scope['roleProposals'][role]['containerId'],
            'ACCEPTED_R5_CONTEXT_SCOPE_DRIFT')
        require(encoded(compile_policy(parse(values['template']),parse(values['launch']),context))==values['framePolicy'],
            'COMPLETE_ACCEPTED_FRAME_DRIFT')
        result['roleProposals'][role]['inputHashes']=expected
        result['roleProposals'][role]['sourceClosureHash']=NEW_CLOSURE
        result['roleProposals'][role]['reviewRef']=REVIEW_REF
    result['reviewRef']=REVIEW_REF
    result['package']['sourceClosureHash']=NEW_CLOSURE
    result['runtime']['previousWrapperSha256']=PRIOR_WRAPPER
    result['postTerminalMaintenance']={'successfulResultHash':SUCCESS_SHA,'consumedAliasClaimHash':ALIAS_CLAIM_SHA,
        'retainedContext':str(OLD_CONTEXT),'retainedOutput':str(OLD_OUTPUT)}
    return result


def retained_publication_hash(path,expected):
    p=Path(path)
    require(p.is_relative_to(OLD_OUTPUT) and '..' not in p.parts,'RETAINED_FILE_PATH_ESCAPE')
    return RETAINED_ADVANCED_HASHES.get(str(p.relative_to(OLD_OUTPUT)),expected)


def verify_absent_retained_runc(entry,cfg):
    from transaction_guard_observation import executable_binding
    raw=entry['bound']({'path':str(OLD_OUTPUT/'registry'/ADAPTER/'adapter.json'),
        'sha256':EXPECTED_OBSERVATIONS[ADAPTER]['adapterJournalHash']})
    journal=entry['parse'](raw);runtime_root=journal['runtimeRoot']
    require(type(runtime_root) is str and entry['digest'](runtime_root.encode())==RETAINED_ROOT_HASH,
        'EXACT_RETAINED_RUNTIME_ROOT_REQUIRED')
    p=Path(runtime_root)
    require(p.is_absolute() and '..' not in p.parts and p.is_relative_to('/run') and p!=Path('/run')
        and str(p.resolve())==runtime_root,'RETAINED_RUNTIME_ROOT_PATH_DRIFT')
    template=entry['parse'](entry['bound'](cfg['recordsByRole']['southbound']['preparerTemplate']))
    runtime=template['candidate']['runtimeBinding'];executable_binding(runtime)
    result=subprocess.run([runtime['path'],'--root',runtime_root,'list','--format','json'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and len(result.stdout)<=131072,'RETAINED_RUNC_INVENTORY_UNPROVEN')
    rows=entry['parse'](result.stdout)
    require(type(rows) is list and len(rows)<=1024,'BOUNDED_RETAINED_RUNC_INVENTORY_REQUIRED')
    require(all(v.get('id') not in EXPECTED_OBSERVATIONS for v in rows),'RETAINED_RUNC_RESIDUAL_REQUIRES_DIFFERENT_RECOVERY')
    executable_binding(runtime)
    require(entry['read'](OLD_OUTPUT/'registry'/ADAPTER/'adapter.json')==raw,'RETAINED_JOURNAL_CHANGED_DURING_INVENTORY')

def repaired_entry(raw):
    # Exact two prior-wrapper assertions; no change to the runtime/observer closure.
    require(raw.count(EMPTY_WRAPPER.encode())==2,'EXACT_PRIOR_WRAPPER_ASSERTIONS_REQUIRED')
    return raw.replace(EMPTY_WRAPPER.encode(),PRIOR_WRAPPER.encode())

def validate_preflight(value):
    require(value.get('status')=='POST_TERMINAL_ADMISSION_PREREQUISITES_CAPTURED'
        and value.get('acceptedInputCount')==16 and value.get('retainedFilesVerified')==91
        and value.get('sourceClosureHash')==NEW_CLOSURE
        and value.get('successfulMaintenanceResultHash')==SUCCESS_SHA
        and value.get('consumedAliasClaimHash')==ALIAS_CLAIM_SHA
        and value.get('reviewedDependencyMetadataCovers240Seconds') is True,
        'EXACT_POST_TERMINAL_READBACK_REQUIRED')
    require(value.get('claimsCreated')==0 and value.get('privateKeysRead')==0
        and value.get('signaturesIssued')==0 and value.get('containerLifecycleOperations')==0
        and value.get('startAuthorized') is False,'READ_ONLY_PREFLIGHT_BOUNDARY_REQUIRED')
    guard=value.get('currentEmptyGuard',{})
    require(guard.get('providerSetsEmpty') is True and guard.get('lockInodePreserved') is True
        and guard.get('candidateStateHashes')=={c:v['stateHash'] for c,v in EXPECTED_OBSERVATIONS.items()},
        'EXACT_CURRENT_CREATED_CANDIDATE_GUARD_REQUIRED')
    roles=value.get('roles',{});require(set(roles)=={'adapter','southbound'},'EXACT_TWO_PREFLIGHT_ROLES_REQUIRED')
    for role,cid in (('adapter',ADAPTER),('southbound',SOUTH)):
        row=roles[role]
        require(row.get('containerId')==cid and row.get('taskAbsent') is True
            and row.get('nativeEntryAbsentAtRetainedRoot') is True
            and row.get('containerMetadataHash')==METADATA[cid],
            'EXACT_CURRENT_TASK_ABSENCE_AND_METADATA_REQUIRED')

METADATA={SOUTH:'6a39de17aa02d0358dcac7b931645ac84004bbec013443eec29447c6d772f767',
    ADAPTER:'45b95bc5610c03f5db63d48c52070c5d1302d8bde6a5f22c1ef978bb6bcf2868'}

def retain_terminal_evidence(entry,reader):
    result_path=MAINTENANCE/'maintenance-result.json'
    alias_path=OLD_CONTEXT/'terminal-task-alias-recovery-claim.json'
    result_raw=entry['bound']({'path':str(result_path),'sha256':SUCCESS_SHA})
    alias_raw=entry['bound']({'path':str(alias_path),'sha256':ALIAS_CLAIM_SHA})
    reader['validate_success'](entry['parse'](result_raw),entry['parse'](alias_raw))
    frozen_path=MAINTENANCE/'retained-file-hashes.json'
    frozen=entry['parse'](entry['read'](frozen_path))
    require(type(frozen) is dict and len(frozen)==91,'EXACT_NINETY_ONE_RETAINED_FILES_REQUIRED')
    for p,h in frozen.items():
        require(reader['allowed_frozen_path'](p),'RETAINED_EVIDENCE_PATH_ESCAPE')
        entry['bound']({'path':p,'sha256':h})
    paths=list(MAINTENANCE.iterdir())
    require(0<len(paths)<=64,'BOUNDED_SUCCESSFUL_MAINTENANCE_EVIDENCE_REQUIRED')
    paths.extend((alias_path,OLD_CONTEXT/'execution-claim.json',OLD_CONTEXT/'human-approval-binding.json',
        OLD_CONTEXT/'execution-configuration.json',OLD_OUTPUT/'installation-receipt.json',
        OLD_OUTPUT/'installation-claim.json',OLD_OUTPUT/'runtime-switch-claim.json',
        OLD_OUTPUT/'runtime-switch-receipt.json',OLD_OUTPUT/'cohort-activation-claim.json',
        OLD_OUTPUT/'cohort-activation-denial.json',OLD_OUTPUT/'registry'/ADAPTER/'broker-denial-cohort-ready.json',
        reader['PACKAGE']/'broker-source-recovery-claim.json'))
    for role in ('adapter','southbound'):
        path=OLD_CONTEXT/'role-authority'/role/'role-issuance-receipt.json'
        issued=entry['parse'](entry['read'](path));paths.append(path)
        for binding in issued['records'].values():
            entry['bound'](binding);paths.append(Path(binding['path']))
        signed_files=list((OLD_CONTEXT/'role-authority'/role).rglob('*.json'))
        require(len(signed_files)<=32,'BOUNDED_RETAINED_ROLE_SIGNATURE_EVIDENCE_REQUIRED')
        paths.extend(signed_files)
    for path in paths:frozen[str(path)]=entry['digest'](entry['read'](path))
    return frozen

def verify_absent_retained_tasks(entry,reader):
    from transaction_guard_observation import executable_binding
    ctr={'path':'/usr/bin/ctr','sha256':'8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e'}
    prefix=['--address','/run/containerd/containerd.sock','--namespace','moby']
    reader['absent_tasks'](reader['run_read'](ctr,prefix+['tasks','list'],executable_binding))
    for cid,expected in METADATA.items():
        raw=reader['run_read'](ctr,prefix+['containers','info',cid],executable_binding)
        require(entry['digest'](raw)==expected,'CONTAINER_METADATA_CHANGED_BEFORE_FRESH_CLAIM')

def ensure_preserved(entry,frozen):
    require(all(entry['digest'](entry['read'](p))==h for p,h in frozen.items()),
        'RETAINED_R5_OR_TERMINAL_EVIDENCE_CHANGED')

def main(approval_ref,base_path,r3_path,repair_path,preflight_path):
    global CONTEXT,PHASE,ATTEMPTED
    require(APPROVAL_REF!='PENDING_HUMAN_POST_TERMINAL_ADMISSION_APPROVAL'
        and approval_ref==APPROVAL_REF and type(APPROVED_AT) is int,
        'EXPLICIT_POST_TERMINAL_ADMISSION_APPROVAL_REQUIRED')
    require(int(time.time())>=APPROVED_AT,'ROOT_CLOCK_BEFORE_HUMAN_APPROVAL')
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
    reader=load_definitions(preflight_path,PREFLIGHT_SHA,'fresh_post_terminal_reader')
    with contextlib.redirect_stdout(io.StringIO()) as output:
        read_exit=reader['main']()
    captured=output.getvalue()
    require(captured.startswith('OUF_POST_TERMINAL_ADMISSION_READ_ONLY=') and len(captured)<=131072,'POST_TERMINAL_READBACK_UNPROVEN')
    readback=json.loads(captured.split('=',1)[1])
    if read_exit!=0:
        error=ValueError('FRESH_POST_TERMINAL_PREREQUISITES_REQUIRED')
        error.diagnosis={'preflightReadOnlyDiagnosis':readback}
        raise error
    validate_preflight(readback)
    base=load_definitions(base_path,BASE_SHA,'retained_base')
    r3=load_definitions(r3_path,R3_SHA,'retained_r3')
    require(int(time.time())+240<=base['FRESH_UNTIL'],'DEPENDENCY_VALIDITY_DOES_NOT_COVER_240_SECOND_WINDOW')
    package=base['PACKAGE'];scope=base['SCOPE'];encoded=base['encoded'];sha=base['sha'];write=base['write']
    require(sha(base['REPAIRED_ENTRY'])==base['REPAIRED_ENTRY_SHA256'],'PRIOR_REPAIRED_ENTRY_HASH_DRIFT')
    entry_path=package/'provider_transaction_intake.py'
    entry={'__name__':'bundle_recovery_entry','__file__':str(entry_path)}
    exec(compile(repaired_entry(base['REPAIRED_ENTRY']),str(entry_path),'exec'),entry)
    entry['bound']({'path':str(entry_path),'sha256':scope['package']['entrySha256']})
    sources,observer=entry['load'](package)
    require(sha(encoded({**{n:sha(b) for n,b in sources.items()},'frame-observer.py':sha(observer)}))
        ==scope['package']['sourceClosureHash'],'RUNTIME_OBSERVER_CLOSURE_DRIFT')
    PHASE='VERIFY_RETAINED_R5_AND_SUCCESSFUL_TERMINAL_RECOVERY'
    approval=entry['parse'](entry['read'](OLD_CONTEXT/'human-approval-binding.json'))
    require(approval['approvalRef']=='OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_HUMAN_APPROVAL_20261009_130246',
        'EXACT_PRIOR_APPROVAL_REQUIRED')
    cfg=entry['parse'](entry['bound']({'path':str(OLD_CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
    require(cfg['outputRoot']==str(OLD_OUTPUT),'EXACT_PRIOR_OUTPUT_REQUIRED')
    claim=entry['parse'](entry['read'](OLD_CONTEXT/'execution-claim.json'))
    require(claim['outputRoot']==str(OLD_OUTPUT) and claim['configurationHash']==approval['configurationHash'],
        'EXACT_RETAINED_EXECUTION_CLAIM_REQUIRED')
    denial=entry['parse'](entry['read'](OLD_OUTPUT/'cohort-activation-denial.json'))
    validate_failure(denial)
    require(not os.path.lexists(OLD_OUTPUT/'cohort-activation-receipt.json')
        and not os.path.lexists(OLD_OUTPUT/'runtime-switch-denial.json'),'RETAINED_OUTCOME_CONFLICT')
    for name in ('runtime-switch-claim.json','cohort-activation-claim.json'):
        entry['read'](OLD_OUTPUT/name)
    switched=entry['parse'](entry['read'](OLD_OUTPUT/'runtime-switch-receipt.json'))
    require(switched['status']=='WRAPPER_SWITCHED' and switched['installedWrapperHash']==PRIOR_WRAPPER
        and sha(entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True))==PRIOR_WRAPPER,
        'EXACT_RETAINED_SWITCHED_WRAPPER_REQUIRED')
    receipt=entry['parse'](entry['read'](OLD_OUTPUT/'installation-receipt.json'))
    require(len(receipt['fileHashes'])==81,'EXACT_RETAINED_PUBLICATION_REQUIRED')
    for path,expected in receipt['fileHashes'].items():
        require(Path(path).is_relative_to(OLD_OUTPUT) and '..' not in Path(path).parts,'RETAINED_FILE_PATH_ESCAPE')
        entry['bound']({'path':path,'sha256':retained_publication_hash(path,expected)})
    for role in scope['roleProposals']:
        issued=entry['parse'](entry['read'](OLD_CONTEXT/'role-authority'/role/'role-issuance-receipt.json'))
        require(issued['status']=='ROLE_RECORDS_ISSUED' and issued['signaturesIssued']==4
            and issued['startPerformed'] is False,'RETAINED_ROLE_ISSUANCE_DRIFT')
        for binding in issued['records'].values():entry['bound'](binding)
    for cid,expected in EXPECTED_OBSERVATIONS.items():
        journal=entry['bound']({'path':str(OLD_OUTPUT/'registry'/cid/'adapter.json'),
            'sha256':expected['adapterJournalHash']})
        require(entry['parse'](journal)['state']==('DELETING' if cid==ADAPTER else 'STAGED'),'RETAINED_R5_PHASE_DRIFT')
    require(not os.path.lexists(package/'post-terminal-admission-recovery-claim.json'),'DO_NOT_REPLAY_POST_TERMINAL_ADMISSION')
    frozen=retain_terminal_evidence(entry,reader)
    require(len(frozen)>=91,'COMPLETE_TERMINAL_EVIDENCE_REQUIRED')
    records={r:{n:entry['bound'](b) for n,b in values.items()} for r,values in cfg['recordsByRole'].items()}
    from compile_creation_frame_policy import compile_policy
    next_scope=accepted_scope(records,scope,entry['parse'],encoded,sha,compile_policy)
    for role,values in records.items():
        require({name:sha(raw) for name,raw in values.items()}==readback['roles'][role]['inputHashes'],'FRESH_READBACK_INPUT_DRIFT')
    proposed=load_definitions(repair_path,REPAIR_SHA,'reviewed_source_repair')
    sources=proposed['repair'](sources)
    require(sha(encoded({**{n:sha(b) for n,b in sources.items()},'frame-observer.py':sha(observer)}))==NEW_CLOSURE,
        'EXACT_REVIEWED_SOURCE_CLOSURE_REQUIRED')
    PHASE='OBSERVE_BOTH_CREATED_CANDIDATES_AND_EMPTY_NATIVE_GUARD_BEFORE_KEYS'
    from authenticate_provider_transaction import TARGETS,preflight_input_pair
    from transaction_guard_observation import observe_locked
    preflight_input_pair(records)
    pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']))
    binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
    owner_hash=scope['runtime']['ownerConfigurationSha256']
    owner=entry['parse'](entry['bound']({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':owner_hash}))
    candidates={t['containerId']:{'imageManifestDigest':t['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for t in TARGETS.values()}
    fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        observed=observe_locked(fd,binding,owner_hash,candidates,cfg['commandBindings'])
        require(observed['candidateStateHashes']=={c:v['stateHash'] for c,v in EXPECTED_OBSERVATIONS.items()},
            'RETAINED_FAILED_CANDIDATE_GENERATION_CHANGED')
        verify_absent_retained_runc(entry,cfg)
        verify_absent_retained_tasks(entry,reader)
    finally:os.close(fd)
    PHASE='RESERVE_FRESH_CONTEXT_AFTER_EXACT_TERMINAL_MAINTENANCE'
    r3['install_repairs'](sha)
    base['SCOPE']=next_scope;base['APPROVAL_REF']=APPROVAL_REF;base['APPROVED_AT']=APPROVED_AT
    now=int(time.time());mandates=base['build_mandates'](next_scope,{r:{n:sha(b) for n,b in v.items()} for r,v in records.items()},now,APPROVAL_REF)
    ensure_preserved(entry,frozen)
    CONTEXT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-approved-context-',dir=OLD_CONTEXT.parent));CONTEXT.chmod(0o700)
    write(package/'post-terminal-admission-recovery-claim.json',encoded({'schema':'ouf.semantic-provider-post-terminal-admission-recovery-claim.v1',
        'approvalRef':APPROVAL_REF,'reviewRef':REVIEW_REF,'contextDirectory':str(CONTEXT),
        'retainedContext':str(OLD_CONTEXT),'retainedOutput':str(OLD_OUTPUT),
        'priorWrapperHash':PRIOR_WRAPPER,'acceptedContextHashes':NEW_HASHES,'sourceClosureHash':NEW_CLOSURE,
        'successfulMaintenanceHash':SUCCESS_SHA,'consumedAliasClaimHash':ALIAS_CLAIM_SHA,'notReleaseAcceptance':True}))
    base['sync'](package)
    record_bindings=copy.deepcopy(cfg['recordsByRole']);mandate_bindings={}
    for role in mandates:
        path=CONTEXT/(role+'-mandate.json');raw=encoded(mandates[role]);write(path,raw)
        mandate_bindings[role]={'path':str(path),'sha256':sha(raw)}
    cfg={**cfg,'recordsByRole':record_bindings,'mandatesByRole':mandate_bindings,
        'outputRoot':str(CONTEXT.parent/('semantic-provider-v2-transaction-'+CONTEXT.name.removeprefix('semantic-provider-v2-approved-context-')))}
    raw=encoded(cfg);path=CONTEXT/'execution-configuration.json';write(path,raw)
    write(CONTEXT/'human-approval-binding.json',encoded({'schema':'ouf.semantic-provider-approved-root-context.v1',
        'approvalRef':APPROVAL_REF,'reviewRef':REVIEW_REF,'configurationHash':sha(raw),'issuedAt':now,'expiresAt':now+240,
        'retainedContext':str(OLD_CONTEXT),'notReleaseAcceptance':True}))
    base['sync'](CONTEXT)
    write(CONTEXT/'retained-evidence-hashes.json',encoded(frozen))
    base['sync'](CONTEXT)
    PHASE='INVOKE_APPROVED_POST_TERMINAL_TRANSACTION_ONCE'
    try:
        result=entry['execute_transaction'](CONTEXT,path,sha(raw),sources,observer)
    finally:
        ATTEMPTED=os.path.lexists(CONTEXT/'execution-claim.json')
        ensure_preserved(entry,frozen)
    result['retainedR5AndMaintenanceEvidencePreserved']=True
    print('OUF_POST_TERMINAL_ADMISSION_RECOVERY='+encoded(result).decode())

if __name__=='__main__':
    try:
        require(len(sys.argv)==6,'EXACT_APPROVAL_TWO_BRIDGES_SOURCE_REPAIR_AND_PREFLIGHT_REQUIRED')
        main(*sys.argv[1:])
    except Exception as error:
        report=dict(getattr(error,'diagnosis',{}))
        report.update(status='BLOCKED',phase=PHASE,errorType=report.get('errorType',type(error).__name__),
            contextDirectory=str(CONTEXT) if CONTEXT else None,retainedEvidenceDirectory=str(OLD_OUTPUT),
            privateValuesPrinted=False,privateKeysRead=None if ATTEMPTED else 0,
            containerLifecycleOperations=None if ATTEMPTED else 0,startAuthorized=False,
            notReleaseAcceptance=True,doNotRerunApply=CONTEXT is not None)
        if 'reason' not in report:
            report['reason']=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'POST_TERMINAL_ADMISSION_RECOVERY_UNPROVEN'
        report['revisedSourceClosureHash']=NEW_CLOSURE
        if isinstance(error,OSError):report['errno']=error.errno
        report['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]]
        if CONTEXT:
            try:
                fd=os.open(CONTEXT/'operator-denial.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:os.write(fd,json.dumps(report,sort_keys=True).encode());os.fsync(fd)
                finally:os.close(fd)
            except Exception:report['diagnosisSaved']=False
        print('OUF_POST_TERMINAL_ADMISSION_RECOVERY='+json.dumps(report,sort_keys=True));raise SystemExit(1)
