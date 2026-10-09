"""One reviewed R4 recovery with revised source closure; inert until human approval.

Reuse pinned downloaded bridges and sealed runtime sources. Preserve R3 evidence.
Reuse sixteen accepted inputs, preserve R4, issue fresh source-bound authority.
"""
import copy
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

APPROVAL_REF='PENDING_HUMAN_BROKER_SOURCE_RECOVERY_APPROVAL'
APPROVED_AT=None
REVIEW_REF='OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_REVIEW_20261009_R5'
BASE_SHA='e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4'
R3_SHA='5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328'
OLD_CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-kaa8rbxd')
OLD_OUTPUT=OLD_CONTEXT.parent/'semantic-provider-v2-transaction-kaa8rbxd'
PRIOR_WRAPPER='2c752d0c65383d59862ef3f8a84ec94fa07ebf2d40117329b73d8338d48b4815'
EMPTY_WRAPPER='4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd'
OLD_PARENT='/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'
NEW_PARENT='/run/containerd/io.containerd.runtime.v2.task/moby'
NEW_HASHES={'adapter':'cfc1bfc12855dc49bfe0bf3eef22d0b2fb1f376d017a5cf68a4e77822dc9dfc6',
    'southbound':'ce46668d3652eeb1fbf45ebba78c6fdc15aefa9af62801b536b616635a0f4246'}
EXPECTED_OBSERVATIONS={
    '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916':{
        'stateHash':'d53e61384c9b5911ba54e257a33ceadac8be37bbcc6ef9310bc1d25c6b49cfa4',
        'adapterJournalHash':'b30e44bc9eb98cc6964a2c715e4601c87e834e5a8ac160a50517f4c9cd6a8214'},
    'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67':{
        'stateHash':'e7aa0522b02f2e55cb22db2023f4a38956b40f2a72508447cf08d2eb18b17b9b',
        'adapterJournalHash':'1c62ff47e7007f1a751dd41efe692b805fe382263b1ab197502ae2e5a66376ab'}}
SOUTH='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
NEW_CLOSURE='702403e9cd99ddc4ddeed7166f3f408c55657fc690e475e0b35bb5d2c2242bb3'
REPAIR_SHA='c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f'
RETAINED_ROOT_HASH='c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342'
RETAINED_ADVANCED_HASHES={
    'registry/'+SOUTH+'/adapter.json':'b30e44bc9eb98cc6964a2c715e4601c87e834e5a8ac160a50517f4c9cd6a8214',
    'registry/'+SOUTH+'/broker-state.json':'6b0cac8df6822709a045eb7a91099890ad1dc3f6d7c4d29490674d9ed91da7e3',
    'registry/'+SOUTH+'/deployment.json':'1cae726e4f7e48dee557a20f2f7420c5de59b3c23a6acc8300b02998a2e489c5'}
CONTEXT=None
PHASE='REQUIRE_EXPLICIT_REVISED_SOURCE_RECOVERY_APPROVAL'
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
        'EXACT_RETAINED_R3_COHORT_DENIAL_REQUIRED')
    observations=denial.get('candidateObservations',{})
    require(set(observations)==set(EXPECTED_OBSERVATIONS)
        and set(denial.get('dockerResults',{}))==set(EXPECTED_OBSERVATIONS),
        'BOTH_RETAINED_CANDIDATE_OBSERVATIONS_REQUIRED')
    for cid,expected in EXPECTED_OBSERVATIONS.items():
        require(observations[cid].get('adapterState')==('DELETING' if cid==SOUTH else 'STAGED')
            and observations[cid].get('nativeDenialReason')=='TWO_PHASE_BROKER_DENIED'
            and all(observations[cid].get(k)==v for k,v in expected.items())
            and denial['dockerResults'][cid]=={'exitCode':1,'exactCidAcknowledged':False,'errorType':None},
            'EXACT_RETAINED_R4_BROKER_DENIAL_REQUIRED')

def accepted_scope(records,scope,parse,encoded,sha,compile_policy):
    result=copy.deepcopy(scope)
    require(set(records)==set(NEW_HASHES),'EXACT_TWO_ACCEPTED_ROLES_REQUIRED')
    for role,values in records.items():
        expected={**scope['roleProposals'][role]['inputHashes'],'context':NEW_HASHES[role]}
        require({k:sha(v) for k,v in values.items()}==expected,'ACCEPTED_R4_SIXTEEN_INPUTS_DRIFT')
        context=parse(values['context'])
        require(context['bundleParent']==NEW_PARENT and context['containerId']==scope['roleProposals'][role]['containerId'],
            'ACCEPTED_R4_CONTEXT_SCOPE_DRIFT')
        require(encoded(compile_policy(parse(values['template']),parse(values['launch']),context))==values['framePolicy'],
            'COMPLETE_ACCEPTED_FRAME_DRIFT')
        result['roleProposals'][role]['inputHashes']=expected
        result['roleProposals'][role]['sourceClosureHash']=NEW_CLOSURE
        result['roleProposals'][role]['reviewRef']=REVIEW_REF
    result['reviewRef']=REVIEW_REF
    result['package']['sourceClosureHash']=NEW_CLOSURE
    return result


def retained_publication_hash(path,expected):
    p=Path(path)
    require(p.is_relative_to(OLD_OUTPUT) and '..' not in p.parts,'RETAINED_FILE_PATH_ESCAPE')
    return RETAINED_ADVANCED_HASHES.get(str(p.relative_to(OLD_OUTPUT)),expected)


def verify_absent_retained_runc(entry,cfg):
    from transaction_guard_observation import executable_binding
    raw=entry['bound']({'path':str(OLD_OUTPUT/'registry'/SOUTH/'adapter.json'),
        'sha256':EXPECTED_OBSERVATIONS[SOUTH]['adapterJournalHash']})
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
    require(entry['read'](OLD_OUTPUT/'registry'/SOUTH/'adapter.json')==raw,'RETAINED_JOURNAL_CHANGED_DURING_INVENTORY')

def repaired_entry(raw):
    # Exact two prior-wrapper assertions; no change to the runtime/observer closure.
    require(raw.count(EMPTY_WRAPPER.encode())==2,'EXACT_PRIOR_WRAPPER_ASSERTIONS_REQUIRED')
    return raw.replace(EMPTY_WRAPPER.encode(),PRIOR_WRAPPER.encode())

def main(approval_ref,base_path,r3_path,repair_path):
    global CONTEXT,PHASE,ATTEMPTED
    require(APPROVAL_REF!='PENDING_HUMAN_BROKER_SOURCE_RECOVERY_APPROVAL'
        and approval_ref==APPROVAL_REF and type(APPROVED_AT) is int,
        'EXPLICIT_REVISED_SOURCE_RECOVERY_APPROVAL_REQUIRED')
    require(int(time.time())>=APPROVED_AT,'ROOT_CLOCK_BEFORE_HUMAN_APPROVAL')
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
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
    PHASE='VERIFY_RETAINED_R4_DENIAL_AND_CURRENT_WRAPPER'
    approval=entry['parse'](entry['read'](OLD_CONTEXT/'human-approval-binding.json'))
    require(approval['approvalRef']=='OUF_PROVIDER_V2_BUNDLE_CONTEXT_RECOVERY_HUMAN_APPROVAL_20261009_102223',
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
        require(entry['parse'](journal)['state']==('DELETING' if cid==SOUTH else 'STAGED'),'RETAINED_R4_PHASE_DRIFT')
    require(not os.path.lexists(package/'broker-source-recovery-claim.json'),'DO_NOT_REPLAY_BROKER_SOURCE_RECOVERY')
    records={r:{n:entry['bound'](b) for n,b in values.items()} for r,values in cfg['recordsByRole'].items()}
    from compile_creation_frame_policy import compile_policy
    next_scope=accepted_scope(records,scope,entry['parse'],encoded,sha,compile_policy)
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
    finally:os.close(fd)
    PHASE='RESERVE_NEW_CONTEXT_WITH_EXPLICIT_REVISED_SOURCE_MANDATES'
    r3['install_repairs'](sha)
    base['SCOPE']=next_scope;base['APPROVAL_REF']=APPROVAL_REF;base['APPROVED_AT']=APPROVED_AT
    now=int(time.time());mandates=base['build_mandates'](next_scope,{r:{n:sha(b) for n,b in v.items()} for r,v in records.items()},now,APPROVAL_REF)
    CONTEXT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-approved-context-',dir=OLD_CONTEXT.parent));CONTEXT.chmod(0o700)
    write(package/'broker-source-recovery-claim.json',encoded({'schema':'ouf.semantic-provider-broker-source-recovery-claim.v1',
        'approvalRef':APPROVAL_REF,'reviewRef':REVIEW_REF,'contextDirectory':str(CONTEXT),
        'retainedContext':str(OLD_CONTEXT),'retainedOutput':str(OLD_OUTPUT),
        'priorWrapperHash':PRIOR_WRAPPER,'acceptedContextHashes':NEW_HASHES,'sourceClosureHash':NEW_CLOSURE,'notReleaseAcceptance':True}))
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
    PHASE='INVOKE_APPROVED_CORRECTED_TRANSACTION_ONCE'
    try:result=entry['execute_transaction'](CONTEXT,path,sha(raw),sources,observer)
    finally:ATTEMPTED=os.path.lexists(CONTEXT/'execution-claim.json')
    print('OUF_BROKER_SOURCE_RECOVERY='+encoded(result).decode())

if __name__=='__main__':
    try:
        require(len(sys.argv)==5,'EXACT_APPROVAL_TWO_RETAINED_BRIDGES_AND_SOURCE_REPAIR_ARGUMENTS_REQUIRED')
        main(*sys.argv[1:])
    except Exception as error:
        report=dict(getattr(error,'diagnosis',{}))
        report.update(status='BLOCKED',phase=PHASE,errorType=report.get('errorType',type(error).__name__),
            contextDirectory=str(CONTEXT) if CONTEXT else None,retainedEvidenceDirectory=str(OLD_OUTPUT),
            privateValuesPrinted=False,privateKeysRead=None if ATTEMPTED else 0,
            containerLifecycleOperations=None if ATTEMPTED else 0,startAuthorized=False,
            notReleaseAcceptance=True,doNotRerunApply=CONTEXT is not None)
        if 'reason' not in report:
            report['reason']=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'BROKER_SOURCE_RECOVERY_UNPROVEN'
        report['revisedSourceClosureHash']=NEW_CLOSURE
        if isinstance(error,OSError):report['errno']=error.errno
        report['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]]
        if CONTEXT:
            try:
                fd=os.open(CONTEXT/'operator-denial.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:os.write(fd,json.dumps(report,sort_keys=True).encode());os.fsync(fd)
                finally:os.close(fd)
            except Exception:report['diagnosisSaved']=False
        print('OUF_BROKER_SOURCE_RECOVERY='+json.dumps(report,sort_keys=True));raise SystemExit(1)
