"""One reviewed R3 bundle-parent recovery; inert until recorded human approval.

Reuse pinned downloaded bridges and sealed runtime sources. Preserve R3 evidence.
Change two private contexts only, then issue fresh authority and run native cohort.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import traceback

APPROVAL_REF='PENDING_HUMAN_BUNDLE_CONTEXT_RECOVERY_APPROVAL'
APPROVED_AT=None
REVIEW_REF='OUF_PROVIDER_V2_BUNDLE_CONTEXT_RECOVERY_REVIEW_20261009_R4'
BASE_SHA='e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4'
R3_SHA='5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328'
OLD_CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-rsj9dtwr')
OLD_OUTPUT=OLD_CONTEXT.parent/'semantic-provider-v2-transaction-rsj9dtwr'
PRIOR_WRAPPER='3234529d94e84c70ed66f6e54a2d86f156e875fc73c9f8e15844b61edbb8ae20'
EMPTY_WRAPPER='4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd'
OLD_PARENT='/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'
NEW_PARENT='/run/containerd/io.containerd.runtime.v2.task/moby'
NEW_HASHES={'adapter':'cfc1bfc12855dc49bfe0bf3eef22d0b2fb1f376d017a5cf68a4e77822dc9dfc6',
    'southbound':'ce46668d3652eeb1fbf45ebba78c6fdc15aefa9af62801b536b616635a0f4246'}
EXPECTED_OBSERVATIONS={
    '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916':{
        'stateHash':'14ab4ac6481e0c3e956a3130068e5219858f3dbebf4cab8247c79d05a92353c7',
        'adapterJournalHash':'27e92be87f2d4b32b5d74a62e49741ae35f5476d804bab7f825df2095fa53080'},
    'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67':{
        'stateHash':'02740d700d511306be44675ae87ca402263b057479a33052a02956f488cfe809',
        'adapterJournalHash':'2c007e0ae5d5979e917364437fdd3a4589a62003dc6f77a77d4e4683ed3d57ae'}}
CONTEXT=None
PHASE='REQUIRE_EXPLICIT_CHANGED_CONTEXT_RECOVERY_APPROVAL'
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
        require(observations[cid].get('adapterState')=='STAGED'
            and observations[cid].get('nativeDenialReason')=='ADAPTER_BINDING_UNPROVEN_L283'
            and all(observations[cid].get(k)==v for k,v in expected.items())
            and denial['dockerResults'][cid]=={'exitCode':1,'exactCidAcknowledged':False,'errorType':None},
            'EXACT_PRE_CREATE_BINDING_DENIAL_REQUIRED')

def changed_records(records,scope,parse,encoded,sha,compile_policy):
    require(set(records)==set(scope['roleProposals'])==set(NEW_HASHES),'EXACT_TWO_ROLES_REQUIRED')
    changed={r:dict(v) for r,v in records.items()}
    next_scope=copy.deepcopy(scope)
    for role,values in records.items():
        require({k:sha(v) for k,v in values.items()}==scope['roleProposals'][role]['inputHashes'],
            'RETAINED_ACCEPTED_INPUTS_DRIFT')
        context=parse(values['context'])
        require(context['bundleParent']==OLD_PARENT
            and context['containerId']==scope['roleProposals'][role]['containerId'],
            'EXACT_PRIOR_CONTEXT_REQUIRED')
        context=dict(context,bundleParent=NEW_PARENT)
        raw=encoded(context)
        require(sha(raw)==NEW_HASHES[role],'PROPOSED_CONTEXT_HASH_DRIFT')
        policy=compile_policy(parse(values['template']),parse(values['launch']),context)
        require(encoded(policy)==values['framePolicy'],'COMPLETE_FRAME_CHANGE_REQUIRES_SEPARATE_REVIEW')
        require(sha(encoded(policy['expectedOci']))==scope['roleProposals'][role]['applicationHash'],
            'ACCEPTED_APPLICATION_HASH_DRIFT')
        changed[role]['context']=raw
        next_scope['roleProposals'][role]['inputHashes']['context']=NEW_HASHES[role]
        next_scope['roleProposals'][role]['reviewRef']=REVIEW_REF
    next_scope['reviewRef']=REVIEW_REF
    return changed,next_scope

def repaired_entry(raw):
    # Exact two prior-wrapper assertions; no change to the runtime/observer closure.
    require(raw.count(EMPTY_WRAPPER.encode())==2,'EXACT_PRIOR_WRAPPER_ASSERTIONS_REQUIRED')
    return raw.replace(EMPTY_WRAPPER.encode(),PRIOR_WRAPPER.encode())

def main(approval_ref,base_path,r3_path):
    global CONTEXT,PHASE,ATTEMPTED
    require(APPROVAL_REF!='PENDING_HUMAN_BUNDLE_CONTEXT_RECOVERY_APPROVAL'
        and approval_ref==APPROVAL_REF and type(APPROVED_AT) is int,
        'EXPLICIT_CHANGED_CONTEXT_RECOVERY_APPROVAL_REQUIRED')
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
    PHASE='VERIFY_RETAINED_R3_DENIAL_AND_CURRENT_WRAPPER'
    approval=entry['parse'](entry['read'](OLD_CONTEXT/'human-approval-binding.json'))
    require(approval['approvalRef']=='OUF_PROVIDER_V2_POST_SIGNATURE_RECOVERY_HUMAN_APPROVAL_20261009_093008',
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
        entry['bound']({'path':path,'sha256':expected})
    for role in scope['roleProposals']:
        issued=entry['parse'](entry['read'](OLD_CONTEXT/'role-authority'/role/'role-issuance-receipt.json'))
        require(issued['status']=='ROLE_RECORDS_ISSUED' and issued['signaturesIssued']==4
            and issued['startPerformed'] is False,'RETAINED_ROLE_ISSUANCE_DRIFT')
        for binding in issued['records'].values():entry['bound'](binding)
    for cid,expected in EXPECTED_OBSERVATIONS.items():
        journal=entry['bound']({'path':str(OLD_OUTPUT/'registry'/cid/'adapter.json'),
            'sha256':expected['adapterJournalHash']})
        require(entry['parse'](journal)['state']=='STAGED','RETAINED_CANDIDATE_ALREADY_PROGRESSSED')
    require(not os.path.lexists(package/'bundle-context-recovery-claim.json'),'DO_NOT_REPLAY_BUNDLE_CONTEXT_RECOVERY')
    records={r:{n:entry['bound'](b) for n,b in values.items()} for r,values in cfg['recordsByRole'].items()}
    from compile_creation_frame_policy import compile_policy
    records,next_scope=changed_records(records,scope,entry['parse'],encoded,sha,compile_policy)
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
    finally:os.close(fd)
    PHASE='RESERVE_NEW_CONTEXT_WITH_EXACT_APPROVED_TWO_INPUT_CHANGES'
    r3['install_repairs'](sha)
    base['SCOPE']=next_scope;base['APPROVAL_REF']=APPROVAL_REF;base['APPROVED_AT']=APPROVED_AT
    now=int(time.time());mandates=base['build_mandates'](next_scope,{r:{n:sha(b) for n,b in v.items()} for r,v in records.items()},now,APPROVAL_REF)
    CONTEXT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-approved-context-',dir=OLD_CONTEXT.parent));CONTEXT.chmod(0o700)
    write(package/'bundle-context-recovery-claim.json',encoded({'schema':'ouf.semantic-provider-bundle-context-recovery-claim.v1',
        'approvalRef':APPROVAL_REF,'reviewRef':REVIEW_REF,'contextDirectory':str(CONTEXT),
        'retainedContext':str(OLD_CONTEXT),'retainedOutput':str(OLD_OUTPUT),
        'priorWrapperHash':PRIOR_WRAPPER,'proposedContextHashes':NEW_HASHES,'notReleaseAcceptance':True}))
    base['sync'](package)
    record_bindings=copy.deepcopy(cfg['recordsByRole']);mandate_bindings={}
    for role in mandates:
        path=CONTEXT/(role+'-context.json');write(path,records[role]['context'])
        record_bindings[role]['context']={'path':str(path),'sha256':NEW_HASHES[role]}
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
    print('OUF_BUNDLE_CONTEXT_RECOVERY='+encoded(result).decode())

if __name__=='__main__':
    try:
        require(len(sys.argv)==4,'EXACT_APPROVAL_AND_TWO_RETAINED_BRIDGE_ARGUMENTS_REQUIRED')
        main(*sys.argv[1:])
    except Exception as error:
        report=dict(getattr(error,'diagnosis',{}))
        report.update(status='BLOCKED',phase=PHASE,errorType=report.get('errorType',type(error).__name__),
            contextDirectory=str(CONTEXT) if CONTEXT else None,retainedEvidenceDirectory=str(OLD_OUTPUT),
            privateValuesPrinted=False,privateKeysRead=None if ATTEMPTED else 0,
            containerLifecycleOperations=None if ATTEMPTED else 0,startAuthorized=False,
            notReleaseAcceptance=True,doNotRerunApply=CONTEXT is not None)
        if 'reason' not in report:
            report['reason']=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'BUNDLE_CONTEXT_RECOVERY_UNPROVEN'
        report['differentFields']=['bundleParent']
        if isinstance(error,OSError):report['errno']=error.errno
        report['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]]
        if CONTEXT:
            try:
                fd=os.open(CONTEXT/'operator-denial.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:os.write(fd,json.dumps(report,sort_keys=True).encode());os.fsync(fd)
                finally:os.close(fd)
            except Exception:report['diagnosisSaved']=False
        print('OUF_BUNDLE_CONTEXT_RECOVERY='+json.dumps(report,sort_keys=True));raise SystemExit(1)
