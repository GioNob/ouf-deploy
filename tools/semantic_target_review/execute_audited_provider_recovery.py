"""Single fresh audited admission after successful R6 cleanup; approval inert.

Reuse immutable private inputs and retained source bytes. Construct one coherent
sealed package, preserve every prior claim, and let the existing transaction own
signing, guarded wrapper publication and the controlled two-CID cohort.
"""
import copy
import fcntl
import hashlib
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

APPROVAL_REF = 'PENDING_AUDITED_PROVIDER_RECOVERY_APPROVAL'
APPROVED_AT = None
APPROVAL_EXPIRES_AT = None
REVIEW_REF = 'OUF_PROVIDER_AUDITED_RECOVERY_REVIEW_20261009_R7'
DELTA_FILES = {'provider_transaction_intake.py': 'f81d8ec23d551acb2419aaefa0c2a4531de4de6219758e263496c228cfa4570d', 'publish_provider_transaction.py': '7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080', 'guarded_runtime_switch.py': '1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd', 'authenticated_runtime_switch.py': 'ce5625aa645b3da470e84b8544adfa82d5bca8665bb88d8e2d49fd3701548d83', 'repair_broker_sources.py': 'c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f', 'repair_admission_transport.py': 'a5bece68adb2f710fd082d25fad3b09cadd202d31e8bbd2c13f19b5f19d187f5', 'build_audited_source_package.py': '785ca8e275e0590b6e63aef904cee65c62e74c72cdf17a128abdaad144880ba7', 'scope.json': 'deb00aad4fd5070f72d45c4b6650444c08baf9054357b3a9eb98b7e2cbb205af'}
BASE = Path('/etc/ouf/deploy-snapshots')
PACKAGE = BASE/'semantic-provider-v2-transaction-source-ff13uh3n'
CONTEXT = BASE/'semantic-provider-v2-approved-context-aj1j95xl'
OUTPUT = BASE/'semantic-provider-v2-transaction-aj1j95xl'
MAINTENANCE = BASE/'semantic-r6-terminal-cleanup-f87o7724'
WRAPPER = Path('/usr/local/sbin/ouf-semantic-admitted-v2')
ENTRY_SHA = 'edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
MANIFEST_SHA = '2699c82124b6bfcbd61991f09a96ebb5c6a2d336aaf3384dcae9288101b29de4'
WRAPPER_SHA = 'cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b'
SUCCESS_SHA = '8ed508977b44da7b18de04fb89255a571eccbc77dc1ab66ec5d5621c97eae948'
ROOT_SHA = 'c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342'
OWNER_SHA = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
OLD_CLOSURE = '702403e9cd99ddc4ddeed7166f3f408c55657fc690e475e0b35bb5d2c2242bb3'
A = 'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
S = '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
STATES = {A:'90ad7da25dd59e78566b06512e8bf57e4b7022bb101b6e701585ed7a79fcab58',
          S:'7674a0e65ecc160881ecaa65c30c61c1d64b91a3dab78c3c5c9a9183acb762bc'}
METADATA = {A:'32c634d6dc131f577be32caf8d80f8662437f6fb3521ed52bc3cae7bdd0e73ff',
            S:'a2f5559ede95345286407a66a7dc8206ba39a7cab93cf66a666f4a64ec082b0a'}
TASK_PIDS = {A:1770715,S:1770730}
CLAIM_PATH = BASE/'semantic-provider-audited-recovery-20261009-claim.json'
NEW_CONTEXT = None
NEW_OUTPUT = None
PHASE = 'REQUIRE_EXPLICIT_AUDITED_RECOVERY_APPROVAL'


class Denied(ValueError): pass
def require(ok,reason):
    if not ok: raise Denied(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def publish(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def download_bytes(directory):
    require(Path(directory).is_absolute(),'ABSOLUTE_REVIEWED_DOWNLOAD_REQUIRED')
    result={}
    for name,expected in DELTA_FILES.items():
        fd=os.open(Path(directory)/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_size<=131072,'BOUNDED_REVIEWED_SOURCE_REQUIRED')
            raw=os.read(fd,131073)
        finally:os.close(fd)
        require(sha(raw)==expected,'REVIEWED_DOWNLOAD_HASH_DRIFT')
        result[name]=raw
    require(len(result)==8,'COMPLETE_REVIEWED_DOWNLOAD_REQUIRED')
    return result


def definitions(name,raw,path):
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module.__dict__


def validate_cleanup(value,claim,window):
    require(sha(encoded(value))==SUCCESS_SHA and value.get('schema')=='ouf.semantic-r6-terminal-cleanup.v1'
        and value.get('status')=='TWO_TERMINAL_TASKS_REMOVED_ALIAS_RECOVERY_CONTAINERS_PRESERVED'
        and value.get('evidenceDirectory')==str(MAINTENANCE),'EXACT_SUCCESSFUL_R6_CLEANUP_REQUIRED')
    require(value['taskDeleteRequests']==2 and value['wrapperRestored'] is True
        and value['priorJournalsPreserved'] is True and value['doNotRerunApply'] is True,
        'EXACT_CONSUMED_CLEANUP_RESULT_REQUIRED')
    require(all(value[k]==0 for k in ('dockerStartRequests','privateKeysRead','signaturesIssued','providerCalls'))
        and value['daemonRestarted'] is False and value['automaticRetryPerformed'] is False,
        'CLEANUP_NO_START_BOUNDARY_REQUIRED')
    require(claim.get('schema')=='ouf.semantic-r6-terminal-cleanup-claim.v1'
        and claim.get('approvalRef')=='OUF_R6_TERMINAL_CLEANUP_APPROVED_20261009T174356_CEST'
        and claim.get('approvedAt')==1791560636 and claim.get('evidenceDirectory')==str(MAINTENANCE)
        and claim.get('retainedWrapperHash')==WRAPPER_SHA
        and claim.get('tasks')=={cid:{'pid':pid} for cid,pid in TASK_PIDS.items()},
        'EXACT_CONSUMED_R6_CLEANUP_CLAIM_REQUIRED')
    require(claim['windowHash']==sha(encoded(window)) and window['approvalRef']==claim['approvalRef']
        and window['tasks']==claim['tasks'],'CONSUMED_CLEANUP_WINDOW_DRIFT')
    guard=value['postMaintenanceEmptyGuard']
    require(guard['candidateStateHashes']==STATES and guard['configurationHash']==OWNER_SHA
        and guard['providerSetsEmpty'] is True and guard['lockInodePreserved'] is True,
        'RETAINED_EMPTY_GUARD_REQUIRED')


def confined(path,root):
    p=Path(path)
    return p.is_absolute() and str(p)==path and '..' not in p.parts and p.is_relative_to(root) and p!=root


def retain(entry):
    read,bound,parse=entry['read'],entry['bound'],entry['parse']
    success_raw=bound({'path':str(MAINTENANCE/'maintenance-result.json'),'sha256':SUCCESS_SHA})
    claim_raw=read(CONTEXT/'r6-terminal-task-cleanup-claim.json');claim=parse(claim_raw)
    window_raw=bound({'path':str(MAINTENANCE/'window.json'),'sha256':claim['windowHash']})
    validate_cleanup(parse(success_raw),claim,parse(window_raw))
    frozen_raw=read(MAINTENANCE/'retained-file-hashes.json');frozen=parse(frozen_raw)
    require(type(frozen) is dict and 81<=len(frozen)<=256,'BOUNDED_RETAINED_R6_EVIDENCE_REQUIRED')
    for path,h in frozen.items():
        require((confined(path,OUTPUT) or confined(path,CONTEXT)) and re.fullmatch('[0-9a-f]{64}',h),
                'RETAINED_EVIDENCE_PATH_ESCAPE')
        bound({'path':path,'sha256':h})
    installation=parse(read(OUTPUT/'installation-receipt.json'))
    require(set(installation['fileHashes'])<=set(frozen),'ALL_PUBLISHED_FILES_MUST_BE_PRESERVED')
    source_hashes={str(Path(p).relative_to(OUTPUT/'source')):h for p,h in installation['fileHashes'].items()
                   if confined(p,OUTPUT/'source')}
    require(sha(encoded(source_hashes))==OLD_CLOSURE,'EXACT_PRIOR_RUNTIME_CLOSURE_REQUIRED')
    # Preserve JSON authority/phase evidence already retained on the node; never
    # scan private-key directories or infer current authority from old signatures.
    for parent in (CONTEXT,OUTPUT,MAINTENANCE):
        paths=list(parent.rglob('*.json'));require(len(paths)<=256,'RETAINED_JSON_INVENTORY_UNBOUNDED')
        for path in paths:frozen[str(path)]=sha(read(path))
    frozen[str(MAINTENANCE/'retained-file-hashes.json')]=sha(frozen_raw)
    approval=parse(read(CONTEXT/'human-approval-binding.json'))
    require(approval['approvalRef']=='OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_APPROVED_20261009T165118_CEST_R6',
            'EXACT_RETAINED_R6_APPROVAL_REQUIRED')
    cfg=parse(bound({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
    require(cfg['outputRoot']==str(OUTPUT),'EXACT_RETAINED_R6_OUTPUT_REQUIRED')
    bound({'path':str(OUTPUT/'cohort-activation-denial.json'),
           'sha256':'a87bc84ef93af80fb8bd871daae77979604eea9ab77fa352ceca35e828c0bf3d'})
    require(not os.path.lexists(OUTPUT/'cohort-activation-receipt.json'),'CONFLICTING_RETAINED_COHORT_RESULT')
    require(sha(read(WRAPPER,True))==WRAPPER_SHA,'EXACT_RESTORED_R6_WRAPPER_REQUIRED')
    return cfg,frozen


def ensure_preserved(entry,frozen):
    require(all(sha(entry['read'](p))==h for p,h in frozen.items()),'PRIOR_EVIDENCE_CHANGED')


def absent_tasks(raw):
    lines=raw.decode().splitlines()
    require(lines and lines[0].split()==['TASK','PID','STATUS'],'EXACT_TASK_INVENTORY_HEADER_REQUIRED')
    for line in lines[1:]:
        fields=line.split()
        require(len(fields)==3 and fields[1].isdigit(),'EXACT_TASK_INVENTORY_ROW_REQUIRED')
        require(fields[0] not in STATES,'RESIDUAL_TASK_REQUIRES_SEPARATE_RECOVERY')


def native_preflight(entry,cfg):
    from transaction_guard_observation import executable_binding,observe_locked
    from authenticate_provider_transaction import TARGETS
    def command(binding,args):
        identity=executable_binding(binding)
        with tempfile.TemporaryFile() as output:
            result=subprocess.run([binding['path'],*args],stdin=subprocess.DEVNULL,stdout=output,
                stderr=subprocess.DEVNULL,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            output.seek(0);raw=output.read(131073)
        require(result.returncode==0 and len(raw)<=131072,'BOUNDED_NATIVE_PREFLIGHT_REQUIRED')
        require(executable_binding(binding)==identity,'NATIVE_PREFLIGHT_BINARY_CHANGED')
        return raw
    pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']))
    binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
    owner=entry['parse'](entry['bound']({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':OWNER_SHA}))
    fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        guard=observe_locked(fd,binding,OWNER_SHA,{v['containerId']:{'imageManifestDigest':v['imageManifestDigest'],
            'runtimeName':'ouf-semantic-admitted-v2'} for v in TARGETS.values()},cfg['commandBindings'])
        require(guard['candidateStateHashes']==STATES,'CANDIDATE_CHANGED_SINCE_R6_CLEANUP')
        ctr={'path':'/usr/bin/ctr','sha256':'8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e'}
        prefix=['--address','/run/containerd/containerd.sock','--namespace','moby']
        absent_tasks(command(ctr,[*prefix,'tasks','list']))
        for cid,h in METADATA.items():
            require(sha(command(ctr,[*prefix,'containers','info',cid]))==h,'RETAINED_CONTAINER_METADATA_DRIFT')
        journal=entry['parse'](entry['read'](OUTPUT/'registry'/A/'adapter.json'));root=journal['runtimeRoot']
        require(type(root) is str and sha(root.encode())==ROOT_SHA and str(Path(root).resolve())==root,
                'EXACT_RETAINED_NATIVE_ROOT_REQUIRED')
        template=entry['parse'](entry['bound'](cfg['recordsByRole']['adapter']['preparerTemplate']))
        native=entry['parse'](command(template['candidate']['runtimeBinding'],['--root',root,'list','--format','json']))
        # runc emits null for an empty inventory on some reviewed versions.
        if native is None:native=[]
        require(type(native) is list and len(native)<=1024 and all(type(v) is dict and v.get('id') not in STATES for v in native),
                'NATIVE_ENTRY_REQUIRES_SEPARATE_RECOVERY')
        require(sha(entry['read'](WRAPPER,True))==WRAPPER_SHA,'WRAPPER_CHANGED_DURING_PREFLIGHT')
        return guard
    finally:os.close(fd)


def build_mandates(scope,records,now,approval_ref):
    require(APPROVAL_REF!='PENDING_AUDITED_PROVIDER_RECOVERY_APPROVAL' and approval_ref==APPROVAL_REF,
            'EXPLICIT_AUDITED_RECOVERY_APPROVAL_REQUIRED')
    require(type(APPROVED_AT) is int and type(APPROVAL_EXPIRES_AT) is int
        and APPROVED_AT<=now<APPROVAL_EXPIRES_AT,'LIVE_AUDITED_RECOVERY_APPROVAL_REQUIRED')
    require(scope['reviewRef']==REVIEW_REF and set(records)==set(scope['roles'])=={'adapter','southbound'},
            'EXACT_AUDITED_RECOVERY_SCOPE_REQUIRED')
    from datetime import datetime
    end=int(datetime.fromisoformat(scope['dependencyValidUntil'].replace('Z','+00:00')).timestamp())
    require(now+240<=end,'DEPENDENCY_VALIDITY_DOES_NOT_COVER_240_SECOND_WINDOW')
    result={}
    for role,values in records.items():
        proposal=scope['roles'][role]
        require({n:sha(raw) for n,raw in values.items()}==proposal['inputHashes'],'ACCEPTED_SIXTEEN_INPUTS_DRIFT')
        result[role]={**copy.deepcopy(proposal),'schema':'ouf.semantic-provider-transaction-role-mandate.v1',
            'state':'ACTIVE','decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION',
            'approvalRef':approval_ref,'issuedAt':now,'expiresAt':now+240}
    return result


def install_package(path,files):
    for name,raw in files.items():
        relative=Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix()==name,
                'REVIEWED_PACKAGE_PATH_ESCAPE')
        destination=path/relative
        destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        publish(destination,raw)


def collected_diagnostics(output):
    result={}
    if output is None:return result
    names=['broker-denial-prepare.json','broker-denial-cohort-ready.json','broker-denial-authorize-create.json',
        'broker-denial-record-created.json','attestation-producer-denial-attestation.json',
        'approval-producer-denial-approval.json','preparer-denial-prepare.json',
        *('driver-denial-'+v+'.json' for v in ('plan','apply','verify','start'))]
    for role,cid in (('adapter',A),('southbound',S)):
        for name in names:
            path=output/'registry'/cid/name
            if not os.path.lexists(path):continue
            try:
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:raw=os.read(fd,8193)
                finally:os.close(fd)
                require(len(raw)<=8192,'BOUNDED_CHILD_DIAGNOSIS_REQUIRED')
                value=json.loads(raw);reason=value.get('reason','')
                require(re.fullmatch('[A-Z][A-Z0-9_]{0,95}',reason),'SYMBOLIC_CHILD_DIAGNOSIS_REQUIRED')
                points=value.get('exceptionPoints',[])
                require(type(points) is list and len(points)<=4 and all(set(t)=={'file','function','line'}
                    and re.fullmatch('[A-Za-z0-9_.-]{1,100}',t['file']) and re.fullmatch('[A-Za-z0-9_<>]{1,100}',t['function'])
                    and type(t['line']) is int for t in points),'BOUNDED_CHILD_EXCEPTION_POINTS_REQUIRED')
                result[role+'/'+name]={'sha256':sha(raw),'reason':reason,'exceptionPoints':points}
            except Exception:result[role+'/'+name]={'status':'DIAGNOSIS_UNREADABLE'}
    return result


def main(approval_ref,delta_directory):
    global NEW_CONTEXT,NEW_OUTPUT,PHASE
    require(APPROVAL_REF!='PENDING_AUDITED_PROVIDER_RECOVERY_APPROVAL' and approval_ref==APPROVAL_REF,
            'EXPLICIT_AUDITED_RECOVERY_APPROVAL_REQUIRED')
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
    delta=download_bytes(delta_directory);scope=json.loads(delta['scope.json'])
    require(scope['reviewRef']==REVIEW_REF and scope['priorContext']==str(CONTEXT) and scope['priorOutput']==str(OUTPUT)
        and scope['successfulCleanup']==str(MAINTENANCE) and scope['successfulCleanupReceiptSha256']==SUCCESS_SHA
        and scope['priorWrapperSha256']==WRAPPER_SHA,'EXACT_REVIEWED_RECOVERY_GENERATION_REQUIRED')
    claim_path=CLAIM_PATH
    require(not os.path.lexists(claim_path),'DO_NOT_REPLAY_AUDITED_PROVIDER_RECOVERY')
    PHASE='READ_RETAINED_SEALED_SOURCE_AND_SUCCESSFUL_CLEANUP'
    path=PACKAGE/'provider_transaction_intake.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:raw=os.read(fd,131073)
    finally:os.close(fd)
    require(sha(raw)==ENTRY_SHA,'ORIGINAL_RETAINED_ENTRY_DRIFT')
    entry=definitions('audited_retained_entry',raw,path)
    require(entry['read'](path)==raw,'ORIGINAL_ENTRY_CUSTODY_DRIFT')
    manifest_raw=entry['bound']({'path':str(PACKAGE/'intake-source-closure.json'),'sha256':MANIFEST_SHA})
    original={name:entry['bound']({'path':str(PACKAGE/name),'sha256':h})
              for name,h in entry['parse'](manifest_raw)['sourceHashes'].items()}
    entry['load'](PACKAGE)
    cfg,frozen=retain(entry)
    records={role:{name:entry['bound'](binding) for name,binding in values.items()} for role,values in cfg['recordsByRole'].items()}
    from authenticate_provider_transaction import preflight_input_pair,validate_dependency_evidence
    preflight_input_pair(records)
    now=int(time.time());build_mandates(scope,records,now,approval_ref)
    for role,values in records.items():validate_dependency_evidence(entry['parse'](values['dependencyEvidence']),role,now,now+240)
    PHASE='BUILD_COHERENT_REVIEWED_PACKAGE_WITHOUT_TARGET_MUTATION'
    for name in ('repair_broker_sources','repair_admission_transport','build_audited_source_package'):
        definitions(name,delta[name+'.py'],Path(delta_directory)/(name+'.py'))
    builder=sys.modules['build_audited_source_package']
    built=builder.build(manifest_raw,original,{name:delta[Path(name).name] for name in builder.REPLACEMENTS},
                        delta['provider_transaction_intake.py'])
    require(all(built[k]==scope['package'][k] for k in ('manifestHash','entryHash','sourceClosureHash',
        'changedRuntimeFiles','changedUtilities')),'REVIEWED_RECOVERY_PACKAGE_DRIFT')
    PHASE='VERIFY_CURRENT_EMPTY_GUARD_TASK_ABSENCE_AND_PRESERVED_INPUTS'
    observed=native_preflight(entry,cfg);ensure_preserved(entry,frozen)
    PHASE='RESERVE_FRESH_AUDITED_TRANSACTION'
    now=int(time.time());mandates=build_mandates(scope,records,now,approval_ref)
    NEW_CONTEXT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-approved-context-',dir=BASE));NEW_CONTEXT.chmod(0o700)
    NEW_OUTPUT=BASE/('semantic-provider-v2-transaction-'+NEW_CONTEXT.name.removeprefix('semantic-provider-v2-approved-context-'))
    publish(claim_path,encoded({'schema':'ouf.semantic-audited-provider-recovery-claim.v1','approvalRef':approval_ref,
        'reviewRef':REVIEW_REF,'contextDirectory':str(NEW_CONTEXT),'retainedContext':str(CONTEXT),
        'sourceClosureHash':built['sourceClosureHash'],'successfulCleanupHash':SUCCESS_SHA,'notReleaseAcceptance':True}))
    package=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-transaction-source-audited-',dir=BASE));package.chmod(0o700)
    install_package(package,built['files'])
    publish(NEW_CONTEXT/'retained-evidence-hashes.json',encoded(frozen))
    publish(NEW_CONTEXT/'native-preflight.json',encoded(observed))
    current=definitions('audited_current_entry',built['files']['provider_transaction_intake.py'],package/'provider_transaction_intake.py')
    sources,observer=current['load'](package)
    bindings={}
    for role,value in mandates.items():
        path=NEW_CONTEXT/(role+'-mandate.json');raw=encoded(value);publish(path,raw)
        bindings[role]={'path':str(path),'sha256':sha(raw)}
    next_cfg={**cfg,'mandatesByRole':bindings,'outputRoot':str(NEW_OUTPUT)}
    configuration=NEW_CONTEXT/'execution-configuration.json';raw=encoded(next_cfg);publish(configuration,raw)
    publish(NEW_CONTEXT/'human-approval-binding.json',encoded({'schema':'ouf.semantic-provider-approved-root-context.v1',
        'approvalRef':approval_ref,'reviewRef':REVIEW_REF,'configurationHash':sha(raw),'sourcePackage':str(package),
        'sourceClosureHash':built['sourceClosureHash'],'issuedAt':now,'expiresAt':now+240,'notReleaseAcceptance':True}))
    PHASE='INVOKE_COHERENT_SIGNED_PUBLICATION_AND_CONTROLLED_COHORT_ONCE'
    try:result=current['execute_transaction'](NEW_CONTEXT,configuration,sha(raw),sources,observer)
    except Exception as error:
        if not hasattr(error,'diagnosis'):error.diagnosis={'stage':current['STAGE']}
        raise
    finally:ensure_preserved(entry,frozen)
    result.update(retainedR6AndCleanupEvidencePreserved=True,sourcePackage=str(package),
        sourceClosureHash=built['sourceClosureHash'],contextDirectory=str(NEW_CONTEXT))
    publish(NEW_CONTEXT/'audited-recovery-receipt.json',encoded(result))
    return result


if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'EXACT_APPROVAL_AND_REVIEWED_DELTA_DIRECTORY_REQUIRED')
        result=main(*sys.argv[1:]);print('OUF_AUDITED_PROVIDER_RECOVERY='+encoded(result).decode())
    except Exception as error:
        report=dict(getattr(error,'diagnosis',{}));attempted=NEW_CONTEXT is not None and os.path.lexists(NEW_CONTEXT/'execution-claim.json')
        report.update(status='BLOCKED',phase=PHASE,contextDirectory=str(NEW_CONTEXT) if NEW_CONTEXT else None,
            evidenceDirectory=str(NEW_OUTPUT) if NEW_OUTPUT else None,doNotRerunApply=NEW_CONTEXT is not None or os.path.lexists(CLAIM_PATH),
            privateKeysRead=None if attempted else 0,containerLifecycleOperations=None if attempted else 0,
            automaticRetryPerformed=False,notReleaseAcceptance=True,privateValuesPrinted=False,
            startAuthorized=False,errorType=type(error).__name__,retainedPhaseDiagnostics=collected_diagnostics(NEW_OUTPUT))
        if 'reason' not in report:
            reason=str(error);report['reason']=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',reason) else 'AUDITED_RECOVERY_UNPROVEN'
        report['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno}
            for t in traceback.extract_tb(error.__traceback__)[-4:]]
        if isinstance(error,OSError):report['errno']=error.errno
        if NEW_CONTEXT:
            try:publish(NEW_CONTEXT/'operator-denial.json',encoded(report))
            except Exception:report['diagnosisSaved']=False
        print('OUF_AUDITED_PROVIDER_RECOVERY='+encoded(report).decode());raise SystemExit(1)
