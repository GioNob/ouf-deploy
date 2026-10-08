"""Low-level single-file runtime switch; never an authorization producer.

No target CLI. A sealed target orchestrator must authenticate full records and
observe stopped candidates/empty guard before supplying the locked verifier.
Failure after durable claim is retained, including uncertain switch outcome.
"""
import fcntl
import os
from pathlib import Path
import re
import stat

from authenticate_provider_transaction import TransactionDenied, require
from assemble_provider_profiles import digest, encoded
from publish_provider_transaction import directory, publish_once, sync


def custody(path, mode):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'VERIFY_RUNTIME_SWITCH', 'ABSOLUTE_SWITCH_PATH_REQUIRED')
    for ancestor in (path.parent, *path.parent.parents): directory(ancestor)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
                and before.st_size <= 131072, 'VERIFY_RUNTIME_SWITCH', 'ROOT_SWITCH_FILE_REQUIRED')
        raw = os.read(fd, 131073)
        after = os.fstat(fd)
        fields = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity = tuple(getattr(before,k) for k in fields)
        require(len(raw) == before.st_size and identity == tuple(getattr(after,k) for k in fields)
                == tuple(getattr(path.lstat(),k) for k in fields),
                'VERIFY_RUNTIME_SWITCH', 'RUNTIME_SWITCH_CUSTODY_CHANGED')
        return raw, identity
    finally: os.close(fd)


def wrapper_bytes(python_path, source_root, configuration):
    paths = (str(python_path), str(Path(source_root)/'scripts/semantic_provider_docker_runtime.py'), str(configuration))
    require(all(Path(p).is_absolute() and '..' not in Path(p).parts
                and re.fullmatch(r'/[A-Za-z0-9_./-]+',p) for p in paths),
            'VERIFY_RUNTIME_SWITCH', 'CLOSED_WRAPPER_PATH_REQUIRED')
    return ('#!/bin/sh\nexec '+paths[0]+' -I -B '+paths[1]+' --configuration '+paths[2]+' "$@"\n').encode()


def verify_installed_plan(plan):
    """Recheck publication against a freshly authenticated in-process plan.

    This is file custody, NOT signature verification. The caller must rebuild
    plan through build_install_plan with actual live authenticated inputs before
    every switch checkpoint; a deserialized plan/receipt cannot confer authority.
    No journals may have progressed from their approved STAGED bytes yet.
    """
    stage='RECHECK_INSTALLED_TRANSACTION'
    require(plan['status']=='AUTHENTICATED_INSTALL_PLAN_ASSEMBLED'
            and plan['startAuthorized'] is False and plan['leaseAuthorized'] is False,
            stage,'FRESH_AUTHENTICATED_PLAN_REQUIRED')
    configuration=plan['adapterConfiguration'];root=Path(configuration['registryRoot']).parent
    source=root/'source'
    require(configuration['registryRoot']==str(root/'registry')
            and configuration['driverPath']==str(source/'scripts/semantic_provider_preexec_hook.py')
            and configuration['admissionPath']==str(source/'scripts/semantic_provider_deployment_broker.py'),
            stage,'INSTALLED_PLAN_ROOT_DRIFT')
    expected={**plan['files'],str(root/'runtime-configuration-proposal.json'):encoded(configuration)}
    for path,raw in expected.items():
        require(Path(path).is_relative_to(root) and '..' not in Path(path).parts
                and custody(path,0o600)[0]==raw,stage,'INSTALLED_PROFILE_OR_JOURNAL_DRIFT')
    for name,expected_hash in plan['sourceHashes'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts
                and digest(custody(source/name,0o600)[0])==expected_hash,
                stage,'INSTALLED_SOURCE_CLOSURE_DRIFT')
    return {'configurationHash':digest(encoded(configuration)),'root':str(root)}


def switch_existing_wrapper(wrapper, expected_wrapper_hash, proposed_bytes, claim_root,
                            lock_path, expected_lock_identity, verify_locked):
    """Atomic CAS under existing native guard lock, with no implicit authority.

    verify_locked(fd, phase) MUST raise on stale authority, changed source/profile
    custody, candidate generation/runtime/config drift or nonempty kernel sets.
    It must observe using the held lock, not reacquire it. This helper deliberately
    has no default verifier and cannot be invoked as an operator command.
    The signed transaction/generation integration remains the caller's duty.
    """
    stage = 'VERIFY_RUNTIME_SWITCH'; wrapper = Path(wrapper); root = Path(claim_root); lock_path = Path(lock_path)
    claimed = False; replaced = False; rename_attempted = False; fd = None; staging = None
    try:
        require(os.geteuid() == 0 and callable(verify_locked) and type(proposed_bytes) is bytes
                and 0 < len(proposed_bytes) <= 131072 and re.fullmatch('[0-9a-f]{64}',expected_wrapper_hash),
                stage, 'EXPLICIT_VERIFIED_RUNTIME_SWITCH_REQUIRED')
        directory(root)
        for ancestor in root.parents: directory(ancestor)
        require(stat.S_IMODE(root.lstat().st_mode) == 0o700,stage,'PRIVATE_SWITCH_EVIDENCE_REQUIRED')
        require(not os.path.lexists(root/'runtime-switch-claim.json'),stage,'EXISTING_RUNTIME_SWITCH_CLAIM_PRESERVED')
        original, wrapper_identity = custody(wrapper,0o755)
        require(digest(original) == expected_wrapper_hash,stage,'INSTALLED_WRAPPER_HASH_DRIFT')
        lock_raw, lock_identity = custody(lock_path,0o600)
        require(lock_raw == b'' and tuple(expected_lock_identity) == lock_identity,
                stage,'EXISTING_NATIVE_GUARD_LOCK_DRIFT')
        fd = os.open(lock_path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        def stable_lock():
            require(custody(lock_path,0o600)[1] == lock_identity
                    and (os.fstat(fd).st_dev,os.fstat(fd).st_ino) == lock_identity[:2],
                    stage,'NATIVE_GUARD_LOCK_REPLACED')
        def verify(phase):
            require(verify_locked(fd,phase) is None,stage,'LOCKED_VERIFIER_MUST_RAISE_ON_DENIAL')
        stable_lock(); verify('BEFORE_CLAIM'); stable_lock()
        require(custody(wrapper,0o755) == (original,wrapper_identity),stage,'WRAPPER_CHANGED_BEFORE_CLAIM')
        # This claim is irreversible evidence of an attempted switch, not authority.
        publish_once(root/'runtime-switch-claim.json',encoded({
            'schema':'ouf.semantic-provider-runtime-switch-claim.v1','state':'SWITCHING',
            'priorWrapperHash':digest(original),'proposedWrapperHash':digest(proposed_bytes),
            'containerLifecycleOperations':0,'notReleaseAcceptance':True}))
        claimed = True
        publish_once(root/'prior-runtime-wrapper.sh',original)
        staging = wrapper.parent/('.ouf-runtime-switch-'+digest(str(root).encode()))
        publish_once(staging,proposed_bytes)
        os.chmod(staging,0o755)
        tmpfd=os.open(staging,os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(tmpfd)
        finally:os.close(tmpfd)
        sync(staging.parent)
        stage = 'COMMIT_RUNTIME_SWITCH'
        stable_lock(); verify('BEFORE_RENAME'); stable_lock()
        require(custody(wrapper,0o755) == (original,wrapper_identity)
                and custody(staging,0o755)[0] == proposed_bytes,
                stage,'WRAPPER_CHANGED_BEFORE_RENAME')
        rename_attempted = True
        os.replace(staging,wrapper); replaced = True; sync(wrapper.parent)
        stage = 'VERIFY_RUNTIME_SWITCH_READBACK'
        stable_lock(); verify('AFTER_RENAME'); stable_lock()
        require(custody(wrapper,0o755)[0] == proposed_bytes,stage,'SWITCHED_WRAPPER_READBACK_DRIFT')
        report={'schema':'ouf.semantic-provider-runtime-switch.v1','status':'WRAPPER_SWITCHED',
                'priorWrapperHash':digest(original),'installedWrapperHash':digest(proposed_bytes),
                'containerLifecycleOperations':0,'daemonRestarted':False,'notReleaseAcceptance':True}
        publish_once(root/'runtime-switch-receipt.json',encoded(report)); return report
    except Exception as error:
        diagnosis = error.diagnosis.copy() if isinstance(error,TransactionDenied) else {
            'status':'BLOCKED','stage':stage,'reason':'GUARDED_RUNTIME_SWITCH_UNPROVEN','secretValuesPrinted':False}
        diagnosis.update(evidenceDirectory=str(root),doNotRerunApply=claimed or os.path.lexists(root/'runtime-switch-claim.json'),
                         wrapperReplaced=replaced,renameAttempted=rename_attempted,
                         switchOutcome='REPLACED' if replaced else 'UNPROVEN' if rename_attempted else 'UNCHANGED',
                         containerLifecycleOperations=0,notReleaseAcceptance=True)
        if isinstance(error,OSError):diagnosis.update(errorType=type(error).__name__,errno=error.errno)
        if claimed:
            try:publish_once(root/'runtime-switch-denial.json',encoded(diagnosis))
            except Exception:diagnosis['diagnosisSaved']=False
        failure=TransactionDenied(stage,diagnosis['reason']);failure.diagnosis=diagnosis
        raise failure from None
    finally:
        if fd is not None:os.close(fd)
