"""Initialize one canonical finite recovery, after actual signed authority.

This helper issues no authority and dispatches no Docker/OAuth/application
operation. Partial or existing installations are retained and never adopted or
reinitialized. Source/launcher custody is a separate mandatory boundary.
"""
import json,os,time
from pathlib import Path
from .core import require,digest,encoded,Store,initial,validate_current
from .factory import factory_scope,current_scope
from .read_budget import ReadBudget,read_scope
from .installed_owner import owner_scope,build_observer
from tools.semantic_policy_token_owner.producer import protected_directory

def installation_scope(context,reference):
    factory=factory_scope(context);owner=owner_scope(context['plan'],reference)
    return {'schema':'ouf.semantic-registry-recovery-installation-scope.v1',
        'factoryScopeHash':digest(factory),'installedOwnerScopeHash':digest(owner),
        'executionRoot':factory['executionRoot'],'logicalOperationRef':context['plan']['logicalOperationRef'],
        'operation':'CREATE_ONE_CANONICAL_FINITE_RECOVERY_ONLY','maximumDirectoryCreates':2,
        'maximumRuntimeSeconds':900,'existingInstallationAdoptionAllowed':False,
        'oldClaimsRemainConsumed':True,'budgetReset':False,'runtimeEffectsAllowed':False}

def _publish(directory,name,value):
    raw=encoded(value);fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        with os.fdopen(os.dup(fd),'wb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
        os.fsync(fd);os.fsync(directory)
    finally:os.close(fd)

def install(context,reference,authority,raw):
    require(os.geteuid()==os.getegid()==0,'ROOT_RECOVERY_INSTALLER_REQUIRED')
    expected=installation_scope(context,reference)
    _,_,scoped=current_scope(context,authority,raw);signed=json.loads(raw)
    require(signed.get('semanticRegistryRecoveryInstallation')==expected
        and signed.get('semanticRegistryRecoveryReads')==read_scope(context['plan'],context['executionRoot']),
        'CURRENT_SIGNED_RECOVERY_INSTALLATION_AND_READ_SCOPES_REQUIRED')
    # Refuse a parked owner before any directory/ledger creation. This only
    # reconstructs the exact existing observer; it never waits or starts it.
    owner=build_observer(context['plan'],reference,authority,raw)
    root=Path(context['executionRoot']);wall,mono=time.time(),time.monotonic()
    expires=min(wall+900,signed['expiresAt'])
    require(signed['issuedAt']<=wall<expires,'CURRENT_FINITE_INSTALLATION_WINDOW_REQUIRED')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    value=initial(context['plan'],authority_hash=scoped.hash,expires_unix=expires,
        expires_monotonic=mono+expires-wall,boot_id=boot,
        predecessor_history_hash=authority.expected['predecessorHistoryHash'],
        created_unix=wall,created_monotonic=mono)
    scoped.guard(value)
    with protected_directory(root.parent) as parent:
        parent_info=os.fstat(parent)
        require(installation_scope(context,reference)==expected and authority(raw) is True,
            'INSTALLATION_SCOPE_CHANGED_BEFORE_DIRECTORY_CREATION')
        owner.guard(owner.binding.digest())
        # mkdir is the durable one-attempt fence. Every subsequent failure
        # leaves the directory in place; no cleanup/retry/alternate parent.
        os.mkdir(root.name,0o700,dir_fd=parent);os.fsync(parent)
        fd=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            os.mkdir('node',0o700,dir_fd=fd);os.fsync(fd)
            store=Store(root,context['plan']['logicalOperationRef']);store.initialize(value)
            ReadBudget.initialize(store,scoped,context['plan'])
            owner.guard(owner.binding.digest());scoped.guard(store.read())
            validate_current(context['plan'],store.read(),boot,(time.time(),time.monotonic()))
            info=os.fstat(fd);now=os.fstat(parent)
            pin=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
            require(pin(parent_info)==pin(now) and pin(info)==pin(root.lstat())
                and installation_scope(context,reference)==expected,'CANONICAL_INSTALLATION_CUSTODY_CHANGED')
            receipt={'schema':'ouf.semantic-registry-recovery-installation-receipt.v1',
                'installationScopeHash':digest(expected),'contextHash':digest(context),'authorityHash':scoped.hash,
                'executionRoot':str(root),'directoryIdentity':{'device':info.st_dev,'inode':info.st_ino},
                'ownerBindingHash':owner.profile_hash,'initialJournalHash':digest(value),
                'expiresUnix':expires,'bootId':boot,'runtimeEffectsDispatched':0,
                'authorityIssuedByInstaller':False,'automaticReplayAllowed':False,'budgetReset':False}
            _publish(fd,'installation.json',receipt)
            return receipt
        finally:os.close(fd)
