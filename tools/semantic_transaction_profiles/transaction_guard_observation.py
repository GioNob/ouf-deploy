"""Read-only native empty-guard observation under the caller's existing lock.

No installed code is executed/imported, no lock inode is replaced, no kernel
write occurs. This reader does not confer image/start/lease authority.
"""
import fcntl
import os
from pathlib import Path
import subprocess
import stat
import tempfile
import time

from authenticate_provider_transaction import require
from assemble_provider_profiles import digest, encoded
from guarded_runtime_switch import custody
from tools.semantic_provider_deployment_authentication import decode
from tools.semantic_provider_lease_nft import NftBackend


UNIT_PATHS={'guard.service':'/etc/systemd/system/ouf-semantic-boot-guard.service',
            'docker-drop-in.conf':'/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf'}


class ReadOnlyDeadlineBackend(NftBackend):
    def __init__(self,*args,deadline):
        super().__init__(*args);self.deadline=deadline

    def run(self,arguments,raw=None,timeout=None):
        stage='OBSERVE_LOCKED_EMPTY_GUARD'
        require(raw is None and arguments in (['-j','list','table','inet',self.table],
                    ['-j','list','table','bridge',self.table]),stage,'READ_ONLY_GUARD_COMMAND_REQUIRED')
        remaining=self.deadline-time.monotonic()
        require(remaining>0,stage,'GUARD_OBSERVATION_BUDGET_EXCEEDED')
        return super().run(arguments,timeout=min(self.budget,remaining))


def private_binding(binding):
    stage='OBSERVE_LOCKED_EMPTY_GUARD'
    require(type(binding) is dict and set(binding)=={'path','sha256'},stage,'EXACT_GUARD_FILE_BINDING_REQUIRED')
    raw=custody(binding['path'],0o600)[0]
    require(digest(raw)==binding['sha256'],stage,'INSTALLED_GUARD_FILE_HASH_DRIFT')
    return raw


def executable_binding(binding):
    # Interpreter/tool bytes can exceed the private JSON/source-file bound.
    stage='OBSERVE_LOCKED_EMPTY_GUARD'
    require(type(binding) is dict and set(binding)=={'path','sha256'},stage,'EXACT_GUARD_COMMAND_BINDING_REQUIRED')
    path=Path(binding['path'])
    from publish_provider_transaction import directory
    require(path.is_absolute() and '..' not in path.parts,stage,'ABSOLUTE_NATIVE_COMMAND_REQUIRED')
    for parent in path.parents:directory(parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and before.st_nlink==1 and before.st_mode&0o111 and not before.st_mode&0o022
                and before.st_size<=64000000,stage,'ROOT_NATIVE_COMMAND_REQUIRED')
        chunks=[];size=0
        while True:
            chunk=os.read(fd,min(65536,64000001-size))
            if not chunk:break
            size+=len(chunk);require(size<=64000000,stage,'NATIVE_COMMAND_SIZE_UNBOUNDED');chunks.append(chunk)
        raw=b''.join(chunks)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        require(size==before.st_size and tuple(getattr(before,k) for k in fields)
                ==tuple(getattr(os.fstat(fd),k) for k in fields)==tuple(getattr(path.lstat(),k) for k in fields),
                stage,'NATIVE_COMMAND_CUSTODY_CHANGED')
    finally:os.close(fd)
    require(digest(raw)==binding['sha256'],stage,'INSTALLED_GUARD_EXECUTABLE_DRIFT')
    return raw


def ensure_borrowed_lock(fd,path):
    stage='OBSERVE_LOCKED_EMPTY_GUARD'
    require(type(fd) is int and fd>=0,stage,'EXPLICIT_EXISTING_GUARD_DESCRIPTOR_REQUIRED')
    _,identity=custody(path,0o600);info=os.fstat(fd)
    require((info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink)
            ==identity[:6],stage,'BORROWED_GUARD_LOCK_INODE_DRIFT')
    # Idempotent on the held open-file description; never open/reacquire another
    # description. If it was not already held, acquire exclusive or fail closed.
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    return identity


def observe_locked(fd,receipt_binding,expected_owner_hash,candidates,command_bindings,unit_paths=UNIT_PATHS):
    """Consume pinned installation metadata and real native bounded reads.

    candidates maps exact approved CID -> {imageManifestDigest,runtimeName}.
    The target caller pins the migrated receipt, owner hash, commands and CIDs;
    fixture bindings are accepted only by CI callers, never target defaults.
    The held descriptor is not closed/unlocked here. No callback can assert
    native tables or candidate state on behalf of nft/Docker.
    """
    stage='OBSERVE_LOCKED_EMPTY_GUARD';saved={};deadline=time.monotonic()+12
    require(os.geteuid()==0 and set(command_bindings)=={'nft','docker','systemctl'}
            and set(unit_paths)==set(UNIT_PATHS) and len(candidates)==2,
            stage,'EXPLICIT_TWO_CANDIDATE_GUARD_OBSERVATION_REQUIRED')
    def bound(path,sha):
        raw=private_binding({'path':str(path),'sha256':sha});saved[str(path)]=raw;return raw
    receipt=decode(bound(receipt_binding['path'],receipt_binding['sha256']),131072)
    root=Path(receipt['directory'])
    require(Path(receipt_binding['path'])==root/'installation-receipt.json'
            and receipt['schema']=='ouf.semantic-provider-network-guard-installation.v1'
            and receipt['state']=='INSTALLED' and receipt['configurationHash']==expected_owner_hash
            and receipt['startAuthorized'] is False and receipt['leaseAuthorized'] is False,
            stage,'PINNED_EMPTY_GUARD_INSTALLATION_REQUIRED')
    owner=decode(bound(root/'coordinated-configuration.json',expected_owner_hash),131072)
    boot=decode(bound(root/'boot-configuration.json',receipt['bootConfigurationHash']),131072)
    profile=decode(bound(root/'boot-profile.json',receipt['bootProfileHash']),131072)
    require(owner['kernel']==boot['kernel'] and owner['commonLockFile']==boot['lockFile']
            and profile['coordinatedConfigurationHash']==expected_owner_hash
            and profile['bootConfigurationHash']==receipt['bootConfigurationHash']
            and len(owner['kernel']['providerFlows'])==2,
            stage,'INSTALLED_EMPTY_GUARD_COHORT_DRIFT')
    lock_identity=ensure_borrowed_lock(fd,owner['commonLockFile'])
    bound(root/'transition-source.py',receipt['observerHash'])
    for prefix,hashes in (('source',receipt['sourceHashes']),('migration',receipt['transitionSourceHashes'])):
        for name,sha in hashes.items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts,stage,'GUARD_SOURCE_PATH_ESCAPE_DENIED')
            bound(root/prefix/name,sha)
    bound(boot['compilerFile'],boot['compilerHash']);bound(profile['bootGuardFile'],profile['bootGuardHash'])
    for name,path in unit_paths.items():bound(path,receipt['artifactHashes'][name])
    binaries={name:executable_binding(binding) for name,binding in command_bindings.items()}
    require(command_bindings['nft']=={'path':owner['nftPath'],'sha256':owner['nftSha256']},
            stage,'INSTALLED_NFT_COMMAND_SCOPE_DRIFT')
    def command(name,args):
        remaining=deadline-time.monotonic();require(remaining>0,stage,'GUARD_OBSERVATION_BUDGET_EXCEEDED')
        with tempfile.TemporaryFile() as out, tempfile.TemporaryDirectory(dir='/root',prefix='ouf-empty-docker-config-') as empty:
            argv=[command_bindings[name]['path'],*(['--config',empty] if name=='docker' else []),*args]
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,timeout=remaining,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock'})
            out.seek(0);raw=out.read(16385)
        require(result.returncode==0 and len(raw)<=16384,stage,'NATIVE_GUARD_OBSERVATION_COMMAND_FAILED')
        return raw
    for unit,prop in [('ouf-semantic-boot-guard.service','ExecStart'),('docker.service','ExecStartPre')]:
        require(receipt['guardCommand'].encode() in command('systemctl',['show',unit,'--property='+prop,'--value']),
                stage,'LOADED_GUARD_COMMAND_DRIFT')
    backend=ReadOnlyDeadlineBackend([owner['nftPath']],owner['kernel'],owner['expectedStructureHash'],
                       owner['readBudgetSeconds'],deadline=deadline)
    backend.verify_ownership(owner['kernel'])
    sets=backend.read_sets(owner['kernel'])
    require(set(sets)=={(family,i) for family in ('inet','bridge') for i in range(2)}
            and all(not v for v in sets.values()),stage,'PROVIDER_KERNEL_MEMBERSHIP_NOT_EMPTY')
    owner_journal=custody(owner['journalFile'],0o600)[0];boot_journal=custody(boot['journalFile'],0o600)[0]
    require(decode(owner_journal,131072)=={'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],
        'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[],[]]},
        stage,'EMPTY_COORDINATED_JOURNAL_DRIFT')
    require(decode(boot_journal,131072)=={'schema':'ouf.semantic-runtime-transition.v1','state':'RUNTIME_EMPTY',
        'transactionId':boot['transactionId'],'configurationHash':receipt['bootConfigurationHash'],
        'leaseStructureHash':owner['expectedStructureHash'],'startAuthorized':False},stage,'EMPTY_BOOT_JOURNAL_DRIFT')
    facts={}
    fmt='{"id":{{json .Id}},"image":{{json .Image}},"runtime":{{json .HostConfig.Runtime}},"state":{{json .State}}}'
    for cid,expected in candidates.items():
        value=decode(command('docker',['inspect','--type','container','--format',fmt,cid]),16384)
        state=value['state']
        require(value['id']==cid and value['image']==expected['imageManifestDigest']
                and value['runtime']==expected['runtimeName'] and state['Status']=='created'
                and state['Running'] is False and state['Pid']==0 and state['StartedAt'].startswith('0001-'),
                stage,'APPROVED_CANDIDATE_STOPPED_STATE_DRIFT')
        facts[cid]=digest(encoded(value))
    backend.verify_ownership(owner['kernel'])
    require(all(not v for v in backend.read_sets(owner['kernel']).values()),stage,'EMPTY_KERNEL_READBACK_DRIFT')
    for path,raw in {**saved,owner['journalFile']:owner_journal,boot['journalFile']:boot_journal}.items():
        require(custody(path,0o600)[0]==raw,stage,'GUARD_INPUT_CUSTODY_CHANGED')
    require(ensure_borrowed_lock(fd,owner['commonLockFile'])==lock_identity,stage,'GUARD_LOCK_CUSTODY_CHANGED')
    for name,binding in command_bindings.items():
        require(executable_binding(binding)==binaries[name],stage,'NATIVE_COMMAND_CUSTODY_CHANGED')
    require(time.monotonic()<deadline,stage,'GUARD_OBSERVATION_BUDGET_EXCEEDED')
    return {'configurationHash':expected_owner_hash,'kernelConfigurationHash':digest(encoded(owner['kernel'])),
            'candidateStateHashes':facts,'providerSetsEmpty':True,
            'lockInodePreserved':True,'containerLifecycleOperations':0,'notReleaseAcceptance':True}
