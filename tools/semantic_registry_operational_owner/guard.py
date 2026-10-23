"""Operational root configuration and a shared lifetime publication fence.

A completed installation is durable configuration, not an extension of its
finite HUMAN execution window. Only the installer may create it. Runtime never
opens signing keys, initializes journals or changes a predecessor fence.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from .core import require, encoded, digest
from .store import identity, file_identity


def protected_file(path, maximum, *, expected=None, modes=(0o400,0o600)):
    path=Path(path);fds=[];pins=[]
    require(path.is_absolute() and '..' not in path.parts and len(path.parts)<=48,'EXACT_OPERATIONAL_INPUT_PATH_REQUIRED')
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in path.parts[1:-1]:
            info=os.fstat(fd);require(info.st_uid==0 and not info.st_mode&0o022,'ROOT_OPERATIONAL_INPUT_ANCESTRY_REQUIRED')
            parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            fds.append(fd);pins.append((parent,part,fd,identity(os.fstat(fd))))
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(leaf)
        before=os.fstat(leaf)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
                and stat.S_IMODE(before.st_mode) in modes and 0<before.st_size<=maximum,
                'CUSTODIED_OPERATIONAL_INPUT_REQUIRED')
        chunks=[];count=0
        while count<before.st_size:
            block=os.read(leaf,min(65536,before.st_size-count));require(bool(block),'COMPLETE_OPERATIONAL_INPUT_REQUIRED')
            chunks.append(block);count+=len(block)
        raw=b''.join(chunks)
        require(file_identity(before)==file_identity(os.fstat(leaf))
                ==file_identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)), 'OPERATIONAL_INPUT_CHANGED')
        for parent,part,child,pin in pins:
            require(pin==identity(os.fstat(child))==identity(os.stat(part,dir_fd=parent,follow_symlinks=False)),
                    'OPERATIONAL_INPUT_ANCESTRY_CHANGED')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'OPERATIONAL_INPUT_HASH_CHANGED')
        return raw
    finally:
        for fd in reversed(fds):os.close(fd)


def private_json(path, expected=None):
    raw=protected_file(path,1048576,expected=expected)
    value=json.loads(raw);require(type(value) is dict and encoded(value)==raw,'CANONICAL_OPERATIONAL_INPUT_REQUIRED')
    return value


class InstalledGuard:
    """The process manager pins configurationHash in its protected command line.

    root-only source/configuration custody is the ordinary operating-service
    trust boundary. The installation receipt records the finite authenticated
    deployment; it does not pretend that old authority is currently valid.
    """
    def __init__(self, configuration_path, configuration_hash):
        self.path=Path(configuration_path);self.hash=configuration_hash
        self.configuration=private_json(self.path,configuration_hash)
        c=self.configuration
        require(set(c)=={'schema','proposalHash','sourceManifest','sources','ownerInputs','policy','destinations',
                         'priorControlledAttempts','predecessorInputsHash','fenceBinding','commonLockIdentity','verification','tlsCa'}
                and c['schema']=='ouf.registry-operational-token-configuration.v1'
                and c['priorControlledAttempts']==321, 'EXACT_INSTALLED_OPERATIONAL_CONFIGURATION_REQUIRED')
        self.fd=None;self.pid=None
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        v=c['verification']
        require(type(v) is dict and set(v)=={'trustPolicy','openssl','context'},'PUBLIC_INSTALLATION_VERIFICATION_PROFILE_REQUIRED')
        self.verifier=DetachedAuthenticator(v['trustPolicy'],str(self.path.parent/'receipt-signatures'),v['openssl'])
        self.metadata_guard()

    def metadata_guard(self):
        c=self.configuration
        require(private_json(self.path,self.hash)==c,'OPERATIONAL_CONFIGURATION_CHANGED')
        receipt=private_json(self.path.parent/'installed.json')
        require(receipt.get('schema')=='ouf.registry-operational-token-installation-receipt.v1'
                and receipt.get('complete') is True and receipt.get('configurationHash')==self.hash
                and receipt.get('proposalHash')==c['proposalHash']
                and receipt.get('sourceManifestHash')==digest(c['sourceManifest'])
                and receipt.get('operationalRenewalInstalled') is True
                and receipt.get('priorControlledAttempts')==321, 'COMPLETED_OPERATIONAL_INSTALLATION_REQUIRED')
        ctx=c['verification']['context']
        require(self.verifier(encoded(receipt),'CREATION_ATTESTATION',ctx['attestorRef'],ctx['installationRef'],ctx['entityRef']) is True,
                'CURRENT_SCOPED_INSTALLATION_RECEIPT_SIGNATURE_REQUIRED')
        from .contract import SOURCE_NAMES
        manifest=c['sourceManifest']
        require(set(manifest['sourceHashes'])==SOURCE_NAMES,'COMPLETE_EXECUTING_OPERATIONAL_SOURCE_MANIFEST_REQUIRED')
        for name,sha in manifest['sourceHashes'].items():
            module=sys.modules.get(name)
            require(module is not None,'OPERATIONAL_SOURCE_MODULE_NOT_PRELOADED')
            qualified=getattr(module,'__qualified_source_sha256__',None)
            if qualified is not None:require(qualified==sha,'OPERATIONAL_EXECUTING_SOURCE_HASH_CHANGED')
            else:protected_file(module.__file__,1048576,expected=sha,modes=(0o400,0o600,0o644))
        require(private_json(c['fenceBinding']['path'])==c['fenceBinding']['value'],'OPERATIONAL_OWNER_FENCE_CHANGED')
        for source in c['sources']:
            require(type(source) is dict and set(source)=={'path','sha256','maximumBytes'},'EXACT_OPERATIONAL_SOURCE_BINDING_REQUIRED')
            require(type(source['maximumBytes']) is int and 1<=source['maximumBytes']<=67108864,'BOUNDED_OPERATIONAL_SOURCE_REQUIRED')
            protected_file(source['path'],source['maximumBytes'],expected=source['sha256'],modes=(0o400,0o600,0o644,0o755))
        owner=c['ownerInputs'];credential=Path(owner['credentialPath'])
        from tools.semantic_policy_token_owner.producer import protected_directory
        with protected_directory(credential.parent) as parent:
            info=os.stat(credential.name,dir_fd=parent,follow_symlinks=False)
            observed=[info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
            require(observed==owner['credentialMetadata'] and info.st_uid==info.st_gid==0
                    and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o400,
                    'EXISTING_SERVICE_CREDENTIAL_CUSTODY_CHANGED')
        binding=owner['binding']
        with protected_directory(binding['output_directory'],gid=binding['output_gid'],mode=0o750) as directory:
            s=os.fstat(directory)
            require(owner['outputDirectoryIdentity']=={'device':s.st_dev,'inode':s.st_ino},'OPERATIONAL_TOKEN_OUTPUT_DIRECTORY_CHANGED')

    @contextmanager
    def invocation(self):
        require(self.fd is None,'NESTED_OPERATIONAL_COMMON_FENCE')
        self.metadata_guard();path=self.configuration['destinations']['commonInvocationLock']
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            require(list(file_identity(os.fstat(fd)))==self.configuration['commonLockIdentity'],
                    'CURRENT_LOGICAL_OWNER_COMMON_LOCK_REQUIRED')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:require(False,'ANOTHER_LOGICAL_TOKEN_OWNER_IS_RUNNING')
            self.fd,self.pid=fd,os.getpid()
            self.guard();yield self
        finally:self.fd=None;self.pid=None;os.close(fd)

    def guard(self):
        require(self.fd is not None and self.pid==os.getpid(),'SAME_PROCESS_LOGICAL_OWNER_LIFETIME_FENCE_REQUIRED')
        self.metadata_guard()
        require(file_identity(os.fstat(self.fd))==file_identity(os.stat(self.configuration['destinations']['commonInvocationLock'],follow_symlinks=False)),
                'LOGICAL_OWNER_LOCK_REPLACED')
