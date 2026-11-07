"""Durable installed lease-owner trust; finite HUMAN authority installs only.

Runtime verifies a completed signed installation and a current signed generation
receipt plus independent native observation. It never reads signing keys, issues
authority, migrates a journal, adopts a generation or starts a container.
"""
from contextlib import contextmanager
import copy,fcntl,hashlib,os,re,sys,stat
from pathlib import Path
from .custody_capture import digest,encoded,require
from tools.semantic_registry_operational_owner.guard import protected_file,private_json
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,ancestors
from .native_generation_probe import NativeLeaseGenerationProbe

CONFIG_FIELDS={'schema','installationInputsHash','desiredProfileHash','sourceManifest','sources','verification',
    'serviceUnitPath','serviceUnitHash','commonInvocationLock','commonLockIdentity','generationReceiptPath',
    'hostBootIdPath','ledgerRoot','scopePolicyHash'}

REQUIRED_MODULES={'tools.m2_discovery_installation_profile.installed_lease_guard',
    'tools.m2_discovery_installation_profile.lease_worker','tools.m2_discovery_installation_profile.native_generation_probe'}

def boot_id(reference):
    path=Path(reference);ancestors(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
            and stat.S_IMODE(before.st_mode) in (0o400,0o444,0o600) and before.st_nlink==1
            and 0<=before.st_size<=256,'CUSTODIED_DISCOVERY_LEASE_BOOT_SOURCE_REQUIRED')
        raw=os.read(fd,257);after=os.fstat(fd)
        require(0<len(raw)<=256 and (before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode)
            ==(after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode),
            'DISCOVERY_LEASE_BOOT_SOURCE_CHANGED')
    finally:os.close(fd)
    value=raw.strip().decode('ascii')
    require(re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',value),
        'EXACT_NATIVE_DISCOVERY_LEASE_BOOT_ID_REQUIRED')
    return value


class InstalledLeaseGuard:
    def __init__(self,configuration_path,configuration_hash,*,generation_probe):
        require(type(generation_probe) is NativeLeaseGenerationProbe,'INDEPENDENT_NATIVE_GENERATION_PROBE_REQUIRED')
        self.path,self.sha=Path(configuration_path),configuration_hash
        self.configuration=private_json(self.path,configuration_hash)
        c=self.configuration
        require(type(c) is dict and set(c)==CONFIG_FIELDS
            and c['schema']=='ouf.discovery-operational-lease-configuration.v1'
            and all(type(c[k]) is str and re.fullmatch('[0-9a-f]{64}',c[k])
                for k in ('installationInputsHash','desiredProfileHash','serviceUnitHash','scopePolicyHash')),
            'EXACT_INSTALLED_DISCOVERY_LEASE_CONFIGURATION_REQUIRED')
        verification=c['verification']
        require(type(verification) is dict and set(verification)=={'trustPolicy','openssl','context'},
            'EXACT_PUBLIC_DISCOVERY_LEASE_VERIFICATION_PROFILE_REQUIRED')
        self.verifier=DetachedAuthenticator(verification['trustPolicy'],str(self.path.parent/'receipt-signatures'),
            verification['openssl'])
        require(generation_probe.root==Path(c['generationReceiptPath']).parent/'observations',
            'EXACT_INSTALLED_NATIVE_GENERATION_OBSERVATION_ROOT_REQUIRED')
        self.probe=generation_probe;self.fd=None;self.pid=None;self.metadata_guard()

    def signature(self,value):
        ctx=self.configuration['verification']['context']
        require(set(ctx)=={'installationRef','entityRef','attestorRef'}
            and self.verifier(encoded(value),'CREATION_ATTESTATION',ctx['attestorRef'],
                ctx['installationRef'],ctx['entityRef']) is True,
            'CURRENT_SCOPED_DISCOVERY_LEASE_RECEIPT_SIGNATURE_REQUIRED')

    def metadata_guard(self):
        c=self.configuration
        require(private_json(self.path,self.sha)==c,'INSTALLED_DISCOVERY_LEASE_CONFIGURATION_CHANGED')
        receipt=private_json(self.path.parent/'installed.json')
        expected={'schema','complete','configurationHash','installationInputsHash','desiredProfileHash',
            'sourceManifestHash','serviceUnitHash','scopePolicyHash','finiteApprovalAuthorizesInstallationOnly',
            'operationalLifetime','runtimeSigningKeyAccessAllowed','containerLifecycleOperationsAllowed'}
        require(set(receipt)==expected and receipt['schema']=='ouf.discovery-operational-lease-installation-receipt.v1'
            and receipt['complete'] is True and receipt['configurationHash']==self.sha
            and receipt['installationInputsHash']==c['installationInputsHash']
            and receipt['desiredProfileHash']==c['desiredProfileHash']
            and receipt['sourceManifestHash']==digest(c['sourceManifest'])
            and receipt['serviceUnitHash']==c['serviceUnitHash'] and receipt['scopePolicyHash']==c['scopePolicyHash']
            and receipt['finiteApprovalAuthorizesInstallationOnly'] is True
            and receipt['operationalLifetime']=='UNTIL_DISABLE_CUSTODY_OR_INSTALLATION_TRUST_REVOCATION'
            and receipt['runtimeSigningKeyAccessAllowed'] is False
            and receipt['containerLifecycleOperationsAllowed'] is False,
            'COMPLETED_DISTINCT_OPERATIONAL_LEASE_INSTALLATION_REQUIRED')
        self.signature(receipt)
        protected_file(c['serviceUnitPath'],65536,expected=c['serviceUnitHash'],modes=(0o600,0o644))
        manifest=c['sourceManifest']
        require(type(manifest) is dict and set(manifest)=={'schema','sourceHashes','dependencyClosureHash'}
            and manifest['schema']=='ouf.discovery-operational-lease-sources.v1'
            and type(manifest['sourceHashes']) is dict and REQUIRED_MODULES<=set(manifest['sourceHashes'])
            and 3<=len(manifest['sourceHashes'])<=64
            and type(manifest['dependencyClosureHash']) is str and re.fullmatch('[0-9a-f]{64}',manifest['dependencyClosureHash']),
            'CLOSED_EXECUTING_DISCOVERY_LEASE_SOURCE_MANIFEST_REQUIRED')
        for name,sha in manifest['sourceHashes'].items():
            require(type(name) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.]{0,255}',name)
                and type(sha) is str and re.fullmatch('[0-9a-f]{64}',sha),'EXACT_DISCOVERY_LEASE_SOURCE_IDENTITY_REQUIRED')
            module=sys.modules.get(name);require(module is not None,'DISCOVERY_LEASE_SOURCE_MODULE_NOT_PRELOADED')
            qualified=getattr(module,'__qualified_source_sha256__',None)
            if qualified is not None:require(qualified==sha,'EXECUTING_DISCOVERY_LEASE_SOURCE_CHANGED')
            else:protected_file(module.__file__,1048576,expected=sha,modes=(0o400,0o600,0o644))
        require(type(c['sources']) is list and 1<=len(c['sources'])<=64,'BOUNDED_INSTALLED_DISCOVERY_LEASE_SOURCES_REQUIRED')
        for item in c['sources']:
            require(type(item) is dict and set(item)=={'path','sha256','maximumBytes'}
                and type(item['maximumBytes']) is int and 1<=item['maximumBytes']<=67108864,
                'EXACT_INSTALLED_DISCOVERY_LEASE_SOURCE_BINDING_REQUIRED')
            protected_file(item['path'],item['maximumBytes'],expected=item['sha256'],modes=(0o400,0o600,0o644,0o755))
        return receipt

    @contextmanager
    def invocation(self):
        require(self.fd is None,'NESTED_INSTALLED_DISCOVERY_LEASE_INVOCATION')
        self.metadata_guard();path=Path(self.configuration['commonInvocationLock'])
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        def identity(s):return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink]
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,
                'PRIVATE_DISCOVERY_LEASE_LOGICAL_OWNER_LOCK_REQUIRED')
            current=identity(info)
            require(current==self.configuration['commonLockIdentity']
                and current==identity(path.lstat()),'CURRENT_DISCOVERY_LEASE_LOGICAL_OWNER_LOCK_REQUIRED')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.fd,self.pid=fd,os.getpid();yield self
        finally:self.fd=None;self.pid=None;os.close(fd)

    def current(self,scope_hash,generation_ref):
        require(self.fd is not None and self.pid==os.getpid(),'SAME_PROCESS_OPERATIONAL_LEASE_LIFETIME_FENCE_REQUIRED')
        require(type(self.probe) is NativeLeaseGenerationProbe
            and self.probe.root==Path(self.configuration['generationReceiptPath']).parent/'observations',
            'EXACT_INSTALLED_NATIVE_GENERATION_PROBE_REQUIRED')
        self.metadata_guard();c=self.configuration
        s=os.fstat(self.fd);path=Path(c['commonInvocationLock'])
        require([s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink]==c['commonLockIdentity']
            and (s.st_dev,s.st_ino)==(path.lstat().st_dev,path.lstat().st_ino),
            'DISCOVERY_LEASE_LOGICAL_OWNER_LOCK_REPLACED')
        generation=private_json(c['generationReceiptPath'])
        fields={'schema','configurationHash','desiredProfileHash','scopePolicyHash','scopeHash','generationRef',
            'bootId','nativeObservationHash','nativeProfileHash','ledgerRoot','state','containerStartAuthorized'}
        require(set(generation)==fields and generation['schema']=='ouf.discovery-operational-lease-generation-receipt.v1'
            and generation['configurationHash']==self.sha and generation['desiredProfileHash']==c['desiredProfileHash']
            and generation['scopePolicyHash']==c['scopePolicyHash'] and generation['scopeHash']==scope_hash
            and generation['generationRef']==generation_ref and generation['ledgerRoot']==c['ledgerRoot']
            and generation['state']=='NATIVE_GENERATION_ADMITTED' and generation['containerStartAuthorized'] is False
            and all(type(generation[k]) is str and re.fullmatch('[0-9a-f]{64}',generation[k])
                for k in ('scopeHash','generationRef','nativeObservationHash','nativeProfileHash')),
            'EXACT_CURRENT_OPERATIONAL_LEASE_GENERATION_RECEIPT_REQUIRED')
        self.signature(generation)
        boot=boot_id(c['hostBootIdPath'])
        require(boot==generation['bootId'],'OPERATIONAL_LEASE_CURRENT_BOOT_REQUIRED')
        observed=self.probe(copy.deepcopy(generation))
        require(type(observed) is dict and set(observed)=={'nativeObservationHash','nativeProfileHash','generationRef','bootId'}
            and all(observed[k]==generation[k] for k in observed),
            'CURRENT_INDEPENDENT_NATIVE_LEASE_GENERATION_REQUIRED')
        self.metadata_guard()
        require(private_json(c['generationReceiptPath'])==generation,'OPERATIONAL_LEASE_GENERATION_RECEIPT_CHANGED')
        return True
