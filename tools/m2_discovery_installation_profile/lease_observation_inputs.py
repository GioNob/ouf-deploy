"""Host-only installed inputs; never acquire the worker recovery/CAS lock.

The frozen service factory builds a runnable worker and reads through its
exclusive Journal transaction. An outside observer must instead read a stable
private snapshot. Atomic publication drift consumes the caller's existing read
attempt/deadline; it cannot fail the writer, initialize a ledger or revoke it.
"""
import copy,dataclasses,os,re,stat,time,types
from pathlib import Path
from .custody_capture import digest,require
from .lease_service import configuration_anchor,SERVICE_MODULES,RECIPE_FIELDS
from .installed_lease_guard import InstalledLeaseGuard
from .native_generation_probe import NativeLeaseGenerationProbe
from .discovery_nft_backend import DiscoveryNftBackend
from .lease_worker import DiscoveryRecovery,SCOPE_FIELDS
from bounded_recovery import Policy,fingerprint
from recovery_journal import unique,encoded
from tools.semantic_provider_lease_owner import LeaseOwner
from tools.semantic_provider_lease_coordination import Coordinator,PrivateJournal
from tools.semantic_registry_operational_owner.guard import protected_file,private_json
from tools.semantic_registry_operational_owner.installation import directory
from tools.semantic_registry_operational_owner.store import identity,file_identity
import json

STATES={'NEW','ACTIVE','RETRY_WAIT','PAUSED_EXHAUSTED','BLOCKED','RECONCILE_REQUIRED',
    'CANCELLED','ATTEMPTING','PUBLISHING'}


def no_operation(*args,**kwargs):
    raise ValueError('READ_ONLY_DISCOVERY_OBSERVATION_INPUTS')


class RecoverySnapshot:
    """No transaction, lock, create, CAS, write or lifecycle API."""
    def __init__(self,root,scope,policy):
        self.root=Path(root);self.scope=copy.deepcopy(scope);self.policy=policy
        with directory(self.root) as fd:
            s=os.fstat(fd);self.root_identity=identity(s)
            require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,
                'PRIVATE_OBSERVED_DISCOVERY_RECOVERY_DIRECTORY_REQUIRED')

    def read(self):
        with directory(self.root) as parent:
            require(identity(os.fstat(parent))==self.root_identity,'OBSERVED_DISCOVERY_RECOVERY_DIRECTORY_CHANGED')
            fd=os.open('recovery.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            def custody(s,*,unlinked=False):
                return (stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
                    and s.st_nlink in ((0,1) if unlinked else (1,)) and 0<s.st_size<=65536)
            try:
                before=os.fstat(fd)
                require(custody(before),'PRIVATE_OBSERVED_DISCOVERY_RECOVERY_RECORD_REQUIRED')
                raw=os.read(fd,65537);after=os.fstat(fd)
                named=os.stat('recovery.json',dir_fd=parent,follow_symlinks=False)
                require(custody(after,unlinked=True) and custody(named),
                    'PRIVATE_OBSERVED_DISCOVERY_RECOVERY_RECORD_REQUIRED')
                if (len(raw)!=before.st_size or file_identity(before)!=file_identity(after)
                    or file_identity(after)!=file_identity(named)):
                    raise BlockingIOError('DISCOVERY_RECOVERY_CHANGED_DURING_READ')
            finally:os.close(fd)
            value=json.loads(raw,object_pairs_hook=unique)
            require(type(value) is dict and encoded(value)==raw,'CANONICAL_OBSERVED_DISCOVERY_RECOVERY_REQUIRED')
            s=self.scope
            require(value.get('schema')=='ouf.bounded-recovery.v1'
                and value.get('contextRef')==s['contextRef'] and value.get('generationRef')==s['generationRef']
                and value.get('policyHash')==s['policyHash']
                and value.get('discoveryLeaseScopeHash')==fingerprint(s)
                and value.get('timeAccountingProfile')==DiscoveryRecovery.PROFILE,
                'RETAINED_DISCOVERY_LEASE_SCOPE_AND_ACCOUNTING_REQUIRED')
            require(type(value.get('state')) is str and value['state'] in STATES
                and all(type(value.get(k)) is int and value[k]>=0 for k in ('attempts','publicationCount')),
                'OBSERVED_DISCOVERY_RECOVERY_STATE_AND_COUNTERS_REQUIRED')
            validator=DiscoveryRecovery(None,None,self.policy,s['contextRef'],s['generationRef'],
                lambda:(time.time(),time.monotonic()),lambda:.5)
            validator.validate_time_accounting(value)
            return value


def build_observed(configuration_path,anchor):
    """Static composition, not a worker; recovery validation occurs on read."""
    require(os.geteuid()==os.getegid()==0 and type(anchor) is str
        and re.fullmatch('[0-9a-f]{64}',anchor),'ROOT_ANCHORED_DISCOVERY_LEASE_ENTRY_REQUIRED')
    path=Path(configuration_path);configuration=private_json(path)
    require(configuration_anchor(configuration)==anchor,'DISCOVERY_LEASE_CONFIGURATION_ANCHOR_CHANGED')
    probe=NativeLeaseGenerationProbe(Path(configuration['generationReceiptPath']).parent/'observations')
    guard=InstalledLeaseGuard(path,digest(configuration),generation_probe=probe);c=guard.configuration
    require(SERVICE_MODULES<=set(c['sourceManifest']['sourceHashes']),
        'COMPLETE_EXECUTING_DISCOVERY_LEASE_SERVICE_CLOSURE_REQUIRED')
    recipe_path=path.parent/'worker-recipe.json';refs=[v for v in c['sources'] if v['path']==str(recipe_path)]
    require(len(refs)==1 and 1<=refs[0]['maximumBytes']<=1048576,
        'FIXED_BOUND_INSTALLED_DISCOVERY_LEASE_RECIPE_REQUIRED')
    recipe=private_json(recipe_path,refs[0]['sha256'])
    require(type(recipe) is dict and set(recipe)==RECIPE_FIELDS
        and recipe['schema']=='ouf.discovery-operational-lease-recipe.v1','EXACT_INSTALLED_DISCOVERY_LEASE_RECIPE_REQUIRED')
    scope=copy.deepcopy(recipe['scope']);ledger=Path(c['ledgerRoot'])
    require(recipe['coordinationJournal']==str(ledger/'coordination.json')
        and recipe['leaseCommonLock']!=c['commonInvocationLock'] and Path(recipe['leaseCommonLock']).is_absolute(),
        'DISTINCT_DISCOVERY_LEASE_LEDGER_AND_SHARED_KERNEL_LOCK_REQUIRED')
    nft=recipe['nft']
    require(type(nft) is dict and set(nft)=={'path','sha256','maximumBytes'}
        and type(nft['maximumBytes']) is int and 1<=nft['maximumBytes']<=67108864,
        'EXACT_INSTALLED_DISCOVERY_NFT_PROGRAM_REQUIRED')
    protected_file(nft['path'],nft['maximumBytes'],expected=nft['sha256'],modes=(0o755,))
    backend=DiscoveryNftBackend([nft['path']],recipe['kernel'],scope['leaseStructureHash'],5)
    owner=LeaseOwner(recipe['kernel'],recipe['dns'],backend);coordination=PrivateJournal(ledger/'coordination.json')
    coordinator=Coordinator(owner,recipe['binding'],no_operation,coordination.read,no_operation)
    policy=copy.deepcopy(recipe['policy'])
    require(type(policy) is dict and type(policy.get('delays')) is list,'EXACT_DISCOVERY_SERVICE_RETRY_POLICY_REQUIRED')
    policy['delays']=tuple(policy['delays']);policy=Policy(**policy)
    require(type(scope) is dict and set(scope)==SCOPE_FIELDS
        and all(type(scope[k]) is str and re.fullmatch('[0-9a-f]{64}',scope[k])
            for k in SCOPE_FIELDS-{'pollSeconds','heartbeatSeconds'})
        and type(scope['pollSeconds']) is int and 1<=scope['pollSeconds']<=300
        and type(scope['heartbeatSeconds']) is int and 1<=scope['heartbeatSeconds']<=30,
        'EXACT_SEALED_DISCOVERY_LEASE_WORKER_INPUTS_REQUIRED')
    require(scope['sourceClosureHash']==c['sourceManifest']['dependencyClosureHash']
        and scope['installationInputsHash']==c['installationInputsHash']
        and scope['policyHash']==c['scopePolicyHash']==fingerprint(dataclasses.asdict(policy)),
        'EXACT_INSTALLED_DISCOVERY_SERVICE_SCOPE_REQUIRED')
    require(fingerprint(coordinator.binding)==scope['coordinatorBindingHash']
        and fingerprint(coordinator.configuration)==scope['configurationHash']
        and fingerprint(owner.profile)==scope['dnsProfileHash'] and backend.expected==scope['leaseStructureHash'],
        'DISCOVERY_LEASE_WORKER_OWNER_OR_POLICY_DRIFT')
    snapshot=RecoverySnapshot(ledger,scope,policy)
    return types.SimpleNamespace(c=coordinator,r=types.SimpleNamespace(journal=snapshot)),guard,scope
