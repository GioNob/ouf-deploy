"""Foreground installed discovery lease entry; never installs or starts peers.

Only the exact signed installation, its fixed bound recipe and an existing
distinct ledger are accepted. The manager's independent configuration anchor
omits serviceUnitHash to avoid a unit/configuration hash dependency cycle.
"""
import copy,dataclasses,os,re,signal,threading
from pathlib import Path
import dns,readback_margin_compiler
from deadline_backend import DeadlineNftBackend
from bounded_recovery import Policy,fingerprint
from recovery_journal import Journal
from tools.semantic_provider_lease_owner import LeaseOwner
from tools.semantic_provider_lease_coordination import Coordinator,PrivateJournal,hold_common_lock
from tools.semantic_registry_operational_owner.guard import private_json,protected_file
from .custody_capture import digest,encoded,require
from .installed_lease_guard import CONFIG_FIELDS,InstalledLeaseGuard
from .native_generation_probe import NativeLeaseGenerationProbe
from .installed_lease_session import serve_installed
from .lease_worker import build_worker,LeaseReporter

MODULE='tools.m2_discovery_installation_profile.lease_service'
SERVICE_MODULES={MODULE,'tools.m2_discovery_installation_profile.installed_lease_session',
    'dns','readback_margin_compiler','deadline_backend','nft_seconds_backend',
    'bounded_recovery','recovery_journal','lease_recovery_budget','continuous_supervisor',
    'resilient_lease_adapter','adaptive_supervisor','tools.semantic_provider_lease_owner',
    'tools.semantic_provider_lease_coordination','tools.semantic_provider_dns',
    'tools.materialize_southbound_kernel','tools.materialize_southbound_lease_refresh'}
RECIPE_FIELDS={'schema','kernel','dns','binding','policy','scope','nft','coordinationJournal','leaseCommonLock'}


def configuration_anchor(configuration):
    require(type(configuration) is dict and set(configuration)==CONFIG_FIELDS
        and configuration['schema']=='ouf.discovery-operational-lease-configuration.v1',
        'EXACT_ANCHORED_DISCOVERY_LEASE_CONFIGURATION_REQUIRED')
    return digest({k:v for k,v in configuration.items() if k!='serviceUnitHash'})


def build_installed(configuration_path,anchor):
    """Read/compose only. No journal initialization, DNS, nft or lifecycle call."""
    require(os.geteuid()==os.getegid()==0 and type(anchor) is str
        and re.fullmatch('[0-9a-f]{64}',anchor),'ROOT_ANCHORED_DISCOVERY_LEASE_ENTRY_REQUIRED')
    path=Path(configuration_path);configuration=private_json(path)
    require(configuration_anchor(configuration)==anchor,'DISCOVERY_LEASE_CONFIGURATION_ANCHOR_CHANGED')
    probe=NativeLeaseGenerationProbe(Path(configuration['generationReceiptPath']).parent/'observations')
    guard=InstalledLeaseGuard(path,digest(configuration),generation_probe=probe)
    c=guard.configuration
    require(SERVICE_MODULES<=set(c['sourceManifest']['sourceHashes']),
        'COMPLETE_EXECUTING_DISCOVERY_LEASE_SERVICE_CLOSURE_REQUIRED')
    recipe_path=path.parent/'worker-recipe.json'
    refs=[v for v in c['sources'] if v['path']==str(recipe_path)]
    require(len(refs)==1 and 1<=refs[0]['maximumBytes']<=1048576,
        'FIXED_BOUND_INSTALLED_DISCOVERY_LEASE_RECIPE_REQUIRED')
    recipe=private_json(recipe_path,refs[0]['sha256'])
    require(type(recipe) is dict and set(recipe)==RECIPE_FIELDS
        and recipe['schema']=='ouf.discovery-operational-lease-recipe.v1',
        'EXACT_INSTALLED_DISCOVERY_LEASE_RECIPE_REQUIRED')
    scope=copy.deepcopy(recipe['scope']);ledger=Path(c['ledgerRoot'])
    require(recipe['coordinationJournal']==str(ledger/'coordination.json')
        and recipe['leaseCommonLock']!=c['commonInvocationLock']
        and Path(recipe['leaseCommonLock']).is_absolute(),
        'DISTINCT_DISCOVERY_LEASE_LEDGER_AND_SHARED_KERNEL_LOCK_REQUIRED')
    nft=recipe['nft']
    require(type(nft) is dict and set(nft)=={'path','sha256','maximumBytes'}
        and type(nft['maximumBytes']) is int and 1<=nft['maximumBytes']<=67108864,
        'EXACT_INSTALLED_DISCOVERY_NFT_PROGRAM_REQUIRED')
    def program():
        protected_file(nft['path'],nft['maximumBytes'],expected=nft['sha256'],modes=(0o755,))
    program()
    backend=DeadlineNftBackend([nft['path']],recipe['kernel'],scope['leaseStructureHash'],5)
    owner=LeaseOwner(recipe['kernel'],recipe['dns'],backend)
    coordination=PrivateJournal(ledger/'coordination.json')
    coordinator=Coordinator(owner,recipe['binding'],lambda:hold_common_lock(Path(recipe['leaseCommonLock'])),
        coordination.read,coordination.write)
    policy=copy.deepcopy(recipe['policy'])
    require(type(policy) is dict and type(policy.get('delays')) is list,'EXACT_DISCOVERY_SERVICE_RETRY_POLICY_REQUIRED')
    policy['delays']=tuple(policy['delays']);policy=Policy(**policy)
    journal=Journal(ledger)
    require(scope['sourceClosureHash']==c['sourceManifest']['dependencyClosureHash']
        and scope['installationInputsHash']==c['installationInputsHash']
        and scope['policyHash']==c['scopePolicyHash']==fingerprint(dataclasses.asdict(policy)),
        'EXACT_INSTALLED_DISCOVERY_SERVICE_SCOPE_REQUIRED')
    recipe_hash=digest(recipe)
    def local():
        require(private_json(recipe_path,refs[0]['sha256'])==recipe and digest(recipe)==recipe_hash,
            'INSTALLED_DISCOVERY_SERVICE_RECIPE_CHANGED')
        program()
    def runtime(scope_hash):
        local();return guard.current(scope_hash,scope['generationRef'])
    def generation(reference):
        local();return reference==scope['generationRef']
    def custody(configuration_hash,structure_hash):
        local()
        require(configuration_hash==scope['configurationHash'] and structure_hash==scope['leaseStructureHash'],
            'INSTALLED_DISCOVERY_KERNEL_CUSTODY_CHANGED')
        return True
    worker=build_worker(coordinator,journal,policy,scope,runtime_guard=runtime,
        generation_guard=generation,custody_guard=custody,dns=dns,compiler=readback_margin_compiler)
    return worker,guard,scope


def run(configuration_path,anchor,emit=print):
    worker,guard,scope=build_installed(configuration_path,anchor)
    stop=threading.Event();handlers={}
    def output(value):emit(value,flush=True)
    reporter=LeaseReporter(worker.r.journal,output)
    try:
        for sig in (signal.SIGTERM,signal.SIGINT):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
        return serve_installed(worker,guard,scope,stop,reporter)
    finally:
        for sig,handler in handlers.items():signal.signal(sig,handler)


def execute(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='Installed OUF discovery lease worker')
    parser.add_argument('--configuration',required=True)
    parser.add_argument('--configuration-anchor',required=True)
    args=parser.parse_args(argv)
    try:
        run(args.configuration,args.configuration_anchor)
        return 0
    except (Exception,KeyboardInterrupt):
        # Never expose native configuration, endpoints, credentials or raw errors.
        print(encoded({'schema':'ouf.discovery-operational-lease-exit.v1','status':'STOP_RECONCILE',
            'reasonCode':'LOCAL_INSTALLED_DISCOVERY_LEASE_OUTCOME_UNPROVEN','automaticReplayAllowed':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}).decode(),flush=True)
        return 2


if __name__=='__main__':raise SystemExit(execute())
