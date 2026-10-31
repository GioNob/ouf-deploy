"""Independent bounded installed-worker observation. No manager/kernel writes.

The phase owner must separately verify its parent node/provider admission. This
reader proves the installed worker and positive owned leases, never application
readiness, OCI admission or permission to start/replay an action.
"""
import importlib,os,re,stat,subprocess,time
from pathlib import Path
from .custody_capture import encoded,digest,require
from .lease_capsule import PINS
from .lease_service import build_installed
from .installed_lease_guard import boot_id
from .native_generation_probe import ticks
from tools.semantic_registry_operational_owner.guard import protected_file,private_json
from tools.semantic_provider_deployment_authentication import ancestors

PROPERTIES={'LoadState','ActiveState','SubState','MainPID','FragmentPath','DropInPaths',
    'NeedDaemonReload','User','Group','NoNewPrivileges','CapabilityBoundingSet','AmbientCapabilities','RootDirectory'}

# Only this finite public vocabulary may leave the privileged reader. Exception
# messages from a process, file or imported guard can contain private values.
DENIAL_CODES=frozenset({
    'BOUNDED_DISCOVERY_WORKER_OBSERVATION_REQUIRED',
    'ROOT_BOUNDED_DISCOVERY_WORKER_OBSERVATION_REQUIRED',
    'EXACT_DISCOVERY_MANAGER_READER_REQUIRED',
    'DISCOVERY_WORKER_OBSERVATION_DEADLINE_MISSED',
    'BOUNDED_DISCOVERY_MANAGER_READBACK_REQUIRED',
    'EXACT_DISCOVERY_MANAGER_PROPERTY_RECORD_REQUIRED',
    'EXACT_DISCOVERY_MANAGER_PROPERTIES_REQUIRED',
    'EXACT_RUNNING_DISCOVERY_MANAGER_CONFIGURATION_REQUIRED',
    'BOUNDED_DISCOVERY_WORKER_ARGUMENTS_REQUIRED',
    'EXACT_DISCOVERY_WORKER_PROCESS_ARGUMENTS_REQUIRED',
    'EXACT_DISCOVERY_WORKER_PROCESS_EXECUTABLE_REQUIRED',
    'BOUNDED_DISCOVERY_WORKER_PROCESS_STATUS_REQUIRED',
    'EXACT_DISCOVERY_WORKER_PROCESS_CAPABILITIES_REQUIRED',
    'EXACT_DISCOVERY_WORKER_PROCESS_ROOT_CONFIGURATION_REQUIRED',
    'EXACT_DISCOVERY_WORKER_PROCESS_ROOT_REQUIRED',
    'POSITIVE_DISCOVERY_WORKER_CHECKPOINT_REQUIRED',
    'CURRENT_SIGNED_DISCOVERY_WORKER_GENERATION_REQUIRED',
    'CURRENT_NATIVE_DISCOVERY_WORKER_GENERATION_REQUIRED',
    'CURRENT_OWNED_DISCOVERY_LEASE_PUBLICATION_REQUIRED',
    'CURRENT_TWO_FAMILY_DISCOVERY_LEASE_REQUIRED',
    'DISCOVERY_LEASE_CHANGED_DURING_OBSERVATION',
    'DISCOVERY_WORKER_CHANGED_DURING_OBSERVATION',
    'CURRENT_DISCOVERY_KERNEL_LOCK_INODE_REQUIRED',
    'DISCOVERY_KERNEL_LOCK_REPLACED',
})


def failure(error):
    """Safe UNKNOWN diagnostics; no probe, retry, evidence or native effect."""
    if isinstance(error,subprocess.SubprocessError):kind='PROCESS_READ_UNPROVEN'
    elif isinstance(error,BlockingIOError):kind='READ_CONTENTION'
    elif isinstance(error,OSError):kind='IO_READ_UNPROVEN'
    elif isinstance(error,ValueError):kind='READ_DENIED'
    else:kind='READ_UNPROVEN'
    # Inspect only an exact string argument, never arbitrary __str__, paths,
    # errno, stdout/stderr or an exception subclass's custom representation.
    reason=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
    return {'schema':'ouf.discovery-worker-observation-failure.v1','kind':kind,
        'reasonCode':reason if reason in DENIAL_CODES else 'DISCOVERY_WORKER_OBSERVATION_UNPROVEN'}


def preload_runtime():
    # The parent uses the same reviewed runtime modules. No ambient substitute
    # can satisfy the private installed manifest's executing-code checks.
    for name in sorted(PINS):importlib.import_module(name)


def publication_snapshot(coordinator,path,identity):
    """Read a stable positive publication without taking the writer's lock.

    The worker deliberately uses nonblocking exclusive acquisition. A reader
    taking that same lock can force its renewal AND safe revocation to fail.
    Authenticate the approved inode without flock, and reject an incomplete or
    changing publication. This performs no retry, DNS, kernel or journal write.
    """
    path=Path(path);ancestors(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    def attributes(s):return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink]
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0
            and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1
            and type(identity) is list and len(identity)==6
            and attributes(s)==identity==attributes(path.lstat()),
            'CURRENT_DISCOVERY_KERNEL_LOCK_INODE_REQUIRED')
        coordination=coordinator.journal();coordinator.owner.backend.verify_ownership(coordinator.configuration)
        values=coordinator.owner.backend.read_sets(coordinator.configuration)
        flows=coordinator.configuration['providerFlows']
        require(coordination['state']=='LEASE_READY' and coordination['leaseAuthorized'] is True
            and set(values)=={(f,i) for f in ('inet','bridge') for i in range(len(flows))},
            'CURRENT_OWNED_DISCOVERY_LEASE_PUBLICATION_REQUIRED')
        for i in range(len(flows)):
            left,right=values['inet',i],values['bridge',i]
            require(left and right and set(left)==set(right)
                and set(left)<=set(coordination['leaseAddresses'][i]),'CURRENT_TWO_FAMILY_DISCOVERY_LEASE_REQUIRED')
        coordinator.owner.backend.verify_ownership(coordinator.configuration)
        require(coordinator.journal()==coordination,'DISCOVERY_LEASE_CHANGED_DURING_OBSERVATION')
        require(attributes(os.fstat(fd))==identity==attributes(path.lstat()),'DISCOVERY_KERNEL_LOCK_REPLACED')
    finally:os.close(fd)


def observe(configuration_path,anchor,*,unit_name,systemctl,seconds=15):
    require(type(seconds) is int and 1<=seconds<=30,'BOUNDED_DISCOVERY_WORKER_OBSERVATION_REQUIRED')
    deadline=time.monotonic()+seconds
    for attempt in range(3):
        try:return _observe(configuration_path,anchor,unit_name=unit_name,systemctl=systemctl,deadline=deadline)
        except BlockingIOError:
            if attempt==2 or deadline-time.monotonic()<=.05:raise
            # Short journal/kernel-lock contention is read-only reconciliation,
            # never permission to start a process or republish an earlier lease.
            time.sleep(.02*(attempt+1))


def _observe(configuration_path,anchor,*,unit_name,systemctl,deadline):
    require(os.geteuid()==os.getegid()==0
        and type(unit_name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,100}[.]service',unit_name),
        'ROOT_BOUNDED_DISCOVERY_WORKER_OBSERVATION_REQUIRED')
    require(type(systemctl) is dict and set(systemctl)=={'path','sha256','maximumBytes'}
        and type(systemctl['maximumBytes']) is int and 1<=systemctl['maximumBytes']<=67108864,
        'EXACT_DISCOVERY_MANAGER_READER_REQUIRED')
    def remaining(maximum):
        value=deadline-time.monotonic();require(value>0,'DISCOVERY_WORKER_OBSERVATION_DEADLINE_MISSED')
        return min(maximum,value)
    def manager():
        protected_file(systemctl['path'],systemctl['maximumBytes'],expected=systemctl['sha256'],modes=(0o755,))
        result=subprocess.run([systemctl['path'],'show',unit_name,'--no-pager','--property='+','.join(sorted(PROPERTIES))],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=remaining(5),
            env={'PATH':'/usr/bin:/usr/sbin:/bin','LC_ALL':'C'})
        require(result.returncode==0 and 0<len(result.stdout)<=16384,'BOUNDED_DISCOVERY_MANAGER_READBACK_REQUIRED')
        lines=result.stdout.decode('ascii').splitlines();pairs=[line.split('=',1) for line in lines]
        require(all(len(pair)==2 for pair in pairs),'EXACT_DISCOVERY_MANAGER_PROPERTY_RECORD_REQUIRED')
        values=dict(pairs)
        require(len(values)==len(pairs) and set(values)==PROPERTIES,'EXACT_DISCOVERY_MANAGER_PROPERTIES_REQUIRED')
        return values
    preload_runtime();worker,guard,scope=build_installed(configuration_path,anchor);c=guard.configuration
    before=manager()
    require(before['LoadState']=='loaded' and before['ActiveState']=='active' and before['SubState']=='running'
        and before['MainPID'].isdigit() and int(before['MainPID'])>1
        and Path(before['FragmentPath']).resolve()==Path(c['serviceUnitPath'])
        and before['DropInPaths']=='' and before['NeedDaemonReload']=='no'
        and before['User']==before['Group']=='root' and before['NoNewPrivileges']=='yes'
        and before['CapabilityBoundingSet']==before['AmbientCapabilities']=='cap_net_admin',
        'EXACT_RUNNING_DISCOVERY_MANAGER_CONFIGURATION_REQUIRED')
    pid=int(before['MainPID']);proc=Path('/proc')/str(pid)
    process_ticks=ticks(pid)
    # These are host-side metadata reads by the privileged phase owner, not
    # extra procfs mounts or privileges granted to the worker.
    with (proc/'cmdline').open('rb') as stream:raw=stream.read(16385)
    require(0<len(raw)<=16384,'BOUNDED_DISCOVERY_WORKER_ARGUMENTS_REQUIRED')
    argv=raw.rstrip(b'\0').split(b'\0')
    install=Path(configuration_path).parent
    expected=[b'-I',b'-B',b'-S',str(install/'capsule.py').encode(),b'worker',b'--configuration',
        str(configuration_path).encode(),b'--configuration-anchor',anchor.encode()]
    require(argv[1:]==expected,'EXACT_DISCOVERY_WORKER_PROCESS_ARGUMENTS_REQUIRED')
    source=next(v for v in c['sources'] if v['path']==os.fsdecode(argv[0]))
    protected_file(source['path'],source['maximumBytes'],expected=source['sha256'],modes=(0o755,))
    actual=(proc/'exe').stat();approved=Path(source['path']).stat()
    require((actual.st_dev,actual.st_ino)==(approved.st_dev,approved.st_ino),
        'EXACT_DISCOVERY_WORKER_PROCESS_EXECUTABLE_REQUIRED')
    with (proc/'status').open('rb') as stream:raw_status=stream.read(65537)
    require(0<len(raw_status)<=65536,'BOUNDED_DISCOVERY_WORKER_PROCESS_STATUS_REQUIRED')
    process={k:v.strip() for k,v in (line.split(':',1) for line in raw_status.decode('ascii').splitlines() if ':' in line)}
    require(all(int(process[k],16)==1<<12 for k in ('CapEff','CapPrm','CapBnd','CapAmb'))
        and process['NoNewPrivs']=='1','EXACT_DISCOVERY_WORKER_PROCESS_CAPABILITIES_REQUIRED')
    unit=protected_file(c['serviceUnitPath'],65536,expected=c['serviceUnitHash'],modes=(0o644,0o600)).decode('ascii')
    roots=[line.split('=',1)[1] for line in unit.splitlines() if line.startswith('RootDirectory=')]
    require(roots==[before['RootDirectory']],'EXACT_DISCOVERY_WORKER_PROCESS_ROOT_CONFIGURATION_REQUIRED')
    actual_root=(proc/'root').stat();approved_root=Path(roots[0]).stat()
    require((actual_root.st_dev,actual_root.st_ino)==(approved_root.st_dev,approved_root.st_ino),
        'EXACT_DISCOVERY_WORKER_PROCESS_ROOT_REQUIRED')
    record=worker.r.journal.read()
    require(record['state']=='ACTIVE','POSITIVE_DISCOVERY_WORKER_CHECKPOINT_REQUIRED')
    generation=private_json(c['generationReceiptPath'])
    require(set(generation)=={'schema','configurationHash','desiredProfileHash','scopePolicyHash','scopeHash','generationRef',
        'bootId','nativeObservationHash','nativeProfileHash','ledgerRoot','state','containerStartAuthorized'}
        and generation['schema']=='ouf.discovery-operational-lease-generation-receipt.v1'
        and generation['configurationHash']==guard.sha and generation['desiredProfileHash']==c['desiredProfileHash']
        and generation['scopePolicyHash']==c['scopePolicyHash'] and generation['scopeHash']==digest(scope)
        and generation['generationRef']==scope['generationRef'] and generation['ledgerRoot']==c['ledgerRoot']
        and generation['state']=='NATIVE_GENERATION_ADMITTED' and generation['containerStartAuthorized'] is False
        and generation['bootId']==boot_id('/proc/sys/kernel/random/boot_id'),
        'CURRENT_SIGNED_DISCOVERY_WORKER_GENERATION_REQUIRED')
    guard.signature(generation);observed=guard.probe(generation)
    require(all(observed[k]==generation[k] for k in ('nativeObservationHash','nativeProfileHash','generationRef','bootId')),
        'CURRENT_NATIVE_DISCOVERY_WORKER_GENERATION_REQUIRED')
    recipe_path=Path(configuration_path).parent/'worker-recipe.json'
    reference=next(v for v in c['sources'] if v['path']==str(recipe_path))
    recipe=private_json(recipe_path,reference['sha256'])
    publication_snapshot(worker.c,recipe['leaseCommonLock'],recipe['leaseCommonLockIdentity'])
    after_record=worker.r.journal.read();guard.metadata_guard()
    require(after_record['state']=='ACTIVE' and all(after_record[k]==record[k] for k in
        ('contextRef','generationRef','policyHash','discoveryLeaseScopeHash','startedWall','startedMonotonic'))
        and after_record['attempts']>=record['attempts'] and after_record['publicationCount']>=record['publicationCount']
        and private_json(c['generationReceiptPath'])==generation and manager()==before and ticks(pid)==process_ticks,
        'DISCOVERY_WORKER_CHANGED_DURING_OBSERVATION')
    remaining(1)
    return {'schema':'ouf.discovery-installed-lease-observation.v1','configurationHash':guard.sha,
        'scopeHash':digest(scope),'generationRef':scope['generationRef'],'managerProcessId':pid,
        'managerProcessRunning':True,'workerCheckpointActive':True,'bothOwnedLeaseFamiliesPositive':True,
        'recoveryAttempts':after_record['attempts'],'publications':after_record['publicationCount'],
        'runtimeAuthorityIssued':False,'applicationReady':False,'containerStartAuthorized':False,'releaseAcceptance':False}
