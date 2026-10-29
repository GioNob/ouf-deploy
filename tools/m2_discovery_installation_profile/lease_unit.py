"""Pure generation-bound service compiler. No filesystem writes or authority.

No API filesystem is mounted: only the three approved process stat files and
the two Docker network namespace bind points are visible. Avoid settings that
implicitly mount a complete procfs. Native sandbox qualification is separate.
"""
import copy,hashlib,re
from pathlib import PurePosixPath as Path
from .custody_capture import digest,require
from .lease_service import configuration_anchor,RECIPE_FIELDS
from .native_generation_probe import generation_reference


def path(value):
    require(type(value) is str and re.fullmatch('/[A-Za-z0-9_./-]+',value)
        and '..' not in Path(value).parts and str(Path(value))==value and value!='/',
        'EXACT_DISCOVERY_SERVICE_BOUND_PATH_REQUIRED')
    return value


def beneath(value,parent):
    return value==parent or Path(parent) in Path(value).parents


def compile_unit(configuration,recipe,snapshot,python,*,installation_root,signing_key_paths,engine_unit='docker.service'):
    """Initial generation sandbox; new boot/peer identity requires new admission."""
    c=copy.deepcopy(configuration);r=copy.deepcopy(recipe);s=copy.deepcopy(snapshot)
    require(type(engine_unit) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,100}[.]service',engine_unit),
        'EXACT_DISCOVERY_ENGINE_MANAGER_UNIT_REQUIRED')
    anchor=configuration_anchor(c);install=path(installation_root);ledger=path(c['ledgerRoot'])
    require(len(Path(install).parts)>=4 and len(Path(ledger).parts)>=4
        and not beneath(ledger,install) and not beneath(install,ledger),
        'DISJOINT_INSTALLED_DISCOVERY_CODE_AND_LEDGER_REQUIRED')
    require(type(r) is dict and set(r)==RECIPE_FIELDS and r['schema']=='ouf.discovery-operational-lease-recipe.v1'
        and r['coordinationJournal']==ledger+'/coordination.json',
        'EXACT_DISCOVERY_SERVICE_UNIT_RECIPE_REQUIRED')
    require(c['generationReceiptPath']==install+'/current-generation.json'
        and c['hostBootIdPath']==install+'/host-boot-id'
        and path(c['commonInvocationLock'])!=path(r['leaseCommonLock'])
        and all(len(Path(path(p)).parts)>=4 and p.endswith('.lock')
            for p in (c['commonInvocationLock'],r['leaseCommonLock']))
        and path(c['serviceUnitPath']).endswith('.service'),
        'FIXED_DISTINCT_DISCOVERY_SERVICE_PATHS_REQUIRED')
    refs={path(v['path']):v for v in c['sources']}
    require(len(refs)==len(c['sources']) and all(not beneath(p,ledger) for p in refs),
        'UNIQUE_READ_ONLY_DISCOVERY_SOURCE_BINDINGS_REQUIRED')
    for p in (install+'/capsule.py',install+'/worker-recipe.json'):
        require(p in refs,'EXACT_DISCOVERY_CAPSULE_AND_RECIPE_BINDINGS_REQUIRED')
    require(refs[install+'/worker-recipe.json']['sha256']==digest(r),
        'DISCOVERY_SERVICE_RECIPE_BINDING_CHANGED')
    require(type(python) is dict and set(python)=={'path','sha256','maximumBytes'}
        and re.fullmatch('/usr/bin/python3(?:[.][0-9]+)?',path(python['path'])),
        'EXACT_DISCOVERY_SYSTEM_PYTHON_REQUIRED')
    for program in (python,r['nft'],c['verification']['openssl']):
        p=path(program['path'])
        require(p.startswith('/usr/') and not p.startswith('/usr/local/')
            and p in refs and refs[p]['sha256']==program['sha256'],
            'REVIEWED_DISCOVERY_EXECUTABLE_BINDING_REQUIRED')
    scope=r['scope']
    require(type(s) is dict and s.get('schema')=='ouf.discovery-lease-generation-observation.v1'
        and s.get('desiredProfileHash')==c['desiredProfileHash']
        and set(s.get('peers',{}))=={'registry','provider'}
        and set(s.get('profiles',{}))=={'registry','provider'}
        and s.get('nativeProfileHash')==digest(s['profiles'])
        and s.get('generationRef')==scope['generationRef']==generation_reference(s),
        'EXACT_ADMITTED_DISCOVERY_SERVICE_GENERATION_REQUIRED')
    engine=s['engineBinding'];socket=path(engine['socketPath'])
    require(socket in ('/run/docker.sock','/var/run/docker.sock')
        and type(engine.get('peerCredentials')) is list and len(engine['peerCredentials'])==3
        and engine['peerCredentials'][1:]==[0,0],
        'EXACT_DISCOVERY_SERVICE_ENGINE_BINDING_REQUIRED')
    pids=[engine['peerCredentials'][0]]+[s['peers'][role]['pid'] for role in ('registry','provider')]
    require(len(set(pids))==3 and all(type(pid) is int and 1<pid<2147483647 for pid in pids),
        'THREE_DISTINCT_DISCOVERY_STAT_PROCESSES_REQUIRED')
    stats=sorted('/proc/'+str(pid)+'/stat' for pid in pids)
    namespaces=[]
    for role in ('registry','provider'):
        ns=s['peers'][role]['namespace'];p=path(ns['path'])
        require(re.fullmatch('/run/docker/netns/[A-Za-z0-9_-]+',p)
            and type(ns.get('identity')) is list and len(ns['identity'])==2
            and all(type(v) is int and v>0 for v in ns['identity']),
            'EXACT_DISCOVERY_SERVICE_NAMESPACE_BINDING_REQUIRED')
        namespaces.append(p)
    require(len(set(namespaces))==2,'DISTINCT_DISCOVERY_SERVICE_PEER_NAMESPACES_REQUIRED')
    signatures=install+'/receipt-signatures';observations=install+'/observations'
    directories={'/usr/lib','/lib','/usr/lib64','/lib64',signatures,observations}
    readonly=set(refs)|{install+'/configuration.json',install+'/installed.json',install+'/current-generation.json',
        signatures,observations,path(c['verification']['trustPolicy']['path']),path(c['serviceUnitPath']),
        path(c['commonInvocationLock']),socket,*stats,*namespaces,'/etc/ld.so.cache','/etc/passwd','/etc/group',
        '/etc/nsswitch.conf',*directories}
    writable={ledger,path(r['leaseCommonLock'])}
    require(not readonly.intersection(writable),'DISCOVERY_READ_ONLY_AND_WRITE_BINDINGS_OVERLAP')
    require(type(signing_key_paths) is list and 1<=len(signing_key_paths)<=64,
        'EXPLICIT_DISCOVERY_SIGNING_KEY_ISOLATION_INPUTS_REQUIRED')
    mounted=readonly|writable
    for key in signing_key_paths:
        key=path(key)
        require(not any(beneath(key,p) for p in mounted),
            'DISCOVERY_SIGNING_KEY_WOULD_BE_EXPOSED')
    optional={'/lib64','/usr/lib64'}
    ro=[('-' if p in optional else '')+p+':'+p+':norbind' for p in sorted(readonly)]
    ro.append('/proc/sys/kernel/random/boot_id:'+c['hostBootIdPath']+':norbind')
    rw=[p+':'+p+':norbind' for p in sorted(writable)]
    executables=sorted({python['path'],r['nft']['path'],c['verification']['openssl']['path'],
        '/usr/lib','/lib','/usr/lib64','/lib64'})
    lines=['[Unit]','Description=OUF installed discovery finite lease worker','After=network-online.target '+engine_unit,
        'Wants=network-online.target','BindsTo='+engine_unit,'StartLimitIntervalSec=300','StartLimitBurst=3','',
        '[Service]','Type=simple','User=root','Group=root','RootDirectory='+install+'/sandbox',
        'ExecStart=:'+python['path']+' -I -B -S '+install+'/capsule.py worker --configuration '+install+
        '/configuration.json --configuration-anchor '+anchor,
        'Restart=on-failure','RestartSec=15','TimeoutStopSec=45','KillMode=control-group','UMask=0077',
        'NoNewPrivileges=yes','CapabilityBoundingSet=CAP_NET_ADMIN','AmbientCapabilities=CAP_NET_ADMIN',
        'MountAPIVFS=no','ProtectSystem=strict','ProtectHome=yes','PrivateDevices=yes','PrivateTmp=yes',
        'LockPersonality=yes','MemoryDenyWriteExecute=yes','RestrictRealtime=yes','RestrictSUIDSGID=yes',
        'RestrictNamespaces=yes','RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK',
        'SystemCallArchitectures=native','SystemCallFilter=@system-service',
        'SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd mount umount2 setns unshare',
        'BindReadOnlyPaths='+' '.join(ro),'BindPaths='+' '.join(rw),
        'ReadWritePaths='+' '.join('+'+p for p in sorted(writable)),
        'NoExecPaths=/','ExecPaths='+' '.join('+'+p for p in executables),
        'Environment=PATH=/usr/bin:/usr/sbin:/bin LC_ALL=C OPENSSL_CONF=/dev/null',
        'UnsetEnvironment=PYTHONPATH PYTHONHOME PYTHONSTARTUP SSLKEYLOGFILE SSL_CERT_FILE SSL_CERT_DIR HTTP_PROXY HTTPS_PROXY ALL_PROXY',
        'StandardInput=null','StandardOutput=journal','StandardError=journal','LimitNOFILE=256','TasksMax=32','',
        '[Install]','WantedBy=multi-user.target','']
    raw='\n'.join(lines).encode('ascii')
    return {'schema':'ouf.discovery-lease-service-unit-proposal.v1','unitBody':raw.decode(),
        'unitSha256':hashlib.sha256(raw).hexdigest(),'configurationAnchor':anchor,
        'generationRef':s['generationRef'],'engineUnit':engine_unit,'processStatPaths':stats,'readOnlyBindings':sorted(readonly),
        'readWriteBindings':sorted(writable),'sourceManifestHash':digest(c['sourceManifest']),
        'nativeSandboxProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
