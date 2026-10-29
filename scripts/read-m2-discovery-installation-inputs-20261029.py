#!/usr/bin/env python3
"""Finite installation reference inventory. No configuration/credential content or effects."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
from urllib.parse import urlsplit
MAXIMUMS={'engineGets':9,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
class Stop(Exception):
    pass

def require(value, code):
    if not value:
        raise Stop(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'DUPLICATE_PRIVATE_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_PRIVATE_JSON')))

def frame(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def ancestry(path):
    require(path.is_absolute() and path.resolve() == path and '..' not in path.parts, 'CANONICAL_ROOT_PATH_REQUIRED')
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'PROTECTED_ROOT_ANCESTRY_REQUIRED')

class Capture:
    def __init__(self, root, cohort_size, reconcile=False):
        require(type(cohort_size) is int and 1 <= cohort_size <= 32, 'BOUNDED_CAPTURE_COHORT_REQUIRED')
        require(type(reconcile) is bool, 'EXPLICIT_RECONCILIATION_MODE_REQUIRED')
        self.maximums = {**MAXIMUMS, 'engineGets': 1 + 2*cohort_size,
                         'privateMetadataReads': 5 if reconcile else 3}
        self.root = Path(root)
        ancestry(self.root.parent)
        require(not os.path.lexists(self.root), 'CSV_RECOVERY_CAPTURE_CONSUMED_NO_REPLAY')
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.seals = {}
        self.sync(self.root.parent)
        self.put('claim.json', {'schema': 'ouf.managed-csv-recovery-input-capture-claim.v1', 'maximums': self.maximums,
                               'containerWrites': 0, 'automaticReplayAllowed': False, 'budgetReset': False})

    def sync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def put(self, name, value):
        require(re.fullmatch(r'[a-z0-9-]+\.json', name) is not None, 'CLOSED_CAPTURE_FILENAME_REQUIRED')
        fd = os.open(self.root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(encoded(value)); out.flush(); os.fsync(out.fileno())
        self.sync(self.root)

    def private(self, path, expected=None):
        require(self.counts['privateMetadataReads'] < self.maximums['privateMetadataReads'], 'PRIVATE_CAPTURE_READ_LIMIT')
        self.counts['privateMetadataReads'] += 1
        path = Path(path)
        self.put('private-read-'+str(self.counts['privateMetadataReads'])+'-claim.json', {'path': str(path), 'attemptNotCompletion': True})
        ancestry(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and 0 < before.st_size <= 6*1024*1024, 'SEALED_PRIVATE_CAPTURE_INPUT_REQUIRED')
            raw = b''
            while len(raw) <= before.st_size:
                part = os.read(fd, min(65536, before.st_size+1-len(raw)))
                if not part:
                    break
                raw += part
            require(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd)) == frame(path.lstat()), 'CAPTURE_HISTORY_CHANGED')
            require(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'EXACT_INSTALLED_CAPTURE_HASH_REQUIRED')
            self.counts['bytes'] += len(raw)
            require(self.counts['bytes'] <= MAXIMUMS['totalBytes'], 'PRIVATE_CAPTURE_BYTE_LIMIT')
            value = decode(raw)
            self.seals[str(path)] = {'metadata': list(frame(before)), 'sha256': hashlib.sha256(raw).hexdigest()}
            return value
        finally:
            os.close(fd)

def process_pin(pid):
    require(type(pid) is int and pid >= 1, 'POSITIVE_CAPTURE_PID_REQUIRED')
    raw = Path('/proc/'+str(pid)+'/stat').read_bytes()
    require(0 < len(raw) < 16384 and b') ' in raw, 'BOUNDED_CAPTURE_PROCESS_REQUIRED')
    namespaces = {}
    for name in ('net', 'mnt'):
        info = Path('/proc/'+str(pid)+'/ns/'+name).stat()
        namespaces[name] = [info.st_dev, info.st_ino]
    return {'pid': pid, 'startTicks': int(raw.rsplit(b') ', 1)[1].split()[19]), 'namespaces': namespaces}

def stable_binding(actual):
    return {'containerId': actual['Id'], 'imageId': actual['Image'], 'name': actual['Name'], 'pid': actual['State']['Pid'], 'startedAt': actual['State']['StartedAt'],
            'configHash': digest(actual['Config']), 'hostConfigHash': digest(actual['HostConfig']),
            'mountsHash': digest(sorted(actual['Mounts'], key=lambda v: v['Destination'])), 'networkSettingsHash': digest(actual['NetworkSettings']),
            'profile': 'ouf.acquisition-read.mount-set-binding.v1'}

class Engine:
    def __init__(self, capture, binding, ids):
        self.capture, self.binding = capture, binding
        require(0 < len(ids) <= 32 and len(set(ids)) == len(ids) and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'EXACT_DISTINCT_COHORT_IDS_REQUIRED')
        self.allowed = {'/v1.44/info'} | {'/v1.44/containers/'+cid+'/json' for cid in ids}

    def get(self, path):
        c = self.capture
        require(path in self.allowed and c.counts['engineGets'] < c.maximums['engineGets'], 'CLOSED_READ_ONLY_ENGINE_CAPTURE_REQUIRED')
        selected = Path(self.binding['socketPath']); ancestry(selected.parent)
        info = selected.lstat()
        require(stat.S_ISSOCK(info.st_mode) and [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)] == self.binding['socketBinding'], 'EXACT_CAPTURE_ENGINE_SOCKET_REQUIRED')
        c.counts['engineGets'] += 1
        c.put('engine-get-'+str(c.counts['engineGets'])+'-claim.json', {'method': 'GET', 'path': path, 'attemptNotCompletion': True})
        binding = self.binding
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); conn.sock.settimeout(4); conn.sock.connect(str(selected))
                peer = list(struct.unpack('3i', conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
                require(peer == binding['peerCredentials'] and peer[1] == 0, 'EXACT_CAPTURE_ROOT_ENGINE_PEER_REQUIRED')
        conn = Local('root-local-engine', timeout=4)
        try:
            conn.request('GET', path, headers={'Connection': 'close'})
            response = conn.getresponse(); raw = response.read(MAXIMUMS['responseBytes']+1)
            c.counts['bytes'] += len(raw)
            require(response.status == 200 and 0 < len(raw) <= MAXIMUMS['responseBytes'] and c.counts['bytes'] <= MAXIMUMS['totalBytes'], 'BOUNDED_SUCCESSFUL_ENGINE_CAPTURE_REQUIRED')
            value = decode(raw)
            c.put('engine-get-'+str(c.counts['engineGets'])+'-response.json', value)
            return value
        finally:
            conn.close()

class Logger:
    def __init__(self, path):
        self.original = sys.stdout
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        self.file = os.fdopen(fd, "w", buffering=1)

    def write(self, value):
        self.file.write(value); self.file.flush(); os.fsync(self.file.fileno())
        return self.original.write(value)

    def flush(self):
        self.file.flush(); os.fsync(self.file.fileno()); self.original.flush()

    def isatty(self):
        return self.original.isatty()

    def fileno(self):
        return self.original.fileno()

"""Installation-specific reference inventory; captured metadata is never authority."""
CASE={
 'sourceRoot':'/etc/ouf/deploy-snapshots/m2-discovery-current-bindings-0601fdfa-20261029-v1',
 'sourceInputsHash':'14e42ac96293d342cd71b7386360b976882ac7ec75a18838d3960999430f3a13',
 'sourceResultHash':'a5161311451021f936692274c6ad91cecb7a40ca2e0017da533765905fd0f674',
 'outputRoot':'/etc/ouf/deploy-snapshots/m2-discovery-installation-inputs-14e42ac9-20261029-v1',
 'targets':{
  'mcp':{'containerId':'756f70a813a0a01218b9d9a07d56c01702364b67943181b8cc339be98d96531a','imageId':'sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220','nativeBindingHash':'d5750f01ee879ba43c28d97385ffd835c3e2836a48e6346d6bce5293a4831c19'},
  'semantic':{'containerId':'790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d','imageId':'sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3','nativeBindingHash':'46b5e7dec97ebb90d0cd1b9a7e6c51a377f4449a56f435ae0550441a2bc98180'},
  'gateway-owner':{'containerId':'8daa3d7a4afcffeb39bf8c63c0891abf1679d8ce43880d3f29ff41b3f2f7e6e9','imageId':'sha256:979de5eb0a554e0adfe924969627eb62362c4165974357afcee5bf30450f8f21','nativeBindingHash':'a63036c59e5d62c520bc706b3580bca7b02647610e1e540b2dd860f4671ac220'},
  'apisix':{'containerId':'d36bef2faf3d25c6aaaadd72bfb6ebe0a85b2838ae6bf477a5471f8b68d9d912','imageId':'sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d','nativeBindingHash':'67b344c1d30e10b2458c0e76c8ee7cfdafc2fdf893724529f6a10138881c1555'},
 }}

# Only source-defined NONSECRET reference settings can be disclosed. Passwords,
# tokens, application JSON/JVM option bodies, keys and arbitrary Env are excluded.
REFERENCE_TYPES={
 'MCP_GATEWAY_ENDPOINT':'URI','MCP_GATEWAY_RECOVERY_ENDPOINT':'URI',
 'MCP_AUTHORIZATION_BUNDLE_ENDPOINT':'URI','MCP_OIDC_TOKEN_ENDPOINT':'URI',
 'MCP_OIDC_CLIENT_ID':'IDENTIFIER','MCP_OIDC_CLIENT_SECRET_FILE':'PATH',
 'MCP_FINGERPRINT_KEY_FILE':'PATH','SSL_CERT_FILE':'PATH','SSL_CERT_DIR':'PATH',
 'MCP_REPROCESSING_KEY_PROFILE_FILE':'PATH','MCP_REPROCESSING_PERMIT_FILE':'PATH',
 'MCP_REPROCESSING_EXISTING_POLICY_FILE':'PATH',
 'OUF_SCHEMA_GOV_GATEWAY_BASE_URL':'URI','OUF_SCHEMA_GOV_SEARCH_PATH':'PATH',
 'OUF_SCHEMA_GOV_FETCH_PATH':'PATH','OUF_SCHEMA_GOV_TOKEN_ENDPOINT':'URI',
 'OUF_SCHEMA_GOV_CLIENT_ID':'IDENTIFIER','OUF_SCHEMA_GOV_CLIENT_SECRET_FILE':'PATH',
 'OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'SCOPES','OUF_IAM_ISSUER':'URI','OUF_IAM_AUDIENCE':'IDENTIFIER',
 'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE':'PATH',
 'OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD':'IDENTIFIER',
}
STATE_KEYS=('OUF_SCHEMA_GOV_ENABLED','OUF_DISCOVERY_WORKER_ENABLED',
            'OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED','OUF_IAM_ENABLED')
OVERRIDE_KEYS=('SPRING_APPLICATION_JSON','SPRING_CONFIG_IMPORT','JAVA_TOOL_OPTIONS',
               'JDK_JAVA_OPTIONS','_JAVA_OPTIONS','JAVA_OPTS')


def safe_reference(value,kind):
    if type(value) is not str or not 0<len(value)<=2048 or any(ord(ch)<32 or ord(ch)==127 for ch in value):
        return None
    if kind=='PATH':
        if (value.startswith('/') and value!='/' and '//' not in value and not value.endswith('/')
            and not set(value.split('/'))&{'.','..'} and re.fullmatch(r'/[A-Za-z0-9_./@:+-]+',value)):
            return value
    elif kind=='IDENTIFIER':
        if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}',value):return value
    elif kind=='SCOPES':
        if len(value)<=1024 and re.fullmatch(r'[A-Za-z0-9._:-]+( [A-Za-z0-9._:-]+)*',value):return value
    elif kind=='URI':
        try:
            uri=urlsplit(value)
            if (uri.scheme in ('https','http') and uri.hostname and uri.username is None
                and uri.password is None and uri.query==uri.fragment==''
                and not any(c in value for c in ('\\',' ','%','?','#'))
                and not set(uri.path.split('/'))&{'.','..'} and uri.port!=0):return value
        except (ValueError,UnicodeError):pass
    return None


def reference_inventory(actual):
    env={};rows=actual['Config'].get('Env')
    if rows is None:rows=[]
    require(type(rows) is list and len(rows)<=512,'BOUNDED_INSTALLATION_ENV_REQUIRED')
    for row in rows:
        require(type(row) is str and '=' in row and len(row)<=1048576,'TYPED_INSTALLATION_ENV_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',key) and key not in env,
                'UNIQUE_INSTALLATION_ENV_KEYS_REQUIRED')
        env[key]=value
    refs={}
    for key,kind in REFERENCE_TYPES.items():
        if not env.get(key):refs[key]={'state':'ABSENT'};continue
        safe=safe_reference(env[key],kind)
        refs[key]={'state':'DECLARED_REFERENCE','kind':kind,'value':safe} if safe is not None else {'state':'UNRESOLVED_NOT_DISCLOSED'}
    mounts=actual.get('Mounts')
    require(type(mounts) is list and len(mounts)<=64,'BOUNDED_INSTALLATION_MOUNTS_REQUIRED')
    summary=[]
    for mount in mounts:
        target=mount.get('Destination');source=mount.get('Source');kind=mount.get('Type')
        require(safe_reference(target,'PATH') is not None and type(mount.get('RW')) is bool
                and kind in ('bind','volume','tmpfs') and type(source) is str and len(source)<=4096,
                'TYPED_INSTALLATION_MOUNT_REFERENCE_REQUIRED')
        summary.append({'destination':target,'type':kind,'readOnly':not mount['RW'],
                        'sourceReferenceHash':digest(source),'sourceContentRead':False})
    return {'references':refs,
        'declaredStates':{k:('ABSENT' if k not in env else 'TRUE' if env[k]=='true' else 'FALSE' if env[k]=='false' else 'UNRECOGNIZED') for k in STATE_KEYS},
        'overrideSurfacePresent':{k:bool(env.get(k)) for k in OVERRIDE_KEYS},
        'inlineCredentialEnvironmentPresent':{k:bool(env.get(k)) for k in ('MCP_WORKLOAD_TOKEN','MCP_FINGERPRINT_KEY')},
        'databaseUrlSettingPresent':bool(env.get('MCP_DATABASE_URL')),
        'environmentKeyNames':sorted(env),'mounts':sorted(summary,key=lambda row:row['destination']),
        'entrypointHash':digest(actual['Config'].get('Entrypoint')),
        'commandHash':digest(actual['Config'].get('Cmd')),
        'effectiveConfigurationProven':False,'credentialCustodyProven':False,
        'configurationFileContentReads':0,'credentialFileReads':0,'signingKeyReads':0}


def installation_inputs(c,case=None,*,engine_factory=Engine,pin=process_pin,
                        boot_path=Path('/proc/sys/kernel/random/boot_id')):
    case=CASE if case is None else case
    require(str(c.root)==case['outputRoot'],'EXACT_NEW_INSTALLATION_INPUT_SCOPE_REQUIRED')
    root=Path(case['sourceRoot'])
    previous=c.private(root/'inputs.json',case['sourceInputsHash'])
    receipt=c.private(root/'result.json',case['sourceResultHash'])
    require(digest(previous)==case['sourceInputsHash'] and digest(receipt)==case['sourceResultHash']
        and previous['schema']=='ouf.m2-discovery-current-private-bindings.v1'
        and receipt['schema']=='ouf.m2-discovery-current-bindings-result.v1'
        and receipt['status']=='M2_DISCOVERY_CURRENT_BINDINGS_CAPTURED_NOT_AUTHORIZED'
        and receipt['complete'] is True and receipt['inputsHash']==case['sourceInputsHash']
        and receipt['contextPath']==case['sourceRoot'] and receipt['cohortSize']==13
        and previous['historicalAuthorityReused'] is False and previous['runtimeAuthorityIssued'] is False
        and previous['automaticReplayAllowed'] is False and previous['budgetReset'] is False
        and receipt['runtimeAuthorityIssued'] is False and receipt['targetApplyAuthorized'] is False
        and receipt['automaticReplayAllowed'] is False and receipt['budgetReset'] is False,
        'EXACT_CONSUMED_CURRENT_CAPTURE_REQUIRED')
    observations=previous['observations'];public={row['containerId']:row for row in receipt['bindings']}
    require(len(observations)==len(public)==len(receipt['bindings'])==13
        and len({row['Id'] for row in observations.values()})==13,
        'EXACT_CONSUMED_COHORT13_REQUIRED')
    for role,actual in observations.items():
        require(public[actual['Id']]['nativeBindingHash']==digest(stable_binding(actual))
            and public[actual['Id']]['generation']==previous['processPins'][role],
            'CONSUMED_BINDING_PROJECTION_CHANGED')
    targets=case['targets']
    require(set(targets)=={'mcp','semantic','gateway-owner','apisix'}
        and len({row['containerId'] for row in targets.values()})==4,
        'FOUR_DISTINCT_REVIEWED_INSTALLATION_TARGETS_REQUIRED')
    selected={}
    for role,expected in targets.items():
        matches=[(old_role,row) for old_role,row in observations.items() if row['Id']==expected['containerId']]
        require(len(matches)==1,'EXACT_SELECTED_CURRENT_TARGET_REQUIRED')
        old_role,row=matches[0]
        require(row['Image']==expected['imageId'] and digest(stable_binding(row))==expected['nativeBindingHash'],
                'EXACT_SELECTED_IMAGE_AND_BINDING_REQUIRED')
        selected[role]=(row,previous['processPins'][old_role])
    binding=previous['engineBinding']
    roots={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}
    require(roots==previous['rootProcessPins'] and boot_path.read_text().strip()==previous['bootId'],
            'CURRENT_CAPTURE_ROOT_GENERATION_OR_BOOT_CHANGED')
    engine=engine_factory(c,binding,[row['containerId'] for row in targets.values()])
    require(engine.get('/v1.44/info')['ServerVersion']=='29.8.1','QUALIFIED_INSTALLATION_ENGINE_REQUIRED')
    fresh={};pins={};inventories={}
    for role,(expected,generation) in sorted(selected.items()):
        actual=engine.get('/v1.44/containers/'+expected['Id']+'/json')
        require(actual['State']['Running'] is True and actual['State']['Paused'] is False
            and actual['State']['Restarting'] is False and stable_binding(actual)==stable_binding(expected)
            and pin(actual['State']['Pid'])==generation,'SELECTED_INSTALLATION_GENERATION_CHANGED')
        fresh[role]=actual;pins[role]=generation;inventories[role]=reference_inventory(actual)
    for role,first in sorted(fresh.items()):
        again=engine.get('/v1.44/containers/'+first['Id']+'/json')
        require(stable_binding(again)==stable_binding(first) and pin(again['State']['Pid'])==pins[role],
                'INSTALLATION_BINDING_CHANGED_DURING_READ')
    require(roots=={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}
        and boot_path.read_text().strip()==previous['bootId'],'INSTALLATION_ROOT_OR_BOOT_CHANGED_DURING_READ')
    for path,seal in c.seals.items():
        require(list(frame(Path(path).lstat()))==seal['metadata'],'CONSUMED_INPUT_METADATA_CHANGED')
    private={'schema':'ouf.m2-discovery-private-installation-inputs.v1','bootId':previous['bootId'],
        'sourceBinding':{'root':case['sourceRoot'],'inputsHash':case['sourceInputsHash'],'resultHash':case['sourceResultHash']},
        'engineBinding':binding,'rootProcessPins':roots,'observations':fresh,'processPins':pins,
        'metadataSeals':copy.deepcopy(c.seals),'historicalAuthorityReused':False,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('inputs.json',private)
    out={'schema':'ouf.m2-discovery-installation-inputs-result.v1',
        'status':'M2_DISCOVERY_INSTALLATION_REFERENCES_CAPTURED_NOT_AUTHORIZED','complete':True,
        'contextPath':str(c.root),'inputsHash':digest(private),'sourceInputsHash':case['sourceInputsHash'],
        'counts':dict(c.counts),'selectedTargetCount':4,'otherNinePeersReobserved':False,
        'inventories':inventories,'configurationFileContentReads':0,'credentialFileReads':0,'signingKeyReads':0,
        'engineWrites':0,'sqlSessions':0,'oauthRequests':0,'iamRequests':0,'imageImports':0,
        'containerLifecycleOperations':0,'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,
        'uploads':0,'newJobs':0,'acquisitionsExecuted':0,'sourceActivations':0,
        'effectiveProviderConfigurationProven':False,'applicationReadinessOrProviderReachabilityProven':False,
        'databaseAdmissionProven':False,'credentialCustodyProven':False,'runtimeAuthorityIssued':False,
        'historicalAuthorityReused':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,
        'budgetReset':False,'stableCapabilitiesOperationalProven':False,'applicationE2EProven':False,
        'releaseAcceptance':False}
    c.put('result.json',out);return out


def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),
            'ISOLATED_OUFADMIN_INSTALLATION_INPUTS_REQUIRED')
        require(sys.stdin.isatty() and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve(); ancestry(code.parent); info=code.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
            and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400,'ROOT400_INSTALLATION_INPUTS_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'M2_INSTALLATION_INPUT_SCOPE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_INSTALLATION_INPUT_WINDOW_EXPIRED'))
        signal.alarm(90)
        c=Capture(CASE['outputRoot'],4)
        print('Nuovo scope: due metadata della cattura consumata; nove GET Engine su quattro container esatti (Registry,MCP,Gateway owner,APISIX). Riferimenti nonsegreti e impronte mount,90s/24MiB. Nessun contenuto config/credenziale/chiave,SQL,IAM/OAuth,write,import,lifecycle,grant,budget,resume o acquisizione. Env completi restano privati root0600. Nessuna authority. STOP conserva e consuma:non rilanciare.',flush=True)
        result=installation_inputs(c)
    except BaseException as error:
        reason=str(error) if isinstance(error,Stop) and re.fullmatch('[A-Z0-9_]{1,120}',str(error)) else 'PRIVATE_M2_INSTALLATION_INPUTS_FAILURE_RECONCILE'
        result={'schema':'ouf.m2-discovery-installation-inputs-result.v1','status':'STOP_RECONCILE',
            'complete':False,'reasonCode':reason,'contextPath':str(c.root) if c else None,
            'counts':dict(c.counts) if c else {},'engineWrites':0,'sqlSessions':0,'iamRequests':0,
            'oauthRequests':0,'humanBudgetsGranted':0,'resumes':0,'runtimeAuthorityIssued':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not (c.root/'result.json').exists(): c.put('result.json',result)
    finally:
        signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete'] else 2


if __name__=='__main__':
    raise SystemExit(main())
