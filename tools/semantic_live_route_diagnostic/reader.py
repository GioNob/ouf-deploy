"""Live Gateway route and stopped Registry correlation; GET only, no recovery authority."""
import hashlib,http.client,ipaddress,json,os,re,signal,socket,stat,subprocess,sys
from pathlib import Path,PurePosixPath
from contextlib import contextmanager
from urllib.parse import urlsplit

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

class Stop(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Stop(code)

def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)

def private_json(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
            'EXACT_PRIVATE_PATH_REQUIRED')
    for parent in p.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'ROOT_CONTROLLED_METADATA_ANCESTRY_REQUIRED')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and not before.st_mode & 0o022 and 0 < before.st_size <= 8_388_608,
                'ROOT_OWNED_BOUNDED_METADATA_REQUIRED')
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65_536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()),
                'PRIVATE_METADATA_CHANGED')
        return decode(raw), bytes(raw)
    finally:
        os.close(fd)

class BaseEngine:
    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
                'EXACT_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0
                and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'ENGINE_BINDING_CHANGED')

    def get(self, path):
        require(path in self.paths and self.calls < MAX_GETS, 'CLOSED_SIX_GET_BUDGET')
        self.check()
        selected = self.binding['socketPath']

        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(selected)

        connection = Connection('retained-engine', timeout=4)
        try:
            self.calls += 1
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, 'LOG_OR_METADATA_LIMIT_REACHED')
            self.check()
            require(response.status == 200, 'ENGINE_GET_STATUS_' + str(response.status))
            return raw
        finally:
            connection.close()

    def inspect(self, cid):
        path = '/v1.44/containers/' + cid + '/json'
        require(path in self.inspects, 'EXACT_INSPECT_ID_REQUIRED')
        value = decode(self.get(path))
        require(value['Id'] == cid, 'EXACT_INSPECT_ID_REQUIRED')
        return value

def generation(actual, pin):
    s = actual['State']
    require(actual['Id'] == pin['containerId'] and s['Pid'] == pin['pid']
            and s['StartedAt'] == pin['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead'),
            'GATEWAY_GENERATION_CHANGED')
    require(actual['Image'] == pin['imageId'] and all(digest(actual[field]) == pin[key]
            for field,key in [('Config','configHash'),('HostConfig','hostConfigHash'),
                              ('NetworkSettings','networkSettingsHash')]), 'GATEWAY_BINDING_CHANGED')

def stable_fields(actual):
    # Omit continuously changing health-check history; bind lifecycle/config/network.
    return {'Id': actual['Id'], 'Image': actual['Image'], 'Config': actual['Config'],
            'HostConfig':actual['HostConfig'], 'Mounts':actual['Mounts'],
            'NetworkSettings': actual['NetworkSettings'], 'RestartCount': actual['RestartCount'],
            'State': {key: actual['State'].get(key) for key in STATE_FIELDS}}

def stopped(error):
    reason = str(error) if type(error) is Stop else 'DIAGNOSTIC_UNCONFIRMED_' + type(error).__name__
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'DIAGNOSTIC_UNCONFIRMED'
    return {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'readOnlyRuntime': True, 'runtimeEffectsDispatched': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'rootCauseEstablished': False}

STATE_FIELDS=("Status","Running","Paused","Restarting","Dead","OOMKilled","Pid","ExitCode","Error","StartedAt","FinishedAt")

def registry_baseline(actual,pin):
    state=actual['State']
    require(actual['Id']==pin['containerId'] and actual['Image']==pin['imageId']
            and state['Status']=='exited' and state['Running'] is False and state['Pid']==0
            and not any(state.get(k) for k in ('Paused','Restarting','Dead')),
            'EXACT_STOPPED_REGISTRY_REQUIRED')
    require(digest(stable_fields(actual))==pin['stableMetadataHash']
            and all(digest(actual[field])==pin[key] for field,key in [('Config','configHash'),
                    ('HostConfig','hostConfigHash'),('NetworkSettings','networkSettingsHash')])
            and digest(sorted(actual['Mounts'],key=lambda m:m['Destination']))==pin['mountsHash'],
            'STOPPED_REGISTRY_BASELINE_CHANGED')

MAX_GETS=6
MAX_BYTES=2097152
SCHEMA="ouf.semantic-live-route-diagnostic-result.v1"
OPERATION="/api/semantic/v1/references:resolve"

def hashed(value):return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None

def path(value):
    require(type(value) is str and len(value)<=4096 and value.startswith('/') and str(PurePosixPath(value))==value
            and '..' not in PurePosixPath(value).parts,'CANONICAL_ABSOLUTE_PATH_REQUIRED')
    return value

MAX_RESPONSE=8388608
MAX_ROUTES=256
ROUTE_ID=re.compile(r"[A-Za-z0-9._-]{1,128}")

def route_value(doc):
    # Same APISIX envelope normalization used by the qualified route installers.
    value = doc.get('value', doc)
    if type(value) is dict and type(value.get('value')) is dict:
        value = value['value']
    require(type(value) is dict, 'APISIX_ROUTE_OBJECT_REQUIRED')
    return {k: v for k, v in value.items() if k not in ('create_time', 'update_time')}

def route_map(rows):
    require(type(rows) is list and 0 < len(rows) <= MAX_ROUTES, 'COMPLETE_BOUNDED_GATEWAY_ROUTES_REQUIRED')
    result = {}
    for row in rows:
        value = route_value(row)
        rid = value.get('id')
        require(type(rid) is str and ROUTE_ID.fullmatch(rid) and rid not in result,
                'UNIQUE_EXACT_GATEWAY_ROUTE_ID_REQUIRED')
        require(len(encoded(value)) <= 262144, 'GATEWAY_ROUTE_BOUND_EXCEEDED')
        result[rid] = value
    return result

def selected_admin_key(raw, external_key=None):
    # Closed scalar/list subset of the selected APISIX admin_key section only.
    # No YAML dependency, interpolation, aliases, tags or arbitrary configuration
    # execution in the isolated installer. Unsupported syntax requires review.
    lines = raw.decode('utf-8').splitlines()
    entries = [(i, len(line)-len(line.lstrip(' '))) for i,line in enumerate(lines)
               if re.fullmatch(r' *admin_key: *(?:#.*)?',line)]
    require(len(entries) == 1, 'ONE_LITERAL_ADMIN_KEY_SECTION_REQUIRED')
    start, indentation = entries[0]
    parents=[]
    for line in lines[:start]:
        if not line.strip() or line.lstrip().startswith('#'): continue
        match=re.fullmatch(r'( *)([A-Za-z_][A-Za-z0-9_]*): *(?:#.*)?',line)
        depth=len(line)-len(line.lstrip(' '))
        parents=[p for p in parents if p[0]<depth]
        if match: parents.append((depth,match[2]))
    require([p[1] for p in parents if p[0]<indentation] == ['deployment','admin'],
            'SELECTED_DEPLOYMENT_ADMIN_SECTION_REQUIRED')
    candidates=[]; row=None
    for line in lines[start+1:]:
        if not line.strip() or line.lstrip().startswith('#'): continue
        require('\t' not in line, 'LITERAL_ADMIN_KEY_INDENTATION_REQUIRED')
        depth=len(line)-len(line.lstrip(' '))
        if depth <= indentation: break
        match=re.fullmatch(r' +(- +)?(name|key|role): *(.*?) *',line)
        require(match is not None, 'UNSUPPORTED_ADMIN_KEY_SYNTAX')
        if match[1]:
            if row is not None: candidates.append(row)
            row={}
        require(row is not None and match[2] not in row, 'DUPLICATE_OR_UNBOUNDED_ADMIN_KEY_FIELD')
        value=match[3]
        if value.startswith('"'):
            value=json.loads(value)
        elif value.startswith("'"):
            require(len(value)>=2 and value.endswith("'"), 'ADMIN_KEY_SCALAR_INVALID')
            value=value[1:-1].replace("''", "'")
        else:
            value=value.split(' #',1)[0].strip()
        require(type(value) is str and re.fullmatch(r'[A-Za-z0-9._=+-]{1,4096}',value),
                'LITERAL_ADMIN_KEY_SCALAR_REQUIRED')
        row[match[2]]=value
    if row is not None: candidates.append(row)
    require(len(candidates)<=8 and all(set(r)=={'name','key','role'} for r in candidates),
            'CLOSED_ADMIN_CREDENTIAL_RECORD_REQUIRED')
    admin=[r for r in candidates if r.get('role') == 'admin']
    # The selected live config has a literal but empty admin_key section.
    # Its separate existing admin-key file was observed to authorize a GET.
    # No fallback is permitted for ambiguous/nonempty credential records.
    if not candidates and external_key is not None:
        key=external_key
    else:
        require(external_key is None and len(admin)==1,
                'ONE_SELECTED_APISIX_ADMIN_CREDENTIAL_REQUIRED')
        key=admin[0].get('key')
    require(type(key) is str and 16 <= len(key) <= 4096 and all(33 <= ord(c) <= 126 for c in key)
            and not key.startswith(('$ENV', '${', '$secret')), 'LITERAL_SELECTED_ADMIN_CREDENTIAL_REQUIRED')
    return key

def metadata(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def validate(binding,*,maximum=1048576):
    require(type(maximum)is int and 1<=maximum<=2147483648,'EXPLICIT_BOUNDED_FILE_PROFILE_REQUIRED')
    require(type(binding)is dict and set(binding)=={'path','sha256','metadata','ancestors'},
            'EXACT_PRIVATE_FILE_PROFILE_REQUIRED')
    selected=path(binding['path'])
    require(hashed(binding['sha256'])and type(binding['metadata'])is list
            and len(binding['metadata'])==9 and all(type(v)is int and v>=0 for v in binding['metadata']),
            'EXACT_PRIVATE_FILE_SEAL_REQUIRED')
    parts=PurePosixPath(selected).parts;ancestors=binding['ancestors']
    require(type(ancestors)is list and len(ancestors)==len(parts)-1,'COMPLETE_FILE_ANCESTRY_PROFILE_REQUIRED')
    expected=['/']+['/'+ '/'.join(parts[1:i])for i in range(2,len(parts))]
    for item,name in zip(ancestors,expected):
        require(type(item)is dict and set(item)=={'path','identity'}and item['path']==name
                and type(item['identity'])is list and len(item['identity'])==5
                and all(type(v)is int and v>=0 for v in item['identity']),'EXACT_DIRECTORY_CUSTODY_IDENTITY_REQUIRED')
        mode=item['identity'][4]
        require(stat.S_ISDIR(mode)and not mode&0o022,'PRIVATE_FILE_ANCESTRY_WRITABLE')
    mode=binding['metadata'][4]
    require(stat.S_ISREG(mode)and not mode&0o022 and binding['metadata'][5]==1
            and 0<binding['metadata'][6]<=maximum,'BOUNDED_CUSTODIED_REGULAR_FILE_REQUIRED')
    return binding

@contextmanager
def _opened(binding,*,maximum=1048576,verify_bytes=True):
    """Yield one already verified FD at offset0; recheck seal after consumption."""
    validate(binding,maximum=maximum);fds=[];pins=[]
    identity=lambda s:[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
        root=binding['ancestors'][0]
        require(identity(os.fstat(parent))==root['identity'],'PRIVATE_FILE_ROOT_CUSTODY_CHANGED')
        for item in binding['ancestors'][1:]:
            name=PurePosixPath(item['path']).name
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
            require(identity(os.fstat(fd))==item['identity'],'PRIVATE_FILE_DIRECTORY_CUSTODY_CHANGED')
            pins.append((parent,name,fd,item['identity']));parent=fd
        name=PurePosixPath(binding['path']).name
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);fds.append(fd)
        def recheck():
            require(metadata(os.fstat(fd))==binding['metadata']
                    ==metadata(os.stat(name,dir_fd=parent,follow_symlinks=False)),'PRIVATE_FILE_METADATA_CHANGED')
            require(identity(os.fstat(fds[0]))==root['identity'],'PRIVATE_FILE_ROOT_CHANGED')
            for directory,entry,held,seal in pins:
                require(identity(os.fstat(held))==seal==identity(os.stat(entry,dir_fd=directory,follow_symlinks=False)),
                        'PRIVATE_FILE_ANCESTRY_CHANGED_DURING_READ')
        recheck()
        if verify_bytes:
            count=0;digest=hashlib.sha256()
            while True:
                chunk=os.read(fd,65536)
                if not chunk:break
                count+=len(chunk);require(count<=maximum,'PRIVATE_FILE_BOUND_EXCEEDED');digest.update(chunk)
            require(count==binding['metadata'][6]and digest.hexdigest()==binding['sha256'],'PRIVATE_FILE_BYTES_OR_IDENTITY_CHANGED')
        recheck();os.lseek(fd,0,os.SEEK_SET)
        yield fd
        recheck()
    finally:
        for fd in reversed(fds):os.close(fd)

@contextmanager
def opened(binding,*,maximum=1048576):
    with _opened(binding,maximum=maximum,verify_bytes=True)as fd:yield fd

def read(binding):
    with opened(binding)as fd:
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(1048577)
        require(len(raw)==binding['metadata'][6],'EXACT_SELECTED_FILE_READ_REQUIRED')
        return raw

CHILD_SOURCE = r'''import hashlib,http.client,ipaddress,json,os,re,signal,sys
signal.alarm(12)
try:
    raw=sys.stdin.buffer.read(655361)
    if not 0<len(raw)<=655360:raise ValueError()
    v=json.loads(raw)
    if type(v)is not dict or set(v)!={'method','path','body','key','host','port'}:raise ValueError()
    method,path,body,key=(v[n] for n in ('method','path','body','key'))
    if method!='GET' or path!='/apisix/admin/routes' or body is not None:raise ValueError()
    if path!='/apisix/admin/routes' and not re.fullmatch(r'/apisix/admin/routes/[A-Za-z0-9._-]{1,128}',path):raise ValueError()
    
    
    if type(key)is not str or not 16<=len(key)<=4096 or not all(33<=ord(c)<=126 for c in key):raise ValueError()
    host,port=v['host'],v['port']
    if type(host)is not str or not ipaddress.ip_address(host).is_loopback:raise ValueError()
    if type(port)is not int or not 1<=port<=65535:raise ValueError()
    payload=None if body is None else json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if payload is not None and len(payload)>262144:raise ValueError()
    if len(sys.argv)!=2 or not re.fullmatch(r'[0-9]{1,10}',sys.argv[1]):raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    client=http.client.HTTPConnection(host,port,timeout=10)
    client.request(method,path,body=payload,headers={'X-API-KEY':key,'Content-Type':'application/json','Accept':'application/json','Connection':'close'})
    response=client.getresponse();payload=response.read(8388609)
    if len(payload)>8388608:raise ValueError()
    retry=response.getheader('Retry-After','')
    if len(retry)>128 or any(ord(c)<32 or ord(c)>126 for c in retry):raise ValueError()
    try:parsed=json.loads(payload) if payload else {}
    except ValueError:
        if method!='GET' or response.status not in (429,502,503,504):raise
        parsed={'unparsedBodySha256':hashlib.sha256(payload).hexdigest(),'bodyBytes':len(payload)}
    result=json.dumps({'status':response.status,'body':parsed,'retryAfter':retry},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(result)>8454144:raise ValueError()
    sys.stdout.buffer.write(result);sys.stdout.buffer.flush();client.close()
except BaseException:
    os._exit(1)
os._exit(0)
'''


class Engine(BaseEngine):
    def __init__(self,binding,gid,rid,nid):
        require(len({gid,rid})==2 and all(type(x) is str and re.fullmatch('[a-f0-9]{64}',x) for x in (gid,rid,nid)),
                'EXACT_TWO_CONTAINERS_AND_NETWORK_REQUIRED')
        self.binding,self.calls=binding,0
        self.inspects={'/v1.44/containers/'+cid+'/json' for cid in (gid,rid)}
        self.network_path='/v1.44/networks/'+nid
        self.paths=self.inspects|{self.network_path}
    def network(self):return decode(self.get(self.network_path))


def selected_route(routes):
    selected=[r for r in routes.values() if OPERATION in [r.get('uri'),*r.get('uris',[])]
              and 'GET' in r.get('methods',['GET']) and r.get('status',1)==1]
    require(len(selected)==1,'ONE_EXACT_CURRENT_SEMANTIC_GET_ROUTE_REQUIRED')
    row=selected[0]
    require(not any(k in row for k in ('upstream_id','service_id')),'INLINE_CURRENT_UPSTREAM_REQUIRED')
    upstream=row.get('upstream',{})
    require(not upstream.get('discovery_type') and not upstream.get('service_name'), 'STATIC_CURRENT_UPSTREAM_REQUIRED')
    raw=upstream['nodes'];nodes=[]
    if type(raw) is dict:
        for hostport,weight in raw.items():
            u=urlsplit('//'+hostport)
            require(not u.username and not u.password and not u.path and not u.query and not u.fragment
                    and type(weight) in (int,float) and weight>0,'EXACT_CURRENT_NODE_REQUIRED')
            nodes.append((u.hostname,u.port))
    elif type(raw) is list:
        for node in raw:
            require(type(node.get('weight')) in (int,float) and node['weight']>0,'EXACT_CURRENT_NODE_REQUIRED')
            nodes.append((node['host'],node['port']))
    require(len(nodes)==1 and type(nodes[0][1]) is int and 0<nodes[0][1]<65536,'ONE_CURRENT_STATIC_NODE_REQUIRED')
    ipaddress.IPv4Address(nodes[0][0])
    return row,nodes[0]


def correlate(routes,retained,request,registry,network,gateway):
    row,node=selected_route(routes);old,_=selected_route(retained)
    endpoints=request['NetworkingConfig']['EndpointsConfig']
    require(type(endpoints) is dict and len(endpoints)==1,'ONE_REVIEWED_REGISTRY_NETWORK_REQUIRED')
    endpoint=next(iter(endpoints.values()));nid=endpoint['NetworkID']
    require(network['Id']==nid and network['Driver']=='bridge' and network.get('EnableIPv6') is False
            and any(e['NetworkID']==nid for e in gateway['NetworkSettings']['Networks'].values()),
            'SAME_REVIEWED_REGISTRY_GATEWAY_NETWORK_REQUIRED')
    address=str(ipaddress.IPv4Address(endpoint['IPAMConfig']['IPv4Address']))
    env={}
    for item in request['Env']:
        key,sep,value=item.partition('=')
        require(sep and key not in env,'UNIQUE_RETAINED_ENV_REQUIRED');env[key]=value
    port=int(env.get('PORT','8080'))
    containers=network.get('Containers') or {}
    require(type(containers) is dict and len(containers)<=512,'BOUNDED_CURRENT_NETWORK_ENDPOINTS_REQUIRED')
    matches=[]
    for cid,item in containers.items():
        require(re.fullmatch('[a-f0-9]{64}',cid) and type(item) is dict,'EXACT_CURRENT_NETWORK_MEMBER_REQUIRED')
        raw=item.get('IPv4Address','')
        if raw and str(ipaddress.IPv4Interface(raw).ip)==node[0]:matches.append(cid)
    target=node==(address,port)
    result={'liveGatewayRouteMapRead':True,'currentRouteEqualsRetainedSemanticRoute':row==old,
        'completeCurrentRouteMapMatchesRetained':routes==retained,'routeCount':len(routes),
        'currentRouteTargetsReviewedRegistryAddressAndPort':target,
        'reviewedRegistryStopped':registry['State']['Status']=='exited' and registry['State']['Pid']==0,
        'reviewedRegistryHasLiveNetworkEndpoint':registry['Id'] in containers,
        'currentTargetEndpointCount':len(matches),'currentTargetEndpointIsReviewedRegistry':matches==[registry['Id']],
        'rootCauseEstablished':False,'dataPlaneRequestReproduced':False,'applicationReadinessProven':False,
        'addressesPrinted':False,'rawRouteMapPrinted':False}
    if target and result['reviewedRegistryStopped'] and not matches and registry['Id'] not in containers:
        result['finding']='LIVE_ADMIN_ROUTE_TARGETS_STOPPED_REVIEWED_REGISTRY_WITH_NO_NETWORK_ENDPOINT'
    elif not target:result['finding']='LIVE_ADMIN_ROUTE_TARGET_DIFFERS_FROM_REVIEWED_REGISTRY'
    else:result['finding']='LIVE_ADMIN_ROUTE_TARGET_REQUIRES_FURTHER_RECONCILIATION'
    return result


def verify_program(binding):
    require(set(binding)=={'path','sha256'} and hashed(binding['sha256']),'EXACT_NAMESPACE_PROGRAM_REQUIRED')
    selected=Path(path(binding['path'])).resolve(strict=True)
    fd=os.open(selected,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
                and info.st_mode&0o111 and 0<info.st_size<=67108864,'ROOT_CONTROLLED_NAMESPACE_PROGRAM_REQUIRED')
        value=bytearray()
        while len(value)<=info.st_size:
            block=os.read(fd,min(65536,info.st_size+1-len(value)))
            if not block:break
            value.extend(block)
        require(len(value)==info.st_size and metadata(info)==metadata(os.fstat(fd))==metadata(selected.stat())
                and hashlib.sha256(value).hexdigest()==binding['sha256'],'NAMESPACE_PROGRAM_CHANGED')
    finally:os.close(fd)


def process_ticks(pid):
    with open('/proc/'+str(pid)+'/stat','rb') as source:raw=source.read(16385)
    require(len(raw)<=16384 and b') ' in raw,'BOUNDED_GATEWAY_PROCESS_STAT_REQUIRED')
    fields=raw.rsplit(b') ',1)[1].split()
    return int(fields[19])


def admin_routes(profile,gateway):
    require(set(profile)=={'schema','endpoint','pythonExecutable','config','adminKey'}
            and profile['schema']=='ouf.ingestion-rollout-gateway-transport.v1','EXACT_RETAINED_ADMIN_PROFILE_REQUIRED')
    endpoint=profile['endpoint']
    require(set(endpoint)=={'host','port'} and ipaddress.ip_address(endpoint['host']).is_loopback
            and type(endpoint['port']) is int and 0<endpoint['port']<65536,'RETAINED_LOOPBACK_ONLY_REQUIRED')
    verify_program(profile['pythonExecutable'])
    config=read(profile['config']);external=None if profile['adminKey'] is None else read(profile['adminKey']).decode('ascii').strip()
    key=selected_admin_key(config,external)
    request=encoded({'method':'GET','path':'/apisix/admin/routes','body':None,'key':key,**endpoint})
    require(len(request)<=655360,'BOUNDED_PRIVATE_ADMIN_REQUEST_REQUIRED')
    pid=gateway['State']['Pid'];ns_path='/proc/'+str(pid)+'/ns/net';ticks=process_ticks(pid)
    fd=os.open(ns_path,os.O_RDONLY|os.O_CLOEXEC);child=None
    identity=lambda info:(info.st_dev,info.st_ino)
    held=identity(os.fstat(fd))
    try:
        require(held==identity(os.stat(ns_path)) and process_ticks(pid)==ticks,'GATEWAY_NAMESPACE_CHANGED')
        child=subprocess.Popen([profile['pythonExecutable']['path'],'-I','-B','-S','-c',CHILD_SOURCE,str(fd)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),
            close_fds=True,cwd='/',env={'LC_ALL':'C'})
        output,_=child.communicate(request,timeout=15)
        require(child.returncode==0 and 0<len(output)<=8454144,'READ_ONLY_ADMIN_GET_UNCONFIRMED')
        require(held==identity(os.fstat(fd))==identity(os.stat(ns_path)) and process_ticks(pid)==ticks,
                'GATEWAY_NAMESPACE_CHANGED_DURING_GET')
        verify_program(profile['pythonExecutable']);read(profile['config'])
        if profile['adminKey'] is not None:read(profile['adminKey'])
        result=decode(output)
        require(type(result) is dict and set(result)=={'status','body','retryAfter'} and result['status']==200,
                'LIVE_ADMIN_ROUTE_READ_NOT_200')
        body=result['body']
        require(type(body) is dict and type(body.get('list')) is list and type(body.get('total')) is int
                and body['total']==len(body['list']) and 0<body['total']<=256,'COMPLETE_BOUNDED_LIVE_ROUTE_MAP_REQUIRED')
        return route_map(body['list'])
    finally:
        if child is not None:
            if child.poll() is None:child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin,child.stdout):
                if stream is not None:stream.close()
        os.close(fd)


def run(case):
    require(type(case) is dict and set(case)=={'schema','inputsPath','inputsHash','compositionPath','compositionHash','patchContext'}
            and case['schema']=='ouf.semantic-live-route-diagnostic-case.v1'
            and hashed(case['inputsHash']) and hashed(case['compositionHash']),'EXACT_LIVE_DIAGNOSTIC_CASE_REQUIRED')
    for field,prefix,filename in [('inputsPath','semantic-registry-history-capture-','inputs.json'),
                                  ('compositionPath','semantic-registry-recovery-composition-','composition.json')]:
        p=Path(path(case[field]));require(str(p.parent.parent)=='/etc/ouf/deploy-snapshots'
                and p.parent.name.startswith(prefix) and p.name==filename,'EXACT_RETAINED_DIAGNOSTIC_INPUT_PATH_REQUIRED')
    root=path(case['patchContext'])
    require(Path(root).parent==Path('/etc/ouf/deploy-snapshots')
            and Path(root).name.startswith('ingestion-readiness-stage8-execution-'),'EXACT_COMPLETED_PATCH_CONTEXT_REQUIRED')
    saved={}
    def selected(p,sha=None):
        value,raw=private_json(p)
        require(sha is None or hashlib.sha256(raw).hexdigest()==sha==digest(value),'EXACT_PRIVATE_INPUT_HASH_REQUIRED')
        saved[p]=raw;return value
    inputs=selected(case['inputsPath'],case['inputsHash']);composition=selected(case['compositionPath'],case['compositionHash'])
    require(inputs['historicalBinding']['historicalDeploymentChainBound'] is True
            and inputs['unresolvedGateCount']==7 and inputs['runtimeAuthorityIssued'] is False
            and composition['inputsHash']==case['inputsHash'] and composition['runtimeAuthorityIssued'] is False
            and composition['targetApplyAuthorized'] is False,'HISTORICAL_INPUTS_ARE_NOT_RUNTIME_AUTHORITY')
    proposal=inputs['proposal'];review=selected(root+'/review.json');journal=selected(root+'/recovery.json')
    packet=selected(root+'/packet.json');native=review['executionReview']
    require(digest(review)==proposal['retainedPatchReviewHash'] and digest(journal)==proposal['retainedPatchJournalHash']
            and native['packetBinding']['path']==root+'/packet.json' and native['packetBinding']['sha256']==digest(packet)
            and journal['nextStage']==len(native['stages'])==len(journal['effects'])==12
            and all(e['state']=='APPLIED' for e in journal['effects']),'EXACT_COMPLETED_PATCH_CHAIN_REQUIRED')
    gateway_pin=proposal['gatewayBinding'];registry_pin=proposal['registry'];request=inputs['registryInputs']['creationRequest']
    require(request['Image']==registry_pin['imageId'],'SAME_REVIEWED_REGISTRY_IMAGE_REQUIRED')
    endpoints=request['NetworkingConfig']['EndpointsConfig'];require(len(endpoints)==1,'ONE_REVIEWED_NETWORK_REQUIRED')
    nid=next(iter(endpoints.values()))['NetworkID']
    engine=Engine(proposal['engineBinding'],gateway_pin['containerId'],registry_pin['containerId'],nid)
    gateway=engine.inspect(gateway_pin['containerId']);generation(gateway,gateway_pin)
    registry=engine.inspect(registry_pin['containerId']);registry_baseline(registry,registry_pin)
    network=engine.network()
    profile=native['gatewayTransportProfile']
    require({k:profile['config'][k] for k in ('path','sha256','metadata')}==packet['retainedGatewayConfig'],
            'SAME_RETAINED_ADMIN_CONFIG_REQUIRED')
    selected_mounts=[item for item in gateway['Mounts'] if item.get('Destination')=='/usr/local/apisix/conf/config.yaml']
    require(len(selected_mounts)==1 and selected_mounts[0].get('Type')=='bind'
            and selected_mounts[0].get('RW') is False and selected_mounts[0].get('Source')==profile['config']['path'],
            'CURRENT_GATEWAY_MUST_MOUNT_RETAINED_ADMIN_CONFIG')
    routes=admin_routes(profile,gateway)
    result=correlate(routes,packet['routeDraft']['afterRoutes'],request,registry,network,gateway)
    after_network=engine.network();after_registry=engine.inspect(registry_pin['containerId']);registry_baseline(after_registry,registry_pin)
    after_gateway=engine.inspect(gateway_pin['containerId']);generation(after_gateway,gateway_pin)
    require(network==after_network and stable_fields(gateway)==stable_fields(after_gateway)
            and stable_fields(registry)==stable_fields(after_registry),'LIVE_DIAGNOSTIC_RESOURCE_DRIFT')
    for p,raw in saved.items():require(private_json(p)[1]==raw,'RETAINED_DIAGNOSTIC_INPUT_CHANGED')
    return {'schema':SCHEMA,'status':'LIVE_ROUTE_AND_REGISTRY_CORRELATED','complete':True,'readOnlyRuntime':True,
        **result,'engineGets':engine.calls,'maximumEngineGets':MAX_GETS,'adminGets':1,'maximumAdminGets':1,
        'credentialFileReadOperations':2*(1+int(profile['adminKey'] is not None)),'credentialValuesPrinted':False,
        'oauthRequests':0,'databaseCalls':0,'gatewayWrites':0,'runtimeEffectsDispatched':0,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'activationResubmitted':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}


if __name__=='__main__':
    try:
        require(os.geteuid()==0 and sys.flags.isolated and hasattr(os,'setns'),'ROOT_ISOLATED_NAMESPACE_READER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('LIVE_DIAGNOSTIC_DEADLINE')));signal.alarm(55)
        require(len(sys.argv)==2,'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1],'rb') as source:raw=source.read(8193)
        require(len(raw)<=8192,'BOUNDED_CASE_REQUIRED')
        print(json.dumps(run(decode(raw)),sort_keys=True),flush=True)
    except Exception as error:
        print(json.dumps(stopped(error),sort_keys=True),flush=True);sys.exit(1)
