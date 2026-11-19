#!/usr/bin/env python3
"""Installation-specific Ingestion ambiguous-start readback; bounded GET only."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time

from pathlib import Path

from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-1711f307b106011ee1bf1bf4a6dadf1379b40bda58a0299d39f0cf15d37a0bd6')

REVIEW='62c8837120f9079cbf2dd026105ccce7befbbbfbbd09b1c67fc813e6a468f91e'

AUTHORITY='b6335ae592c469d253a345c29352a6fe2180e1297a29146b98bf1048016b4fe4'

SOURCE='f6078a5ac07853b4abc13d310882f5a30086baba'

UNIT='ouf-file-cohort-1711f307b106011ee1bf1bf4a6dadf13.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-ingestion-exec-readback.v1',check=check,readOnly=True,
        automaticRetry=False,budgetReset=False,acceptanceGranted=False)
    require(not set(values)&set(fixed),'RESERVED_OUTPUT_FIELD')
    print(json.dumps({**fixed,**values},sort_keys=True),flush=True)

class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def unique(rows):
    d={}
    for k,v in rows:require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
    return d

def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'READ_DRIFT')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'READ_HASH_DRIFT')
        return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)

def bounded(argv, seconds=15, maximum=2097152, discard=False):
    """Drain both pipes concurrently; cap bytes/time and kill the CLI on exit."""
    proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    output=bytearray(); errors=bytearray(); count=0; end=time.monotonic()+seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,'out')
            selector.register(proc.stderr,selectors.EVENT_READ,'err')
            while selector.get_map():
                require(time.monotonic()<end,'DIAGNOSTIC_HOST_TIME_BOUND_EXHAUSTED')
                for key,_ in selector.select(min(0.2,max(0,end-time.monotonic()))):
                    raw=os.read(key.fd,65536)
                    if not raw:selector.unregister(key.fileobj);continue
                    if key.data=='out':
                        count+=len(raw);require(count<=maximum,'DIAGNOSTIC_OUTPUT_BOUND_EXHAUSTED')
                        if not discard:output.extend(raw)
                    else:
                        require(len(errors)+len(raw)<=65536,'DIAGNOSTIC_STDERR_BOUND_EXHAUSTED')
                        errors.extend(raw)
            code=proc.wait(timeout=max(0.01,end-time.monotonic()))
        return code,bytes(output),bytes(errors),count
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()

def executable(binding):
    path=Path(binding['path']);info=path.stat()
    require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid==0 and
        not info.st_mode&0o022 and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],
        'NATIVE_EXECUTABLE_BINDING_DRIFT')
    return str(path)

def stopped(binding):
    code,raw,_,_=bounded([executable(binding),'show',UNIT,'--property=ActiveState,MainPID,Job'])
    values=dict(line.split('=',1)for line in raw.decode().splitlines()if '=' in line)
    require(code==0 and values.get('ActiveState') in ('inactive','failed') and
        values.get('MainPID')=='0' and values.get('Job')=='','DELIVERY_MUST_BE_STOPPED')

def runtime_pin(actual):
    mounts=actual['Mounts']
    require(type(mounts)is list and all(type(m)is dict and type(m.get('Destination'))is str for m in mounts)
        and len({m['Destination'] for m in mounts})==len(mounts),'DUPLICATE_OR_INVALID_MOUNT')
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        'mountsHash':digest(sorted(mounts,key=lambda m:m['Destination'])),
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('networkSettings','NetworkSettings'))}}

def engine_get(engine,kind,reference):
    require(kind in ('containers','images') and type(reference)is str and
        re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',reference),'FIXED_ENGINE_GET_REQUIRED')
    path=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(path,follow_symlinks=False)
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and
            (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.sock.settimeout(10);self.sock.connect(path)
    conn=Local('localhost',timeout=10)
    try:
        conn.request('GET','/v1.44/'+kind+'/'+quote(reference,safe='')+'/json')
        reply=conn.getresponse();raw=reply.read(2097153)
        require(reply.status in (200,404) and len(raw)<=2097152,'ENGINE_READ_UNAVAILABLE');guard()
        return None if reply.status==404 else json.loads(raw,object_pairs_hook=unique)
    finally:conn.close()

PlanDenied=ReadDenied

MAX_ROUTES=256

ROUTE_ID=re.compile(r"[A-Za-z0-9._-]{1,128}")

EXTERNAL_ADMIN_KEY="/opt/ouf/secrets/apisix-admin-key"

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

_EXISTING_CONFIG_CUSTODY = {
    # These are the observed, already-running selections on this host. Do not
    # change ownership of /opt/ouf or the files mounted into live containers.
    '/opt/ouf/installation/active-projection.json': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/installation': (0, 0, 0o700)},
        'file': (0, 0, 0o600)},
    '/opt/ouf/secrets/onboarding-ths.yaml': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        'file': (10003, 10003, 0o400)},
    EXTERNAL_ADMIN_KEY: {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        # 0600 does not grant group access. The observed uid/mode are fixed;
        # the actual gid is pinned by the returned file metadata.
        'file': (1000, None, 0o600)},
    '/etc/ouf/deploy-snapshots/consultation-human-read-20261002-1153/prepared/apisix-config.yaml': {
        'parents': {}, 'file': (636, 636, 0o400)},
}

def selected_directory_custody(info, path, exception):
    selected = exception['parents'].get(path) if exception else None
    if selected is not None:
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == selected
    return info.st_uid == 0 and not info.st_mode & 0o022

def selected_file_custody(info, exception):
    selected = exception['file'] if exception else None
    if selected is not None:
        uid,gid,mode=selected
        return info.st_uid==uid and (gid is None or info.st_gid==gid) and stat.S_IMODE(info.st_mode)==mode
    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (0o400,0o440,0o444,0o600,0o640,0o644)

def private_config(path, expected=None):
    """Read an exact selected file with pinned, no-follow path custody.

    The three existing selections above have different named owners. All
    other paths, including newly staged APISIX config, retain root custody.
    """
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts, 'EXACT_APISIX_CONFIG_PATH_REQUIRED')
    exception = _EXISTING_CONFIG_CUSTODY.get(str(target))
    fds = []; ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)
        current = '/'
        for name in target.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child); info = os.fstat(child)
            current = os.path.join(current, name)
            require(selected_directory_custody(info,current,exception),'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED')
            ancestors.append((parent,name,child,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            parent = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
        s = os.fstat(fd)
        pin = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= 1048576
                and selected_file_custody(s,exception),
                'ROOT_CONTROLLED_SELECTED_APISIX_CONFIG_REQUIRED')
        raw = b''
        while len(raw) <= 1048576:
            part = os.read(fd,65536)
            if not part: break
            raw += part
        require(len(raw) == s.st_size and pin(s) == pin(os.fstat(fd))
                == pin(os.stat(target.name, dir_fd=parent, follow_symlinks=False)), 'APISIX_CONFIG_READ_DRIFT')
        binding = {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': list(pin(s))}
        require(expected is None or binding == expected, 'APISIX_SELECTED_CONFIG_CHANGED')
        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
        for parent,name,child,seal in ancestors:
            require(seal == identity(os.fstat(child)) == identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'APISIX_CONFIG_ANCESTRY_CHANGED')
        return raw, binding
    finally:
        for fd in reversed(fds): os.close(fd)

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

GET_CHILD=r'''import http.client,json,os,signal,sys
signal.alarm(12)
try:
    raw=sys.stdin.buffer.read(8193)
    if not 0<len(raw)<=8192:raise ValueError()
    data=json.loads(raw)
    if type(data)is not dict or set(data)!={'key'}:raise ValueError()
    key=data['key']
    if type(key)is not str or not 16<=len(key)<=4096 or not all(33<=ord(c)<=126 for c in key):raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    conn=http.client.HTTPConnection('127.0.0.1',9180,timeout=10)
    conn.request('GET','/apisix/admin/routes',headers={'X-API-KEY':key,'Accept':'application/json','Connection':'close'})
    reply=conn.getresponse();body=reply.read(8388609)
    if reply.status!=200 or len(body)>8388608:raise ValueError()
    sys.stdout.buffer.write(body);sys.stdout.buffer.flush();conn.close()
except BaseException:os._exit(1)
os._exit(0)
'''

def transport_binding(p,dirs,record):
    plan=p['gatewayPlan'];runtime=p.get('gatewayRuntimePlan')
    require(runtime is not None and runtime.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1',
        'EXACT_NUMERIC_MOUNT_SET_RUNTIME_REQUIRED')
    row=record(Path(dirs['gatewayRuntime'])/'recovery.json')
    steps=('disable_restart','stop','rename','create','connect','start','ready','restore_restart')
    require(row['schema']=='ouf.chatbot-file-cohort.gateway-runtime.v1' and
        row['planHash']==digest(runtime) and row['authorityHash']==AUTHORITY and row['budgetReset'] is False and
        row['nextStep']==8 and len(row['effects'])==8 and
        all(e['state']=='APPLIED' and e['step']==s for s,e in zip(steps,row['effects'])),
        'RETAINED_GATEWAY_RUNTIME_INCOMPLETE')
    pin=row['effects'][-1]['evidence']['runtimeBinding']
    require(row['effects'][3]['evidence']['containerId']==pin['containerId'] and
        all(pin[k]==v for k,v in row['effects'][5]['evidence']['runtimeBinding'].items() if k!='hostConfigHash'),
        'RETAINED_GATEWAY_GENERATION_DRIFT')
    actual=engine_get(p['engine'],'containers',pin['containerId'])
    require(actual is not None and runtime_pin(actual)==pin,'GATEWAY_RUNTIME_DRIFT')
    ns=os.stat('/proc/'+str(pin['pid'])+'/ns/net')
    return {'runtimeBinding':pin,'configBinding':runtime['newConfigBinding'],
        'adminKeyBinding':runtime['adminKeyBinding'],'pythonExecutable':runtime['pythonExecutable'],
        'networkNamespace':{'device':ns.st_dev,'inode':ns.st_ino}}

def gateway_check(engine,binding):
    actual=engine_get(engine,'containers',binding['runtimeBinding']['containerId'])
    require(actual is not None and runtime_pin(actual)==binding['runtimeBinding'] and
        actual['Name']=='/ouf-apisix' and actual['State']['Running'] is True and
        actual['State']['Paused'] is False,'GATEWAY_GENERATION_DRIFT')
    mounts=[m for m in actual['Mounts'] if m.get('Destination')=='/usr/local/apisix/conf/config.yaml']
    require(len(mounts)==1 and mounts[0].get('Type')=='bind' and mounts[0].get('RW') is False and
        mounts[0].get('Source')==binding['configBinding']['path'],'GATEWAY_CONFIG_MOUNT_DRIFT')
    raw,_=private_config(binding['configBinding']['path'],binding['configBinding'])
    external=None
    if binding.get('adminKeyBinding') is not None:
        key,_=private_config(EXTERNAL_ADMIN_KEY,binding['adminKeyBinding']);external=key.decode('ascii').strip()
    selected_admin_key(raw,external)
    ns=os.stat('/proc/'+str(actual['State']['Pid'])+'/ns/net')
    require({'device':ns.st_dev,'inode':ns.st_ino}==binding['networkNamespace'],'GATEWAY_NAMESPACE_DRIFT')
    executable(binding['pythonExecutable'])
    return selected_admin_key(raw,external)

def gateway_read(engine,binding):
    key=gateway_check(engine,binding)
    ns=os.open('/proc/'+str(binding['runtimeBinding']['pid'])+'/ns/net',os.O_RDONLY)
    child=None
    try:
        info=os.fstat(ns)
        require({'device':info.st_dev,'inode':info.st_ino}==binding['networkNamespace'],'GATEWAY_NAMESPACE_FD_DRIFT')
        child=subprocess.Popen([binding['pythonExecutable']['path'],'-I','-B','-S','-c',GET_CHILD,str(ns)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(ns,),close_fds=True,
            cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        raw,_=child.communicate(encoded({'key':key}),timeout=15)
        require(child.returncode==0 and 0<len(raw)<=8388608,'GATEWAY_READ_UNAVAILABLE')
        value=json.loads(raw,object_pairs_hook=unique)
        require(type(value)is dict and type(value.get('list'))is list and
            value.get('total')==len(value['list']),'COMPLETE_GATEWAY_INVENTORY_REQUIRED')
        rows=route_map(value['list']);gateway_check(engine,binding);return rows
    finally:
        if child is not None:
            if child.poll()is None:child.kill()
            child.wait(timeout=5)
            for pipe in (child.stdin,child.stdout):
                if pipe is not None:pipe.close()
        os.close(ns)


def environment(values):
    require(type(values)is list and len(values)<=512,'ENVIRONMENT_SHAPE_DRIFT')
    result={}
    for item in values:
        require(type(item)is str and '=' in item,'ENVIRONMENT_ENTRY_DRIFT')
        key,value=item.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key) and key not in result,'ENVIRONMENT_KEY_DRIFT')
        result[key]=value
    return result


def native_state(actual):
    state=actual['State']
    require(state.get('Status') in ('created','running','paused','restarting','removing','exited','dead') and
        all(type(state.get(k))is bool for k in ('Running','Paused','Restarting','Dead')) and
        all(type(state.get(k))is int for k in ('Pid','ExitCode')) and
        type(actual.get('RestartCount'))is int and re.fullmatch('[0-9a-f]{64}',actual['Id']),
        'SAFE_NATIVE_STATE_REQUIRED')
    return dict(containerId=actual['Id'],status=state['Status'],running=state['Running'],paused=state['Paused'],
        restarting=state['Restarting'],dead=state['Dead'],pid=state['Pid'],exitCode=state['ExitCode'],
        restartCount=actual['RestartCount'],neverStarted=state.get('StartedAt')=='0001-01-01T00:00:00Z',
        runtimeHash=digest(runtime_pin(actual)))


def metadata(label,path):
    value=read(path,2097152)
    allowed={}
    for key in ('version','nextPhase','attempts','publicationCount','controlledPredecessorGrantAttempts',
                'controlledCumulativeGrantAttempts','predecessorGrantAttempts','maximumAttempts','maximumElapsedSeconds'):
        if key in value:
            require(type(value[key])is int and 0<=value[key]<=10000000,'SAFE_INTEGER_METADATA_REQUIRED')
            allowed[key]=value[key]
    for key in ('state','phase'):
        if key in value:
            require(type(value[key])is str and re.fullmatch('[A-Z][A-Z0-9_]{0,159}',value[key]),'SAFE_STATE_METADATA_REQUIRED')
            allowed[key]=value[key]
    for key in ('databaseMayHaveChanged','applicationWritesMayHaveOccurred','automaticReplayAllowed','preMigrationRestoreAllowed'):
        if key in value:
            require(type(value[key])is bool,'SAFE_BOOLEAN_METADATA_REQUIRED');allowed[key]=value[key]
    emit(label,recordHash=digest(value),**allowed)
    return value

MODULES=('udp','onboarding','ingestion','mcp')
STAGES=('rename','create','start','ready','restart_policy')
CONFIG_FIELDS=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck ArgsEscaped Image Volumes WorkingDir Entrypoint NetworkDisabled MacAddress OnBuild Labels StopSignal StopTimeout Shell'.split())

def configuration_projection(row,actual,image):
    """Compare exact fields and inherited defaults; classify, never accept."""
    request=row['creationRequest'];config=actual['Config'];defaults=image.get('Config')or{}
    require(image.get('Id')==request['Image'],'EXACT_REQUEST_IMAGE_REQUIRED')
    keys=set(request)-{'HostConfig','NetworkingConfig'}
    keys-={k for k in ('Hostname',)if k in request and not request[k]}
    checks={k:config.get(k)==request[k]for k in keys}
    known={k:v for k,v in checks.items()if k in CONFIG_FIELDS}
    requested=environment(request.get('Env')or[]);inherited=environment(defaults.get('Env')or[])
    observed=environment(config.get('Env')or[])
    merged={**inherited,**requested}
    image_labels=defaults.get('Labels')or{};requested_labels=request.get('Labels')or{}
    return dict(originalProcessPredicateMatches=all(checks.values()),fieldMatches=known,
        unknownRequestedFieldCount=len(keys-CONFIG_FIELDS),
        differingUnknownFieldCount=sum(not checks[k]for k in keys-CONFIG_FIELDS),
        differingFields=sorted(k for k,v in known.items()if not v),
        environmentMatchesImageDefaultsAndRequest=observed==merged,
        environmentRequestedValuesMatch=all(observed.get(k)==v for k,v in requested.items()),
        environmentRequestCount=len(requested),environmentImageDefaultCount=len(inherited),
        environmentObservedCount=len(observed),environmentUnexpectedKeyCount=len(set(observed)-set(merged)),
        environmentMissingKeyCount=len(set(merged)-set(observed)),
        environmentChangedValueCount=sum(k in observed and observed[k]!=v for k,v in merged.items()),
        labelsMatchImageDefaultsAndRequest=config.get('Labels')=={**image_labels,**requested_labels},
        dictionaryFieldsMatchImageDefaultsAndRequest={k:config.get(k)=={**(defaults.get(k)or{}),**(request.get(k)or{})}
            for k in ('ExposedPorts','Volumes')},
        hostFieldMatches={k:actual['HostConfig'].get(k)==v for k,v in request['HostConfig'].items()
            if k in ('NetworkMode','ReadonlyRootfs','Privileged','AutoRemove','RestartPolicy')},
        environmentValuesPrinted=False,labelValuesPrinted=False,configValuesPrinted=False)

def container_checkpoint(plan,journal):
    rows=plan['replacements'];require([r['module']for r in rows]==list(MODULES),'EXACT_FOUR_MODULE_PLAN_REQUIRED')
    steps=[m+'.'+s for m in MODULES for s in STAGES];n=journal.get('nextStep');effects=journal.get('effects')
    require(journal.get('schema')=='ouf.chatbot-cohort-container-journal.v1'
        and journal.get('planHash')==digest(plan) and journal.get('authorityHash')==AUTHORITY
        and journal.get('budgetReset')is False and type(n)is int and 10<=n<20
        and type(effects)is list and len(effects)in(n,n+1)
        and [e['step']for e in effects]==steps[:len(effects)]
        and all(e['state']=='APPLIED'for e in effects[:n])
        and (len(effects)==n or effects[-1]['state']=='CLAIMED'),'EXACT_POST_GATEWAY_CONTAINER_HISTORY_REQUIRED')
    by_module={r['module']:r for r in rows}
    for e in effects:
        module,stage=e['step'].split('.')
        require(e.get('intentHash')==digest({'modulePlan':by_module[module],'stage':stage}),
            'CONTAINER_INTENT_DRIFT')
        if e['state']=='APPLIED':require(e.get('evidenceHash')==digest(e['evidence']),'CONTAINER_EVIDENCE_DRIFT')
    gate=journal.get('gates',{}).get('gateway',{})
    require(gate.get('scopeHash')==plan['gatewayPlanHash'] and
        type(gate.get('evidenceHash'))is str and re.fullmatch('[0-9a-f]{64}',gate['evidenceHash']),
        'COMPLETED_GATEWAY_OWNER_GATE_REQUIRED')
    return {'nextStep':n,'appliedCount':n,'effectCount':len(effects),'pendingStep':steps[n],
        'claimed':len(effects)==n+1,'module':steps[n].split('.')[0],
        'technicalPhase':6 if n<15 else 7}

def completed_gateway(plan,journal):
    changes=plan['changes'];effects=journal.get('effects')
    require(journal.get('schema')=='ouf.chatbot-file-cohort.gateway-publication.v1'
        and journal.get('authorityHash')==AUTHORITY and journal.get('planHash')==digest(plan)
        and journal.get('budgetReset')is False and len(changes)==28
        and journal.get('nextStep')==len(changes) and type(effects)is list and len(effects)==len(changes)
        and all(e.get('state')=='APPLIED' and e.get('routeId')==c['id']
            and e.get('intentHash')==digest(c)for e,c in zip(effects,changes)),
        'EXACT_COMPLETED_GATEWAY_HISTORY_REQUIRED')

CREATED='cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35'

def start_error_metadata(actual):
    """Classify retained Docker text without printing message, paths or values."""
    text=actual['State'].get('Error','')
    require(type(text)is str and len(text.encode())<=65536,'BOUNDED_RETAINED_DOCKER_ERROR_REQUIRED')
    patterns={
        'PERMISSION_DENIED':r'permission denied|operation not permitted|access denied',
        'MOUNT_FAILURE':r'\bmount(?:ing)?\b|bind mount|mountpoint',
        'PORT_CONFLICT':r'address already in use|port is already allocated|port.*in use',
        'MISSING_PATH_OR_EXECUTABLE':r'no such file|executable file not found|not found in.*path',
        'EXEC_FORMAT':r'exec format error',
        'NETWORK_FAILURE':r'network.*not found|network.*endpoint|failed.*network|ip address',
        'OCI_RUNTIME_FAILURE':r'oci runtime|runc|failed to create.*task|shim task',
        'READ_ONLY_FILESYSTEM':r'read-only file system',
        'RESOURCE_EXHAUSTION':r'no space left|cannot allocate memory|resource temporarily unavailable',
        'APPARMOR_OR_SECCOMP':r'apparmor|seccomp',
        'CONTAINER_STATE_CONFLICT':r'already started|already running|marked for removal',
    }
    categories=sorted(k for k,v in patterns.items()if re.search(v,text,re.I))
    return dict(errorPresent=bool(text),errorBytes=len(text.encode()),categories=categories,
        unclassifiedError=bool(text)and not categories,rawErrorPrinted=False,
        historicalStartHttpStatusAvailable=False)

def start_generation(row,actual,journal):
    require(actual is not None and actual['Id']==CREATED,'EXACT_CREATED_INGESTION_REQUIRED')
    effects={e['step']:e for e in journal['effects']}
    created=effects['ingestion.create']
    require(created['state']=='APPLIED' and created['evidence']['containerId']==CREATED
        and actual['Image']==created['evidence']['imageId']
        and digest(actual['Config'])==created['evidence']['configHash']
        and digest(actual['Mounts'])==created['evidence']['mountsHash'],
        'INGESTION_CREATED_EVIDENCE_DRIFT')
    claimed=effects['ingestion.start']
    require(claimed['state']=='CLAIMED','EXACT_CLAIMED_INGESTION_START_REQUIRED')
    return dict(createEvidenceHash=created['evidenceHash'],startIntentHash=claimed['intentHash'],
        sameCreatedContainer=True,startClaimPreserved=True)

def execution_contract(row,actual,image):
    """Read process/PATH metadata only; never execute the selected command."""
    request=row['creationRequest'];defaults=image.get('Config')or{}
    require(image.get('Id')==request['Image'],'EXACT_REQUEST_IMAGE_REQUIRED')
    requested=environment(request.get('Env')or[]);inherited=environment(defaults.get('Env')or[])
    planned={**inherited,**requested};observed=environment(actual['Config'].get('Env')or[])
    entry=actual['Config'].get('Entrypoint')or[]
    require(type(entry)is list and all(type(v)is str for v in entry),'BOUNDED_PROCESS_CONTRACT_REQUIRED')
    error=actual['State'].get('Error','');require(type(error)is str and len(error.encode())<=65536,'BOUNDED_RETAINED_DOCKER_ERROR_REQUIRED')
    argv0=entry[0]if entry else''
    path=observed.get('PATH','').split(':');image_path=inherited.get('PATH','').split(':')
    home=inherited.get('JAVA_HOME')or inherited.get('JRE_HOME')
    java_bin=(home.rstrip('/')+'/bin')if home else None
    return dict(entrypointMatchesImage=entry==(defaults.get('Entrypoint')or[]),
        entrypointMatchesRequest=entry==(request.get('Entrypoint')or[]),
        entrypointArgumentCount=len(entry),entrypointIsJava=bool(argv0)and argv0.rsplit('/',1)[-1]=='java',
        entrypointUsesPathSearch=bool(argv0)and '/'not in argv0,
        runtimePathSource='REQUEST_OVERRIDE'if 'PATH'in requested else'IMAGE_DEFAULT'if 'PATH'in inherited else'ABSENT',
        requestOverridesImagePath='PATH'in requested and requested.get('PATH')!=inherited.get('PATH'),
        requestOverridesImageJavaHome='JAVA_HOME'in requested and requested.get('JAVA_HOME')!=inherited.get('JAVA_HOME'),
        runtimePathMatchesImage=observed.get('PATH')==inherited.get('PATH'),
        runtimeJavaHomeMatchesImage=observed.get('JAVA_HOME')==inherited.get('JAVA_HOME'),
        plannedPathMatchesImage=planned.get('PATH')==inherited.get('PATH'),
        imageJavaHomePresent=bool(home),imageJavaBinOnImagePath=java_bin is not None and java_bin in image_path,
        imageJavaBinOnRuntimePath=java_bin is not None and java_bin in path,
        pathSearchFailure=bool(re.search(r'executable file not found in \$PATH',error,re.I)),
        retainedErrorMentionsEntrypoint=bool(argv0)and argv0 in error,
        missingFileFailure=bool(re.search(r'no such file or directory',error,re.I)),
        rawErrorPrinted=False,processValuesPrinted=False,environmentValuesPrinted=False)

def main():
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READER_REQUIRED')
    signal.alarm(180)
    emit('BEGIN',maximumSeconds=180,maximumGatewayReads=2,backupArchiveReads=0,databaseCalls=0,
        databaseMutations=0,dumpProbes=0,gatewayWrites=0,grantRequests=0,iamCalls=0,mcpCalls=0,serviceMutations=0)
    review=read(CONTEXT/'review.json',8388608,REVIEW);authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority[k]==v for k,v in review['scopes'].items()),'EXACT_RETAINED_AUTHORITY_REQUIRED')
    process=review['scopes']['finiteActionProcess'];programs=review['sourceClosure']['executables']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    stopped(programs['systemctl'])
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    snapshots={}
    def record(path,maximum=2097152):
        path=Path(path);value=read(path,maximum);snapshots[path]=value;return value
    decision=record(CONTEXT/'decision.json');require(decision.get('approvedReviewHash')==REVIEW
        and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('expiresAt')==authority['expiresAt'],'RETAINED_DECISION_DRIFT')
    status=record(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='COHORT_START_REQUIRES_RECONCILIATION','EXACT_CONTAINER_PAUSE_REQUIRED')
    emit('RETAINED_DELIVERY',recordHash=digest(status),authorityExpiredAtRead=time.time()>=authority['expiresAt'])
    dirs=process['directoryPlan'];plan=p['cohortPlan']
    require(digest(plan)==review['scopes']['applicationCohortInstallation']['planHash']
        and plan['gatewayPlanHash']==digest(p['gatewayPlan']),'REVIEWED_COHORT_PLAN_DRIFT')
    journal=record(Path(dirs['containers'])/'recovery.json');checkpoint=container_checkpoint(plan,journal)
    emit('CONTAINER_CHECKPOINT',recordHash=digest(journal),**checkpoint)
    require(checkpoint['nextStep']==12 and checkpoint['pendingStep']=='ingestion.start' and checkpoint['claimed'],
        'EXACT_INGESTION_START_BOUNDARY_REQUIRED')
    worker=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(worker)==p['postGrantWorkerDirectory'],'CURRENT_WORKER_DIRECTORY_DRIFT')
    for filename,label in (('recovery.json','WORKER'),('owner-session.json','WORKER_SESSION'),('owner-admission.json','WORKER_ADMISSION')):
        path=worker/filename;record(path);metadata(label,path)
    db=record(Path(dirs['databases'])/'recovery.json')
    require(db.get('authorityHash')==AUTHORITY and db.get('planHash')==digest(p['databasePlan']),
        'DATABASE_JOURNAL_SCOPE_DRIFT')
    emit('DATABASE_CHECKPOINT',recordHash=digest(db),migrationState=db['mcpMigration']['state'],
        auditRoleState=db['mcpAuditRole']['state'],archiveStates={m:db['backups'][m]['state']for m in MODULES})
    routes=record(Path(dirs['gateway'])/'recovery.json');completed_gateway(p['gatewayPlan'],routes)
    transport=transport_binding(p,dirs,record)
    first=gateway_read(p['engine'],transport);second=gateway_read(p['engine'],transport)
    emit('GATEWAY_ROUTES',recordHash=digest(routes),completedNewChanges=routes['nextStep'],
        firstMapHash=digest(first),secondMapHash=digest(second),stable=first==second,
        matchesFinalPlan=first==p['gatewayPlan']['proposedRoutes'],routeCount=len(first),routeValuesPrinted=False)
    require(first==second and first==p['gatewayPlan']['proposedRoutes'],'GATEWAY_FINAL_MAP_DRIFT')
    observations=[]
    for row in plan['replacements']:
        actual=engine_get(p['engine'],'containers',row['name']);observations.append((row['name'],actual))
        replacement=actual is not None and actual['Id']!=row['oldRuntimeBinding']['containerId']
        emit('MODULE_NATIVE',module=row['module'],present=actual is not None,replacementPresent=replacement,
            **(native_state(actual)if actual is not None else{}))
        if row['module']=='ingestion':
            emit('INGESTION_START_GENERATION',**start_generation(row,actual,journal))
            emit('INGESTION_RETAINED_START_ERROR',**start_error_metadata(actual))
        if replacement:
            image=engine_get(p['engine'],'images',row['creationRequest']['Image'])
            emit('MODULE_CONFIG_COMPARISON',module=row['module'],**configuration_projection(row,actual,image))
            emit('MODULE_EXECUTION_CONTRACT',module=row['module'],**execution_contract(row,actual,image))
    gateway_check(p['engine'],transport);stopped(programs['systemctl'])
    for name,value in observations:require(engine_get(p['engine'],'containers',name)==value,'NATIVE_CHANGED_DURING_READ')
    for path,value in snapshots.items():require(read(path,8388608)==value,'RETAINED_RECORD_CHANGED_DURING_READ')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    emit('END',complete=True,technicalPhase=checkpoint['technicalPhase'],functionalMilestonesProven=0,
        technicalPhase5Verified=True,stableGatewayReads=True,retainedRecordsUnchanged=True,
        backupArchiveReads=0,databaseCalls=0,databaseMutations=0,dumpProbes=0,gatewayWrites=0,
        grantRequests=0,iamCalls=0,mcpCalls=0,serviceMutations=0,reconciliationPerformed=False,
        runtimeAuthorityIssued=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)

