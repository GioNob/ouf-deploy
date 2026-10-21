#!/usr/bin/env python3
"""Installation-specific private review of a Registry upstream binding correction."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time

from pathlib import Path

from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-upstream-preparation.v1',check=check,readOnly=False,
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
                        require(len(errors)+len(raw)<=maximum,'DIAGNOSTIC_STDERR_BOUND_EXHAUSTED')
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

def live_process(binding):
    code,raw,_,_=bounded([executable(binding),'show',UNIT,'--property=ActiveState,MainPID,Job'])
    values=dict(line.split('=',1)for line in raw.decode().splitlines()if '='in line)
    require(code==0 and values.get('ActiveState')=='active' and values.get('MainPID')=='3733354'
        and values.get('Job')=='','EXACT_FINITE_DELIVERY_NOT_ACTIVE')

def lua_constant(route,name):
    functions=route.get('plugins',{}).get('serverless-post-function',{}).get('functions',[])
    require(type(functions)is list and len(functions)==1,'ONE_RETAINED_FUNCTION_REQUIRED')
    found=re.findall(r'local '+re.escape(name)+r' = ("[^"\n]*")',functions[0])
    require(len(found)==1,'ONE_CLOSED_ENV_REFERENCE_REQUIRED')
    value=json.loads(found[0]);require(re.fullmatch('[A-Z][A-Z0-9_]{0,127}',value),'CLOSED_ENV_REFERENCE_REQUIRED')
    return value

def nginx_environment(raw):
    text=raw.decode();marker='nginx_config:\n  envs:\n'
    require(text.count(marker)==1,'EXACT_NGINX_ENV_ALLOWLIST_REQUIRED')
    result=[]
    for line in text.split(marker,1)[1].splitlines():
        m=re.fullmatch(r'  - ([A-Z][A-Z0-9_]{0,127})',line)
        if not m:break
        require(m[1]not in result,'DUPLICATE_ENV_ALLOWLIST');result.append(m[1])
    require(result,'NONEMPTY_ENV_ALLOWLIST_REQUIRED');return result

def log_metadata(raw):
    text=raw.decode('utf-8',errors='replace');counts={}
    paths={'/internal/capabilities/v1/execute/semantic/search':'gatewaySemanticSearch',
        '/internal/capabilities/v1/execute/semantic/get':'gatewaySemanticGet',
        '/api/internal/v1/semantic/consultation/search':'ownerSemanticSearch',
        '/api/internal/v1/semantic/consultation/get':'ownerSemanticGet'}
    for line in text.splitlines():
        m=re.search(r'"(?:GET|POST) ([^ ?"]+)(?:\?[^ "]*)? HTTP/[0-9.]+" ([1-5][0-9]{2})(?: |$)',line)
        if m and m[1]in paths:
            key=paths[m[1]]+':'+m[2];counts[key]=counts.get(key,0)+1
    markers={
        'UPSTREAM_CONNECTION_REFUSED':r'connect\(\) failed.*Connection refused',
        'UPSTREAM_DNS_FAILURE':r'could not be resolved|host not found|failed to resolve',
        'NO_LIVE_UPSTREAMS':r'no live upstreams|no valid upstream',
        'UPSTREAM_TIMEOUT':r'upstream timed out',
        'LUA_RUNTIME_ERROR':r'lua entry thread aborted|attempt to call|attempt to index',
        'SEMANTIC_RECEIPT_CONFIG':r'SEM_READ_DELEGATION_CONFIG_INVALID|SEM_READ_DELEGATION_KEY_UNAVAILABLE',
        'SEMANTIC_RECEIPT_DENIED':r'SEM_READ_RECEIPT_INVALID|SEM_READ_RECEIPT_OR_POLICY_DENIED',
        'DATABASE_CONNECTION_FAILURE':r'Connection refused|CannotGetJdbcConnectionException|SQLTransientConnectionException',
        'AUTHORIZATION_UNAVAILABLE':r'AUTHORIZATION_UNAVAILABLE|AUTHZ_UNAVAILABLE|POLICY_UNAVAILABLE',
    }
    return dict(httpStatusCounts=counts,classifiedMarkerCounts={k:len(re.findall(v,text,re.I))for k,v in markers.items()},
        rawLinesPrinted=False,rawDiagnosticPrinted=False,diagnosisFromMarkerAlone=False)

DNS_CHILD=r'''import ipaddress,json,os,re,signal,socket,struct,sys
signal.alarm(25)
try:
    stage='INPUT';data=json.loads(sys.stdin.buffer.read(32769));fd=int(sys.argv[1]);stage='NAMESPACE';os.setns(fd,0);os.close(fd)
    queries=data['queries'];allowed=set(data['registryAddresses']);resolver=str(ipaddress.ip_address(data['resolver']))
    if not 0<len(queries)<=4 or not 0<len(allowed)<=4:raise ValueError()
    result=[]
    def skip_name(raw,pos):
        for _ in range(128):
            n=raw[pos];pos+=1
            if n==0:return pos
            if n&192==192:return pos+1
            if n>63:raise ValueError()
            pos+=n
        raise ValueError()
    for query in queries:
        stage='QUERY_NAME';host=query['host'];port=query['port'];addresses=[];rcode=0;dns_unavailable=False
        if type(port)is not int or not 1<=port<=65535:raise ValueError()
        try:addresses=[str(ipaddress.ip_address(host))]
        except ValueError:
            if type(host)is not str or len(host)>253 or not re.fullmatch(r'[A-Za-z0-9_.-]+',host):raise ValueError()
            labels=host.rstrip('.').split('.')
            if not all(0<len(v)<=63 for v in labels):raise ValueError()
            token=os.urandom(2);name=b''.join(bytes([len(v)])+v.encode('ascii')for v in labels)+b'\0'
            request=token+struct.pack('!HHHHH',256,1,0,0,0)+name+struct.pack('!HH',1,1)
            stage='DNS_RESPONSE';family=socket.AF_INET6 if ':'in resolver else socket.AF_INET
            try:
                with socket.socket(family,socket.SOCK_DGRAM)as conn:
                    conn.settimeout(2);conn.connect((resolver,53));conn.send(request);raw=conn.recv(8192)
            except OSError:
                dns_unavailable=True;raw=token+struct.pack('!HHHHH',0x8002,0,0,0,0)
            if raw[:2]!=token or len(raw)<12:raise ValueError()
            flags,questions,answers,_,_=struct.unpack('!HHHHH',raw[2:12]);rcode=flags&15;pos=12
            if questions>4 or answers>32 or flags&512:raise ValueError()
            for _ in range(questions):pos=skip_name(raw,pos)+4
            for _ in range(answers):
                pos=skip_name(raw,pos);kind,klass,ttl,size=struct.unpack('!HHIH',raw[pos:pos+10]);pos+=10
                value=raw[pos:pos+size];pos+=size
                if klass==1 and kind==1 and size==4:addresses.append(socket.inet_ntop(socket.AF_INET,value))
        stage='TCP';addresses=sorted(set(addresses));matches=[v for v in addresses if v in allowed];reachable=False
        for value in matches[:4]:
            try:
                with socket.create_connection((value,port),timeout=2):reachable=True
            except OSError:pass
        direct=False
        for value in sorted(allowed)[:4]:
            try:
                with socket.create_connection((value,port),timeout=2):direct=True
            except OSError:pass
        result.append({'rcode':rcode,'dnsUnavailable':dns_unavailable,'addressCount':len(addresses),'matchesRegistry':bool(matches),
            'onlyRegistryAddresses':bool(addresses)and set(addresses)<=allowed,
            'matchedTcpReachable':reachable,'directRegistryTcpReachable':direct})
    sys.stdout.write(json.dumps(result));sys.stdout.flush()
except BaseException as error:
    sys.stdout.write(json.dumps({'probeFailure':locals().get('stage','INPUT'),'exceptionClass':type(error).__name__}));sys.stdout.flush()
    os._exit(1)
os._exit(0)
'''

def resolver_selection(actual):
    path=Path(actual.get('ResolvConfPath',''))
    require(path.is_absolute()and path.name=='resolv.conf'and path.parent.name==actual['Id']
        and path.resolve()==path,'SELECTED_CONTAINER_RESOLVER_PATH_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode)and before.st_uid==0 and not before.st_mode&0o022
            and before.st_nlink==1 and 0<before.st_size<=16384,'RESOLVER_FILE_CUSTODY_DRIFT')
        raw=os.read(fd,16385)
        require(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
            'RESOLVER_SELECTION_CHANGED')
    finally:os.close(fd)
    import ipaddress
    servers=[str(ipaddress.ip_address(line.split()[1]))for line in raw.decode('ascii').splitlines()
        if re.match(r'^nameserver +[^ ]+',line)]
    require(0<len(servers)<=3,'BOUNDED_CONFIGURED_DNS_RESOLVER_REQUIRED');return servers[0]

def upstream_metadata(prepared,routes,gateway,registry,transport):
    import ipaddress
    selected=[v for v in routes.values()if v.get('uri')=='/internal/capabilities/v1/execute/semantic/search']
    require(len(selected)==1,'EXACT_SEMANTIC_ROUTE_REQUIRED');upstream=selected[0].get('upstream')
    require(type(upstream)is dict and type(upstream.get('nodes'))is dict
        and 0<len(upstream['nodes'])<=4,'BOUNDED_INLINE_UPSTREAM_REQUIRED')
    nodes=upstream['nodes'];queries=[];alias_matches=[];common=[];addresses=set();aliases={registry['Name'].lstrip('/')}
    for name,net in registry['NetworkSettings'].get('Networks',{}).items():
        peer=gateway['NetworkSettings'].get('Networks',{}).get(name)
        if peer and peer.get('NetworkID')==net.get('NetworkID'):
            common.append(name);aliases.update(net.get('Aliases')or[])
            if net.get('IPAddress'):addresses.add(str(ipaddress.ip_address(net['IPAddress'])))
    require(common and 0<len(addresses)<=4,'SELECTED_REGISTRY_NETWORK_REQUIRED')
    for node,weight in sorted(nodes.items()):
        host,sep,port=node.rpartition(':');require(sep and port.isdigit()and 1<=int(port)<=65535
            and type(weight)in(int,float)and 0<weight<=1000,'BOUNDED_REVIEWED_UPSTREAM_NODE_REQUIRED')
        queries.append({'host':host,'port':int(port)});alias_matches.append(host in aliases or host in addresses)
    resolver=resolver_selection(gateway);gateway_check(prepared['engine'],transport)
    fd=os.open('/proc/'+str(gateway['State']['Pid'])+'/ns/net',os.O_RDONLY);child=None
    try:
        info=os.fstat(fd);require({'device':info.st_dev,'inode':info.st_ino}==transport['networkNamespace'],'SELECTED_NAMESPACE_DRIFT')
        child=subprocess.Popen([executable(transport['pythonExecutable']),'-I','-B','-S','-c',DNS_CHILD,str(fd)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),close_fds=True,
            cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        raw,_=child.communicate(encoded({'queries':queries,'registryAddresses':sorted(addresses),'resolver':resolver}),timeout=30)
        require(0<len(raw)<=32768,'BOUNDED_NAMESPACE_DNS_READ_UNAVAILABLE')
        observed=json.loads(raw,object_pairs_hook=unique)
        if type(observed)is dict and observed.get('probeFailure')in('INPUT','NAMESPACE','QUERY_NAME','DNS_RESPONSE','TCP'):
            require(False,'DNS_PROBE_FAILED_AT_'+observed['probeFailure'])
        require(child.returncode==0,'BOUNDED_NAMESPACE_DNS_READ_UNAVAILABLE')
        require(type(observed)is list and len(observed)==len(queries),
            'EXACT_DNS_RESULT_COUNT_REQUIRED')
    finally:
        if child is not None:
            if child.poll()is None:child.kill()
            child.wait(timeout=5)
            for pipe in (child.stdin,child.stdout):
                if pipe is not None:pipe.close()
        os.close(fd)
    checks=upstream.get('checks')or{};active=checks.get('active')or{}
    return dict(nodeCount=len(nodes),commonNetworkCount=len(common),configuredAliasesMatchCurrentRegistry=alias_matches,
        dnsAndTcp=observed,activeHealthCheckConfigured=bool(active),passiveHealthCheckConfigured=bool(checks.get('passive')),
        activeHealthPathIsReadiness=active.get('http_path')in('/actuator/health/readiness','/health/ready'),
        referencesPrinted=False,addressesPrinted=False,configurationModified=False)


def compile_binding_repair(plan,registry,request):
    import copy
    binding=plan.get('upstreamBindings',{}).get('ouf-semantic-registry')
    require(type(binding)is dict and type(binding.get('alias'))is str and type(binding.get('port'))is int,
        'RETAINED_REVIEWED_REGISTRY_BINDING_REQUIRED')
    import ipaddress
    endpoints=request.get('NetworkingConfig',{}).get('EndpointsConfig',{})
    require(type(endpoints)is dict and len(endpoints)==1,'ONE_REVIEWED_STATIC_REGISTRY_NETWORK_REQUIRED')
    name,endpoint=next(iter(endpoints.items()));network=registry['NetworkSettings']['Networks'].get(name)
    require(type(network)is dict and endpoint.get('NetworkID')==network.get('NetworkID')==binding.get('networkId')
        and endpoint.get('IPAMConfig',{}).get('IPv4Address')==network.get('IPAddress'),
        'REVIEWED_STATIC_REGISTRY_ADDRESS_DRIFT')
    current=str(ipaddress.IPv4Address(network['IPAddress']))
    require(current!=binding['alias'],'DISTINCT_CURRENT_REGISTRY_ADDRESS_REQUIRED')
    old=binding['alias']+':'+str(binding['port']);new=current+':'+str(binding['port'])
    before=plan['proposedRoutes'];after=copy.deepcopy(before);changes=[]
    for rid,row in sorted(after.items()):
        nodes=row.get('upstream',{}).get('nodes')
        if type(nodes)is not dict or old not in nodes:continue
        require(new not in nodes,'REGISTRY_BINDING_NODE_COLLISION')
        weight=nodes.pop(old);nodes[new]=weight
        changes.append({'routeId':rid,'before':copy.deepcopy(before[rid]),'after':copy.deepcopy(row)})
    require(0<len(changes)<=32,'BOUNDED_REGISTRY_ROUTE_CHANGES_REQUIRED')
    selected={v['after'].get('uri')for v in changes}
    require({'/internal/capabilities/v1/execute/semantic/search',
        '/internal/capabilities/v1/execute/semantic/get'}<=selected,'SEMANTIC_BINDINGS_NOT_INCLUDED')
    return {'schema':'ouf.chatbot-semantic-upstream-repair-review.v1','oldBinding':binding,
        'proposedBinding':{'host':current,'profile':'ouf.reviewed-retained-static-registry-address.v1',
            'networkId':binding['networkId'],'creationRequestHash':digest(request),
            'port':binding['port'],'runtimeBinding':runtime_pin(registry)},
        'beforeMapHash':digest(before),'afterMapHash':digest(after),'changes':changes,
        'proposedRoutes':after,'automaticWriteReplayAllowed':False,'runtimeAuthorityIssued':False,
        'databaseRestoreAuthorized':False,'serviceLifecycleAuthorized':False,'newGrantAuthorized':False,
        'budgetReset':False,'notReleaseAcceptance':True}

def stage_binding_review(value):
    parent=CONTEXT.parent
    require(parent==Path('/etc/ouf/deploy-snapshots'),'EXACT_PRIVATE_REVIEW_PARENT_REQUIRED')
    for part in (parent,*parent.parents):
        info=part.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,
            'ROOT_REVIEW_ANCESTRY_REQUIRED')
    raw=encoded(value);require(len(raw)<=8388608,'BOUNDED_PRIVATE_REVIEW_REQUIRED')
    fingerprint=hashlib.sha256(raw).hexdigest();folder=parent/('semantic-upstream-review-'+fingerprint)
    try:folder.mkdir(mode=0o700)
    except FileExistsError:
        require(folder.resolve()==folder and folder.lstat().st_uid==0
            and stat.S_IMODE(folder.lstat().st_mode)==0o700,'PRIVATE_REVIEW_DIRECTORY_DRIFT')
        require(read(folder/'review.json',8388608,fingerprint)==value,'PRIVATE_REVIEW_CONTENT_DRIFT')
        return str(folder/'review.json'),fingerprint,0
    target=folder/'review.json'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(read(target,8388608,fingerprint)==value,'PRIVATE_REVIEW_WRITE_DRIFT')
    return str(target),fingerprint,1

def main():
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READER_REQUIRED');signal.alarm(180)
    emit('BEGIN',maximumSeconds=180,maximumGatewayReads=3,maximumLogReads=0,
        databaseCalls=0,backupArchiveReads=0,dumpProbes=0,grantRequests=0,iamCalls=0,mcpCalls=0,
        gatewayWrites=0,serviceMutations=0)
    review=read(CONTEXT/'review.json',8388608,REVIEW);authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority[k]==v for k,v in review['scopes'].items()),'EXACT_RETAINED_AUTHORITY_REQUIRED')
    process=review['scopes']['finiteActionProcess'];programs=review['sourceClosure']['executables']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_LIVE_PROCESS_REQUIRED')
    live_process(programs['systemctl'])
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    status=read(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')in
        ('ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED','CSV_ACCEPTANCE_EVIDENCE_UNAVAILABLE','COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE'),
        'FINITE_CSV_WINDOW_NOT_READY')
    emit('CURRENT_WINDOW',phase=status['phase'],authorityExpiredAtRead=time.time()>=authority['expiresAt'],
        authorityExpiresAt=authority['expiresAt'],permanentRuntimeAcceptance=False)
    dirs=process['directoryPlan'];snapshots={}
    def record(path):
        value=read(path,2097152);snapshots[Path(path)]=value;return value
    routes=record(Path(dirs['gateway'])/'recovery.json');completed_gateway(p['gatewayPlan'],routes)
    transport=transport_binding(p,dirs,record);first=gateway_read(p['engine'],transport);second=gateway_read(p['engine'],transport)
    require(first==second==p['gatewayPlan']['proposedRoutes'],'GATEWAY_MAP_DRIFT')
    emit('GATEWAY_ROUTES',routeCount=len(first),stable=True,matchesFinalPlan=True,routeMapHash=digest(first))
    gateway=engine_get(p['engine'],'containers',transport['runtimeBinding']['containerId'])
    env=environment(gateway['Config'].get('Env')or[])
    raw,_=private_config(transport['configBinding']['path'],transport['configBinding']);exposed=nginx_environment(raw)
    for label,path in [('semanticSearch','/internal/capabilities/v1/execute/semantic/search'),
                       ('semanticGet','/internal/capabilities/v1/execute/semantic/get')]:
        selected=[v for v in first.values()if v.get('uri')==path];require(len(selected)==1,'EXACT_SEMANTIC_ROUTE_REQUIRED')
        route=selected[0]
        for role,constant in [('delegation','DELEGATION_KEY_ENV'),('owner','OWNER_KEY_ENV')]:
            name=lua_constant(route,constant);value=env.get(name)
            emit('GATEWAY_SIGNING_CONFIGURATION',route=label,keyRole=role,referencePresent=name in env,
                hex64=type(value)is str and re.fullmatch('[0-9a-fA-F]{64}',value)is not None,
                exposedByNginxConfiguration=name in exposed,valuesPrinted=False,referencesPrinted=False)
    reg_id='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
    registry=engine_get(p['engine'],'containers',reg_id);require(registry is not None,'RETAINED_REGISTRY_ABSENT')
    emit('REGISTRY_NATIVE',**native_state(registry))
    observations=[(gateway['Id'],gateway),(reg_id,registry)]
    require(digest(runtime_pin(registry))=='09376b5f06f4ce547eddf7801cb913005374cda1179ae78807292bf2fa48badb',
        'DIAGNOSED_REGISTRY_GENERATION_DRIFT')
    require(time.time()<authority['expiresAt'],'EXISTING_FINITE_WINDOW_EXPIRED')
    old_observation=upstream_metadata(p,first,gateway,registry,transport)
    emit('REGISTRY_NAME_DNS_SHAPE',nameLength=len(registry['Name'].lstrip('/')),
        maximumLabelLength=max(map(len,registry['Name'].lstrip('/').rstrip('.').split('.'))),
        dnsLabelLengthsValid=all(0<len(v)<=63 for v in registry['Name'].lstrip('/').rstrip('.').split('.')),
        valuesPrinted=False)
    repair=compile_binding_repair(p['gatewayPlan'],registry,p['registry']['creationRequest'])
    candidate=upstream_metadata(p,repair['proposedRoutes'],gateway,registry,transport)
    require(all(candidate['configuredAliasesMatchCurrentRegistry'])and all(v['rcode']==0
        and not v['dnsUnavailable']and v['onlyRegistryAddresses']and v['matchedTcpReachable']
        for v in candidate['dnsAndTcp']),'PROPOSED_REGISTRY_DNS_AND_TCP_NOT_PROVEN')
    repair.update(predecessorAuthorityHash=AUTHORITY,predecessorReviewHash=REVIEW,
        authorityExpiresAt=authority['expiresAt'],oldObservation=old_observation,candidateObservation=candidate,
        gatewayRuntimeBinding=runtime_pin(gateway),transportBinding=transport,
        projectionBinding=p['gatewayPlan']['projectionBinding'],readerSourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        unchangedRouteCount=len(first)-len(repair['changes']))
    emit('PROPOSED_BINDING_CHECKED',changedRouteCount=len(repair['changes']),
        unchangedRouteCount=repair['unchangedRouteCount'],candidateDnsAndTcpProven=True,
        aliasValuesPrinted=False,routeValuesPrinted=False,
        proposedBindingProfile='ouf.reviewed-retained-static-registry-address.v1')
    gateway_check(p['engine'],transport);live_process(programs['systemctl'])
    for cid,actual in observations:
        following=engine_get(p['engine'],'containers',cid)
        require(following is not None and runtime_pin(following)==runtime_pin(actual),'LIVE_GENERATION_DRIFT')
    for path,value in snapshots.items():require(read(path,8388608)==value,'RETAINED_JOURNAL_DRIFT')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    require(gateway_read(p['engine'],transport)==first and time.time()<authority['expiresAt'],
        'GATEWAY_OR_WINDOW_CHANGED_BEFORE_REVIEW')
    path,fingerprint,writes=stage_binding_review(repair)
    emit('PRIVATE_REPAIR_REVIEW_READY_NOT_AUTHORIZED',reviewPath=path,reviewHash=fingerprint,
        privateEvidenceWrites=writes,changedRouteCount=len(repair['changes']),targetApplyAuthorized=False)
    emit('END',complete=True,completedTechnicalPhases=8,functionalMilestonesProven=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,budgetResetPreserved=True,
        databaseCalls=0,backupArchiveReads=0,dumpProbes=0,grantRequests=0,iamCalls=0,mcpCalls=0,
        gatewayWrites=0,serviceMutations=0,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)
