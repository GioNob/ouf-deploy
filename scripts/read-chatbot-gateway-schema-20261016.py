#!/usr/bin/env python3
"""Fixed incident schema/image readback: GET only, no SQL or backup reads."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time

from pathlib import Path

from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5')

REVIEW='bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144'

AUTHORITY='0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8'

SOURCE='70af66b26d9a8dfdd7151c55f44eb5795fcc84a8'

UNIT='ouf-file-cohort-35d5c6c756feb9c4811ac6d24610698a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-gateway-schema-readback.v1',check=check,readOnly=True,
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
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}

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
    if runtime is None:return plan['transportBinding']
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

SAFE_KEYS=set('id uri uris name desc methods host hosts remote_addr remote_addrs priority status plugins upstream upstream_id timeout enable_websocket pass_host scheme type nodes checks retries retry_timeout connect send read labels vars filter_func service_id script plugin_config_id weight upstream_host openid-connect proxy-rewrite cors jwt-auth serverless-pre-function limit-req redirect headers add set remove bearer_only client_id client_secret discovery introspection_endpoint public_key realm scope ssl_verify access_token_in_authorization_header use_jwks token_signing_alg_values_expected unauth_action session lifetime http_version keepalive_pool size idle_timeout requests'.split())

SAFE_NUMERIC={'priority','status','retries','retry_timeout','weight','connect','send','read'}

def difference(expected,observed):
    """Only structural field names, types and whitelisted numeric defaults."""
    counts={};samples=[];visited=0
    def kind(v):return 'null' if v is None else {dict:'object',list:'array',str:'string',bool:'boolean',int:'number',float:'number'}.get(type(v),'invalid')
    def add(path,reason,left,right):
        counts[reason]=counts.get(reason,0)+1
        if len(samples)<64:
            row={'path':path,'difference':reason,'expectedType':kind(left),'observedType':kind(right)}
            key=path.rsplit('/',1)[-1]
            if key in SAFE_NUMERIC:
                for label,value in (('expected',left),('observed',right)):
                    if type(value) in (int,float) and abs(value)<=1000000:row[label]=value
            samples.append(row)
    def walk(a,b,path,depth):
        nonlocal visited
        visited+=1;require(visited<=50000 and depth<=32,'ROUTE_DIFF_BOUND_EXHAUSTED')
        if type(a)is not type(b):add(path,'TYPE',a,b)
        elif type(a)is dict:
            for key in sorted(set(a)|set(b)):
                shown=key if key in SAFE_KEYS else '<redacted-key>'
                nextpath=path+'/'+shown
                if key not in a:add(nextpath,'UNEXPECTED_FIELD',None,b[key])
                elif key not in b:add(nextpath,'MISSING_FIELD',a[key],None)
                else:walk(a[key],b[key],nextpath,depth+1)
        elif type(a)is list:
            if len(a)!=len(b):add(path,'ARRAY_LENGTH',a,b)
            for i,(x,y) in enumerate(zip(a,b)):walk(x,y,path+'/'+str(i),depth+1)
        elif a!=b:add(path,'VALUE',a,b)
    walk(expected,observed,'',0)
    return {'differenceCount':sum(counts.values()),'fieldCounts':counts,'samples':samples,
        'samplesTruncated':sum(counts.values())>len(samples),'privateValuesPrinted':False,'unknownKeysPrinted':False}

def gateway_projection(plan,journal,observed):
    before=plan['previousRoutes'];after=plan['proposedRoutes'];changes=plan['changes'];n=journal['nextStep']
    require(plan['schema']=='ouf.chatbot-file-cohort.gateway-publication.v1' and
        plan['previousRuntimeHash']==digest(before) and plan['proposedRuntimeHash']==digest(after) and
        route_map(list(before.values()))==before and route_map(list(after.values()))==after and
        set(before)<=set(after) and changes==[{'id':k,'before':before.get(k),'after':after[k]} for k in sorted(after) if before.get(k)!=after[k]],
        'GATEWAY_PLAN_DRIFT')
    require(journal['planHash']==digest(plan) and journal['authorityHash']==AUTHORITY and
        journal['budgetReset'] is False and type(n)is int and 0<=n<len(changes) and
        len(journal['effects'])==n+1 and
        all(e['routeId']==changes[i]['id'] and e['intentHash']==digest(changes[i]) and
            e['state']==('APPLIED' if i<n else 'CLAIMED') for i,e in enumerate(journal['effects'])),
        'EXACT_GATEWAY_CLAIM_REQUIRED')
    current=dict(before)
    for change in changes[:n]:current[change['id']]=change['after']
    target=changes[n]['id'];expected={**current,target:changes[n]['after']}
    differing=sorted(k for k in set(expected)|set(observed) if expected.get(k)!=observed.get(k))
    details=[]
    for key in differing[:16]:
        details.append({'routeIdHash':digest(key),'claimedRoute':key==target,
            'expectedPresent':key in expected,'observedPresent':key in observed,
            **difference(expected.get(key),observed.get(key))})
    return {'journalHash':digest(journal),'nextStep':n,'totalChanges':len(changes),'appliedCount':n,
        'claimIntentHash':journal['effects'][-1]['intentHash'],'claimedRouteIdHash':digest(target),
        'observedMapHash':digest(observed),'expectedAfterClaimMapHash':digest(expected),
        'matchesBeforeClaim':observed==current,'matchesAfterClaim':observed==expected,
        'matchesFinalPlan':observed==after,'claimedRoutePresent':target in observed,
        'claimedRouteMatchesExpected':observed.get(target)==expected[target],
        'differingRouteCount':len(differing),'unrelatedDifferingRouteCount':sum(k!=target for k in differing),
        'routeDifferences':details,'routeDifferencesTruncated':len(differing)>16,
        'writeAcknowledgementRetained':False,'routeValuesPrinted':False,'routeNamesPrinted':False}

EXPECTED_JOURNAL='9d1c903c6290dca22c28c601ccfda33f440d06f6079ff7e7d104584c99b6a515'
EXPECTED_SCHEMA='442d48f31d9c117a440dac709e698aa1e71f5b37c03f4db89d127c77f9296232'
EXPECTED_PROJECTION='47f15551e639f73b72854cb3e5b58d0dec6aecd6e93ed48a0a7c09d1ebeb47c0'

def schema_projection(plan):
    import copy
    routes=plan['proposedRoutes']
    selected=routes['mcp-managed-file-review-prepare']['plugins']['request-validation']['body_schema']
    def references(v):
        if type(v)is dict:return sum(int(k in ('$ref','$dynamicRef','$recursiveRef'))+references(x) for k,x in v.items())
        if type(v)is list:return sum(references(x) for x in v)
        return 0
    proposal=selected['properties']['Arguments']['properties']['executionProposal']
    count=references(selected)
    urn=proposal.get('$id')=='urn:ouf:managed-file-execution-proposal:lexical-csv:v1'
    projected=copy.deepcopy(selected)
    if count==0 and urn:del projected['properties']['Arguments']['properties']['executionProposal']['$id']
    limits=[]
    for rid,field in [('mcp-managed-file-review-prepare','expectedVersion'),
                      ('semantic-proposal-review','expectedRowVersion'),('semantic-proposal-validate','expectedRowVersion')]:
        schema=routes[rid]['plugins']['request-validation']['body_schema']
        maximum=schema['properties']['Arguments']['properties'][field]['maximum']
        # Output only whether the known public contract bound matches. Never
        # output an unknown value from private input, even when malformed.
        limits.append({'routeIdHash':digest(rid),'bodySchemaHash':digest(schema),
                       'maximumMatchesSafeIntegerContract':type(maximum)is int and maximum==9007199254740991})
    return {'bodySchemaHash':digest(selected),'matchesPackagedCanonicalSchema':digest(selected)==EXPECTED_SCHEMA,
        'knownNestedIdentifierPresent':urn,'referenceKeywordCount':count,
        'metadataOnlyProjectionHash':digest(projected),'matchesQualifiedMetadataProjection':digest(projected)==EXPECTED_PROJECTION,
        'numericLimits':limits,'schemaValuesPrinted':False,'schemaModifiedOnTarget':False}

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated,'ISOLATED_ROOT_READ_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:require(False,'TOTAL_TIME_BOUND_EXHAUSTED'));signal.alarm(120)
    emit('BEGIN',maximumSeconds=120,maximumGatewayReads=2,databaseCalls=0,backupArchiveReads=0,
         databaseMutations=0,serviceMutations=0,gatewayWrites=0,grantRequests=0,iamCalls=0)
    review=read(CONTEXT/'review.json',8388608,REVIEW)
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE and
        all(authority[k]==v for k,v in review['scopes'].items()),'EXACT_RETAINED_AUTHORITY_REQUIRED')
    process=review['scopes']['finiteActionProcess'];programs=review['sourceClosure']['executables']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    stopped(programs['systemctl'])
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and
        digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    snapshots={}
    def record(path,maximum=2097152):
        path=Path(path);v=read(path,maximum);snapshots[path]=v;return v
    status=record(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION' and
        status.get('reason')=='GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY','EXACT_GATEWAY_PAUSE_REQUIRED')
    dirs=process['directoryPlan'];plan=p['gatewayPlan']
    require(dirs['gateway']==str(CONTEXT/'gateway') and digest(plan)==p['cohortPlan']['gatewayPlanHash'],'GATEWAY_PLAN_DRIFT')
    journal=record(Path(dirs['gateway'])/'recovery.json')
    require(digest(journal)==EXPECTED_JOURNAL,'EXACT_RETAINED_NINE_APPLIED_ONE_CLAIMED_REQUIRED')
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(owner)==p['postGrantWorkerDirectory'],'WORKER_DIRECTORY_DRIFT')
    worker=record(owner/'recovery.json');admission=record(owner/'owner-admission.json')
    require(worker.get('state')=='CANCELLED' and worker.get('controlledCumulativeGrantAttempts')==8
        and admission.get('state')=='BLOCKED','CANCELLED_EIGHT_GRANT_HISTORY_REQUIRED')
    transport=transport_binding(p,dirs,record)
    gateway_check(p['engine'],transport)
    image_id=transport['runtimeBinding']['imageId'];image=engine_get(p['engine'],'images',image_id)
    require(type(image)is dict and image.get('Id')==image_id and re.fullmatch('sha256:[0-9a-f]{64}',image_id),'SELECTED_IMAGE_REQUIRED')
    emit('GATEWAY_IMAGE',imageId=image_id,imageMetadataHash=digest(image),privateValuesPrinted=False)
    facts=schema_projection(plan);emit('PLANNED_SCHEMA_COMPATIBILITY',facts=facts)
    first=gateway_read(p['engine'],transport);first_projection=gateway_projection(plan,journal,first)
    emit('GATEWAY_FIRST_READ',**first_projection)
    second=gateway_read(p['engine'],transport);second_projection=gateway_projection(plan,journal,second)
    emit('GATEWAY_SECOND_READ',**second_projection)
    require(first==second and first_projection['matchesBeforeClaim'] and not first_projection['claimedRoutePresent'],
        'STABLE_ABSENT_CLAIM_BASELINE_REQUIRED')
    require(engine_get(p['engine'],'images',image_id)==image,'IMAGE_CHANGED_DURING_READ')
    gateway_check(p['engine'],transport);stopped(programs['systemctl'])
    for path,value in snapshots.items():require(read(path,8388608)==value,'RETAINED_RECORD_CHANGED_DURING_READ')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    emit('END',complete=True,technicalPhase=5,functionalMilestonesProven=0,retainedRecordsUnchanged=True,
        stableGatewayReads=True,controlledCumulativeGrantAttempts=8,databaseCalls=0,backupArchiveReads=0,
        databaseMutations=0,serviceMutations=0,gatewayWrites=0,grantRequests=0,iamCalls=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)
