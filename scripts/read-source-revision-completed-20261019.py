"""Installation-specific uow4n8lp completed-update readback. No replay/authority/login."""
import hashlib,http.client,ipaddress,json,os,re,selectors,signal,socket,stat,subprocess,sys,time
from pathlib import Path
from urllib.parse import quote
class ReadDenied(Exception):pass
PlanDenied=ReadDenied
def require(ok,code="READ_RECONCILIATION_UNPROVEN"):
    if not ok:raise ReadDenied(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def unique(rows):
    d={}
    for k,v in rows:require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
    return d

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

def sha(raw):return hashlib.sha256(raw).hexdigest()

def parse(raw):
 def unique(rows):
  value={}
  for key,item in rows:require(key not in value);value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))

def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute() and path.resolve()==path)
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=maximum)
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat()) and(expected is None or sha(raw)==expected));return raw
 finally:os.close(fd)

FROZEN_NAMES={'iam_binding_candidate': 'iam_binding_candidate.py', 'migration_root_custody': 'migration_root_custody.py', 'tools.chatbot_file_cohort.continued_owner': 'continued_owner.py', 'tools.chatbot_file_cohort.review': 'review.py', 'tools.chatbot_file_cohort.human_session': 'human_session.py', 'tools.chatbot_file_cohort.gateway': 'gateway.py', 'tools.semantic_policy_token_owner.installed_owner': 'installed_owner.py', 'tools.semantic_policy_token_owner.supervisor': 'supervisor.py', 'image_custody': 'image_custody.py', 'tools.semantic_mcp_update.entry': 'mcp_entry.py', 'tools.semantic_mcp_update.authority': 'mcp_authority.py', 'tools.semantic_mcp_update.permit': 'mcp_permit.py', 'tools.semantic_mcp_update.plan': 'mcp_plan.py', 'tools.semantic_mcp_update.session': 'mcp_session.py', 'tools.semantic_mcp_update.owner': 'mcp_owner.py', 'tools.semantic_mcp_update.native': 'mcp_native.py', 'tools.ingestion_readiness_update.entry': 'readiness_entry.py', 'tools.ingestion_readiness_update.authority': 'readiness_authority.py', 'tools.ingestion_readiness_update.plan': 'readiness_plan.py', 'tools.ingestion_readiness_update.owner': 'readiness_owner.py', 'tools.ingestion_readiness_update.native': 'readiness_native.py', 'tools.onboarding_audit_update.entry': 'audit_entry.py', 'tools.onboarding_audit_update.authority': 'audit_authority.py', 'tools.onboarding_audit_update.owner': 'audit_owner.py', 'tools.onboarding_audit_update.native': 'audit_native.py', 'tools.onboarding_audit_update.preparation': 'audit_preparation.py', 'tools.resolution_ths_update.entry': 'resolution_entry.py', 'tools.resolution_ths_update.authority': 'resolution_authority.py', 'tools.resolution_ths_update.owner': 'resolution_owner.py', 'tools.resolution_ths_update.native': 'resolution_native.py', 'tools.resolution_ths_update.plan': 'resolution_plan.py', 'tools.resolution_ths_configuration.entry': 'config_entry.py', 'tools.resolution_ths_configuration.authority': 'config_authority.py', 'tools.resolution_ths_configuration.owner': 'config_owner.py', 'tools.resolution_ths_configuration.native': 'config_native.py', 'tools.resolution_ths_configuration.plan': 'config_plan.py', 'tools.udp_resolution_update.entry': 'udp_entry.py', 'tools.udp_resolution_update.authority': 'udp_authority.py', 'tools.udp_resolution_update.owner': 'udp_owner.py', 'tools.udp_resolution_update.native': 'udp_native.py', 'tools.udp_resolution_update.plan': 'udp_plan.py', 'tools.udp_resolution_update.preparation': 'udp_preparation.py', 'tools.resolution_comparison_update.entry': 'comparison_entry.py', 'tools.resolution_comparison_update.authority': 'comparison_authority.py', 'tools.resolution_comparison_update.owner': 'comparison_owner.py', 'tools.resolution_comparison_update.native': 'comparison_native.py', 'tools.resolution_comparison_update.plan': 'comparison_plan.py', 'tools.resolution_comparison_update.preparation': 'comparison_preparation.py', 'tools.linked_property_rollout.entry': 'linked_entry.py', 'tools.linked_property_rollout.authority': 'linked_authority.py', 'tools.linked_property_rollout.owner': 'linked_owner.py', 'tools.linked_property_rollout.native': 'linked_native.py', 'tools.linked_property_rollout.plan': 'linked_plan.py', 'tools.linked_property_rollout.preparation': 'linked_preparation.py', 'tools.linked_property_rollout.database': 'linked_database.py', 'tools.linked_property_rollout.configuration': 'linked_configuration.py', 'tools.linked_property_rollout.login': 'linked_login.py', 'tools.chat_recovery_update.entry': 'chat_recovery_entry.py', 'tools.chat_recovery_update.authority': 'chat_recovery_authority.py', 'tools.chat_recovery_update.owner': 'chat_recovery_owner.py', 'tools.chat_recovery_update.native': 'chat_recovery_native.py', 'tools.chat_recovery_update.plan': 'chat_recovery_plan.py', 'tools.chat_recovery_update.preparation': 'chat_recovery_preparation.py', 'tools.chat_recovery_update.database': 'chat_recovery_database.py', 'tools.chat_recovery_update.login': 'chat_recovery_login.py', 'tools.chat_recovery_update.readiness': 'chat_recovery_readiness.py', 'tools.chatbot_file_cohort.authorization': 'authorization.py', 'tools.source_revision_update.entry': 'source_revision_entry.py', 'tools.source_revision_update.authority': 'source_revision_authority.py', 'tools.source_revision_update.owner': 'source_revision_owner.py', 'tools.source_revision_update.native': 'source_revision_native.py', 'tools.source_revision_update.plan': 'source_revision_plan.py', 'tools.source_revision_update.preparation': 'source_revision_preparation.py', 'tools.source_revision_update.database': 'source_revision_database.py', 'tools.source_revision_update.configuration': 'source_revision_configuration.py', 'tools.source_revision_update.login': 'source_revision_login.py', 'tools.source_revision_update.gateway': 'source_revision_gateway.py'}
PREFIX=('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD')
SUFFIX=('DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')
STAGES=('VERIFY_INPUTS',)+tuple(n+'.'+s for n in ('onboarding','mcp') for s in PREFIX)+('BACKUP_ONBOARDING',)+tuple('onboarding.'+s for s in SUFFIX[:-1])+('VERIFY_MIGRATION','onboarding.RESTORE_RESTART_POLICY')+tuple('mcp.'+s for s in SUFFIX)+('GATEWAY_PREPARE_ROUTE','GATEWAY_READ_ROUTE','VERIFY_FINAL',)
MIGRATION={'module':'onboarding','from':33,'to':34,'owner':'APPLICATION_FLYWAY','script':'V34__source_property_revision.sql','checksum':-1996496299,'sha256':'08161423d63540db5ee5e3084361370e0e774448ed0bd9d37acacd6ae42ff4e5'}
def sql(module, app):
 require(module in('onboarding','udp','mcp') and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',app),'EXACT_DATABASE_MODULE_AND_ROLE_REQUIRED')
 schema='ouf_'+module
 common="'database',current_database(),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on','databaseOid',(select oid::bigint from pg_database where datname=current_database()),'databaseBytes',pg_database_size(current_database())"
 if module in('onboarding','udp'):
  fields=f"""'migrations',(select jsonb_agg(x order by installed_rank) from
   (select installed_rank,version,script,checksum,success from {schema}.flyway_schema_history order by installed_rank limit 100)x)"""
 else:fields=f"'migrations',(select jsonb_agg(x order by version) from (select version,checksum::text from {schema}.schema_migration order by version limit 100)x)"
 if module=='onboarding':
  fields+=f""",'revisionTablePresent',to_regclass('{schema}.source_property_revision')is not null,
   'revisionTableOwned',(select pg_get_userbyid(relowner)='{app}' from pg_class where oid=to_regclass('{schema}.source_property_revision')),
   'revisionAppendOnly',exists(select 1 from pg_trigger where tgrelid=to_regclass('{schema}.source_property_revision')
    and tgname='source_property_revision_append_only' and not tgisinternal and tgenabled='O' and tgtype=27
    and tgfoid=to_regprocedure('{schema}.reject_audit_change()'))"""
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SELECT jsonb_build_object("+common+","+fields+"); ROLLBACK;"

ROOT=Path('/etc/ouf/deploy-snapshots')
EXECUTION=ROOT/'source-revision-execution-uow4n8lp'
PREPARED=ROOT/'source-revision-human-recovery-inmfuoj2'
BASE=ROOT/'source-revision-custody-continuation-dvf517sr'
BASE_PACKAGE='afc2dbbfa72c14a64b00e9a0fba04fa731bd2ec51b08f5b65211a74a3dafd30d'
SOURCE='b829415351f7b0576f72a20b7e36e913294b447a'
SOURCE_SUCCESSORS={'tools.source_revision_update.entry':'f44e301293ac4df85afb041184f82284c76b73157b83eaa3087668ea89f0811b','tools.source_revision_update.login':'a3797360d89a1ca24d2364d7a8b0adb3737e3537018552c7fa4a319c37ea98e7'}
AUTH_PLAN='f9f96e8d8c577b8e67c3e612306ab767316c5df7a8db9aafebfd5eff5959fb16'
ORIGINAL='b3988d964a3c60b06b17952863f4fc62fc9a8f1626ced82bfb864721eb7b740a'
INPUTS='1ab309f747d2e0c70b3a284258ea0f2100d51bc149ef9c2ae2b55b73f3871c62'

def document(path,expected=None):return parse(read(path,expected))
def same_documents(snapshots):
 for path,raw in snapshots.items():require(read(path)==raw,'EVIDENCE_CHANGED_DURING_OBSERVATION')

def frozen_preparation():
 result=document(PREPARED/'postboot-preparation-result.json');package=document(PREPARED/'executor-code/package.json',result['executorCodeBinding']['packageSha256'])
 base=document(BASE/'executor-code/package.json',BASE_PACKAGE)
 require(result['schema']=='ouf.source-revision-postboot-preparation-result.v1' and result['contextPath']==str(PREPARED)
  and result['runtimeAuthorityIssued']is False and result['readyForExecution']is False and result['retainedHumanAttempts']==189)
 require(package['sourceCommit']==SOURCE and result['executorCodeBinding']['sourceCommit']==SOURCE
  and package['sourceHashes']=={**base['sourceHashes'],**SOURCE_SUCCESSORS}
  and package['executorSha256']==base['executorSha256'] and package['loaderSha256']==base['loaderSha256'])
 require(set(package['sourceHashes'])==set(FROZEN_NAMES))
 code=PREPARED/'executor-code';expected={'case.json','package.json','runtime.py','execute.py'}|set(FROZEN_NAMES.values())
 require(len(expected)==81 and {x.name for x in code.iterdir()}==expected)
 for module,name in FROZEN_NAMES.items():read(code/name,package['sourceHashes'][module],262144)
 read(code/'execute.py',package['executorSha256'],262144);read(code/'runtime.py',package['loaderSha256'],65536)
 case=document(code/'case.json',package['caseSha256']);require(result['caseBinding']=={'path':str(code/'case.json'),'sha256':package['caseSha256']})
 for field,name,h in [('currentOriginalPreparationBinding','current-original-preparation.json',ORIGINAL),('preparedInputsBinding','postboot-private-inputs.json',INPUTS)]:
  b=result[field];require(b=={'path':str(ROOT/'source-revision-postboot-prepared-kfy691gh'/name),'sha256':h});read(b['path'],h)
 for field,name in [('nativePlanBinding','prepared-plan.json'),('continuationPlanBinding','continuation-plan.json'),('nativeLoginReviewBinding','native-login-review-candidate.json')]:
  b=result[field];require(b['path']==str(PREPARED/name));read(b['path'],b['sha256'])
 return result,case

def completed_history(row,plan,review,authority):
 require(row['schema']=='ouf.source-revision-update-journal.v1' and row['budgetReset']is False
  and row['scopeHash']==digest(review['scopes']['sourceRevisionUpdate']) and row['authorityHash']==sha(authority)
  and row['nextStage']==len(STAGES) and len(row['effects'])==len(STAGES)
  and row['incidentState']=='RECOVERED' and row['version']==57)
 for stage,effect in zip(STAGES,row['effects']):
  require(effect['stage']==stage and effect['state']=='APPLIED'
   and effect['intentHash']==digest({'planHash':digest(plan),'stage':stage}),'COMPLETED_STAGE_HISTORY_DRIFT')
 require(row['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'CURRENT_BOOT_REQUIRED')
 final=row['effects'][-1]['evidence'];require(set(final['applications'])=={'onboarding','mcp'}
  and final['routeMapHash']==digest(plan['gateway']['afterRoutes']))
 return final

def applications(plan,row,final):
 out={};old={}
 for name,r in plan['replacements'].items():
  expected=final['applications'][name]['runtimeBinding'];actual=engine_get(plan['engine'],'containers',expected['containerId'])
  require(actual is not None and runtime_pin(actual)==expected and actual['Name']=='/'+r['name']
   and actual['State']['Running']is True and actual['State']['Paused']is False and actual['State']['Restarting']is False
   and actual['RestartCount']==0 and actual['HostConfig']['RestartPolicy']==r['restoreRestartPolicy'],'NEW_GENERATION_DRIFT')
  net=actual['NetworkSettings']['Networks'];require(set(net)=={r['network']['name']}
   and net[r['network']['name']]['NetworkID']==r['network']['id'] and net[r['network']['name']]['IPAddress']==r['network']['ip']
   and net[r['network']['name']]['MacAddress'].lower()==r['network']['mac'].lower())
  predecessor=engine_get(plan['engine'],'containers',r['oldRuntimeBinding']['containerId'])
  require(predecessor is not None and predecessor['Name']=='/'+r['retiredName'] and predecessor['State']['Running']is False
   and predecessor['State']['Pid']==0 and predecessor['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0}
   and predecessor['Image']==r['oldRuntimeBinding']['imageId'] and digest(predecessor['Config'])==r['oldRuntimeBinding']['configHash']
   and digest(sorted(predecessor['Mounts'],key=lambda m:m['Destination']))==r['oldRuntimeBinding']['mountsHash'],'RETAINED_OLD_CONTAINER_DRIFT')
  out[name]={'containerId':actual['Id'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],'runtimeBindingVerified':True,'restartPolicyPreserved':True}
  old[name]={'retained':True,'stopped':True,'restartDisabled':True}
 for name,expected in plan['unchangedApplications'].items():
  actual=engine_get(plan['engine'],'containers',expected['containerId']);require(actual is not None and runtime_pin(actual)==expected
   and actual['State']['Running']is True and actual['State']['Paused']is False,'UNCHANGED_APPLICATION_DRIFT')
  out[name]={'containerId':actual['Id'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],'unchangedBindingVerified':True}
 return out,old

def readiness(plan):
 result={}
 for name,r in plan['replacements'].items():
  ip=ipaddress.ip_address(r['network']['ip']);selection=r['readiness'];require(ip.is_private and not ip.is_loopback)
  require(type(selection['readinessPort'])is int and 1<=selection['readinessPort']<=65535
   and selection['readinessPath']==('/actuator/health/readiness' if name=='onboarding' else '/health/ready'))
  client=http.client.HTTPConnection(str(ip),selection['readinessPort'],timeout=5)
  try:
   client.request('GET',selection['readinessPath'],headers={'Accept':'application/json','Connection':'close'});response=client.getresponse();raw=response.read(65537)
   require(len(raw)<=65536 and (response.status==200 and parse(raw).get('status')=='UP' if name=='onboarding' else response.status==204 and not raw),'CURRENT_READINESS_UNPROVEN')
   result[name]={'status':response.status,'ready':True}
  finally:client.close()
 return result

def backup_metadata(plan):
 b=document(EXECUTION/'backup.json');require(b['path']==str(EXECUTION/'onboarding.dump') and b['payloadParsed']is True and b['restorePerformed']is False
  and b['databaseOid']==plan['database']['before']['onboarding']['databaseOid'] and b['historyHash']==digest(plan['database']['before']['onboarding']['migrations']))
 # Deliberately do not open the data dump; prior full checksum proof is historical.
 st=Path(b['path']).lstat();require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size==b['bytes']and st.st_size>100)
 return {'receiptBound':True,'dumpCustodyAndSizeMatch':True,'dumpOpened':False,'currentFullChecksumVerified':False,'priorPayloadParsed':True}

def database_readback(plan,original):
 pg=plan['database']['postgresRuntimeBinding'];actual=engine_get(plan['engine'],'containers',pg['containerId'])
 def raw_pin(a):return {'containerId':a['Id'],'imageId':a['Image'],'pid':a['State']['Pid'],'startedAt':a['State']['StartedAt'],**{n+'Hash':digest(a[k])for n,k in [('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings')]}}
 require(actual is not None and actual['State']['Running']is True and raw_pin(actual)==pg,'POSTGRES_GENERATION_DRIFT')
 db=original['databasePlan'];admin=db['mcpAuditRoleAdministration']['admin'];require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',admin))
 for module in ('onboarding','udp','mcp'):
  b=next(v for v in db['modules'] if v['module']==module);require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',b['database']))
  argv=[executable(plan['programs']['docker']),'--host','unix://'+plan['engine']['socketPath'],'--config',str(EXECUTION),'exec',pg['containerId'],
   'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
   'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',b['database'],'-c',sql(module,b['user'])]
  code,raw,_,_=bounded(argv,seconds=20,maximum=131072);require(code==0,'READ_ONLY_SQL_FAILED');f=parse(raw);before=plan['database']['before'][module]
  require(f['transactionReadOnly']is True and f['role']==admin and all(f[k]==before[k]for k in ('database','databaseOid','role')))
  history=before['migrations']+([{'installed_rank':34,'version':'34','script':MIGRATION['script'],'checksum':MIGRATION['checksum'],'success':True}]if module=='onboarding'else[])
  require(f['migrations']==history,'CURRENT_MIGRATION_HISTORY_DRIFT')
  if module=='onboarding':require(all(f[k]is True for k in ('revisionTablePresent','revisionTableOwned','revisionAppendOnly')))
 following=engine_get(plan['engine'],'containers',pg['containerId']);require(following is not None and raw_pin(following)==pg,'POSTGRES_CHANGED_DURING_READ')
 return {'readOnlySessions':3,'onboardingVersion':34,'udpVersion':36,'mcpMigrationsUnchanged':True,'revisionTableOwnershipAndAppendOnlyProven':True}

def custody_pin(st):
 return [getattr(st,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def retained_metadata_file(binding,pin):
 require(set(pin)=={'path','sha256','metadata'}and binding=={k:pin[k]for k in('path','sha256')},'EXACT_RETAINED_MCP_METADATA_PIN_REQUIRED')
 path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path and path.name in('permit.json','policy.json','profile.json'),'EXACT_RETAINED_MCP_METADATA_PATH_REQUIRED')
 for parent in path.parents:
  st=parent.lstat();require(stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022,'MCP_METADATA_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==0 and before.st_gid>0
   and stat.S_IMODE(before.st_mode)==0o440 and before.st_nlink==1 and 0<before.st_size<=65536
   and custody_pin(before)==pin['metadata'],'RETAINED_MCP_METADATA_CUSTODY_CHANGED')
  raw=os.read(fd,65537);require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==binding['sha256']
   and custody_pin(before)==custody_pin(os.fstat(fd))==custody_pin(path.lstat()),'RETAINED_MCP_METADATA_BYTES_CHANGED')
 finally:os.close(fd)
 return {'exactBinding':True,'readOnlyServiceMetadata':True,'custodyPreserved':True}

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ReadDenied("READ_TIME_BOUND_EXHAUSTED")))
 signal.alarm(180)
 snapshots={}
 def doc(p,expected=None):
  raw=read(p,expected);snapshots[Path(p)]=raw;return parse(raw)
 result,case=frozen_preparation()
 plan=doc(EXECUTION/'execution-plan.json');review=doc(EXECUTION/'review.json');authority=doc(EXECUTION/'authority.json');journal=doc(EXECUTION/'recovery.json')
 require(plan['authorityDirectory']==str(EXECUTION) and review['authorityDirectory']==str(EXECUTION)
  and review['sourceClosureHash']==result['sourceClosureSha256']==authority['sourceClosureHash']
  and review['scopes']['sourceRevisionUpdate']['planHash']==digest(plan)
  and authority['scopedExecution']['reviewHash']==digest(review),'EXACT_COMPLETED_CONTEXT_BINDING_REQUIRED')
 auth=doc(EXECUTION/'authorization-plan.json',AUTH_PLAN);ar=doc(EXECUTION/'authorization/recovery.json')
 require(ar['schema']=='ouf.chatbot-file-authorization-journal.v1'and ar['planHash']==AUTH_PLAN
  and ar['authorityHash']==sha(snapshots[EXECUTION/'authority.json']) and ar['budgetReset']is False)
 require(all(e['state']=='APPLIED'for e in ar['effects'].values()),'UNRECONCILED_AUTHORIZATION_EFFECT')
 reference=plan['logicalScopeSuccessor'];predecessor=Path(reference['context'])
 require(predecessor==ROOT/'source-revision-execution-dvf517sr')
 old_claim=doc(reference['claimBinding']['path'],reference['claimBinding']['sha256'])
 require(Path(reference['claimBinding']['path'])==ROOT/('source-revision-update-'+plan['logicalUpdateRef']+'.claim.json'))
 child=doc(predecessor/'logical-successor.claim.json')
 require(child=={'schema':'ouf.source-revision-logical-scope-successor-claim.v1','logicalUpdateRef':plan['logicalUpdateRef'],
  'predecessorClaimSha256':reference['claimBinding']['sha256'],'predecessorAuthoritySha256':reference['authorityBinding']['sha256'],
  'planHash':digest(plan),'authorityHash':sha(snapshots[EXECUTION/'authority.json']),'context':str(EXECUTION),
  'priorCumulativeReadinessAttempts':0,'predecessorEffects':0,'budgetReset':False,'automaticReplayAllowed':False})
 doc(EXECUTION/'backup.json')
 for b in plan['retainedMcpMetadata']:retained_metadata_file(b,plan['retainedMcpMetadataCustody'][b['path']])
 final=completed_history(journal,plan,review,snapshots[EXECUTION/'authority.json'])
 current,old=applications(plan,journal,final);health=readiness(plan)
 routes=gateway_read(plan['engine'],plan['gateway']['transport']);require(routes==plan['gateway']['afterRoutes']and len(routes)==len(plan['gateway']['beforeRoutes'])+2,'EXACT_ADDITIVE_ROUTE_MAP_REQUIRED')
 original=doc(result['currentOriginalPreparationBinding']['path'],ORIGINAL)
 database=database_readback(plan,original);backup=backup_metadata(plan)
 again,old_again=applications(plan,journal,final);require(again==current and old_again==old,'APPLICATION_CHANGED_DURING_READ')
 for b in plan['retainedMcpMetadata']:retained_metadata_file(b,plan['retainedMcpMetadataCustody'][b['path']])
 same_documents(snapshots)
 # Closure/result and backup receipt checked again; no tokens, HUMAN journals or signing keys are opened.
 following,_=frozen_preparation();require(following==result);doc(EXECUTION/'backup.json');same_documents(snapshots)
 return {'schema':'ouf.source-revision-completed-readback.v1','complete':True,'contextPath':str(EXECUTION),'preparedContextPath':str(PREPARED),
  'frozenFilesVerified':81,'retainedMcpMetadataCustodyAndHashesVerified':True,'preparationResultSha256':sha(read(PREPARED/'postboot-preparation-result.json')),'sourceClosureSha256':result['sourceClosureSha256'],
  'journalVersion':journal['version'],'allStagesApplied':True,'authorityAcceptedForExecution':False,'authorityExpiredByWallClock':time.time()>=journal['expiresAt'],
  'applications':current,'retainedOldContainers':old,'readiness':health,'database':database,'backup':backup,
  'gatewayRouteCount':len(routes),'allOriginalGatewayRoutesPreserved':True,'revisionRoutesAdded':2,'authorizationEffectsApplied':True,
  'freshChatClientTokenScopesProven':False,'nativeProfilePublished':False,'functionalStage5Proven':False,'functionalStage6Proven':False,
  'runtimeAuthorityIssued':False,'humanJournalsRead':0,'tokenFilesOpened':0,'credentialValuesPrinted':False,'credentialJournalHashesPrinted':False,
  'automaticRetry':False,'budgetReset':False,'journalWrites':0,'jobsRetried':0,'profilePublications':0,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt)as error:
  output={'schema':'ouf.source-revision-completed-readback.v1','complete':False,'exceptionClass':type(error).__name__,'rawErrorPrinted':False,'automaticRetry':False,'budgetReset':False,'runtimeAuthorityIssued':False,'reconciliationRequired':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output['complete']else 2)
