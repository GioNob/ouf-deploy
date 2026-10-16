#!/usr/bin/env python3
"""Fixed-context phase-5 readback. GET/SELECT only; no retry or recovery effects."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path
from urllib.parse import quote
CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5')
REVIEW='bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144'
AUTHORITY='0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8'
SOURCE='70af66b26d9a8dfdd7151c55f44eb5795fcc84a8'
UNIT='ouf-file-cohort-35d5c6c756feb9c4811ac6d24610698a.service'
MODULES=('udp','onboarding','ingestion','mcp')

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-gateway-publication-readback.v1',check=check,readOnly=True,
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

def archive(path, maximum):
    require(path.is_absolute() and path.resolve()==path,'EXACT_ARCHIVE_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ARCHIVE_ANCESTRY_DRIFT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and
            stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and
            0<=before.st_size<=maximum,'ARCHIVE_CUSTODY_DRIFT')
        h=hashlib.sha256();count=0;magic=b''
        while raw:=os.read(fd,65536):
            count+=len(raw);require(count<=maximum,'ARCHIVE_BOUND_EXHAUSTED')
            if not magic:magic=raw[:5]
            h.update(raw)
        require(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'ARCHIVE_READ_DRIFT')
        return {'bytes':count,'sha256':h.hexdigest(),'customFormatHeader':magic==b'PGDMP'}
    finally:os.close(fd)

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

def migration_request(prepared):
    row=next(r for r in prepared['cohortPlan']['replacements'] if r['module']=='mcp')
    suffix=row['retiredName'].removeprefix('ouf-mcp-before-')
    require(re.fullmatch('[a-z0-9-]{1,60}',suffix),'MIGRATION_NAME_DRIFT')
    creation=row['creationRequest'];values=[v for v in creation['Env'] if v.startswith('MCP_DATABASE_URL=')]
    require(len(values)==1 and creation['User']=='10005:10005' and
        creation['Entrypoint']==['/usr/local/bin/ouf-mcp'] and
        re.fullmatch('sha256:[0-9a-f]{64}',creation['Image']),'MIGRATION_REQUEST_DRIFT')
    network=creation['NetworkingConfig']['EndpointsConfig']['ouf-backend']['NetworkID']
    require(re.fullmatch('[0-9a-f]{64}',network),'NETWORK_ID_DRIFT')
    request={'Image':creation['Image'],'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],
        'Cmd':['migrate'],'WorkingDir':'/app','Env':values,
        'Labels':{'it.ouf.file-cohort':suffix,'it.ouf.role':'mcp-migration'},
        'HostConfig':{'NetworkMode':'ouf-backend','RestartPolicy':{'Name':'no','MaximumRetryCount':0},
            'AutoRemove':False,'ReadonlyRootfs':True},
        'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':network}}}}
    return 'ouf-mcp-migrate-'+suffix,request

def environment(values):
    require(type(values)is list and len(values)<=512,'ENVIRONMENT_SHAPE_DRIFT')
    result={}
    for item in values:
        require(type(item)is str and '=' in item,'ENVIRONMENT_ENTRY_DRIFT')
        key,value=item.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key) and key not in result,'ENVIRONMENT_KEY_DRIFT')
        result[key]=value
    return result

def native_projection(name,request,actual,image):
    """Classify differences, never accept them or print environment/label values."""
    require(type(actual)is dict and type(image)is dict and image.get('Id')==request['Image'],
        'EXACT_REQUEST_IMAGE_REQUIRED')
    config=actual['Config'];host=actual['HostConfig']
    checks={'Name':actual.get('Name')=='/'+name,'Image':actual.get('Image')==request['Image']}
    for key in ('User','Entrypoint','Cmd','WorkingDir','Env','Labels'):
        checks['Config.'+key]=config.get(key)==request[key]
    for key in ('NetworkMode','ReadonlyRootfs','AutoRemove'):
        checks['HostConfig.'+key]=host.get(key)==request['HostConfig'][key]
    checks['HostConfig.Privileged']=host.get('Privileged') is False
    checks['Mounts']=actual.get('Mounts')==[]
    network=actual.get('NetworkSettings',{}).get('Networks',{}).get('ouf-backend',{})
    expected_network=request['NetworkingConfig']['EndpointsConfig']['ouf-backend']['NetworkID']
    checks['NetworkID']=network.get('NetworkID')==expected_network
    image_config=image.get('Config') or {}
    requested=environment(request['Env']);defaults=environment(image_config.get('Env') or [])
    observed=environment(config.get('Env') or [])
    labels={**(image_config.get('Labels') or {}),**request['Labels']}
    return dict(originalPredicateMatches=all(checks.values()),fieldMatches=checks,
        environmentMatchesImageDefaultsAndRequest=observed=={**defaults,**requested},
        environmentRequestedValuesMatch=all(observed.get(k)==v for k,v in requested.items()),
        environmentImageDefaultCount=len(defaults),environmentObservedCount=len(observed),
        labelsMatchImageDefaultsAndRequest=config.get('Labels')==labels,
        networkIdEmpty=network.get('NetworkID') in ('',None),
        restartPolicyMatches=host.get('RestartPolicy')==request['HostConfig']['RestartPolicy'],
        unexpectedNetworks=sorted(actual.get('NetworkSettings',{}).get('Networks',{}))!=['ouf-backend'],
        environmentValuesPrinted=False,labelValuesPrinted=False)

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

def literal(value):
    require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'FIXED_SQL_IDENTIFIER_REQUIRED')
    return "'"+value+"'"

def identifier(value):
    literal(value)
    return chr(34)+value+chr(34)

def sha(value):
    return type(value)is str and re.fullmatch("[0-9a-f]{64}",value)is not None

def incident_metadata(application_user, omit_temporary=False):
    """Canonical ACL preserves existing privileges and ownership across cleanup.

    A superuser grant is recorded as the table owner's grant. Only the reviewed
    non-grantable TRIGGER edge to the application role may be excluded.
    """
    identifier(application_user)
    app = '(SELECT oid FROM pg_roles WHERE rolname='+literal(application_user)+')'
    edge = "a.grantee="+app+" AND a.grantor=c.relowner AND a.privilege_type='TRIGGER' AND NOT a.is_grantable"
    acl = ("COALESCE((SELECT jsonb_agg(jsonb_build_array(a.grantor,a.grantee,a.privilege_type,a.is_grantable) "
           "ORDER BY a.grantor,a.grantee,a.privilege_type,a.is_grantable) "
           "FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a"+
           (' WHERE NOT ('+edge+')' if omit_temporary else '')+"),'[]'::jsonb)")
    return ("SELECT json_build_object('oid',c.oid::bigint,'ownerOid',c.relowner::bigint,"
            "'aclHash',encode(sha256(convert_to(("+acl+")::text,'UTF8')),'hex'),"
            "'triggerAuthority',has_table_privilege("+app+",c.oid,'TRIGGER'),"
            "'triggerGrantCount',(SELECT count(*) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE "+edge+")) "
            "FROM pg_class c WHERE c.oid=to_regclass('ouf_mcp.security_incident') AND c.relkind='r'")

def validate_incident_binding(value):
    require(type(value) is dict and set(value)=={'oid','ownerOid','aclHash','triggerAuthority','triggerGrantCount'}
            and all(type(value[k]) is int and value[k]>0 for k in ('oid','ownerOid'))
            and sha(value['aclHash']) and type(value['triggerAuthority']) is bool
            and type(value['triggerGrantCount']) is int and value['triggerGrantCount'] in (0,1),
            'EXACT_SECURITY_INCIDENT_TABLE_AND_ACL_REQUIRED')

def state_query(binding,plan):
    app=literal(binding['user']);admin=literal(plan['mcpAuditRoleAdministration']['admin'])
    role="'ouf_mcp_operational_audit_owner'"
    return ("SELECT json_build_object('databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),"
        "'databaseMatched',current_database()="+literal(binding['database'])+",'roleMatched',current_user="+admin+","
        "'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),"
        "'readOnly',current_setting('transaction_read_only')='on',"
        "'migrations',(SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM ouf_mcp.schema_migration),"
        "'roleExists',EXISTS(SELECT 1 FROM pg_roles WHERE rolname="+role+"),"
        "'noLogin',COALESCE((SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole FROM pg_roles WHERE rolname="+role+"),false),"
        "'schemaCreate',COALESCE((SELECT has_schema_privilege(oid,'ouf_mcp','CREATE') FROM pg_roles WHERE rolname="+role+"),false),"
        "'membershipCount',(SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname="+role+")),"
        "'appMembership',(SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname="+role+") AND member=(SELECT oid FROM pg_roles WHERE rolname="+app+") AND set_option AND NOT inherit_option AND NOT admin_option),"
        "'functionOwnerCount',(SELECT count(*) FROM pg_proc WHERE oid IN (to_regprocedure('ouf_mcp.capture_operational_attempt_audit()'),to_regprocedure('ouf_mcp.capture_operational_security_audit()')) AND proowner=(SELECT oid FROM pg_roles WHERE rolname="+role+")),"
        "'incidentBinding',("+incident_metadata(binding['user'],plan['mcpAuditRoleAdministration']['temporaryIncidentTrigger'])+"))")

def sql_read(binary,prepared,config,binding):
    plan=prepared['databasePlan'];admin=plan['mcpAuditRoleAdministration']['admin']
    pg=engine_get(prepared['engine'],'containers',plan['postgresRuntimeBinding']['containerId'])
    require(runtime_pin(pg)==plan['postgresRuntimeBinding'] and pg['State']['Running'] is True and
        pg['State']['Paused'] is False,'POSTGRES_GENERATION_DRIFT')
    require([v.split('=',1)[1] for v in pg['Config'].get('Env',[]) if v.startswith('POSTGRES_USER=')]==[admin],
        'ADMINISTRATOR_SELECTION_DRIFT')
    argv=[binary,'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],
        'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
        'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
        '-U',admin,'-d',binding['database'],'-c',state_query(binding,plan)]
    code,raw,err,_=bounded(argv,seconds=20,maximum=65536)
    require(code==0,'READ_ONLY_SQL_FAILED')
    facts=json.loads(raw,object_pairs_hook=unique)
    return database_projection(facts,binding,plan)

def database_projection(facts,binding,plan):
    flags=('databaseMatched','roleMatched','superuser','readOnly','roleExists','noLogin','schemaCreate')
    counts=('membershipCount','appMembership','functionOwnerCount')
    require(type(facts)is dict and set(facts)==set(flags)|set(counts)|{'databaseOid','migrations','incidentBinding'} and
        all(type(facts[k])is bool for k in flags) and all(facts[k] for k in flags[:4]) and
        type(facts['databaseOid'])is int and facts['databaseOid']==binding['databaseOid'] and
        all(type(facts[k])is int and 0<=facts[k]<=1000000 for k in counts),'DATABASE_FACTS_DRIFT')
    rows=facts['migrations'];require(type(rows)is list and len(rows)<=256,'BOUNDED_HISTORY_REQUIRED')
    for row in rows:
        require(type(row)is dict and set(row)=={'version','checksum'} and type(row['version'])is int and
            type(row['checksum'])is str and re.fullmatch('[0-9a-f]{64}',row['checksum']),'MIGRATION_HISTORY_SHAPE_DRIFT')
    actual=facts['incidentBinding'];validate_incident_binding(actual)
    original=plan['mcpAuditRolePreflight']['incidentBinding'];validate_incident_binding(original)
    return {**{k:facts[k] for k in flags+counts},'databaseOid':facts['databaseOid'],
        'migrationCount':len(rows),'historyHash':digest(rows),
        'beforeMigrationsMatch':rows==binding['beforeMigrations'],
        'expectedMigrationsMatch':rows==binding['expectedMigrations'],
        'incidentOwnerMatches':actual['ownerOid']==original['ownerOid'],
        'incidentOidMatches':actual['oid']==original['oid'],
        'incidentPreservedAclMatches':actual['aclHash']==original['aclHash'],
        'incidentTriggerAuthority':actual['triggerAuthority'],'incidentTriggerGrantCount':actual['triggerGrantCount']}

# Custody, credential parser and route normalization copied from qualified runtime70.
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

# This child has one literal GET endpoint. It cannot receive an HTTP method,
# path or body from input. Credential and response values never enter logs.
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

def module_schema_read(binary,p,config,binding):
    require(binding['module'] in ('udp','onboarding'),'EXACT_POST_MIGRATION_MODULE_REQUIRED')
    schema=identifier(binding['schema']);database=literal(binding['database']);user=identifier(binding['user'])
    query=("SELECT json_build_object('databaseOid',d.oid::bigint,'databaseMatched',current_database()="+database+
        ",'readOnly',current_setting('transaction_read_only')='on','migrations',"
        "(SELECT COALESCE(json_agg(json_build_object('version',version,'script',script,'type',type,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "+schema+
        ".flyway_schema_history)) FROM pg_database d WHERE d.datname=current_database()")
    argv=[binary,'--host','unix://'+p['engine']['socketPath'],'--config',config,'exec',
        p['databasePlan']['postgresRuntimeBinding']['containerId'],'env','LC_ALL=C',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
        'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',binding['user'],'-d',binding['database'],'-c',query]
    code,raw,_,_=bounded(argv,seconds=20,maximum=131072);require(code==0,'MODULE_SCHEMA_READ_FAILED')
    value=json.loads(raw,object_pairs_hook=unique)
    require(type(value)is dict and value['databaseOid']==binding['databaseOid'] and value['databaseMatched'] is True
        and value['readOnly'] is True and type(value['migrations'])is list and len(value['migrations'])<=256,'MODULE_SCHEMA_IDENTITY_DRIFT')
    return {'databaseOid':value['databaseOid'],'readOnly':True,'migrationCount':len(value['migrations']),
        'historyHash':digest(value['migrations']),'expectedMigrationsMatch':value['migrations']==binding['expectedMigrations']}

def module_native(p,journal,module):
    row=next(r for r in p['cohortPlan']['replacements'] if r['module']==module)
    effects={e['step']:e for e in journal['effects']}
    stages=('rename','create','start','ready','restart_policy')
    selected=[effects.get(module+'.'+s) for s in stages]
    require(all(e and e['state']=='APPLIED' and e['intentHash']==digest({'modulePlan':row,'stage':s})
        and e['evidenceHash']==digest(e['evidence']) for s,e in zip(stages,selected)), 'COMPLETED_MODULE_EFFECTS_REQUIRED')
    created=selected[1]['evidence'];started=selected[2]['evidence']
    actual=engine_get(p['engine'],'containers',created['containerId'])
    require(actual is not None,'COMPLETED_MODULE_CONTAINER_ABSENT')
    matches=(actual['Id']==created['containerId'] and actual['Image']==created['imageId'] and
        digest(actual['Config'])==created['configHash'] and digest(actual['Mounts'])==created['mountsHash'] and
        digest(actual['HostConfig'])==selected[-1]['evidence']['hostConfigHash'] and
        actual['State']['Pid']==started['runtimeState']['Pid'] and actual['State']['StartedAt']==started['runtimeState']['StartedAt'])
    return {'module':module,'completedEffects':5,'generationMatches':matches,**native_state(actual)}

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated,'ISOLATED_ROOT_READ_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:require(False,'TOTAL_TIME_BOUND_EXHAUSTED'));signal.alarm(240)
    emit('BEGIN',maximumSeconds=240,databaseMutations=0,serviceMutations=0,dumpProbes=0,
        grantRequests=0,iamCalls=0,gatewayWrites=0,maximumGatewayReads=2)
    review=read(CONTEXT/'review.json',8388608,REVIEW)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_EXECUTED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(all(authority[k]==v for k,v in review['scopes'].items()),'AUTHORITY_SCOPE_DRIFT')
    process=review['scopes']['finiteActionProcess'];programs=review['sourceClosure']['executables']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    stopped(programs['systemctl'])
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and
        digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    snapshots={}
    def record(path,maximum=2097152):
        path=Path(path);value=read(path,maximum);snapshots[path]=value;return value
    status=record(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION' and
        status.get('reason')=='GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY','EXACT_GATEWAY_PAUSE_REQUIRED')
    emit('RETAINED_DELIVERY',recordHash=digest(status),runtimeAuthorityPreviouslyIssued=True,
        authorityExpiredAtRead=time.time()>=authority['expiresAt'])
    dirs=process['directoryPlan'];plan=p['databasePlan']
    require(all(dirs[k]==str(CONTEXT/k) for k in ('databases','backups','gateway','containers')) and
        digest(plan)==p['cohortPlan']['databasePlanHash'],'DATABASE_PLAN_DRIFT')
    journal=record(Path(dirs['databases'])/'recovery.json')
    require(journal['schema']=='ouf.chatbot-cohort-database-journal.v1' and journal['planHash']==digest(plan) and
        journal['authorityHash']==AUTHORITY and journal['budgetReset'] is False and journal['restorePerformed'] is False,
        'DATABASE_JOURNAL_BINDING_DRIFT')
    require([r['module'] for r in plan['modules']]==list(MODULES) and set(journal['backups'])==set(MODULES),'ALL_BACKUPS_REQUIRED')
    archives={}
    for row in plan['modules']:
        info=archive(Path(dirs['backups'])/(row['module']+'.dump'),row['maximumArchiveBytes'])
        require(journal['backups'][row['module']]=={'state':'COMPLETE','scopeHash':digest(row),'archiveSha256':info['sha256'],
            'archiveBytes':info['bytes'],'payloadParsed':True} and info['customFormatHeader'] and info['bytes']>100,
            'COMPLETE_ARCHIVE_DRIFT')
        archives[row['module']]=info;emit('RETAINED_ARCHIVE',module=row['module'],state='COMPLETE',**info)
    name,request=migration_request(p);claim=journal.get('mcpMigration');role=journal.get('mcpAuditRole')
    binding=next(r for r in plan['modules'] if r['module']=='mcp')
    require(type(claim)is dict and claim.get('state')=='COMPLETE' and claim.get('name')==name and
        claim.get('intentHash')==digest(request) and claim.get('historyHash')==digest(binding['expectedMigrations']),
        'COMPLETE_MIGRATION_CHECKPOINT_REQUIRED')
    require(type(role)is dict and role.get('state')=='CLEAN','CLEAN_AUDIT_CHECKPOINT_REQUIRED')
    emit('DATABASE_CHECKPOINT',recordHash=digest(journal),migrationState=claim['state'],auditRoleState=role['state'],
        migrationIntentHash=digest(request),technicalPhase1ArchivesVerified=True)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(owner)==p['postGrantWorkerDirectory'],'CURRENT_WORKER_DIRECTORY_DRIFT')
    for file,label in (('recovery.json','WORKER'),('owner-session.json','WORKER_SESSION'),
                       ('owner-admission.json','WORKER_ADMISSION'),('owner-first-grant.json','FIRST_GRANT_REFERENCE')):
        path=owner/file;record(path);metadata(label,path)
    components={}
    for component in ('containers','authorization','gateway'):
        path=Path(dirs[component])/'recovery.json';v=record(path);components[component]=v
        metadata('COHORT_'+component.upper(),path)
        emit('COHORT_EFFECT_COUNT',component=component,effectCount=len(v.get('effects',[])))
    container_journal=components['containers']
    require(container_journal['planHash']==digest(p['cohortPlan']) and container_journal['authorityHash']==AUTHORITY and
        container_journal['nextStep']==10 and len(container_journal['effects'])==10,'TWO_COMPLETED_REPLACEMENTS_REQUIRED')
    transition_path=Path(p['registry']['directoryPlan']['transition'])/'recovery.json'
    transition=record(transition_path);metadata('REGISTRY_TRANSITION',transition_path)
    require(type(transition.get('effects'))is list and len(transition['effects'])==10 and
        all(e.get('state')=='APPLIED' for e in transition['effects']),'TEN_REGISTRY_EFFECTS_REQUIRED')
    emit('REGISTRY_EFFECTS',effectCount=10,appliedCount=10)
    actual=engine_get(p['engine'],'containers',claim['containerId'])
    require(actual is not None and actual['Id']==claim['containerId'] and actual['Image']==request['Image'],'MIGRATION_CONTAINER_DRIFT')
    emit('MIGRATION_NATIVE',**native_state(actual))
    observations={}
    with tempfile.TemporaryDirectory(prefix='ouf-gateway-read-config-')as config:
        binary=executable(programs['docker']);facts=sql_read(binary,p,config,binding)
        emit('MCP_DATABASE_STATE',facts=facts)
        for module in ('udp','onboarding'):
            row=next(r for r in plan['modules'] if r['module']==module)
            state=module_native(p,container_journal,module);observations[module]=state
            emit('COMPLETED_MODULE_NATIVE',**state,currentReadinessProbed=False)
            emit('COMPLETED_MODULE_SCHEMA',module=module,facts=module_schema_read(binary,p,config,row))
    gateway_plan=p['gatewayPlan']
    require(digest(gateway_plan)==p['cohortPlan']['gatewayPlanHash'],'GATEWAY_PLAN_BINDING_DRIFT')
    transport=transport_binding(p,dirs,record)
    emit('GATEWAY_TRANSPORT',runtimeHash=digest(transport['runtimeBinding']),
        containerId=transport['runtimeBinding']['containerId'],adminCredentialPrinted=False)
    first=gateway_read(p['engine'],transport)
    emit('GATEWAY_FIRST_READ',**gateway_projection(gateway_plan,components['gateway'],first))
    second=gateway_read(p['engine'],transport)
    emit('GATEWAY_SECOND_READ',**gateway_projection(gateway_plan,components['gateway'],second))
    emit('GATEWAY_SCAN_STABILITY',stable=first==second,firstMapHash=digest(first),secondMapHash=digest(second))
    require(engine_get(p['engine'],'containers',claim['containerId'])==actual,'MIGRATION_NATIVE_CHANGED_DURING_READ')
    for module,observed in observations.items():require(module_native(p,container_journal,module)==observed,'MODULE_GENERATION_CHANGED_DURING_READ')
    pg=engine_get(p['engine'],'containers',plan['postgresRuntimeBinding']['containerId'])
    require(runtime_pin(pg)==plan['postgresRuntimeBinding'],'POSTGRES_CHANGED_DURING_READ')
    stopped(programs['systemctl'])
    for path,value in snapshots.items():require(read(path,8388608)==value,'RETAINED_RECORD_CHANGED_DURING_READ')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    for row in plan['modules']:
        require(archive(Path(dirs['backups'])/(row['module']+'.dump'),row['maximumArchiveBytes'])==archives[row['module']],
            'RETAINED_ARCHIVE_CHANGED_DURING_READ')
    emit('END',complete=True,technicalPhase=5,functionalMilestonesProven=0,retainedBackupsAndJournalsUnchanged=True,
        databaseMutations=0,serviceMutations=0,dumpProbes=0,grantRequests=0,iamCalls=0,gatewayWrites=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)
