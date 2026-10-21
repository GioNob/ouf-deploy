#!/usr/bin/env python3
"""Fixed-context phase-2 readback. GET/SELECT only; no retry or recovery effects."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path
from urllib.parse import quote
CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-f9616bc49b224fa219e6ea4b8c9ff5425f9728fda0bc2175d6d877ebb5189a9a')
REVIEW='225d317b485939ebf2a5b2582d0f5168a5ff6fe19be17e0e68109c9003dade1c'
AUTHORITY='ce4fcdc3b0af1aaee503582f00af4beed06786641d15afe4a55efa0cd29584d7'
SOURCE='b93e3570bd3e43b6c8e99d2237743bb819e43304'
UNIT='ouf-file-cohort-f9616bc49b224fa219e6ea4b8c9ff542.service'
MODULES=('udp','onboarding','ingestion','mcp')

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-mcp-migration-readback.v1',check=check,readOnly=True,
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

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated,'ISOLATED_ROOT_READ_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:require(False,'TOTAL_TIME_BOUND_EXHAUSTED'));signal.alarm(180)
    emit('BEGIN',maximumSeconds=180,databaseMutations=0,serviceMutations=0,dumpProbes=0,grantRequests=0,iamCalls=0)
    review=read(CONTEXT/'review.json',expected=REVIEW)
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
        status.get('reason')=='MCP_MIGRATION_ROLE_NATIVE_IDENTITY_DRIFT','EXACT_MIGRATION_PAUSE_REQUIRED')
    emit('RETAINED_DELIVERY',recordHash=digest(status),runtimeAuthorityPreviouslyIssued=True,
        authorityExpiredAtRead=time.time()>=1792118031)
    dirs=process['directoryPlan'];plan=p['databasePlan']
    require(all(dirs[k]==str(CONTEXT/k) for k in ('databases','backups')) and
        digest(plan)==p['cohortPlan']['databasePlanHash'],'DATABASE_PLAN_DRIFT')
    journal=record(Path(dirs['databases'])/'recovery.json')
    require(journal['schema']=='ouf.chatbot-cohort-database-journal.v1' and journal['planHash']==digest(plan) and
        journal['authorityHash']==AUTHORITY and journal['budgetReset'] is False and journal['restorePerformed'] is False,
        'DATABASE_JOURNAL_BINDING_DRIFT')
    require([r['module'] for r in plan['modules']]==list(MODULES) and set(journal['backups'])==set(MODULES),
        'ALL_BACKUPS_REQUIRED')
    archives={}
    for row in plan['modules']:
        info=archive(Path(dirs['backups'])/(row['module']+'.dump'),row['maximumArchiveBytes'])
        entry=journal['backups'][row['module']]
        require(entry=={'state':'COMPLETE','scopeHash':digest(row),'archiveSha256':info['sha256'],
            'archiveBytes':info['bytes'],'payloadParsed':True} and info['customFormatHeader'] and info['bytes']>100,
            'COMPLETE_ARCHIVE_DRIFT')
        archives[row['module']]=info;emit('RETAINED_ARCHIVE',module=row['module'],state='COMPLETE',**info)
    name,request=migration_request(p);claim=journal.get('mcpMigration');role=journal.get('mcpAuditRole')
    require(type(claim)is dict and claim.get('state')=='CLAIMED' and claim.get('name')==name and
        claim.get('intentHash')==digest(request),'EXACT_MIGRATION_CLAIM_REQUIRED')
    require(type(role)is dict and role.get('state') in ('BOOTSTRAP_CLAIMED','BOOTSTRAPPED','CLEANUP_CLAIMED','CLEAN'),
        'AUDIT_ROLE_CHECKPOINT_REQUIRED')
    emit('DATABASE_CHECKPOINT',recordHash=digest(journal),migrationState=claim['state'],
        auditRoleState=role['state'],migrationIntentHash=digest(request),technicalPhase1ArchivesVerified=True)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(owner)==p['postGrantWorkerDirectory'],'CURRENT_WORKER_DIRECTORY_DRIFT')
    for file,label in (('recovery.json','WORKER'),('owner-session.json','WORKER_SESSION'),
                       ('owner-admission.json','WORKER_ADMISSION'),('owner-first-grant.json','FIRST_GRANT_REFERENCE')):
        path=owner/file;record(path);metadata(label,path)
    for component in ('containers','authorization','gateway'):
        path=Path(dirs[component])/'recovery.json';v=record(path);metadata('COHORT_'+component.upper(),path)
        emit('COHORT_EFFECT_COUNT',component=component,effectCount=len(v.get('effects',[])))
    transition_path=Path(p['registry']['directoryPlan']['transition'])/'recovery.json'
    transition=record(transition_path);metadata('REGISTRY_TRANSITION',transition_path)
    require(type(transition.get('effects'))is list and len(transition['effects'])<=11,'REGISTRY_EFFECT_SHAPE')
    emit('REGISTRY_EFFECTS',effectCount=len(transition['effects']),
        appliedCount=sum(e.get('state')=='APPLIED' for e in transition['effects']))
    actual=engine_get(p['engine'],'containers',name)
    require(actual is not None,'CLAIMED_MIGRATION_CONTAINER_ABSENT')
    image=engine_get(p['engine'],'images',request['Image'])
    emit('MIGRATION_NATIVE',**native_state(actual),**native_projection(name,request,actual,image))
    binding=next(r for r in plan['modules'] if r['module']=='mcp')
    with tempfile.TemporaryDirectory(prefix='ouf-mcp-read-config-')as config:
        facts=sql_read(executable(programs['docker']),p,config,binding)
    emit('MCP_DATABASE_STATE',facts=facts)
    require(engine_get(p['engine'],'containers',name)==actual,'MIGRATION_NATIVE_CHANGED_DURING_READ')
    pg=engine_get(p['engine'],'containers',plan['postgresRuntimeBinding']['containerId'])
    require(runtime_pin(pg)==plan['postgresRuntimeBinding'],'POSTGRES_CHANGED_DURING_READ')
    stopped(programs['systemctl'])
    for path,value in snapshots.items():require(read(path,2097152)==value,'RETAINED_RECORD_CHANGED_DURING_READ')
    for row in plan['modules']:
        require(archive(Path(dirs['backups'])/(row['module']+'.dump'),row['maximumArchiveBytes'])==archives[row['module']],
            'RETAINED_ARCHIVE_CHANGED_DURING_READ')
    emit('END',complete=True,technicalPhase=2,functionalMilestonesProven=0,retainedBackupsAndJournalsUnchanged=True,
        databaseMutations=0,serviceMutations=0,dumpProbes=0,grantRequests=0,iamCalls=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)
