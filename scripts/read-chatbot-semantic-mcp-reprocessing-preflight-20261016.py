#!/usr/bin/env python3
"""Installation-specific exact MCP admission claim metadata. Read-only SQL; no rearm, retry or claim deletion."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path
from urllib.parse import quote, urlsplit

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-mcp-reprocessing-preflight.v1',check=check,readOnly=True,
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

def engine_info(engine):
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
        conn.request('GET','/v1.44/info')
        reply=conn.getresponse();raw=reply.read(2097153)
        require(reply.status==200 and len(raw)<=2097152,'ENGINE_READ_UNAVAILABLE');guard()
        return json.loads(raw,object_pairs_hook=unique)
    finally:conn.close()

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

KEY='teatri-semantic-draft-be74308e098aa3a6-20261016'
SUBJECT='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'

def literal(value):
    require(type(value)is str and re.fullmatch('[A-Za-z0-9_:.-]{1,128}',value),'CLOSED_SQL_BINDING_REQUIRED')
    return "'"+value+"'"

def query(tenant,database,admin,application):
    where="c.principal_id="+literal(SUBJECT)+" AND c.tenant_id="+literal(tenant)+" AND c.idempotency_key="+literal(KEY)+" AND c.owner='semantic' AND c.capability_id='ouf.semantic.propose' AND c.operation_class='COMMAND'"
    return ("BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "
        "SELECT json_build_object('preflight',(SELECT json_build_object("
        "'applicationRoleExists',true,'applicationSuperuser',r.rolsuper,'applicationCreateRole',r.rolcreaterole,"
        "'applicationCanCreateInSchema',has_schema_privilege(r.oid,'ouf_mcp','CREATE'),"
        "'applicationCanInsertMigration',has_table_privilege(r.oid,'ouf_mcp.schema_migration','INSERT'),"
        "'applicationCanReferenceAttempts',has_table_privilege(r.oid,'ouf_mcp.tool_attempt','REFERENCES'),"
        "'applicationCanReferenceWindows',has_table_privilege(r.oid,'ouf_mcp.budget_window','REFERENCES'),"
        "'applicationCanExecuteImmutableTrigger',has_function_privilege(r.oid,'ouf_mcp.reject_mutation()','EXECUTE'),"
        "'retentionRoleExists',EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ouf_mcp_retention_owner'),"
        "'retentionRoleNoLogin',COALESCE((SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='ouf_mcp_retention_owner'),false),"
        "'retentionRoleSuperuser',COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname='ouf_mcp_retention_owner'),false),"
        "'retentionRoleMembers',(SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname='ouf_mcp_retention_owner')),"
        "'applicationCanSetRetentionRole',CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ouf_mcp_retention_owner') THEN pg_has_role(r.oid,'ouf_mcp_retention_owner','SET') ELSE false END,"
        "'applicationCanUseRetentionRole',CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ouf_mcp_retention_owner') THEN pg_has_role(r.oid,'ouf_mcp_retention_owner','USAGE') ELSE false END,"
        "'retentionFunctionOwnedByRetentionRole',COALESCE((SELECT p.proowner=(SELECT oid FROM pg_roles WHERE rolname='ouf_mcp_retention_owner') FROM pg_proc p WHERE p.oid=to_regprocedure('ouf_mcp.purge_terminal_attempt_graph(timestamp with time zone,integer)')),false),"
        "'retentionFunctionHash',(SELECT encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex') FROM pg_proc p WHERE p.oid=to_regprocedure('ouf_mcp.purge_terminal_attempt_graph(timestamp with time zone,integer)')),"
        "'newSessionTableAbsent',to_regclass('ouf_mcp.semantic_reprocessing_session') IS NULL,"
        "'serverVersionNum',current_setting('server_version_num')::int,"
        "'migrationCount',(SELECT count(*) FROM ouf_mcp.schema_migration),"
        "'migrations',(SELECT COALESCE(json_agg(x),'[]'::json) FROM (SELECT version,checksum FROM ouf_mcp.schema_migration ORDER BY version LIMIT 256)x)"
        ") FROM pg_roles r WHERE r.rolname="+literal(application)+"),'readOnly',current_setting('transaction_read_only')='on',"
        "'databaseMatched',current_database()="+literal(database)+",'roleMatched',current_user="+literal(admin)+","
        "'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),"
        "'claimCount',(SELECT count(*) FROM ouf_mcp.idempotency_claim c WHERE "+where+"),"
        "'claims',(SELECT COALESCE(json_agg(x),'[]'::json) FROM ("
        "SELECT c.attempt_id::text AS \"attemptId\",c.request_hash AS \"requestHash\","
        "a.manifest_checksum AS \"manifestChecksum\",c.service_principal_id AS \"servicePrincipalId\",ac.actor_type AS \"actorType\",a.state,a.dispatch_state AS \"dispatchState\",a.lock_version AS \"lockVersion\","
        "b.state AS \"reservationState\",b.actual_tool_calls AS \"actualToolCalls\","
        "b.reserved_tool_calls AS \"reservedToolCalls\","
        "EXISTS(SELECT 1 FROM ouf_mcp.attempt_admission_context ac WHERE ac.attempt_id=c.attempt_id) AS \"admissionContextPresent\","
        "COALESCE((SELECT safe_detail->>'outcomeCode' FROM ouf_mcp.audit_event WHERE attempt_id=c.attempt_id AND event_type='TOOL_ATTEMPT_RECONCILED' ORDER BY sequence_id DESC LIMIT 1),'')='SEM_CAPABILITY_REQUIRED:ouf.semantic.propose' AS \"expectedDenialCodeProven\" "
        "FROM ouf_mcp.idempotency_claim c JOIN ouf_mcp.tool_attempt a USING(attempt_id) "
        "LEFT JOIN ouf_mcp.budget_reservation b USING(attempt_id) LEFT JOIN ouf_mcp.attempt_admission_context ac USING(attempt_id) WHERE "+where+
        " ORDER BY c.attempt_id LIMIT 4) x)); ROLLBACK;")

EXPECTED_MIGRATIONS=[{'checksum': 'a70a2389352f5f8387f96b6051becf97f64f1e922aba9c353545449e0fa0b225', 'version': 1}, {'checksum': '138614ca67d9365e7525c0d56313ab1514e3ea9f1fe32b5095a3d85e3ecbb74d', 'version': 2}, {'checksum': '044d5d6fe3fdd5f77179a4f677885aa3ca4f72ca1bc52f6f10c44b57306bfb3e', 'version': 3}, {'checksum': '9bae68eb83dabf8bd80fcfdf38189c54cced1228b3b22a7128c4c5cda3b7c72c', 'version': 4}, {'checksum': '3dc65eeee6668444e77e3a08982a71a1412fda53c3e8b90cbddd7d6959e5ad54', 'version': 5}, {'checksum': '8973286df97ef30dd7281dfaf5bfb251ca078d4a2862de235b6988bc5e5eb375', 'version': 6}, {'checksum': 'ad1e6b93b10ae2b6e407015f4bfb5026f2cd633a8565d30584fddd98e274f174', 'version': 7}, {'checksum': '2e279669f11a1b4949c93e17522d127003aa7c3f54cd2af0461500676f2bef28', 'version': 8}, {'checksum': '798ec17290d8952a6824871739d4b352bc3984f4e600fda9c704d6784d704dd2', 'version': 9}, {'checksum': '64b586222b534976c379dbec667e4bcb3f7c58087b436b02f79f588e3bb9b0a5', 'version': 10}, {'checksum': 'd6393214c1b83da875015018e5e50833fe6fe4ea0571adf98d5f34fbe390995e', 'version': 11}, {'checksum': 'de64bdcfa45b1e373807d07e603cd1940defe056cec4a21e0db4c7667330cc68', 'version': 12}]
EXPECTED_RUNTIME_BINDING="f31e9c1951f79765287b3cb9263294785446430f7b0833a2d87b0a7783b7950d"

def project(facts,binding):
    require(type(facts)is dict and 'preflight'in facts,'PREFLIGHT_FACTS_REQUIRED')
    facts=dict(facts);preflight=facts.pop('preflight')
    boolean_keys={'applicationRoleExists','applicationSuperuser','applicationCreateRole',
        'applicationCanCreateInSchema','applicationCanInsertMigration','applicationCanReferenceAttempts',
        'applicationCanReferenceWindows','applicationCanExecuteImmutableTrigger','retentionRoleExists',
        'retentionRoleNoLogin','retentionRoleSuperuser','applicationCanSetRetentionRole',
        'applicationCanUseRetentionRole','retentionFunctionOwnedByRetentionRole','newSessionTableAbsent'}
    require(type(preflight)is dict and set(preflight)==boolean_keys|{'retentionRoleMembers',
        'retentionFunctionHash','serverVersionNum','migrationCount','migrations'}
        and all(type(preflight[k])is bool for k in boolean_keys)
        and all(type(preflight[k])is int and 0<=preflight[k]<=1000000
            for k in ('retentionRoleMembers','serverVersionNum','migrationCount'))
        and preflight['retentionFunctionHash']is not None and type(preflight['retentionFunctionHash'])is str
        and re.fullmatch('[0-9a-f]{64}',preflight['retentionFunctionHash'])
        and preflight['migrationCount']==12 and preflight['migrations']==EXPECTED_MIGRATIONS,
        'EXACT_MIGRATION_PREFIX_AND_ROLE_FACTS_REQUIRED')
    flags=('readOnly' ,'databaseMatched','roleMatched')
    require(type(facts)is dict and set(facts)==set(flags)|{'databaseOid','claimCount','claims'}
        and all(facts.get(k)is True for k in flags)
        and type(facts['databaseOid'])is int and facts['databaseOid']==binding['databaseOid']
        and type(facts['claimCount'])is int and 0<=facts['claimCount']<=4
        and type(facts['claims'])is list and len(facts['claims'])==facts['claimCount'], 'BOUNDED_EXACT_DATABASE_FACTS_REQUIRED')
    keys={'attemptId','requestHash','state','dispatchState','lockVersion','reservationState',
          'actualToolCalls','reservedToolCalls','admissionContextPresent','manifestChecksum','servicePrincipalId','actorType','expectedDenialCodeProven'}
    for row in facts['claims']:
        require(type(row)is dict and set(row)==keys
            and type(row['attemptId'])is str and re.fullmatch('[0-9a-f-]{36}',row['attemptId'])
            and type(row['manifestChecksum'])is str and re.fullmatch('[0-9a-f]{64}',row['manifestChecksum'])
            and type(row['servicePrincipalId'])is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',row['servicePrincipalId'])
            and row['actorType']in {'HUMAN','AI_AGENT','SYSTEM'}
            and type(row['expectedDenialCodeProven'])is bool
            and type(row['requestHash'])is str and re.fullmatch('[0-9a-f]{64}',row['requestHash'])
            and row['state']in {'ADMITTED','RUNNING','SUCCEEDED','FAILED','UNKNOWN','UNRESOLVED','NOT_DISPATCHED'}
            and row['dispatchState']in {'NOT_DISPATCHED','DISPATCHED','ACKNOWLEDGED','UNKNOWN'}
            and row['reservationState']in {None,'RESERVED','RECONCILED'}
            and type(row['lockVersion'])is int and 0<=row['lockVersion']<=1000000
            and all(row[k]is None or type(row[k])is int and 0<=row[k]<=1000000
                for k in ('actualToolCalls','reservedToolCalls'))
            and type(row['admissionContextPresent'])is bool,'SAFE_CLAIM_PROJECTION_REQUIRED')
    facts['preflight']=preflight
    return facts

def observe(*,report=True):
    report_event=emit if report else lambda *args,**kwargs:None
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READER_REQUIRED');signal.alarm(120)
    report_event('BEGIN',maximumSeconds=120,maximumSqlSessions=1,maximumClaims=4,maximumEngineReads=4,
        credentialFilesRead=0,databaseMutations=0,serviceMutations=0,grantRequests=0,mcpCalls=0,
        claimDeletionAllowed=False,claimRearmAllowed=False)
    review=read(CONTEXT/'review.json',8388608,REVIEW);authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority[k]==v for k,v in review['scopes'].items()),'RETAINED_AUTHORITY_BINDING_DRIFT')
    process=review['scopes']['finiteActionProcess'];programs=review['sourceClosure']['executables']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'PROCESS_BINDING_DRIFT')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    plan=p['databasePlan'];binding=next(r for r in plan['modules']if r['module']=='mcp')
    module=next(r for r in p['cohortPlan']['replacements']if r['module']=='mcp')
    require(type(module['sourceCommit'])is str and re.fullmatch('[0-9a-f]{40}',module['sourceCommit']),
        'EXACT_MCP_SOURCE_COMMIT_REQUIRED')
    mcp=engine_get(p['engine'],'containers',module['name'])
    observed_source=(mcp or {}).get('Config',{}).get('Labels',{}).get('org.opencontainers.image.revision')
    report_event('MCP_PACKAGE_CHECKS',reviewedSourceCommit=module['sourceCommit'],containerPresent=mcp is not None,
        nativeSourceCommit=observed_source if type(observed_source)is str and re.fullmatch('[0-9a-f]{40}',observed_source)else None,
        nativeImageMatchesReviewed=mcp is not None and mcp['Image']==module['creationRequest']['Image'],
        nativeSourceLabelMatchesReviewed=observed_source==module['sourceCommit'],configurationValuesPrinted=False)
    require(mcp is not None and mcp['State']['Running']is True and mcp['State']['Paused']is False
        and mcp['Image']==module['creationRequest']['Image']
        and mcp['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==module['sourceCommit'],
        'REVIEWED_MCP_PACKAGE_GENERATION_REQUIRED')
    mcp_pin=runtime_pin(mcp)
    require(digest(mcp_pin)==EXPECTED_RUNTIME_BINDING,'OBSERVED_MCP_GENERATION_REQUIRED')

    require(type(binding['databaseOid'])is int and binding['databaseOid']>0,'EXACT_DATABASE_OID_REQUIRED')
    admin=plan['mcpAuditRoleAdministration']['admin'];tenant=p['authorization']['plan']['selection']['tenant']
    require(p['authorization']['plan']['selection']['subject']==SUBJECT,'EXACT_RETAINED_HUMAN_REQUIRED')
    for value in (binding['database'],admin):
        require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_SQL_IDENTIFIER_REQUIRED')
    pg=engine_get(p['engine'],'containers',plan['postgresRuntimeBinding']['containerId'])
    require(pg is not None and runtime_pin(pg)==plan['postgresRuntimeBinding']
        and pg['State']['Running']is True and pg['State']['Paused']is False,'POSTGRES_GENERATION_DRIFT')
    require([v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]==[admin],
        'ADMINISTRATOR_SELECTION_DRIFT')
    with tempfile.TemporaryDirectory(prefix='ouf-mcp-claim-read-config-')as config:
        argv=[executable(programs['docker']),'--host','unix://'+p['engine']['socketPath'],'--config',config,
            'exec',pg['Id'],'env','LC_ALL=C',
            'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
            'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
            '-U',admin,'-d',binding['database'],'-c',query(tenant,binding['database'],admin,binding['user'])]
        code,raw,err,_=bounded(argv,seconds=20,maximum=65536)
        require(code==0,'READ_ONLY_SQL_FAILED')
        facts=project(json.loads(raw,object_pairs_hook=unique),binding)
    require(runtime_pin(engine_get(p['engine'],'containers',pg['Id']))==plan['postgresRuntimeBinding'],
        'POSTGRES_CHANGED_DURING_READ')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    after=engine_get(p['engine'],'containers',mcp['Id'])
    require(after is not None and runtime_pin(after)==mcp_pin,'MCP_CHANGED_DURING_READ')
    report_event('MCP_RELEASE_BINDING',sourceCommit=module['sourceCommit'],imageId=mcp['Image'],
        containerId=mcp['Id'],runtimeBindingHash=digest(mcp_pin),runtimeBinding=mcp_pin,
        nativeSourceLabelMatchesReviewed=True,configurationValuesPrinted=False)
    preflight=facts.pop('preflight')
    report_event('MIGRATION_ROLE_PREFLIGHT',facts=preflight,migrationPrefixMatchesInstalledSource=True,
        privilegeChangesPerformed=False,migrationPerformed=False)
    report_event('EXACT_MCP_CLAIM',facts=facts,rawSqlOutputPrinted=False,claimRearmed=False,
        semanticMutationDispatchedByReader=False)
    report_event('END',complete=True,completedTechnicalPhases=8,functionalMilestonesProven=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,databaseMutations=0,
        automaticRestart=False,budgetResetPreserved=True)
    return {'prepared':p,'module':module,'mcp':mcp,'runtimeBinding':mcp_pin,
        'claimFacts':facts,'rolePreflight':preflight,'programs':programs,
        'sourceReviewHash':REVIEW,'sourceAuthorityHash':AUTHORITY}

def main():
    observe()

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)
