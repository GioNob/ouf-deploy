#!/usr/bin/env python3
"""Inspect the confirmed MCP failure, worker history and proposed backup reader.

No journal writes, backup replacement, migration, IAM or runtime authority.
The diagnostic stream is discarded; it is never accepted as a backup.
"""
import hashlib, http.client, json, os, re, selectors, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-37f1e44e094db4158bd12c5d83a67478786a1531142ba6c07d172ae05f80cbb9')
REVIEW='9d2e5fbc8c0c0b0e14faaea7003d151fe221c94b08ca3c1204d3a402ea837219'
AUTHORITY='936d15d844e0d11bd95ee3c463843fbb5e5e2361e10c3d9ac22901f4557a9b36'
SOURCE='e70ca5957772e170bc762dd937e1c46a40051f0a'
UNIT='ouf-file-cohort-37f1e44e094db4158bd12c5d83a67478.service'
MODULES=('udp','onboarding','ingestion','mcp')
DATABASE_JOURNAL='2c55b26774660d1e56d6855b5425c18b2cc26a6ab09da463fe324229b744094c'
class ReadDenied(Exception):pass
def require(ok,code):
    if not ok:raise ReadDenied(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def emit(check,**v):
    fixed=dict(schema='ouf.chatbot-mcp-backup-preflight.v1',check=check,readOnly=True,automaticRetry=False,budgetReset=False)
    require(not set(v)&set(fixed),'RESERVED_DIAGNOSTIC_FIELD')
    print(json.dumps({**fixed,**v},sort_keys=True),flush=True)
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

def classify(raw, code):
    """Closed classifications only; never print stderr, table names or SQL."""
    if code == 0:return 'DUMP_PROBE_SUCCEEDED'
    if code in (124,137,-9):return 'PROBE_TIME_BOUND_EXHAUSTED'
    patterns=(
        (rb'permission denied for (?:table|sequence|schema|relation)', 'INSUFFICIENT_PRIVILEGE'),
        (rb'query would be affected by row-level security policy', 'ROW_LEVEL_SECURITY'),
        (rb'password authentication failed', 'PASSWORD_AUTHENTICATION_FAILED'),
        (rb'Peer authentication failed', 'PEER_AUTHENTICATION_FAILED'),
        (rb'no pg_hba.conf entry', 'HOST_AUTHENTICATION_DENIED'),
        (rb'aborting because of server version mismatch', 'DUMP_VERSION_MISMATCH'),
        (rb'canceling statement due to lock timeout', 'LOCK_TIMEOUT'),
        (rb'canceling statement due to statement timeout', 'STATEMENT_TIMEOUT'),
        (rb'too many (?:clients|connections)', 'CONNECTION_CAPACITY'),
        (rb'database system is (?:starting up|shutting down|in recovery)', 'DATABASE_UNAVAILABLE'),
        (rb'database .* is not currently accepting connections', 'DATABASE_CONNECTIONS_DISABLED'),
        (rb'(?:timeout|pg_dump).* (?:not found|No such file or directory)', 'PROBE_TOOL_UNAVAILABLE'))
    for pattern, reason in patterns:
        if re.search(pattern,raw):return reason
    return 'UNCLASSIFIED_DUMP_FAILURE'

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

def inspect(engine,cid):
    require(re.fullmatch('[0-9a-f]{64}',cid),'EXACT_CONTAINER_ID_REQUIRED')
    path=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(path,follow_symlinks=False)
        require(stat.S_ISSOCK(s.st_mode) and
            (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.sock.settimeout(10);self.sock.connect(path)
    conn=Local('localhost',timeout=10)
    try:
        conn.request('GET','/v1.44/containers/'+cid+'/json');reply=conn.getresponse();raw=reply.read(2097153)
        require(reply.status==200 and len(raw)<=2097152,'CONTAINER_GET_FAILED');guard()
        return json.loads(raw,object_pairs_hook=unique)
    finally:conn.close()

def runtime_pin(actual):
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}

def native_guard(prepared):
    pin=prepared['databasePlan']['postgresRuntimeBinding']
    pg=inspect(prepared['engine'],pin['containerId'])
    require(runtime_pin(pg)==pin and pg['State']['Running'] is True and pg['State']['Paused'] is False,
        'POSTGRES_GENERATION_DRIFT')
    for row in prepared['cohortPlan']['replacements']:
        pin=row['oldRuntimeBinding'];actual=inspect(prepared['engine'],pin['containerId'])
        host={**row['oldHostConfig'],'RestartPolicy':{'Name':'no','MaximumRetryCount':0}}
        require(actual['Id']==pin['containerId'] and actual['Image']==pin['imageId'] and
            digest(actual['Config'])==pin['configHash'] and digest(actual['HostConfig'])==digest(host) and
            actual['State']['Running'] is False and actual['State']['Pid']==0 and
            actual['State']['StartedAt']==pin['startedAt'],'PRODUCER_QUIESCENCE_UNPROVEN')

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

def failed_binding(plan, journal):
    require(journal.get('schema')=='ouf.chatbot-cohort-database-journal.v1' and
        journal.get('planHash')==digest(plan) and journal.get('authorityHash')==AUTHORITY and
        journal.get('budgetReset') is False and journal.get('restorePerformed') is False and
        journal.get('mcpMigration') is None and journal.get('mcpAuditRole') is None,'EXACT_UNMIGRATED_DATABASE_JOURNAL_REQUIRED')
    require([r['module']for r in plan['modules']]==list(MODULES),'EXACT_DATABASE_ORDER_REQUIRED')
    backups=journal['backups'];require(type(backups)is dict and set(backups)<=set(MODULES),'UNKNOWN_BACKUP_ENTRY')
    claimed=[m for m in MODULES if backups.get(m,{}).get('state')=='CLAIMED']
    require(len(claimed)==1,'ONE_UNRESOLVED_BACKUP_REQUIRED')
    index=MODULES.index(claimed[0]);require(set(backups)==set(MODULES[:index+1]),'BACKUP_PREFIX_DRIFT')
    for row in plan['modules'][:index+1]:
        entry=backups[row['module']]
        require(entry.get('scopeHash')==digest(row) and
            entry.get('state')==('CLAIMED' if row['module']==claimed[0] else 'COMPLETE'),'BACKUP_SCOPE_DRIFT')
    row=plan['modules'][index]
    require(backups[claimed[0]]=={'state':'CLAIMED','scopeHash':digest(row)},'UNKNOWN_CLAIM_FIELDS')
    for name in ('user','database'):
        require(type(row[name])is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',row[name]),'EXACT_DATABASE_IDENTIFIER_REQUIRED')
    require(type(row['maximumArchiveBytes'])is int and 100<row['maximumArchiveBytes']<=1073741824,'DUMP_SIZE_BOUND_REQUIRED')
    return row

def dump_probe(binary,engine,config,plan,binding):
    # timeout runs INSIDE PostgreSQL's container; killing Docker's CLI alone
    # would not prove termination of its remote exec. Missing timeout fails closed.
    argv=[binary,'--host','unix://'+engine['socketPath'],'--config',config,
        'exec',plan['postgresRuntimeBinding']['containerId'],'env','LC_ALL=C',
        'timeout','-s','KILL','75','pg_dump','-U',binding['user'],'-d',binding['database'],
        '--format=custom','--no-owner','--no-acl','--lock-wait-timeout=10s']
    code,_,err,count=bounded(argv,seconds=85,maximum=binding['maximumArchiveBytes'],discard=True)
    reason=classify(err,code)
    if code==0 and count<=100:reason='DUMP_PROBE_TOO_SMALL'
    return {'classification':reason,'exitCode':code,'dumpBytes':count,
        'stderrBytes':len(err),'rawDiagnosticPrinted':False,'backupAccepted':False}

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

def recovery_checkpoint(review,prepared):
    """Public hashes/counters only; never read credentials or execute old source."""
    paths=prepared['registry']['directoryPlan']
    transition=metadata('REGISTRY_TRANSITION',Path(paths['transition'])/'recovery.json')
    phases={'STOP_REVOKE_OLD_LEASE','QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT',
        'CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER','ADMIT_MIGRATION',
        'START_REPLACEMENT','VERIFY_APPLICATION','RELEASE_PRODUCERS'}
    rows=[]
    require(type(transition.get('effects'))is list and len(transition['effects'])<=11,'BOUNDED_REGISTRY_EFFECTS_REQUIRED')
    for effect in transition['effects']:
        require(effect.get('phase')in phases and effect.get('state')in ('APPLIED','IN_FLIGHT','NO_EFFECT','UNKNOWN'),
            'KNOWN_REGISTRY_PHASE_REQUIRED')
        item={k:effect[k]for k in ('phase','state')}
        for key in ('intentHash','authorityEvidenceHash','nativeEvidenceHash'):
            value=effect.get(key)
            require(value is None or (type(value)is str and re.fullmatch('[0-9a-f]{64}',value)),'SAFE_PHASE_HASH_REQUIRED')
            item[key]=value
        rows.append(item)
    emit('REGISTRY_PHASES',effects=rows)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    for name,label in [('recovery.json','WORKER'),('owner-session.json','WORKER_SESSION'),
                       ('owner-admission.json','WORKER_ADMISSION'),('owner-first-grant.json','FIRST_GRANT')]:
        metadata(label,owner/name)
    directories=review['scopes']['finiteActionProcess']['directoryPlan']
    for name in ('containers','authorization','gateway'):
        value=metadata('COHORT_'+name.upper(),Path(directories[name])/'recovery.json')
        emit('COHORT_EFFECT_COUNT',component=name,effectCount=len(value.get('effects',[])))
    node=Path(paths['node'])
    for name,label in [('frame-policy.json','NODE_POLICY'),('paused-acceptance.json','NODE_ACCEPTANCE'),
                       ('attestation-issuance-claim.json','NODE_ISSUANCE')]:
        metadata(label,node/name)
    cid='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
    actual=inspect(prepared['engine'],cid);state=actual['State']
    require(state.get('Status')in ('created','running','paused','restarting','removing','exited','dead'),
        'SAFE_REGISTRY_STATUS_REQUIRED')
    require(all(type(state.get(k))is bool for k in ('Running','Paused')) and
        type(state.get('Pid'))is int and type(actual.get('RestartCount'))is int,'SAFE_REGISTRY_NATIVE_METADATA_REQUIRED')
    emit('REGISTRY_NATIVE',runtimeHash=digest(runtime_pin(actual)),status=state['Status'],
        running=state['Running'],paused=state['Paused'],pid=state['Pid'],restartCount=actual['RestartCount'])

def backup_reader_preflight(binary,prepared,config,binding):
    plan=prepared['databasePlan'];admin=plan['mcpAuditRoleAdministration']['admin']
    require(type(admin)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',admin),'EXACT_EXISTING_ADMIN_SELECTOR_REQUIRED')
    pg=inspect(prepared['engine'],plan['postgresRuntimeBinding']['containerId'])
    selectors=[v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]
    require(selectors==[admin],'SELECTED_ADMIN_CONFIG_DRIFT')
    app="'"+binding['user']+"'";database="'"+binding['database']+"'"
    query=("SELECT json_build_object('databaseOid',d.oid::bigint,"
        "'databaseMatched',current_database()="+database+",'roleMatched',current_user='"+admin+"',"
        "'superuser',r.rolsuper,'readOnly',current_setting('transaction_read_only')='on',"
        "'applicationMissingTableSelect',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE c.relkind IN ('r','p','m') AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' "
        "AND NOT has_table_privilege("+app+",c.oid,'SELECT')),"
        "'applicationMissingSequenceSelect',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' "
        "AND NOT has_sequence_privilege("+app+",c.oid,'SELECT')),"
        "'applicationIncidentSelect',has_table_privilege("+app+",'ouf_mcp.security_incident','SELECT')) "
        "FROM pg_database d CROSS JOIN pg_roles r WHERE d.datname=current_database() AND r.rolname=current_user")
    argv=[binary,'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],
        'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000',
        'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',query]
    code,raw,_,_=bounded(argv,seconds=20,maximum=8192)
    require(code==0,'ADMINISTRATIVE_READ_ONLY_PREFLIGHT_FAILED')
    facts=json.loads(raw,object_pairs_hook=unique)
    flags=('databaseMatched','roleMatched','superuser','readOnly','applicationIncidentSelect')
    counts=('applicationMissingTableSelect','applicationMissingSequenceSelect')
    require(type(facts)is dict and set(facts)==set(flags)|set(counts)|{'databaseOid'} and
        type(facts['databaseOid'])is int and facts['databaseOid']==binding['databaseOid'] and
        all(type(facts[k])is bool for k in flags) and all(facts[k] for k in flags[:-1]) and
        all(type(facts[k])is int and 0<=facts[k]<=1000000 for k in counts),'ADMINISTRATIVE_PREFLIGHT_IDENTITY_OR_SHAPE_DRIFT')
    return admin,facts

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated,'ISOLATED_ROOT_READ_REQUIRED')
    emit('BEGIN',databaseMutations=0,serviceMutations=0,grantRequests=0,maximumDumpProbes=1)
    review=read(CONTEXT/'review.json',expected=REVIEW)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_EXECUTED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(all(authority[k]==v for k,v in review['scopes'].items()),'AUTHORITY_SCOPE_DRIFT')
    process=review['scopes']['finiteActionProcess']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and
        digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    status=read(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION' and
        status.get('reason')=='COHORT_DATABASE_DUMP_FAILED','EXACT_BACKUP_FAILURE_REQUIRED')
    programs=review['sourceClosure']['executables'];stopped(programs['systemctl'])
    directories=process['directoryPlan']
    require(all(directories[k]==str(CONTEXT/k)for k in ('databases','backups')),'FIXED_BACKUP_DIRECTORIES_REQUIRED')
    journal_path=Path(directories['databases'])/'recovery.json';journal=read(journal_path)
    plan=p['databasePlan'];require(digest(plan)==p['cohortPlan']['databasePlanHash'],'DATABASE_PLAN_DRIFT')
    binding=failed_binding(plan,journal)
    retained={}
    for row in plan['modules']:
        if row['module'] not in journal['backups']:continue
        info=archive(Path(directories['backups'])/(row['module']+'.dump'),row['maximumArchiveBytes'])
        retained[row['module']]=info
        entry=journal['backups'][row['module']]
        if entry['state']=='COMPLETE':
            require(entry.get('archiveSha256')==info['sha256'] and entry.get('archiveBytes')==info['bytes'] and
                entry.get('payloadParsed') is True and info['customFormatHeader'],'COMPLETE_ARCHIVE_DRIFT')
        emit('RETAINED_ARCHIVE',module=row['module'],state=entry['state'],**info)
    emit('RETAINED_CHECKPOINT',failedModule=binding['module'],journalHash=digest(journal),
        migrationStarted=False,originalStderrAvailable=False)
    require(digest(journal)==DATABASE_JOURNAL and binding['module']=='mcp',
        'CONFIRMED_MCP_BACKUP_CHECKPOINT_DRIFT')
    recovery_checkpoint(review,p)
    native_guard(p)
    with tempfile.TemporaryDirectory(prefix='ouf-backup-read-')as config:
        binary=executable(programs['docker'])
        admin,preflight=backup_reader_preflight(binary,p,config,binding)
        emit('MCP_BACKUP_READER_PREFLIGHT',facts=preflight)
        result=dump_probe(binary,p['engine'],config,plan,{**binding,'user':admin})
    native_guard(p);stopped(programs['systemctl'])
    require(read(journal_path)==journal and read(CONTEXT/'delivery-status.json',16384)==status,'RETAINED_JOURNAL_CHANGED')
    for row in plan['modules']:
        if row['module'] in retained:
            require(archive(Path(directories['backups'])/(row['module']+'.dump'),row['maximumArchiveBytes'])==retained[row['module']],
                'RETAINED_BACKUP_CHANGED')
    emit('ADMINISTRATIVE_DUMP_PROBE',module=binding['module'],applicationPrivilegesChanged=False,**result)
    emit('END',complete=True,retainedBackupsAndJournalUnchanged=True,databaseMutations=0,serviceMutations=0,
        grantRequests=0,runtimeAuthorityIssued=False,reconciliationPerformed=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)
