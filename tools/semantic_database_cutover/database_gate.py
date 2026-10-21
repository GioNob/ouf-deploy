"""Database-specific admission and writer fence primitive, never a target CLI.

A sealed root caller still owns authority, producer lifecycle, source/command
custody, backup admission and peer/lease coordination. No default target, grant,
automatic reopen, restore, retry or application migration is implemented here.
ADMISSION_CLOSED is explicitly weaker than WRITERS_FENCED.
"""
import hashlib, json, os, re, selectors, stat, subprocess, tempfile, time, uuid
from pathlib import Path

class GateDenied(RuntimeError): pass

def require(ok, reason):
    if not ok: raise GateDenied(reason)

def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
def literal(value): return "'" + value.replace("'", "''") + "'"
def identifier(value):
    require(type(value) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value), 'DATABASE_IDENTIFIER_DENIED')
    return '"'+value+'"'

def durable(path,value):
    path=Path(path)
    info=path.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_EVIDENCE_DIRECTORY_REQUIRED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(encoded(value)+b'\n');stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

class Psql:
    """Bounded JSON-framed local psql channel. Caller pins actual command custody.

    This adapter uses the container's local PostgreSQL authentication; it reads
    no host registry credentials and prints no SQL, passwords or stderr values.
    """
    def __init__(self,container_id,user,database,application_name):
        require(re.fullmatch('[0-9a-f]{64}',container_id) is not None,'FULL_DATABASE_CONTAINER_ID_REQUIRED')
        identifier(user);identifier(database)
        require(re.fullmatch('ouf-cutover-[a-z0-9-]{1,40}',application_name) is not None,'BOUNDED_APPLICATION_NAME_REQUIRED')
        self.temp=tempfile.TemporaryDirectory(prefix='ouf-pg-channel-')
        self.error=open(Path(self.temp.name)/'stderr','xb');os.chmod(self.error.name,0o600)
        self.process=subprocess.Popen(['docker','--config',self.temp.name,'exec','-i',container_id,'env','PGAPPNAME='+application_name,
                    'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d',database],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error)
        self.selector=selectors.DefaultSelector();self.selector.register(self.process.stdout,selectors.EVENT_READ);self.buffer=b''
        self.database=database
    def query(self,expression,statement='',timeout=15):
        nonce=uuid.uuid4().hex
        raw=(statement+"\nSELECT json_build_object('nonce',"+literal(nonce)+",'value',("+expression+"));\n").encode()
        try:self.process.stdin.write(raw);self.process.stdin.flush()
        except (OSError,BrokenPipeError):raise GateDenied('PG_CHANNEL_CLOSED') from None
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            while b'\n' in self.buffer:
                line,self.buffer=self.buffer.split(b'\n',1)
                if not line.strip():continue
                try:value=json.loads(line)
                except ValueError:raise GateDenied('PG_CHANNEL_FRAME_INVALID') from None
                require(value.get('nonce')==nonce,'PG_CHANNEL_FRAME_ORDER_CHANGED')
                return value['value']
            if self.selector.select(max(0,until-time.monotonic())):
                raw=os.read(self.process.stdout.fileno(),65536)
                require(bool(raw),'PG_STATEMENT_DENIED')
                self.buffer+=raw;require(len(self.buffer)<262144,'PG_CHANNEL_OUTPUT_UNBOUNDED')
        raise GateDenied('PG_CHANNEL_TIMEOUT')
    def close(self):
        if self.process.poll() is None:
            try:self.process.stdin.write(b'\\q\n');self.process.stdin.flush();self.process.stdin.close()
            except OSError:pass
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.terminate();self.process.wait(timeout=5)
        self.selector.close();self.error.close();self.temp.cleanup()

def install_gate(admin,database,expected_oid,retained_sessions,evidence_directory,*,checkpoint=None):
    """Close only one exact database, terminate other sessions, prove the fence.

    retained_sessions are exact pid/backend_start/application_name/usename pins
    from the separately authenticated caller. They are not booleans conferring
    maintenance authority. The caller must admit only its fixed backup/hold
    programs and prove their behavior/custody. Claims are one-use; no rollback.
    """
    require(type(admin) is Psql and admin.database!=database,'OUTSIDE_DATABASE_ADMIN_CHANNEL_REQUIRED')
    name=identifier(database)
    require(type(expected_oid) is int and expected_oid>0,'EXACT_DATABASE_OID_REQUIRED')
    require(type(retained_sessions) is list and len(retained_sessions)<=2,'BOUNDED_MAINTENANCE_SESSIONS_REQUIRED')
    for session in retained_sessions:
        require(set(session)=={'pid','backendStart','applicationName','user'} and type(session['pid']) is int and session['pid']>1
                and type(session['backendStart']) is str and re.fullmatch('ouf-cutover-(dump|hold)-[a-f0-9]{16}',session['applicationName']) is not None,
                'EXACT_MAINTENANCE_SESSION_PIN_REQUIRED')
    require(len(set(s['pid'] for s in retained_sessions))==len(retained_sessions),'DUPLICATE_MAINTENANCE_SESSION')
    root=Path(evidence_directory)
    phase='PRECHECK'
    claim=root/'gate-claim.json'
    require(not os.path.lexists(claim),'DO_NOT_REPLAY_GATE_CLAIM')
    def database_state():
        return admin.query("SELECT json_build_object('oid',oid::bigint,'allowConnections',datallowconn,'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts WHERE database="+literal(database)+")) FROM pg_database WHERE datname="+literal(database))
    def sessions():
        return admin.query("SELECT COALESCE(json_agg(json_build_object('pid',pid,'backendStart',(backend_start AT TIME ZONE 'UTC')::text,'applicationName',application_name,'user',usename) ORDER BY pid),'[]'::json) FROM pg_stat_activity WHERE datname="+literal(database),"SELECT pg_stat_clear_snapshot();")
    # pg_stat_clear_snapshot returns an empty scalar line, compatible with quiet psql.
    state=database_state()
    require(state and state['oid']==expected_oid and state['allowConnections'] and state['preparedTransactions']==0,'DATABASE_SCOPE_OR_INITIAL_STATE_CHANGED')
    require(admin.query("SELECT rolsuper FROM pg_roles WHERE rolname=current_user") is True,'SCOPED_ADMIN_TERMINATION_AUTHORITY_REQUIRED')
    require(admin.query("SELECT current_setting('fsync')='on' AND current_setting('synchronous_commit')='on'") is True,'DURABLE_DATABASE_GATE_REQUIRED')
    actual=sessions()
    require(all(s in actual for s in retained_sessions),'MAINTENANCE_SESSION_GENERATION_CHANGED')
    durable(claim,{'schema':'ouf.discovery.database-gate-claim.v1','databaseScopeHash':digest({'name':database,'oid':expected_oid}),
                  'retainedSessionHashes':[digest(s) for s in retained_sessions],'state':'INSTALLING_NOT_FENCED','automaticReopen':False,'doNotRerunApply':True})
    try:
        phase='CLOSE_ADMISSION'
        admin.query('true','ALTER DATABASE '+name+' ALLOW_CONNECTIONS false;')
        phase='ADMISSION_CLOSED_NOT_YET_WRITER_FENCED'
        require(database_state()['allowConnections'] is False,'DATABASE_ADMISSION_CLOSE_UNPROVEN')
        durable(root/'admission-closed.json',{'state':phase,'writersFenced':False,'automaticReopen':False})
        if checkpoint:checkpoint(phase)
        allowed={s['pid'] for s in retained_sessions}
        deadline=time.monotonic()+10
        while True:
            current=sessions()
            require(all(s in current for s in retained_sessions),'MAINTENANCE_SESSION_GENERATION_CHANGED')
            victims=[s['pid'] for s in current if s['pid'] not in allowed]
            if not victims:break
            require(time.monotonic()<deadline,'DATABASE_WRITER_TERMINATION_UNPROVEN')
            for pid in victims:
                require(admin.query('SELECT pg_terminate_backend('+str(pid)+',1000)') is True,'DATABASE_WRITER_TERMINATION_DENIED')
        phase='WRITERS_FENCED'
        require(database_state()['allowConnections'] is False and sessions()==sorted(retained_sessions,key=lambda s:s['pid']),'DATABASE_FENCE_FINAL_READ_CHANGED')
        report={'schema':'ouf.discovery.database-gate.v1','status':phase,'databaseScopeHash':digest({'name':database,'oid':expected_oid}),
                'retainedSessionHashes':[digest(s) for s in retained_sessions],'newConnectionsDenied':True,'otherSessionsAbsent':True,
                'automaticReopen':False,'restorePerformed':False,'migrationPerformed':False,'notReleaseAcceptance':True}
        durable(root/'gate-receipt.json',report)
        if checkpoint:checkpoint(phase)
        return report
    except Exception as error:
        diagnosis={'schema':'ouf.discovery.database-gate-denial.v1','status':'GATE_INSTALLATION_INCOMPLETE','phase':phase,
                   'reason':str(error) if isinstance(error,GateDenied) else type(error).__name__,'writersFencedProven':False,
                   'automaticReopen':False,'doNotRerunApply':True,'backupOrMigrationAuthorityGranted':False}
        try:durable(root/'gate-denial.json',diagnosis)
        except OSError:pass
        raise GateDenied('GATE_INSTALLATION_INCOMPLETE:'+phase) from None
