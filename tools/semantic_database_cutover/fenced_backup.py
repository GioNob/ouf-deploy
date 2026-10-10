"""Locked snapshot + already-admitted dump + persistent database gate.
Prepared primitive only: no target entry point, authority, reopen or restore.
"""
import hashlib, os, shutil, subprocess, time, uuid
from pathlib import Path
from database_gate import GateDenied, Psql, digest, durable, identifier, install_gate, literal, require

CATALOG = "SELECT COALESCE(jsonb_agg(jsonb_build_object('schema',n.nspname,'name',c.relname,'oid',c.oid::bigint,'kind',c.relkind) ORDER BY c.oid),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN ('r','p','f','m','S')"

def pin(channel):
    return channel.query("SELECT json_build_object('pid',pid,'backendStart',(backend_start AT TIME ZONE 'UTC')::text,'applicationName',application_name,'user',usename) FROM pg_stat_activity WHERE pid=pg_backend_pid()")

def fenced_backup(admin,container_id,user,database,expected_oid,directory,*,checkpoint=None):
    """Block known tables before snapshot export and prove no writers survive.

    Gate opens no connection after its installation. pg_dump is admitted first,
    observed waiting on a held relation lock, retained by exact generation pin,
    then finishes after the completed gate and controller COMMIT. Before/after
    catalog comparison rejects concurrent new-table DDL. The accepted backup
    stays private; failure never reopens admission or grants migration/restore.
    The sealed caller must first quiesce every inventoried application producer.
    """
    identifier(database);identifier(user)
    root=Path(directory)
    require(not os.path.lexists(root/'backup-claim.json'),'DO_NOT_REPLAY_BACKUP_CLAIM')
    require(shutil.disk_usage(root).free>1073741824,'PRIVATE_BACKUP_FREE_SPACE_REQUIRED')
    nonce=uuid.uuid4().hex[:16]
    hold=Psql(container_id,user,database,'ouf-cutover-hold-'+nonce)
    dump=None;dump_pin=None;phase='PRECHECK';gate_completed=False
    archive=root/'semantic.dump.partial'
    error_path=root/'dump.stderr.private'
    try:
        catalog=hold.query(CATALOG)
        require(catalog and len(catalog)<=128 and all(c['schema']=='ouf_sem' and c['kind'] in ('r','p','m','S') for c in catalog),'EXACT_SEMANTIC_ONLY_DATABASE_REQUIRED')
        require(hold.query('SELECT count(*) FROM pg_largeobject_metadata')==0,'LARGE_OBJECT_SCOPE_REQUIRES_SEPARATE_CLOSURE')
        require(hold.query('SELECT count(*) FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database())')==0,'REPLICATION_WRITERS_REQUIRE_SEPARATE_FENCE')
        require(hold.query('SELECT oid::bigint FROM pg_database WHERE datname=current_database()')==expected_oid,'DATABASE_OID_CHANGED')
        locks=[identifier(c['schema'])+'.'+identifier(c['name']) for c in catalog if c['kind'] in ('r','p')]
        require(bool(locks),'NO_SEMANTIC_LOCKABLE_TABLES')
        durable(root/'backup-claim.json',{'schema':'ouf.discovery.fenced-backup-claim.v1','state':'PREPARING_NOT_BACKUP_AUTHORITY','catalogHash':digest(catalog),'doNotRerunApply':True,'automaticReopen':False})
        phase='LOCK_AND_EXPORT_SNAPSHOT'
        snapshot=hold.query('SELECT pg_export_snapshot()',"BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'; LOCK TABLE "+','.join(locks)+' IN ACCESS EXCLUSIVE MODE;')
        require(type(snapshot) is str and len(snapshot)<128 and all(c in '0123456789ABCDEFabcdef-' for c in snapshot),'EXPORTED_SNAPSHOT_INVALID')
        hold_pin=pin(hold)
        phase='ADMIT_READ_ONLY_DUMP'
        dump_name='ouf-cutover-dump-'+nonce
        with archive.open('xb') as output,error_path.open('xb') as error:
            os.chmod(archive,0o600);os.chmod(error_path,0o600)
            dump=subprocess.Popen(['docker','--config',hold.temp.name,'exec',container_id,'env','PGAPPNAME='+dump_name,
                'pg_dump','-U',user,'-d',database,'--format=custom','--no-owner','--no-acl','--snapshot='+snapshot,'--lock-wait-timeout=30s'],stdout=output,stderr=error)
            until=time.monotonic()+10
            while time.monotonic()<until:
                require(dump.poll() is None,'DUMP_EXITED_BEFORE_FENCE')
                pins=admin.query("SELECT COALESCE(json_agg(json_build_object('pid',a.pid,'backendStart',(a.backend_start AT TIME ZONE 'UTC')::text,'applicationName',a.application_name,'user',a.usename)),'[]'::json) FROM pg_stat_activity a WHERE a.datname="+literal(database)+" AND a.application_name="+literal(dump_name)+" AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='relation' AND NOT l.granted)")
                if len(pins)==1:dump_pin=pins[0];break
                time.sleep(.05)
            require(dump_pin is not None,'DUMP_SNAPSHOT_AND_LOCK_ADMISSION_UNPROVEN')
            phase='INSTALL_DATABASE_GATE'
            gate=install_gate(admin,database,expected_oid,[hold_pin,dump_pin],root,checkpoint=checkpoint)
            gate_completed=True
            require(hold.query(CATALOG)==catalog,'CONCURRENT_CATALOG_DDL_CHANGED_SNAPSHOT_SCOPE')
            phase='FINISH_PINNED_DUMP_UNDER_COMPLETED_FENCE'
            hold.query('true','COMMIT;')
            require(dump.wait(timeout=90)==0,'PINNED_DUMP_FAILED')
            output.flush();os.fsync(output.fileno())
        require(archive.stat().st_size>100,'PRIVATE_DUMP_EMPTY')
        phase='PARSE_COMPLETE_ARCHIVE_PAYLOAD'
        if checkpoint:checkpoint(phase)
        with archive.open('rb') as stream:
            parsed=subprocess.run(['docker','--config',hold.temp.name,'exec','-i',container_id,'pg_restore','--file=/dev/null'],stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=90)
        require(parsed.returncode==0,'PRIVATE_DUMP_PAYLOAD_INVALID')
        # No new connection is opened; the retained hold channel observes the
        # same fenced database and the unchanged catalog after dump completion.
        require(hold.query(CATALOG)==catalog,'CATALOG_DRIFT_AFTER_FENCED_DUMP')
        require(admin.query("SELECT NOT datallowconn FROM pg_database WHERE oid="+str(expected_oid)) is True,'DATABASE_GATE_LOST_AFTER_DUMP')
        with archive.open('rb') as stream:archive_hash=hashlib.file_digest(stream,'sha256').hexdigest()
        final=root/'semantic.dump';os.rename(archive,final)
        receipt={'schema':'ouf.discovery.fenced-backup.v1','status':'PRIVATE_FENCED_SNAPSHOT_PAYLOAD_VALIDATED','archiveSha256':archive_hash,'archiveBytes':final.stat().st_size,
            'catalogHash':digest(catalog),'snapshotHash':digest(snapshot),'gateReceiptHash':digest(gate),'archivePayloadParsed':True,'databaseAdmissionRemainsClosed':True,
            'allOtherSessionsAbsentAtGate':True,'backupUploaded':False,'rolesAndAclsIncluded':False,'restorePerformed':False,'migrationPerformed':False,'targetAuthorityGranted':False,'notReleaseAcceptance':True}
        durable(root/'backup-receipt.json',receipt)
        return receipt
    except Exception as error:
        diagnosis={'schema':'ouf.discovery.fenced-backup-denial.v1','status':'FENCED_BACKUP_INCOMPLETE','phase':phase,'gateCompleted':gate_completed,
            'reason':str(error) if isinstance(error,GateDenied) else type(error).__name__,'automaticReopen':False,'doNotRerunApply':os.path.lexists(root/'backup-claim.json'),'backupOrMigrationAuthorityGranted':False}
        try:durable(root/'backup-denial.json',diagnosis)
        except OSError:pass
        raise GateDenied('FENCED_BACKUP_INCOMPLETE:'+phase) from None
    finally:
        if dump and dump.poll() is None:
            # Terminate only the exact retained dump generation, never a PID
            # reused by another process. Errors retain the closed/partial gate.
            if dump_pin:
                try:
                    still=admin.query("SELECT (backend_start AT TIME ZONE 'UTC')::text="+literal(dump_pin['backendStart'])+" AND application_name="+literal(dump_pin['applicationName'])+" FROM pg_stat_activity WHERE pid="+str(dump_pin['pid']))
                    if still is True:admin.query('SELECT pg_terminate_backend('+str(dump_pin['pid'])+',1000)')
                except GateDenied:pass
            try:dump.wait(timeout=5)
            except subprocess.TimeoutExpired:dump.terminate();dump.wait(timeout=5)
        hold.close()
