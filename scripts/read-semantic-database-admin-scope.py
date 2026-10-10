"""Read the existing administrator's exact DB scope; no grants, rows or writes.
The credential is taken from the existing database container binding and sent
only through stdin. No role names, passwords or session queries are published.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

s=importlib.util.spec_from_file_location('backup',Path(__file__).with_name('backup-semantic-target.py'))
backup=importlib.util.module_from_spec(s);s.loader.exec_module(backup)

def require(ok,why):
    if not ok:raise RuntimeError(why)

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def stable(v):
    return {k:v[k] for k in ('Id','Image','Config','HostConfig','Mounts','NetworkSettings')}|{
        'generation':{k:v['State'][k] for k in ('Pid','StartedAt','Running')}}

def main():
    report=dict(schema='ouf.discovery.database-admin-scope-observation.v1',databaseWrites=0,
                applicationRowsRead=0,grantsIssued=0,credentialFilesOpened=0,credentialValuesPrinted=False,
                containerLifecycleOperations=0,commonLeaseLockAcquired=False,
                databaseFenceInstalled=False,backupPerformed=False,notReleaseAcceptance=True)
    try:
        semantic,postgres=backup.inspect('ouf-semantic'),backup.inspect('ouf-postgres')
        database,_,_=backup.binding(semantic,postgres)
        values={}
        for row in postgres['Config']['Env']:
            k,v=row.split('=',1);require(k not in values,'UNIQUE_DATABASE_ENV_REQUIRED');values[k]=v
        user,password=values.get('POSTGRES_USER','postgres'),values.get('POSTGRES_PASSWORD')
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',user) is not None and
                type(password) is str and 0<len(password)<=4096 and not any(c in password for c in '\n\r\x00'),
                'EXISTING_ADMIN_CREDENTIAL_BINDING_UNPROVEN')
        require(database!='postgres','OUTSIDE_APPLICATION_DATABASE_CHANNEL_REQUIRED')
        # database was already validated as a bounded identifier by backup.binding.
        literal="'"+database+"'"
        query="""BEGIN READ ONLY; SET LOCAL statement_timeout='5s';
SELECT json_build_object('adminSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
 'adminDatabase',current_database(),'adminUser',current_user,'serverVersionNum',current_setting('server_version_num'),
 'fsync',current_setting('fsync'),'synchronousCommit',current_setting('synchronous_commit'),
 'database',(SELECT json_build_object('oid',oid::bigint,'name',datname,'owner',pg_get_userbyid(datdba),'allowConnections',datallowconn)
             FROM pg_database WHERE datname="""+literal+"""),
 'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts WHERE database="""+literal+"""),
 'sessions',(SELECT COALESCE(json_agg(json_build_object('pid',pid,'backendStart',(backend_start AT TIME ZONE 'UTC')::text,
                       'user',usename,'applicationName',application_name,'clientAddress',host(client_addr),'state',state) ORDER BY pid),'[]'::json)
             FROM pg_stat_activity WHERE datname="""+literal+""")); COMMIT;"""
        raw=backup.pg(postgres['Id'],'psql',['--host=127.0.0.1','--port=5432','--username='+user,'--dbname=postgres',
                      '-X','-q','-A','-t','--set=ON_ERROR_STOP=1','-c',query],password.encode()+b'\n')
        require(len(raw)<=131072,'BOUNDED_ADMIN_CATALOG_REQUIRED')
        value=json.loads(raw)
        require(value['adminDatabase']=='postgres' and value['database']['name']==database and
                value['adminSuperuser'] is True,'SCOPED_COMPLETE_ADMIN_VISIBILITY_UNPROVEN')
        require(stable(semantic)==stable(backup.inspect('ouf-semantic')) and
                stable(postgres)==stable(backup.inspect('ouf-postgres')),'ADMIN_NATIVE_BINDINGS_CHANGED_DURING_READ')
        report.update(status='EXISTING_ADMIN_OUTSIDE_DATABASE_SCOPE_OBSERVED',postgresContainerId=postgres['Id'],
                      adminUserHash=digest(value['adminUser']),databaseNameHash=digest(database),
                      databaseOid=value['database']['oid'],databaseOwnerHash=digest(value['database']['owner']),
                      adminSuperuser=True,outsideApplicationDatabase=True,completeSessionVisibility=True,
                      serverVersionNum=value['serverVersionNum'],fsyncOn=value['fsync']=='on',
                      synchronousCommitOn=value['synchronousCommit']=='on',allowConnections=value['database']['allowConnections'],
                      preparedTransactionCount=value['preparedTransactions'],sessionCount=len(value['sessions']),
                      sessionGenerationHashes=[digest(v) for v in value['sessions']],
                      sessionsAreObservationsNotTerminationAuthority=True,
                      readConsistencyMode='CURRENT_METADATA_NOT_FENCE_OR_BACKUP_AUTHORITY')
        code=0
    except Exception as error:
        reason=str(error)
        report.update(status='ADMIN_SCOPE_READ_BLOCKED',errorType=type(error).__name__,
                      reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'ADMIN_SCOPE_UNPROVEN')
        code=1
    print('OUF_DATABASE_ADMIN_SCOPE='+json.dumps(report,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
