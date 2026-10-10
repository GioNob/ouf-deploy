#!/usr/bin/env python3
"""Read only database/catalog metadata; no rows, writes, dump, keys or lifecycle.
Uses the already scoped backup binding/credential transport. Never prints names,
passwords, query text, client addresses or application data.
"""
import hashlib, importlib.util, json
from pathlib import Path

spec = importlib.util.spec_from_file_location("scoped_backup", Path(__file__).with_name("backup-semantic-target.py"))
backup = importlib.util.module_from_spec(spec); spec.loader.exec_module(backup)
CID = "7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147"
SQL = """
BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT json_build_object(
 'database', current_database(), 'user', current_user,
 'databaseOwner', (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),
 'allowConnections', (SELECT datallowconn FROM pg_database WHERE datname=current_database()),
 'preparedTransactions', (SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()),
 'role', (SELECT row_to_json(t) FROM (SELECT rolsuper,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user) t),
 'migrations', (SELECT json_agg(version ORDER BY installed_rank) FROM ouf_sem.flyway_schema_history WHERE success),
 'relations', (SELECT json_agg(json_build_object('oid',c.oid,'kind',c.relkind,'owner',pg_get_userbyid(c.relowner)) ORDER BY c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ouf_sem' AND c.relkind IN ('r','p','f','m','S')),
 'effectiveWriterRoles', (SELECT json_agg(json_build_object('role',r.rolname,'login',r.rolcanlogin,'superuser',r.rolsuper) ORDER BY r.rolname) FROM pg_roles r WHERE r.rolsuper OR (has_schema_privilege(r.oid,'ouf_sem','USAGE') AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ouf_sem' AND c.relkind IN ('r','p','f') AND has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE')))),
 'sessions', (SELECT json_agg(json_build_object('sameRole',usename=current_user,'state',state,'semanticPeer',client_addr=inet '172.18.0.6','sameDatabase',datname=current_database(),'clientAddress',client_addr::text,'applicationName',application_name) ORDER BY pid) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()),
 'otherDatabaseSessionsUsingSameRole', (SELECT count(*) FROM pg_stat_activity WHERE usename=current_user AND datname IS DISTINCT FROM current_database()),
 'largeObjectCount', (SELECT count(*) FROM pg_largeobject_metadata),
 'relationsOutsideSemanticSchema', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('ouf_sem','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN ('r','p','f','m','S')),
 'replicationSubscriptions', (SELECT count(*) FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database()))
);
COMMIT;
"""

def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def sha(value): return hashlib.sha256(encoded(value)).hexdigest()

def stable_binding(value):
    return {key:value[key] for key in ('Id','Image','Config','HostConfig','Mounts','NetworkSettings')} | {
        'generation':{key:value['State'][key] for key in ('Pid','StartedAt','Running')}}

def project(raw):
    static = {key:value for key,value in raw.items() if key not in ('sessions','otherDatabaseSessionsUsingSameRole')}
    role = raw['role']; writers = raw['effectiveWriterRoles'] or []
    return {'databaseNameHash':sha(raw['database']), 'databaseUserHash':sha(raw['user']), 'databaseOwnerMatchesUser':raw['databaseOwner']==raw['user'],
            'allowConnections':raw['allowConnections'], 'preparedTransactionCount':raw['preparedTransactions'], 'currentRole':role,
            'successfulMigrations':raw['migrations'], 'relationCount':len(raw['relations'] or []),
            'effectiveWriterRoles':[{'roleHash':sha(r['role']), 'login':r['login'], 'superuser':r['superuser'], 'sameAsCurrentRole':r['role']==raw['user']} for r in writers],
            'sessionCount':len(raw['sessions'] or []), 'semanticPeerSessionCount':sum(1 for s in raw['sessions'] or [] if s['semanticPeer'] is True),
            'otherDatabaseSessionsUsingSameRole':raw['otherDatabaseSessionsUsingSameRole'], 'replicationSubscriptionCount':raw['replicationSubscriptions'], 'largeObjectCount':raw['largeObjectCount'], 'relationsOutsideSemanticSchema':raw['relationsOutsideSemanticSchema'],
            'sessionGroups': [{'clientAddressHash':sha(address), 'applicationNameHash':sha(app), 'sameRole':same_role, 'count':sum(1 for s in raw['sessions'] or [] if (s['clientAddress'],s['applicationName'],s['sameRole'])==(address,app,same_role))} for address,app,same_role in sorted(set((s['clientAddress'] or '',s['applicationName'],s['sameRole']) for s in raw['sessions'] or []))],
            'catalogHash':sha(static), 'catalogReadVisibilityComplete':role['rolsuper'], 'globalRoleLoginFenceRejected':role['rolsuper'] or raw['otherDatabaseSessionsUsingSameRole']>0, 'dedicatedRoleCustodyProven':False,
            'sessionsAreObservationalNotFenceAuthority':True}

def main():
    report={'schema':'ouf.discovery.database-cutover-metadata.v1','applyAuthorized':False,'databaseWrites':0,'applicationRowsRead':0,
            'backupPerformed':False,'containerLifecycleOperations':0,'privateKeysRead':0,'privateValuesPrinted':False,'commonLeaseLockAcquired':False,'notReleaseAcceptance':True}
    try:
        semantic, postgres = backup.inspect('ouf-semantic'), backup.inspect('ouf-postgres')
        if semantic['Id']!=CID: raise RuntimeError('EXACT_SEMANTIC_CONTAINER_REQUIRED')
        database,user,credential=backup.binding(semantic,postgres)
        base=['--host=127.0.0.1','--port=5432','--username='+user,'--dbname='+database,'-X','-A','-t','-q','--set=ON_ERROR_STOP=1','-c',SQL]
        def read():
            raw=backup.pg(postgres['Id'],'psql',base,credential)
            if len(raw)>131072:raise RuntimeError('CATALOG_READ_UNBOUNDED')
            return project(json.loads(raw))
        first,second=read(),read()
        ids=backup.call(['docker','ps','--no-trunc','--format','{{.ID}}']).decode().split()
        if len(ids)>64:raise RuntimeError('CONTAINER_INVENTORY_UNBOUNDED')
        peers=[]
        for cid in ids:
            raw=json.loads(backup.call(['docker','inspect','--type','container','--format','{{json .NetworkSettings.Networks}}',cid]))
            peers.extend({'containerId':cid,'clientAddressHash':sha(n['IPAddress'])} for n in raw.values() if n.get('IPAddress'))
        for group in second['sessionGroups']:
            group['matchingContainerIds']=sorted(set(p['containerId'] for p in peers if p['clientAddressHash']==group['clientAddressHash']))
        if first['catalogHash']!=second['catalogHash']:raise RuntimeError('CATALOG_CHANGED_DURING_READ')
        if stable_binding(semantic)!=stable_binding(backup.inspect('ouf-semantic')) or stable_binding(postgres)!=stable_binding(backup.inspect('ouf-postgres')):
            raise RuntimeError('LIVE_BINDING_CHANGED_DURING_READ')
        report.update(status='DATABASE_CUTOVER_METADATA_CAPTURED',metadata=second,semanticContainerId=CID,postgresContainerId=postgres['Id'],readConsistencyMode='STABLE_CATALOG_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY')
    except Exception as error:
        report.update(status='READ_BLOCKED',reason=str(error) if isinstance(error,RuntimeError) else type(error).__name__)
    print('OUF_SEMANTIC_DATABASE_CUTOVER_METADATA='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='DATABASE_CUTOVER_METADATA_CAPTURED' else 1

if __name__=='__main__':raise SystemExit(main())
