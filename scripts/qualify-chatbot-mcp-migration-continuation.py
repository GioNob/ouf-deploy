#!/usr/bin/env python3
"""Disposable CI: original packaged MCP applies migrations 10-12, then cleanup.

This is NOT a VPS delivery. Fixture SQL/containers are created only in CI.
"""
import copy,hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('native_readback',ROOT/'scripts/qualify-chatbot-mcp-migration-readback.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
from tools.chatbot_file_cohort.migration_native import request_for,native_matches,created,immutable_native

def main():
    # First run the independently qualified frozen-image/read-only diagnostic.
    q.main()
    output=Path(sys.argv[2]);summary=json.loads((output/'summary.json').read_text())
    source=ROOT/'.pairwise/mcp';source_commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    q.r.require(source_commit==summary['sourceCommit']=='f249b3dcc58c2a96742092d90fa09fd90b705bd0','EXACT_MIGRATION_SOURCE_REQUIRED')
    files=sorted((source/'internal/adapter/postgres/migrations').glob('*.sql'))
    q.r.require(len(files)==12,'EXACT_TWELVE_MIGRATIONS_REQUIRED')
    expected=[{'version':int(p.name[:3]),'checksum':hashlib.sha256(p.read_bytes()).hexdigest()}for p in files]
    pg=cid=None;network=q.docker('network','create','ouf-backend')
    try:
        pg=q.docker('run','--detach','--name','ouf-migration-ci-db','--network','ouf-backend',
            '--env','POSTGRES_USER=postgres','--env','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine')
        ready=False
        for _ in range(60):
            result=subprocess.run(['docker','exec',pg,'pg_isready','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
            if result.returncode==0:ready=True;break
            time.sleep(1)
        q.r.require(ready,'CI_DATABASE_READY_REQUIRED')
        def sql(statement,user='postgres'):
            result=subprocess.run(['docker','exec','-i',pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d','postgres'],
                input=statement.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            q.r.require(result.returncode==0,'CI_SQL_FAILED');return result.stdout.decode().strip()
        # Historical migrations 4/6 create distinct NOLOGIN roles. Build only
        # the disposable pre-existing baseline with a fixture administrator;
        # revoke these setup attributes before the candidate binary is tested.
        sql("CREATE ROLE fixture_app LOGIN SUPERUSER; CREATE ROLE fixture_incident NOLOGIN; CREATE SCHEMA ouf_mcp AUTHORIZATION fixture_app; GRANT CREATE ON DATABASE postgres TO fixture_app;")
        sql("CREATE TABLE ouf_mcp.schema_migration(version integer primary key,checksum char(64) not null,applied_at timestamptz not null default transaction_timestamp());",'fixture_app')
        for p,row in zip(files[:9],expected[:9]):
            sql('BEGIN; '+p.read_text()+"\nINSERT INTO ouf_mcp.schema_migration(version,checksum) VALUES ("+str(row['version'])+",'"+row['checksum']+"'); COMMIT;",'fixture_app')
        sql('ALTER ROLE fixture_app NOSUPERUSER NOCREATEROLE; ALTER TABLE ouf_mcp.security_incident OWNER TO fixture_incident;')
        q.r.require(sql("SELECT NOT rolsuper AND NOT rolcreaterole FROM pg_roles WHERE rolname='fixture_app'")=='t',
            'CANDIDATE_MIGRATION_MUST_USE_NONADMIN_ROLE')
        incident=json.loads(sql(q.r.incident_metadata('fixture_app',False)))
        q.r.require(incident['triggerAuthority'] is False and incident['triggerGrantCount']==0,'NONOWNED_INCIDENT_FIXTURE_REQUIRED')
        sql('CREATE ROLE ouf_mcp_operational_audit_owner NOLOGIN NOSUPERUSER NOCREATEROLE; '
            'GRANT CREATE ON SCHEMA ouf_mcp TO ouf_mcp_operational_audit_owner; '
            'GRANT ouf_mcp_operational_audit_owner TO fixture_app WITH ADMIN FALSE, INHERIT FALSE, SET TRUE; '
            'GRANT TRIGGER ON TABLE ouf_mcp.security_incident TO fixture_app;')
        image=json.loads(q.docker('image','inspect',summary['nativeImageId']))[0]
        plan={'replacements':[{'module':'mcp','retiredName':'ouf-mcp-before-native-continuation',
            'creationRequest':{'Image':image['Id'],'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],
                'Env':['MCP_DATABASE_URL=postgres://fixture_app@ouf-migration-ci-db/postgres?sslmode=disable'],
                'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':network}}}}}]}
        name,request=request_for(plan)
        response=q.engine('POST','/containers/create?name='+name,request);cid=response['Id']
        before=q.engine('GET','/containers/'+cid+'/json');native_matches(name,request,image['Config'],before);created(before)
        immutable=immutable_native(before)
        q.engine('POST','/containers/'+cid+'/start')
        code=q.docker('wait',cid);q.r.require(code=='0','PACKAGED_MIGRATION_EXIT_FAILED')
        after=q.engine('GET','/containers/'+cid+'/json');native_matches(name,request,image['Config'],after)
        q.r.require(immutable_native(after)==immutable,'POST_START_IMMUTABLE_FIELDS_DRIFT')
        history=json.loads(sql("SELECT json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version) FROM ouf_mcp.schema_migration"))
        q.r.require(history==expected,'PACKAGED_MIGRATION_HISTORY_DRIFT')
        active=json.loads(sql(q.r.incident_metadata('fixture_app',True)))
        q.r.require(all(active[k]==incident[k] for k in ('oid','ownerOid','aclHash')) and active['triggerGrantCount']==1,'INCIDENT_PRESERVATION_FAILED')
        sql('BEGIN; REVOKE ouf_mcp_operational_audit_owner FROM fixture_app; REVOKE CREATE ON SCHEMA ouf_mcp FROM ouf_mcp_operational_audit_owner; REVOKE TRIGGER ON TABLE ouf_mcp.security_incident FROM fixture_app; COMMIT;')
        binding={'database':'postgres','user':'fixture_app','databaseOid':int(sql("SELECT oid FROM pg_database WHERE datname=current_database()")),
            'beforeMigrations':expected[:9],'expectedMigrations':expected}
        dbplan={'mcpAuditRoleAdministration':{'admin':'postgres','temporaryIncidentTrigger':True},'mcpAuditRolePreflight':{'incidentBinding':incident}}
        facts=json.loads(sql('BEGIN READ ONLY; '+q.r.state_query(binding,dbplan)+'; COMMIT;'))
        final=q.r.database_projection(facts,binding,dbplan)
        q.r.require(final['expectedMigrationsMatch'] and final['noLogin'] and not final['schemaCreate'] and
            final['membershipCount']==final['appMembership']==0 and final['functionOwnerCount']==2 and
            final['incidentPreservedAclMatches'] and final['incidentOwnerMatches'] and not final['incidentTriggerAuthority'] and final['incidentTriggerGrantCount']==0,
            'NATIVE_MIGRATION_OR_CLEANUP_UNPROVEN')
        result={'schema':'ouf.mcp-phase2-native-migration-qualification.v1','sourceCommit':source_commit,
            'artifactSha256':q.PART_SHA,'nativeImageId':image['Id'],'beforeMigrationCount':9,'afterMigrationCount':12,
            'createCount':1,'startCount':1,'containerExitCode':0,'immutableConfigurationPreserved':True,
            'candidateDatabaseUserSuperuser':False,'candidateDatabaseUserCreateRole':False,
            'cleanup':final,'targetAccess':False,'runtimeAuthorityIssued':False,'signedAggregateEndToEnd':False}
        output.joinpath('migration-summary.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
    finally:
        if cid:q.docker('rm','--force',cid)
        if pg:q.docker('rm','--force',pg)
        q.docker('network','rm','ouf-backend')
if __name__=='__main__':
    try:main()
    except Exception as error:
        import traceback
        reason=str(error) if type(error)is q.r.ReadDenied else type(error).__name__
        print(json.dumps({'ciFailure':reason,'locations':[{'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)][-6:],'rawDiagnosticPrinted':False}))
        sys.exit(1)
