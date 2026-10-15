"""Packaged migration/compiler and signed backup failure qualification.

Actual private files, signatures and subprocess pipes; Docker/PostgreSQL state
and pg_dump/restore are disposable fixtures, not VPS or real PG backup evidence.
Flyway CRC behavior is derived from its ChecksumCalculator/LoadableResource:
https://github.com/flyway/flyway/pull/3764/files (first BOM, readLine, UTF-8 CRC32).
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import test_chatbot_cohort_containers as runtime_fixture
from tools.chatbot_file_cohort import databases as d, plan as p, containers as c
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine
crypto=runtime_fixture.crypto


def inputs():
    pg,_,_=runtime_fixture.container_fixture('udp')
    pg.update(Id='5'*64,Name='/ouf-postgres')
    pg['Config']['Env']=['POSTGRES_USER=fixture_admin']
    pg['State'].update(Pid=5555)
    bindings={m:{'database':'fixture_'+m,'user':'postgres'} for m in p.MODULES}
    expected={m:[{'version':'1','script':'V1__base.sql','type':'SQL','checksum':78787420,'success':True},
                 {'version':'2','script':'V2__next.sql','type':'SQL','checksum':-873187034,'success':True}]
              for m in p.MODULES if m!='mcp'}
    expected['mcp']=[{'version':1,'checksum':'a'*64}]
    current={m:{'identity':{'name':bindings[m]['database'],'oid':100+i,'allowConnections':True,'prepared':0},
                'migrations':copy.deepcopy(expected[m][:1])} for i,m in enumerate(p.MODULES)}
    return pg,bindings,expected,current

class DatabaseCompiler(unittest.TestCase):
    def jar(self,rows):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            for name,raw in rows:z.writestr(name,raw)
        stream.seek(0)
        return stream

    def test_signed_crc32_utf8_first_bom_and_line_endings(self):
        for raw in (b'123456789',b'123\r\n456\r789\n',b'\xef\xbb\xbf123\n456789'):
            self.assertEqual(d.flyway_checksum(raw),-873187034)
        self.assertEqual(d.flyway_checksum("SELECT 'città';".encode()),319451442)
        self.assertNotEqual(d.flyway_checksum(b'a\n\xef\xbb\xbfb'),d.flyway_checksum(b'ab'))
        with self.assertRaises(UnicodeDecodeError):d.flyway_checksum(b'\xff')

    def test_jar_migrations_are_from_exact_packaged_prefix_and_numeric_order(self):
        prefix='BOOT-INF/classes/db/migration/'
        rows=d.java_migrations(self.jar([(prefix+'V10__last.sql',b'123456789'),
            ('foreign/V3__ignored.sql',b'wrong'),(prefix+'V2__base.sql',b'SELECT 1;')]))
        self.assertEqual([r['version'] for r in rows],['2','10'])
        self.assertEqual([r['checksum'] for r in rows],[78787420,-873187034])
        for name in (prefix+'nested/V1__hidden.sql',prefix+'R__repeat.sql',prefix+'application.properties'):
            with self.assertRaisesRegex(p.PlanDenied,'CUSTOM_MIGRATION'):
                d.java_migrations(self.jar([(name,b'SELECT 1;')]))
        with self.assertRaisesRegex(p.PlanDenied,'DUPLICATE'):
            d.java_migrations(self.jar([(prefix+'V1__a.sql',b'a'),(prefix+'V1__b.sql',b'b')]))

    def test_mcp_uses_its_own_sha256_source_contract(self):
        with tempfile.TemporaryDirectory(dir=runtime_fixture.ROOT) as root:
            directory=Path(root)/'internal/adapter/postgres/migrations';directory.mkdir(parents=True)
            raw=b'SELECT 1;\n';(directory/'001_base.sql').write_bytes(raw)
            self.assertEqual(d.mcp_migrations(root),[{'version':1,'checksum':hashlib.sha256(raw).hexdigest()}])
            (directory/'002_link.sql').symlink_to('001_base.sql')
            with self.assertRaisesRegex(p.PlanDenied,'EXACT_MCP'):d.mcp_migrations(root)

    def test_all_owner_schemas_and_exact_installed_prefix_are_required(self):
        pg,b,e,o=inputs();plan=d.compile_database_plan(pg,b,e,o)
        self.assertEqual({r['module']:r['schema'] for r in plan['modules']},d.SCHEMAS)
        self.assertFalse(plan['automaticRestoreAllowed']);self.assertFalse(plan['manualSqlMigrationAllowed'])
        self.assertEqual([r['pendingMigrationCount'] for r in plan['modules']],[1,1,1,0])
        o['udp']['migrations'][0]['checksum']+=1
        with self.assertRaisesRegex(p.PlanDenied,'MUST_MATCH_PACKAGED'):d.compile_database_plan(pg,b,e,o)
        pg,b,e,o=inputs();e['mcp'].extend({'version':version,'checksum':str(version)*64}
                                              for version in (10,11,12))
        plan=d.compile_database_plan(pg,b,e,o)
        self.assertEqual(next(r for r in plan['modules'] if r['module']=='mcp')['pendingMigrationCount'],3)
        self.assertTrue(plan['mcpAuditRoleAdministration']['cleanupRequiredBeforeCohortStart'])
        o['mcp']['migrations'][0]['checksum']='f'*64
        with self.assertRaisesRegex(p.PlanDenied,'MUST_MATCH_PACKAGED'):d.compile_database_plan(pg,b,e,o)
        pg,b,e,o=inputs();b['mcp']['database']=b['udp']['database'];o['mcp']['identity']['name']=b['udp']['database']
        with self.assertRaisesRegex(p.PlanDenied,'SHARED_DATABASE'):d.compile_database_plan(pg,b,e,o)

    def test_exact_flyway_schema_creation_marker_is_preserved_without_sql_bypass(self):
        pg,b,e,o=inputs()
        for module in ('udp','onboarding','ingestion'):
            marker={'version':None,'script':'"ouf_'+module+'"','type':'SCHEMA',
                    'checksum':None,'success':True}
            o[module]['migrations'].insert(0,marker)
        plan=d.compile_database_plan(pg,b,e,o)
        for row in plan['modules']:
            if row['module']=='mcp':continue
            self.assertEqual(row['beforeMigrations'][0],o[row['module']]['migrations'][0])
            self.assertEqual(row['expectedMigrations'][0],o[row['module']]['migrations'][0])
            self.assertEqual(row['pendingMigrationCount'],1)
        o['udp']['migrations'][0]['script']='"other_schema"'
        with self.assertRaisesRegex(p.PlanDenied,'MUST_MATCH_PACKAGED'):
            d.compile_database_plan(pg,b,e,o)
        o['udp']['migrations'][0]['script']='"ouf_udp"'
        o['udp']['migrations'][1]['checksum']+=1
        with self.assertRaisesRegex(p.PlanDenied,'MUST_MATCH_PACKAGED'):
            d.compile_database_plan(pg,b,e,o)

    def test_database_reads_exact_owner_schema_not_public(self):
        pg,b,e,o=inputs();queries=[]
        class Pg:
            def __init__(self,cid,user,database,*args):self.module=next(m for m in b if b[m]['database']==database)
            def query(self,sql,**kwargs):
                queries.append(sql)
                return copy.deepcopy(o[self.module]['identity' if 'current_database()' in sql else 'migrations'])
            def close(self):pass
        with patch.object(d,'Psql',Pg):
            for module in p.MODULES:d.observe_database(pg['Id'],b[module]['user'],b[module]['database'],module)
        for idx,module in enumerate(p.MODULES):
            suffix='schema_migration' if module=='mcp' else 'flyway_schema_history'
            self.assertIn('"'+d.SCHEMAS[module]+'".'+suffix,queries[idx*2+1])
        self.assertFalse(any('public.' in sql for sql in queries))

    def test_pending_migration_uses_observed_admin_without_default_or_role_promotion(self):
        pg,b,e,o=inputs();e['mcp'].extend({'version':v,'checksum':str(v)*64} for v in (10,11,12))
        self.assertEqual(d.compile_database_plan(pg,b,e,o)['mcpAuditRoleAdministration']['admin'],'fixture_admin')
        pg['Config']['Env']=[]
        with self.assertRaisesRegex(Exception,'IDENTIFIER'):d.compile_database_plan(pg,b,e,o)

    def test_incident_owner_need_not_be_application_when_admin_and_acl_are_proven(self):
        calls=[]
        facts={'serverVersion':170011,'adminSuperuser':True,'adminRoleMatched':True,
               'applicationRoleExists':True,'auditRoleAbsent':True,
               'applicationSchemaOwnerAuthority':True,'applicationAuditTableOwnerAuthority':True,
               'applicationAttemptTableOwnerAuthority':True,'applicationIncidentTableOwnerAuthority':False,
               'applicationAuditSequenceOwnerAuthority':True,'incidentBinding':incident_binding(False)}
        class Pg:
            def __init__(self,cid,user,database,name):calls.append(user)
            def query(self,sql):return copy.deepcopy(facts)
            def close(self):pass
        with patch.object(d,'Psql',Pg):
            self.assertEqual(d.mcp_admin_preflight('5'*64,'fixture_mcp','fixture_app','fixture_admin'),facts)
            facts['incidentBinding']=None
            with self.assertRaisesRegex(p.PlanDenied,'INCIDENT_TABLE'):
                d.mcp_admin_preflight('5'*64,'fixture_mcp','fixture_app','fixture_admin')
        self.assertEqual(calls,['fixture_admin','fixture_admin'])


def incident_binding(trigger=True):
    return {'oid':100,'ownerOid':101,'aclHash':'c'*64,'triggerAuthority':trigger,
            'triggerGrantCount':int(trigger)}

class DatabaseRuntime(unittest.TestCase):
    def fixture(self, mcp_pending=False, incident_trigger=True, backup_reader=False):
        fixture=runtime_fixture.CohortRuntime();cohort,native,f,_=fixture.fixture();self.addCleanup(fixture.doCleanups)
        pg,b,e,o=inputs();native.state[pg['Id']]=copy.deepcopy(pg)
        if mcp_pending:e['mcp'].extend({'version':version,'checksum':str(version)*64}
                                       for version in (10,11,12))
        dbplan=d.compile_database_plan(pg,b,e,o)
        if mcp_pending:
            dbplan['mcpAuditRolePreflight']={'adminSuperuser':True,'auditRoleAbsent':True,
                                           'incidentBinding':incident_binding(incident_trigger)}
            dbplan['mcpAuditRoleAdministration']['temporaryIncidentTrigger']=not incident_trigger
        if backup_reader:
            facts={'databaseOid':o['mcp']['identity']['oid'],'databaseMatched':True,
                'roleMatched':True,'superuser':True,'readOnly':True}
            dbplan=d.compile_mcp_backup_reader(dbplan,facts)
            preflight=patch.object(d,'mcp_backup_preflight',return_value=facts)
            preflight.start();self.addCleanup(preflight.stop)
        installation=copy.deepcopy(cohort.plan);installation['databasePlanHash']=p.digest(dbplan)
        migration=next(r for r in installation['replacements'] if r['module']=='mcp')
        migration['creationRequest']['Entrypoint']=['/usr/local/bin/ouf-mcp']
        migration['creationRequest']['Env'].append('MCP_DATABASE_URL=postgres://fixture@ouf-postgres/fixture_mcp')
        raw=json.loads(f.authority);raw['applicationCohortInstallation']=c.installation_scope(installation)
        f.authority=crypto.encoded(raw);f.approval['executionAuthorityHash']=crypto.sha(f.authority)
        f.write(f.mandate,crypto.encoded(f.approval));f.approved=crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        backup=f.root/'backup';backup.mkdir(mode=0o700)
        journal=f.root/'db-journal';journal.mkdir(mode=0o700)
        executable=f.root/'fixture-docker';log=f.root/'fixture-subprocess.log'
        payload=b'EXPLICIT_DISPOSABLE_ARCHIVE_FIXTURE\n'+b'data'*256
        code='#!/usr/bin/python3\nimport sys,pathlib\npayload='+repr(payload)+'\nlog=pathlib.Path('+repr(str(log))+')\n'
        code+="with log.open('a') as out:out.write('dump\\n' if 'pg_dump' in sys.argv else 'parse\\n')\n"
        code+="if 'pg_dump' in sys.argv:sys.stdout.buffer.write(payload)\nelse:raise SystemExit(0 if sys.stdin.buffer.read()==payload else 1)\n"
        executable.write_text(code);executable.chmod(0o700)
        owner=d.CohortDatabases(action,native.engine,Journal(journal),installation,dbplan,backup,
            {'path':str(executable),'sha256':hashlib.sha256(executable.read_bytes()).hexdigest()})
        if mcp_pending:
            preflight=patch.object(d,'mcp_admin_preflight',return_value=dbplan['mcpAuditRolePreflight'])
            preflight.start();self.addCleanup(preflight.stop)
            role={'roleExists':False,'noLogin':False,'schemaCreate':False,
                  'membershipCount':0,'appMembership':0,'functionOwnerCount':0}
            incident=incident_binding(incident_trigger)
            def audit_state(binding,statement=''):
                if 'CREATE ROLE' in statement:
                    role.update(roleExists=True,noLogin=True,schemaCreate=True,
                                membershipCount=1,appMembership=1)
                    if 'GRANT TRIGGER ON TABLE' in statement:
                        incident.update(triggerAuthority=True,triggerGrantCount=1)
                if 'REVOKE' in statement:
                    role.update(schemaCreate=False,membershipCount=0,appMembership=0)
                    if 'REVOKE TRIGGER ON TABLE' in statement:
                        incident.update(triggerAuthority=False,triggerGrantCount=0)
                role['functionOwnerCount']=2 if o['mcp']['migrations']==e['mcp'] else 0
                return {'adminSuperuser':True,'adminRoleMatched':True,**role,'incidentBinding':copy.deepcopy(incident)}
            owner.audit_role_state=audit_state
        observation=patch.object(d,'observe_database',side_effect=lambda cid,u,db,m:copy.deepcopy(o[m]))
        observation.start();self.addCleanup(observation.stop)
        owner.initialize()
        return owner,native,f,o,e,log

    def test_explicit_mcp_reader_is_signed_and_does_not_change_workload_role(self):
        owner,_,_,_,_,_=self.fixture(mcp_pending=True,backup_reader=True)
        binding=owner.plan['modules'][-1]
        self.assertEqual(binding['user'],'postgres')
        self.assertEqual(d.selected_backup_user(owner.plan,binding),'fixture_admin')
        for row in owner.plan['modules'][:-1]:self.assertEqual(d.selected_backup_user(owner.plan,row),row['user'])
        owner.backup_quiesced()
        self.assertEqual(owner.record()['backups']['mcp']['state'],'COMPLETE')
        self.assertIsNone(owner.record()['mcpMigration'])

    def test_changed_admin_preflight_denies_before_archive_creation(self):
        owner,_,_,_,_,_=self.fixture(mcp_pending=True,backup_reader=True)
        with patch.object(d,'mcp_backup_preflight',return_value={'superuser':False}):
            with self.assertRaisesRegex(p.PlanDenied,'CURRENT_MCP_BACKUP_READER_DRIFT'):owner.backup_quiesced()
        self.assertFalse((owner.root/'mcp.dump').exists())
        self.assertEqual(owner.record()['backups']['mcp']['state'],'CLAIMED')

    def test_no_implicit_privilege_fallback_and_no_old_claim_replay(self):
        owner,_,_,_,_,_=self.fixture(mcp_pending=True)
        binding=owner.plan['modules'][-1]
        self.assertEqual(d.selected_backup_user(owner.plan,binding),binding['user'])
        previous=owner.record();following=copy.deepcopy(previous);following['version']+=1
        following['backups']['mcp']={'state':'CLAIMED','scopeHash':p.digest(binding)}
        owner.journal.compare_and_save(previous,following)
        with self.assertRaisesRegex(p.PlanDenied,'NOT_REPLAY'):owner.backup_quiesced()

    def test_reader_field_tampering_and_wrong_preflight_are_denied(self):
        owner,_,_,_,_,_=self.fixture(mcp_pending=True,backup_reader=True)
        for key,value in [('user','unreviewed'),('database','other'),('databaseOid',99),
                          ('sourceDatabasePlanHash','0'*64),('automaticFallbackAllowed',True)]:
            changed=copy.deepcopy(owner.plan);changed['mcpBackupReader'][key]=value
            with self.assertRaises(p.PlanDenied):d.selected_backup_user(changed,changed['modules'][-1])
        prior=copy.deepcopy(owner.plan);prior.pop('mcpBackupReader')
        facts=copy.deepcopy(owner.plan['mcpBackupReader']['preflight']);facts['superuser']=False
        with self.assertRaises(p.PlanDenied):d.compile_mcp_backup_reader(prior,facts)

    def test_dump_error_categories_are_closed_and_bounded(self):
        self.assertEqual(d.dump_failure_reason(b'permission denied for table SECRET'),
            'COHORT_DATABASE_DUMP_INSUFFICIENT_PRIVILEGE')
        self.assertEqual(d.dump_failure_reason(b'unknown SECRET'), 'COHORT_DATABASE_DUMP_FAILED')
        owner,_,_,_,_,log=self.fixture()
        binary=Path(owner.docker['path'])
        binary.write_text('#!/usr/bin/python3\nimport sys\nsys.stderr.write("permission denied for table SECRET\\n");sys.exit(1)\n')
        owner.docker['sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        with self.assertRaisesRegex(p.PlanDenied,'DUMP_INSUFFICIENT_PRIVILEGE')as caught:owner.backup_quiesced()
        self.assertNotIn('SECRET',str(caught.exception));self.assertEqual(owner.record()['backups']['udp']['state'],'CLAIMED')

    def test_temporary_trigger_grant_is_scoped_and_cleanup_preserves_prior_acl(self):
        owner,_,_,_,_,_=self.fixture(mcp_pending=True,incident_trigger=False)
        owner.backup_quiesced();binding=owner.plan['modules'][-1]
        statements=[];channel=owner.audit_role_state
        def capture(binding,statement=''):
            if statement:statements.append(statement)
            return channel(binding,statement)
        owner.audit_role_state=capture
        owner.prepare_mcp_audit_role(binding)
        prior=owner.record();following=copy.deepcopy(prior);following['version']+=1
        following['mcpMigration']={'state':'COMPLETE'};owner.journal.compare_and_save(prior,following)
        # The existing runtime fixture reports both packaged function owners
        # only once its migration history is at the reviewed expected suffix.
        channel_state=owner.audit_role_state
        def completed(binding,statement=''):
            value=channel_state(binding,statement);value['functionOwnerCount']=2;return value
        owner.audit_role_state=completed
        owner.clean_mcp_audit_role(binding)
        self.assertEqual(owner.record()['mcpAuditRole']['state'],'CLEAN')
        self.assertIn('GRANT TRIGGER ON TABLE ouf_mcp.security_incident TO "postgres";',statements[0])
        self.assertIn('REVOKE TRIGGER ON TABLE ouf_mcp.security_incident FROM "postgres";',statements[1])
        self.assertFalse(any('ALTER TABLE' in sql or 'OWNER TO' in sql for sql in statements))
        state={'incidentBinding':incident_binding(False)};owner.incident_state(state,False)
        state['incidentBinding']['aclHash']='f'*64
        with self.assertRaisesRegex(p.PlanDenied,'PRIVILEGES_DRIFT'):owner.incident_state(state,False)

    def test_native_private_capture_reconciles_complete_archives_without_replay_or_restore(self):
        owner,native,_,current,expected,log=self.fixture()
        report=owner.backup_quiesced();self.assertEqual(report['backupCount'],4);self.assertFalse(report['restorePerformed'])
        calls=log.read_text();self.assertEqual(calls.count('dump'),4);self.assertEqual(calls.count('parse'),4)
        owner.backup_quiesced();self.assertEqual(log.read_text(),calls)
        for module in p.MODULES:
            path=owner.root/(module+'.dump');self.assertEqual(path.stat().st_mode&0o777,0o600)
            current[module]['migrations']=copy.deepcopy(expected[module])
            proof=owner.verify_module(module);self.assertEqual(proof['migrationCount'],len(expected[module]))
        self.assertEqual(native.calls,[])
        self.assertNotIn('data',json.dumps(report))

    def test_partial_capture_claim_and_existing_archive_never_authorize_rerun(self):
        owner,native,_,_,_,log=self.fixture();capture=owner.capture
        def crash(binding):capture(binding);raise RuntimeError('fixture crash after durable archive')
        owner.capture=crash
        with self.assertRaisesRegex(RuntimeError,'durable archive'):owner.backup_quiesced()
        self.assertEqual(owner.record()['backups']['udp']['state'],'CLAIMED')
        before=log.read_text();owner.capture=capture
        with self.assertRaisesRegex(p.PlanDenied,'NOT_REPLAY'):owner.backup_quiesced()
        self.assertEqual(log.read_text(),before);self.assertEqual(native.calls,[])

    def test_archive_byte_drift_schema_drift_and_producer_restart_deny(self):
        owner,native,_,current,expected,log=self.fixture();owner.backup_quiesced();calls=log.read_text()
        current['udp']['migrations']=copy.deepcopy(expected['udp']);current['udp']['migrations'][1]['checksum']+=1
        with self.assertRaisesRegex(p.PlanDenied,'NOT_PACKAGED_VERSION'):owner.verify_module('udp')
        current['udp']['migrations']=copy.deepcopy(expected['udp'])
        path=owner.root/'udp.dump';path.write_bytes(path.read_bytes()+b'foreign')
        with self.assertRaisesRegex(p.PlanDenied,'ARCHIVE_CHANGED'):owner.verify_module('udp')
        native.find('1'*64)['State'].update(Running=True,Pid=2222)
        with self.assertRaisesRegex(p.PlanDenied,'QUIESCENT'):owner.backup_quiesced()
        self.assertEqual(log.read_text(),calls)

    def test_current_human_revocation_and_database_generation_drift_block_backup(self):
        for kind in ('authority','postgres'):
            with self.subTest(kind=kind):
                owner,native,f,_,_,log=self.fixture()
                if kind=='authority':f.approval['state']='REVOKED';f.write(f.mandate,crypto.encoded(f.approval))
                else:native.find('5'*64)['State']['Pid']+=1
                with self.assertRaises(Exception):owner.backup_quiesced()
                self.assertEqual(owner.record()['backups'],{});self.assertFalse(log.exists())

    def test_separate_mcp_role_applies_pending_history_once_after_backup(self):
        owner,native,_,current,expected,_=self.fixture(mcp_pending=True)
        owner.backup_quiesced(); original=owner.engine.request; migrator={};effects=[]
        def transport(method,path,body=None):
            if path.startswith('/v1.44/containers/ouf-mcp-migrate-fixture/json'):
                return (200,copy.deepcopy(migrator)) if migrator else (404,None)
            if path.startswith('/v1.44/containers/create?name=ouf-mcp-migrate-fixture'):
                effects.append('create')
                migrator.update(Id='e'*64,Name='/ouf-mcp-migrate-fixture',Image=body['Image'],
                    Config={k:copy.deepcopy(v) for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')},
                    HostConfig={**copy.deepcopy(body['HostConfig']),'Privileged':False},Mounts=[],RestartCount=0,
                    NetworkSettings={'Networks':{'ouf-backend':{'NetworkID':body['NetworkingConfig']['EndpointsConfig']['ouf-backend']['NetworkID']}}},
                    State={'Status':'created','Running':False,'Pid':0})
                return 201,{'Id':migrator['Id']}
            if path == '/v1.44/containers/'+'e'*64+'/start':
                effects.append('start');migrator['State'].update(Status='exited',ExitCode=0)
                current['mcp']['migrations']=copy.deepcopy(expected['mcp'])
                return 204,None
            return original(method,path,body)
        owner.engine.request=transport;self.addCleanup(setattr,owner.engine,'request',original)
        proof=owner.migrate_mcp();self.assertEqual(proof['pendingMigrationCount'],3)
        self.assertEqual(effects,['create','start'])
        owner.migrate_mcp();self.assertEqual(effects,['create','start'])
        self.assertEqual(owner.record()['mcpMigration']['state'],'COMPLETE')
        self.assertEqual(owner.record()['mcpAuditRole']['state'],'CLEAN')

    def test_ambiguous_mcp_creation_does_not_replay_effect(self):
        owner,native,_,_,_,_=self.fixture(mcp_pending=True)
        owner.backup_quiesced(); original=owner.engine.request;effects=[]
        def transport(method,path,body=None):
            if path.startswith('/v1.44/containers/ouf-mcp-migrate-fixture/json'):
                return 404,None
            if path.startswith('/v1.44/containers/create?name=ouf-mcp-migrate-fixture'):
                effects.append('create');return 500,None
            return original(method,path,body)
        owner.engine.request=transport;self.addCleanup(setattr,owner.engine,'request',original)
        with self.assertRaisesRegex(p.PlanDenied,'RECONCILIATION'):owner.migrate_mcp()
        self.assertEqual(owner.record()['mcpMigration']['state'],'CLAIMED')
        with self.assertRaisesRegex(p.PlanDenied,'RECONCILIATION'):owner.migrate_mcp()
        self.assertEqual(effects,['create'])

    def test_ambiguous_administrator_bootstrap_never_replays_role_grant(self):
        owner,native,_,_,_,_=self.fixture(mcp_pending=True)
        owner.backup_quiesced();statements=[]
        def lost_ack(binding,statement=''):
            if statement:
                statements.append(statement)
                raise RuntimeError('administrator ACK lost')
            return {'adminSuperuser':True,'roleExists':False,'noLogin':False,
                    'schemaCreate':False,'membershipCount':0,'appMembership':0,
                    'functionOwnerCount':0}
        owner.audit_role_state=lost_ack
        with self.assertRaisesRegex(RuntimeError,'ACK lost'):owner.migrate_mcp()
        self.assertEqual(owner.record()['mcpAuditRole']['state'],'BOOTSTRAP_CLAIMED')
        with self.assertRaisesRegex(p.PlanDenied,'RECONCILIATION'):owner.migrate_mcp()
        self.assertEqual(len(statements),1);self.assertEqual(native.calls,[])

    def test_capture_size_bound_leaves_consumed_claim_and_private_partial(self):
        owner,native,_,_,_,log=self.fixture()
        # Test the capture's bounded stream directly after a durable synthetic
        # claim. Production binding always supplies the signed 1 GiB bound.
        binding=copy.deepcopy(owner.plan['modules'][0]);binding['maximumArchiveBytes']=120
        prior=owner.record();following=copy.deepcopy(prior)
        following['backups']['udp']={'state':'CLAIMED','scopeHash':p.digest(binding)}
        following['version']+=1;owner.journal.compare_and_save(prior,following)
        with self.assertRaisesRegex(p.PlanDenied,'SIZE_BOUND'):owner.capture(binding)
        self.assertEqual(owner.record()['backups']['udp']['state'],'CLAIMED')
        self.assertEqual((owner.root/'udp.dump').stat().st_mode&0o777,0o600)
        before=log.read_text()
        with self.assertRaisesRegex(p.PlanDenied,'NOT_REPLAY'):owner.backup_quiesced()
        self.assertEqual(log.read_text(),before);self.assertEqual(native.calls,[])

if __name__=='__main__':unittest.main()
