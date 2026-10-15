"""Real Docker/PostgreSQL backup qualification, never a target VPS operation.

CI supplies its disposable PostgreSQL service container. No mock replaces the
Engine, Psql, pg_dump, pg_restore, private Journal or signed action in this test.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import unittest

import test_chatbot_cohort_containers as fixture
from tools.chatbot_file_cohort import containers as c, databases as d, plan as p
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine


@unittest.skipUnless(os.environ.get('OUF_NATIVE_POSTGRES') == '1', 'explicit disposable Docker/PostgreSQL CI only')
class NativePostgres(unittest.TestCase):
    def test_real_containerd_bundle_and_namespace_profile_are_exact(self):
        """Native path/inode qualification on the existing disposable service."""
        sys.path.insert(0,str(fixture.ROOT/'tools/semantic_frame_compiler'))
        import file_only_preparation as prep
        cid=os.environ['OUF_POSTGRES_CONTAINER_ID']
        docker=Path(shutil.which('docker')).resolve();runtime=Path(shutil.which('runc')).resolve()
        def native(argv):
            return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,check=True,timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}).stdout
        with __import__('tempfile').TemporaryDirectory() as config:
            def inspect():
                return json.loads(native([str(docker),'--host','unix:///var/run/docker.sock',
                    '--config',config,'inspect','--type=container',cid]))[0]
            current=inspect()
            state=json.loads(native([str(runtime),'--root',prep.RUNTIME_ROOT,'state',cid]))
            context=prep.retained_runtime_context(current,state,{'runtimeStateRoot':'/run/docker'})
            prep.verify_namespace(current,context)
            self.assertIn(context['bundleParent'],prep.BUNDLE_PARENTS)
            self.assertEqual(state['bundle'],context['bundleParent']+'/'+cid)
            info=Path(state['bundle']).stat()
            self.assertTrue(stat.S_ISDIR(info.st_mode));self.assertEqual(info.st_uid,0)
            self.assertFalse(info.st_mode&0o022)
            self.assertEqual(json.loads(native([str(runtime),'--root',prep.RUNTIME_ROOT,'state',cid])),state)
            self.assertEqual(p.runtime_pin(inspect()),p.runtime_pin(current))

    def test_custom_admin_and_nonowned_incident_table_apply_exact_audit_migration(self):
        """Actual PG primitives and pinned migration; not a target rollout."""
        cid=os.environ['OUF_POSTGRES_CONTAINER_ID'];self.assertRegex(cid,r'^[a-f0-9]{64}$')
        docker=shutil.which('docker')
        def sql(database,statement,user='postgres'):
            return subprocess.run([docker,'exec','-i',cid,'psql','-X','-q','-A','-t',
                '-v','ON_ERROR_STOP=1','-U',user,'-d',database],input=statement.encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=30).stdout
        suffix=os.urandom(8).hex();database='ouf_audit_'+suffix
        admin='ouf_admin_'+suffix;app='ouf_app_'+suffix;other='ouf_incident_'+suffix
        sql('postgres','CREATE ROLE '+admin+' LOGIN SUPERUSER; CREATE ROLE '+app+
            ' LOGIN NOSUPERUSER NOCREATEROLE; CREATE ROLE '+other+' NOLOGIN;')
        sql('postgres','CREATE DATABASE '+database+';')
        def cleanup():
            sql('postgres','DROP DATABASE '+database+' WITH (FORCE);')
            sql('postgres','DROP ROLE ouf_mcp_operational_audit_owner; DROP ROLE '+app+
                '; DROP ROLE '+other+'; DROP ROLE '+admin+';')
        self.addCleanup(cleanup)
        sql(database,'CREATE SCHEMA ouf_mcp AUTHORIZATION '+app+'; SET ROLE '+app+'; '
            'CREATE TABLE ouf_mcp.audit_event(sequence_id bigserial, audit_event_id uuid, event_type text, '
            'actor_type text,service_principal_id text,attempt_id uuid,manifest_checksum char(64),safe_detail jsonb,occurred_at timestamptz); '
            'CREATE TABLE ouf_mcp.tool_attempt(attempt_id uuid,service_principal_id text,manifest_checksum char(64),'
            'state text,lock_version bigint,unknown_since timestamptz,admitted_at timestamptz); '
            'CREATE TABLE ouf_mcp.security_incident(attempt_id uuid); RESET ROLE; '
            'ALTER TABLE ouf_mcp.security_incident OWNER TO '+other+';',admin)
        facts=d.mcp_admin_preflight(cid,database,app,admin)
        self.assertTrue(facts['adminRoleMatched']);self.assertTrue(facts['adminSuperuser'])
        self.assertFalse(facts['applicationIncidentTableOwnerAuthority'])
        before=facts['incidentBinding'];self.assertFalse(before['triggerAuthority'])
        # The required trigger privilege is separately proven, without altering
        # the owner or using a superuser as the candidate migration workload.
        channel=d.Psql(cid,app,database,'ouf-cutover-native-denied')
        try:
            with self.assertRaises(Exception):
                channel.query('true',"CREATE FUNCTION ouf_mcp.denied_capture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN new; END $$; CREATE TRIGGER denied_capture AFTER INSERT ON ouf_mcp.security_incident FOR EACH ROW EXECUTE FUNCTION ouf_mcp.denied_capture();")
        finally:channel.close()
        sql(database,'BEGIN; '+d.incident_guard(app,before)+
            'CREATE ROLE ouf_mcp_operational_audit_owner NOLOGIN NOSUPERUSER NOCREATEROLE; '
            'GRANT CREATE ON SCHEMA ouf_mcp TO ouf_mcp_operational_audit_owner; '
            'GRANT ouf_mcp_operational_audit_owner TO '+app+' WITH ADMIN FALSE, INHERIT FALSE, SET TRUE; '
            'GRANT TRIGGER ON TABLE ouf_mcp.security_incident TO '+app+'; COMMIT;',admin)
        source=Path(os.environ['OUF_CHATBOT_MCP_ROOT'])/'internal/adapter/postgres/migrations/012_operational_audit_capture.sql'
        raw=source.read_bytes()
        self.assertEqual(hashlib.sha1(('blob '+str(len(raw))+'\0').encode()+raw).hexdigest(),
                         '733eddb3d0c9f5cacd883ad78ea2286601cbe30b')
        channel=d.Psql(cid,app,database,'ouf-cutover-native-migration')
        try:channel.query('true',raw.decode(),timeout=20)
        finally:channel.close()
        channel=d.Psql(cid,admin,database,'ouf-cutover-native-acl')
        try:
            active=channel.query(d.incident_metadata(app,True))
            self.assertEqual(active['ownerOid'],before['ownerOid'])
            self.assertEqual(active['aclHash'],before['aclHash'])
            self.assertTrue(active['triggerAuthority']);self.assertEqual(active['triggerGrantCount'],1)
            # A changed unrelated privilege blocks the guarded cleanup.
            sql(database,'GRANT SELECT ON ouf_mcp.security_incident TO '+app+';',admin)
            with self.assertRaises(subprocess.CalledProcessError):
                sql(database,'BEGIN; '+d.incident_guard(app,active,True)+'ROLLBACK;',admin)
            sql(database,'REVOKE SELECT ON ouf_mcp.security_incident FROM '+app+';',admin)
            sql(database,'BEGIN; '+d.incident_guard(app,active,True)+
                'REVOKE TRIGGER ON TABLE ouf_mcp.security_incident FROM '+app+'; '
                'REVOKE ouf_mcp_operational_audit_owner FROM '+app+'; '
                'REVOKE CREATE ON SCHEMA ouf_mcp FROM ouf_mcp_operational_audit_owner; COMMIT;',admin)
            self.assertEqual(channel.query(d.incident_metadata(app)),before)
            self.assertEqual(channel.query("SELECT count(*) FROM pg_proc WHERE oid IN (to_regprocedure('ouf_mcp.capture_operational_attempt_audit()'),to_regprocedure('ouf_mcp.capture_operational_security_audit()')) AND proowner='ouf_mcp_operational_audit_owner'::regrole"),2)
            sql(database,'INSERT INTO ouf_mcp.security_incident VALUES (NULL);',admin)
            self.assertEqual(channel.query("SELECT count(*) FROM ouf_mcp.audit_event WHERE event_type='OPERATIONAL_SECURITY_ATTENTION'"),1)
            self.assertFalse(channel.query("SELECT has_schema_privilege('ouf_mcp_operational_audit_owner','ouf_mcp','CREATE')"))
            self.assertEqual(channel.query("SELECT count(*) FROM pg_auth_members WHERE roleid='ouf_mcp_operational_audit_owner'::regrole"),0)
        finally:channel.close()

    def test_real_archives_preserve_rows_and_owner_migration_identity(self):
        self.real_archives()

    def test_restricted_mcp_role_requires_explicit_backup_reader(self):
        self.real_archives(restricted_mcp=True)

    def real_archives(self, restricted_mcp=False):
        self.assertEqual(os.geteuid(), 0)
        cid = os.environ['OUF_POSTGRES_CONTAINER_ID']
        self.assertRegex(cid, r'^[a-f0-9]{64}$')
        binary = Path(shutil.which('docker')).resolve()
        def docker(*args, data=None):
            return subprocess.run([str(binary), *args], input=data, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45).stdout
        def sql(database, statement):
            return docker('exec', '-i', cid, 'psql', '-X', '-q', '-A', '-t',
                '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database,
                data=statement.encode())
        socket_path = '/var/run/docker.sock'
        s = os.stat(socket_path, follow_symlinks=False)
        engine = Engine(socket_path, (s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)))
        code, pg = engine.request('GET', '/v1.44/containers/'+cid+'/json')
        self.assertEqual(code, 200)
        f = fixture.crypto.SignedCutover(); f.setUp(); self.addCleanup(f.doCleanups)
        bindings, expected, current = {}, {}, {}
        prefix = 'ouf_ci_'+f.root.name.replace('-', '_')[-20:]+'_'
        self.assertRegex(prefix, r'^[a-zA-Z_][a-zA-Z_0-9]*$')
        for module in p.MODULES:
            database = prefix+module
            sql('postgres', 'CREATE DATABASE '+d.identifier(database)+';')
            bindings[module] = {'database': database, 'user': 'postgres'}
            schema = d.identifier(d.SCHEMAS[module])
            if module == 'mcp':
                expected[module] = [{'version': 1, 'checksum': 'a'*64}]
                history = "CREATE TABLE "+schema+".schema_migration(version bigint PRIMARY KEY,checksum text NOT NULL); INSERT INTO "+schema+".schema_migration VALUES (1,'"+'a'*64+"');"
            else:
                expected[module] = [{'version': '1', 'script': 'V1__base.sql', 'type': 'SQL', 'checksum': 78787420, 'success': True}]
                history = "CREATE TABLE "+schema+".flyway_schema_history(installed_rank int PRIMARY KEY,version text,script text,type text,checksum int,success boolean); INSERT INTO "+schema+".flyway_schema_history VALUES (1,'1','V1__base.sql','SQL',78787420,true);"
            sql(database, 'CREATE SCHEMA '+schema+';'+history+'CREATE TABLE '+schema+".retained_data(id int PRIMARY KEY,value text); INSERT INTO "+schema+".retained_data VALUES (1,'preexisting'),(2,'città');")
            if module=='mcp' and restricted_mcp:
                app=prefix+'app'
                sql(database,'CREATE ROLE '+d.identifier(app)+' LOGIN NOSUPERUSER NOCREATEROLE; GRANT USAGE ON SCHEMA '+schema+' TO '+d.identifier(app)+'; GRANT SELECT ON '+schema+'.schema_migration TO '+d.identifier(app)+';')
                bindings[module]['user']=app
                denied=subprocess.run([str(binary),'exec',cid,'pg_dump','-U',app,'-d',database,
                    '--format=custom','--no-owner','--no-acl','--lock-wait-timeout=10s'],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
                self.assertNotEqual(denied.returncode,0)
                self.assertEqual(d.dump_failure_reason(denied.stderr),'COHORT_DATABASE_DUMP_INSUFFICIENT_PRIVILEGE')
            current[module] = d.observe_database(cid, bindings[module]['user'], database, module)
        if restricted_mcp:
            expected['mcp'] += [{'version':v,'checksum':'b'*64}for v in (10,11,12)]
        dbplan = d.compile_database_plan(pg, bindings, expected, current)
        if restricted_mcp:
            facts=d.mcp_backup_preflight(cid,bindings['mcp']['database'],'postgres')
            dbplan=d.compile_mcp_backup_reader(dbplan,facts)
        replacements = []
        for index, module in enumerate(p.MODULES):
            name = prefix+module+'_producer'
            child = docker('run', '-d', '--name', name, '--restart=no', '--entrypoint', 'sleep', pg['Image'], '300').decode().strip()
            self.addCleanup(lambda identity=child: subprocess.run([str(binary), 'rm', '-f', identity], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20))
            status, old = engine.request('GET', '/v1.44/containers/'+child+'/json')
            self.assertEqual(status, 200)
            replacements.append({'module': module, 'oldRuntimeBinding': p.runtime_pin(old), 'oldHostConfig': copy.deepcopy(old['HostConfig'])})
            docker('stop', '--timeout', '1', child)
        installation = {'schema': 'ouf.chatbot-file-cohort-installation-plan.v1', 'cohortManifestHash': 'f'*64,
            'replacements': replacements, 'databasePlanHash': p.digest(dbplan)}
        raw = json.loads(f.authority); raw['applicationCohortInstallation'] = c.installation_scope(installation)
        f.authority = fixture.crypto.encoded(raw)
        f.approval['executionAuthorityHash'] = fixture.crypto.sha(f.authority)
        f.write(f.mandate, fixture.crypto.encoded(f.approval)); f.approved = fixture.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']: f.sign(role)
        action = AggregateAction(f.gate(), f.authority, f.expected['sourceClosureHash'])
        backup = f.root/'postgres-backups'; backup.mkdir(mode=0o700)
        journal = f.root/'database-journal'; journal.mkdir(mode=0o700)
        owner = d.CohortDatabases(action, engine, Journal(journal), installation, dbplan, backup,
            {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
        owner.initialize()
        receipt = owner.backup_quiesced()
        self.assertEqual(receipt['backupCount'], 4); self.assertFalse(receipt['restorePerformed'])
        first = owner.record()
        self.assertEqual(owner.backup_quiesced(), receipt)
        self.assertEqual(owner.record(), first)
        for module in p.MODULES:
            if module!='mcp' or not restricted_mcp:owner.verify_module(module)
            schema = d.identifier(d.SCHEMAS[module])
            self.assertEqual(sql(bindings[module]['database'], 'SELECT count(*) FROM '+schema+'.retained_data;').strip(), b'2')
            raw = (backup/(module+'.dump')).read_bytes()
            self.assertTrue(raw.startswith(b'PGDMP'))
            restored = docker('exec', '-i', cid, 'pg_restore', '--file=-', data=raw)
            self.assertIn(b'preexisting', restored); self.assertIn('città'.encode(), restored)
        if restricted_mcp:
            self.assertEqual(sql(bindings['mcp']['database'],"SELECT has_table_privilege("+d.literal(app)+",'ouf_mcp.retained_data','SELECT');").strip(),b'f')
            self.assertIsNone(owner.record()['mcpMigration'])
            self.assertIsNone(owner.record()['mcpAuditRole'])
        # Changing a real installed owner history fails the signed migration match.
        sql(bindings['udp']['database'], 'UPDATE '+d.identifier(d.SCHEMAS['udp'])+'.flyway_schema_history SET checksum=0;')
        with self.assertRaisesRegex(p.PlanDenied, 'NOT_PACKAGED_VERSION'): owner.verify_module('udp')


if __name__ == '__main__': unittest.main()
