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
import unittest

import test_chatbot_cohort_containers as fixture
from tools.chatbot_file_cohort import containers as c, databases as d, plan as p
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine


@unittest.skipUnless(os.environ.get('OUF_NATIVE_POSTGRES') == '1', 'explicit disposable Docker/PostgreSQL CI only')
class NativePostgres(unittest.TestCase):
    def test_real_archives_preserve_rows_and_owner_migration_identity(self):
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
            current[module] = d.observe_database(cid, 'postgres', database, module)
        dbplan = d.compile_database_plan(pg, bindings, expected, current)
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
            owner.verify_module(module)
            schema = d.identifier(d.SCHEMAS[module])
            self.assertEqual(sql(bindings[module]['database'], 'SELECT count(*) FROM '+schema+'.retained_data;').strip(), b'2')
            raw = (backup/(module+'.dump')).read_bytes()
            self.assertTrue(raw.startswith(b'PGDMP'))
            restored = docker('exec', '-i', cid, 'pg_restore', '--file=-', data=raw)
            self.assertIn(b'preexisting', restored); self.assertIn('città'.encode(), restored)
        # Changing a real installed owner history fails the signed migration match.
        sql(bindings['udp']['database'], 'UPDATE '+d.identifier(d.SCHEMAS['udp'])+'.flyway_schema_history SET checksum=0;')
        with self.assertRaisesRegex(p.PlanDenied, 'NOT_PACKAGED_VERSION'): owner.verify_module('udp')


if __name__ == '__main__': unittest.main()
