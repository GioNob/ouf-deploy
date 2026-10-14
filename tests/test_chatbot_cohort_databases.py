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
        pg,b,e,o=inputs();e['mcp'].append({'version':2,'checksum':'b'*64})
        with self.assertRaisesRegex(p.PlanDenied,'MCP_MIGRATION_ROLE'):d.compile_database_plan(pg,b,e,o)
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

class DatabaseRuntime(unittest.TestCase):
    def fixture(self):
        fixture=runtime_fixture.CohortRuntime();cohort,native,f,_=fixture.fixture();self.addCleanup(fixture.doCleanups)
        pg,b,e,o=inputs();native.state[pg['Id']]=copy.deepcopy(pg)
        dbplan=d.compile_database_plan(pg,b,e,o)
        installation=copy.deepcopy(cohort.plan);installation['databasePlanHash']=p.digest(dbplan)
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
        observation=patch.object(d,'observe_database',side_effect=lambda cid,u,db,m:copy.deepcopy(o[m]))
        observation.start();self.addCleanup(observation.stop)
        owner.initialize()
        return owner,native,f,o,e,log

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
