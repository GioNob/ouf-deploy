"""Actual PG17/Flyway18 resources, Docker GETs and one native read-only session.

All DDL/tampering here is confined to disposable CI fixtures, never the target.
The application container is a sleeping fixture, not the candidate JVM.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('db_native',ROOT/'scripts/read-ingestion-db-preflight-20261020.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def command(arguments, seconds=30, env=None):
    result = subprocess.run(arguments,capture_output=True,timeout=seconds,env=env)
    if result.returncode:
        raise RuntimeError('FIXTURE_COMMAND_FAILED: '+result.stderr.decode(errors='replace')[-2000:])
    return result.stdout


class NativeDatabase(unittest.TestCase):
    def setUp(self):
        m.DB_PROGRESS.clear()

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='ingestion-db-native-',dir=os.environ['OUF_TEST_ROOT'])
        cls.root = Path(cls.directory.name)
        cls.label = 'ouf-db-read-'+uuid.uuid4().hex[:10]
        cls.pg,cls.app,cls.network = cls.label+'-pg',cls.label+'-app',cls.label+'-network'
        cls.db,cls.user = 'admission_fixture','admission_runtime'
        cls.docker = shutil.which('docker')
        cls.addClassCleanup(cls.cleanup)
        command([cls.docker,'pull','postgres:17-alpine'],120)
        command([cls.docker,'network','create',cls.network])
        command([cls.docker,'run','-d','--name',cls.pg,'--network',cls.network,
                 '-p','127.0.0.1::5432','-e','POSTGRES_PASSWORD=ci-only-admin',
                 '-e','POSTGRES_DB='+cls.db,'postgres:17-alpine'])
        for attempt in range(30):
            # Entrypoint's temporary init server accepts Unix probes before the
            # requested DB exists. Require the final TCP server and real DB.
            ready = subprocess.run([cls.docker,'exec','-e','PGPASSWORD=ci-only-admin',cls.pg,
                                    'psql','-X','-w','-q','-A','-t','-h','127.0.0.1',
                                    '-U','postgres','-d',cls.db,'-c','SELECT 1'],capture_output=True,timeout=5)
            if ready.returncode == 0: break
            if attempt == 29: raise RuntimeError('FIXTURE_POSTGRES_READINESS_EXHAUSTED')
            time.sleep(.5)
        cls.admin("CREATE ROLE "+cls.user+" LOGIN PASSWORD 'ci-only-runtime'; GRANT CONNECT,CREATE ON DATABASE "+cls.db+" TO "+cls.user)
        actual = cls.inspect(cls.pg)
        port = actual['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        cls.sql_root = Path(os.environ['OUF_INGESTION_SQL_ROOT'])
        for row in m.MANIFEST['migrations']:
            assert hashlib.sha256((cls.sql_root/row['script']).read_bytes()).hexdigest() == row['resourceSha256']
        env = dict(os.environ,OUF_FIXTURE_JDBC='jdbc:postgresql://127.0.0.1:'+port+'/'+cls.db,
                   OUF_FIXTURE_USER=cls.user,OUF_FIXTURE_PASSWORD='ci-only-runtime')
        native = command([os.environ['OUF_FIXTURE_JAVA'],'-cp',os.environ['OUF_FLYWAY_CLASSPATH'],'NativeFlyway','migrate',str(cls.sql_root)],90,env)
        observed = {}
        for line in native.decode().splitlines():
            if line.startswith('OUF_NATIVE_SQL_CHECKSUM='):
                script,checksum = line.split('=',1)[1].split('\t')
                observed[script] = int(checksum)
        assert observed == {r['script']:r['checksum'] for r in m.MANIFEST['migrations']}
        cls.native_checksums = len(observed)
        cls.admin('REVOKE CREATE ON DATABASE '+cls.db+' FROM '+cls.user)
        command([cls.docker,'run','-d','--name',cls.app,'--network',cls.network,
                 '-e','OUF_ING_DB_URL=jdbc:postgresql://'+cls.pg+':5432/'+cls.db,
                 '-e','OUF_ING_DB_USER='+cls.user,'-e','OUF_ING_DB_PASSWORD=CI_ONLY_NEVER_PRINT',
                 'postgres:17-alpine','sleep','600'])
        socket = Path('/var/run/docker.sock').resolve(); info = socket.stat()
        pg,app = cls.inspect(cls.pg),cls.inspect(cls.app)
        oid = int(cls.admin("SELECT oid FROM pg_database WHERE datname='"+cls.db+"'").strip())
        cls.selected = {'engine':{'socketPath':str(socket),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]},
                        'postgres':m.runtime(pg,False),'ingestion':m.runtime(app),'database':cls.db,'user':cls.user,'databaseOid':oid,
                        'docker':{'path':cls.docker,'sha256':hashlib.sha256(Path(cls.docker).read_bytes()).hexdigest()},
                        'dockerConfigDirectory':str(cls.root)}
        facts = cls.facts()
        cls.reference = m.digest(facts['catalog'])
        if m.REFERENCE_CATALOG_SHA256 is not None:
            assert cls.reference == m.REFERENCE_CATALOG_SHA256, 'PINNED_REFERENCE_CATALOG_MISMATCH'
        print('OUF_REFERENCE_CATALOG_SHA256='+cls.reference,flush=True)
        print('OUF_NATIVE_FLYWAY_SQL_CHECKSUMS='+str(cls.native_checksums),flush=True)

    @classmethod
    def cleanup(cls):
        for name in (getattr(cls,'app',''),getattr(cls,'pg','')):
            if name: subprocess.run([cls.docker,'rm','-f',name],capture_output=True,timeout=20)
        if getattr(cls,'network',''): subprocess.run([cls.docker,'network','rm',cls.network],capture_output=True,timeout=20)
        if hasattr(cls,'directory'): cls.directory.cleanup()

    @classmethod
    def inspect(cls,name):
        return json.loads(command([cls.docker,'inspect',name]))[0]

    @classmethod
    def admin(cls,sql):
        return command([cls.docker,'exec',cls.pg,'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d',cls.db,'-c',sql])

    @classmethod
    def facts(cls):
        args = m.native_arguments(cls.selected,cls.docker)
        status,raw,errors = m.bounded_command(args)
        if status: raise RuntimeError('NATIVE_FIXTURE_READ_FAILED: '+errors.decode(errors='replace')[-2000:])
        return m.decode(raw)

    def analyzed(self):
        with patch.object(m,'REFERENCE_CATALOG_SHA256',self.reference):
            return m.analyze(self.facts(),self.selected)

    def test_native_flyway_checksums_and_real_schema_match(self):
        self.assertEqual(self.native_checksums,18)
        report = self.analyzed()
        self.assertTrue(report['sqlHistoryMatchesCandidate'])
        self.assertTrue(report['runtimeCatalogMatchesQualifiedCandidate'])
        self.assertTrue(report['requiredRuntimePrivilegesAvailable'])
        self.assertTrue(report['databaseReadPrerequisitesProven'])

    def test_complete_native_docker_and_psql_adapter_without_target_authority(self):
        before = self.admin('SELECT count(*) FROM ouf_ingestion.audit_event')
        with patch.object(m,'REFERENCE_CATALOG_SHA256',self.reference): report = m.collect(self.selected)
        self.assertTrue(report['databaseReadPrerequisitesProven'])
        self.assertEqual(report['engineGetRequests'],4)
        self.assertEqual(report['nativeSqlSessions'],1)
        self.assertFalse(report['databaseAdmissionProven'])
        self.assertFalse(report['runtimeStartupMigrationPolicyProven'])
        self.assertFalse(report['runtimeAuthorityIssued'])
        self.assertEqual(self.admin('SELECT count(*) FROM ouf_ingestion.audit_event'),before)
        self.assertNotIn('CI_ONLY_NEVER_PRINT',m.encoded(report).decode())

    def test_read_only_server_enforcement_denies_mutation(self):
        args = m.native_arguments(self.selected,self.docker)
        args[-1] = "UPDATE ouf_ingestion.runtime_pressure_policy SET state='HARD_PRESSURE'"
        status,_,errors = m.bounded_command(args)
        self.assertNotEqual(status,0); self.assertIn(b'25006',errors)
        self.assertEqual(self.admin('SELECT state FROM ouf_ingestion.runtime_pressure_policy').strip(),b'NORMAL')

    def test_unrecorded_schema_drift_is_detected_despite_unchanged_history(self):
        self.admin('ALTER TABLE ouf_ingestion.ing_run ADD COLUMN diagnostic_drift text')
        try:
            report = self.analyzed()
            self.assertTrue(report['sqlHistoryMatchesCandidate'])
            self.assertFalse(report['runtimeCatalogMatchesQualifiedCandidate'])
            self.assertFalse(report['databaseReadPrerequisitesProven'])
        finally: self.admin('ALTER TABLE ouf_ingestion.ing_run DROP COLUMN diagnostic_drift')

    def test_effective_role_privilege_gap_is_detected_without_catalog_owner_hash(self):
        self.admin('ALTER TABLE ouf_ingestion.ing_run OWNER TO postgres; GRANT SELECT,INSERT,DELETE ON ouf_ingestion.ing_run TO '+self.user)
        try:
            report = self.analyzed()
            self.assertTrue(report['runtimeCatalogMatchesQualifiedCandidate'])
            self.assertFalse(report['requiredRuntimePrivilegesAvailable'])
            self.assertIn({'table':'ing_run','permission':'update_allowed'},report['privilegeGaps'])
        finally: self.admin('ALTER TABLE ouf_ingestion.ing_run OWNER TO '+self.user)

    def test_hard_pressure_is_observed_without_mutating_policy(self):
        self.admin("UPDATE ouf_ingestion.runtime_pressure_policy SET state='HARD_PRESSURE'")
        try:
            report = self.analyzed()
            self.assertEqual(report['storedPressureState'],'HARD_PRESSURE')
            self.assertFalse(report['databaseReadPrerequisitesProven'])
            self.assertEqual(self.admin('SELECT state FROM ouf_ingestion.runtime_pressure_policy').strip(),b'HARD_PRESSURE')
        finally: self.admin("UPDATE ouf_ingestion.runtime_pressure_policy SET state='NORMAL'")

    def test_pending_work_blocks_replacement_preflight(self):
        self.admin("INSERT INTO ouf_ingestion.ing_run(run_id,source_id,bundle_id,bundle_version,bundle_checksum,mode,state,correlation_id) VALUES('11111111-1111-1111-1111-111111111111','synthetic','synthetic','1','synthetic','MANAGED_ONCE','READY','synthetic')")
        try:
            report = self.analyzed()
            self.assertFalse(report['runtimeWorkDrainedAtSnapshot'])
            self.assertFalse(report['databaseReadPrerequisitesProven'])
        finally: self.admin("DELETE FROM ouf_ingestion.ing_run WHERE run_id='11111111-1111-1111-1111-111111111111'")

    def test_permission_failure_returns_only_sqlstate_and_constant_reason(self):
        self.admin('ALTER TABLE ouf_ingestion.runtime_pressure_policy OWNER TO postgres')
        try:
            with patch.object(m,'REFERENCE_CATALOG_SHA256',self.reference):
                with self.assertRaisesRegex(m.Denied,'NATIVE_FIXED_READ_ONLY_SQL_FAILED'): m.collect(self.selected)
            self.assertEqual(m.DB_PROGRESS.get('nativeSqlState'),'42501')
            self.assertNotIn('CI_ONLY_NEVER_PRINT',m.encoded(m.DB_PROGRESS).decode())
        finally: self.admin('ALTER TABLE ouf_ingestion.runtime_pressure_policy OWNER TO '+self.user)


if __name__ == '__main__': unittest.main()
