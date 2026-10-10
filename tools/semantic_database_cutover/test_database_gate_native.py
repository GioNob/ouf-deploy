"""Real disposable PostgreSQL gates, cross-database isolation and incomplete-fault semantics."""
import json, os, selectors, subprocess, sys, tempfile, time, unittest, uuid
from pathlib import Path
from database_gate import GateDenied, Psql, install_gate

def call(args,check=True):
    p=subprocess.run(args,capture_output=True,timeout=45)
    if check and p.returncode:raise RuntimeError('NATIVE_FIXTURE_COMMAND_FAILED')
    return p

class NativeGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name='ouf-db-gate-ci-'+uuid.uuid4().hex[:8]
        cls.cid=call(['docker','run','-d','--name',cls.name,'-e','POSTGRES_PASSWORD=fixture-only','postgres:17','-c','max_prepared_transactions=5']).stdout.decode().strip()
        for _ in range(30):
            if call(['docker','exec',cls.cid,'pg_isready','--host=127.0.0.1','-U','postgres'],False).returncode==0:break
            time.sleep(1)
        else:raise RuntimeError('NATIVE_POSTGRES_NOT_READY')
    @classmethod
    def tearDownClass(cls):call(['docker','rm','-f',cls.cid],False)
    def setUp(self):
        self.db='semantic_'+uuid.uuid4().hex[:8]
        self.foreign='foreign_'+uuid.uuid4().hex[:8]
        self.channels=[]
        self.admin=self.channel('postgres','admin')
        self.admin.query('true','CREATE DATABASE '+self.db+'; CREATE DATABASE '+self.foreign+';')
        self.oid=self.admin.query("SELECT oid::bigint FROM pg_database WHERE datname='"+self.db+"'")
        self.writer=self.channel(self.db,'writer')
        self.other=self.channel(self.foreign,'foreign')
        self.writer.query('true','CREATE TABLE fixture(id int); INSERT INTO fixture VALUES(1);')
        self.other.query('true','CREATE TABLE fixture(id int); INSERT INTO fixture VALUES(1);')
        self.directory=tempfile.TemporaryDirectory(prefix='ouf-db-gate-evidence-')
        os.chmod(self.directory.name,0o700)
    def channel(self,database,kind):
        channel=Psql(self.cid,'postgres',database,'ouf-cutover-'+kind+'-'+uuid.uuid4().hex[:16]);self.channels.append(channel);return channel
    def tearDown(self):
        for channel in reversed(self.channels):channel.close()
        self.directory.cleanup()
    def install(self,retained=None,checkpoint=None,oid=None):
        return install_gate(self.admin,self.db,self.oid if oid is None else oid,retained or [],self.directory.name,checkpoint=checkpoint)
    def test_complete_gate_denies_existing_and_new_clients_preserves_foreign_database_and_role(self):
        report=self.install()
        self.assertEqual(report['status'],'WRITERS_FENCED')
        with self.assertRaises(GateDenied):self.writer.query('true','INSERT INTO fixture VALUES(2);')
        denied=self.channel(self.db,'fresh')
        with self.assertRaises(GateDenied):denied.query('true')
        self.assertEqual(self.other.query('SELECT count(*) FROM fixture','INSERT INTO fixture VALUES(2);'),2)
        self.assertTrue(self.admin.query("SELECT rolcanlogin FROM pg_roles WHERE rolname='postgres'"))
        self.assertTrue(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.foreign+"'"))
        with self.assertRaisesRegex(GateDenied,'DO_NOT_REPLAY'):self.install()
    def test_failure_after_admission_close_is_retained_incomplete_never_migration_authority(self):
        def fail(phase):raise RuntimeError('FIXTURE_PROCESS_INTERRUPTION')
        with self.assertRaisesRegex(GateDenied,'INSTALLATION_INCOMPLETE'):self.install(checkpoint=fail)
        denial=json.loads((Path(self.directory.name)/'gate-denial.json').read_bytes())
        self.assertFalse(denial['writersFencedProven']);self.assertFalse(denial['backupOrMigrationAuthorityGranted'])
        self.assertFalse(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        # Existing admitted clients may still write in this partial phase. The
        # product must not call this a completed fence or use a backup from it.
        self.assertEqual(self.writer.query('SELECT count(*) FROM fixture','INSERT INTO fixture VALUES(2);'),2)
        fresh=self.channel(self.db,'fresh')
        with self.assertRaises(GateDenied):fresh.query('true')
        self.assertFalse((Path(self.directory.name)/'gate-receipt.json').exists())
        with self.assertRaisesRegex(GateDenied,'DO_NOT_REPLAY'):self.install()
    def test_wrong_database_oid_and_reused_session_generation_rejected_before_mutation(self):
        with self.assertRaisesRegex(GateDenied,'SCOPE_OR_INITIAL_STATE'):self.install(oid=self.oid+1)
        self.assertTrue(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        session=self.writer.query("SELECT json_build_object('pid',pg_backend_pid(),'backendStart',(backend_start AT TIME ZONE 'UTC')::text,'applicationName',application_name,'user',usename) FROM pg_stat_activity WHERE pid=pg_backend_pid()")
        session['applicationName']='ouf-cutover-hold-'+uuid.uuid4().hex[:16]
        with self.assertRaisesRegex(GateDenied,'SESSION_GENERATION_CHANGED'):self.install([session])
        self.assertFalse((Path(self.directory.name)/'gate-claim.json').exists())
    def test_exact_retained_session_is_kept_but_not_a_backup_or_migration_authority(self):
        hold=self.channel(self.db,'hold')
        session=hold.query("SELECT json_build_object('pid',pg_backend_pid(),'backendStart',(backend_start AT TIME ZONE 'UTC')::text,'applicationName',application_name,'user',usename) FROM pg_stat_activity WHERE pid=pg_backend_pid()")
        report=self.install([session]);self.assertEqual(len(report['retainedSessionHashes']),1)
        self.assertTrue(hold.query('true'))
        self.assertFalse(report['migrationPerformed']);self.assertFalse(report['restorePerformed'])
    def test_completed_fence_survives_actual_controller_process_kill(self):
        code="from database_gate import Psql,install_gate; import sys,time; a=Psql(sys.argv[1],'postgres','postgres','ouf-cutover-admin-crash'); install_gate(a,sys.argv[2],int(sys.argv[3]),[],sys.argv[4]); print('FENCED',flush=True); time.sleep(60)"
        child=subprocess.Popen([sys.executable,'-c',code,self.cid,self.db,str(self.oid),self.directory.name],cwd=Path(__file__).parent,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
        try:
            self.assertTrue(selector.select(20),'CONTROLLER_NOT_READY')
            self.assertEqual(child.stdout.readline().strip(),b'FENCED')
            child.kill();child.wait(timeout=5)
            self.assertFalse(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
            with self.assertRaises(GateDenied):self.writer.query('true','INSERT INTO fixture VALUES(2);')
            denied=self.channel(self.db,'fresh')
            with self.assertRaises(GateDenied):denied.query('true')
            self.assertEqual(json.loads((Path(self.directory.name)/'gate-receipt.json').read_bytes())['status'],'WRITERS_FENCED')
        finally:
            selector.close()
            if child.poll() is None:child.kill();child.wait(timeout=5)
    def test_prepared_transaction_blocks_before_admission_change(self):
        self.writer.query('true',"BEGIN; INSERT INTO fixture VALUES(2); PREPARE TRANSACTION 'fixture_prepared';")
        try:
            with self.assertRaisesRegex(GateDenied,'SCOPE_OR_INITIAL_STATE'):self.install()
            self.assertTrue(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        finally:self.writer.query('true',"ROLLBACK PREPARED 'fixture_prepared';")

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(NativeGate)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():print('OUF_DATABASE_GATE_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualPostgresql':True,'completeFenceAndIncompleteAdmissionDistinguished':True,'crossDatabaseIsolation':True,'globalRoleChanged':False,'targetApplied':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
