"""Real PostgreSQL17/Engine/executable/readonly session and actual Ed25519.

Image admission and token/node owner are explicit inherited synthetic fixtures;
this is database-channel qualification, not a full Registry recovery test.
"""
import copy,json,os,shutil,subprocess,sys,unittest,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_current_admission as fixture
from engine_creation import Engine
from tools.ingestion_readiness_patch_execution import runtime_bindings
from tools.semantic_registry_recovery_execution import core as c

class NativeDatabase(unittest.TestCase):
    setUp=fixture.CurrentAdmission.setUp
    native=fixture.CurrentAdmission.native;write=fixture.CurrentAdmission.write
    binding=fixture.CurrentAdmission.binding;sign=fixture.CurrentAdmission.sign;resign=fixture.CurrentAdmission.resign

    def configure_database(self):
        cid=os.environ['OUF_FIXTURE_POSTGRES'];self.assertRegex(cid,r'^[a-f0-9]{64}$');self.cid=cid
        binary=str(Path(shutil.which('docker')).resolve());self.binary=binary
        path='/var/run/docker.sock';info=os.stat(path,follow_symlinks=False)
        engine=Engine(path,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode&0o777))
        status,actual=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(status,200)
        self.pg=actual;self.pin={'binding':runtime_bindings.observed(actual,runtime_bindings.SORTED),
            'bindingProfile':runtime_bindings.SORTED,'restartCount':actual['RestartCount']}
        self.lifecycle.engine=engine;real_request=engine.request
        # Current image scope is qualified elsewhere; isolate the real PG
        # channel without introducing a second application image/target.
        engine.request=lambda method,path,body=None:((200,{'syntheticImageMetadata':True}) if '/images/' in path
            else real_request(method,path,body))
        suffix=uuid.uuid4().hex[:12];database='ouf_recovery_'+suffix;role='ouf_reader_'+suffix
        self.sql('postgres','CREATE ROLE '+role+' LOGIN NOSUPERUSER NOCREATEROLE;')
        self.addCleanup(lambda:self.sql('postgres','DROP ROLE '+role+';'))
        self.sql('postgres','CREATE DATABASE '+database+';')
        self.addCleanup(lambda:self.sql('postgres','DROP DATABASE '+database+' WITH (FORCE);'))
        self.sql(database,"CREATE SCHEMA ouf_sem; CREATE TABLE ouf_sem.flyway_schema_history("
            "installed_rank int,version text,type text,script text,checksum int,success boolean); "
            "INSERT INTO ouf_sem.flyway_schema_history VALUES(1,'1','SQL','V1__fixture.sql',123,true); "
            'GRANT USAGE ON SCHEMA ouf_sem TO '+role+'; GRANT SELECT ON ouf_sem.flyway_schema_history TO '+role+';')
        oid=int(self.sql(database,'SELECT oid FROM pg_database WHERE datname=current_database();').strip())
        self.readiness.update(databaseContainerId=cid,databaseUser=role,database=database,databaseOid=oid)
        self.program=fixture.file_profile(binary)

    def sql(self,database,sql):
        return subprocess.run([self.binary,'exec','-i',self.cid,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
            '-U','postgres','-d',database],input=sql.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            check=True,timeout=15,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}).stdout

    def test_real_readonly_role_oid_and_flyway_history_are_verified(self):
        before=self.store.read();proof=self.database.snapshot()
        self.assertTrue(proof['transactionReadOnly']);self.assertTrue(proof['databaseIdentityProven'])
        self.assertEqual(proof['flywayHistoryHash'],c.digest(self.history))
        self.assertEqual(proof['databaseMutations'],0);self.assertEqual(self.store.read(),before)
        self.assertEqual(self.budget.read()['counts']['databaseSessions'],1)

    def test_actual_changed_migration_history_is_not_accepted(self):
        self.database.snapshot()
        self.sql(self.readiness['database'],'UPDATE ouf_sem.flyway_schema_history SET checksum=999;')
        with self.assertRaisesRegex(c.RecoveryDenied,'FLYWAY_HISTORY_CHANGED'):self.database.snapshot()
        self.assertEqual(self.budget.read()['counts']['databaseSessions'],2)

if __name__=='__main__':unittest.main()
