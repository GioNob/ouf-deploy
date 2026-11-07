"""Native disposable PostgreSQL/Engine/CLI and real migration artifacts/crypto.

Other ten peers and selected-owner lineage are fixtures; no target or full
cohort admission. Only this suite's captured disposable container is removed.
"""
import copy,gc,hashlib,os,shutil,socket,stat,struct,subprocess,sys,time,unittest,uuid,warnings
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_databases as fixtures
from tools.m2_discovery_installation_profile import current_databases as m
from tools.m2_discovery_installation_profile import current_cohort as cohort
from database_gate import identifier,literal


class NativeDatabases(unittest.TestCase):
    @classmethod
    def command(cls,*args,input=None):
        try:return subprocess.check_output([cls.docker,*args],input=input,stderr=subprocess.PIPE,timeout=90)
        except subprocess.CalledProcessError as error:
            # Only disposable fixture metadata can enter this bounded diagnostic.
            raise AssertionError('DISPOSABLE_DATABASE_FIXTURE_COMMAND_FAILED: '+error.stderr[-2048:].decode(errors='replace')) from None
    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0:raise AssertionError('ROOT_DISPOSABLE_NATIVE_DATABASE_FIXTURE_REQUIRED')
        cls.docker=str(Path(shutil.which('docker')).resolve());cls.cid=None
        def cleanup():
            if cls.cid is not None:cls.command('rm','-f',cls.cid)
        cls.addClassCleanup(cleanup)
        cls.command('pull','postgres:17-alpine')
        name='ouf-current-db-native-'+uuid.uuid4().hex
        cls.cid=cls.command('run','-d','--network','none','--name',name,
            '--label','ouf.fixture=current-database-native-no-target','-e','POSTGRES_HOST_AUTH_METHOD=trust',
            'postgres:17-alpine').decode().strip()
        if not cohort.hashed(cls.cid):raise AssertionError('EXACT_DISPOSABLE_DATABASE_CONTAINER_ID_REQUIRED')
        deadline=time.monotonic()+45
        while True:
            # The init-only temporary server listens on its Unix socket. TCP
            # loopback readiness waits for the final postmaster, using the same
            # original 45-second fixture deadline and no application restart.
            ready=subprocess.run([cls.docker,'exec',cls.cid,'pg_isready','-h','127.0.0.1','-U','postgres'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            if ready.returncode==0:break
            if time.monotonic()>=deadline:raise AssertionError('DISPOSABLE_POSTGRES_READINESS_DEADLINE')
            time.sleep(.1)
        for module in m.MODULES:
            user='fixture_'+module;database=user
            cls.command('exec','-i',cls.cid,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres',
                input=('CREATE ROLE '+identifier(user)+' LOGIN;\nCREATE DATABASE '+identifier(database)+' OWNER '+identifier(user)+';\n').encode())

    def setUp(self):
        h=fixtures.DatabaseAdmission();h.setUp();self.addCleanup(h.doCleanups);self.h=h
        runtime,_,_=h.runtime_fixture();inputs=copy.deepcopy(runtime.inputs)
        sock=str(Path('/var/run/docker.sock').resolve());s=Path(sock).stat()
        engine=m.Engine(sock,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
        code,actual=engine.request('GET','/v1.44/containers/'+self.cid+'/json');self.assertEqual(code,200)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2);client.connect(sock)
            credentials=list(struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        self.assertGreater(credentials[0],1,'DISPOSABLE_ENGINE_PEER_PID: '+str(credentials))
        self.assertEqual(credentials[1:],[0,0],'DISPOSABLE_ENGINE_PEER_IDENTITY: '+str(credentials))
        self.assertIn(stat.S_IMODE(s.st_mode),(0o600,0o660),'DISPOSABLE_ENGINE_SOCKET_MODE: '+str(stat.S_IMODE(s.st_mode)))
        engine_pin=cohort.process_pin(credentials[0]);inputs.update(
            bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            engineBinding={'socketPath':sock,'socketBinding':list(engine.binding),'peerCredentials':credentials,'startTicks':engine_pin['startTicks']},
            rootProcessPins={'pid1':cohort.process_pin(1),'engine':engine_pin})
        inputs['peers']['postgres'].update(runtimeBinding=m.Engine.runtime_binding(actual),processPin=cohort.process_pin(actual['State']['Pid']))
        rows=fixtures.artifacts(h.root)
        for row in rows:
            module=row['module'];schema=identifier(m.SCHEMAS[module]);db=row['database'];user=row['user']
            if module=='mcp':
                table='schema_migration';columns='version integer,checksum text'
                values=','.join('('+str(v['version'])+','+literal(v['checksum'])+')' for v in row['expectedMigrations'])
            else:
                table='flyway_schema_history';columns='installed_rank integer,version text,script text,type text,checksum integer,success boolean'
                values=','.join('('+str(i)+','+literal(v['version'])+','+literal(v['script'])+','+literal(v['type'])+','+str(v['checksum'])+',true)'
                    for i,v in enumerate(row['expectedMigrations'],1))
            sql=('CREATE SCHEMA IF NOT EXISTS '+schema+'; CREATE TABLE IF NOT EXISTS '+schema+'.'+table+' ('+columns+'); '
                'TRUNCATE '+schema+'.'+table+'; INSERT INTO '+schema+'.'+table+' VALUES '+values+';')
            self.command('exec','-i',self.cid,'psql','-X','-v','ON_ERROR_STOP=1','-U',user,'-d',db,input=sql.encode())
            oid=self.command('exec',self.cid,'psql','-X','-A','-t','-U',user,'-d',db,'-c',
                "SELECT oid FROM pg_database WHERE datname=current_database()").decode().strip()
            row['databaseOid']=int(oid)
        data={k:inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        data.update(schema=m.SCHEMA,postgresRuntimeBinding=m.Engine.runtime_binding(actual),
            dockerBinding={'path':self.docker,'sha256':hashlib.sha256(Path(self.docker).read_bytes()).hexdigest()},modules=rows)
        extended=m.bind_database_inputs(inputs,data)
        review=copy.deepcopy(h.review);review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        h.review=cohort.bind_runtime_review(review,extended);parent=h.authority(seconds=300)
        runtime.selected.images.parent=parent;runtime.selected.images.component=h.review['components']['cohortInstallation']
        runtime.selected.images.engine=engine
        runtime.selected.guard=lambda:parent.guard('cohortInstallation',runtime.selected.images.component) # explicit selected-native fixture
        self.runtime=cohort.CurrentCohortRuntime(runtime.selected,extended)
        self.owner=m.CurrentCohortDatabases(self.runtime,data)

    def test_actual_four_databases_match_reviewed_artifacts_in_read_only_transactions(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always',ResourceWarning);proof=self.owner.observe();gc.collect()
        self.assertFalse([w for w in caught if issubclass(w.category,ResourceWarning)])
        self.assertEqual(proof['databaseCount'],4);self.assertEqual(proof['moduleReadSessions'],8)
        self.assertTrue(proof['readOnlyTransactions']);self.assertTrue(proof['reviewedArtifactBytesMatchHistories'])
        for key in ('artifactPublisherProvenanceVerifiedHere','fullCohortProven','runtimeAuthorityIssued','targetApplyAuthorized','migrationDispatched','releaseAcceptance'):
            self.assertIs(proof[key],False)

    def test_actual_postgres_migration_drift_is_denied_without_repair(self):
        row=self.owner.inputs['modules'][0];schema=identifier(m.SCHEMAS[row['module']])
        self.command('exec',self.cid,'psql','-X','-v','ON_ERROR_STOP=1','-U',row['user'],'-d',row['database'],
            '-c','UPDATE '+schema+'.flyway_schema_history SET checksum=checksum+1')
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always',ResourceWarning)
            with self.assertRaisesRegex(ValueError,'PACKAGED_MIGRATIONS_CHANGED'):self.owner.observe()
            gc.collect()
        self.assertFalse([w for w in caught if issubclass(w.category,ResourceWarning)])
        current=int(self.command('exec',self.cid,'psql','-X','-A','-t','-U',row['user'],'-d',row['database'],
            '-c','SELECT checksum FROM '+schema+'.flyway_schema_history').decode().strip())
        self.assertEqual(current,row['expectedMigrations'][0]['checksum']+1)

if __name__=='__main__':unittest.main()
