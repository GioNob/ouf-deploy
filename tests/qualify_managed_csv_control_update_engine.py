"""Real two-owner executor in isolated Docker29.8.1/PG17; synthetic CI authorities/workloads only."""
import copy,hashlib,http.client,importlib.util,json,os,signal,socket,stat,struct,subprocess,time,unittest,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=load('control_protocol_fixture',BASE/'tests/test_managed_csv_control_update_protocol.py')
retained=load('retained_native_fixture',BASE/'tests/qualify_onboarding_profile_recovery_update_engine.py')
planner=load('control_native_planner',BASE/'tools/managed_csv_recovery/image_plan.py')
class Native(fixture.Protocol):
    cli=retained.Native.cli
    api=retained.Native.api
    psql=retained.Native.psql
    apply_fixture_migration=retained.Native.apply_fixture_migration
    def cleanup_native(self):
        retained.Native.cleanup_native(self)
        # Identical synthetic builds across cases retain native manifests after
        # removing containers/tags. Remove ONLY these disposable fixture images
        # so each following case exercises fresh positive import dispatch.
        for image in set(getattr(self,'case',{}).get('nativeImageIds',{}).values()):
            subprocess.run(['docker','image','rm','--force',image],capture_output=True,timeout=30)
    context_instance=retained.Native.context_instance
    decision=retained.Native.decision
    def setup_native(self):
        self.ids=[];self.net='ouf-onboarding-update-ci-'+uuid.uuid4().hex[:12];self.nid=self.cli('network','create',self.net)
        self.source='e'*40;build=self.root/'build';build.mkdir()
        (build/'server.py').write_text('''import http.server
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(204 if self.path=='/health/ready' else 200 if self.path=='/actuator/health/readiness' else 404);self.end_headers();self.wfile.write(b'{"status":"UP"}')
 def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
        tags={}
        for role in('old','new'):
            tag='ouf-onboarding-only-ci-'+role+':'+uuid.uuid4().hex[:12]
            (build/'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /server.py\nUSER 10003:10003\nLABEL org.opencontainers.image.revision="'+self.source+'"\nLABEL synthetic.fixture="'+role+'"\nENTRYPOINT ["python","/server.py"]\nCMD ["server"]\n')
            self.cli('build','--quiet','--tag',tag,str(build));tags[role]=tag
        self.cli_env=json.loads(self.cli('image','inspect',tags['old']))[0]['Config']['Env']
        self.original={};mount=self.root/'synthetic-config';mount.write_bytes(b'SYNTHETIC_NOT_A_CREDENTIAL');mount.chmod(0o400)
        for role in('gateway','ingestion','udp','ingestion-read','udp-read','mcp','onboarding','extra0','extra1','extra2','extra3'):
            name='ouf-fixture-'+role+'-'+uuid.uuid4().hex[:10]
            req={'Image':tags['old'],'User':'10003:10003','Hostname':name,'Entrypoint':['python','/server.py'],'Cmd':['server'],
                 'Env':self.cli_env,
                 'HostConfig':{'NetworkMode':self.net,'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Memory':134217728,'MemorySwap':134217728,'Binds':[str(mount)+':/fixture/config:ro']},
                 'NetworkingConfig':{'EndpointsConfig':{self.net:{'NetworkID':self.nid,'Aliases':[name]}}}}
            if role=='mcp':req['Env']=[*req['Env'],'MCP_OIDC_TOKEN_ENDPOINT=https://ci.invalid/token','MCP_OIDC_CLIENT_ID=ci-only','MCP_OIDC_CLIENT_SECRET_FILE=/fixture/config']
            if role=='onboarding':
                req['HostConfig']['Memory']=req['HostConfig']['MemorySwap']=getattr(self,'memory_bytes',134217728)
                req['NetworkingConfig']['EndpointsConfig'][self.net]['MacAddress']='02:42:ac:44:01:07'
                if getattr(self,'legacy_explicit',True):req['MacAddress']='02:42:ac:44:01:07'
            cid=self.api('POST','/containers/create?name='+name,req)['Id'];self.ids.append(cid);self.api('POST','/containers/'+cid+'/start');self.original[role]=self.api('GET','/containers/'+cid+'/json')
        foreign=copy.deepcopy(req);foreign.pop('MacAddress',None);foreign['Hostname']='synthetic-registry-unchanged';foreign['NetworkingConfig']['EndpointsConfig'][self.net].pop('MacAddress',None)
        registry=self.api('POST','/containers/create?name=ouf-registry-'+uuid.uuid4().hex[:10],foreign)['Id'];self.ids.append(registry);self.api('POST','/containers/'+registry+'/start');self.registry=self.api('GET','/containers/'+registry+'/json')
        self.assertEqual(self.original['onboarding']['Config']['MacAddress'],'02:42:ac:44:01:07','REAL_LEGACY_CONFIG_MAC_REQUIRED')
        self.pg=self.cli('run','--detach','--network',self.net,'--env','POSTGRES_PASSWORD=ci-not-production','postgres:17');self.ids.append(self.pg)
        ready=None
        for _ in range(60):
            logs=subprocess.run(['docker','logs',self.pg],capture_output=True,timeout=5)
            # pg_isready alone also succeeds against the temporary initdb server.
            # Wait for the entrypoint to finish and stop that server before admitting the final postmaster.
            initialized=b'PostgreSQL init process complete; ready for start up.'in(logs.stdout+logs.stderr)
            if initialized:
                ready=subprocess.run(['docker','exec',self.pg,'pg_isready','-U','postgres'],capture_output=True,timeout=5)
                if ready.returncode==0:break
            time.sleep(1)
        self.assertIsNotNone(ready,'POSTGRES_FIXTURE_INITIALIZATION_NOT_COMPLETE');self.assertEqual(ready.returncode,0)
        self.original['postgres']=self.api('GET','/containers/'+self.pg+'/json')
        self.psql('CREATE SCHEMA ouf_onboarding;')
        fence=self.parts['state_fence'];migrations=json.loads((BASE/'releases/onboarding-profile-recovery-migration-fence-20261027.json').read_bytes())
        for table in fence.TABLES:
            ddl="job_id uuid PRIMARY KEY,asset_id uuid,state text,attempts integer,profile_id uuid,idempotency_key text DEFAULT 'ci-retained',created_at timestamptz DEFAULT now()"if table=='file_profile_job'else'id integer,readiness_lease_until timestamptz,readiness_phase text'if table=='managed_onboarding_review'else'asset_id uuid PRIMARY KEY'if table=='managed_file_asset'else'quarantine_id uuid PRIMARY KEY'if table=='managed_file_quarantine'else'id integer,payload text'
            self.psql('CREATE TABLE ouf_onboarding.'+table+'('+ddl+');')
        self.psql('CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version text,script text,checksum integer,success boolean,type text);')
        for n,row in enumerate(migrations[:35],1):self.psql("INSERT INTO ouf_onboarding.flyway_schema_history VALUES(%d,'%s','%s',%d,true,'SQL')"%(n,row['version'],row['script'],row['flywayChecksum']))
        self.psql("INSERT INTO ouf_onboarding.file_profile_job(job_id,asset_id,state,attempts,profile_id) VALUES('%s','%s','FAILED',5,NULL);INSERT INTO ouf_onboarding.source VALUES(1,'PRIVATE_CANARY');INSERT INTO ouf_onboarding.managed_onboarding_review VALUES(1,NULL,'ACTIVE');"%(fence.JOB,fence.ASSET))
        self.original['registry']=self.registry
        self.apply_fixture_migration() # V36 already installed BEFORE the new controller. CI fixture only.
        info=self.api('GET','/info');self.assertEqual(info['ServerVersion'],'29.8.1');native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[])
        self.assertEqual(native,os.environ['EXPECTED_STORE']=='containerd')
        # A second immutable image identity; both synthetic HTTP contracts are explicit in server.py.
        mcp_tag='ouf-mcp-control-ci-new:'+uuid.uuid4().hex[:12]
        self.cli('build','--quiet','--label','org.opencontainers.image.ci.owner=mcp','--tag',mcp_tag,str(build));tags['mcp-new']=mcp_tag
        custody=self.parts['image_custody'];folder=self.root/'prepared';folder.mkdir(mode=0o700)
        audits={};archives={}
        import tarfile
        for role,tag in [('onboarding',tags['new']),('mcp',mcp_tag)]:
            archive=self.root/(role+'-source.tar');self.cli('save','--output',str(archive),tag)
            with tarfile.open(archive)as tar:
                manifest=json.load(tar.extractfile('manifest.json'))[0];raw=tar.extractfile(manifest['Config']).read();config_id='sha256:'+hashlib.sha256(raw).hexdigest()
            with archive.open('rb')as stream:
                checksum,_=custody.hashed(stream,custody.LIMIT);audit=custody.archive(stream,checksum,config_id,self.source)
                path=folder/(role+'-native.tar');fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o400)
                with os.fdopen(fd,'w+b')as output:
                    os.fchmod(output.fileno(),0o400);derived=custody.tagless_archive(stream,output,audit,containerd=True);output.flush();os.fsync(output.fileno());metadata=list(self.p.frame(os.fstat(output.fileno())))
            audit['nativeIdentity']=custody.native_identity(audit);audits[role]=audit
            archives[role]={'path':str(path),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':metadata}
            self.cli('image','rm',tag)
        selected=Path('/run/docker.sock').resolve();s=selected.stat();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
        engine={'socketPath':str(selected),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':peer}
        def root_pin(pid):
            raw=Path('/proc/'+str(pid)+'/stat').read_bytes();ns={}
            for name in('net','mnt'):
                row=Path('/proc/'+str(pid)+'/ns/'+name).stat();ns[name]=[row.st_dev,row.st_ino]
            return {'pid':pid,'startTicks':int(raw.rsplit(b') ',1)[1].split()[19]),'namespaces':ns}
        cohort={'onboarding'if role=='onboarding'else'peer-'+actual['Id'][:16]:actual for role,actual in self.original.items()}
        self.assertEqual(len(cohort),13)
        capture={'schema':'ouf.managed-csv-recovery-current-inputs.v1','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'engineBinding':engine,'engineInfo':info,'currentObservations':cohort,
                 'currentProcessPins':{key:self.p.process_pin(actual['State']['Pid'])for key,actual in cohort.items()},
                 'currentRootProcessPins':{'pid1':root_pin(1),'engine':root_pin(peer[0])},'targets':['onboarding','mcp'],
                 'resolvedTargetRoles':{'onboarding':'onboarding','mcp':'peer-'+self.original['mcp']['Id'][:16]},
                 'counts':{'privateMetadataReads':5,'bytes':1,'engineGets':27},
                 'captureAccounting':{'cumulativeCounts':{'privateMetadataReads':8,'bytes':2,'engineGets':27}},
                 'currentJobOrBudgetStateObserved':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
        capture_result={'complete':True,'inputsHash':self.core.digest(capture),'contextPath':str(self.root/'capture'),'runtimeAuthorityIssued':False,
                        'counts':capture['counts'],'captureAccounting':capture['captureAccounting'],'targetRoles':['onboarding','mcp']}
        docker=Path('/usr/bin/docker').resolve();profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1',
            'identity':{'database':'postgres','databaseOid':int(self.psql("SELECT oid FROM pg_database WHERE datname='postgres'")),'runtimeRole':'postgres','adminRole':'postgres','postgresPort':5432,'schema':'ouf_onboarding'},
            'engineBinding':{k:v for k,v in engine.items()if k!='peerCredentials'},'postgresRuntimeBinding':self.parts['engine_creation'].Engine.runtime_binding(self.original['postgres']),
            'runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1','dockerExecutable':{'path':str(docker),'sha256':hashlib.sha256(docker.read_bytes()).hexdigest()},
            'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},'unixSocketDirectory':'/var/run/postgresql'}
        application=json.loads((BASE/'releases/managed-profile-control-onboarding-image-custody-20261027.json').read_bytes())['application']
        application.update(jarBytes=1,jarSha256=hashlib.sha256(b'x').hexdigest())
        owner_binding={'path':str(mount),'sha256':hashlib.sha256(mount.read_bytes()).hexdigest(),'metadata':list(self.p.frame(mount.lstat()))}
        proposal={'engineBinding':engine,'boundDatabaseProfile':profile,
                  'onboardingReplacement':{'request':self.p.config_copy(self.original['onboarding']),'readiness':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'}},
                  'nativeFlywayConfiguration':{'ownerOverlays':[{'binding':owner_binding}]},'candidateApplicationFacts':application}
        retained_review={'schema':'ouf.onboarding-profile-recovery-update-review.v1','bootId':capture['bootId'],'nativePlan':{'proposal':proposal}}
        case={'captureResult':capture_result,'captureHash':self.core.digest(capture),'captureRoot':str(self.root/'capture'),'retainedReviewHash':self.core.digest(retained_review)}
        receipts={role:{'imageAudit':audit,'nativeImageId':custody.runtime_image_id(audit),'application':application}for role,audit in audits.items()}
        plan=planner.compile_plan(capture,capture_result,retained_review,receipts,archives,self.p,self.parts['retained_mac'],case)
        native={'schema':'ouf.managed-csv-control-private-execution-inputs.v1','capturedInputsHash':case['captureHash'],'currentCapture':capture,
                'conditionalNativePlanHash':self.core.digest(plan),'nativeArchives':archives,'imageAudits':audits,
                **{key:False for key in('executionEntryQualified','runtimeAuthorityIssued','targetUpdateAuthorized','currentRuntimeRevalidated','automaticReplayAllowed','budgetReset')}}
        counts={'privateMetadataReads':3,'privateMetadataBytes':1,'ciZipReads':2,'nativeArchivesPrepared':2,'engineGets':0,'containerWrites':0,'imageImports':0}
        result={'schema':'ouf.managed-csv-control-image-plan-result.v1','status':'MANAGED_CSV_CONTROL_IMAGES_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED',
                'complete':True,'executionInputsHash':self.core.digest(native),'conditionalNativePlanHash':self.core.digest(plan),'capturedInputsHash':case['captureHash'],
                'counts':counts,'newDatabaseMigrations':0,'runtimeAuthorityIssued':False}
        for name,value in [('execution-inputs.json',native),('execution-plan.json',plan),('result.json',result)]:self.write(folder,name,value)
        self.case={'executionInputsHash':self.core.digest(native),'conditionalPlanHash':self.core.digest(plan),'inputsHash':case['captureHash'],
                   'preparedRoot':str(folder),'executionRoot':str(self.root/'control-update-execution'),'ownerOverlayPath':str(mount),'preparationCounts':counts,
                   'sources':{role:self.source for role in audits},'testedSources':{role:self.source for role in audits},
                   'nativeImageIds':{role:custody.runtime_image_id(audit)for role,audit in audits.items()},'archives':{role:value['sha256']for role,value in archives.items()},
                   'transportHashes':{'retainedEngineBindingHash':self.core.digest(profile['engineBinding']),'capturedEngineBindingHash':self.core.digest(engine),'peerCredentialsHash':self.core.digest(peer)}}
        self.public={'trustPolicy':self.verification['trustPolicy'],'context':self.context,'profile':self.profile}

    def test_full_two_owner_native_lifecycle_and_exact_v36_state(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx);result=self.entry.execute_approved(ctx,review,self.decision(review))
            self.assertTrue(result['complete']);self.assertEqual(result['sqlSessionsByRepair'],8);self.assertEqual(result['databaseMigrationsByRepair'],0)
            self.assertTrue(result['backup']['payloadParsed']);row=ctx.execution.journal.read();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),26)
            self.assertEqual(row['counts']['imageLoadAttempts'],2);self.assertEqual(row['counts']['quarantineStops'],0)
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role in self.core.ROLES:
                    self.assertFalse(after['State']['Running']);self.assertEqual(after['NetworkSettings']['Networks'],{});self.assertEqual(before['State']['StartedAt'],after['State']['StartedAt'])
                    candidate=self.api('GET','/containers/'+row['candidates'][role]['id']+'/json');old_endpoint=before['NetworkSettings']['Networks'][self.net];new_endpoint=candidate['NetworkSettings']['Networks'][self.net]
                    for key in('MacAddress','IPAddress'):self.assertEqual(old_endpoint[key],new_endpoint[key])
                    self.assertEqual(candidate['HostConfig']['Memory'],before['HostConfig']['Memory']);self.assertIs(candidate['HostConfig']['AutoRemove'],False)
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
            self.assertEqual(self.psql('SELECT count(*) FROM ouf_onboarding.managed_profile_budget_session'),'0')
            with self.assertRaisesRegex(self.core.Stop,'CONSUMED_NO_REPLAY'):self.context_instance()
            print(json.dumps({'status':'CONTROL_TWO_OWNER_NATIVE_PASS','realDocker':'29.8.1','cohort':13,'unchangedPeers':11,'realReadonlySqlSessions':8,'realQuiescedBackupParsed':True,'alreadyInstalledSchema':36,'newMigrations':0,'finiteDualSignaturesAndThirdAttestation':True,'memoryBytes':getattr(self,'memory_bytes',134217728),'applicationWorkloadsSynthetic':True,'applicationE2EProven':False}),flush=True)
        finally:self.cleanup_native()

    def test_zero_memory_retained(self):
        self.memory_bytes=0;self.test_full_two_owner_native_lifecycle_and_exact_v36_state()

    def test_pending_profile_stops_before_runtime_writes(self):
        try:
            self.setup_native();self.psql("UPDATE ouf_onboarding.file_profile_job SET state='READY'");ctx=self.context_instance();review=self.entry.review(ctx)
            with self.assertRaisesRegex(RuntimeError,'QUIESCENT'):self.entry.execute_approved(ctx,review,self.decision(review))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['engineWrites'],0);self.assertEqual(row['counts']['sqlSessions'],1)
            for role in self.core.ROLES:self.assertTrue(self.api('GET','/containers/'+self.original[role]['Id']+'/json')['State']['Running'])
        finally:self.cleanup_native()

    def test_external_change_before_start_is_retained_and_not_reset(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx);cls=self.parts['ports'].NativePorts;original=cls.execute
            def drift(ports,stage):
                if stage=='VERIFY_PRESTART_STATE':self.psql("UPDATE ouf_onboarding.source SET payload='EXTERNAL_CHANGE_RETAINED'")
                return original(ports,stage)
            cls.execute=drift
            with self.assertRaisesRegex(RuntimeError,'STATE_HISTORY_COUNTERS'):self.entry.execute_approved(ctx,review,self.decision(review))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['sqlSessions'],5);self.assertEqual(row['effects'][-1]['stage'],'VERIFY_PRESTART_STATE')
            self.assertNotIn('START_ONBOARDING_OWNER',[item['stage']for item in row['effects']]);self.assertEqual(self.psql('SELECT payload FROM ouf_onboarding.source'),'EXTERNAL_CHANGE_RETAINED')
            self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
            self.assertTrue(self.api('GET','/containers/'+self.original['mcp']['Id']+'/json')['State']['Running'])
        finally:self.cleanup_native()

    def test_actual_lost_controller_quarantines_only_its_two_candidates(self):
        try:
            self.setup_native();r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);ctx=self.context_instance();review=self.entry.review(ctx);cls=self.parts['ports'].NativePorts;original=cls.execute
                    def lost(ports,stage):
                        proof=original(ports,stage)
                        if stage=='START_MCP_OWNER':os.write(w,b'BOTH_STARTED');os._exit(73)
                        return proof
                    cls.execute=lost;self.entry.execute_approved(ctx,review,self.decision(review));os._exit(74)
                except BaseException:
                    import traceback
                    traceback.print_exc();os._exit(75)
            os.close(w)
            import select
            self.assertTrue(select.select([r],[],[],240)[0]);self.assertEqual(os.read(r,32),b'BOTH_STARTED');os.close(r);_,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
            journal=self.journal.Journal(Path(self.case['executionRoot']));deadline=time.monotonic()+30
            while True:
                row=self.parts['quarantine'].snapshot(journal)
                if(row.get('quarantine')or{}).get('state')=='APPLIED':break
                self.assertLess(time.monotonic(),deadline);time.sleep(.2)
            self.assertEqual(row['counts']['quarantineStops'],2);self.assertEqual(row['state'],'STOP_RECONCILE');self.assertEqual(row['effects'][-1]['state'],'CLAIMED')
            for role,value in row['candidates'].items():
                actual=self.api('GET','/containers/'+value['id']+'/json');self.assertFalse(actual['State']['Running']);self.assertEqual(actual['HostConfig']['RestartPolicy']['Name'],'no')
            for role,before in self.original.items():
                if role not in self.core.ROLES:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(self.api('GET','/containers/'+before['Id']+'/json')))
            print('CONTROL_LOST_CONTROLLER_TWO_CANDIDATES_ONLY_PASS',flush=True)
        finally:self.cleanup_native()

if __name__=='__main__':
    # The inherited cryptographic suite runs in its own job, rather than duplicating it here.
    names=__import__('sys').argv[1:]or[name for name in sorted(Native.__dict__)if name.startswith('test_')]
    assert names and all(name in Native.__dict__ and name.startswith('test_')for name in names)
    suite=unittest.TestSuite(Native(name)for name in names)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful()else 1)
