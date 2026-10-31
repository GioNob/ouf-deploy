"""Real Docker new ONBOARDING-only executor; synthetic workload/history/CI authorities.

No production image startup, credentials, grants, acquisitions or HUMAN decision.
Actual candidate image byte/import validation is qualified separately.
"""
import copy,hashlib,http.client,importlib.util,json,os,signal,socket,stat,struct,subprocess,time,unittest,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('protocol_fixture',BASE/'tests/test_onboarding_diagnostic_update_protocol.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
class Native(fixture.Protocol):
    def cli(self,*args):return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE,timeout=120).strip()
    def api(self,method,path,body=None):
        class Unix(http.client.HTTPConnection):
            def connect(c):c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.sock.settimeout(20);c.sock.connect('/run/docker.sock')
        c=Unix('ci-engine',timeout=20)
        try:
            c.request(method,'/v1.44'+path,None if body is None else self.core.encoded(body),{'Content-Type':'application/json'});r=c.getresponse();raw=r.read(2097153);self.assertLessEqual(len(raw),2097152);self.assertIn(r.status,(200,201,204));return json.loads(raw)if raw else None
        finally:c.close()
    def setup_native(self):
        self.ids=[];self.net='ouf-onboarding-update-ci-'+uuid.uuid4().hex[:12];self.nid=self.cli('network','create',self.net)
        self.source='e'*40;build=self.root/'build';build.mkdir()
        (build/'server.py').write_text('''import http.server
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200 if self.path=='/actuator/health/readiness' else 404);self.end_headers();self.wfile.write(b'{"status":"UP"}')
 def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
        tags={}
        for role in('old','new'):
            tag='ouf-onboarding-only-ci-'+role+':'+uuid.uuid4().hex[:12]
            (build/'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /server.py\nUSER 10003:10003\nLABEL org.opencontainers.image.revision="'+self.source+'"\nLABEL synthetic.fixture="'+role+'"\nENTRYPOINT ["python","/server.py"]\nCMD ["server"]\n')
            self.cli('build','--quiet','--tag',tag,str(build));tags[role]=tag
        self.original={};mount=self.root/'synthetic-config';mount.write_bytes(b'SYNTHETIC_NOT_A_CREDENTIAL');mount.chmod(0o400)
        for role in('gateway','ingestion','udp','ingestion-read','udp-read','mcp','onboarding'):
            name='ouf-fixture-'+role+'-'+uuid.uuid4().hex[:10]
            req={'Image':tags['old'],'User':'10003:10003','Hostname':name,'Entrypoint':['python','/server.py'],'Cmd':['server'],
                 'Env':['PATH=/usr/local/bin:/usr/bin:/bin'],
                 'HostConfig':{'NetworkMode':self.net,'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Memory':134217728,'MemorySwap':134217728,'Binds':[str(mount)+':/fixture/config:ro']},
                 'NetworkingConfig':{'EndpointsConfig':{self.net:{'NetworkID':self.nid,'Aliases':[name]}}}}
            if role=='onboarding':
                req['HostConfig']['Memory']=req['HostConfig']['MemorySwap']=getattr(self,'memory_bytes',134217728)
                req['NetworkingConfig']['EndpointsConfig'][self.net]['MacAddress']='02:42:ac:44:01:07'
                if getattr(self,'legacy_explicit',True):req['MacAddress']='02:42:ac:44:01:07'
            cid=self.api('POST','/containers/create?name='+name,req)['Id'];self.ids.append(cid);self.api('POST','/containers/'+cid+'/start');self.original[role]=self.api('GET','/containers/'+cid+'/json')
        foreign=copy.deepcopy(req);foreign.pop('MacAddress',None);foreign['Hostname']='synthetic-registry-unchanged';foreign['NetworkingConfig']['EndpointsConfig'][self.net].pop('MacAddress',None)
        registry=self.api('POST','/containers/create?name=ouf-registry-'+uuid.uuid4().hex[:10],foreign)['Id'];self.ids.append(registry);self.api('POST','/containers/'+registry+'/start');self.registry=self.api('GET','/containers/'+registry+'/json')
        self.assertEqual(self.original['onboarding']['Config']['MacAddress'],'02:42:ac:44:01:07','REAL_LEGACY_CONFIG_MAC_REQUIRED')
        self.pg=self.cli('run','--detach','--network',self.net,'--env','POSTGRES_PASSWORD=ci-not-production','postgres:17');self.ids.append(self.pg)
        for _ in range(60):
            ready=subprocess.run(['docker','exec',self.pg,'pg_isready','-U','postgres'],capture_output=True)
            if ready.returncode==0:break
            time.sleep(1)
        self.assertEqual(ready.returncode,0)
        self.original['postgres']=self.api('GET','/containers/'+self.pg+'/json')
        self.psql('CREATE SCHEMA ouf_onboarding;')
        fence=self.parts['state_fence'];migrations=json.loads((BASE/'releases/onboarding-diagnostic-migration-fence-20261027.json').read_bytes())
        for table in fence.TABLES:
            ddl='job_id uuid,asset_id uuid,state text,attempts integer,profile_id uuid'if table=='file_profile_job'else'id integer,readiness_lease_until timestamptz,readiness_phase text'if table=='managed_onboarding_review'else'id integer,payload text'
            self.psql('CREATE TABLE ouf_onboarding.'+table+'('+ddl+');')
        self.psql('CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version text,script text,checksum integer,success boolean,type text);')
        for n,row in enumerate(migrations,1):self.psql("INSERT INTO ouf_onboarding.flyway_schema_history VALUES(%d,'%s','%s',%d,true,'SQL')"%(n,row['version'],row['script'],row['flywayChecksum']))
        self.psql("INSERT INTO ouf_onboarding.file_profile_job VALUES('%s','%s','FAILED',5,NULL);INSERT INTO ouf_onboarding.source VALUES(1,'PRIVATE_CANARY');INSERT INTO ouf_onboarding.managed_onboarding_review VALUES(1,NULL,'ACTIVE');"%(fence.JOB,fence.ASSET))
        info=self.api('GET','/info');self.assertEqual(info['ServerVersion'],'29.8.1');native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[])
        self.assertEqual(native,os.environ['EXPECTED_STORE']=='containerd')
        archive=self.root/'source.tar';self.cli('save','--output',str(archive),tags['new'])
        import tarfile
        with tarfile.open(archive)as tar:
            manifest=json.load(tar.extractfile('manifest.json'))[0];raw=tar.extractfile(manifest['Config']).read();config_id='sha256:'+hashlib.sha256(raw).hexdigest()
        custody=self.parts['image_custody'];folder=self.root/'prepared';folder.mkdir(mode=0o700)
        with archive.open('rb')as stream:
            checksum,_=custody.hashed(stream,custody.LIMIT);audit=custody.archive(stream,checksum,config_id,self.source)
            path=folder/'native.tar';fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o400)
            with os.fdopen(fd,'w+b')as output:
                os.fchmod(output.fileno(),0o400);derived=custody.tagless_archive(stream,output,audit,containerd=native);output.flush();os.fsync(output.fileno());metadata=list(self.p.frame(os.fstat(output.fileno())))
        if native:audit['nativeIdentity']=custody.native_identity(audit)
        self.native_id=custody.runtime_image_id(audit);self.cli('image','rm',tags['new'])
        selected=Path('/run/docker.sock').resolve();s=selected.stat();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
        engine={'socketPath':str(selected),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':peer}
        capture={'schema':'ouf.onboarding-diagnostic-current-inputs.v1','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'onboardingObservation':self.original['onboarding'],'onboardingProcessPin':self.p.process_pin(self.original['onboarding']['State']['Pid']),
                 'engineBinding':engine,'engineInfo':info,'counts':{'syntheticCaptureOnly':True}}
        input_path=self.root/'synthetic-capture.json';self.write(self.root,input_path.name,capture);input_hash=self.core.digest(capture)
        execution_inputs={'schema':'ouf.onboarding-diagnostic-private-execution-inputs.v1','capturedInputsHash':input_hash,'bootId':capture['bootId'],
                          'engineBinding':engine,'engineInfoHash':self.core.digest(info),'currentOnboarding':capture['onboardingObservation'],
                          'currentProcessPin':capture['onboardingProcessPin'],'reviewedSourceCommit':'d'*40,'testedCommit':self.source,
                          'nativeImageId':self.native_id,'imageAudit':audit,'nativeArchive':{'path':str(path),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':metadata},
                          **{k:False for k in('executionEntryQualified','runtimeAuthorityIssued','lifecyclePlanCompiled','currentRuntimeRevalidated','targetUpdateAuthorized','automaticReplayAllowed','budgetReset')}}
        prepared=folder/'execution-inputs.json';self.write(folder,prepared.name,execution_inputs)
        docker=Path('/usr/bin/docker').resolve();profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1',
            'identity':{'database':'postgres','databaseOid':int(self.psql("SELECT oid FROM pg_database WHERE datname='postgres'")),'runtimeRole':'postgres','adminRole':'postgres','postgresPort':5432},
            'engineBinding':{k:v for k,v in engine.items()if k!='peerCredentials'},'postgresRuntimeBinding':self.parts['engine_creation'].Engine.runtime_binding(self.original['postgres']),
            'runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1','dockerExecutable':{'path':str(docker),'sha256':hashlib.sha256(docker.read_bytes()).hexdigest()},
            'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},'unixSocketDirectory':'/var/run/postgresql'}
        frozen={'schema':'ouf.onboarding-v35-frozen-native-plan.v1','boundDatabaseProfile':profile,'replacements':{'onboarding':{'request':self.original['onboarding']['Config'],'readiness':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'}}},'nativeFlywayConfiguration':{'ownerOverlays':[{'binding':{'path':str(mount),'sha256':hashlib.sha256(mount.read_bytes()).hexdigest(),'metadata':list(self.p.frame(mount.lstat()))}}]}}
        identity=self.root/'synthetic-database-identity.json';self.write(self.root,identity.name,frozen)
        self.case={'executionInputsHash':self.core.digest(execution_inputs),'inputsHash':input_hash,'nativeImageId':self.native_id,'sourceCommit':'d'*40,'testedCommit':self.source,
                   'nativeArchiveHash':derived['derivedArchiveSha256'],'executionInputsPath':str(prepared),'inputsPath':str(input_path),
                   'databaseIdentityPath':str(identity),'databaseIdentityHash':self.core.digest(frozen),'ownerOverlayPath':str(mount)}
        old=self.root/'original-unissued-preflight';old.mkdir(mode=0o700)
        self.write(old,'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':self.case['executionInputsHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        for i in range(1,4):self.write(old,'preflight-attempt-1234-%05d.json'%i,{'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True})
        read_root=self.root/'reconciled-read';read_root.mkdir(mode=0o700)
        retained=json.loads((BASE/'tests/fixtures/onboarding-peer-reconciled-result.json').read_bytes())
        hashes={'retainedEngineBindingHash':self.core.digest(profile['engineBinding']),'capturedEngineBindingHash':self.core.digest(engine),'peerCredentialsHash':self.core.digest(engine['peerCredentials'])}
        retained.update(contextPath=str(read_root),**{k:hashes[k]for k in('retainedEngineBindingHash','capturedEngineBindingHash')})
        retained['engineBindingDifferences'][0]['captured']['sha256']=hashes['peerCredentialsHash'];self.write(read_root,'result.json',retained)
        first=old/'retained-peer-credentials-continuation-v1';first.mkdir(mode=0o700)
        self.write(first,'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':self.case['executionInputsHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        for serial,attempt in enumerate(range(4,12),1):self.write(first,'preflight-attempt-2345-%05d.json'%serial,{'kind':'ownerConfigurationReads','attempt':attempt,'attemptNotCompletion':True})
        prior_code=self.root/'prior-peer-code';prior_code.mkdir(mode=0o700);mapping={}
        for name in fixture.bundle.FILES:
            raw=('CI_ONLY_PRIOR_SOURCE_NOT_EXECUTED:'+name).encode();self.write(prior_code,name,raw);mapping[name]=self.core.sha(raw)
        self.write(prior_code,'sources.json',mapping)
        stop={'applicationE2EProven':False,'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,'complete':False,'contextPath':None,'reasonCode':'EXACT_CURRENT_ROOT_ENGINE_PEER_CREDENTIALS_REQUIRED','releaseAcceptance':False,'runtimeEffectsMayBePartial':True,'schema':'ouf.onboarding-diagnostic-update-result.v1','status':'STOP_RECONCILE'}
        self.write(prior_code,'operator.log',stop);(prior_code/'operator.log').chmod(0o600)
        self.case.update(executionRoot=str(first/'pid1-peer-continuation-v1'),priorStop={'root':str(old),'resultPath':str(read_root/'result.json'),'resultHash':self.core.digest(retained),'readerCounts':retained['counts'],'transportHashes':hashes},priorPeerStop={'root':str(first),'codeRoot':str(prior_code),'manifestHash':self.core.digest(mapping)})
        self.assertNotIn('peerCredentials',profile['engineBinding']);self.assertIn('peerCredentials',engine)
        self.public={'trustPolicy':self.verification['trustPolicy'],'context':self.context,'profile':self.profile}
    def psql(self,sql):return self.cli('exec',self.pg,'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres','-c',sql)
    def context_instance(self):return self.parts['context'].Context(self.parts,self.auth,self.sign,self.journal,self.closure,case=self.case,public_authority=lambda p:copy.deepcopy(self.public),runtime=self.runtime)
    def decision(self,review):return {'schema':'ouf.synthetic-ci-decision.v1','reviewHash':self.core.digest(review),'decision':self.core.DECISION,'approvedAt':int(time.time())}
    def cleanup_native(self):
        # Disposable CI fixture cleanup only. No production recovery/rollback.
        for cid in getattr(self,'ids',[]):subprocess.run(['docker','rm','-f',cid],capture_output=True)
        if hasattr(self,'case'):
            journal=Path(self.case['executionRoot'])/'recovery.json'
            if journal.exists():
                for row in json.loads(journal.read_text()).get('candidates',{}).values():subprocess.run(['docker','rm','-f',row['id']],capture_output=True)
        if hasattr(self,'net'):subprocess.run(['docker','network','rm',self.net],capture_output=True)
    def test_full_new_signed_executor_legacy_frame_and_attested_commit(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx);result=self.entry.execute_approved(ctx,review,self.decision(review))
            self.assertTrue(result['complete']);self.assertEqual(result['sqlSessionsByRepair'],4);row=ctx.execution.journal.read();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),14)
            self.assertEqual(review['retainedUnissuedPreflight']['retainedPreflightCounts']['ownerConfigurationReads'],11)
            self.assertEqual(review['preflightCounts']['ownerConfigurationReads'],11+37+4+2)
            self.assertFalse(review['retainedTransportCompatibility']['historicalMetadataRewritten'])
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role=='onboarding':self.assertFalse(after['State']['Running']);self.assertEqual(after['NetworkSettings']['Networks'],{});self.assertEqual(before['State']['StartedAt'],after['State']['StartedAt'])
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            candidate=self.api('GET','/containers/'+row['candidates']['onboarding']['id']+'/json');self.assertEqual(candidate['NetworkSettings']['Networks'][self.net]['MacAddress'],'02:42:ac:44:01:07');self.assertEqual(candidate['NetworkSettings']['Networks'][self.net]['IPAddress'],self.original['onboarding']['NetworkSettings']['Networks'][self.net]['IPAddress'])
            self.assertEqual(candidate['HostConfig']['Memory'],self.original['onboarding']['HostConfig']['Memory']);self.assertIs(candidate['HostConfig']['AutoRemove'],False)
            self.assertEqual(self.p.stable_binding(self.registry),self.p.stable_binding(self.api('GET','/containers/'+self.registry['Id']+'/json')))
            self.assertTrue((ctx.root/'candidate-result.json').is_file());self.assertTrue((ctx.root/'result.json').is_file())
            print(json.dumps({'schema':'ouf.onboarding-update-synthetic-native-executor-ci.v1','complete':True,'backend':os.environ['EXPECTED_STORE'],'retainedMemoryBytes':candidate['HostConfig']['Memory'],'retainedUnissuedMetadataReads':11,'preReviewMetadataReads':review['preflightCounts']['ownerConfigurationReads'],'sameMetadataMaximum':self.core.LIMITS['ownerConfigurationReads'],'creationProfile':'EXPLICIT_LEGACY_CONFIG'if getattr(self,'legacy_explicit',True)else'ENDPOINT_ONLY_COMPAT_CONFIG','realDualRoleAuthorityAndAttestation':True,'oldLegacyMacInitiallyPresent':True,'fullSignedLifecycle':True,'sixOtherContainersUnchanged':True,'outsideScopeRegistryUnchanged':True,'endpointMacPreserved':True,'endpointIpPreserved':True,'oldRetainedStopped':True,'commitAfterThirdSignature':True,'applicationWorkloadSynthetic':True,'productionRuntimeAccess':False,'applicationE2EProven':False}),flush=True)
        finally:self.cleanup_native()
    def test_full_endpoint_legacy_compatibility_profile(self):
        self.legacy_explicit=False;self.test_full_new_signed_executor_legacy_frame_and_attested_commit()
    def test_zero_memory_full_explicit_legacy(self):
        self.memory_bytes=0;self.test_full_new_signed_executor_legacy_frame_and_attested_commit()
    def test_zero_memory_full_endpoint_legacy(self):
        self.memory_bytes=0;self.legacy_explicit=False;self.test_full_new_signed_executor_legacy_frame_and_attested_commit()
    def test_pending_profile_blocks_before_any_runtime_write(self):
        try:
            self.setup_native();self.psql("UPDATE ouf_onboarding.file_profile_job SET state='READY'")
            ctx=self.context_instance();review=self.entry.review(ctx)
            with self.assertRaisesRegex(RuntimeError,'QUIESCENT'):self.entry.execute_approved(ctx,review,self.decision(review))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['engineWrites'],0);self.assertEqual(row['counts']['sqlSessions'],1)
            self.assertEqual(row['effects'][0]['state'],'CLAIMED');self.assertTrue(self.api('GET','/containers/'+self.original['onboarding']['Id']+'/json')['State']['Running'])
            self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
        finally:self.cleanup_native()
    def test_source_drift_stops_before_new_owner_start_without_reset(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx);cls=self.parts['ports'].NativePorts;original=cls.execute
            def drift(ports,stage):
                if stage=='VERIFY_PRESTART_STATE':self.psql("UPDATE ouf_onboarding.source SET payload='EXTERNAL_CHANGE_RETAINED'")
                return original(ports,stage)
            cls.execute=drift
            with self.assertRaisesRegex(RuntimeError,'STATE_OR_COUNTER_CHANGED'):self.entry.execute_approved(ctx,review,self.decision(review))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['sqlSessions'],3);self.assertEqual(row['effects'][-1]['stage'],'VERIFY_PRESTART_STATE');self.assertEqual(row['effects'][-1]['state'],'CLAIMED')
            self.assertNotIn('START_ONBOARDING',[r['stage']for r in row['effects']]);self.assertEqual(row['quarantine']['state'],'APPLIED')
            self.assertEqual(self.psql('SELECT payload FROM ouf_onboarding.source'),'EXTERNAL_CHANGE_RETAINED');self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
        finally:self.cleanup_native()
    def test_actual_lost_controller_watchdog_stops_only_its_new_onboarding(self):
        self.legacy_explicit=False;self.memory_bytes=0
        try:
            self.setup_native();r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);ctx=self.context_instance();review=self.entry.review(ctx);ports_class=self.parts['ports'].NativePorts;original=ports_class.execute
                    def fault(ports,stage):
                        proof=original(ports,stage)
                        if stage=='START_ONBOARDING':os.write(w,b'STARTED');os._exit(73)
                        return proof
                    ports_class.execute=fault;self.entry.execute_approved(ctx,review,self.decision(review));os._exit(74)
                except BaseException:
                    import traceback
                    traceback.print_exc();os._exit(75)
            os.close(w)
            import select
            self.assertTrue(select.select([r],[],[],180)[0]);self.assertEqual(os.read(r,32),b'STARTED');os.close(r);_,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
            journal_path=Path(self.case['executionRoot'])/'recovery.json';deadline=time.monotonic()+30
            while True:
                try:row=self.parts['quarantine'].snapshot(self.journal.Journal(journal_path.parent))
                except BlockingIOError:
                    self.assertLess(time.monotonic(),deadline);time.sleep(.02);continue
                if (row.get('quarantine')or{}).get('state')=='APPLIED':break
                self.assertLess(time.monotonic(),deadline);time.sleep(.2)
            candidate=self.api('GET','/containers/'+row['candidates']['onboarding']['id']+'/json');self.assertFalse(candidate['State']['Running']);self.assertEqual(candidate['HostConfig']['RestartPolicy']['Name'],'no')
            self.assertEqual(row['counts']['quarantineStops'],1);self.assertEqual(row['state'],'STOP_RECONCILE');self.assertEqual(row['effects'][-1]['state'],'CLAIMED')
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role=='onboarding':self.assertFalse(after['State']['Running'])
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            self.assertEqual(self.p.stable_binding(self.registry),self.p.stable_binding(self.api('GET','/containers/'+self.registry['Id']+'/json')))
            print(json.dumps({'schema':'ouf.onboarding-update-lost-controller-ci.v1','complete':True,'backend':os.environ['EXPECTED_STORE'],'actualControllerExitAfterStartClaim':True,'watchdogStoppedOnlyOwnOnboarding':True,'oldNotRestarted':True,'sixOtherContainersUnchanged':True,'outsideScopeRegistryUnchanged':True,'claimedStageRetained':True,'syntheticAuthoritiesAndWorkload':True,'productionRuntimeAccess':False}),flush=True)
        finally:self.cleanup_native()
if __name__=='__main__':
    suite=unittest.TestSuite([Native(name)for name in('test_full_new_signed_executor_legacy_frame_and_attested_commit','test_full_endpoint_legacy_compatibility_profile','test_zero_memory_full_explicit_legacy','test_zero_memory_full_endpoint_legacy','test_pending_profile_blocks_before_any_runtime_write','test_source_drift_stops_before_new_owner_start_without_reset','test_actual_lost_controller_watchdog_stops_only_its_new_onboarding')]);result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if result.wasSuccessful()else 1)
