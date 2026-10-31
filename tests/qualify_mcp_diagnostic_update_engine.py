"""Real Docker new MCP-only executor; synthetic workload/history/CI authorities.

No production image startup, credentials, grants, acquisitions or HUMAN decision.
Actual candidate image byte/import validation is qualified separately.
"""
import copy,hashlib,http.client,importlib.util,json,os,signal,socket,stat,struct,subprocess,time,unittest,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('protocol_fixture',BASE/'tests/test_mcp_diagnostic_update_protocol.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
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
        self.ids=[];self.net='ouf-mcp-update-ci-'+uuid.uuid4().hex[:12];self.nid=self.cli('network','create',self.net);self.source='e'*40
        build=self.root/'build';build.mkdir();(build/'server.py').write_text('''import http.server
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(204 if self.path=='/health/ready' else 404);self.end_headers()
 def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
        tags={}
        for role in('old','new'):
            tag='ouf-mcp-only-ci-'+role+':'+uuid.uuid4().hex[:12]
            (build/'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /server.py\nUSER 10005:10005\nLABEL org.opencontainers.image.revision="'+self.source+'"\nLABEL synthetic.fixture="'+role+'"\nENTRYPOINT ["python","/server.py"]\nCMD ["server"]\n')
            self.cli('build','--quiet','--tag',tag,str(build));tags[role]=tag
        self.original={};mount=self.root/'synthetic-config';mount.write_bytes(b'SYNTHETIC_NOT_A_CREDENTIAL');mount.chmod(0o400)
        for role in('gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp'):
            name='ouf-fixture-'+role+'-'+uuid.uuid4().hex[:10]
            req={'Image':tags['old'],'User':'10005:10005','Hostname':name,'Entrypoint':['python','/server.py'],'Cmd':['server'],
                 'Env':['PATH=/usr/local/bin:/usr/bin:/bin','MCP_OIDC_TOKEN_ENDPOINT=https://never-contacted.invalid/token','MCP_OIDC_CLIENT_ID=ci-synthetic-mcp','MCP_OIDC_CLIENT_SECRET_FILE=/not-read/secret'],
                 'HostConfig':{'NetworkMode':self.net,'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Memory':134217728,'MemorySwap':134217728,'Binds':[str(mount)+':/fixture/config:ro']},
                 'NetworkingConfig':{'EndpointsConfig':{self.net:{'NetworkID':self.nid,'Aliases':[name]}}}}
            if role=='mcp':
                req['HostConfig']['Memory']=getattr(self,'memory_bytes',134217728)
                req['HostConfig']['MemorySwap']=getattr(self,'memory_bytes',134217728)
                req['NetworkingConfig']['EndpointsConfig'][self.net]['MacAddress']='02:42:ac:44:01:07'
                if getattr(self,'legacy_explicit',True):req['MacAddress']='02:42:ac:44:01:07'
            cid=self.api('POST','/containers/create?name='+name,req)['Id'];self.ids.append(cid);self.api('POST','/containers/'+cid+'/start');self.original[role]=self.api('GET','/containers/'+cid+'/json')
        foreign=copy.deepcopy(req);foreign.pop('MacAddress',None);foreign['Hostname']='synthetic-registry-outside-scope';foreign['NetworkingConfig']['EndpointsConfig'][self.net].pop('MacAddress',None)
        registry=self.api('POST','/containers/create?name=ouf-registry-outside-'+uuid.uuid4().hex[:10],foreign)['Id'];self.ids.append(registry);self.api('POST','/containers/'+registry+'/start');self.registry=self.api('GET','/containers/'+registry+'/json')
        self.assertEqual(self.original['mcp']['Config']['MacAddress'],'02:42:ac:44:01:07','REAL_LEGACY_CONFIG_MAC_REQUIRED')
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
        image={'Id':config_id,'Config':audit['imageConfig']};self.native_id=custody.runtime_image_id(audit)
        self.cli('image','rm',tags['new'])
        inputs={'schema':'ouf.mcp-denial-update-inputs.v1','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'currentObservations':self.original,'currentProcessPins':{r:self.p.process_pin(v['State']['Pid'])for r,v in self.original.items()}}
        input_path=self.root/'synthetic-capture.json';self.write(self.root,input_path.name,inputs);input_hash=self.core.digest(inputs)
        selected=Path('/run/docker.sock').resolve();s=selected.stat();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
        proposal={'schema':'ouf.synthetic-ci-mcp-frozen-plan.v1','capturedInputsHash':input_hash,'bootId':inputs['bootId'],
                  'engineBinding':{'socketPath':str(selected),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':peer},
                  'nativeIdentityProfile':'CONFIG_AND_NATIVE_MANIFEST'if native else'CONFIG_DIGEST',
                  'existingApplications':{r:self.p.stable_binding(v)for r,v in self.original.items()},'mcpReplacement':self.p.mcp_replacement(self.original['mcp'],image,input_hash),
                  'legacyConfigMacDetachPolicy':self.parts['retained_mac'].policy(self.original['mcp']),
                  'retainedInstallationCounts':{'syntheticHistoryOnly':True},'retainedCaptureCounts':{'syntheticHistoryOnly':True}}
        plan={'schema':'ouf.mcp-denial-native-image-plan.v1','proposal':proposal,'frozenPlanHash':self.core.digest(proposal),'nativeImageId':self.native_id,'imageAudit':audit,
              'nativeArchive':{'path':str(path),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':metadata},'executionEntryQualified':False,'runtimeAuthorityIssued':False}
        native_path=folder/'native-plan.json';self.write(folder,native_path.name,plan)
        self.case={'nativePlanHash':self.core.digest(plan),'frozenPlanHash':plan['frozenPlanHash'],'inputsHash':input_hash,'nativeImageId':self.native_id,'sourceCommit':self.source,'nativeArchiveHash':derived['derivedArchiveSha256'],'nativePlanPath':str(native_path),'inputsPath':str(input_path),'executionRoot':str(self.root/'new-execution')}
        if getattr(self,'memory_bytes',134217728)==0:
            self.assertEqual({k:self.original['mcp']['HostConfig'][k]for k in('Memory','AutoRemove','OomKillDisable')},{'Memory':0,'AutoRemove':False,'OomKillDisable':None})
            old=self.root/'prior-stopped';old.mkdir(mode=0o700)
            self.write(old,'preparation-claim.json',{'schema':'ouf.mcp-diagnostic-update-preflight-claim.v1','nativePlanHash':self.case['nativePlanHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
            for i in(1,2):self.write(old,'preflight-attempt-1234-%05d.json'%i,{'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True})
            retained=json.loads((BASE/'tests/fixtures/mcp-zero-memory-reconciliation.json').read_bytes());self.write(self.root,'synthetic-reconciliation.json',retained)
            self.case.update(executionRoot=str(old/'retained-host-policy-continuation-v1'),priorPreflight={'root':str(old),'reconciliationPath':str(self.root/'synthetic-reconciliation.json'),'reconciliationSha256':self.core.digest(retained)})
        self.public={'trustPolicy':self.verification['trustPolicy'],'context':self.context,'profile':self.profile}
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
            self.assertTrue(result['complete']);row=ctx.execution.journal.read();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),11)
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role=='mcp':self.assertFalse(after['State']['Running']);self.assertEqual(after['NetworkSettings']['Networks'],{});self.assertEqual(before['State']['StartedAt'],after['State']['StartedAt'])
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            candidate=self.api('GET','/containers/'+row['candidates']['mcp']['id']+'/json');self.assertEqual(candidate['NetworkSettings']['Networks'][self.net]['MacAddress'],'02:42:ac:44:01:07');self.assertEqual(candidate['NetworkSettings']['Networks'][self.net]['IPAddress'],self.original['mcp']['NetworkSettings']['Networks'][self.net]['IPAddress'])
            self.assertEqual(candidate['HostConfig']['Memory'],self.original['mcp']['HostConfig']['Memory']);self.assertIs(candidate['HostConfig']['AutoRemove'],False)
            if self.case.get('priorPreflight'):
                self.assertEqual(review['nativePlan']['proposal']['retainedPreflightReconciliation']['retainedOriginalCounts']['ownerConfigurationReads'],2)
                self.assertGreaterEqual(review['preflightCounts']['ownerConfigurationReads'],10)
                self.assertEqual(len(list(Path(self.case['priorPreflight']['root']).iterdir())),4)
            self.assertEqual(self.p.stable_binding(self.registry),self.p.stable_binding(self.api('GET','/containers/'+self.registry['Id']+'/json')))
            self.assertTrue((ctx.root/'candidate-result.json').is_file());self.assertTrue((ctx.root/'result.json').is_file())
            print(json.dumps({'schema':'ouf.mcp-update-synthetic-native-executor-ci.v1','complete':True,'backend':os.environ['EXPECTED_STORE'],'retainedMemoryBytes':candidate['HostConfig']['Memory'],'priorPreflightCountsPreserved':bool(self.case.get('priorPreflight')),'creationProfile':'EXPLICIT_LEGACY_CONFIG'if getattr(self,'legacy_explicit',True)else'ENDPOINT_ONLY_COMPAT_CONFIG','realDualRoleAuthorityAndAttestation':True,'oldLegacyMacInitiallyPresent':True,'fullSignedLifecycle':True,'sixOtherContainersUnchanged':True,'outsideScopeRegistryUnchanged':True,'endpointMacPreserved':True,'endpointIpPreserved':True,'oldRetainedStopped':True,'commitAfterThirdSignature':True,'applicationWorkloadSynthetic':True,'productionRuntimeAccess':False,'applicationE2EProven':False}),flush=True)
        finally:self.cleanup_native()
    def test_full_endpoint_legacy_compatibility_profile(self):
        self.legacy_explicit=False;self.test_full_new_signed_executor_legacy_frame_and_attested_commit()
    def test_zero_memory_full_explicit_legacy(self):
        self.memory_bytes=0;self.test_full_new_signed_executor_legacy_frame_and_attested_commit()
    def test_zero_memory_full_endpoint_legacy(self):
        self.memory_bytes=0;self.legacy_explicit=False;self.test_full_new_signed_executor_legacy_frame_and_attested_commit()
    def test_actual_lost_controller_watchdog_stops_only_its_new_mcp(self):
        self.legacy_explicit=False;self.memory_bytes=0
        try:
            self.setup_native();r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);ctx=self.context_instance();review=self.entry.review(ctx);ports_class=self.parts['ports'].NativePorts;original=ports_class.execute
                    def fault(ports,stage):
                        proof=original(ports,stage)
                        if stage=='START_MCP':os.write(w,b'STARTED');os._exit(73)
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
            candidate=self.api('GET','/containers/'+row['candidates']['mcp']['id']+'/json');self.assertFalse(candidate['State']['Running']);self.assertEqual(candidate['HostConfig']['RestartPolicy']['Name'],'no')
            self.assertEqual(row['counts']['quarantineStops'],1);self.assertEqual(row['state'],'STOP_RECONCILE');self.assertEqual(row['effects'][-1]['state'],'CLAIMED')
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role=='mcp':self.assertFalse(after['State']['Running'])
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            self.assertEqual(self.p.stable_binding(self.registry),self.p.stable_binding(self.api('GET','/containers/'+self.registry['Id']+'/json')))
            print(json.dumps({'schema':'ouf.mcp-update-lost-controller-ci.v1','complete':True,'backend':os.environ['EXPECTED_STORE'],'actualControllerExitAfterStartClaim':True,'watchdogStoppedOnlyOwnMcp':True,'oldNotRestarted':True,'sixOtherContainersUnchanged':True,'outsideScopeRegistryUnchanged':True,'claimedStageRetained':True,'syntheticAuthoritiesAndWorkload':True,'productionRuntimeAccess':False}),flush=True)
        finally:self.cleanup_native()
if __name__=='__main__':
    suite=unittest.TestSuite([Native(name)for name in('test_full_new_signed_executor_legacy_frame_and_attested_commit','test_full_endpoint_legacy_compatibility_profile','test_zero_memory_full_explicit_legacy','test_zero_memory_full_endpoint_legacy','test_actual_lost_controller_watchdog_stops_only_its_new_mcp')]);result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if result.wasSuccessful()else 1)
