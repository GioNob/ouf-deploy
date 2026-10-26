"""Actual two-READ replacement; synthetic workloads, history and CI signing keys.

No production acquisition, account, image startup or runtime access. Tests the
same compiler, sealed controller, signatures, journal and watchdog on Docker29.
"""
import copy,hashlib,http.client,importlib.util,json,os,select,socket,stat,struct,subprocess,time,unittest,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('redaction_protocol_fixture',BASE/'tests/test_acquisition_redaction_update_protocol.py')
compiler=module('redaction_native_compiler',BASE/'scripts/prepare-acquisition-redaction-image-plan-20261026.py')
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
        self.ids=[];self.net='ouf-redaction-ci-'+uuid.uuid4().hex[:12];self.nid=self.cli('network','create',self.net)
        build=self.root/'build';build.mkdir();(build/'server.py').write_text('''import http.server
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200 if self.path=='/actuator/health/readiness'else 404);self.end_headers();self.wfile.write(b'{"status":"UP"}')
 def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
        tags={};sources={'old':'a'*40,'ingestion':'e'*40,'udp':'d'*40}
        for role,source in sources.items():
            tag='ouf-redaction-synthetic-'+role+':'+uuid.uuid4().hex[:12]
            (build/'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /server.py\nUSER 10005:10005\nLABEL org.opencontainers.image.revision="'+source+'"\nENTRYPOINT ["python","/server.py"]\nCMD ["server"]\n')
            self.cli('build','--quiet','--tag',tag,str(build));tags[role]=tag
        mount=self.root/'synthetic-config';mount.write_bytes(b'SYNTHETIC_NOT_A_CREDENTIAL');mount.chmod(0o400);self.original={}
        for i,role in enumerate(('gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp','registry')):
            name='ouf-synthetic-'+role+'-'+uuid.uuid4().hex[:10]
            req={'Image':tags['old'],'User':'10005:10005','Hostname':name,'Entrypoint':['python','/server.py'],'Cmd':['server'],
                 'HostConfig':{'NetworkMode':self.net,'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Memory':0 if role=='ingestion-read'else 134217728,'MemorySwap':0 if role=='ingestion-read'else 134217728,
                 'Binds':[str(mount)+':/fixture/config:ro'],'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true']},
                 'NetworkingConfig':{'EndpointsConfig':{self.net:{'NetworkID':self.nid,'Aliases':[name]}}}}
            if role in('ingestion-read','udp-read')and getattr(self,'legacy_explicit',True):
                req['MacAddress']='02:42:ac:45:01:%02x'%(i+1);req['NetworkingConfig']['EndpointsConfig'][self.net]['MacAddress']=req['MacAddress']
            if role in('ingestion-read','udp-read')and getattr(self,'mount_specs',False):
                req['HostConfig'].update(Binds=None,Mounts=[{'Type':'bind','Source':str(mount),'Target':'/fixture/config','ReadOnly':True,'BindOptions':{'Propagation':'rprivate'}}],Tmpfs={'/tmp':'rw,nosuid,nodev,noexec,size=64m'},PidsLimit=128)
            cid=self.api('POST','/containers/create?name='+name,req)['Id'];self.ids.append(cid);self.api('POST','/containers/'+cid+'/start');actual=self.api('GET','/containers/'+cid+'/json')
            if role=='registry':self.registry=actual
            else:self.original[role]=actual
        for role in('ingestion-read','udp-read'):
            config=self.original[role]['Config']
            if getattr(self,'legacy_explicit',True):self.assertTrue(self.p.valid_mac(config.get('MacAddress')),'REAL_INITIAL_LEGACY_CONFIG_MAC_REQUIRED')
            else:self.assertNotIn('MacAddress',config,'REAL_INITIAL_ENDPOINT_ONLY_CONFIG_MAC_ABSENCE_REQUIRED')
        info=self.api('GET','/info');self.assertEqual(info['ServerVersion'],'29.8.1');native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]);self.assertEqual(native,os.environ['EXPECTED_STORE']=='containerd')
        facts={};images={};receipts={};folder=self.root/'prepared';folder.mkdir(mode=0o700)
        for role in self.core.ROLES:
            expanded=self.root/(role+'.tar');self.cli('save','--output',str(expanded),tags[role]);image=self.api('GET','/images/'+tags[role]+'/json');custody=self.parts['image_custody']
            import tarfile
            with tarfile.open(expanded)as tar:
                manifest=json.load(tar.extractfile('manifest.json'))[0];config_id='sha256:'+hashlib.sha256(tar.extractfile(manifest['Config']).read()).hexdigest()
            image['Id']=config_id;images[role]=image;target=folder/role;target.mkdir(mode=0o700)
            with expanded.open('rb')as stream:
                checksum,_=custody.hashed(stream,custody.LIMIT);audit=custody.archive(stream,checksum,config_id,sources[role]);path=target/'native.tar';fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o400)
                with os.fdopen(fd,'w+b')as out:
                    os.fchmod(out.fileno(),0o400);derived=custody.tagless_archive(stream,out,audit,containerd=native);out.flush();os.fsync(out.fileno());metadata=list(self.p.frame(os.fstat(out.fileno())))
            if native:audit['nativeIdentity']=custody.native_identity(audit)
            identity={'configurationImageId':config_id,'nativeImageId':custody.runtime_image_id(audit),'derivedArchiveSha256':derived['derivedArchiveSha256'],'archiveBytes':derived['archiveBytes']}
            facts[role]={'identity':identity,'audit':audit,'archive':{'path':str(path),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':metadata}}
            receipts[role]={'descriptor':{'sourceCommit':sources[role]}};self.cli('image','rm',tags[role])
        selected=Path('/run/docker.sock').resolve();s=selected.stat();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
        inputs={'schema':'ouf.acquisition-redaction-update-inputs.v1','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'currentObservations':self.original,'currentProcessPins':{r:self.p.process_pin(v['State']['Pid'])for r,v in self.original.items()},
                'engineBinding':{'socketPath':str(selected),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':peer},'engineInfo':info,
                'counts':{'bytes':72997,'engineGets':10,'privateMetadataReads':4},'retainedMcpCounts':{'syntheticHistoryOnly':True},'candidateSourceCommits':{r:sources[r]for r in self.core.ROLES}}
        input_path=self.root/'synthetic-capture.json';self.write(self.root,input_path.name,inputs);input_hash=self.core.digest(inputs);compiler.INPUT_HASH=input_hash
        proposal=compiler.compile_plan(inputs,receipts,images,self.p,self.parts['retained_mac'])
        plan={'schema':'ouf.acquisition-redaction-native-image-plan.v1','proposal':proposal,'frozenPlanHash':self.core.digest(proposal),'nativeImages':facts,'executionEntryQualified':False,'runtimeAuthorityIssued':False}
        native_path=folder/'native-plan.json';self.write(folder,native_path.name,plan);native_hash=self.core.digest(plan)
        result={'schema':'ouf.acquisition-redaction-image-plan-prepared.v1','status':'ACQUISITION_REDACTION_IMAGES_AND_PLAN_PREPARED_NOT_AUTHORIZED','complete':True,'nativePlanHash':native_hash,'frozenPlanHash':plan['frozenPlanHash'],'inputsHash':input_hash,'runtimeAuthorityIssued':False,'executionEntryQualified':False,
                'counts':{'privateMetadataReads':2,'ciZipReads':2,'nativeArchivesPrepared':2,'engineGets':0,'containerWrites':0,'imageImports':0},'nativeImages':{r:v['identity']for r,v in facts.items()}}
        self.write(folder,'result.json',result);self.case={'nativePlanHash':native_hash,'frozenPlanHash':plan['frozenPlanHash'],'inputsHash':input_hash,'sources':inputs['candidateSourceCommits'],'archives':{r:v['archive']['sha256']for r,v in facts.items()},'nativePlanPath':str(native_path),'resultPath':str(folder/'result.json'),'inputsPath':str(input_path),'executionRoot':str(self.root/'new-execution')}
        self.public={'trustPolicy':self.verification['trustPolicy'],'context':self.context,'profile':self.profile}
    def context_instance(self):return self.parts['context'].Context(self.parts,self.auth,self.sign,self.journal,self.closure,case=self.case,public_authority=lambda p:copy.deepcopy(self.public),runtime=self.runtime)
    def decision(self,review):return {'schema':'ouf.synthetic-ci-decision.v1','reviewHash':self.core.digest(review),'decision':self.core.DECISION,'approvedAt':int(time.time())}
    def cleanup_native(self):
        for cid in getattr(self,'ids',[]):subprocess.run(['docker','rm','-f',cid],capture_output=True)
        if hasattr(self,'case'):
            path=Path(self.case['executionRoot'])/'recovery.json'
            if path.exists():
                for v in json.loads(path.read_text()).get('candidates',{}).values():subprocess.run(['docker','rm','-f',v['id']],capture_output=True)
        if hasattr(self,'net'):subprocess.run(['docker','network','rm',self.net],capture_output=True)
    def assert_unaffected(self):
        for role,before in self.original.items():
            after=self.api('GET','/containers/'+before['Id']+'/json')
            if role.endswith('-read'):self.assertFalse(after['State']['Running']);self.assertEqual(after['NetworkSettings']['Networks'],{});self.assertEqual(after['State']['StartedAt'],before['State']['StartedAt'])
            else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
        self.assertEqual(self.p.stable_binding(self.registry),self.p.stable_binding(self.api('GET','/containers/'+self.registry['Id']+'/json')))
    def test_complete_legacy_explicit(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx);result=self.entry.execute_approved(ctx,review,self.decision(review));self.assertTrue(result['complete']);row=ctx.execution.journal.read();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),len(self.core.STAGES));self.assert_unaffected()
            for role in self.core.ROLES:
                actual=self.api('GET','/containers/'+row['candidates'][role]['id']+'/json');before=self.original[role+'-read'];net=actual['NetworkSettings']['Networks'][self.net];original=before['NetworkSettings']['Networks'][self.net]
                self.assertEqual(net['MacAddress'],original['MacAddress']);self.assertEqual(net['IPAddress'],original['IPAddress']);self.assertEqual(actual['HostConfig']['Memory'],before['HostConfig']['Memory']);self.assertEqual(actual['Config']['Env'],before['Config']['Env']);self.assertEqual(actual['Config']['Cmd'],before['Config']['Cmd'])
            print(json.dumps({'schema':'ouf.two-read-redaction-native-executor-ci.v1','complete':True,'backend':os.environ['EXPECTED_STORE'],'oldConfigProfile':'LEGACY_PRESENT'if getattr(self,'legacy_explicit',True)else'ENDPOINT_ONLY_ABSENT','mountProfile':'MOUNT_SPECS_RO_WITH_WRITABLE_TMPFS'if getattr(self,'mount_specs',False)else'RETAINED_BINDS_RO','fullSignedLifecycle':True,'stages':len(self.core.STAGES),'fiveOtherComponentsAndRegistryUnchanged':True,'endpointMacIpPreserved':True,'memoryZeroAndPositiveRetained':True,'oldReadsRetainedStopped':2,'thirdSignatureBeforeCommit':True,'syntheticAuthoritiesAndWorkload':True,'productionRuntimeAccess':False,'applicationE2EProven':False}),flush=True)
        finally:self.cleanup_native()
    def test_complete_endpoint_only(self):self.legacy_explicit=False;self.test_complete_legacy_explicit()
    def test_complete_retained_mount_specs_and_tmpfs(self):self.mount_specs=True;self.test_complete_legacy_explicit()
    def test_lost_controller_after_both_new_read_starts(self):
        try:
            self.setup_native();r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);ctx=self.context_instance();review=self.entry.review(ctx);ports_class=self.parts['ports'].NativePorts;original=ports_class.execute
                    def fault(ports,stage):
                        proof=original(ports,stage)
                        if stage=='START_UDP_READ':os.write(w,b'STARTED');os._exit(73)
                        return proof
                    ports_class.execute=fault;self.entry.execute_approved(ctx,review,self.decision(review));os._exit(74)
                except BaseException:
                    import traceback
                    traceback.print_exc();os._exit(75)
            os.close(w);self.assertTrue(select.select([r],[],[],180)[0]);self.assertEqual(os.read(r,32),b'STARTED');os.close(r);_,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
            path=Path(self.case['executionRoot'])/'recovery.json';deadline=time.monotonic()+30
            while True:
                row=self.parts['quarantine'].snapshot(self.journal.Journal(path.parent))
                if(row.get('quarantine')or{}).get('state')=='APPLIED':break
                self.assertLess(time.monotonic(),deadline);time.sleep(.2)
            self.assertEqual(row['counts']['quarantineStops'],2);self.assertEqual(row['effects'][-1]['state'],'CLAIMED');self.assertEqual(row['state'],'STOP_RECONCILE')
            for candidate in row['candidates'].values():
                v=self.api('GET','/containers/'+candidate['id']+'/json');self.assertFalse(v['State']['Running']);self.assertEqual(v['HostConfig']['RestartPolicy']['Name'],'no')
            self.assert_unaffected();print(json.dumps({'schema':'ouf.two-read-redaction-lost-controller-ci.v1','complete':True,'backend':os.environ['EXPECTED_STORE'],'bothOwnReadCandidatesStopped':True,'fiveOtherComponentsAndRegistryUnchanged':True,'claimedStartRetained':True,'noRollbackOrReplay':True,'syntheticAuthoritiesAndWorkload':True,'productionRuntimeAccess':False}),flush=True)
        finally:self.cleanup_native()
if __name__=='__main__':
    names=('test_complete_legacy_explicit','test_complete_endpoint_only','test_complete_retained_mount_specs_and_tmpfs','test_lost_controller_after_both_new_read_starts');result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Native(n)for n in names));raise SystemExit(0 if result.wasSuccessful()else 1)
