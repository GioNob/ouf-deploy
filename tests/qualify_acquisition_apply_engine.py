"""Real Docker/APISIX lifecycle with synthetic owners and CI-only signing keys."""
import copy,gzip,hashlib,http.client,importlib.util,io,json,os,re,shutil,socket,stat,struct,subprocess,tempfile,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fixture=module('protocol_fixture',BASE/'tests/test_acquisition_apply_protocol.py')
class EngineLifecycle(fixture.Protocol):
    def cli(self,*args):
        env=dict(os.environ)
        if args[0]=='inspect'or args[:2]==('image','inspect'):env['DOCKER_API_VERSION']='1.44'
        return subprocess.check_output(['docker',*args],stderr=subprocess.PIPE,text=True,env=env).strip()
    def setup_runtime(self,launch_watchdog=True):
        self.resources=[];self.net='ouf-acq-ci-'+str(time.time_ns());self.nid=self.cli('network','create',self.net);self.resources.append(('network',self.net));self.source_commit='e'*40
        folder=self.root/'build';folder.mkdir(mode=0o700);(folder/'server.py').write_text('''import http.server,os
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/health/ready':self.send_response(204);self.end_headers();return
  if self.path=='/actuator/health/readiness':
   body=b'{"status":"UP"}';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
  self.send_error(404)
 def log_message(self,*a):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
        images={};old_images={}
        for role,uid in(('ingestion',10002),('udp',10004),('mcp',10005),('postgres',10006)):
            for version in(('old','candidate')if role!='postgres'else('old',)):
                tag='ouf-fixture-'+role+'-'+version+':'+str(time.time_ns());(folder/'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /server.py\nUSER '+str(uid)+':'+str(uid)+'\nLABEL org.opencontainers.image.revision="'+self.source_commit+'"\nLABEL fixture.version="'+version+'"\nENV PYTHONDONTWRITEBYTECODE=1\nENTRYPOINT ["python","/server.py"]\n'+('CMD ["server"]\n'if role=='mcp'else''));self.cli('build','--quiet','--tag',tag,str(folder));value=json.loads(self.cli('image','inspect',tag))[0]
                if version=='old':old_images[role]=(tag,value)
                else:images[role]=(tag,value)
        self.old={}
        for role in('ingestion','udp','mcp','postgres'):
            name='ouf-fixture-old-'+role+'-'+str(time.time_ns());args=['run','--detach','--name',name,'--network',self.net,'--restart','unless-stopped']
            if role=='mcp':args+=['--env','MCP_OIDC_TOKEN_ENDPOINT=https://issuer.fixture/token','--env','MCP_OIDC_CLIENT_ID=fixture-mcp','--env','MCP_OIDC_CLIENT_SECRET_FILE=/fixture/not-read']
            cid=self.cli(*args,old_images[role][0]);self.resources.append(('container',cid));self.old[role]=json.loads(self.cli('inspect',cid))[0]
        key='fixture-admin-key-00000000';self.config=self.root/'apisix-config.yaml';self.config.write_text('''apisix:
  node_listen: 9080
deployment:
  role: traditional
  role_traditional:
    config_provider: etcd
  admin:
    admin_listen:
      ip: 127.0.0.1
      port: 9180
    allow_admin:
      - 127.0.0.1/32
    admin_key:
      - name: admin
        key: fixture-admin-key-00000000
        role: admin
  etcd:
    host:
      - http://127.0.0.1:23799
''');self.config.chmod(0o400)
        name='ouf-fixture-etcd-'+str(time.time_ns());cid=self.cli('run','--detach','--name',name,'--network','host','quay.io/coreos/etcd:v3.5.15','/usr/local/bin/etcd','--listen-client-urls','http://127.0.0.1:23799','--advertise-client-urls','http://127.0.0.1:23799');self.resources.append(('container',cid));time.sleep(2)
        name='ouf-fixture-apisix-'+str(time.time_ns());cid=self.cli('run','--detach','--name',name,'--user','0:0','--network','host','--volume',str(self.config)+':/usr/local/apisix/conf/config.yaml:ro','apache/apisix:3.18.0-debian');self.resources.append(('container',cid));self.old['gateway']=json.loads(self.cli('inspect',cid))[0]
        def api(method,path,body=None):
            c=http.client.HTTPConnection('127.0.0.1',9180,timeout=3)
            try:
                c.request(method,path,None if body is None else json.dumps(body).encode(),{'X-API-KEY':key,'Content-Type':'application/json'});r=c.getresponse();raw=r.read();return r.status,json.loads(raw)if raw else None
            finally:c.close()
        self.api=api
        for _ in range(60):
            try:
                if api('GET','/apisix/admin/routes')[0]==200:break
            except (OSError,ValueError):pass
            time.sleep(1)
        else:
            for kind,value in self.resources:
                if kind=='container':
                    diagnostic=subprocess.run(['docker','logs',value],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,check=False);print(diagnostic.stdout[-3000:],flush=True)
            raise AssertionError('Synthetic APISIX admin did not start')
        for i in range(82):
            s,v=api('PUT','/apisix/admin/routes/fixture-'+str(i),{'id':'fixture-'+str(i),'uri':'/fixture/'+str(i),'methods':['GET'],'upstream':{'type':'roundrobin','nodes':{'127.0.0.1:9':1}}});self.assertIn(s,(200,201))
        p=self.p;old_gateway={'transportBinding':{},'projectionBinding':{}}
        raw,binding=p.private_config(str(self.config));projection=self.root/'projection.json';p.put(projection,{'synthetic':True});_,projection_binding=p.private_config(str(projection));old_gateway['transportBinding']={'configBinding':binding,'adminKeyBinding':None};old_gateway['projectionBinding']=projection_binding
        proposal={'existingApplications':{r:p.stable_binding(v)for r,v in self.old.items()},'readComponents':{},'mcpReplacement':{},'gateway':old_gateway};native_facts={};identity=self.parts['native_prepare'].identity_profile(json.loads(self.cli('info','--format','{{json .}}')))
        for role in('ingestion','udp','mcp'):
            tag,value=images[role];archive=self.root/(role+'-docker-save.tar');self.cli('save','--output',str(archive),tag)
            import tarfile
            with tarfile.open(archive)as tar:
                manifest=json.load(tar.extractfile('manifest.json'))[0];config=tar.extractfile(manifest['Config']).read();config_id='sha256:'+hashlib.sha256(config).hexdigest()
            image={'Id':config_id,'Config':value['Config']};folder=self.root/('native-'+role);folder.mkdir(mode=0o700)
            with archive.open('rb')as stream:
                checksum,_=self.parts['image_custody'].hashed(stream,self.parts['image_custody'].LIMIT);stream.seek(0);audit=self.parts['image_custody'].archive(stream,checksum,config_id,self.source_commit)
                path=folder/'native.tar';fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o400)
                try:
                    with os.fdopen(os.dup(fd),'r+b')as out:derived=self.parts['image_custody'].tagless_archive(stream,out,audit,containerd=identity=='CONFIG_AND_NATIVE_MANIFEST');out.flush();os.fsync(out.fileno())
                    metadata=list(p.frame(os.fstat(fd)))
                finally:os.close(fd)
            if identity=='CONFIG_AND_NATIVE_MANIFEST':audit['nativeIdentity']=self.parts['image_custody'].native_identity(audit)
            image['Id']=self.parts['image_custody'].runtime_image_id(audit);native_facts[role]={'nativeImageId':image['Id'],'nativeArchive':{'path':str(path),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':metadata},'audit':audit}
            if role=='mcp':item=p.mcp_replacement(self.old[role],image,p.CASE_HASH);proposal['mcpReplacement']=item
            else:
                # Synthetic Python process replaces only the Java launcher in the fixture.
                old=copy.deepcopy(self.old[role]);old['Config']['Entrypoint']=['java','-jar','/synthetic.jar'];ci_image=copy.deepcopy(image);ci_image['Config']['Entrypoint']=['python','/server.py'];item=p.read_component(role,old,ci_image,p.CASE_HASH);item['oldOwnerUnchanged']=p.stable_binding(self.old[role]);item['request']['Entrypoint']=['python','/server.py'];proposal['readComponents'][role]=item
            item['runtimeLabelProjection']=self.parts['native_prepare'].labels(item['request'],audit)
            self.cli('image','rm',tag)
            for image_id in set((value['Id'],image['Id'])):subprocess.run(['docker','image','rm',image_id],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        # Use the actual current schema defaults for old routes, but the same inline
        # upstream shape emitted by the qualified acquisition materializer for new.
        routes=[r['value']for r in api('GET','/apisix/admin/routes')[1]['list']];routes=[{k:v for k,v in r.items()if k not in('create_time','update_time')}for r in routes]
        proposal['gateway']['previousRoutes']=routes;proposal['gateway']['newRoutes']=[]
        for rid,uri in(('execute-ouf-ingestion-acquisition-read','/internal/capabilities/v1/execute/ouf.ingestion.acquisition.read'),('execute-urban-acquisition-read','/internal/capabilities/v1/execute/urban.acquisition.read')):
            route=copy.deepcopy(routes[0]);route.update(id=rid,uri=uri,methods=['POST'],status=1,priority=0);route['upstream']={'type':'roundrobin','scheme':'http','nodes':{'127.0.0.1:9':1},'retries':0,'timeout':{'connect':3,'send':12,'read':12}};proposal['gateway']['newRoutes'].append(route)
        socket_path=Path('/var/run/docker.sock').resolve();s=socket_path.stat();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(socket_path));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close();proposal['engineBinding']={'socketPath':str(socket_path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':peer}
        observations={}
        for role,value in self.old.items():
            path=self.root/(role+'-retained.json');p.put(path,value);observations[role]={'path':str(path),'sha256':p.digest(value)}
        inputs={'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'currentProcessPins':{r:p.process_pin(v['State']['Pid'])for r,v in self.old.items()},'currentObservations':observations};path=self.root/'inputs.json';p.put(path,inputs);p.INPUTS=path;proposal['capturedInputsHash']=p.digest(inputs)
        profile={**self.profile,'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':self.context,'policyBinding':self.verification['trustPolicy']};profile_path=self.root/'profile';p.put(profile_path,profile);profile_binding={'path':str(profile_path),'sha256':p.digest(profile)};public=self.parts['native_prepare'].public_authority(p,profile_binding,self.verification['trustPolicy'],self.context)
        native={'schema':'ouf.acquisition-native-execution-inputs.v1','frozenPlanHash':self.parts['native_prepare'].PLAN_HASH,'nativeProposal':proposal,'nativeProposalHash':p.digest(proposal),'candidateFacts':native_facts,'imageIdentityProfile':identity,'bootId':inputs['bootId'],'publicAuthority':public,'sourceClosure':{},'executionEntryQualified':False,'targetApplyAuthorized':False};native_path=self.root/'native-inputs.json';p.put(native_path,native)
        outer=self
        class FixtureContext(self.entry.Context):
            def refresh_authority(ctx):
                ctx.reserve('ownerConfigurationReads');ctx.reserve('ownerConfigurationReads');current=ctx.preparer.public_authority(ctx.p,profile_binding,outer.verification['trustPolicy'],outer.context);outer.assertEqual(current,ctx.native['publicAuthority']);ctx.profile=current['profile'];return current
        ctx=FixtureContext(self.parts,self.auth,self.sign,self.journal,self.closure,native_path=native_path,native_hash=p.digest(native),root=self.root/'runtime');self.ctx=ctx;ctx.current();ctx.reserve('adminGets');response=ctx.admin('GET','/apisix/admin/routes');self.assertEqual(ctx.route_map(ctx.route_rows(p.decode(response['body'].encode()))),ctx.route_map(routes))
        review=copy.deepcopy(self.review);review.update(executionRoot=str(ctx.root),frozenPlanHash=native['frozenPlanHash'],nativePlan={'frozenPlanHash':native['frozenPlanHash'],'nativeInputsHash':ctx.NATIVE_HASH,'runtimeBinding':ctx.runtime_binding,'runtimeBindingHash':self.core.digest(ctx.runtime_binding),'proposal':ctx.proposal},preflightCounts=copy.deepcopy(ctx.counts));review['nativePlanHash']=self.core.digest(review['nativePlan']);self.review=review;self.execution_root=ctx.root;self.profile=profile;self.core.validate_review(review);gate=self.issue();ports=ctx.ports_module.NativePorts(ctx,review,gate);execution=self.core.Execution(gate,self.journal.Journal(ctx.root),ports);execution.initialize();
        if launch_watchdog:ctx.watch.launch(ctx,review,gate,execution.journal)
        self.gate,self.native_ports,self.execution=gate,ports,execution
    def teardown_runtime(self):
        for kind,resource in reversed(getattr(self,'resources',[])):
            subprocess.run(['docker','rm','-f',resource]if kind=='container'else['docker','network','rm',resource],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        if hasattr(self,'ctx'):
            for proposal in [*self.ctx.proposal['readComponents'].values(),self.ctx.proposal['mcpReplacement']]:subprocess.run(['docker','rm','-f',proposal['name']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    def test_real_native_lifecycle_and_additive_routes(self):
        try:
            self.setup_runtime()
            try:result=self.execution.run()
            except BaseException:
                row=self.execution.read_journal();print('FixtureFailureStage='+str(row['nextStage']),flush=True)
                for role,candidate in row['candidates'].items():
                    actual=json.loads(self.cli('inspect',candidate['id']))[0];wanted=self.native_ports.proposal(role)['request']['HostConfig'];diff=[{'field':k,'expectedType':type(v).__name__,'observedType':type(actual['HostConfig'].get(k)).__name__,'expected':v,'observed':actual['HostConfig'].get(k)}for k,v in wanted.items()if actual['HostConfig'].get(k)!=v];print(json.dumps({'fixtureRole':role,'hostDifferences':diff}),flush=True)
                raise
            self.assertTrue(result['complete']);self.assertFalse(result['applicationE2EProven']);self.assertEqual(result['counts']['imageLoadAttempts'],3);context=self.review['verification']['context'];signer=self.sign.ExistingEd25519Signer(self.profile['keyBindings']['attestor'],self.profile['keyRefs']['attestor'],self.gate.verifier,{'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']});raw=self.core.encoded(result);self.core.authentication_file(self.ctx.root/'authority',self.core.sha(raw)+'.CREATION_ATTESTATION.json',signer.sign(raw));self.assertTrue(self.gate.verifier(raw,'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef']));self.assertEqual(result['counts']['adminPuts'],2);self.assertEqual(len(self.api('GET','/apisix/admin/routes')[1]['list']),84);old_mcp=self.ctx.proposal['mcpReplacement']['oldBinding']['containerId'];self.assertFalse(json.loads(self.cli('inspect',old_mcp))[0]['State']['Running'])
            for role in('ingestion','udp','postgres','gateway'):self.assertEqual(self.p.stable_binding(json.loads(self.cli('inspect',self.old[role]['Id']))[0]),self.ctx.proposal['existingApplications'][role])
            self.ctx.watch.negative(self.ctx,self.review,self.gate.raw,self.execution.journal,'CI_ALREADY_COMMITTED');self.assertEqual(self.execution.read_journal()['state'],'COMPLETE')
            print(json.dumps({'schema':'ouf.synthetic-native-acquisition-apply-ci.v1','complete':True,'profile':self.ctx.native['imageIdentityProfile'],'realEd25519DualSignatures':True,'realEngineImagesLoaded':3,'realCandidatesCreatedAndStarted':3,'realApisixOldRouteCount':82,'realApisixAddedRouteCount':2,'originalWorkersUnchanged':True,'singleMcpManager':True,'completedNegativeLeaseDoesNothing':True,'productionRuntimeAccess':False}),flush=True)
        finally:self.teardown_runtime()
    def test_killed_controller_quarantines_only_uncommitted_candidates(self):
        import select,signal
        try:self.setup_runtime(launch_watchdog=False)
        except BaseException:self.teardown_runtime();raise
        r,w=os.pipe();child=os.fork()
        if child==0:
            try:
                os.close(r);self.ctx.watch.launch(self.ctx,self.review,self.gate,self.execution.journal);original=self.native_ports.execute
                def paused(stage):
                    if stage=='START_UDP_READ':os.write(w,b'READY');signal.pause();raise AssertionError('Killed controller resumed')
                    return original(stage)
                self.native_ports.execute=paused;self.execution.run();os._exit(3)
            except BaseException:os._exit(4)
        os.close(w)
        try:
            ready,_,_=select.select([r],[],[],120);self.assertTrue(ready,'Controller did not reach owned candidate checkpoint');self.assertEqual(os.read(r,16),b'READY');os.kill(child,signal.SIGKILL);os.waitpid(child,0)
            for _ in range(160):
                row=self.execution.read_journal()
                if row['quarantine']and row['quarantine']['state']=='APPLIED':break
                time.sleep(.25)
            else:raise AssertionError('Negative watchdog did not prove quarantine')
            self.assertEqual(row['state'],'STOP_RECONCILE');self.assertEqual(row['counts']['quarantineStops'],2);self.assertEqual(row['effects'][-1]['state'],'CLAIMED')
            for role,value in self.old.items():self.assertEqual(self.p.stable_binding(json.loads(self.cli('inspect',value['Id']))[0]),self.ctx.proposal['existingApplications'][role]);self.assertTrue(json.loads(self.cli('inspect',value['Id']))[0]['State']['Running'])
            for candidate in row['candidates'].values():
                actual=json.loads(self.cli('inspect',candidate['id']))[0];self.assertFalse(actual['State']['Running']);self.assertEqual(actual['HostConfig']['RestartPolicy'],{'Name':'no','MaximumRetryCount':0})
            self.assertEqual(len(self.api('GET','/apisix/admin/routes')[1]['list']),82);before=copy.deepcopy(row['counts'])
            with self.assertRaises(self.core.Stop):self.execution.run()
            self.assertEqual(before,self.execution.read_journal()['counts']);print(json.dumps({'schema':'ouf.synthetic-acquisition-negative-lease-ci.v1','complete':True,'controllerKilled':True,'ownedCandidatesStopped':2,'allOriginalOwnersStillRunning':True,'oldRoutesUnchanged':82,'claimedEffectNotReplayed':True,'productionRuntimeAccess':False}),flush=True)
        finally:
            os.close(r)
            try:os.kill(child,signal.SIGKILL)
            except ProcessLookupError:pass
            self.teardown_runtime()
if __name__=='__main__':
    suite=unittest.TestSuite([EngineLifecycle('test_real_native_lifecycle_and_additive_routes'),EngineLifecycle('test_killed_controller_quarantines_only_uncommitted_candidates')]);result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if result.wasSuccessful()else 1)
