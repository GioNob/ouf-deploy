import copy,hashlib,http.server,importlib.util,io,json,os,shutil,stat,sys,tarfile,tempfile,threading,unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'scripts/prepare-acquisition-read-native-plan-20261025.py'
spec=importlib.util.spec_from_file_location('acquisition_native_plan',SOURCE);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
GATEWAY=Path(os.environ.get('OUF_GATEWAY_QUALIFIED_SOURCE',str(SOURCE.parents[1]/'gateway-evidence')))
PRIVATE='private-configuration-never-print'

def clear_tools():
    for name in list(sys.modules):
        if name=='tools'or name.startswith('tools.'):del sys.modules[name]

def tar_source(root):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz')as archive:
        for name,wanted in p.SOURCE_HASHES.items():
            raw=(GATEWAY/name).read_bytes();assert p.sha(raw)==wanted
            row=tarfile.TarInfo(name);row.size=len(raw);archive.addfile(row,io.BytesIO(raw))
    return stream.getvalue()

def constants(owner=None):
    values={'DELEGATION_KEY_ENV':'DELEGATION_KEY','ISSUER':'https://auth.test/realms/ouf','AUDIENCE':'gateway','MCP_WORKLOAD':'mcp-workload'}
    if owner:values['OWNER_KEY_ENV']=owner
    return 'return function(conf, ctx)\n'+'\n'.join('local '+k+' = '+json.dumps(v)for k,v in values.items())+'\nend'

def routes():
    base={'id':'retained-execute','uri':'/internal/capabilities/v1/execute','methods':['POST'],'plugins':{
        'openid-connect':{'bearer_only':True,'ssl_verify':True,'use_jwks':True,'unauth_action':'deny'},'limit-count':{},'request-validation':{},'serverless-pre-function':{'functions':['retained']},'serverless-post-function':{'functions':[constants()]}}}
    result=[base]
    for ident,cap,key in [('ingestion','ouf.ingestion.status','INGESTION_KEY'),('udp','urban.object.search','UDP_KEY')]:
        row=copy.deepcopy(base);row.update(id='retained-'+ident,uri='/internal/capabilities/v1/execute/'+cap);row['plugins']['serverless-post-function']['functions']=[constants(key)];result.append(row)
    return result

@unittest.skipUnless(os.geteuid()==os.getegid()==0,'root custody fixtures mandatory in dedicated gate')
class NativePlanTest(unittest.TestCase):
    def setUp(self):
        clear_tools();p.COUNTS.update({k:0 for k in p.COUNTS})
        self.base=Path(tempfile.mkdtemp(prefix='acquisition-native-plan-test-',dir=os.environ.get('OUF_CAPTURE_TEST_PARENT',str(SOURCE.parents[1]))));self.base.chmod(0o700)
        self.packages=self.base/'packages';self.packages.mkdir(mode=0o700);self.root=self.base/'plan';self.input_path=self.base/'inputs.json';self.projection_path=self.base/'projection.json';self.case='a'*64
        self.projection={'installationId':'fixture','revision':1,'checksum':'sha256:fixture','iam':{'workloadClients':{'mcpServer':'mcp-workload','ingestion':'ing-workload','udp':'udp-workload','semantic':'sem-workload'}},'mcp':{'environment':{'MCP_OIDC_CLIENT_ID':'mcp-workload'}},'gateway':{'requiredAudience':'gateway','issuerUrl':'https://auth.test/realms/ouf','publicApiBaseUrl':'https://api.test'},'services':{'bindings':{}}}
        self.write(self.projection_path,self.projection)
        self.actual={};observations={};pin=p.process_pin(os.getpid())
        self.config=self.base/'apisix-config.yaml';self.write(self.config,b'deployment:\n  admin:\n    admin_key:\n')
        self.key=self.base/'admin-key';self.write(self.key,b'fixture-admin-key-00000000')
        for ordinal,role in enumerate(('ingestion','udp','mcp','gateway','postgres'),1):
            uid={'ingestion':'10002:10002','udp':'10004:10004','mcp':'10005:10005'}.get(role,'1000:1000')
            values=['PRIVATE_FIXTURE='+PRIVATE]
            if role=='mcp':values+=['MCP_OIDC_TOKEN_ENDPOINT=https://auth.test/realms/ouf/protocol/openid-connect/token','MCP_OIDC_CLIENT_ID=mcp-workload','MCP_OIDC_CLIENT_SECRET_FILE=/run/secrets/mcp-secret']
            if role=='gateway':values+=['DELEGATION_KEY=fixture-a','INGESTION_KEY=fixture-b','UDP_KEY=fixture-c']
            value={'Id':('%064x'%ordinal),'Name':'/ouf-'+role,'Image':'sha256:'+'e'*64,'State':{'Pid':os.getpid(),'StartedAt':'2026-10-25T01:00:00Z','Running':True},'Config':{'User':uid,'Hostname':'retained-'+role,'Env':values,'Entrypoint':['java','-jar','/app/app.jar']if role in('ingestion','udp')else['original'],'Cmd':['server']if role=='mcp'else None,'Labels':{},'Image':'retained'},'HostConfig':{'NetworkMode':'ouf-backend','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Binds':None,'Mounts':None,'Memory':0,'Privileged':False},'Mounts':[],'NetworkSettings':{'Networks':{'ouf-backend':{'NetworkID':'1'*64,'Aliases':['ouf-'+role]}}}}
            if role=='gateway':value['Mounts']=[{'Type':'bind','Source':str(self.config),'Destination':'/usr/local/apisix/conf/config.yaml','RW':False}]
            self.actual[role]=value;path=self.base/(role+'.json');self.write(path,value);observations[role]={'path':str(path),'sha256':p.sha(p.encoded(value))}
        self.inputs={'schema':'ouf.acquisition-read-current-private-inputs.v1','engineBinding':{'socketPath':'/run/synthetic-only/docker.sock','socketBinding':[1,2,0,0,384],'peerCredentials':[1,0,0]},'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'currentProcessPins':{role:pin for role in self.actual},'currentObservations':observations}
        self.receipt={'schema':'ouf.acquisition-read-packages-staged.v1','complete':True,'rootProtected':True,'caseHash':self.case,'artifacts':{}}
        for role in('ingestion','udp','mcp','gateway'):
            folder=self.packages/role;folder.mkdir(mode=0o700)
            if role=='gateway':
                raw=tar_source(self.base);self.write(folder/'source.tar.gz',raw);self.receipt['artifacts'][role]={'fileHashes':{'source.tar.gz':p.sha(raw)}}
            else:
                name='image-config.json'if role=='mcp'else'acquisition-image-config.json';image={'Id':'sha256:'+str({'ingestion':2,'udp':3,'mcp':4}[role])*64,'Config':{'User':self.actual[role]['Config']['User'],'Entrypoint':['/usr/local/bin/ouf-mcp']if role=='mcp'else['java','read-only-entrypoint'],'Cmd':['server']if role=='mcp'else None,'Labels':{'org.opencontainers.image.revision':'candidate-read-source'}}}
                self.write(folder/name,[image]);self.receipt['artifacts'][role]={'imageId':image['Id'],'sourceCommit':'b'*40,'fileHashes':{name:p.sha(p.encoded([image])),'image.tar.gz':'c'*64}}
        self.refresh()
    def write(self,path,value):
        if path.exists():path.chmod(0o600)
        path.write_bytes(value if isinstance(value,bytes)else p.encoded(value));path.chmod(0o400)
    def refresh(self):
        for role,value in self.actual.items():
            path=self.base/(role+'.json');self.write(path,value);self.inputs['currentObservations'][role]['sha256']=p.sha(p.encoded(value))
        self.write(self.input_path,self.inputs);self.input_hash=p.sha(p.encoded(self.inputs));self.receipt['capturedInputsHash']=self.input_hash
        self.write(self.packages/'complete.json',self.receipt);self.receipt_hash=p.sha(p.encoded(self.receipt))
    def probe(self,actual,inputs,root):
        p.COUNTS['gatewayAdminGetAttempts']+=1
        return copy.deepcopy(routes()),{'syntheticOnly':True}
    def prepare(self,probe=None):return p.prepare(self.input_path,self.input_hash,self.packages,self.receipt_hash,self.root,self.case,self.projection_path,probe or self.probe)
    def tearDown(self):clear_tools();shutil.rmtree(self.base)
    def test_complete_frozen_plan_preserves_workers_routes_and_mcp_identity_without_authority(self):
        result=self.prepare();self.assertTrue(result['complete']);self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['executionEntryQualified']);self.assertEqual(result['engineGetAttempts'],0);self.assertEqual(result['gatewayAdminGetAttempts'],1)
        public=json.dumps(result);self.assertNotIn(PRIVATE,public);self.assertNotIn('fixture-admin-key',public);self.assertNotIn('https://auth.test',public)
        plan=json.loads((self.root/'execution-plan.json').read_text());self.assertEqual(result['privatePlanHash'],p.digest(plan));self.assertEqual(plan['gateway']['previousRoutes'],routes());self.assertEqual(len(plan['gateway']['newRoutes']),2)
        for role in('ingestion','udp'):
            request=plan['readComponents'][role]['request'];self.assertEqual(request['Env'],self.actual[role]['Config']['Env']);self.assertTrue(request['HostConfig']['ReadonlyRootfs']);self.assertEqual(request['HostConfig']['CapDrop'],['ALL']);self.assertFalse(request['HostConfig']['PublishAllPorts'])
        mcp=plan['mcpReplacement'];self.assertTrue(mcp['oldMustBeStoppedAndDetachedBeforeNewStarts']);self.assertEqual(mcp['normalOAuthManagerCountAfterReplacement'],1);self.assertEqual(mcp['request']['Env'],self.actual['mcp']['Config']['Env']);self.assertEqual(mcp['request']['Hostname'],'retained-mcp')
    def test_plan_scope_replay_cannot_reopen_admin_read(self):
        self.prepare();before=(self.root/'execution-plan.json').read_bytes()
        with self.assertRaisesRegex(p.Stop,'NATIVE_PLAN_SCOPE_CONSUMED_NO_REPLAY'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],1);self.assertEqual(before,(self.root/'execution-plan.json').read_bytes())
    def test_captured_process_drift_stops_before_admin_or_credential_read(self):
        self.inputs['currentProcessPins']['gateway']=dict(self.inputs['currentProcessPins']['gateway'],startTicks=0);self.refresh()
        with self.assertRaisesRegex(p.Stop,'CAPTURED_ROLE_PROCESS_CHANGED'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0);self.assertEqual(p.COUNTS['serviceCredentialFilesOpened'],0)
    def test_wrong_staged_receipt_hash_stops_before_admin(self):
        self.receipt_hash='0'*64
        with self.assertRaisesRegex(p.Stop,'EXACT_PRIVATE_METADATA_HASH_REQUIRED'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_second_mcp_authentication_source_is_rejected_before_any_admin_get(self):
        self.actual['mcp']['Config']['Env'].append('MCP_WORKLOAD_TOKEN=forbidden-second-source');self.refresh()
        with self.assertRaisesRegex(p.Stop,'ONE_EXISTING_MCP_CLIENT_CREDENTIALS_SOURCE_REQUIRED'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_jvm_trust_settings_and_original_spring_arguments_are_preserved(self):
        value=self.actual['ingestion']['Config'];value['Entrypoint']=['java','-Djavax.net.ssl.trustStore=/run/trusted/ca','-Xmx256m','-jar','/app/app.jar'];value['Cmd']=['--spring.config.additional-location=file:/run/existing/owner.yml'];self.refresh();self.prepare()
        plan=json.loads((self.root/'execution-plan.json').read_text());request=plan['readComponents']['ingestion']['request']
        self.assertEqual(request['Entrypoint'][1:3],value['Entrypoint'][1:3]);self.assertEqual(request['Cmd'],value['Cmd']);self.assertEqual(request['Entrypoint'][3:],["read-only-entrypoint"])
    def test_unknown_owner_launcher_is_not_silently_reinterpreted(self):
        self.actual['udp']['Config']['Entrypoint']=['unknown-wrapper'];self.refresh()
        with self.assertRaisesRegex(p.Stop,'RETAINED_JAVA_JAR_LAUNCHER_REQUIRED'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_nonempty_unknown_docker_config_is_not_silently_dropped(self):
        self.actual['ingestion']['Config']['UnknownFutureField']='important';self.refresh()
        with self.assertRaisesRegex(p.Stop,'NONDEFAULT_UNSUPPORTED_CONTAINER_CONFIG'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_read_services_do_not_receive_existing_writeable_mounts(self):
        self.actual['ingestion']['Mounts']=[{'Type':'bind','Source':str(self.base),'Destination':'/existing-owner-token-dir','RW':True,'Propagation':'rprivate'}];self.refresh();self.prepare()
        plan=json.loads((self.root/'execution-plan.json').read_text());self.assertTrue(plan['readComponents']['ingestion']['request']['HostConfig']['Mounts'][0]['ReadOnly']);self.assertTrue(self.actual['ingestion']['Mounts'][0]['RW'])
    def test_host_control_socket_is_rejected_before_admin(self):
        self.actual['udp']['Mounts']=[{'Type':'bind','Source':'/run/docker.sock','Destination':'/run/docker.sock','RW':True}];self.refresh()
        with self.assertRaisesRegex(p.Stop,'NO_HOST_CONTROL_MOUNT_IN_READ_COMPONENT'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_retained_route_scope_or_identity_drift_cannot_be_compiled(self):
        def drift(actual,inputs,root):
            rows=routes();rows[1]['plugins']['serverless-post-function']['functions']=[constants('INGESTION_KEY').replace('mcp-workload','forged')];return rows,{}
        with self.assertRaisesRegex(p.Stop,'RETAINED_ROUTE_INSTALLATION_IDENTITY_REQUIRED'):self.prepare(drift)
        self.assertFalse((self.root/'execution-plan.json').exists())
    def test_missing_current_route_is_not_filled_from_source_assumptions(self):
        with self.assertRaisesRegex(p.Stop,'ONE_RETAINED_BOUND_EXECUTE_ROUTE_REQUIRED'):self.prepare(lambda *_:(routes()[:1],{}))
    def test_current_gateway_config_file_symlink_is_refused(self):
        link=self.base/'linked-config';link.symlink_to(self.config)
        with self.assertRaises(OSError):p.private_config(str(link))
    def test_config_custody_and_admin_key_selection_are_closed(self):
        raw,binding=p.private_config(str(self.config));self.assertEqual(binding['sha256'],p.sha(raw))
        with self.assertRaisesRegex(p.Stop,'ONE_SELECTED_APISIX_ADMIN_CREDENTIAL_REQUIRED'):p.selected_admin_key(raw)
        self.assertEqual(p.selected_admin_key(raw,'fixture-admin-key-00000000'),'fixture-admin-key-00000000')
    @unittest.skipUnless(os.environ.get('OUF_NATIVE_NAMESPACE_FIXTURE')=='1','real root namespace transport required by dedicated CI')
    def test_actual_root_namespace_child_performs_exactly_one_authenticated_infrastructure_get(self):
        seen=[];fixture=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                if self.path!='/apisix/admin/routes'or self.headers.get('X-API-KEY')!='fixture-admin-key-00000000':self.send_error(403);return
                raw=p.encoded({'list':routes()});self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*_):pass
        server=http.server.HTTPServer(('127.0.0.1',9180),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            result=self.prepare(lambda actual,inputs,root:p.live_gateway_routes(actual,inputs,root,self.key));self.assertEqual(result['gatewayAdminGetAttempts'],1);self.assertEqual(result['serviceCredentialFilesOpened'],1);self.assertEqual(result['networkNamespaceJoins'],1);self.assertEqual(seen,['/apisix/admin/routes'])
        finally:server.shutdown();server.server_close();thread.join()
    def test_main_negative_path_is_closed_and_does_not_mask_stop(self):
        import subprocess
        result=subprocess.run([sys.executable,str(SOURCE)],capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_PLAN_PREPARATION_REQUIRED');self.assertNotIn('Traceback',result.stderr)
if __name__=='__main__':unittest.main()
