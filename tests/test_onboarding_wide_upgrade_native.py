"""Exact archive, two real Docker networks, V38 history and private JVM trust."""
import hashlib,http.server,importlib.util,json,os,pathlib,ssl,subprocess,tempfile,threading,time,unittest,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('wide',ROOT/'scripts/upgrade-onboarding-wide-20261108.py')
r=module('engine',ROOT/'scripts/upgrade-semantic-application-20261108.py')
mac=module('mac',ROOT/'tools/acquisition_read_native/retained_mac.py')
D=m.DOCKER
def cmd(*args,**kwargs):
 p=subprocess.run(args,capture_output=True,timeout=180,**kwargs)
 if p.returncode:raise AssertionError(p.stderr.decode(errors='replace')[-2500:])
 return p.stdout
class Native(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.p=pathlib.Path(cls.tmp.name);cls.p.chmod(0o755)
  cls.tag='ouf-wide-'+uuid.uuid4().hex[:8];m.BACKEND=cls.tag+'-backend';m.PRIVATE=cls.tag+'-storage'
  cls.pg=cls.tag+'-pg';cls.e=r.Engine();cls.ids=[]
  cmd(*D,'load','-i',str(ROOT/'onboarding-candidate/image.tar.gz'))
  cls.image=json.loads(cmd(*D,'image','inspect','ouf-source-onboarding:'+m.PUBLISHER))[0]['Id']
  record=json.loads((ROOT/'scripts/onboarding-wide-candidate-package-20261108.json').read_text())
  assert cls.image in (record['classicImageId'],record['containerdImageId']);cls.jarsha=record['jarSha256']
  for net in (m.BACKEND,m.PRIVATE):cmd(*D,'network','create','--internal',net)
  cls.gateway=json.loads(cmd(*D,'network','inspect',m.BACKEND))[0]['IPAM']['Config'][0]['Gateway']
  cmd(*D,'run','-d','--name',cls.pg,'--network',m.BACKEND,'-p','127.0.0.1::5432','-e','POSTGRES_PASSWORD=fixture-only','postgres:17')
  for _ in range(60):
   if subprocess.run((*D,'exec',cls.pg,'pg_isready','-U','postgres'),capture_output=True).returncode==0:break
   time.sleep(1)
  else:raise AssertionError('postgres not ready')
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b"CREATE ROLE fixture LOGIN SUPERUSER PASSWORD 'fixture-only';CREATE DATABASE fixture OWNER fixture;")
  port=json.loads(cmd(*D,'inspect',cls.pg))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
  cmd(os.environ['QUALIFIED_JAVA'],'-cp',str(ROOT/'onboarding-native/classes')+':'+str(ROOT/'onboarding-native/lib/*'),'NativeOnboardingBaseline',
      'jdbc:postgresql://127.0.0.1:'+port+'/fixture',str(ROOT/'onboarding-native/migrations'))
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b'ALTER ROLE fixture NOSUPERUSER;')
  # Synthetic retained data; no job exists to trigger background ingestion/profile work.
  cls.sql("INSERT INTO ouf_onboarding.managed_file_asset(asset_id,staging_ref,content_hash,media_type,size_bytes,uploaded_by,retention_ref,status,tenant_id) VALUES('c51745c5-1fc0-4d36-bdcf-1e9a8a049c94','object://managed-files/fixture','sha256:'||repeat('a',64),'text/csv',7,'fixture','fixture','PROFILED','fixture');INSERT INTO ouf_onboarding.file_profile(profile_id,asset_id,version,format,metadata,inferred_schema,candidate_keys,sample_ref) VALUES('da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342','c51745c5-1fc0-4d36-bdcf-1e9a8a049c94',1,'CSV','{}','[]','[]','fixture');")
  cls.trust=cls.p/'storage';cls.trust.mkdir(mode=0o755)
  for leaf,text in [('access-key','fixture-access'),('secret-key','fixture-secret')]:
   (cls.trust/leaf).write_text(text);os.chown(cls.trust/leaf,10003,10003);(cls.trust/leaf).chmod(0o400)
  (cls.p/'token').write_text('fixture-not-a-jwt');(cls.p/'token').chmod(0o444)
  cmd('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.p/'tls.key'),'-out',str(cls.p/'tls.crt'),'-days','1',
      '-subj','/CN=OUF disposable CI','-addext','subjectAltName=IP:'+cls.gateway)
  cmd(os.environ['QUALIFIED_KEYTOOL'],'-importcert','-noprompt','-alias','fixture','-file',str(cls.p/'tls.crt'),
      '-keystore',str(cls.trust/'truststore.p12'),'-storetype','PKCS12','-storepass','changeit')
  os.chown(cls.trust/'truststore.p12',10003,10003);(cls.trust/'truststore.p12').chmod(0o400)
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    self.send_response(200);self.end_headers();self.wfile.write(b'fixture-tls-ok')
   def log_message(self,*args):pass
  cls.server=http.server.ThreadingHTTPServer(('0.0.0.0',0),Handler)
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cls.p/'tls.crt'),str(cls.p/'tls.key'))
  cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
  cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
 @classmethod
 def sql(cls,s):return cmd(*D,'exec','-i',cls.pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','fixture','-d','fixture',input=s.encode()).decode().strip()
 @classmethod
 def tearDownClass(cls):
  cls.server.shutdown();cls.server.server_close()
  for cid in cls.ids+[cls.pg]:subprocess.run((*D,'rm','-f',cid),capture_output=True)
  for net in (m.BACKEND,m.PRIVATE):subprocess.run((*D,'network','rm',net),capture_output=True)
  cls.tmp.cleanup()
 def state(self):
  return self.sql("SELECT json_build_object('history',(SELECT json_agg(t ORDER BY installed_rank) FROM ouf_onboarding.flyway_schema_history t),'assets',(SELECT json_agg(t) FROM ouf_onboarding.managed_file_asset t),'profiles',(SELECT json_agg(t) FROM ouf_onboarding.file_profile t));")
 def ready(self,cid):
  for _ in range(60):
   doc=self.e.inspect(cid)
   if not doc['State']['Running']:break
   if m.readiness(doc):return doc
   time.sleep(1)
  print(cmd(*D,'logs','--tail','80',cid).decode(),flush=True);raise AssertionError('fixture readiness failed')
 def exercise(self,explicit):
  before=self.state();name=self.tag+'-'+uuid.uuid4().hex[:6]
  app=['java','-jar','/app/application.jar',
       '--ouf.onboarding.staging.endpoint=https://ouf-seaweedfs-stage:9002',
       '--ouf.onboarding.staging.bucket=ouf-managed-files',
       '--ouf.onboarding.staging.access-key-file=/run/ouf-seaweedfs/access-key',
       '--ouf.onboarding.staging.secret-key-file=/run/ouf-seaweedfs/secret-key']
  c={'Image':self.image,'User':'10003:10003','WorkingDir':'/app','Entrypoint':m.ENTRY,'Cmd':app,
     'Env':['OUF_ONB_DB_URL=jdbc:postgresql://'+self.pg+':5432/fixture','OUF_ONB_DB_USER=fixture','OUF_ONB_DB_PASSWORD=fixture-only',
            'OUF_ONBOARDING_OBJECT_STORE_GATEWAY_BASE_URL=http://127.0.0.1:9080','OUF_ONBOARDING_OBJECT_STORE_TOKEN_FILE=/run/fixture-token',
            'JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/run/ouf-seaweedfs/truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'],
     'HostConfig':{'NetworkMode':m.BACKEND,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':[
          str(self.trust)+':/run/ouf-seaweedfs:ro',str(self.p/'token')+':/run/fixture-token:ro',str(ROOT/'onboarding-native/classes')+':/run/fixture-classes:ro']},
     'NetworkingConfig':{'EndpointsConfig':{m.BACKEND:{'MacAddress':'02:42:ac:51:01:11','Aliases':['onboarding-fixture']},
                                         m.PRIVATE:{'MacAddress':'02:42:ac:52:01:11','Aliases':['onboarding-storage-fixture']}}}}
  if explicit:c['MacAddress']='02:42:ac:51:01:11'
  cid=self.e.api('POST','/containers/create?name='+name,c)['Id'];self.ids.append(cid);self.e.api('POST','/containers/'+cid+'/start')
  self.e.api('POST','/containers/'+cid+'/kill?signal=USR1');old=self.ready(cid)
  self.assertEqual(old['Config'].get('MacAddress'),'02:42:ac:51:01:11','real legacy precondition required')
  self.assertEqual(m.process(old),app);self.assertEqual(self.sql("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"),'f')
  req=m.request(old,self.image,app,mac);events={};report={}
  try:current=m.replace(self.e,old,req,mac,lambda k,v:events.setdefault(k,v),report)
  except Exception:
   now=self.e.inspect(old['Id']);print('CI_ONLY_OLD_STATE '+json.dumps({'config':now['Config'].get('MacAddress','ABSENT'),'networks':now['NetworkSettings']['Networks'],'events':list(events)}),flush=True)
   if report.get('replacementContainerId'):
    now=self.e.inspect(report['replacementContainerId']);print('CI_ONLY_NEW_DIFF '+json.dumps({'config':now['Config'],'host':{k:[req['HostConfig'].get(k),now['HostConfig'].get(k)] for k in set(req['HostConfig'])|set(now['HostConfig']) if req['HostConfig'].get(k)!=now['HostConfig'].get(k)},'networks':now['NetworkSettings']['Networks']}),flush=True)
   raise
  finally:
   if report.get('replacementContainerId'):self.ids.append(report['replacementContainerId'])
  self.assertEqual(m.process(current),m.ENTRY+app)
  self.assertEqual(r.file_sha(pathlib.Path('/proc',str(current['State']['Pid']),'root/app/application.jar')),self.jarsha)
  self.e.api('POST','/containers/'+current['Id']+'/kill?signal=USR1');live=self.ready(current['Id']);m.verify_replacement(old,req,live,True)
  self.assertEqual(m.process(live),app);self.assertEqual(json.loads(self.state()),json.loads(before))
  tls=cmd(*D,'exec',live['Id'],'java','-cp','/run/fixture-classes','NativeTrustProbe','https://'+self.gateway+':'+str(self.server.server_port)+'/tls-probe')
  self.assertIn(b'JVM_PRIVATE_CA_TLS_OK',tls);self.assertFalse(self.e.inspect(old['Id'])['State']['Running'])
  self.assertNotIn('MacAddress',self.e.inspect(old['Id'])['Config'])
  self.assertEqual(events['detached-0.private.json']['Config']['MacAddress'],old['Config']['MacAddress'])
  print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG','twoNetworks':True,'legacyInitiallyPresent':True,
      'legacyPresentAfterPrivateDetach':True,'legacyAbsentAfterBackendDetach':True,'bothNetworkIpMacAliasesPreserved':True,
      'exactArchivedJarStarted':True,'readinessHttpStatus':200,'jvmPrivateCaTlsVerified':True,'v38HistoryAndRetainedRowsUnchanged':True,'applicationRoleSuperuser':False,'targetAccess':False}),flush=True)
  for x in (live['Id'],old['Id']):cmd(*D,'rm','-f',x);self.ids.remove(x)
 def test_explicit_legacy(self):self.exercise(True)
 def test_endpoint_only_legacy(self):self.exercise(False)
if __name__=='__main__':unittest.main(verbosity=2)
