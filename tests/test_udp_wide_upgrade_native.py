"""Exact archive, two real Docker networks, V38 history and private JVM trust."""
import hashlib,http.server,importlib.util,json,os,pathlib,ssl,subprocess,tempfile,threading,time,unittest,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('wide',ROOT/'scripts/upgrade-udp-wide-20261109.py')
r=module('engine',ROOT/'scripts/upgrade-semantic-application-20261108.py')
mac=module('mac',ROOT/'tools/acquisition_read_native/retained_mac.py')
p=module('preflight',ROOT/'scripts/read-udp-wide-preflight-20261108.py')
hp,c,h=p.helpers();D=m.DOCKER
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
  cmd(*D,'load','-i',str(ROOT/'udp-candidate/image.tar.gz'))
  cls.image=json.loads(cmd(*D,'image','inspect','ouf-udp:'+m.PUBLISHER))[0]['Id']
  assert cls.image in (m.CONFIG_ID,m.NATIVE_ID);cls.jarsha=m.JAR_SHA
  for net in (m.BACKEND,m.PRIVATE):cmd(*D,'network','create','--internal',net)
  cls.gateway=json.loads(cmd(*D,'network','inspect',m.BACKEND))[0]['IPAM']['Config'][0]['Gateway']
  cmd(*D,'run','-d','--name',cls.pg,'--network',m.BACKEND,'-e','POSTGRES_PASSWORD=fixture-only','postgis/postgis:17-3.5-alpine')
  for _ in range(60):
   if subprocess.run((*D,'exec',cls.pg,'pg_isready','-U','postgres'),capture_output=True).returncode==0:break
   time.sleep(1)
  else:raise AssertionError('postgres not ready')
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b"CREATE ROLE fixture LOGIN SUPERUSER PASSWORD 'fixture-only';CREATE DATABASE fixture OWNER fixture;")
  address=json.loads(cmd(*D,'inspect',cls.pg))[0]['NetworkSettings']['Networks'][m.BACKEND]['IPAddress']
  cmd(os.environ['QUALIFIED_JAVA'],'-cp',str(ROOT/'udp-native/classes')+':'+str(ROOT/'udp-native/lib/*'),'NativeUdpBaseline',
      'jdbc:postgresql://'+address+':5432/fixture',str(ROOT/'udp-native/migrations'))
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b'ALTER ROLE fixture NOSUPERUSER;')
  cls.sql("""
   UPDATE ouf_udp.lake_maintenance_schedule SET next_run_at=transaction_timestamp()+interval '1 day';
   INSERT INTO ouf_udp.handoff_intake(handoff_id,ingestion_run_id,ingestion_id,source_id,type_code,source_object_id,content_hash,payload_json,receipt_ref,state) VALUES('fixture','fixture','fixture','fixture','fixture','fixture','fixture','{}','fixture','PROCESSED');
   INSERT INTO ouf_udp.materialization_job(job_id,handoff_id,state) VALUES('00000000-0000-0000-0000-000000000001','fixture','SUCCEEDED');
   INSERT INTO ouf_udp.urban_object(urban_object_id,canonical_type,canonical_key) VALUES('00000000-0000-0000-0000-000000000002','fixture','fixture');
   INSERT INTO ouf_udp.source_binding(source_id,type_code,source_object_id,urban_object_id,first_handoff_id) VALUES('fixture','fixture','fixture','00000000-0000-0000-0000-000000000002','fixture');
   INSERT INTO ouf_udp.lake_object(lake_object_id,tenant_id,source_id,type_code,tier,content_hash,media_type,logical_size_bytes,locator,state,retention_class,access_label,retention_until) VALUES('00000000-0000-0000-0000-000000000003','fixture','fixture','fixture','RAW','sha256:'||repeat('a',64),'text/csv',7,'fixture','VERIFIED','OPERATIONAL','OPEN',transaction_timestamp()+interval '1 day');
  """)
  cls.trust=cls.p/'storage';cls.trust.mkdir(mode=0o755)
  for leaf,text in [('credentials','[default]\naws_access_key_id=fixture-access\naws_secret_access_key=fixture-secret\n')]:
   (cls.trust/leaf).write_text(text);os.chown(cls.trust/leaf,10004,10004);(cls.trust/leaf).chmod(0o400)
  (cls.p/'token').write_text('fixture-not-a-jwt');(cls.p/'token').chmod(0o444)
  cmd('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.p/'tls.key'),'-out',str(cls.p/'tls.crt'),'-days','1',
      '-subj','/CN=OUF disposable CI','-addext','subjectAltName=IP:'+cls.gateway)
  cmd(os.environ['QUALIFIED_KEYTOOL'],'-importcert','-noprompt','-alias','fixture','-file',str(cls.p/'tls.crt'),
      '-keystore',str(cls.trust/'truststore.p12'),'-storetype','PKCS12','-storepass','changeit')
  os.chown(cls.trust/'truststore.p12',10004,10004);(cls.trust/'truststore.p12').chmod(0o400)
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
  return p.result(hp,json.loads(self.sql(m.database_query(p,hp))),p.manifest())
 def ready(self,cid):
  for _ in range(60):
   doc=self.e.inspect(cid)
   if not doc['State']['Running']:break
   if m.readiness(doc):return doc
   time.sleep(1)
  print(cmd(*D,'logs','--tail','80',cid).decode(),flush=True);raise AssertionError('fixture readiness failed')
 def exercise(self,explicit):
  before=self.state();m.verify_database(before,before['databaseOid']);name=self.tag+'-'+uuid.uuid4().hex[:6]
  app=['java','-jar','/app/app.jar',
       '--ouf.udp.lake.s3.endpoint=https://ouf-seaweedfs-stage:9002',
       '--ouf.udp.lake.s3.bucket=ouf-udp','--ouf.udp.lake.s3.region=us-east-1','--ouf.udp.lake.s3.path-style=true']
  c={'Image':self.image,'User':'10004:10004','WorkingDir':'/app','Entrypoint':m.ENTRY,'Cmd':app,
     'Env':['OUF_UDP_DB_URL=jdbc:postgresql://'+self.pg+':5432/fixture','OUF_UDP_DB_USER=fixture','OUF_UDP_DB_PASSWORD=fixture-only',
            'OUF_UDP_MATERIALIZATION_RECOVERY_ENABLED=true',
            'OUF_UDP_LAKE_MAINTENANCE_INITIAL_DELAY_MS=1','OUF_UDP_LAKE_MAINTENANCE_POLL_MS=200',
            'OUF_UDP_LAKE_SHADOW_INITIAL_DELAY_MS=1','OUF_UDP_LAKE_SHADOW_POLL_MS=200',
            'AWS_SHARED_CREDENTIALS_FILE=/run/ouf-seaweedfs/credentials','AWS_PROFILE=default',
            'SPRING_APPLICATION_JSON='+json.dumps({'ouf.udp.execution.enabled':True,'ouf.udp.execution.gateway-url':'http://127.0.0.1:9080','ouf.udp.execution.token-file':'/run/fixture-token','ouf.udp.lake.tenant-id':'fixture','ouf.udp.lake.raw-retention-days':30,'ouf.udp.lake.raw-retention-class':'OPERATIONAL','ouf.udp.lake.raw-access-label':'OPEN'}),
            'JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/run/ouf-seaweedfs/truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'],
     'HostConfig':{'NetworkMode':m.BACKEND,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':[
          str(self.trust)+':/run/ouf-seaweedfs:ro',str(self.p/'token')+':/run/fixture-token:ro',str(ROOT/'udp-native/classes')+':/run/fixture-classes:ro']},
     'NetworkingConfig':{'EndpointsConfig':{m.BACKEND:{'MacAddress':'02:42:ac:51:01:11','Aliases':['onboarding-fixture']},
                                         m.PRIVATE:{'MacAddress':'02:42:ac:52:01:11','Aliases':['onboarding-storage-fixture']}}}}
  if explicit:c['MacAddress']='02:42:ac:51:01:11'
  cid=self.e.api('POST','/containers/create?name='+name,c)['Id'];self.ids.append(cid);self.e.api('POST','/containers/'+cid+'/start')
  self.e.api('POST','/containers/'+cid+'/kill?signal=USR1');old=self.ready(cid)
  self.assertEqual(old['Config'].get('MacAddress'),'02:42:ac:51:01:11','real legacy precondition required')
  self.assertEqual(m.process(old),app);self.assertEqual(self.sql("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"),'f')
  req=m.request(old,self.image,app,mac);events={};report={}
  try:current=m.replace(self.e,old,req,mac,lambda k,v:events.setdefault(k,v),report,lambda:m.verify_database(self.state(),before['databaseOid'],before))
  except Exception:
   now=self.e.inspect(old['Id']);print('CI_ONLY_OLD_STATE '+json.dumps({'config':now['Config'].get('MacAddress','ABSENT'),'networks':now['NetworkSettings']['Networks'],'events':list(events)}),flush=True)
   if report.get('replacementContainerId'):
    now=self.e.inspect(report['replacementContainerId']);print('CI_ONLY_NEW_DIFF '+json.dumps({'config':now['Config'],'host':{k:[req['HostConfig'].get(k),now['HostConfig'].get(k)] for k in set(req['HostConfig'])|set(now['HostConfig']) if req['HostConfig'].get(k)!=now['HostConfig'].get(k)},'networks':now['NetworkSettings']['Networks']}),flush=True)
   raise
  finally:
   if report.get('replacementContainerId'):self.ids.append(report['replacementContainerId'])
  self.assertEqual(m.process(current),m.ENTRY+app)
  self.assertEqual(r.file_sha(pathlib.Path('/proc',str(current['State']['Pid']),'root/app/app.jar')),self.jarsha)
  self.e.api('POST','/containers/'+current['Id']+'/kill?signal=USR1');live=self.ready(current['Id']);m.verify_replacement(old,req,live,True)
  self.assertEqual(m.process(live),app);m.verify_database(self.state(),before['databaseOid'],before)
  time.sleep(1);m.verify_database(self.state(),before['databaseOid'],before)
  tls=cmd(*D,'exec',live['Id'],'java','-cp','/run/fixture-classes','NativeTrustProbe','https://'+self.gateway+':'+str(self.server.server_port)+'/tls-probe')
  self.assertIn(b'JVM_PRIVATE_CA_TLS_OK',tls);self.assertFalse(self.e.inspect(old['Id'])['State']['Running'])
  self.assertNotIn('MacAddress',self.e.inspect(old['Id'])['Config'])
  self.assertEqual(events['detached-0.private.json']['Config']['MacAddress'],old['Config']['MacAddress'])
  print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG','twoNetworks':True,'legacyInitiallyPresent':True,
      'legacyPresentAfterPrivateDetach':True,'legacyAbsentAfterBackendDetach':True,'bothNetworkIpMacAliasesPreserved':True,
      'exactArchivedJarStarted':True,'readinessHttpStatus':200,'jvmPrivateCaTlsVerified':True,'v36HistoryAndRetainedRowsUnchanged':True,'applicationRoleSuperuser':False,'maintenanceAndShadowIdlePollConfigured':True,'all59RetainedTablesUnchanged':True,'materializationRecoveryEnabled':True,'springJsonPreserved':True,'targetAccess':False}),flush=True)
  for x in (live['Id'],old['Id']):cmd(*D,'rm','-f',x);self.ids.remove(x)
 def test_explicit_legacy(self):self.exercise(True)
 def test_endpoint_only_legacy(self):self.exercise(False)
if __name__=='__main__':unittest.main(verbosity=2)
