"""Exact archive startup and one-network replacement, V18 and synthetic retained rows."""
import importlib.util,json,os,pathlib,subprocess,tempfile,time,unittest,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('wide',ROOT/'scripts/upgrade-ingestion-wide-20261108.py')
r=module('engine',ROOT/'scripts/upgrade-semantic-application-20261108.py')
mac=module('mac',ROOT/'tools/acquisition_read_native/retained_mac.py')
p=module('preflight',ROOT/'scripts/read-ingestion-wide-preflight-20261108.py')
hp,c,h=p.helpers();D=m.DOCKER
def cmd(*args,**kwargs):
 q=subprocess.run(args,capture_output=True,timeout=180,**kwargs)
 if q.returncode:raise AssertionError(q.stderr.decode(errors='replace')[-2500:])
 return q.stdout
class Native(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.p=pathlib.Path(cls.tmp.name);cls.p.chmod(0o755)
  cls.tag='ouf-ing-wide-'+uuid.uuid4().hex[:8];cls.net=cls.tag+'-backend';cls.pg=cls.tag+'-pg';cls.e=r.Engine();cls.ids=[]
  cmd(*D,'load','-i',str(ROOT/'ingestion-candidate/image.tar.gz'))
  cls.image=json.loads(cmd(*D,'image','inspect','ouf-ingestion:'+m.SOURCE))[0]['Id']
  assert cls.image in (m.CONFIG_ID,m.NATIVE_ID)
  cmd(*D,'network','create','--internal',cls.net)
  cmd(*D,'run','-d','--name',cls.pg,'--network',cls.net,'-e','POSTGRES_PASSWORD=fixture-only','postgres:17')
  for _ in range(60):
   if subprocess.run((*D,'exec',cls.pg,'pg_isready','-U','postgres'),capture_output=True).returncode==0:break
   time.sleep(1)
  else:raise AssertionError('postgres not ready')
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b"CREATE ROLE fixture LOGIN SUPERUSER PASSWORD 'fixture-only';CREATE DATABASE fixture OWNER fixture;")
  address=cls.e.inspect(cls.pg)['NetworkSettings']['Networks'][cls.net]['IPAddress']
  cmd(os.environ['QUALIFIED_JAVA'],'-cp',str(ROOT/'ingestion-native/classes')+':'+str(ROOT/'ingestion-native/lib/*'),'NativeIngestionBaseline',
      'jdbc:postgresql://'+address+':5432/fixture',str(ROOT/'ingestion-native/migrations'))
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b'ALTER ROLE fixture NOSUPERUSER;')
  cls.sql("""
   INSERT INTO ouf_ingestion.ing_run(run_id,source_id,bundle_id,bundle_version,bundle_checksum,mode,state,correlation_id) VALUES('00000000-0000-0000-0000-000000000001','fixture','fixture','1','fixture','MANAGED_ONCE','SUCCEEDED','fixture');
   INSERT INTO ouf_ingestion.ing_partition(run_id,partition_key,state,checkpoint_json,committed_watermark_json) VALUES('00000000-0000-0000-0000-000000000001','fixture','SUCCEEDED','{"row":3}','{"row":3}');
   INSERT INTO ouf_ingestion.processing_attempt(attempt_id,run_id,source_object_id,attempt_no,adapter_id,bundle_version,state) VALUES('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','fixture',1,'fixture','1','SUCCEEDED');
   INSERT INTO ouf_ingestion.ing_lineage(lineage_id,run_id,attempt_id,source_object_id,bundle_ref,adapter_ref,evidence_json) VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','fixture','fixture','fixture','{}');
   INSERT INTO ouf_ingestion.handoff_outbox(handoff_id,run_id,lineage_id,idempotency_key,payload_json,state,acked_at) VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','fixture','{"fixture":true}','ACKED',transaction_timestamp());
   INSERT INTO ouf_ingestion.runtime_configuration_snapshot(snapshot_id,run_id,bundle_id,bundle_version,bundle_checksum,snapshot_json) VALUES('00000000-0000-0000-0000-000000000005','00000000-0000-0000-0000-000000000001','fixture','1','fixture','{}');
   """)
  for name,content in [('read.key','a'*64),('token','fixture-not-a-jwt'),('extra.properties',
   'ouf.ingestion.execution.enabled=true\nouf.ingestion.activation.gateway-url=http://127.0.0.1:9080\nouf.ingestion.activation.token-file=/run/fixture-token\n'),('fourth','fixture')]:
   (cls.p/name).write_text(content);os.chown(cls.p/name,10002,10002);(cls.p/name).chmod(0o400)
 @classmethod
 def sql(cls,s):return cmd(*D,'exec','-i',cls.pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','fixture','-d','fixture',input=s.encode()).decode().strip()
 @classmethod
 def tearDownClass(cls):
  for cid in cls.ids+[cls.pg]:subprocess.run((*D,'rm','-f',cid),capture_output=True)
  subprocess.run((*D,'network','rm',cls.net),capture_output=True);cls.tmp.cleanup()
 def state(self):return p.result(hp,json.loads(self.sql(m.database_query(p,hp))),p.manifest())
 def ready(self,cid):
  for _ in range(60):
   doc=self.e.inspect(cid)
   if not doc['State']['Running']:break
   if m.readiness(doc):return doc
   time.sleep(1)
  print(cmd(*D,'logs','--tail','100',cid).decode(),flush=True);raise AssertionError('fixture readiness failed')
 def exercise(self,explicit):
  before=self.state();m.verify_database(before,before['databaseOid']);name=self.tag+'-'+uuid.uuid4().hex[:6]
  app=['java','-jar','/app/app.jar','--spring.flyway.enabled=false']
  bindings=[('read.key','/run/read-owner.key'),('token','/run/fixture-token'),('extra.properties','/run/extra.properties'),('fourth','/run/fixture-fourth')]
  req={'Image':self.image,'User':'10002:10002','WorkingDir':'/app','Entrypoint':m.ENTRY,'Cmd':app,
   'Env':['OUF_ING_DB_URL=jdbc:postgresql://'+self.pg+':5432/fixture','OUF_ING_DB_USER=fixture','OUF_ING_DB_PASSWORD=fixture-only',
    'SPRING_FLYWAY_ENABLED=false','SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/extra.properties',
    'OUF_ING_GATEWAY_READ_ENABLED=true','OUF_ING_GATEWAY_READ_KEY_FILE=/run/read-owner.key',
    'OUF_ING_GATEWAY_READ_ISSUER=https://issuer.example.test/realms/fixture','OUF_ING_GATEWAY_READ_AUDIENCE=fixture','OUF_ING_GATEWAY_READ_WORKLOAD=fixture'],
   'HostConfig':{'NetworkMode':self.net,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':[str(self.p/a)+':'+b+':ro' for a,b in bindings]},
   'NetworkingConfig':{'EndpointsConfig':{self.net:{'MacAddress':'02:42:ac:53:01:11','Aliases':['ingestion-fixture']}}}}
  if explicit:req['MacAddress']='02:42:ac:53:01:11'
  cid=self.e.api('POST','/containers/create?name='+name,req)['Id'];self.ids.append(cid);self.e.api('POST','/containers/'+cid+'/start')
  self.e.api('POST','/containers/'+cid+'/kill?signal=USR1');old=self.ready(cid)
  self.assertEqual(old['Config'].get('MacAddress'),'02:42:ac:53:01:11','real legacy precondition required')
  self.assertEqual(m.process(old),app);self.assertEqual(self.sql('SELECT rolsuper FROM pg_roles WHERE rolname=current_user'),'f')
  replacement=m.request(old,self.image,app,mac);events={};report={}
  def stopped_check():m.verify_database(self.state(),before['databaseOid'],before)
  try:current=m.replace(r,self.e,old,replacement,mac,lambda k,v:events.setdefault(k,v),report,stopped_check)
  finally:
   if report.get('replacementContainerId'):self.ids.append(report['replacementContainerId'])
  self.assertEqual(m.process(current),m.ENTRY+app)
  self.assertEqual(r.file_sha(pathlib.Path('/proc',str(current['State']['Pid']),'root/app/app.jar')),m.JAR_SHA)
  self.e.api('POST','/containers/'+current['Id']+'/kill?signal=USR1');live=self.ready(current['Id']);r.verify_replacement(old,replacement,live,True)
  self.assertEqual(m.process(live),app);m.verify_database(self.state(),before['databaseOid'],before)
  self.assertFalse(self.e.inspect(old['Id'])['State']['Running']);self.assertNotIn('MacAddress',self.e.inspect(old['Id'])['Config'])
  print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG','legacyInitiallyPresent':True,
   'legacyAbsentAfterDetach':True,'endpointIpMacAliasesPreserved':True,'exactArchivedJarStarted':True,'readinessHttpStatus':200,
   'v18HistoryAndRetainedRowsUnchanged':True,'applicationRoleSuperuser':False,'flywayDisabled':True,
   'externalConfigurationAndGatewayReadKeyExercised':True,'targetAccess':False}),flush=True)
  for x in (live['Id'],old['Id']):cmd(*D,'rm','-f',x);self.ids.remove(x)
 def test_explicit_legacy(self):self.exercise(True)
 def test_endpoint_only_legacy(self):self.exercise(False)
if __name__=='__main__':unittest.main(verbosity=2)
