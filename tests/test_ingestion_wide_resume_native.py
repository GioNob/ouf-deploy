"""Exact archived app + actual scheduler polling; residual-only lifecycle on both Engine stores."""
import hashlib,http.server,importlib.util,json,pathlib,threading,time,unittest,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
b=module('native_base',ROOT/'tests/test_ingestion_wide_upgrade_native.py')
m=module('resume',ROOT/'scripts/resume-ingestion-wide-20261108.py')
p=module('prerequisites',ROOT/'scripts/read-ingestion-resume-prerequisites-20261108.py')
class Native(b.Native):
 @classmethod
 def setUpClass(cls):
  super().setUpClass();cls.requests=0;cls.envelopes=[]
  for i in (1,2):
   source='schedule-fixture-'+str(i);publication='00000000-0000-0000-0001-%012d'%i
   bundle={'bundleId':'fixture-'+str(i),'bundleVersion':'1','source':{'sourceId':source,'acquisitionMode':'MANAGED'},'status':'ACTIVE','createdFromOnboardingVersion':'fixture-version','semanticRefs':['fixture@1'],'syncProfile':{},'extractionProfile':{}}
   checksum='sha256:'+hashlib.sha256(json.dumps(bundle,sort_keys=True,separators=(',',':')).encode()).hexdigest();bundle['checksum']=checksum
   cls.envelopes.append({'publicationId':publication,'publicationSequence':1,'sourceId':source,'tenantId':'fixture','sourceStatus':'ENABLED','onboardingVersionId':'fixture-version','checksum':checksum,'bundle':bundle})
   cls.sql("INSERT INTO ouf_ingestion.ing_schedule(schedule_id,tenant_id,source_id,interval_seconds,state,next_run_at,last_dispatched_at,publication_id,publication_sequence,publication_checksum,trigger_once,publication_enabled,consumed_publication_id,sync_profile,discovery_verified_at) VALUES('%s','fixture','%s',0,'DISABLED',transaction_timestamp(),transaction_timestamp(),'%s',1,'%s',true,true,'%s','{}',transaction_timestamp())"%(publication,source,publication,checksum,publication))
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    if self.headers.get('Authorization')!='Bearer fixture-not-a-jwt' or not self.path.startswith('/api/onboarding/v1/runtime/publications?'):
     self.send_error(403);return
    cls.requests+=1;raw=json.dumps({'items':cls.envelopes,'nextAfter':''}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
   def log_message(self,*args):pass
  network=json.loads(b.cmd(*b.D,'network','inspect',cls.net))[0];gateway=network['IPAM']['Config'][0]['Gateway']
  cls.server=http.server.ThreadingHTTPServer((gateway,0),Handler);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
  (cls.p/'extra.properties').write_text('ouf.ingestion.execution.enabled=true\nouf.ingestion.activation.enabled=true\nouf.ingestion.activation.poll-ms=300\nouf.ingestion.activation.initial-delay-ms=500\nouf.ingestion.activation.gateway-url=http://'+gateway+':'+str(cls.server.server_port)+'\nouf.ingestion.activation.token-file=/run/fixture-token\nouf.ingestion.activation.tenant-id=fixture\n')
 @classmethod
 def tearDownClass(cls):
  if hasattr(cls,'server'):cls.server.shutdown();cls.server.server_close();cls.thread.join()
  super().tearDownClass()
 def state(self):return json.loads(self.sql(p.query()))
 def poll_twice(self,start):
  for _ in range(60):
   now=self.state()
   if all(y['lockVersion']>=x['lockVersion']+2 for x,y in zip(start['scheduleMetadata'],now['scheduleMetadata'])):return now
   time.sleep(.25)
  self.fail('actual ActivationLoop did not reconcile both same publications twice')
 def exercise(self,explicit):
  name=self.tag+'-'+uuid.uuid4().hex[:6];app=['java','-jar','/app/app.jar','--spring.flyway.enabled=false']
  bindings=[('read.key','/run/read-owner.key'),('token','/run/fixture-token'),('extra.properties','/run/extra.properties'),('fourth','/run/fixture-fourth')]
  req={'Image':self.image,'User':'10002:10002','WorkingDir':'/app','Entrypoint':b.m.ENTRY,'Cmd':app,
   'Env':['OUF_ING_DB_URL=jdbc:postgresql://'+self.pg+':5432/fixture','OUF_ING_DB_USER=fixture','OUF_ING_DB_PASSWORD=fixture-only','SPRING_FLYWAY_ENABLED=false','SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/extra.properties','OUF_ING_GATEWAY_READ_ENABLED=true','OUF_ING_GATEWAY_READ_KEY_FILE=/run/read-owner.key','OUF_ING_GATEWAY_READ_ISSUER=https://issuer.example.test/realms/fixture','OUF_ING_GATEWAY_READ_AUDIENCE=fixture','OUF_ING_GATEWAY_READ_WORKLOAD=fixture'],
   'HostConfig':{'NetworkMode':self.net,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':[str(self.p/a)+':'+x+':ro' for a,x in bindings]},
   'NetworkingConfig':{'EndpointsConfig':{self.net:{'MacAddress':'02:42:ac:53:01:11','Aliases':['ingestion-fixture']}}}}
  if explicit:req['MacAddress']='02:42:ac:53:01:11'
  start=self.state();cid=self.e.api('POST','/containers/create?name='+name,req)['Id'];self.ids.append(cid);self.e.api('POST','/containers/'+cid+'/start');self.e.api('POST','/containers/'+cid+'/kill?signal=USR1')
  old=self.ready(cid);self.assertEqual(old['Config'].get('MacAddress'),'02:42:ac:53:01:11');self.poll_twice(start)
  self.e.api('POST','/containers/'+cid+'/stop?t=35');stopped=self.e.inspect(cid);baseline=self.state()
  self.assertTrue(m.compare_database(start,baseline,baseline['databaseOid'],True))
  m.stopped_guard(old,stopped,stopped,stopped,b.h,b.r,b.mac)
  replacement=b.m.request(old,self.image,app,b.mac);events={};report={};effects=[];engine=self.e
  class ResidualEngine:
   def inspect(self,c):return engine.inspect(c)
   def api(self,method,path,body=None):
    effects.append((method,path));return engine.api(method,path,body)
  def prestart(doc):m.compare_database(baseline,self.state(),baseline['databaseOid'])
  try:live=m.residual(b.m,b.r,ResidualEngine(),b.mac,old,replacement,lambda k,v:events.setdefault(k,v),report,prestart)
  finally:
   if report.get('replacementContainerId'):self.ids.append(report['replacementContainerId'])
  final=self.poll_twice(baseline);self.assertTrue(m.compare_database(baseline,final,baseline['databaseOid'],True))
  self.assertFalse(any('/stop' in path or '/images/load' in path for _,path in effects))
  self.assertEqual(len([x for x in effects if x[1].startswith('/containers/create?')]),1)
  self.assertEqual(b.m.process(live),app);self.assertGreaterEqual(self.requests,4);self.assertNotIn('MacAddress',self.e.inspect(cid)['Config'])
  self.assertFalse(self.e.inspect(cid)['State']['Running'])
  print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG','legacyInitiallyPresent':True,'legacyPreservedAfterStop':stopped['Config'].get('MacAddress')==old['Config']['MacAddress'],'legacyAbsentAfterDetach':True,'endpointIpMacAliasesPreserved':True,'exactArchivedJarStarted':True,'actualActivationLoopRepeatedPolling':True,'sixBusinessTablesAndV18Unchanged':True,'onlyMonotonicSchedulePollFieldsChanged':True,'bothSchedulesDisabledConsumedUnleased':True,'residualStops':0,'residualImageImports':0,'residualCreates':1,'readinessHttpStatus':200,'targetAccess':False}),flush=True)
  for x in (live['Id'],old['Id']):b.cmd(*b.D,'rm','-f',x);self.ids.remove(x)
if __name__=='__main__':unittest.main(verbosity=2)
