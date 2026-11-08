"""Exact archived candidate; disposable V10 DB and real Docker29 legacy lifecycle."""
import copy,importlib.util,json,os,pathlib,subprocess,tempfile,time,unittest,uuid,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def mod(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
r=mod('rollout',ROOT/'scripts/upgrade-semantic-application-20261108.py')
u=mod('upgrade',ROOT/'scripts/upgrade-semantic-v11-v12-20261108.py')
m=mod('mac',ROOT/'tools/acquisition_read_native/retained_mac.py')
D=r.DOCKER
class Binding:DOCKER=D

def cmd(*a,**kw):
 p=subprocess.run(a,capture_output=True,timeout=120,**kw)
 if p.returncode:raise AssertionError(p.stderr.decode(errors='replace')[-3000:])
 return p.stdout

class Native(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.p=pathlib.Path(cls.tmp.name);cls.p.chmod(0o755)
  (cls.p/'spring.datasource.password').write_text('fixture-only');(cls.p/'spring.datasource.password').chmod(0o444)
  cls.tag='ouf-sem-roll-'+uuid.uuid4().hex[:10];cls.pg=cls.tag+'-pg';cls.ids=[];cls.e=r.Engine()
  cmd(*D,'load','-i',str(ROOT/'registry-candidate/image.docker.tar'))
  cls.image=json.loads(cmd(*D,'image','inspect','ouf-cohort-semantic:'+r.SOURCE))[0]['Id']
  assert cls.image in (r.CONFIG_ID,r.NATIVE_ID)
  cmd(*D,'network','create',cls.tag)
  cmd(*D,'run','-d','--name',cls.pg,'--network',cls.tag,'-p','127.0.0.1::5432','-e','POSTGRES_PASSWORD=fixture-only','postgres:17')
  for _ in range(60):
   if subprocess.run((*D,'exec',cls.pg,'pg_isready','-U','postgres'),capture_output=True).returncode==0:break
   time.sleep(1)
  else:raise AssertionError('postgres not ready')
  cmd(*D,'exec','-i',cls.pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres',input=b"CREATE ROLE fixture LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE fixture OWNER fixture;")
  port=json.loads(cmd(*D,'inspect',cls.pg))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
  cls.url='jdbc:postgresql://'+cls.pg+':5432/fixture';cls.host='jdbc:postgresql://127.0.0.1:'+port+'/fixture'
  cls.bundle=json.loads((ROOT/'releases/semantic-migration-helper-20261108.json').read_bytes())
 @classmethod
 def tearDownClass(cls):
  for cid in cls.ids+[cls.pg]:subprocess.run((*D,'rm','-f',cid),capture_output=True)
  subprocess.run((*D,'network','rm',cls.tag),capture_output=True);cls.tmp.cleanup()
 def sql(self,s):return cmd(*D,'exec','-i',self.pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','fixture','-d','fixture',input=s.encode()).decode().strip()
 def baseline(self):
  self.sql('drop schema if exists ouf_sem cascade;')
  cmd(os.environ['QUALIFIED_JAVA'],'-cp',str(ROOT/'native-package/classes')+':'+str(ROOT/'native-package/lib/*'),'NativeBaseline',self.host,str(ROOT/'native-package/migrations'))
  self.sql("insert into ouf_sem.proposal_command_receipt(tenant_id,principal_id,idempotency_key,operation,request_hash,result_json) values('fixture','fixture','keep-me','CREATE',repeat('a',64),'{\"retained\":true}');")
  return self.sql('select oid::text from pg_database where datname=current_database()')
 def old(self,explicit):
  name=self.tag+'-'+uuid.uuid4().hex[:6];mac='02:42:ac:44:01:07'
  request={'Image':self.image,'User':'10001:10001','Entrypoint':r.ENTRY,'Cmd':r.JAVA,
   'Env':['OUF_SEM_DB_URL='+self.url,'OUF_SEM_DB_USER=fixture','SPRING_CONFIG_IMPORT=configtree:/run/fixture/',
    'OUF_DISCOVERY_WORKER_ENABLED=false','OUF_SCHEMA_GOV_ENABLED=false'],
   'HostConfig':{'NetworkMode':self.tag,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':[str(self.p)+':/run/fixture:ro']},
   'NetworkingConfig':{'EndpointsConfig':{self.tag:{'MacAddress':mac,'Aliases':['semantic-fixture']}}}}
  if explicit:request['MacAddress']=mac
  cid=self.e.api('POST','/containers/create?name='+name,request)['Id'];self.ids.append(cid);self.e.api('POST','/containers/'+cid+'/start')
  old=self.e.inspect(cid);self.assertEqual(old['Config'].get('MacAddress'),mac,'real legacy precondition required')
  return old
 def exercise(self,explicit):
  oid=self.baseline();old=self.old(explicit);req=r.request(old,self.image);events={};report={}
  current=r.replace(self.e,old,req,m,lambda k,v:events.setdefault(k,v),report);self.ids.append(current['Id'])
  r.gate_running(current)
  self.assertEqual(r.file_sha(pathlib.Path('/proc',str(current['State']['Pid']),'root/app/application.jar')),r.JAR_SHA)
  self.assertEqual(self.sql('select max(version::int) from ouf_sem.flyway_schema_history'),'10')
  self.assertEqual(cmd(*D,'exec',current['Id'],'id','-u').strip(),b'10001')
  prior=self.sql('select json_agg(t) from (select * from ouf_sem.flyway_schema_history order by installed_rank)t')
  host,path=u.stage_class(current,self.bundle)
  result=u.invoke(Binding,current,path,self.url,'fixture',oid)
  rows=[json.loads(l.split(b' ',1)[1])for l in result.stdout.splitlines()if l.startswith(b'OUF_SEMANTIC_UPGRADE ')]
  self.assertEqual(result.returncode,0,(rows,result.stderr.decode(errors='replace')[-1500:]));self.assertEqual(rows[-1]['status'],'SEMANTIC_V11_V12_MIGRATED_VALIDATED')
  for leaf in ('SemanticMigration.class','loader.properties'):(host/leaf).unlink()
  host.rmdir()
  self.assertEqual(json.loads(prior),json.loads(self.sql('select json_agg(t) from (select * from ouf_sem.flyway_schema_history where version is null or version::int<=10 order by installed_rank)t')))
  self.assertEqual(self.sql("select result_json->>'retained' from ouf_sem.proposal_command_receipt where idempotency_key='keep-me'"),'true')
  self.e.api('POST','/containers/'+current['Id']+'/kill?signal=USR1')
  try:
   for _ in range(60):
    live=self.e.inspect(current['Id'])
    if not live['State']['Running']:raise AssertionError('application exited')
    if r.readiness(current['Id']):break
    time.sleep(1)
   else:raise AssertionError('application readiness timeout')
  except Exception:
   print(cmd(*D,'logs','--tail','90',current['Id']).decode());raise
  r.verify_replacement(old,req,live,True)
  self.assertEqual(self.sql('select count(*) from ouf_sem.discovery_request'),'0')
  self.assertEqual(self.sql('select count(*) from ouf_sem.discovery_attempt'),'0')
  self.assertFalse(self.e.inspect(old['Id'])['State']['Running'])
  print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG','image':self.image,'legacyInitiallyPresent':True,'transition':report['oldMacTransition'],'v10ToV12':True,'exactJarStarted':True,'readinessUp':True,'historyAndReceiptPreserved':True,'oldRetainedStopped':True,'productionAccess':False}),flush=True)
  # Remove only our synthetic containers before the second case uses the fixture MAC.
  for cid in (current['Id'],old['Id']):cmd(*D,'rm','-f',cid);self.ids.remove(cid)
 def test_explicit_legacy(self):self.exercise(True)
 def test_endpoint_only_legacy(self):self.exercise(False)

if __name__=='__main__':unittest.main(verbosity=2)
