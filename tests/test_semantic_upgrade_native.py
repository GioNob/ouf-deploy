"""Disposable databases only. Native proof for the installed-package migration path."""
import base64,hashlib,importlib.util,json,os,subprocess,tempfile,time,unittest,uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upgrade',ROOT/'scripts/upgrade-semantic-v11-v12-20261108.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
DOCKER=('/usr/bin/docker','--host','unix:///run/docker.sock','--config','/nonexistent')
class Binding:pass
Binding.DOCKER=DOCKER

def command(*args,**kw):
 p=subprocess.run(args,capture_output=True,timeout=120,**kw)
 if p.returncode:raise AssertionError(p.stderr.decode(errors='replace')[-2500:])
 return p.stdout

class Native(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tag='ouf-sem-upgrade-'+uuid.uuid4().hex[:10];cls.pg=cls.tag+'-pg';cls.sem=cls.tag+'-sem'
  cls.tmp=tempfile.TemporaryDirectory();cls.path=Path(cls.tmp.name);cls.path.chmod(0o755)
  (cls.path/'spring.datasource.password').write_text('fixture-only');(cls.path/'spring.datasource.password').chmod(0o444)
  command(*DOCKER,'network','create',cls.tag)
  command(*DOCKER,'run','-d','--name',cls.pg,'--network',cls.tag,'-p','127.0.0.1::5432','-e','POSTGRES_USER=fixture','-e','POSTGRES_PASSWORD=fixture-only','-e','POSTGRES_DB=fixture','postgres:17')
  for _ in range(60):
   p=subprocess.run((*DOCKER,'exec',cls.pg,'pg_isready','-h','127.0.0.1','-U','fixture'),capture_output=True)
   if p.returncode==0:break
   time.sleep(0.5)
  else:raise AssertionError('fixture not ready')
  port=json.loads(command(*DOCKER,'inspect',cls.pg))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
  cls.host='jdbc:postgresql://127.0.0.1:'+port+'/fixture';cls.url='jdbc:postgresql://'+cls.pg+':5432/fixture'
  command(*DOCKER,'run','-d','--name',cls.sem,'--network',cls.tag,
    '-v',str(ROOT/'native-package/application.jar')+':/app/application.jar:ro',
    '-v',str(cls.path)+':/run/fixture:ro','-e','OUF_SEM_DB_URL='+cls.url,'-e','OUF_SEM_DB_USER=fixture',
    '-e','SPRING_CONFIG_IMPORT=configtree:/run/fixture/','-e','SPRING_FLYWAY_ENABLED=false',
    '-e','OUF_DISCOVERY_WORKER_ENABLED=false','-e','OUF_SCHEMA_GOV_ENABLED=false',
    'eclipse-temurin:21-jre','sleep','300')
  cls.doc=json.loads(command(*DOCKER,'inspect',cls.sem))[0]
  cls.bundle=json.loads((ROOT/'native-package/helper.json').read_bytes())
  cls.stage,cls.container_path=u.stage_class(cls.doc,cls.bundle)
 @classmethod
 def tearDownClass(cls):
  for name in (cls.sem,cls.pg):subprocess.run((*DOCKER,'rm','-f',name),capture_output=True)
  subprocess.run((*DOCKER,'network','rm',cls.tag),capture_output=True);cls.tmp.cleanup()
 def sql(self,s):
  return command(*DOCKER,'exec','-i',self.pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','fixture','-d','fixture',input=s.encode()).decode().strip()
 def baseline(self):
  self.sql('drop schema if exists ouf_sem cascade;')
  command(os.environ['QUALIFIED_JAVA'],'-cp',str(ROOT/'native-package/classes')+':'+str(ROOT/'native-package/lib/*'),'NativeBaseline',self.host,str(ROOT/'native-package/migrations'))
  return self.sql("select oid::text from pg_database where datname=current_database()")
 def invoke(self,oid):
  p=u.invoke(Binding,self.doc,self.container_path,self.url,'fixture',oid)
  rows=[json.loads(l.split(b' ',1)[1]) for l in p.stdout.splitlines() if l.startswith(b'OUF_SEMANTIC_UPGRADE ')]
  if not rows:raise AssertionError(p.stderr.decode(errors='replace')[-3000:])
  return p,rows
 def test_native_configtree_packaged_flyway_migration_preserves_history_and_receipt(self):
  oid=self.baseline()
  self.sql("insert into ouf_sem.proposal_command_receipt(tenant_id,principal_id,idempotency_key,operation,request_hash,result_json) values('fixture','fixture','keep-me','CREATE',repeat('a',64),'{\"retained\":true}');")
  before=self.sql("select json_agg(t) from (select * from ouf_sem.flyway_schema_history order by installed_rank)t")
  p,rows=self.invoke(oid)
  self.assertEqual(p.returncode,0,(rows,p.stderr.decode(errors='replace')[-1500:]))
  self.assertEqual(rows[-1]['status'],'SEMANTIC_V11_V12_MIGRATED_VALIDATED')
  self.assertEqual(json.loads(before),json.loads(self.sql("select json_agg(t) from (select * from ouf_sem.flyway_schema_history where version is null or version::int<=10 order by installed_rank)t")))
  self.assertEqual(self.sql("select result_json->>'retained' from ouf_sem.proposal_command_receipt where idempotency_key='keep-me'"),'true')
  self.assertEqual(self.sql('select count(*) from ouf_sem.discovery_attempt'),'0')
  self.assertEqual(self.sql('select count(*) from ouf_sem.discovery_request'),'0')
  p,rows=self.invoke(oid)
  self.assertNotEqual(p.returncode,0);self.assertEqual(rows[-1]['reason'],'HISTORY_PREFIX_CHANGED')
  self.assertFalse(any(x['status']=='MIGRATION_DISPATCHED' for x in rows))
 def test_checksum_drift_rejected_before_write(self):
  oid=self.baseline();self.sql("update ouf_sem.flyway_schema_history set checksum=0 where version='1'")
  p,rows=self.invoke(oid);self.assertNotEqual(p.returncode,0)
  self.assertEqual(rows[-1]['reason'],'HISTORY_PREFIX_CHANGED')
  self.assertEqual(self.sql("select max(version::int) from ouf_sem.flyway_schema_history"),'10')
 def test_backlog_rejected_before_write(self):
  oid=self.baseline();self.sql("insert into ouf_sem.discovery_request(request_id,requested_artifact_type,intent,state,created_by_subject) values(gen_random_uuid(),'CLASS','synthetic','PENDING','fixture')")
  p,rows=self.invoke(oid);self.assertNotEqual(p.returncode,0);self.assertEqual(rows[-1]['reason'],'DISCOVERY_REQUESTS_CHANGED')
  self.assertEqual(self.sql("select max(version::int) from ouf_sem.flyway_schema_history"),'10')
 def test_flyway_rejects_history_description_drift_without_repair(self):
  oid=self.baseline();self.sql("update ouf_sem.flyway_schema_history set description='changed fixture' where version='1'")
  p,rows=self.invoke(oid);self.assertNotEqual(p.returncode,0)
  self.assertEqual(rows[-1]['reason'],'FlywayValidateException')
  self.assertFalse(any(x['status']=='MIGRATION_DISPATCHED' for x in rows))
  self.assertEqual(self.sql("select max(version::int) from ouf_sem.flyway_schema_history"),'10')
 def test_wrong_database_oid_rejected(self):
  self.baseline();p,rows=self.invoke('0');self.assertNotEqual(p.returncode,0);self.assertEqual(rows[-1]['reason'],'DATABASE_OID_CHANGED')
 def test_package_source_and_environment_guards(self):
  manifest=json.loads((ROOT/'releases/semantic-migration-source-20261108.json').read_bytes())
  self.assertTrue(u.package(self.doc,manifest)['migrationBytesMatchSource'])
  manifest['files']['V12__discovery_durable_recovery.sql']+='\n-- changed'
  with self.assertRaisesRegex(RuntimeError,'INSTALLED_MIGRATIONS_DIFFER'):u.package(self.doc,manifest)
  env={'OUF_SCHEMA_GOV_ENABLED':'false','OUF_DISCOVERY_WORKER_ENABLED':'false','SPRING_CONFIG_IMPORT':'configtree:/run/fixture/'}
  u.selected_environment(env)
  for key,value in [('OUF_DISCOVERY_WORKER_ENABLED','true'),('SPRING_APPLICATION_JSON','{}'),('JAVA_TOOL_OPTIONS','-Dspring.flyway.target=10'),('SPRING_CONFIG_IMPORT','http://unexpected')]:
   with self.assertRaises(RuntimeError):u.selected_environment(dict(env,**{key:value}))

if __name__=='__main__':unittest.main(verbosity=2)
