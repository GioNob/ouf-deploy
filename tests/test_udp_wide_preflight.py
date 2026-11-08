import copy,importlib.util,io,json,os,pathlib,subprocess,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('udp_read',ROOT/'scripts/read-udp-wide-preflight-20261108.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p,c,h=m.helpers();expected=m.manifest()
def history():
 return [{'version':str(int(x['name'].split('__')[0][1:])),'checksum':x['flywayStyleCrc32Utf8'],'success':True,'type':'SQL','installedRank':int(x['name'].split('__')[0][1:]),'installedOn':'2026-11-08T21:00:00'} for x in expected['migrations']]
def database():
 return {'readOnly':True,'databaseOid':123,'applicationRoleSuperuser':False,'migrations':history(),'activity':dict({t:{} for t in m.STATES},unexpiredLeases={t:0 for t in ('materialization_job','lake_object','lake_maintenance_schedule','lake_shadow_rebuild_plan')},maintenanceDue=0)}
class Unit(unittest.TestCase):
 def test_history_changed_missing_failed_and_added(self):
  self.assertTrue(m.result(p,database(),expected)['exactCandidateMigrationHistory'])
  for mode in ('changed','missing','failed','added'):
   v=database()
   if mode=='changed':v['migrations'][0]['checksum']+=1
   if mode=='missing':v['migrations'].pop()
   if mode=='failed':v['migrations'][0]['success']=False
   if mode=='added':v['migrations'].append(dict(v['migrations'][0],version='37',installedRank=37))
   self.assertFalse(m.result(p,v,expected)['exactCandidateMigrationHistory'])
 def test_activity_has_no_future_restart_authority(self):
  v=database();v['activity']['materialization_job']={'PAUSED':2,'QUARANTINED':1}
  self.assertIn('NOT_QUIESCENCE',m.result(p,v,expected)['activityMeaning'])
  for key,val in [('unexpiredLeases',{}),('maintenanceDue',-1),('materialization_job',{'PRIVATE_STATE':1})]:
   v=database();v['activity'][key]=val
   with self.assertRaises(RuntimeError):m.result(p,v,expected)
 def test_storage_duplicates_and_secret_values(self):
  vals={'endpoint':'https://ouf-seaweedfs-stage:9002','bucket':'ouf-udp','region':'us-east-1','path-style':'true'}
  args=['java','-jar','/app/app.jar']+['--ouf.udp.lake.s3.'+k+'='+v for k,v in vals.items()]
  env={'JAVA_TOOL_OPTIONS':'-Djavax.net.ssl.trustStore=/run/ouf-seaweedfs/truststore.p12 -Djavax.net.ssl.trustStorePassword=PRIVATE',
  'AWS_SHARED_CREDENTIALS_FILE':'/run/ouf-seaweedfs/credentials','AWS_PROFILE':'default','SPRING_APPLICATION_JSON':'{"secret":"PRIVATE"}','OUF_UDP_DB_PASSWORD':'PRIVATE'}
  x=m.declarations(env,args);self.assertTrue(x['allStorageArgumentsMatchSeaweedfsSwitch']);self.assertTrue(x['truststoreDeclarationMatchesSwitch']);self.assertNotIn('PRIVATE',json.dumps(x))
  args+=['--ouf.udp.lake.s3.endpoint=http://old-minio:9000'];self.assertFalse(m.declarations(env,args)['allStorageArgumentsMatchSeaweedfsSwitch'])
  env['_JAVA_OPTIONS']='-Djavax.net.ssl.trustStore=/different';self.assertFalse(m.declarations(env,args)['truststoreDeclarationMatchesSwitch'])
 def test_jdbc_stays_on_retained_database(self):
  d={'Config':{'Env':['OUF_UDP_DB_URL=jdbc:postgresql://ouf-postgres:5432/ouf_udp','OUF_UDP_DB_USER=ouf_udp','OUF_UDP_DB_PASSWORD=PRIVATE']}}
  pg={'Name':'/ouf-postgres','NetworkSettings':{'Networks':{}}};before=copy.deepcopy(d)
  self.assertEqual(m.db_binding(d,pg,c,h),('ouf_udp','ouf_udp'));self.assertEqual(d,before)
  d['Config']['Env'][0]='OUF_UDP_DB_URL=jdbc:postgresql://unexpected/ouf_udp'
  with self.assertRaises(RuntimeError):m.db_binding(d,pg,c,h)
 def test_package_does_not_claim_runtime_behavior(self):
  stream=io.BytesIO();sql=b'SELECT 1;';yaml=b'spring: {}'
  with zipfile.ZipFile(stream,'w') as z:
   z.writestr('BOOT-INF/classes/db/migration/V1__fixture.sql',sql);z.writestr('BOOT-INF/classes/application.yml',yaml)
   z.writestr('BOOT-INF/classes/it/comune/trieste/ouf/udp/PublishedIdentityPolicy.class',b'old')
  target={'migrations':[{'name':'V1__fixture.sql','sha256':m.sha(sql)}],'applicationYaml':{'sha256':m.sha(yaml)},'selectedClasses':{}}
  x=m.package(p,stream.getvalue(),target);self.assertTrue(x['allMigrationFilesMatchCandidate']);self.assertFalse(x['classPresenceProvesRuntimeBehavior'])
  self.assertTrue(x['selectedInstalledClasses']['PublishedIdentityPolicy.class']['present'])
class Native(unittest.TestCase):
 @unittest.skipUnless(os.getenv('OUF_NATIVE_UDP_PREFLIGHT')=='1','native PostgreSQL fixture not selected')
 def test_exact_query_on_all_36_source_migrations_select_only(self):
  def sql(q):
   r=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=q.encode(),capture_output=True,timeout=45)
   self.assertEqual(r.returncode,0,r.stderr.decode());return r.stdout.decode().strip()
  base=ROOT/'candidate/src/main/resources/db/migration'
  for rec in sorted(expected['migrations'],key=lambda x:int(x['name'].split('__')[0][1:])):
   raw=(base/rec['name']).read_bytes();self.assertEqual(m.sha(raw),rec['sha256']);sql(raw.decode())
  values=','.join("(%d,'%s',%d,true,'SQL','2026-11-08T21:00:00')"%(r['installedRank'],r['version'],r['checksum']) for r in history())
  sql("CREATE TABLE ouf_udp.flyway_schema_history(installed_rank int,version text,checksum int,success bool,type text,installed_on timestamp); INSERT INTO ouf_udp.flyway_schema_history VALUES "+values+"; CREATE ROLE reader NOLOGIN NOSUPERUSER; GRANT USAGE ON SCHEMA ouf_udp TO reader; GRANT SELECT ON ALL TABLES IN SCHEMA ouf_udp TO reader;")
  sql("INSERT INTO ouf_udp.handoff_intake(handoff_id,ingestion_run_id,ingestion_id,source_id,type_code,source_object_id,content_hash,payload_json,receipt_ref,state) VALUES('PRIVATE_HANDOFF','fixture','fixture','fixture','fixture','fixture','fixture','{\"PRIVATE_KEY\":\"PRIVATE_VALUE\"}','fixture','DURABLE'); INSERT INTO ouf_udp.materialization_job(job_id,handoff_id,state) VALUES('00000000-0000-0000-0000-000000000001','PRIVATE_HANDOFF','PAUSED');")
  snapshot=sql("SELECT md5(row_to_json(t)::text) FROM ouf_udp.handoff_intake t;")
  first=m.result(p,json.loads(sql('SET ROLE reader;'+m.query(p))),expected)
  self.assertTrue(first['readOnly']);self.assertFalse(first['applicationRoleSuperuser']);self.assertTrue(first['exactCandidateMigrationHistory'])
  self.assertEqual(first['activity']['materialization_job'],{'PAUSED':1});self.assertEqual(first['activity']['maintenanceDue'],1);self.assertNotIn('PRIVATE_',json.dumps(first))
  repeat=m.result(p,json.loads(sql('SET ROLE reader;'+m.query(p))),expected);self.assertEqual(first,repeat)
  self.assertEqual(snapshot,sql("SELECT md5(row_to_json(t)::text) FROM ouf_udp.handoff_intake t;"))
  sql("UPDATE ouf_udp.materialization_job SET state='RUNNING',claimed_by='fixture',lease_until=transaction_timestamp()+interval '1 hour';")
  changed=m.result(p,json.loads(sql('SET ROLE reader;'+m.query(p))),expected);self.assertEqual(changed['activity']['unexpiredLeases']['materialization_job'],1)
if __name__=='__main__':unittest.main(verbosity=2)
