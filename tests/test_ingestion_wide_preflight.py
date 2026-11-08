import copy,importlib.util,io,json,os,pathlib,subprocess,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('ing',ROOT/'scripts/read-ingestion-wide-preflight-20261108.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p,c,h=m.helpers();expected=m.manifest()
def history():
 return [{'version':str(int(x['name'].split('__')[0][1:])),'checksum':x['flywayStyleCrc32Utf8'],'success':True,'type':'SQL',
          'installedRank':int(x['name'].split('__')[0][1:]),'installedOn':'2026-11-08T20:00:00'} for x in sorted(expected['migrations'],key=lambda x:int(x['name'].split('__')[0][1:]))]
class Preflight(unittest.TestCase):
 def test_metadata_detects_schema_drift_and_rejects_arbitrary_activity_values(self):
  original={'readOnly':True,'databaseOid':1,'migrations':history(),'activity':{'runStates':{'PAUSED':2},'handoffStates':{'ACKED':5},'unexpiredPartitionLeases':0}}
  self.assertTrue(m.result(p,copy.deepcopy(original),expected)['exactCandidateMigrationHistory'])
  for mode in ('missing','checksum','failed'):
   value=copy.deepcopy(original)
   if mode=='missing':value['migrations'].pop()
   if mode=='checksum':value['migrations'][0]['checksum']+=1
   if mode=='failed':value['migrations'][0]['success']=False
   self.assertFalse(m.result(p,value,expected)['exactCandidateMigrationHistory'])
  for bad in ({'PRIVATE_VALUE':1},{'READY':'PRIVATE_VALUE'},{'READY':-1}):
   value=copy.deepcopy(original);value['activity']['runStates']=bad
   with self.assertRaises(RuntimeError):m.result(p,value,expected)
 def test_jdbc_binding_cannot_redirect_to_another_host_or_role_in_query(self):
  doc={'Config':{'Env':['OUF_ING_DB_URL=jdbc:postgresql://ouf-postgres:5432/ouf_ingestion','OUF_ING_DB_USER=ouf_ingestion','OUF_ING_DB_PASSWORD=PRIVATE']}}
  pg={'Name':'/ouf-postgres','NetworkSettings':{'Networks':{}}};before=copy.deepcopy(doc)
  self.assertEqual(m.db_binding(doc,pg,c,h),('ouf_ingestion','ouf_ingestion'));self.assertEqual(doc,before)
  for url in ('jdbc:postgresql://other/ouf_ingestion','jdbc:postgresql://ouf-postgres/ouf_ingestion?user=postgres'):
   doc['Config']['Env'][0]='OUF_ING_DB_URL='+url
   with self.assertRaises(RuntimeError):m.db_binding(doc,pg,c,h)
 def test_configuration_never_exposes_secret_or_url_values(self):
  env={'OUF_INGESTION_ACTIVATION_GATEWAY_URL':'https://PRIVATE_VALUE','OUF_INGESTION_ACTIVATION_TOKEN_FILE':'/PRIVATE_VALUE',
       'OUF_INGESTION_EXECUTION_ENABLED':'true','OUF_ING_DB_PASSWORD':'PRIVATE_VALUE','SPRING_APPLICATION_JSON':'PRIVATE_VALUE'}
  value=m.declarations(env,['java','-jar',m.JAR,'--ouf.ingestion.gateway-read.key-file=/PRIVATE_VALUE'])
  self.assertNotIn('PRIVATE_VALUE',json.dumps(value));self.assertEqual(value['selectedProperties']['ouf.ingestion.execution.enabled'][0]['summary'],'true')
  self.assertTrue(value['springApplicationJsonPresent']);self.assertFalse(value['externalConfigContentsRead'])
 def test_installed_package_reports_missing_cursor_without_claiming_membership(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w')as z:
   z.writestr('BOOT-INF/classes/application.yml',b'x')
   z.writestr('BOOT-INF/classes/db/migration/V1__fixture.sql',b'SELECT 1;')
   z.writestr('BOOT-INF/classes/it/comune/trieste/ouf/ingestion/ManagedTabularAdapter.class',b'old')
  target={'applicationYaml':{'sha256':m.sha(b'x')},'migrations':[{'name':'V1__fixture.sql','sha256':m.sha(b'SELECT 1;')}],'selectedClasses':{}}
  v=m.package(p,b.getvalue(),target);self.assertTrue(v['allMigrationFilesMatchCandidate'])
  self.assertFalse(v['selectedInstalledClasses']['ManagedTabularAdapter$CsvCursor.class']['present']);self.assertFalse(v['classPresenceProvesRuntimeBehavior'])
class NativeQuery(unittest.TestCase):
 @unittest.skipUnless(os.getenv('OUF_NATIVE_INGESTION_PREFLIGHT')=='1','native PostgreSQL not selected')
 def test_exact_query_under_select_only_role_returns_counts_and_preserves_state(self):
  def sql(q):
   r=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=q.encode(),capture_output=True,timeout=12)
   self.assertEqual(r.returncode,0,r.stderr.decode());return r.stdout.decode().strip()
  values=','.join("(%d,'%s',%d,true,'SQL','2026-11-08T20:00:00')"%(x['installedRank'],x['version'],x['checksum'])for x in history())
  sql("CREATE ROLE reader NOLOGIN; CREATE SCHEMA ouf_ingestion; CREATE TABLE ouf_ingestion.flyway_schema_history(installed_rank int primary key,version text,checksum int,success boolean,type text,installed_on timestamp);"
      "INSERT INTO ouf_ingestion.flyway_schema_history VALUES "+values+";"
      "CREATE TABLE ouf_ingestion.ing_run(state text);INSERT INTO ouf_ingestion.ing_run VALUES('PAUSED'),('PAUSED'),('UNKNOWN_PRIVATE');"
      "CREATE TABLE ouf_ingestion.handoff_outbox(state text);INSERT INTO ouf_ingestion.handoff_outbox VALUES('ACKED');"
      "CREATE TABLE ouf_ingestion.ing_partition(lease_until timestamptz);INSERT INTO ouf_ingestion.ing_partition VALUES(now()+interval '1 hour');"
      "GRANT USAGE ON SCHEMA ouf_ingestion TO reader;GRANT SELECT ON ALL TABLES IN SCHEMA ouf_ingestion TO reader;")
  snapshot="SELECT json_build_object('h',(SELECT json_agg(t ORDER BY installed_rank) FROM ouf_ingestion.flyway_schema_history t),'r',(SELECT json_agg(t) FROM ouf_ingestion.ing_run t),'o',(SELECT json_agg(t) FROM ouf_ingestion.handoff_outbox t),'p',(SELECT json_agg(t) FROM ouf_ingestion.ing_partition t));"
  before=sql(snapshot);v=json.loads(sql('SET ROLE reader;'+m.query(p)));v=m.result(p,v,expected)
  self.assertTrue(v['readOnly']);self.assertFalse(v['applicationRoleSuperuser']);self.assertTrue(v['exactCandidateMigrationHistory'])
  self.assertEqual(v['activity'],{'runStates':{'PAUSED':2,'OTHER':1},'handoffStates':{'ACKED':1},'unexpiredPartitionLeases':1})
  self.assertNotIn('UNKNOWN_PRIVATE',json.dumps(v));self.assertEqual(sql(snapshot),before)
if __name__=='__main__':unittest.main(verbosity=2)
