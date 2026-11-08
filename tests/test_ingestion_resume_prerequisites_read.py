import copy,importlib.util,json,os,pathlib,subprocess,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('resume',ROOT/'scripts/read-ingestion-resume-prerequisites-20261108.py');c,h,f=m.helpers()
def doc():
 ep={'MacAddress':'02:42:ac:11:01:01','IPAddress':'10.0.0.2','Gateway':'10.0.0.1','EndpointID':'endpoint','NetworkID':'network','Aliases':['fixture'],'IPAMConfig':{'IPv4Address':'10.0.0.2'},'IPPrefixLen':24}
 return {'Id':m.CID,'Image':m.IMAGE,'Name':'/fixture','State':{'Running':False,'Pid':0,'ExitCode':143,'StartedAt':'generation'},
 'Config':{'MacAddress':ep['MacAddress'],'Env':['SECRET=PRIVATE_VALUE']},'HostConfig':{},'Mounts':[],'Path':'sh','Args':['PRIVATE_VALUE'],
 'NetworkSettings':{'SandboxID':'sandbox','Networks':{'ouf-backend':ep}}}
def db():return {'readOnly':True,'databaseOid':21554,'applicationRoleSuperuser':False,
 'migrations':[],'activity':{'runStates':{'SUCCEEDED':3},'handoffStates':{'ACKED':34},'unexpiredPartitionLeases':0},
 'retainedRows':{t:{'rows':0 if t=='ing_schedule' else 3,'fingerprint':'a'*32} for t in m.TABLES},
 'scheduleStableFingerprint':'b'*32,'scheduleMetadata':[]}
class Unit(unittest.TestCase):
 def test_exact_absent_legacy_and_cleared_endpoint_are_observations_not_accepted_policy(self):
  o=doc();a=copy.deepcopy(o);a['Config'].pop('MacAddress');a['NetworkSettings']['SandboxID']=''
  ep=a['NetworkSettings']['Networks']['ouf-backend'];ep.update(MacAddress='',IPAddress='',Gateway='',EndpointID='',IPPrefixLen=0)
  r=m.frame_report(o,o,a);self.assertEqual(r['configBeforeToCurrent']['changedFields'],['MacAddress'])
  self.assertEqual(r['stages']['current']['legacy']['kind'],'ABSENT');self.assertEqual(r['stages']['current']['endpointMac']['kind'],'EMPTY_STRING')
  self.assertTrue(r['environmentUnchanged']);self.assertNotIn('PRIVATE_VALUE',json.dumps(r));self.assertIn('NO_MAC_NORMALIZATION',r['scope'])
 def test_null_and_other_config_changes_remain_distinct(self):
  o=doc();a=copy.deepcopy(o);a['Config']['MacAddress']=None;a['Config']['Env']=['SECRET=changed'];a['Config']['UnknownPrivateKey']='PRIVATE_VALUE'
  r=m.frame_report(o,o,a);self.assertEqual(r['stages']['current']['legacy']['kind'],'NULL');self.assertFalse(r['environmentUnchanged'])
  self.assertEqual(r['configBeforeToCurrent']['otherChangedFieldCount'],1);self.assertNotIn('UnknownPrivateKey',json.dumps(r))
 def test_identity_difference_rejected(self):
  o=doc();a=copy.deepcopy(o);a['Id']='other'
  with self.assertRaises(RuntimeError):m.frame_report(o,o,a)
 def test_database_delta_retains_history_and_no_row_values(self):
  before=db();now=db();r=m.database_summary(now,before,f)
  self.assertTrue(r['allSchedulesDisabled']);self.assertTrue(r['comparisonWithStoppedRead']['migrationHistoryUnchanged']);self.assertFalse(r['historicalChangedColumnsRecoverable'])
  self.assertNotIn('b'*32,json.dumps(r));self.assertFalse(r['comparisonWithStoppedRead']['rowValuesTransferred'])
 def test_declared_database_binding_rejects_redirect(self):
  d={'Config':{'Env':['OUF_ING_DB_URL=jdbc:postgresql://ouf-postgres/ouf_ingestion','OUF_ING_DB_USER=ouf_ingestion']}}
  p={'Name':'/ouf-postgres','NetworkSettings':{'Networks':{}}};self.assertEqual(m.db_binding(d,p,c,h),('ouf_ingestion','ouf_ingestion'))
  d['Config']['Env'][0]='OUF_ING_DB_URL=jdbc:postgresql://unexpected/ouf_ingestion'
  with self.assertRaises(RuntimeError):m.db_binding(d,p,c,h)
class Native(unittest.TestCase):
 @unittest.skipUnless(os.getenv('OUF_NATIVE_RESUME_READ')=='1','native PostgreSQL not selected')
 def test_query_select_only_and_normal_discovery_drift(self):
  def sql(text):
   r=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=text.encode(),capture_output=True,timeout=12)
   self.assertEqual(r.returncode,0,r.stderr.decode());return r.stdout.decode().strip()
  sql("""CREATE ROLE reader NOLOGIN NOSUPERUSER;CREATE SCHEMA ouf_ingestion;
  CREATE TABLE ouf_ingestion.flyway_schema_history(installed_rank int,version text,checksum int,success bool,type text,installed_on timestamp);
  INSERT INTO ouf_ingestion.flyway_schema_history VALUES(18,'18',1281376280,true,'SQL','2026-11-08T21:00:00');
  CREATE TABLE ouf_ingestion.ing_run(state text);INSERT INTO ouf_ingestion.ing_run VALUES('SUCCEEDED');
  CREATE TABLE ouf_ingestion.handoff_outbox(state text);INSERT INTO ouf_ingestion.handoff_outbox VALUES('ACKED');
  CREATE TABLE ouf_ingestion.ing_partition(lease_until timestamptz);INSERT INTO ouf_ingestion.ing_partition VALUES(NULL);
  CREATE TABLE ouf_ingestion.processing_attempt(id int);CREATE TABLE ouf_ingestion.ing_lineage(id int);CREATE TABLE ouf_ingestion.runtime_configuration_snapshot(id int);
  CREATE TABLE ouf_ingestion.ing_schedule(schedule_id uuid,source_id text,state text,interval_seconds int,publication_id uuid,consumed_publication_id uuid,publication_checksum text,publication_enabled bool,trigger_once bool,activation_blocked bool,activation_failures int,lock_version bigint,lease_owner text,lease_until timestamptz,next_run_at timestamptz,last_dispatched_at timestamptz,discovery_verified_at timestamptz,sync_profile jsonb);
  INSERT INTO ouf_ingestion.ing_schedule VALUES('00000000-0000-0000-0000-000000000001','PRIVATE_SOURCE','DISABLED',0,'00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','PRIVATE_HASH',true,true,false,0,1,NULL,NULL,transaction_timestamp(),NULL,transaction_timestamp()-interval '1 hour','{"PRIVATE_KEY":"PRIVATE_VALUE"}');
  GRANT USAGE ON SCHEMA ouf_ingestion TO reader;GRANT SELECT ON ALL TABLES IN SCHEMA ouf_ingestion TO reader;""")
  before=json.loads(sql('SET ROLE reader;'+m.query()))
  self.assertTrue(before['readOnly']);self.assertFalse(before['applicationRoleSuperuser']);self.assertNotEqual(before['databaseOid'],0)
  self.assertNotIn('PRIVATE_',json.dumps(before));self.assertTrue(before['scheduleMetadata'][0]['currentPublicationConsumed'])
  snapshot=sql('SELECT row_to_json(t) FROM ouf_ingestion.ing_schedule t;')
  repeat=json.loads(sql('SET ROLE reader;'+m.query()));self.assertEqual(before,repeat)
  self.assertEqual(snapshot,sql('SELECT row_to_json(t) FROM ouf_ingestion.ing_schedule t;'))
  # Reproduce the two unconditional fields in the source reconciliation SQL, not a target cause assertion.
  sql('UPDATE ouf_ingestion.ing_schedule SET discovery_verified_at=transaction_timestamp(),lock_version=lock_version+1;')
  after=json.loads(sql('SET ROLE reader;'+m.query()));self.assertNotEqual(before['retainedRows']['ing_schedule'],after['retainedRows']['ing_schedule'])
  self.assertEqual(before['scheduleStableFingerprint'],after['scheduleStableFingerprint'])
  # Target identity is independently pinned. Normalize only this disposable database OID for pure output validation.
  before['databaseOid']=after['databaseOid']=21554
  summary=m.database_summary(after,before,f);self.assertEqual(summary['comparisonWithStoppedRead']['changedTables'],['ing_schedule'])
  self.assertTrue(summary['allSchedulesDisabled']);self.assertTrue(summary['noUnexpiredScheduleLeases'])
  sql("UPDATE ouf_ingestion.ing_schedule SET publication_checksum='CHANGED';")
  changed=json.loads(sql('SET ROLE reader;'+m.query()));self.assertNotEqual(after['scheduleStableFingerprint'],changed['scheduleStableFingerprint'])
if __name__=='__main__':unittest.main(verbosity=2)
