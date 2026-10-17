import importlib.util,json,os,re,subprocess,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-teatri-post-resolution-materialization-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_single_readonly_transaction_closed_inputs_and_no_property_values(self):
  raw=m.acquisition_query('udp','ouf-lab');self.assertTrue(raw.startswith('BEGIN READ ONLY;'));self.assertTrue(raw.endswith('ROLLBACK;'))
  self.assertNotRegex(raw,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b')
  self.assertNotIn('value_json',raw);self.assertNotIn('payload_json',raw);self.assertIn('a5183503-04ff-4e10-850f-e22bf874365e',raw)
  for module,tenant in [('ingestion','ouf-lab'),('udp',"x'; drop table x;--")]:
   with self.assertRaises(ValueError):m.acquisition_query(module,tenant)
 def test_receipt_alone_or_one_missing_revision_cannot_prove_materialization(self):
  facts={'receiptCount':1,'receiptIssueCount':11,'matchedDecisionCount':11,'matchedDistinctIssues':11,'confirmedDistinctObjects':11,'confirmedObjectsWithCurrentRevision':11,'confirmedMaterializedRows':11}
  self.assertTrue(m.materialization_proven(facts))
  for k in facts:
   other={**facts,k:0};self.assertFalse(m.materialization_proven(other),k)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','explicit actual PostgreSQL17 qualification')
class NativeSql(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1500:]);return r.stdout.decode().strip()
 def test_actual_postgres_distinguishes_eleven_materialized_from_confirmed_but_quarantined(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:
   self.assertLess(time.monotonic(),end);time.sleep(.2)
  def sql(raw):return self.cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',raw)
  sql("""
   create schema ouf_udp;
   create table ouf_udp.resolution_review_package_confirmation(package_id uuid,tenant_id text,actor_subject text,confirmed_at timestamptz,authorization_decision_ref text,issue_count integer);
   create table ouf_udp.lake_object(lake_object_id uuid,tenant_id text);
   create table ouf_udp.handoff_intake(handoff_id text,source_id text,ingestion_run_id text,type_code text,raw_lake_object_id uuid,state text,source_object_id text);
   create table ouf_udp.human_resolution_decision(issue_id uuid,action text,actor_subject text,decided_at timestamptz,authorization_decision_ref text);
   create table ouf_udp.resolution_issue(issue_id uuid,handoff_id text,state text,tenant_id text,reason_code text);
   create table ouf_udp.materialization_job(handoff_id text,state text,safe_failure_code text);
   create table ouf_udp.source_binding(source_id text,type_code text,source_object_id text,urban_object_id uuid,state text);
   create table ouf_udp.urban_object(urban_object_id uuid,tenant_id text,status text,current_revision_id uuid);
   create table ouf_udp.materialization_observation(handoff_id text,urban_object_id uuid,revision_id uuid);
   create table ouf_udp.object_revision(urban_object_id uuid,revision_id uuid);
   create table ouf_udp.property_contribution(handoff_id text,urban_object_id uuid);
   insert into ouf_udp.resolution_review_package_confirmation values('a5183503-04ff-4e10-850f-e22bf874365e','ouf-lab','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','2026-10-17T16:00:00Z','fixture-auth',11);
   insert into ouf_udp.lake_object select md5(n::text)::uuid,case when n=14 then 'other-tenant' else 'ouf-lab' end from generate_series(1,14)n;
   insert into ouf_udp.handoff_intake select 'h'||n,'teatri-csv-6609b245','a3208f2f-ebfd-415d-bddc-79ab05dea78f','https://schema.org/PerformingArtsTheater',md5(n::text)::uuid,case when n=13 then 'DURABLE' else 'PROCESSED' end,'PRIVATE_SOURCE_'||n from generate_series(1,14)n;
   insert into ouf_udp.resolution_issue select md5(n::text)::uuid,'h'||n,case when n=13 then 'OPEN' else 'RESOLVED' end,case when n=14 then 'other-tenant' else 'ouf-lab' end,'UNRESOLVED_IDENTITY' from generate_series(2,14)n;
   insert into ouf_udp.human_resolution_decision select md5(n::text)::uuid,'CREATE_NEW','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','2026-10-17T16:00:00Z','fixture-auth' from generate_series(2,12)n;
   insert into ouf_udp.materialization_job select 'h'||n,case when n=13 then 'QUARANTINED' else 'SUCCEEDED' end,case when n=13 then 'UDP_IDENTITY_REVIEW_REQUIRED' else null end from generate_series(1,14)n;
   insert into ouf_udp.source_binding select 'teatri-csv-6609b245','https://schema.org/PerformingArtsTheater','PRIVATE_SOURCE_'||n,md5(n::text)::uuid,'ACTIVE' from generate_series(1,12)n;
   insert into ouf_udp.urban_object select md5(n::text)::uuid,'ouf-lab','ACTIVE',md5(('rev'||n))::uuid from generate_series(1,12)n;
   insert into ouf_udp.materialization_observation select 'h'||n,md5(n::text)::uuid,md5(('rev'||n))::uuid from generate_series(1,12)n;
   insert into ouf_udp.object_revision select md5(n::text)::uuid,md5(('rev'||n))::uuid from generate_series(1,12)n;
   insert into ouf_udp.property_contribution select 'h'||n,md5(n::text)::uuid from generate_series(1,12)n;
  """)
  raw=sql(m.acquisition_query('udp','ouf-lab'));self.assertNotIn('PRIVATE_SOURCE_',raw);facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);self.assertEqual(facts['sourceRowCount'],13);self.assertTrue(m.materialization_proven(facts));self.assertEqual(len(facts['details']),11)
  sql("update ouf_udp.materialization_job set state='QUARANTINED',safe_failure_code='UDP_IDENTITY_COVERAGE_UNVERIFIED' where handoff_id='h2';")
  facts=json.loads(sql(m.acquisition_query('udp','ouf-lab')));self.assertEqual(facts['matchedDecisionCount'],11);self.assertEqual(facts['confirmedMaterializedRows'],10);self.assertFalse(m.materialization_proven(facts))
  facts=json.loads(sql(m.acquisition_query('udp','other-tenant')));self.assertEqual(facts['receiptCount'],0);self.assertEqual(facts['matchedDecisionCount'],0);self.assertFalse(m.materialization_proven(facts))
if __name__=='__main__':unittest.main()
