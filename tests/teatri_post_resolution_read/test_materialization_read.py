import importlib.util,json,os,re,subprocess,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-teatri-post-resolution-materialization-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_single_readonly_transaction_closed_inputs_and_no_property_values(self):
  raw=m.acquisition_query('udp','ouf-lab');self.assertTrue(raw.startswith('BEGIN READ ONLY;'));self.assertTrue(raw.endswith('ROLLBACK;'))
  self.assertNotRegex(raw,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b')
  self.assertNotIn("h.type_code='https://schema.org/PerformingArtsTheater'",raw);self.assertNotIn("h.ingestion_run_id=",raw);self.assertNotIn('value_json',raw);self.assertNotIn('payload_json',raw);self.assertIn('a5183503-04ff-4e10-850f-e22bf874365e',raw)
  for module,tenant in [('ingestion','ouf-lab'),('udp',"x'; drop table x;--")]:
   with self.assertRaises(ValueError):m.acquisition_query(module,tenant)
 def test_receipt_alone_or_one_missing_revision_cannot_prove_materialization(self):
  facts={'receiptCount':1,'receiptIssueCount':11,'matchedDecisionCount':11,'matchedDistinctIssues':11,'confirmedDistinctObjects':11,'confirmedObjectsWithCurrentRevision':11,'confirmedMaterializedRows':11}
  self.assertTrue(m.materialization_proven(facts))
  for k in facts:
   other={**facts,k:0};self.assertFalse(m.materialization_proven(other),k)


class LedgerContract(unittest.TestCase):
 def row(self,n,committed=True):
  return dict(handoff_id='h'+str(n),job_count=1,job_state='SUCCEEDED' if committed else 'QUARANTINED',
   intake_state='PROCESSED' if committed else 'DURABLE',binding_count=1 if committed else 0,
   urban_object_id=('d6051381-934b-4a11-8e71-e1d89cee4e49' if n==1 else str(n)) if committed else None,
   verified_observations=1 if committed else 0,contribution_count=20 if committed else 0,
   open_issue_count=0 if committed else 1,in_confirmed_package=committed and n>1)
 def facts(self):return dict(sourceRowCount=13,sourceDetails=[self.row(n,n<13) for n in range(1,14)])
 def test_exception_is_accounted_but_never_thirteen_commits(self):
  ledger=m.row_ledger(self.facts());self.assertTrue(ledger['allRowsAccounted'])
  self.assertFalse(ledger['allThirteenMaterializedProven']);self.assertFalse(ledger['historicalCriterionChanged'])
 def test_every_evidence_failure_remains_unproven(self):
  for key,value in dict(job_count=2,job_state='QUARANTINED',intake_state='DURABLE',binding_count=0,
    urban_object_id=None,verified_observations=0,contribution_count=0,open_issue_count=1).items():
   facts=self.facts();facts['sourceDetails'][0][key]=value
   self.assertFalse(m.row_ledger(facts)['allRowsAccounted'],key)
 def test_quarantine_cannot_include_a_consumed_confirmation(self):
  facts=self.facts();facts['sourceDetails'][-1]['in_confirmed_package']=True
  self.assertFalse(m.row_ledger(facts)['allRowsAccounted'])
 def test_missing_or_duplicated_handoff_never_closes_ledger(self):
  for rows in (self.facts()['sourceDetails'][:-1],self.facts()['sourceDetails'][:-1]+[self.row(1)]):
   with self.assertRaises(ValueError):m.row_ledger(dict(sourceRowCount=13,sourceDetails=rows))
 def test_upstream_checks_identity_and_lineage(self):
  udp=self.facts();up=[dict(handoff_id=r['handoff_id'],state='ACKED',receipt_present=True,lineage_verified=True) for r in udp['sourceDetails']]
  ing=dict(runs=[dict(runId='a3208f2f-ebfd-415d-bddc-79ab05dea78f',state='SUCCEEDED',lineageCount=13,ackedReceipts=13,handoffDetails=up)])
  self.assertTrue(m.upstream_matches(ing,udp));up[0]['lineage_verified']=False;self.assertFalse(m.upstream_matches(ing,udp))
 def test_upstream_query_minimizes_and_closes_input(self):
  raw=m.ingestion_query('ingestion','ouf-lab');self.assertTrue(raw.startswith('BEGIN READ ONLY;'));self.assertTrue(raw.endswith('ROLLBACK;'))
  self.assertNotRegex(raw,r'(?i)\\b(insert|update|delete|truncate|alter|create|grant|revoke)\\b')
  self.assertNotIn('payload_json',raw);self.assertNotIn('downstream_receipt_ref,',raw)
  with self.assertRaises(ValueError):m.ingestion_query('ingestion',"x';--")


 def test_thirteen_rows_can_commit_to_twelve_existing_objects(self):
  facts=self.facts();facts['sourceDetails'][-1]=self.row(13,True)
  facts['sourceDetails'][-1]['urban_object_id']=facts['sourceDetails'][0]['urban_object_id']
  ledger=m.row_ledger(facts);self.assertEqual(ledger['distinctCommittedObjects'],12)
  self.assertEqual(ledger['committedRows'],13);self.assertTrue(ledger['allThirteenMaterializedProven'])
  self.assertTrue(ledger['expectedCurrentDispositionProven'])
 def test_closed_review_without_commit_is_not_completion(self):
  facts=self.facts();facts['sourceDetails'][-1]['open_issue_count']=0
  ledger=m.row_ledger(facts);self.assertFalse(ledger['allThirteenMaterializedProven']);self.assertEqual(ledger['unprovenRows'],1)
 def test_final_progress_can_be_emitted_only_as_computed_result(self):
  import contextlib,io
  output=io.StringIO()
  with contextlib.redirect_stdout(output):m.emit('END',functionalMilestonesProven=3,functionalStage3Proven=True)
  result=json.loads(output.getvalue());self.assertEqual(result['functionalMilestonesProven'],3)
  self.assertTrue(result['readOnly']);self.assertEqual(result['jobsRetried'],0)

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
   create table ouf_udp.flyway_schema_history(installed_rank integer,version text,script text,checksum integer,success boolean);
   insert into ouf_udp.flyway_schema_history values(35,'35','V35__fixture.sql',-376865285,true);
   create table ouf_udp.lake_object(lake_object_id uuid,tenant_id text);
   create table ouf_udp.handoff_intake(handoff_id text,source_id text,ingestion_run_id text,type_code text,raw_lake_object_id uuid,state text,source_object_id text,content_hash text default 'fixture-hash');
   create table ouf_udp.human_resolution_decision(issue_id uuid,action text,actor_subject text,decided_at timestamptz,authorization_decision_ref text);
   create table ouf_udp.resolution_issue(issue_id uuid,handoff_id text,state text,tenant_id text,reason_code text);
   create table ouf_udp.materialization_job(handoff_id text,state text,safe_failure_code text);
   create table ouf_udp.source_binding(source_id text,type_code text,source_object_id text,urban_object_id uuid,state text);
   create table ouf_udp.urban_object(urban_object_id uuid,tenant_id text,status text,current_revision_id uuid);
   create table ouf_udp.materialization_observation(handoff_id text,urban_object_id uuid,revision_id uuid);
   create table ouf_udp.object_revision(urban_object_id uuid,revision_id uuid);
   create table ouf_udp.property_contribution(handoff_id text,urban_object_id uuid,source_id text default 'teatri-csv-6609b245');
   insert into ouf_udp.resolution_review_package_confirmation values('a5183503-04ff-4e10-850f-e22bf874365e','ouf-lab','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','2026-10-17T16:00:00Z','fixture-auth',11);
   insert into ouf_udp.lake_object select md5(n::text)::uuid,case when n=14 then 'other-tenant' else 'ouf-lab' end from generate_series(1,14)n;
   insert into ouf_udp.handoff_intake(handoff_id,source_id,ingestion_run_id,type_code,raw_lake_object_id,state,source_object_id) select 'h'||n,'teatri-csv-6609b245','run-ref:source-envelope','SOURCE_ROW_TYPE',null,case when n=13 then 'DURABLE' else 'PROCESSED' end,'PRIVATE_SOURCE_'||n from generate_series(1,14)n;
   insert into ouf_udp.resolution_issue select md5(n::text)::uuid,'h'||n,case when n=13 then 'OPEN' else 'RESOLVED' end,case when n=14 then 'other-tenant' else 'ouf-lab' end,'UNRESOLVED_IDENTITY' from generate_series(2,14)n;
   insert into ouf_udp.human_resolution_decision select md5(n::text)::uuid,'CREATE_NEW','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','2026-10-17T16:00:00Z','fixture-auth' from generate_series(2,12)n;
   insert into ouf_udp.materialization_job select 'h'||n,case when n=13 then 'QUARANTINED' else 'SUCCEEDED' end,case when n=13 then 'UDP_IDENTITY_REVIEW_REQUIRED' else null end from generate_series(1,14)n;
   insert into ouf_udp.source_binding select 'teatri-csv-6609b245','SOURCE_ROW_TYPE','PRIVATE_SOURCE_'||n,case when n=1 then 'd6051381-934b-4a11-8e71-e1d89cee4e49'::uuid else md5(n::text)::uuid end,'ACTIVE' from generate_series(1,12)n;
   insert into ouf_udp.urban_object select case when n=1 then 'd6051381-934b-4a11-8e71-e1d89cee4e49'::uuid else md5(n::text)::uuid end,'ouf-lab','ACTIVE',md5(('rev'||n))::uuid from generate_series(1,12)n;
   insert into ouf_udp.materialization_observation select 'h'||n,case when n=1 then 'd6051381-934b-4a11-8e71-e1d89cee4e49'::uuid else md5(n::text)::uuid end,md5(('rev'||n))::uuid from generate_series(1,12)n;
   insert into ouf_udp.object_revision select case when n=1 then 'd6051381-934b-4a11-8e71-e1d89cee4e49'::uuid else md5(n::text)::uuid end,md5(('rev'||n))::uuid from generate_series(1,12)n;
   insert into ouf_udp.property_contribution(handoff_id,urban_object_id) select 'h'||n,case when n=1 then 'd6051381-934b-4a11-8e71-e1d89cee4e49'::uuid else md5(n::text)::uuid end from generate_series(1,12)n;
  """)
  raw=sql(m.acquisition_query('udp','ouf-lab'));self.assertNotIn('PRIVATE_SOURCE_',raw);facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);self.assertEqual(facts['sourceRowCount'],13);self.assertTrue(m.materialization_proven(facts));self.assertEqual(len(facts['details']),11)
  ledger=m.row_ledger(facts);self.assertEqual(ledger['committedRows'],12);self.assertEqual(ledger['quarantinedRows'],1)
  self.assertTrue(ledger['allRowsAccounted']);self.assertTrue(ledger['originalObjectRetained']);self.assertFalse(ledger['allThirteenMaterializedProven'])
  self.assertTrue(ledger['expectedCurrentDispositionProven'])
  # A current revision without a verified observation is not a materialized row proof.
  sql("delete from ouf_udp.object_revision where urban_object_id='d6051381-934b-4a11-8e71-e1d89cee4e49';")
  missing=json.loads(sql(m.acquisition_query('udp','ouf-lab')));self.assertFalse(m.row_ledger(missing)['allRowsAccounted'])
  sql("insert into ouf_udp.object_revision values('d6051381-934b-4a11-8e71-e1d89cee4e49',md5('rev1')::uuid);")
  sql("insert into ouf_udp.materialization_job values('h1','SUCCEEDED',null);")
  duplicate=json.loads(sql(m.acquisition_query('udp','ouf-lab')));self.assertFalse(m.row_ledger(duplicate)['allRowsAccounted'])
  sql("delete from ouf_udp.materialization_job where handoff_id='h1';insert into ouf_udp.materialization_job values('h1','SUCCEEDED',null);")

  sql("update ouf_udp.materialization_job set state='QUARANTINED',safe_failure_code='UDP_IDENTITY_COVERAGE_UNVERIFIED' where handoff_id='h2';")
  facts=json.loads(sql(m.acquisition_query('udp','ouf-lab')));self.assertEqual(facts['matchedDecisionCount'],11);self.assertEqual(facts['confirmedMaterializedRows'],10);self.assertFalse(m.materialization_proven(facts))
  facts=json.loads(sql(m.acquisition_query('udp','other-tenant')));self.assertEqual(facts['receiptCount'],0);self.assertEqual(facts['matchedDecisionCount'],0);self.assertFalse(m.materialization_proven(facts))

  # The HUMAN can resolve the review before the materializer finishes.
  sql("update ouf_udp.materialization_job set state='SUCCEEDED',safe_failure_code=null where handoff_id='h2';update ouf_udp.resolution_issue set state='RESOLVED' where handoff_id='h13';")
  sql("insert into ouf_udp.human_resolution_decision values(md5('13')::uuid,'APPROVE','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','2026-10-17T17:00:00Z','fixture-second-auth');")
  closed=json.loads(sql(m.acquisition_query('udp','ouf-lab')))
  self.assertFalse(any(x['state']=='OPEN' for x in closed['sourceIssues']))
  self.assertFalse(m.row_ledger(closed)['allThirteenMaterializedProven'])
  last=next(r for r in closed['sourceDetails']if r['handoff_id']=='h13')
  self.assertEqual(last['latest_decision']['action'],'APPROVE');self.assertEqual(last['job_state'],'QUARANTINED')
  # All13commits are valid when the final contribution links to an existing object.
  sql("""
   update ouf_udp.handoff_intake set state='PROCESSED' where handoff_id='h13';
   update ouf_udp.materialization_job set state='SUCCEEDED',safe_failure_code=null where handoff_id='h13';
   insert into ouf_udp.source_binding values('teatri-csv-6609b245','SOURCE_ROW_TYPE','PRIVATE_SOURCE_13','d6051381-934b-4a11-8e71-e1d89cee4e49','ACTIVE');
   insert into ouf_udp.materialization_observation values('h13','d6051381-934b-4a11-8e71-e1d89cee4e49',md5('rev1')::uuid);
   insert into ouf_udp.property_contribution(handoff_id,urban_object_id) values('h13','d6051381-934b-4a11-8e71-e1d89cee4e49');
  """)
  complete=json.loads(sql(m.acquisition_query('udp','ouf-lab')));ledger=m.row_ledger(complete)
  self.assertEqual(ledger['committedRows'],13);self.assertEqual(ledger['distinctCommittedObjects'],12)
  self.assertTrue(ledger['allThirteenMaterializedProven']);self.assertTrue(ledger['confirmedElevenMaterialized'])
  sql("""
   create schema ouf_ingestion;
   create table ouf_ingestion.ing_run(run_id uuid,source_id text,tenant_id text,state text,phase text,failure_code text,created_at timestamptz,updated_at timestamptz);
   create table ouf_ingestion.ing_schedule(source_id text,tenant_id text,state text,publication_id uuid,publication_sequence bigint,trigger_once boolean,publication_enabled boolean,consumed_publication_id uuid,activation_failures integer,activation_blocked boolean,discovery_verified_at timestamptz,next_run_at timestamptz);
   create table ouf_ingestion.ing_partition(run_id uuid);
   create table ouf_ingestion.processing_attempt(run_id uuid,state text);
   create table ouf_ingestion.ing_lineage(lineage_id uuid,run_id uuid);
   create table ouf_ingestion.handoff_outbox(handoff_id text,run_id uuid,lineage_id uuid,state text,downstream_receipt_ref text);
   create table ouf_ingestion.ing_quarantine(run_id uuid,state text,reason_code text);
   create table ouf_ingestion.source_health(source_id text,status text,consecutive_failures integer,last_error_code text,updated_at timestamptz);
   insert into ouf_ingestion.ing_run values('a3208f2f-ebfd-415d-bddc-79ab05dea78f','teatri-csv-6609b245','ouf-lab','SUCCEEDED','MANAGED_ONCE',null,now(),now());
   insert into ouf_ingestion.ing_lineage select md5(n::text)::uuid,'a3208f2f-ebfd-415d-bddc-79ab05dea78f'::uuid from generate_series(1,13)n;
   insert into ouf_ingestion.handoff_outbox select 'h'||n,'a3208f2f-ebfd-415d-bddc-79ab05dea78f'::uuid,md5(n::text)::uuid,'ACKED','PRIVATE_RECEIPT' from generate_series(1,13)n;
  """)
  raw=sql(m.ingestion_query('ingestion','ouf-lab'));self.assertNotIn('PRIVATE_',raw);up=json.loads(raw)
  down=json.loads(sql(m.acquisition_query('udp','ouf-lab')))
  self.assertTrue(m.upstream_matches(up,down));self.assertTrue(up['transactionReadOnly'])
  sql("update ouf_ingestion.handoff_outbox set downstream_receipt_ref=null where handoff_id='h1';")
  self.assertFalse(m.upstream_matches(json.loads(sql(m.ingestion_query('ingestion','ouf-lab'))),down))
  sql("update ouf_ingestion.handoff_outbox set downstream_receipt_ref='PRIVATE_RECEIPT';delete from ouf_ingestion.ing_lineage where lineage_id=md5('1')::uuid;")
  self.assertFalse(m.upstream_matches(json.loads(sql(m.ingestion_query('ingestion','ouf-lab'))),down))

if __name__=='__main__':unittest.main()
