import importlib.util,json,os,subprocess,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-teatri-active-acquisition-20261017.py');reader=importlib.util.module_from_spec(s);s.loader.exec_module(reader)
def sql(value):
 p=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=value,text=True,capture_output=True,timeout=20)
 if p.returncode:raise AssertionError(p.stderr)
 return p.stdout
class ActualPostgresRead(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  for repo,names in [('ingestion',['V1__ingestion_runtime_core.sql','V4__scheduler_and_source_health.sql','V14__published_activation_schedule.sql']),('udp',['V1__handoff_and_resolution_core.sql','V2__canonical_revision_authority.sql','V7__governed_serving.sql'])]:
   for name in names:sql((ROOT/repo/'src/main/resources/db/migration'/name).read_text())
  sql("""
   insert into ouf_ingestion.ing_run(run_id,source_id,bundle_id,bundle_version,bundle_checksum,mode,state,correlation_id,tenant_id,created_at)
   select ('00000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,'teatri-csv-6609b245','bundle','1','hash','MANAGED_ONCE','RUNNING','fixture','ouf-lab',clock_timestamp()+(n*interval '1 second') from generate_series(1,4)n;
   insert into ouf_ingestion.processing_attempt values('00000000-0000-0000-0001-000000000001','00000000-0000-0000-0000-000000000004','PRIVATE_SOURCE_VALUE',1,'managed-tabular-v1','1','SUCCEEDED',null,clock_timestamp());
   insert into ouf_ingestion.ing_lineage values('00000000-0000-0000-0002-000000000001','00000000-0000-0000-0000-000000000004','00000000-0000-0000-0001-000000000001','PRIVATE_SOURCE_VALUE','bundle','adapter','{"PRIVATE_EVIDENCE":true}',clock_timestamp());
   insert into ouf_ingestion.handoff_outbox(handoff_id,run_id,lineage_id,idempotency_key,payload_json,state,downstream_receipt_ref) values('00000000-0000-0000-0003-000000000001','00000000-0000-0000-0000-000000000004','00000000-0000-0000-0002-000000000001','fixture','{"PRIVATE_PAYLOAD":true}','ACKED','PRIVATE_RECEIPT');
   insert into ouf_udp.handoff_intake(handoff_id,ingestion_run_id,ingestion_id,source_id,type_code,source_object_id,content_hash,payload_json,receipt_ref,state) values('handoff','run','ingestion','teatri-csv-6609b245','https://schema.org/PerformingArtsTheater','PRIVATE_SOURCE_VALUE','hash','{"PRIVATE_PAYLOAD":true}','PRIVATE_RECEIPT','PROCESSED');
   insert into ouf_udp.urban_object(urban_object_id,canonical_type,tenant_id) values('00000000-0000-0000-0004-000000000001','https://schema.org/PerformingArtsTheater','ouf-lab');
   insert into ouf_udp.source_binding(source_id,type_code,source_object_id,urban_object_id,first_handoff_id) values('teatri-csv-6609b245','https://schema.org/PerformingArtsTheater','PRIVATE_SOURCE_VALUE','00000000-0000-0000-0004-000000000001','handoff');
   insert into ouf_udp.property_contribution(contribution_id,urban_object_id,handoff_id,property_iri,value_json,value_hash,access_label,source_id,authority_rank,provenance_json) values('00000000-0000-0000-0005-000000000001','00000000-0000-0000-0004-000000000001','handoff','https://schema.org/name','"PRIVATE_PROPERTY"','hash','RESTRICTED','teatri-csv-6609b245',1,'{"PRIVATE_PROVENANCE":true}');
  """)
 def test_ingestion_bounded_runs_and_receipts_without_payload(self):
  raw=sql(reader.acquisition_query('ingestion','ouf-lab'));self.assertNotIn('PRIVATE_',raw)
  row=json.loads(raw);self.assertTrue(row['transactionReadOnly']);self.assertEqual(len(row['runs']),3)
  run=next(r for r in row['runs']if r['runId'].endswith('000000000004'))
  self.assertEqual(run['lineageCount'],1);self.assertEqual(run['ackedReceipts'],1)
 def test_udp_source_counts_without_properties_or_provenance(self):
  raw=sql(reader.acquisition_query('udp','ouf-lab'));self.assertNotIn('PRIVATE_',raw)
  row=json.loads(raw);self.assertTrue(row['transactionReadOnly']);self.assertEqual(row['sourceBindings'],1)
  self.assertEqual(row['distinctBoundObjects'],1);self.assertEqual(row['propertyContributions'],1)
 def test_other_tenant_cannot_read_bound_objects_and_literals_are_closed(self):
  row=json.loads(sql(reader.acquisition_query('udp','other-tenant')));self.assertEqual(row['sourceBindings'],0)
  with self.assertRaises(ValueError):reader.acquisition_query('udp',"ouf-lab'; select 1")
if __name__=='__main__':unittest.main()
