import importlib.util,json,os,subprocess,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
s=importlib.util.spec_from_file_location('diag',Path(__file__).resolve().parents[2]/'scripts/read-csv-post-resolution-references-20261018.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_exact_read_only_scope(self):
  raw=m.reference_query('udp','ouf-lab')
  self.assertTrue(raw.startswith('BEGIN READ ONLY;'));self.assertTrue(raw.endswith('ROLLBACK;'))
  self.assertNotRegex(raw,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b')
  self.assertIn("payload_json->'contractRefs'",raw);self.assertNotIn('canonicalPayload',raw)
  self.assertIn('9fde61f1-8d3c-4de7-b3fe-b534b32e45e3',raw)
  with self.assertRaises(ValueError):m.reference_query('udp',"x';--")
 def test_get_status_redacts_and_never_follows_redirects(self):
  for code in (200,401,403,302):
   response=Mock(status=code);response.read.return_value=b'{"error_description":"PRIVATE_CREDENTIAL","detail":"Owner authorization denied"}'
   conn=Mock();conn.getresponse.return_value=response
   with patch.object(m.http.client,'HTTPSConnection',return_value=conn):
    safe,_=m.safe_get('https://approved.example','/api/x',b'PRIVATE_TOKEN')
   self.assertEqual(safe['httpStatus'],code);self.assertNotIn('PRIVATE_',json.dumps(safe))
   conn.request.assert_called_once();self.assertEqual(conn.request.call_args.args[0],'GET')
  with self.assertRaises(ValueError):m.safe_get('http://unapproved.example','/api/x',b'PRIVATE_TOKEN')
 def test_config_and_counter_no_renewal(self):
  actual={'Config':{'Env':['OUF_UDP_EXECUTION_GATEWAY_URL=https://approved.example','OUF_UDP_EXECUTION_TOKEN_FILE=/run/secrets/token']}}
  self.assertEqual(m.configured_properties(actual,None),('https://approved.example','/run/secrets/token',None))
  import contextlib,io
  with patch.object(m,'CREDENTIAL_FILES_READ',1),contextlib.redirect_stdout(io.StringIO())as out:m.emit('TEST')
  value=json.loads(out.getvalue());self.assertEqual(value['credentialFilesRead'],1)
  self.assertEqual(value['jobsRetried'],0);self.assertEqual(value['oauthRequests'],0)
@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','actual PostgreSQL17 required')
class NativeSql(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1500:]);return r.stdout.decode().strip()
 def test_exact_job_metadata_and_tenant_isolation(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-U','postgres'],capture_output=True).returncode:
   self.assertLess(time.monotonic(),end);time.sleep(.2)
  def sql(raw):return self.cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',raw)
  sql("""
  create schema ouf_udp;
  create table ouf_udp.handoff_intake(handoff_id text,state text,payload_json jsonb,source_id text,type_code text,source_object_id text,raw_lake_object_id uuid);
  create table ouf_udp.materialization_job(handoff_id text,job_id uuid,state text,state_version bigint,attempts int,integrity_attempts int,safe_failure_code text,missing_ref_hashes jsonb,integrity_baseline_hash text,claimed_by text,lease_until timestamptz);
  create table ouf_udp.resolution_issue(handoff_id text,issue_id uuid,state text,tenant_id text);
  create table ouf_udp.human_resolution_decision(issue_id uuid,action text,decided_at timestamptz);
  create table ouf_udp.lake_object(lake_object_id uuid,tenant_id text,state text);
  create table ouf_udp.source_binding(first_handoff_id text,source_id text,type_code text,source_object_id text);
  create table ouf_udp.materialization_observation(handoff_id text);
  create table ouf_udp.property_contribution(handoff_id text);
  insert into ouf_udp.handoff_intake values('9fde61f1-8d3c-4de7-b3fe-b534b32e45e3','DURABLE','{"contractRefs":{"bundleRef":"urn:fixture"},"canonicalPayload":{"PRIVATE_VALUE":"PRIVATE_VALUE"}}','teatri-csv-6609b245','TYPE','PRIVATE_OBJECT_ID',null);
  insert into ouf_udp.materialization_job values('9fde61f1-8d3c-4de7-b3fe-b534b32e45e3',md5('job')::uuid,'QUARANTINED',17,1,5,'UDP_REFERENCE_INTEGRITY_MISSING','["sha256:fixture"]','sha256:baseline',null,null);
  insert into ouf_udp.resolution_issue values('9fde61f1-8d3c-4de7-b3fe-b534b32e45e3','e16fec6e-311d-49f3-b1de-f274cb5a92d1','RESOLVED','ouf-lab');
  insert into ouf_udp.human_resolution_decision values('e16fec6e-311d-49f3-b1de-f274cb5a92d1','CREATE_NEW',now());
  """)
  raw=sql(m.reference_query('udp','ouf-lab'));self.assertNotIn('PRIVATE_',raw);facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);self.assertEqual(facts['selectedJobCount'],1)
  row=facts['jobs'][0];self.assertEqual(row['issue_state'],'RESOLVED');self.assertEqual(row['latest_action'],'CREATE_NEW')
  self.assertEqual(row['integrity_attempts'],5);self.assertEqual(row['state_version'],17);self.assertEqual(row['binding_count'],0)
  self.assertEqual(row['safe_failure_code'],'UDP_REFERENCE_INTEGRITY_MISSING')
  self.assertEqual(json.loads(sql(m.reference_query('udp','other-tenant')))['selectedJobCount'],0)
if __name__=='__main__':unittest.main()
