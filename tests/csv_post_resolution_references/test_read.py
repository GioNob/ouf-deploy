import importlib.util,json,os,subprocess,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
s=importlib.util.spec_from_file_location('diag',Path(__file__).resolve().parents[2]/'scripts/read-csv-post-resolution-references-20261018.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_delivered_source_matches_pinned_hash(self):
  import hashlib
  root=Path(__file__).resolve().parents[2]
  source=(root/'scripts/read-csv-post-resolution-references-20261018.py').read_bytes()
  launcher=(root/'scripts/launch-csv-post-resolution-references-20261018.sh').read_text()
  self.assertIn(hashlib.sha256(source).hexdigest(),launcher)
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

 def test_safe_semantic_error_identifies_layer_without_echoing_values(self):
  response=Mock(status=403);response.read.return_value=b'{"message":"SEM_CAPABILITY_REQUIRED:ouf.semantic.read","detail":"PRIVATE_SUBJECT_AND_TOKEN"}'
  conn=Mock();conn.getresponse.return_value=response
  with patch.object(m.http.client,'HTTPSConnection',return_value=conn):
   safe,_=m.safe_get('https://approved.example','/api/semantic/v1/references:resolve',b'PRIVATE_TOKEN')
  self.assertEqual(safe['message'],'SEM_CAPABILITY_REQUIRED:ouf.semantic.read')
  self.assertNotIn('PRIVATE_',json.dumps(safe))
 def test_retained_route_scope_is_metadata_and_not_live_proof(self):
  import contextlib,io
  route={'id':'fixture','uri':'/api/semantic/v1/references:resolve','methods':['GET'],'plugins':{'openid-connect':{'required_scopes':['ouf.semantic.read'],'client_id':'owner','bearer_only':True}}}
  with contextlib.redirect_stdout(io.StringIO())as out:
   m.emit_route_access_metadata({'gateway':{'afterRoutes':{'fixture':route}}},{'scope':'other','client_id':'ouf-udp','ouf_actor_type':'SERVICE','aud':['owner']})
  result=json.loads(out.getvalue());self.assertFalse(result['requiredScopesPresentInToken'])
  self.assertFalse(result['liveRouteInventoryProven']);self.assertTrue(result['audienceMatchesRoute'])


 def test_worker_history_preserves_cumulative_budget_without_new_session(self):
  import contextlib,io
  review={'retained':'fixture'};review_hash=m.digest(review);journal=m.POLICY_CONTEXT.parent/('semantic-functional-worker-'+review_hash)
  fence_path=journal.parent/'semantic-functional-session-fixture.fence.json'
  fence={'schema':'ouf.semantic-functional-session-fence.v1','logicalOwnerScopeHash':'fixture','reviewHash':review_hash,'journalPath':str(journal)}
  signed={'fenceBinding':{'path':str(fence_path),'value':fence},'reviewHash':review_hash,'predecessorGrantAttempts':248,'maximumCumulativeGrantAttempts':316,'policy':{'max_attempts':68}}
  row={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':60,'publicationCount':60,'controlledPredecessorGrantAttempts':248,'controlledCumulativeGrantAttempts':308}
  files={str(m.POLICY_CONTEXT/'review.json'):{'scopes':{'policyTokenFiniteWorkerSession':{'fenceBinding':{'path':str(fence_path)},'logicalOwnerScopeHash':'fixture'}}},str(fence_path):fence,str(journal/'owner-session.json'):signed,str(journal/'owner-session-review.json'):review,str(journal/'recovery.json'):row,str(journal/'owner-status.json'):{},str(journal/'owner-admission.json'):{}}
  read=Mock(side_effect=lambda p,*args:files[str(p)])
  with patch.object(m,'unlocked',return_value=True),contextlib.redirect_stdout(io.StringIO())as out:
   m.policy_worker_metadata({'read':read})
  result=json.loads(out.getvalue());self.assertEqual(result['controlledCumulativeGrantAttempts'],308)
  self.assertEqual(result['remainingControlledGrantAttempts'],8);self.assertFalse(result['newWorkerStarted'])
  row['controlledCumulativeGrantAttempts']=1
  with self.assertRaisesRegex(ValueError,'EXACT_CURRENT_CUMULATIVE_BUDGET_REQUIRED'):m.policy_worker_metadata({'read':read})

@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','actual PostgreSQL17 required')
class NativeSql(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1500:]);return r.stdout.decode().strip()
 def test_exact_job_metadata_and_tenant_isolation(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:
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

  caps=[{'capabilityId':'ouf.semantic.read','allowedActors':['SERVICE'],'requiredScope':'ouf.semantic.read','operation':'READ'}]
  grants=[{'capabilityId':'ouf.semantic.read','tenantId':tenant,'servicePrincipalId':service,'subjectId':'PRIVATE_SUBJECT','validFrom':'2020-01-01T00:00:00Z','validUntil':expiry,'constraints':{'effect':'ALLOW','resourceType':resource,'resourceAttributes':{'module':'SEMANTIC'}}} for tenant,service,resource,expiry in [('ouf-lab','ouf-udp','semantic.validation','2099-01-01T00:00:00Z'),('ouf-lab','ouf-udp','semantic.validation','2020-01-02T00:00:00Z'),('ouf-lab','other','semantic.artifact','2099-01-01T00:00:00Z'),('other','ouf-udp','semantic.validation','2099-01-01T00:00:00Z')]]
  payload=json.dumps({'capabilities':caps,'grants':grants})
  sql("create schema ouf_authorization;create table ouf_authorization.policy_bundle(bundle_id text,version bigint,bundle_payload jsonb);create table ouf_authorization.active_policy_bundle(singleton_key boolean,bundle_id text,version bigint);insert into ouf_authorization.policy_bundle values('fixture',42,'"+payload+"');insert into ouf_authorization.active_policy_bundle values(true,'fixture',42);")
  raw=sql(m.semantic_policy_query('ouf-lab',{'sub':'PRIVATE_SUBJECT','client_id':'ouf-udp'}));result=json.loads(raw)
  self.assertTrue(result['transactionReadOnly']);self.assertEqual(result['bundleVersion'],42)
  self.assertNotIn('PRIVATE_',raw);self.assertEqual(len(result['grants']),3)
  matches=[g for g in result['grants']if g['servicePrincipalMatchesToken'] and g['subjectMatchesToken'] and g['resourceTypeMatchesValidation']]
  self.assertEqual(len(matches),2);self.assertEqual(sum(g['validAtRead'] for g in matches),1)

if __name__=='__main__':unittest.main()
