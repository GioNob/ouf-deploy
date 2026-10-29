import importlib.util,json,os,re,subprocess,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-teatri-semantic-reference-access-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_registry_is_bound_to_hash_verified_review_and_not_service_name(self):
  pin={'containerId':'a'*64,'imageId':'sha256:reviewed'}
  link={'path':str(m.POLICY_CONTEXT/'worker-review.json'),'sha256':'b'*64}
  actual={'State':{'Running':True}}
  read=Mock(side_effect=[{'workerReviewBinding':link},{'registryGeneration':pin}]);get=Mock(return_value=actual)
  ns={'read':read,'engine_get':get,'runtime_pin':lambda a:pin}
  self.assertIs(m.reviewed_registry(ns,{'socketPath':'fixture'}),actual)
  self.assertEqual(read.call_args_list[0].args,(m.POLICY_CONTEXT/'review.json',8388608,m.POLICY_REVIEW))
  self.assertEqual(read.call_args_list[1].args,(link['path'],8388608,link['sha256']))
  self.assertEqual(get.call_args.args[2],'a'*64);get.assert_called_once()
  ns['read']=Mock(side_effect=[{'workerReviewBinding':link},{'registryGeneration':pin}]);ns['runtime_pin']=lambda a:{**pin,'imageId':'changed'}
  with self.assertRaisesRegex(ValueError,'CURRENT_REVIEWED_REGISTRY_GENERATION_REQUIRED'):m.reviewed_registry(ns,{})
  ns['read']=Mock(return_value={'workerReviewBinding':{**link,'path':'/unreviewed/file'}});get.reset_mock()
  with self.assertRaisesRegex(ValueError,'EXACT_WORKER_REVIEW_LINK_REQUIRED'):m.reviewed_registry(ns,{})
  get.assert_not_called()
 def test_single_readonly_transaction_and_only_contract_refs_from_payload(self):
  sql=m.acquisition_query('udp','ouf-lab');self.assertTrue(sql.startswith('BEGIN READ ONLY;'));self.assertTrue(sql.endswith('ROLLBACK;'));self.assertNotRegex(sql,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b')
  self.assertIn("payload_json->'contractRefs'",sql);self.assertNotIn('canonicalPayload',sql)
  for value in("x'; drop table x;--",'x\\y'):
   with self.assertRaises(ValueError):m.acquisition_query('udp',value)
 def test_one_get_does_not_follow_redirect_or_print_arbitrary_error_text(self):
  for code in(401,403,302):
   response=Mock(status=code);response.read.return_value=b'{"detail":"Owner authorization denied","error_description":"PRIVATE_CREDENTIAL_VALUE"}'
   conn=Mock();conn.getresponse.return_value=response
   with patch.object(m.http.client,'HTTPSConnection',return_value=conn):
    safe,body=m.safe_get('https://approved.example','/api/onboarding/v1/runtime/publications/resolve?bundleRef=fixture',b'PRIVATE_TOKEN')
   self.assertEqual(safe['httpStatus'],code);self.assertNotIn('PRIVATE_',json.dumps(safe));conn.request.assert_called_once();self.assertEqual(conn.request.call_args.args[0],'GET');conn.close.assert_called_once()
  with self.assertRaisesRegex(ValueError,'REVIEWED_HTTPS_ORIGIN_REQUIRED'):m.safe_get('http://unapproved.example','/api/x',b'PRIVATE_TOKEN')

 def test_selected_environment_and_literal_yaml_config_are_read_without_secrets(self):
  actual={'Config':{'Env':['OUF_UDP_EXECUTION_GATEWAY_URL=https://approved.example','OUF_UDP_EXECUTION_TOKEN_FILE=/run/secrets/token']}}
  with patch.object(m,'mounted_file',side_effect=AssertionError('no file read required')):
   self.assertEqual(m.configured_properties(actual,None),('https://approved.example','/run/secrets/token',None))
  owner={'Config':{'Env':['REGISTRY_URL=https://approved.example/internal/capabilities/v1/authorization/policy-bundle/active','REGISTRY_TOKEN_FILE=/run/secrets/policy']}}
  with patch.object(m,'mounted_file',side_effect=AssertionError('no file read required')):
   endpoint,token,_=m.configured_properties(owner,None,('ouf.authorization.registry-url','ouf.authorization.registry-token-file'))
  self.assertTrue(endpoint.endswith('/active'));self.assertEqual(token,'/run/secrets/policy')
  actual={'Config':{'Env':['SPRING_CONFIG_LOCATION=file:/run/secrets/udp.yml']}}
  raw=b'ouf:\n  udp:\n    execution:\n      gateway-url: https://approved.example\n      token-file: /run/secrets/token\n'
  with patch.object(m,'mounted_file',return_value=raw):
   gateway,token,sha=m.configured_properties(actual,None)
  self.assertEqual((gateway,token),('https://approved.example','/run/secrets/token'));self.assertEqual(len(sha),64)
 def test_credential_read_counter_is_preserved_in_redacted_status(self):
  import contextlib,io
  with patch.object(m,'CREDENTIAL_FILES_READ',1),contextlib.redirect_stdout(io.StringIO())as out:m.emit('TEST_METADATA')
  value=json.loads(out.getvalue());self.assertEqual(value['credentialFilesRead'],1);self.assertFalse(value['credentialValuesPrinted'])

 def test_retained_route_compares_only_required_scope_audience_and_workload_allowlist(self):
  import io,contextlib
  fn='local allowed_services={["ouf-udp"]=true}; local allowed_actors={["SERVICE"]=true};'
  route={'id':'r2b-semantic-reference','uri':'/api/semantic/v1/references:resolve','methods':['GET'],'plugins':{'openid-connect':{'client_id':'gateway','bearer_only':True,'required_scopes':['ouf.semantic.read']},'serverless-post-function':{'functions':[fn]}}}
  plan={'gateway':{'afterRoutes':{'r2b-semantic-reference':route}}}
  claims={'scope':'ouf.semantic.read','ouf_actor_type':'SERVICE','client_id':'ouf-udp','aud':['gateway'],'sub':'PRIVATE_SUBJECT'}
  with contextlib.redirect_stdout(io.StringIO())as out:m.emit_route_access_metadata(plan,claims)
  metadata=json.loads(out.getvalue());self.assertTrue(metadata['requiredScopesPresentInToken']);self.assertTrue(metadata['servicePrincipalAllowedByRetainedGuard']);self.assertTrue(metadata['actorAllowedByRetainedGuard']);self.assertNotIn('PRIVATE_',out.getvalue())
  claims['scope']='unrelated'
  with contextlib.redirect_stdout(io.StringIO())as out:m.emit_route_access_metadata(plan,claims)
  self.assertFalse(json.loads(out.getvalue())['requiredScopesPresentInToken'])
  with contextlib.redirect_stdout(io.StringIO())as out:m.emit_route_access_metadata({'gateway':{'afterRoutes':{}}},claims)
  self.assertEqual(json.loads(out.getvalue())['exactRouteCount'],0)
 def test_owner_metadata_matches_service_scope_and_resource_without_exposing_subject(self):
  import hashlib
  bundle={'capabilities':[{'capabilityId':'ouf.semantic.read','requiredScope':'ouf.semantic.read','allowedActors':['SERVICE']}],
   'grants':[{'capabilityId':'ouf.semantic.read','tenantId':'ouf-lab','servicePrincipalId':principal,'subjectId':'PRIVATE_SUBJECT','validFrom':'2020-01-01T00:00:00Z','validUntil':'2099-01-01T00:00:00Z','constraints':{'effect':'ALLOW','resourceType':resource,'resourceAttributes':{'module':'SEMANTIC'}}}for principal,resource in [('ouf-udp','semantic.validation'),('ouf-ingestion','semantic.artifact')]]}
  doc={'bundleVersion':40,'bundle':bundle,'contentHash':hashlib.sha256(json.dumps(bundle,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()}
  claims={'tenant_id':'ouf-lab','sub':'PRIVATE_SUBJECT','client_id':'ouf-udp'}
  facts=m.policy_metadata(doc,claims);self.assertTrue(facts['compactBundleHashMatchesEnvelope']);self.assertFalse(facts['loadedOwnerSnapshotProven']);self.assertEqual(len(facts['grants']),2)
  matches=[g for g in facts['grants']if g['servicePrincipalMatchesToken']];self.assertEqual(len(matches),1);self.assertTrue(matches[0]['resourceTypeMatchesValidation']);self.assertTrue(matches[0]['subjectMatchesToken']);self.assertNotIn('PRIVATE_SUBJECT',json.dumps(facts))
  doc['contentHash']='0'*64;self.assertNotIn('grants',m.policy_metadata(doc,claims))
  claims['tenant_id']='other-tenant';doc['contentHash']=hashlib.sha256(json.dumps(bundle,separators=(',',':'),ensure_ascii=False).encode()).hexdigest();self.assertEqual(m.policy_metadata(doc,claims)['grants'],[])
 def test_owner_transport_probe_reads_one_additional_token_and_never_prints_it(self):
  import base64,contextlib,io
  claims=base64.urlsafe_b64encode(json.dumps({'exp':4102444800}).encode()).rstrip(b'=')
  token=b'e30.'+claims+b'.c2lnbmF0dXJl'
  actual={'State':{'Pid':123}};real_open=os.open
  with patch.object(m.Path,'read_text',return_value='123 (fixture) '+' '.join(['0']*20)),patch.object(m.os,'readlink',return_value='mnt:[fixture]'),patch.object(m.os,'open',side_effect=lambda *a,**kw:real_open(str(ROOT),os.O_RDONLY|os.O_DIRECTORY)),patch.object(m,'CREDENTIAL_FILES_READ',1),patch.object(m,'configured_properties',return_value=('https://approved.example/internal/capabilities/v1/authorization/policy-bundle/active','/run/secrets/policy',None)),patch.object(m,'mounted_file',return_value=token),patch.object(m,'safe_get',return_value=({'httpStatus':200,'hostTransportOnly':True},{'bundleVersion':40})),contextlib.redirect_stdout(io.StringIO())as out:
   m.probe_owner_policy_channel(actual,'https://approved.example')
  rows=[json.loads(line)for line in out.getvalue().splitlines()];self.assertEqual(len(rows),2);self.assertEqual(rows[0]['credentialFilesRead'],2);self.assertFalse(rows[0]['expiredAtRead']);self.assertEqual(rows[1]['activeBundleVersion'],40);self.assertNotIn(token.decode(),out.getvalue())

@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','explicit actual PostgreSQL17 qualification')
class NativeSql(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1500:]);return r.stdout.decode().strip()
 def test_actual_postgres_exact_eleven_contracts_and_safe_job_codes(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:
   self.assertLess(time.monotonic(),end);time.sleep(.2)
  def sql(raw):return self.cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',raw)
  sql((ROOT/'tests/reference_dependency_read/fixture.sql').read_text())
  raw=sql(m.acquisition_query('udp','ouf-lab'));self.assertNotIn('PRIVATE_',raw);facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);self.assertEqual(facts['confirmedJobCount'],11);self.assertEqual(facts['distinctContractSets'],1)
  refs=facts.pop('contractRefs');self.assertIn('bundleRef',refs);self.assertNotIn('bundleRef',json.dumps(facts))
  self.assertEqual(facts['jobGroups'][0]['safe_failure_code'],'UDP_REFERENCE_INTEGRITY_MISSING');self.assertEqual(facts['jobGroups'][0]['count'],11)
  other=json.loads(sql(m.acquisition_query('udp','other-tenant')));self.assertEqual(other['confirmedJobCount'],0)
if __name__=='__main__':unittest.main()
