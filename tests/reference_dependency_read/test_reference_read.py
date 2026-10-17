import importlib.util,json,os,re,subprocess,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-teatri-reference-dependencies-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
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
  actual={'Config':{'Env':['SPRING_CONFIG_LOCATION=file:/run/secrets/udp.yml']}}
  raw=b'ouf:\n  udp:\n    execution:\n      gateway-url: https://approved.example\n      token-file: /run/secrets/token\n'
  with patch.object(m,'mounted_file',return_value=raw):
   gateway,token,sha=m.configured_properties(actual,None)
  self.assertEqual((gateway,token),('https://approved.example','/run/secrets/token'));self.assertEqual(len(sha),64)
 def test_credential_read_counter_is_preserved_in_redacted_status(self):
  import contextlib,io
  with patch.object(m,'CREDENTIAL_FILES_READ',1),contextlib.redirect_stdout(io.StringIO())as out:m.emit('TEST_METADATA')
  value=json.loads(out.getvalue());self.assertEqual(value['credentialFilesRead'],1);self.assertFalse(value['credentialValuesPrinted'])

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
  sql((Path(__file__).parent/'fixture.sql').read_text())
  raw=sql(m.acquisition_query('udp','ouf-lab'));self.assertNotIn('PRIVATE_',raw);facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);self.assertEqual(facts['confirmedJobCount'],11);self.assertEqual(facts['distinctContractSets'],1)
  refs=facts.pop('contractRefs');self.assertIn('bundleRef',refs);self.assertNotIn('bundleRef',json.dumps(facts))
  self.assertEqual(facts['jobGroups'][0]['safe_failure_code'],'UDP_REFERENCE_INTEGRITY_MISSING');self.assertEqual(facts['jobGroups'][0]['count'],11)
  other=json.loads(sql(m.acquisition_query('udp','other-tenant')));self.assertEqual(other['confirmedJobCount'],0)
if __name__=='__main__':unittest.main()
