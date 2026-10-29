import ast,importlib.util,json,struct,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/read-mcp-human-issuer-stop.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name(SCRIPT.name)
spec=importlib.util.spec_from_file_location('qualified_issuer_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def setUp(self):self.selection={'realm':'fixture','subject':'subject'}
 def line(self,subject='subject',error='invalid_token',reason='Session not active'):
  return ('type="REFRESH_TOKEN_ERROR",realmName="fixture",clientId="ouf-human-admin",userId="'+subject+'",error="'+error+'",reason="'+reason+'",refresh_token_id="SECRET_ID",credential="SECRET_TOKEN"\n').encode()
 def test_exact_subject_known_issuer_reason_and_no_raw_details(self):
  result=m.projection(self.line(),self.selection);self.assertTrue(result['matchingIssuerEventProven'])
  self.assertEqual(result['matchedErrorClasses'][0]['reasonCode'],'SESSION_NOT_ACTIVE');self.assertNotIn('SECRET',json.dumps(result))
 def test_unknown_reason_and_error_are_redacted(self):
  result=m.projection(self.line(error='SECRET',reason='SECRET'),self.selection)
  self.assertNotIn('SECRET',json.dumps(result));self.assertEqual(result['matchedErrorClasses'][0]['errorCode'],'OTHER_REDACTED')
 def test_other_subject_and_client_do_not_attribute_cause(self):
  for raw in (self.line(subject='other'),self.line().replace(b'ouf-human-admin',b'other-client')):
   self.assertFalse(m.projection(raw,self.selection)['matchingIssuerEventProven'])
 def test_multiplexed_docker_log_and_truncation(self):
  raw=self.line();frame=b'\x02\x00\x00\x00'+struct.pack('>I',len(raw))+raw
  self.assertEqual(m.unframe(frame,False),raw)
  for bad in(frame[:-1],b'bad',b'\x03'+frame[1:]):
   with self.assertRaises(Exception):m.unframe(bad,False)
 def test_request_surface_has_three_gets_and_no_exec_oauth_or_mutation(self):
  r=m.Reader({'socketPath':'/fixture/socket','socketBinding':[1,2,0,0,432]},'a'*64)
  self.assertEqual(len(r.allowed),2)
  with self.assertRaises(Exception):r.get('/v1.44/containers/create')
  calls=[n for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  request=[n for n in calls if ast.unparse(n.func)=='connection.request'];self.assertEqual(len(request),1)
  self.assertEqual(ast.literal_eval(request[0].args[0]),'GET')
  self.assertFalse(any(ast.unparse(n.func).endswith(('.refresh_if_due','.login','.execv','.write','.start_refresh'))for n in calls))
if __name__=='__main__':unittest.main()
