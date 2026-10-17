import hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-resolution-ths-property-shapes-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Shapes(unittest.TestCase):
 def test_nested_json_boolean_and_public_scope_flags_without_secret_values(self):
  value={'ouf':{'authorization':{'ths':{'enabled':True}}},'spring.security.oauth2.client.registration.ouf-ths.scope':['openid','resolution.issue.read','resolution.match.approve'],'client-secret':'NEVER_PRINT_THIS'}
  result=m.selected_metadata(b'# private literal\n',{'SPRING_APPLICATION_JSON':json.dumps(value)},'https://fixture.invalid')
  self.assertTrue(result['selectedPropertyMetadata'][0]['boolean']);self.assertTrue(result['selectedPropertyMetadata'][1]['issueReadPresent']);self.assertNotIn('NEVER_PRINT',json.dumps(result))
 def test_placeholder_and_uppercase_are_distinguished_from_missing_property(self):
  raw=b'ouf.authorization.ths.enabled: ${THS_ENABLED:true}\n'
  result=m.selected_metadata(raw,{},'https://fixture.invalid')['selectedPropertyMetadata'][0]
  self.assertEqual(result['kind'],'ENV_REFERENCE');self.assertTrue(result['resolvedBoolean'])
  result=m.selected_metadata(raw,{'THS_ENABLED':'FALSE'},'https://fixture.invalid')['selectedPropertyMetadata'][0];self.assertFalse(result['resolvedBoolean'])
  result=m.selected_metadata(b'ouf.authorization.ths.enabled: True\n',{},'https://fixture.invalid')['selectedPropertyMetadata'][0];self.assertFalse(result['canonicalLowercase']);self.assertTrue(result['boolean'])
 def test_conflicting_channels_and_quoted_yaml_key_are_visible_without_raw_values(self):
  raw=b'"ouf.authorization.ths.enabled": false\n'
  result=m.selected_metadata(raw,{'OUF_AUTHORIZATION_THS_ENABLED':'true'},'https://fixture.invalid')
  self.assertEqual([r['boolean']for r in result['selectedPropertyMetadata']],[False,True])
 def test_flow_and_missing_metadata_do_not_claim_effective_spring_configuration(self):
  result=m.selected_metadata(b'ouf: {authorization: {ths: {enabled: true}}}\n',{},'https://fixture.invalid')
  self.assertTrue(result['yamlContainsFlowSyntax']);self.assertEqual(result['selectedPropertyMetadata'],[]);self.assertFalse(result['effectiveConfigProven'])
 @unittest.skipUnless(os.geteuid()==0,'root custody fixture')
 def test_exact_custody_helper_rejects_changed_file_and_symlink(self):
  reader=m.custody_reader(ROOT/'tools/chatbot_file_cohort/gateway.py')
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT','/root'))as d:
   p=Path(d)/'config';p.write_bytes(b'original');p.chmod(0o600);raw,binding=reader(p);self.assertEqual(raw,b'original')
   p.write_bytes(b'changed')
   with self.assertRaises(Exception):reader(p,binding)
   link=Path(d)/'link';link.symlink_to(p)
   with self.assertRaises(Exception):reader(link)
if __name__=='__main__':unittest.main()
