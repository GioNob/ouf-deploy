import contextlib,hashlib,importlib.util,io,json,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-resolution-ths-bindings-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Metadata(unittest.TestCase):
 def test_nested_selected_properties_scopes_and_no_secret_output(self):
  raw=b'''ouf:
  authorization:
    ths:
      enabled: true
  resolution:
    ths:
      gateway-base-url: "https://fixture.invalid/"
spring:
  security:
    oauth2:
      client:
        registration:
          ouf-ths:
            client-secret: PRIVATE_SECRET
            scope:
              - openid
              - resolution.issue.read
              - resolution.match.approve
'''
  value=m.selected_metadata(raw,{},'https://fixture.invalid');self.assertTrue(value['resolutionGatewayEqualsReviewedOrigin'])
  self.assertTrue(value['declaredScopesIncludeIssueRead']);self.assertTrue(value['declaredScopesIncludeMatchApprove'])
  self.assertTrue(value['authorizationThsEnabledLiteral']);self.assertFalse(value['effectiveConfigProven'])
  out=io.StringIO()
  with contextlib.redirect_stdout(out):m.emit('METADATA',**value)
  parsed=json.loads(out.getvalue());self.assertFalse(parsed['credentialValuesPrinted']);self.assertNotIn('PRIVATE_SECRET',out.getvalue())
 def test_conflicting_env_unresolved_reference_and_tabs_are_unproven(self):
  raw=b'ouf.resolution.ths.gateway-base-url: https://fixture.invalid\n'
  v=m.selected_metadata(raw,{'OUF_RESOLUTION_THS_GATEWAY_BASE_URL':'https://other.invalid'},'https://fixture.invalid')
  self.assertEqual(v['resolutionGatewayValueCount'],2);self.assertFalse(v['resolutionGatewayEqualsReviewedOrigin'])
  v=m.selected_metadata(b'ouf.resolution.ths.gateway-base-url: ${PRIVATE_REFERENCE}\n',{},'https://fixture.invalid')
  self.assertFalse(v['resolutionGatewayLiteral'])
  with self.assertRaises(ValueError):m.selected_metadata(b'ouf:\n\tresolution: bad\n',{},'https://fixture.invalid')
 def test_route_snapshot_includes_existing_pages_without_inventing_resolution(self):
  route={'id':'onboarding','uri':'/trusted-human/onboarding/*','methods':['GET','POST'],'upstream':{'nodes':{'PRIVATE_BACKEND':1}},'plugins':{'openid-connect':{'client_secret':'PRIVATE_SECRET','required_scopes':['scope']}}}
  value=m.route_metadata({'onboarding':route},'fixture.invalid');self.assertEqual(value['resolutionPageMatchesByPathAndMethod'],[])
  self.assertNotIn('PRIVATE_',json.dumps(value));self.assertFalse(value['liveRouteInventoryRead'])
  route['uri']='/trusted-human/resolution/*';value=m.route_metadata({'onboarding':route},'fixture.invalid')
  self.assertEqual(value['resolutionPageMatchesByPathAndMethod'],['onboarding'])
  route['uri']='/*';value=m.route_metadata({'onboarding':route},'fixture.invalid')
  self.assertEqual(value['resolutionPageMatchesByPathAndMethod'],['onboarding'])
 @unittest.skipUnless(os.geteuid()==0,'root fixture required')
 def test_qualified_no_follow_custody_rejects_symlink_and_stale_binding(self):
  read=m.custody_reader(ROOT/'tools/chatbot_file_cohort/gateway.py')
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT','/root'))as root:
   path=Path(root)/'selected.yaml';path.write_bytes(b'ouf:\n  enabled: true\n');path.chmod(0o600)
   raw,binding=read(path);self.assertEqual(raw,path.read_bytes())
   path.write_bytes(b'ouf:\n  enabled: false\n')
   with self.assertRaises(Exception):read(path,binding)
   link=Path(root)/'link.yaml';link.symlink_to(path)
   with self.assertRaises(Exception):read(link)
if __name__=='__main__':unittest.main()
