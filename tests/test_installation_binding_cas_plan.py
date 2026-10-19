import ast,copy,hashlib,importlib.util,json,sys,unittest,urllib.error
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/prepare-installation-binding-cas-plan.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name('plan.py')
spec=importlib.util.spec_from_file_location('cas_plan',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_installation_ingestion_binding_plan as prior

class CasPlan(unittest.TestCase):
 def setUp(self):
  self.old=prior.OwnerPlan();self.old.setUp();self.previous=self.old.compile()
  self.previous['candidatePayloadChecksum']='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98'
  self.active={**self.old.active,'generation':8};self.etag='"4:'+self.active['checksum']+':8"';self.selected=m.strong_active(self.active,self.etag)
 def compiler(self,*args):
  result=prior.p.compile_plan(*args);result['candidatePayloadChecksum']=self.previous['candidatePayloadChecksum'];return result
 def compile(self,first=None,last=None,previous=None):return m.compile_cas(first or self.selected,self.old.revision,last or self.selected,self.old.projection,previous or self.previous,{'retained':'fixture'},self.compiler)
 def test_same_original_candidate_with_new_strong_generation_binding_no_authority(self):
  result=self.compile();self.assertEqual(result['expectedActiveGeneration']if 'expectedActiveGeneration'in result else result['expectedActive']['generation'],8)
  self.assertEqual(result['expectedActiveETag'],self.etag);self.assertEqual(result['candidatePayload'],self.previous['candidatePayload'])
  self.assertFalse(result['ownerApplyAuthorized']);self.assertTrue(result['futureNativeConsentRequired']);self.assertFalse(result['atomicOwnerApiLiveWriteTestPerformed'])
 def test_weak_missing_malformed_or_body_mismatched_etag_is_denied(self):
  for etag in(None,'W/'+self.etag,self.etag+', '+self.etag,'"4:'+self.active['checksum']+':9"'):
   with self.subTest(etag=etag),self.assertRaises(Exception):m.strong_active(self.active,etag)
  for change in({'generation':True},{'generation':0},{'revision':2**63},{'extra':'field'}):
   with self.subTest(change=change),self.assertRaises(Exception):m.strong_active({**self.active,**change},self.etag)
 def test_aba_generation_drift_or_changed_candidate_denies(self):
  last={**self.selected,'generation':10,'etag':self.etag[:-2]+'10"'}
  with self.assertRaises(Exception):self.compile(last=last)
  changed=copy.deepcopy(self.previous);changed['candidatePayload']['unreviewed']='mutation'
  with self.assertRaises(Exception):self.compile(previous=changed)
 def test_other_installation_or_revision_drift_denies(self):
  for change in({'installationId':'other'},{'revision':5},{'checksum':'f'*64}):
   first={**self.selected,**change}
   with self.subTest(change=change),self.assertRaises(Exception):self.compile(first=first,last=first)

class Transport(unittest.TestCase):
 def fixture(self):
  old=prior.OwnerPlan();old.setUp();human=Mock();human.token_path=Path('/private/token')
  credentials=Mock();credentials.token.return_value='PRIVATE_BEARER'
  p=patch.object(m.urllib.request,'build_opener');opener=p.start();self.addCleanup(p.stop)
  response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
  response.status=200;response.read.return_value=b'{"field":"body"}';response.headers={'ETag':'"strong"'};opener.return_value.open.return_value=response
  reader=m.ThreeReads({'origin':'https://fixture.invalid'},human,old.compile(),lambda *a,**kw:credentials,lambda:object())
  return reader,opener.return_value,response
 def test_only_three_exact_gets_return_response_etag_without_writes(self):
  reader,opener,response=self.fixture();paths=[]
  for i in range(3):
   body,etag=reader.next();self.assertEqual(etag,'"strong"');self.assertEqual(body,{'field':'body'})
   req=opener.open.call_args.args[0];self.assertEqual(req.get_method(),'GET');self.assertIsNone(req.data);paths.append(req.full_url)
  self.assertEqual(paths[0],paths[2]);self.assertIn('/revisions/4',paths[1])
  with self.assertRaises(Exception):reader.next()
  self.assertEqual(opener.open.call_count,3)
 def test_transport_failure_has_no_automatic_request_replay(self):
  reader,opener,response=self.fixture();opener.open.side_effect=urllib.error.URLError('PRIVATE_PROVIDER_DETAIL')
  with self.assertRaises(Exception)as error:reader.next()
  self.assertNotIn('PRIVATE',str(error.exception));self.assertEqual(opener.open.call_count,1)

class Limits(unittest.TestCase):
 def test_source_has_no_refresh_login_authority_or_owner_mutation_dispatch(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.refresh_if_due','.login','.issue_action','.start_refresh','.put','.post','.main','.execv'))for c in calls))
  self.assertTrue(all(isinstance(n.value,ast.Constant)and n.value.value=='GET'for n in ast.walk(tree)if isinstance(n,ast.keyword)and n.arg=='method'))
if __name__=='__main__':unittest.main()
