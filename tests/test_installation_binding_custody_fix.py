import ast,copy,fcntl,hashlib,importlib.util,json,os,stat,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
try:import test_installation_binding_custody_stop as fixture
except ModuleNotFoundError:
 spec=importlib.util.spec_from_file_location('read_fixture',HERE/'test_read.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
NATIVE=HERE.parent/'native.py'
if not NATIVE.exists():NATIVE=HERE.parent/'tools/installation_binding_apply/native.py'
READY=HERE/'read_readiness.py'
if not READY.exists():READY=HERE.parent/'scripts/read-installation-binding-continuation-readiness.py'
spec=importlib.util.spec_from_file_location('readiness',READY);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Publisher(fixture.Read):
 # Reuse only the root-custody fixture; inherited STOP tests are not collected twice.
 def publisher(self):
  namespace=fixture.m.custody_reader(self.gateway.encode())
  env={'os':os,'stat':stat,'fcntl':fcntl,'hashlib':hashlib,'Path':Path,'require':fixture.m.require,'private_config':namespace['private_config'],
   'baseline':types.SimpleNamespace(read=lambda *_:(_ for _ in()).throw(AssertionError('LEGACY_READER_MUST_NOT_BE_USED')))}
  tree=ast.parse(NATIVE.read_bytes());nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('approved_projection_bytes','publish_active_projection')]
  self.assertEqual(len(nodes),2);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-profile-publisher>','exec'),env)
  return types.SimpleNamespace(**env)
 def test_actual_publisher_readback_and_later_read_use_approved_nonroot_custody(self):
  native=self.publisher();_,binding=native.private_config(self.profile);before=self.profile.stat().st_ino
  with self.assertRaises(ValueError):fixture.m.read(self.profile)
  new=b'{"fixture":"authoritative-new-export"}';native.publish_active_projection(binding,new,'b'*64)
  self.assertNotEqual(self.profile.stat().st_ino,before);self.assertEqual(native.approved_projection_bytes(self.profile,hashlib.sha256(new).hexdigest()),new)
  self.assertEqual(stat.S_IMODE(self.profile.stat().st_mode),0o600)
 def test_fixed_reader_denies_wrong_hash_or_changed_custody(self):
  native=self.publisher()
  with self.assertRaises(Exception):native.approved_projection_bytes(self.profile,'0'*64)
  self.ouf.chmod(0o770)
  with self.assertRaises(Exception):native.approved_projection_bytes(self.profile,self.export)
# Remove inherited test methods from collection by naming this suite explicitly below.
class Human(unittest.TestCase):
 def setUp(self):
  review={'schema':'ouf.human-explicit-test-continuation-review.v3','priorOAuthAttempts':251,'maximumCumulativeOAuthAttempts':256,'budgetReset':False}
  self.binding={'expiresAt':1792436155,'createdAt':1792428955,'retryProfile':{'maximumAttempts':256},'scopes':['scope'+str(i)for i in range(11)]}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':self.binding,'attempts':255,'budgetReset':False,'bootId':'fixture',
   'state':'READY','lastObservedAt':100,'monotonicDeadline':1000,'accessExpiresAt':105,'accessToken':'NEVER_PRINT_BEARER','refreshToken':'NEVER_PRINT_REFRESH',
   'governedWindowRenewal':{'review':review,'decision':{'reviewHash':r.digest(review),'approvedAt':1792428955,'expiresAt':1792436155}}}
  p=patch.object(r,'HUMAN_REVIEW',r.digest(review));p.start();self.addCleanup(p.stop)
 def project(self):return r.human_readiness(self.row,self.binding,110,200,'fixture')
 def test_expired_access_at255_does_not_offer_incomplete_one_request_refresh(self):
  result=self.project();self.assertEqual(result['remainingOAuthAttempts'],1);self.assertFalse(result['remainingBudgetCoversVerifiedRefresh']);self.assertFalse(result['recordedAccessHas240SecondsMargin'])
  self.assertFalse(result['refreshInvoked']);self.assertFalse(result['newBudgetAuthorized']);self.assertNotIn('NEVER_PRINT',json.dumps(result))
 def test_future_access_is_only_a_recorded_margin_not_signature_proof(self):
  self.row['accessExpiresAt']=600;result=self.project();self.assertTrue(result['recordedAccessHas240SecondsMargin']);self.assertFalse(result['currentBearerOrSignatureVerificationPerformed'])
 def test_counter_reset_binding_or_consent_drift_is_rejected(self):
  for key,value in [('attempts',254),('attempts',257),('budgetReset',True),('bootId','changed')]:
   changed=copy.deepcopy(self.row);changed[key]=value
   with self.subTest(key=key),self.assertRaises(Exception):r.human_readiness(changed,self.binding,110,200,'fixture')
 def test_readiness_source_never_dispatches_or_mutates(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(READY.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.request','.login','.refresh_if_due','.issue_action','.write','.compare_and_save'))for c in calls))
def load_tests(loader,tests,pattern):
 suite=unittest.TestSuite();suite.addTests(loader.loadTestsFromTestCase(Human))
 for name in('test_actual_publisher_readback_and_later_read_use_approved_nonroot_custody','test_fixed_reader_denies_wrong_hash_or_changed_custody'):suite.addTest(Publisher(name))
 return suite
if __name__=='__main__':unittest.main()
