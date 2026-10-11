"""Actual Ed25519 + current root custody, disposable synthetic HUMAN fixture."""
import hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/semantic_cohort_admission/cohort-draft'))
sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
from cutover_authority import CutoverAuthority,AuthorityDenied
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,signing_bytes
from tools.semantic_provider_preexec import PreexecDenied
from cutover_executor import Executor
from transition_journal import Transition,PHASES

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
class SignedCutover(unittest.TestCase):
 def test_actual_dual_signature_gate_composes_with_all_ordered_fixture_phases(self):
  import types
  path=ROOT/'tools/semantic_lease_recovery/recovery_journal.py'
  if not path.exists():path=ROOT/'tests/fixtures/recovery_journal.py'
  spec=importlib.util.spec_from_file_location('signed_fixture_journal',path);j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)
  intents={p:{'syntheticFixturePhase':p} for p in PHASES}
  self.authority=encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in self.expected.items() if k!='intakeHash'},'issuedAt':self.now,'expiresAt':self.now+120,'phaseIntentHashes':{p:sha(encoded(i)) for p,i in intents.items()},'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True})
  self.approval['executionAuthorityHash']=sha(self.authority);self.write(self.mandate,encoded(self.approval));self.approved=sha(self.mandate.read_bytes())
  for role in self.grant['roles']:self.sign(role)
  root=self.root/'journal';root.mkdir(mode=0o700);store=j.Journal(root);initial=Transition.initial(sha(self.authority),self.expected['creationRequestHash'],self.expected['predecessorHistoryHash'],self.expected['predecessorIncidentRef']);store.initialize(initial);t=Transition(store,initial['contextHash']);calls=[]
  def checkpoint(phase,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],'intentHash':sha(encoded(intents[phase])),'authorityHash':sha(self.authority),'sourceClosureHash':self.expected['sourceClosureHash'],'nativeEvidenceHash':'f'*64}
  adapters={p:types.SimpleNamespace(apply=lambda i,p=p:calls.append(p),observe=lambda i:('APPLIED',{'syntheticNativeFixture':True})) for p in PHASES}
  executor=Executor(t,self.authority,self.gate(),checkpoint,adapters,intents,self.clock)
  result=executor.run();self.assertEqual(calls,list(PHASES));self.assertFalse(result['releaseAcceptance'])
  executor.run();self.assertEqual(calls,list(PHASES))
 def setUp(self):
  self.assertEqual(os.geteuid(),0)
  self.temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='cutover-authority-fixture-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.openssl=Path(shutil.which('openssl')).resolve();self.now=int(time.time());self.clock=lambda:self.now
  self.context={'installationRef':'synthetic-fixture-installation','entityRef':'synthetic-fixture-entity','intentIssuerRef':'synthetic-fixture-installer','approvalIssuerRef':'synthetic-fixture-installer','attestorRef':'synthetic-fixture-attestor'}
  self.key=self.root/'disposable.pem';self.native('genpkey','-algorithm','ED25519','-out',str(self.key));self.key.chmod(0o600)
  self.grant={'keyRef':'synthetic-fixture-only-key','issuerRef':self.context['intentIssuerRef'],'roles':['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'],'publicKey':self.native('pkey','-in',str(self.key),'-pubout','-outform','DER')[12:].hex(),'notBefore':self.now-30,'expiresAt':self.now+600,'state':'ACTIVE'}
  attestor={'keyRef':'synthetic-fixture-attestor-key','issuerRef':self.context['attestorRef'],'roles':['CREATION_ATTESTATION'],'publicKey':'f'*64,'notBefore':self.now-30,'expiresAt':self.now+600,'state':'ACTIVE'}
  self.policy=self.root/'policy.json';self.write(self.policy,encoded({'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':self.context['installationRef'],'entityRef':self.context['entityRef'],'keys':[self.grant,attestor]}))
  self.signatures=self.root/'signatures';self.signatures.mkdir(mode=0o700)
  self.verifier=DetachedAuthenticator(self.binding(self.policy),str(self.signatures),{**self.binding(self.openssl),'version':self.native('version').decode().split()[1]},clock=self.clock)
  self.expected={k:c*64 for k,c in zip(('intakeHash','sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef'),'abcde')}
  self.authority=encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in self.expected.items() if k!='intakeHash'},'issuedAt':self.now,'expiresAt':self.now+120})
  self.approval={'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':'SYNTHETIC_FIXTURE_NOT_TARGET_APPROVAL','decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE','issuedAt':self.now-1,'expiresAt':self.now+180,'executionAuthorityHash':sha(self.authority),**self.expected}
  self.mandate=self.root/'human.json';self.write(self.mandate,encoded(self.approval));self.approved=sha(self.mandate.read_bytes())
  for role in self.grant['roles']:self.sign(role)
 def native(self,*args):return subprocess.run([str(self.openssl),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout
 def write(self,p,raw):p.write_bytes(raw);p.chmod(0o600)
 def binding(self,p):return {'path':str(p),'sha256':sha(p.read_bytes())}
 def sign(self,role,entity=None):
  header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':self.grant['keyRef'],'role':role,'issuerRef':self.grant['issuerRef'],'installationRef':self.context['installationRef'],'entityRef':entity or self.context['entityRef'],'payloadHash':sha(self.authority)}
  frame=self.root/'frame';self.write(frame,signing_bytes(self.authority,header));sig=self.native('pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(frame));self.write(self.signatures/(sha(self.authority)+'.'+role+'.json'),encoded({**header,'signature':sig.hex()}))
 def gate(self):return CutoverAuthority(self.verifier,self.binding(self.mandate),self.approved,self.context,self.expected,self.clock)
 def test_actual_two_scoped_signatures_and_explicit_review_hash_pass(self):self.assertTrue(self.gate()(self.authority))
 def test_whole_execution_window_must_fit_current_role_policy_before_effects(self):
  p=json.loads(self.policy.read_bytes());p['keys'][0]['expiresAt']=self.now+80;self.write(self.policy,encoded(p));self.verifier.policy_binding=self.binding(self.policy)
  with self.assertRaisesRegex(AuthorityDenied,'WINDOW_EXCEEDS_SCOPED_KEY_AUTHORITY'):self.gate()(self.authority)
 def test_later_attestor_window_also_must_fit_before_stopping_old_runtime(self):
  p=json.loads(self.policy.read_bytes());p['keys'][1]['expiresAt']=self.now+80;self.write(self.policy,encoded(p));self.verifier.policy_binding=self.binding(self.policy)
  with self.assertRaisesRegex(AuthorityDenied,'WINDOW_EXCEEDS_SCOPED_KEY_AUTHORITY'):self.gate()(self.authority)
 def test_missing_final_signature_or_wrong_entity_denies(self):
  path=self.signatures/(sha(self.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json');saved=path.read_bytes();path.unlink()
  with self.assertRaises((PreexecDenied,OSError)):self.gate()(self.authority)
  self.write(path,saved);self.sign('FINAL_DEPLOYMENT_APPROVAL',entity='another-fixture-entity')
  with self.assertRaises(PreexecDenied):self.gate()(self.authority)
 def test_corrupt_signature_really_fails_crypto(self):
  path=self.signatures/(sha(self.authority)+'.DEPLOYMENT_INTENT.json');v=json.loads(path.read_bytes());v['signature']='0'*128;self.write(path,encoded(v))
  with self.assertRaisesRegex(PreexecDenied,'SIGNATURE_INVALID'):self.gate()(self.authority)
 def test_human_expiry_missing_explicit_hash_or_different_intake_denies(self):
  self.now+=181
  with self.assertRaisesRegex(AuthorityDenied,'CURRENT_HUMAN'):self.gate()(self.authority)
  with self.assertRaises(AuthorityDenied):CutoverAuthority(self.verifier,self.binding(self.mandate),None,self.context,self.expected,self.clock)
  self.now-=181;self.expected['intakeHash']='f'*64
  with self.assertRaisesRegex(AuthorityDenied,'INTAKE_DRIFT'):self.gate()(self.authority)
 def test_human_revocation_changed_after_approval_denies_before_signatures(self):
  gate=self.gate();self.approval['state']='REVOKED';self.write(self.mandate,encoded(self.approval))
  with self.assertRaisesRegex(AuthorityDenied,'MANDATE_CHANGED'):gate(self.authority)
 def test_trust_policy_drift_and_expired_key_deny(self):
  self.now=self.grant['expiresAt']
  # Keep synthetic HUMAN/record windows current to isolate key expiry.
  self.assertRaises(PreexecDenied,self.verifier,self.authority,'DEPLOYMENT_INTENT',self.context['intentIssuerRef'],self.context['installationRef'],self.context['entityRef'])
  self.now-=600;self.policy.write_bytes(self.policy.read_bytes()+b'\n')
  with self.assertRaisesRegex(PreexecDenied,'POLICY_REVOKED_OR_CHANGED'):self.gate()(self.authority)
 def test_noop_verifier_hash_only_and_secret_free_errors_are_denied(self):
  with self.assertRaisesRegex(AuthorityDenied,'ED25519_ROLE_VERIFIER_REQUIRED'):CutoverAuthority(lambda raw:True,self.binding(self.mandate),self.approved,self.context,self.expected,self.clock)
  with self.assertRaises((AuthorityDenied,PreexecDenied)):self.gate()(b'not-a-signed-authority')
if __name__=='__main__':unittest.main()
