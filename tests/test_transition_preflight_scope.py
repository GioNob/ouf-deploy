import copy,importlib.util,os,tempfile,unittest,json,types,io,contextlib
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
scope=module('scope','tools/semantic_application_cutover/transition_policy_scope.py');entry=module('entry','scripts/read-native-v11-transition-preflight.py')
class Scope(unittest.TestCase):
 def test_complete_root_entry_reads_real_fixture_files_without_opening_keys(self):
  from test_native_intake_entry import fixture,raw
  files,expected=fixture();p,k=self.fixture()
  sources={'review':(ROOT/'scripts/publish-native-v11-review-intake.py').read_bytes(),'scope':(ROOT/'tools/semantic_application_cutover/transition_policy_scope.py').read_bytes()}
  custody=ROOT/'tools/semantic_target_review/prepare_application_runtime_inputs.py'
  if not custody.exists():custody=ROOT/'tests/fixtures/custody.py'
  sources['custody']=custody.read_bytes();verified=entry.modules(sources);original_validate=verified['review'].validate
  verified['review'].EXPECTED=expected;verified['review'].validate=lambda files:original_validate(files,expected)
  with tempfile.TemporaryDirectory(dir=ROOT) as f:
   root=Path(f);root.chmod(0o700)
   for role in p['keyBindings']:
    path=root/(role+'.pem');path.write_bytes(b'NEVER_OPEN_PRIVATE_KEY_FIXTURE');path.chmod(0o600);p['keyBindings'][role]={'path':str(path),'sha256':entry.sha(path.read_bytes())}
   policy=root/'policy.json';policy.write_bytes(raw(k));policy.chmod(0o600);policy_binding={'path':str(policy),'sha256':entry.sha(policy.read_bytes())};p['policyBinding']=policy_binding;p['unexpectedSecret']='NEVER_PRINT_PRIVATE_MARKER'
   profile=root/'profile.json';profile.write_bytes(raw(p));profile.chmod(0o600);authority_binding={'path':str(profile),'sha256':entry.sha(profile.read_bytes())}
   intake=root/'intake';intake.mkdir(mode=0o700)
   for name,data in files.items():(intake/name).write_bytes(data);(intake/name).chmod(0o600)
   manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','preparedBindings':expected,'sourceHashes':{'program':entry.HASHES['review'],'atomic':'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6','custody':entry.HASHES['custody']},'fileHashes':{n:entry.sha(b) for n,b in files.items()},'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False,'observationsAreHistorical':True}
   data=raw(manifest);(intake/'intake.json').write_bytes(data);(intake/'intake.json').chmod(0o600)
   reads=[];actual_read=verified['custody'].file_bytes
   def recorded(path,*args,**kwargs):reads.append(str(path));return actual_read(path,*args,**kwargs)
   verified['custody'].file_bytes=recorded;output=io.StringIO()
   with patch.object(entry,'modules',return_value=verified),patch.object(entry,'INTAKE',intake),patch.object(entry,'INTAKE_HASH',entry.sha(data)),patch.object(entry,'AUTHORITY',authority_binding),patch.object(entry,'POLICY',policy_binding),patch.object(entry.time,'time',return_value=150),patch.object(entry.sys,'flags',types.SimpleNamespace(isolated=True)),patch.object(entry.sys,'dont_write_bytecode',True),patch.object(entry.sys,'argv',['isolated-fixture']),contextlib.redirect_stdout(output):
    self.assertEqual(entry.main(),0)
   v=json.loads(output.getvalue().split('=',1)[1]);self.assertEqual(v['intakeFilesReverified'],5);self.assertEqual(v['privateKeysRead'],0);self.assertFalse(v['productionApplyReady']);self.assertNotIn('NEVER_PRINT',output.getvalue());self.assertNotIn('NEVER_OPEN',output.getvalue());self.assertTrue(all(b['path'] not in reads for b in p['keyBindings'].values()))
 def fixture(self):
  c=entry.CONTEXT;b=entry.POLICY
  profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':c,'policyBinding':b,'keyRefs':{'installer':'fixture-installer-key','attestor':'fixture-attestor-key'},'keyBindings':{r:{'path':'/fixture/'+r+'.pem','sha256':'a'*64} for r in ('installer','attestor')}}
  keys=[{'keyRef':profile['keyRefs'][r],'issuerRef':issuer,'roles':roles,'publicKey':'a'*64,'notBefore':100,'expiresAt':200,'state':'ACTIVE'} for r,issuer,roles in [('installer',c['intentIssuerRef'],['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('attestor',c['attestorRef'],['CREATION_ATTESTATION'])]]
  policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':c['installationRef'],'entityRef':c['entityRef'],'keys':keys};return profile,policy
 def test_current_role_windows_are_metadata_not_runtime_authority(self):
  p,k=self.fixture();v=scope.project(p,k,150,entry.CONTEXT,entry.POLICY);self.assertTrue(v['roles']['installer']['requiredRoleWindowsEligible']);self.assertTrue(v['roles']['attestor']['requiredRoleWindowsEligible']);self.assertFalse(v['runtimeAuthorityIssued']);self.assertTrue(v['metadataOnlyNotSignatureVerification']);self.assertNotIn('a'*64,str(v))
 def test_expired_revoked_missing_role_or_key_never_promotes_scope(self):
  for mode in ('expired','revoked','missing-role','missing-key'):
   p,k=self.fixture()
   if mode=='expired':k['keys'][0]['expiresAt']=149
   elif mode=='revoked':k['keys'][0]['state']='REVOKED'
   elif mode=='missing-role':k['keys'][0]['roles']=['DEPLOYMENT_INTENT']
   else:k['keys'].pop(0)
   with self.subTest(mode=mode):self.assertFalse(scope.project(p,k,150,entry.CONTEXT,entry.POLICY)['roles']['installer']['requiredRoleWindowsEligible'])
 def test_foreign_entity_duplicate_key_or_unrecognized_role_is_denied(self):
  for mode in ('entity','duplicate','role'):
   p,k=self.fixture()
   if mode=='entity':k['entityRef']='foreign-entity'
   elif mode=='duplicate':k['keys'].append(copy.deepcopy(k['keys'][0]))
   else:k['keys'][0]['roles']=['SIGN_EVERYTHING']
   with self.subTest(mode=mode),self.assertRaises(ValueError):scope.project(p,k,150,entry.CONTEXT,entry.POLICY)
 def test_public_metadata_never_copies_unselected_secret_fields(self):
  p,k=self.fixture();p['unexpected-secret']='NEVER_PRINT_PRIVATE_VALUE';v=scope.project(p,k,150,entry.CONTEXT,entry.POLICY);self.assertNotIn('NEVER_PRINT',str(v));self.assertNotIn('/fixture/',str(v))
 def test_key_metadata_never_opens_key_bytes(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as f:
   p=Path(f)/'fixture.pem';p.write_bytes(b'NEVER_READ_PRIVATE_FIXTURE');p.chmod(0o600)
   with patch('builtins.open',side_effect=AssertionError('KEY_BYTES_OPENED')),patch.object(os,'open',side_effect=AssertionError('KEY_BYTES_OPENED')):v=entry.key_metadata(str(p))
   self.assertTrue(v['present']);self.assertTrue(v['metadataCustodyMatches']);self.assertFalse(v['privateKeyBytesRead'])
   p.chmod(0o644);self.assertFalse(entry.key_metadata(str(p))['metadataCustodyMatches']);p.unlink();self.assertFalse(entry.key_metadata(str(p))['present'])
 def test_all_sealed_source_hashes_verified_before_any_module_execution(self):
  paths={'review':ROOT/'scripts/publish-native-v11-review-intake.py','scope':ROOT/'tools/semantic_application_cutover/transition_policy_scope.py','custody':ROOT/'tools/semantic_target_review/prepare_application_runtime_inputs.py'}
  if not paths['custody'].exists():paths['custody']=ROOT/'tests/fixtures/custody.py'
  valid={k:p.read_bytes() for k,p in paths.items()}
  for name,raw in valid.items():self.assertEqual(entry.sha(raw),entry.HASHES[name])
  for name in valid:
   bad=dict(valid);bad[name]+=b'#tamper'
   with self.subTest(name=name),patch('builtins.exec',side_effect=AssertionError('EARLY_EXEC')),self.assertRaisesRegex(ValueError,'SOURCE_HASH_MISMATCH'):entry.modules(bad)
  self.assertEqual(set(entry.modules(valid)),set(valid))
if __name__=='__main__':unittest.main()
