"""Isolated root fixtures, no target server, transport or HUMAN authority."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('retained_reader',BASE/'scripts/read-onboarding-diagnostic-transport-stop-20261027.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'root file-custody fixture')
class Read(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSPORT_READ_TEST_ROOT',str(BASE.parent)));self.root=Path(self.tmp.name)
  self.code=self.root/'old-code';self.old=self.root/'old-scope';self.code.mkdir(mode=0o700);self.old.mkdir(mode=0o700)
  self.before={'socketPath':'/run/docker.sock','socketBinding':[1,2,0,0,432],'peerCredentials':[123,0,0]}
  self.after={**self.before,'socketBinding':[1,3,0,0,432]}
  self.prepared={'schema':'ouf.onboarding-diagnostic-private-execution-inputs.v1','runtimeAuthorityIssued':False,'engineBinding':self.after}
  self.frozen={'schema':'ouf.onboarding-v35-frozen-native-plan.v1','boundDatabaseProfile':{'schema':'ouf.current-onboarding-database-snapshot-profile.v1','runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1','engineBinding':self.before}}
  mapping={}
  for name in m.FILES:
   raw=('CI_ONLY_NOT_EXECUTED_'+name).encode();self.put(self.code/name,raw);mapping[name]=m.sha(raw)
  self.put(self.code/'sources.json',mapping)
  self.case={'root':str(self.root/'read-once'),'oldCode':str(self.code),'oldScope':str(self.old),
   'oldManifestHash':m.digest(mapping),'executionInputsPath':str(self.root/'prepared.json'),'executionInputsHash':m.digest(self.prepared),
   'frozenPath':str(self.root/'frozen.json'),'frozenHash':m.digest(self.frozen)}
  self.put(self.root/'prepared.json',self.prepared);self.put(self.root/'frozen.json',self.frozen)
  self.put(self.old/'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':self.case['executionInputsHash'],'maximums':m.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
  for i in range(1,4):self.put(self.old/('preflight-attempt-1234-%05d.json'%i),{'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True})
  self.put(self.code/'operator.log',m.EXPECTED_STOP,0o600)
 def tearDown(self):self.tmp.cleanup()
 def put(self,path,value,mode=0o400):
  if path.exists():path.chmod(0o600)
  raw=value if isinstance(value,bytes)else m.encoded(value);path.write_bytes(raw);path.chmod(mode)
 def update(self):
  self.put(self.root/'prepared.json',self.prepared);self.put(self.root/'frozen.json',self.frozen)
  self.case['executionInputsHash']=m.digest(self.prepared);self.case['frozenHash']=m.digest(self.frozen)
  claim=json.loads((self.old/'preparation-claim.json').read_bytes());claim['executionInputsHash']=self.case['executionInputsHash'];self.put(self.old/'preparation-claim.json',claim)
 def snapshot(self):return {str(p):p.read_bytes()for root in(self.code,self.old)for p in root.iterdir()if p.is_file()}
 def test_exact_guard_components_counts_and_original_files_preserved(self):
  before=self.snapshot();r=m.reconcile(self.case)
  self.assertEqual(r['failedGuardChecks'],['engineBinding']);self.assertEqual(r['counts']['privateMetadataReads'],7);self.assertEqual(r['counts']['protectedCodeReads'],22)
  self.assertEqual(r['retainedPreflightCounts']['ownerConfigurationReads'],3);self.assertEqual(r['engineBindingDifferences'][0]['field'],['socketBinding',1])
  self.assertTrue(r['sameSocketPath']);self.assertFalse(r['sameSocketCustody']);self.assertTrue(r['samePeerCredentials'])
  self.assertTrue(r['pinnedCodeAndRetainedClaimsProveNoRuntimeDispatch']);self.assertFalse(r['continuationAuthorized']);self.assertEqual(before,self.snapshot())
 def test_sorted_profile_reported_never_normalized(self):
  self.frozen['boundDatabaseProfile']['runtimeBindingProfile']='ouf.runtime-binding.mounts-sorted-destination.v1';self.update();r=m.reconcile(self.case)
  self.assertIn('runtimeBindingProfile',r['failedGuardChecks']);self.assertEqual(r['observedRuntimeBindingProfile'],'ouf.runtime-binding.mounts-sorted-destination.v1')
 def test_schema_mismatch_reported_without_guessing(self):
  self.frozen['boundDatabaseProfile']['schema']='other-private-schema';self.update();r=m.reconcile(self.case)
  self.assertIn('profileSchema',r['failedGuardChecks']);self.assertEqual(r['observedProfileSchema'],'UNRECOGNIZED');self.assertNotIn('other-private-schema',m.encoded(r).decode())
 def test_matching_profile_does_not_reconcile_this_stop(self):
  self.frozen['boundDatabaseProfile']['engineBinding']=self.after;self.update()
  with self.assertRaisesRegex(m.Stop,'CAUSE_NOT_REPRODUCED'):m.reconcile(self.case)
 def test_existing_authority_or_journal_refuses_without_adoption(self):
  self.put(self.old/'authority.json',{'notAuthority':True});before=self.snapshot()
  with self.assertRaisesRegex(m.Stop,'PREFLIGHT_ONLY'):m.reconcile(self.case)
  self.assertEqual(before,self.snapshot())
 def test_missing_or_changed_preflight_count_refuses(self):
  path=self.old/'preflight-attempt-1234-00003.json';row=json.loads(path.read_bytes());row['attempt']=2;self.put(path,row)
  with self.assertRaisesRegex(m.Stop,'PREFLIGHT_COUNTS'):m.reconcile(self.case)
 def test_wrong_retained_operator_result_refuses(self):
  row=copy.deepcopy(m.EXPECTED_STOP);row['reasonCode']='OTHER_STOP';self.put(self.code/'operator.log',row,0o600)
  with self.assertRaisesRegex(m.Stop,'TERMINAL_TRANSPORT_STOP'):m.reconcile(self.case)
 def test_changed_input_bytes_refuse(self):
  self.put(self.root/'prepared.json',{'unapproved':True})
  with self.assertRaisesRegex(m.Stop,'FILE_HASH'):m.reconcile(self.case)
 def test_changed_old_code_bytes_refuse_before_evidence_interpretation(self):
  self.put(self.code/'context.py',b'changed')
  with self.assertRaisesRegex(m.Stop,'FILE_HASH'):m.reconcile(self.case)
 def test_private_socket_paths_and_values_never_printed(self):
  self.after['socketPath']='/PRIVATE_SOCKET_PATH_CANARY';self.prepared['engineBinding']=self.after;self.update();r=m.reconcile(self.case)
  raw=m.encoded(r).decode();self.assertNotIn('PRIVATE_SOCKET_PATH_CANARY',raw);self.assertNotIn('/run/docker.sock',raw);self.assertFalse(r['addressesPrinted'])
 def test_reader_scope_cannot_be_replayed(self):
  m.reconcile(self.case)
  with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.reconcile(self.case)
 def test_no_network_sql_process_or_old_entry_execution_imports(self):
  import ast
  tree=ast.parse((BASE/'scripts/read-onboarding-diagnostic-transport-stop-20261027.py').read_text())
  imports=[n.names[0].name for n in ast.walk(tree)if isinstance(n,ast.Import)];self.assertFalse(set(imports)&{'socket','subprocess','http','urllib','importlib'})
  forbidden={'exec','eval','compile','Popen','system'}
  self.assertFalse(any(isinstance(n,ast.Call)and(isinstance(n.func,ast.Name)and n.func.id in forbidden or isinstance(n.func,ast.Attribute)and n.func.attr in forbidden)for n in ast.walk(tree)))
if __name__=='__main__':unittest.main(verbosity=2)
