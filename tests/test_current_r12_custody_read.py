import ast,copy,contextlib,hashlib,importlib.util,io,json
from pathlib import Path
import types,unittest
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('current_read',ROOT/'scripts/read-current-r12-cutover-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
PATHS={'planner':'scripts/compile-semantic-creation-plan-after-r12.py',
 'prepare':'scripts/prepare-semantic-inputs-after-r12.py',
 'custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py',
 'creation':'tools/semantic_application_cutover/creation_plan.py'}
def sources():
 return {k:(ROOT/path if (ROOT/path).exists() else ROOT/'tests/fixtures'/f'{k}.py').read_bytes() for k,path in PATHS.items()}
class CustodyRead(unittest.TestCase):
 def test_source_closure_matches_all_retained_qualified_bytes(self):
  values=sources()
  for k,v in values.items():self.assertEqual(hashlib.sha256(v).hexdigest(),m.SOURCE_HASHES[k])
  planner,prepare,custody,creation=m.modules(values)
  self.assertEqual(prepare.UNIT,'ouf-semantic-provider-lease-resilient-r12.service')
 def test_tamper_in_every_source_blocks_before_module_execution(self):
  for k in m.SOURCE_HASHES:
   values=sources();values[k]=b'raise AssertionError("must never execute")'
   with self.subTest(k=k),self.assertRaisesRegex(ValueError,'READ_ONLY_SOURCE_HASH_MISMATCH'):m.modules(values)
  for values in (None,{},dict(sources(),extra=b'anything')):
   with self.assertRaisesRegex(ValueError,'EXACT_READ_ONLY_SOURCE_CLOSURE_REQUIRED'):m.modules(values)
 def fixture(self):
  planner,prepare,_,creation=m.modules(sources())
  flow={'inetAddressCount':1,'bridgeAddressCount':1,'approvedAddressCount':1,'minRemainingTtlSeconds':16,'leaseSeconds':30}
  lease={'journalState':'LEASE_READY','leaseAuthorized':True,'nativeStructureVerified':True,'journalAndMembershipConsistent':True,'providerSetsEmpty':False,'flowCount':2,'flows':[flow,copy.deepcopy(flow)]}
  scope={'lease':lease,'currentSemanticPeer':{'generation':{'pid':10}}}
  raw_reader=('from pathlib import Path\nimport json\nCONTEXT=Path("/fixture")\nSEMANTIC_ID="exact-fixture"\n'
    'def private(path,*args):return b\'{"configurationHash":"fixture","commandBindings":{"docker":"fixture"}}\'\n'
    'def parse(raw):return json.loads(raw)\n'
    'def collect_cutover():return '+repr(scope)+'\n').encode()
  declaration=b'{"fixture":"declaration"}'
  custody=types.SimpleNamespace(file_bytes=Mock(side_effect=lambda path,*args,**kw:raw_reader if str(path).endswith('reader.py') else declaration))
  current={'State':{'Pid':10},'Config':{'fixture':'unchanged'}}
  prepare.native=Mock(side_effect=[json.dumps([current]).encode(),json.dumps([copy.deepcopy(current)]).encode()])
  before={'workerPid':20,'refreshCount':100,'workerGeneration':{'pid':20,'start':1},'authorizationHash':'a'*64}
  after=copy.deepcopy(before);after['refreshCount']=101
  prepare.r12_state=Mock(side_effect=[before,after]);prepare.frame=lambda value:value
  planner.verify_secret_custody=Mock()
  return planner,prepare,custody,creation,after
 def test_stable_native_reread_projects_only_safe_fields(self):
  planner,prepare,custody,creation,after=self.fixture();result=m.observe(planner,prepare,custody,creation)
  self.assertEqual(result['refreshCount'],101);self.assertEqual(result['flowCount'],2)
  self.assertEqual(planner.verify_secret_custody.call_count,2)
  for name in ('fixture','commandBindings','State','Config','credential'):
   self.assertNotIn(name,json.dumps(result))
  self.assertFalse(result['newCandidateImageCustodyProven'])
 def test_worker_generation_and_authorization_drift_denied(self):
  for field,value in [('workerGeneration',{'pid':21}),('authorizationHash','b'*64),('refreshCount',99)]:
   planner,prepare,custody,creation,after=self.fixture();after[field]=value
   with self.subTest(field=field),self.assertRaisesRegex(ValueError,'CURRENT_GENERATION_CHANGED_DURING_READ'):m.observe(planner,prepare,custody,creation)
 def test_application_frame_drift_denied(self):
  planner,prepare,custody,creation,after=self.fixture()
  prepare.native.side_effect=[b'[{"State":{"Pid":10}}]',b'[{"State":{"Pid":11}}]']
  with self.assertRaisesRegex(ValueError,'CURRENT_GENERATION_CHANGED_DURING_READ'):m.observe(planner,prepare,custody,creation)
 def test_final_expired_native_lease_denied(self):
  planner,prepare,custody,creation,after=self.fixture();original=planner.native_lease_ready
  count=[0]
  def expire(lease):
   count[0]+=1
   if count[0]==2:lease['flows'][0]['minRemainingTtlSeconds']=0
   original(lease)
  planner.native_lease_ready=expire
  with self.assertRaisesRegex(ValueError,'CURRENT_NATIVE_TWO_FLOW_LEASE_REQUIRED'):m.observe(planner,prepare,custody,creation)
 def test_input_drift_denied_on_second_read(self):
  planner,prepare,custody,creation,after=self.fixture();original=custody.file_bytes.side_effect;count=[0]
  def changed(path,*args,**kw):
   if str(path)==str(planner.DECLARATION):
    count[0]+=1
    if count[0]==2:return b'changed'
   return original(path,*args,**kw)
  custody.file_bytes.side_effect=changed
  with self.assertRaisesRegex(ValueError,'CURRENT_INPUT_DECLARATION_CHANGED'):m.observe(planner,prepare,custody,creation)
 def test_entrypoint_requires_root_isolation_and_safe_errors(self):
  flags=types.SimpleNamespace(isolated=1)
  fake_sys=types.SimpleNamespace(flags=flags,dont_write_bytecode=True,argv=['reader.py'])
  with patch.object(m,'sys',fake_sys),patch.object(m.os,'geteuid',return_value=0),patch.object(m,'modules',return_value=(None,)*4),patch.object(m,'observe',side_effect=ValueError('https://secret@private')):
   output=io.StringIO()
   with contextlib.redirect_stdout(output):self.assertEqual(m.main(),1)
   self.assertNotIn('secret',output.getvalue());self.assertIn('CURRENT_R12_CUSTODY_UNPROVEN',output.getvalue())
  with patch.object(m.os,'geteuid',return_value=1000),patch.object(m,'modules') as loader:
   with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(m.main(),1)
   loader.assert_not_called()
 def test_read_entrypoint_has_no_mutation_or_planner_calls(self):
  tree=ast.parse((ROOT/'scripts/read-current-r12-cutover-custody.py').read_text())
  called={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
  self.assertTrue({'create','mkdir','mkdtemp','compile_creation','write_text','write_bytes','chmod','chown'}.isdisjoint(called))
if __name__=='__main__':unittest.main()
