import hashlib,importlib.util,json,unittest,types
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('diagnostic',ROOT/'scripts/read-r12-readiness-diagnosis.py');d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
def sources():
 paths={'prepare':'scripts/prepare-semantic-inputs-after-r12.py','custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py'}
 out={}
 for name,path in paths.items():
  f=ROOT/path
  if not f.exists():f=ROOT/'tests/fixtures'/(name+'.py')
  out[name]=f.read_bytes()
 return out
class Diagnosis(unittest.TestCase):
 def test_service_read_crosses_actual_retained_native_command_scope(self):
  p=d.modules(sources())['prepare'];reads=[]
  reader=types.SimpleNamespace(private=lambda *a,**k:reads.append((a,k)))
  binding={'path':'/usr/bin/systemctl','sha256':'retained-bound-hash'}
  result=types.SimpleNamespace(returncode=0,stdout=b'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=2446150\nRestart=no\nNRestarts=0\nExecStart=private retained activation\n')
  with patch.object(p.subprocess,'run',return_value=result) as run:
   service=d.service_read(p,reader,binding)
  self.assertEqual(service['MainPID'],'2446150');self.assertEqual(len(reads),2)
  self.assertEqual(run.call_args.args[0],['/usr/bin/systemctl','show',p.UNIT,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,ExecStart'])
  self.assertEqual(run.call_args.kwargs['timeout'],15)
 def test_original_expanded_service_scope_is_rejected_before_native_execution(self):
  p=d.modules(sources())['prepare']
  with patch.object(p.subprocess,'run',side_effect=AssertionError('NATIVE_COMMAND_EXECUTED')),self.assertRaisesRegex(ValueError,'EXACT_READ_ONLY_NATIVE_SCOPE_REQUIRED'):
   p.native(None,{},['show',p.UNIT,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,Result,ExecMainCode,ExecMainStatus,ExecStart'])
 def test_paused_budget_and_reason_are_observable_without_readiness(self):
  worker={'schema':'ouf.provider-resilient-worker-status.v1','status':'LEASE_PAUSED','state':'RETRY_WAIT',
   'ready':False,'live':True,'setsRevoked':True,'attempts':7,'refreshCount':2500,'workerPid':2446150,
   'recoveryBudgetRemainingSeconds':86321.5,'reason':'DEPENDENCY_TIMEOUT','incidentRef':'expected',
   'doNotRerunApply':True,'startAuthorized':False}
  checks=d.worker_checks(worker,'expected');self.assertFalse(checks['leaseActive']);self.assertFalse(checks['stateActive']);self.assertFalse(checks['ready'])
  p=d.projection(worker);self.assertTrue(p['live']);self.assertTrue(p['setsRevoked']);self.assertEqual(p['attempts'],7);self.assertEqual(p['reason'],'DEPENDENCY_TIMEOUT')
 def test_blocked_exhausted_reconcile_failed_and_stopped_are_not_ready(self):
  for state in ('BLOCKED','PAUSED_EXHAUSTED','RECONCILE_REQUIRED','STOPPED'):
   self.assertFalse(all(d.worker_checks({'state':state,'status':'LEASE_PAUSED','ready':False},'expected').values()))
  self.assertFalse(d.worker_checks({'status':'LEASE_WORKER_FAILED','workerPid':2446150},'expected')['leaseActive'])
 def test_only_exact_active_predicates_satisfy_retained_guard(self):
  worker={'schema':'ouf.provider-resilient-worker-status.v1','status':'LEASE_ACTIVE','state':'ACTIVE','ready':True,
   'incidentRef':'expected','doNotRerunApply':True,'startAuthorized':False,'refreshCount':2,'workerPid':2446150}
  self.assertTrue(all(d.worker_checks(worker,'expected').values()))
  for key in worker:
   changed=dict(worker);changed[key]=None
   with self.subTest(key=key):self.assertFalse(all(d.worker_checks(changed,'expected').values()))
 def test_secret_fields_strings_and_unknown_exception_values_are_not_printed(self):
  value={'status':'LEASE_PAUSED','reason':'secret.example/path?token=private-secret','password':'private-secret',
   'sourceAddresses':['192.0.2.123'],'Env':['SECRET=private-secret'],'errorType':'private-secret',
   'exceptionChain':[{'reason':'private-secret','message':'private-secret','errorType':'PermissionError'}]}
  encoded=json.dumps(d.projection(value));self.assertNotIn('private-secret',encoded);self.assertNotIn('192.0.2.123',encoded);self.assertNotIn('Env',encoded)
  self.assertIn('PermissionError',encoded);self.assertIn('UNPROJECTED',encoded)
 def test_numeric_boolean_nonfinite_oversized_and_negative_values_are_filtered(self):
  for value in (True,-1,float('nan'),float('inf'),2**10000):
   self.assertFalse(d.number(value));self.assertNotIn('attempts',d.projection({'attempts':value}))
  self.assertTrue(d.number(0));self.assertTrue(d.number(1.25))
 def test_nested_diagnosis_is_bounded_and_profile_is_exact(self):
  value={'state':'BLOCKED','exceptionChain':[]};nested={'reason':'INTEGRITY_UNPROVEN','exceptionChain':[]}
  for i in range(20):nested={'exceptionChain':[nested]*10}
  value['exceptionChain']=[nested]*10
  self.assertLess(len(json.dumps(d.projection(value))),500000)
  self.assertEqual(d.projection({'timeAccountingProfile':'ouf.lease-cumulative-recovery-time.v1'})['timeAccountingProfile'],'ouf.lease-cumulative-recovery-time.v1')
  self.assertEqual(d.projection({'timeAccountingProfile':'secret-value'})['timeAccountingProfile'],'UNPROJECTED')
 def test_complete_closure_checked_before_any_exec(self):
  valid=sources()
  for name,raw in valid.items():self.assertEqual(hashlib.sha256(raw).hexdigest(),d.HASHES[name])
  for name in valid:
   broken=dict(valid);broken[name]+=b'#tamper'
   with self.subTest(name=name),patch('builtins.exec',side_effect=AssertionError('EARLY_EXEC')),self.assertRaisesRegex(ValueError,'SOURCE_HASH_MISMATCH'):d.modules(broken)
 def test_partial_closure_denied_and_valid_closure_loads_without_any_recovery(self):
  with patch('builtins.exec',side_effect=AssertionError('EARLY_EXEC')),self.assertRaisesRegex(ValueError,'EXACT_R12_DIAGNOSIS_SOURCE_SET'):d.modules({})
  m=d.modules(sources());self.assertEqual(m['prepare'].UNIT,'ouf-semantic-provider-lease-resilient-r12.service')
if __name__=='__main__':unittest.main()
