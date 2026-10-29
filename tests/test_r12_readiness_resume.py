import json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SHELL=(ROOT/'releases/resume-native-v11-plan-20261011.sh').read_text()
CODE=SHELL.split("/usr/bin/python3 -I -B -c '\n",1)[1].split("\n' \"$OUF_DIR/diagnosis.txt\"",1)[0]
def receipt():
 checks={k:True for k in ('schemaMatches','leaseActive','stateActive','ready','incidentMatches','applyReplayDisabled','startNotAuthorized','twoRenewalsObserved','workerPidPresent')}
 v={'schema':'ouf.r12-protected-readiness-diagnosis.v1','status':'R12_PRIVATE_READINESS_AND_BUDGET_CAPTURED_NO_RECOVERY_AUTHORITY','workerReadinessChecks':checks,'workerReadinessChecksAfter':dict(checks),'service':{'LoadState':'loaded','ActiveState':'active','SubState':'running','Restart':'no','NRestarts':'0'}}
 v.update({k:True for k in ('hostBootMatches','invocationBootMatches','invocationContextMatches','invocationPidMatchesWorker','journalContextMatchesAuthorization','journalGenerationMatchesAuthorization','serviceInvocationBindingsMatch')})
 v.update({k:False for k in ('revocationMarkerPresent','workerDenialPresent','budgetReset','diagnosisGrantsRecoveryAuthority','productionApplyReady','applicationCutoverAuthorized')})
 return v
class Resume(unittest.TestCase):
 def test_complete_orchestration_stops_on_diagnosis_gate_and_plan_failures(self):
  for mode,exitcode,expected in [('diagnosis_fail',71,['diagnosis']),('gate_fail',1,['diagnosis']),('plan_fail',99,['diagnosis','plan']),('success',0,['diagnosis','plan'])]:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as f:
    root=Path(f);binary=root/'bin';binary.mkdir();marker=root/'children'
    paths={'diagnosis':str(ROOT/'releases/r12-readiness-diagnosis-20261011.sh'),'plan':str(ROOT/'releases/native-v11-plan-20261011.sh')}
    (binary/'gh').write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
key='diagnosis' if 'r12-readiness-diagnosis' in sys.argv[-1] else 'plan'
sys.stdout.buffer.write(pathlib.Path(json.loads(os.environ['FILES'])[key]).read_bytes())
''');(binary/'gh').chmod(0o700)
    (binary/'bash').write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
key=pathlib.Path(sys.argv[1]).stem
with open(os.environ['MARKER'],'a') as f:f.write(key+'\\n')
mode=os.environ['MODE']
if key=='diagnosis':
 v=json.loads(os.environ['RECEIPT'])
 if mode=='gate_fail':v['workerReadinessChecksAfter']['ready']=False
 print('OUF_R12_READINESS_DIAGNOSIS='+json.dumps(v))
 raise SystemExit(71 if mode=='diagnosis_fail' else 0)
raise SystemExit(99 if mode=='plan_fail' else 0)
''');(binary/'bash').chmod(0o700)
    p=root/'launcher.sh';p.write_text(SHELL.replace('$HOME',str(root)))
    env=dict(os.environ,PATH=str(binary)+':'+os.environ['PATH'],FILES=json.dumps(paths),MARKER=str(marker),MODE=mode,RECEIPT=json.dumps(receipt()))
    result=subprocess.run(['/bin/bash',str(p)],env=env,capture_output=True,timeout=10)
    self.assertEqual(result.returncode,exitcode);self.assertEqual(marker.read_text().splitlines(),expected)
    self.assertIn(('OUF_NATIVE_V11_RESUME_EXIT='+str(exitcode)).encode(),result.stdout)
 def gate(self,v,duplicate=False):
  with tempfile.TemporaryDirectory() as f:
   p=Path(f)/'receipt.txt';p.write_text(('OUF_R12_READINESS_DIAGNOSIS='+json.dumps(v)+'\n')*(2 if duplicate else 1))
   return subprocess.run(['python3','-I','-B','-c',CODE,str(p)],capture_output=True,timeout=10)
 def test_complete_readiness_allows_only_independent_fresh_plan_preparation(self):
  p=self.gate(receipt());self.assertEqual(p.returncode,0);self.assertIn(b'NO_TRANSITION_AUTHORITY',p.stdout)
 def test_each_missing_or_false_predicate_prevents_plan(self):
  for key in ('workerReadinessChecks','workerReadinessChecksAfter'):
   for pred in receipt()[key]:
    v=receipt();v[key][pred]=False
    with self.subTest(key=key,pred=pred):self.assertNotEqual(self.gate(v).returncode,0)
  for key,value in receipt().items():
   v=receipt();del v[key]
   with self.subTest(missing=key):self.assertNotEqual(self.gate(v).returncode,0)
 def test_blocked_diagnosis_or_restarted_service_never_advances(self):
  for value in ('R12_PRIVATE_DIAGNOSIS_BLOCKED','LEASE_PAUSED'):
   v=receipt();v['status']=value;self.assertNotEqual(self.gate(v).returncode,0)
  v=receipt();v['service']['NRestarts']='1';self.assertNotEqual(self.gate(v).returncode,0)
  self.assertNotEqual(self.gate(receipt(),duplicate=True).returncode,0)
 def test_every_download_or_digest_failure_prevents_any_child_execution(self):
  for fail in ('diagnosis','plan'):
   for mode in ('download','tamper'):
    with self.subTest(fail=fail,mode=mode),tempfile.TemporaryDirectory() as f:
     root=Path(f);binary=root/'bin';binary.mkdir();marker=root/'child'
     paths={'diagnosis':str(ROOT/'releases/r12-readiness-diagnosis-20261011.sh'),'plan':str(ROOT/'releases/native-v11-plan-20261011.sh')}
     (binary/'gh').write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
key='diagnosis' if 'r12-readiness-diagnosis' in sys.argv[-1] else 'plan'
if key==os.environ['FAIL'] and os.environ['MODE']=='download':raise SystemExit(71)
raw=pathlib.Path(json.loads(os.environ['FILES'])[key]).read_bytes()
if key==os.environ['FAIL'] and os.environ['MODE']=='tamper':raw+=b'#tamper'
sys.stdout.buffer.write(raw)
''');(binary/'gh').chmod(0o700)
     (binary/'bash').write_text('#!/bin/sh\nprintf called > "'+str(marker)+'"\nexit 98\n');(binary/'bash').chmod(0o700)
     p=root/'launcher.sh';p.write_text(SHELL.replace('$HOME',str(root)))
     env=dict(os.environ,PATH=str(binary)+':'+os.environ['PATH'],FILES=json.dumps(paths),FAIL=fail,MODE=mode)
     result=subprocess.run(['/bin/bash',str(p)],env=env,capture_output=True,timeout=10)
     self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())
if __name__=='__main__':unittest.main()
