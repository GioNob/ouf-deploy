import contextlib,copy,hashlib,importlib.util,io,json,os,signal,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('delivery',ROOT/'scripts/deliver-prepared-source-revision-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class PreparedDelivery(unittest.TestCase):
 def fixture(self,root):
  code=root/'executor-code';code.mkdir(mode=0o700)
  def put(path,value):
   raw=m.encoded(value) if not isinstance(value,bytes) else value;path.write_bytes(raw);path.chmod(0o600);return m.digest(raw)
  overlays={'fixture.module'+str(i):('member'+str(i)+'.py','fixture')for i in range(77)}
  executor=('import sys\nOVERLAYS='+repr(overlays)+'\nif __name__=="__main__":\n print("NATIVE_GATE_FIXTURE")\n raise SystemExit(0)\n').encode()
  exsha=put(code/'execute.py',executor);loader=put(code/'runtime.py',b'pass\n')
  sources={module:put(code/name,b'pass\n')for module,(name,_)in overlays.items()}
  original={'path':str(root/'current-original-preparation.json'),'sha256':put(root/'current-original-preparation.json',{'secret':'CANARY'})}
  private={'path':str(root/'postboot-private-inputs.json'),'sha256':put(root/'postboot-private-inputs.json',{'secret':'CANARY'})}
  casesha=put(code/'case.json',{'schema':'ouf.source-revision-postboot-update-selection.v2','preparedPlanBinding':private,'postbootOriginalPreparationBinding':original})
  pkgsha=put(code/'package.json',{'schema':'ouf.source-revision-executable-package.v1','sourceCommit':'a'*40,'executorSha256':exsha,'loaderSha256':loader,'caseSha256':casesha,'sourceHashes':sources})
  plansha=put(root/'prepared-plan.json',{'plan':'CANARY'})
  result={'schema':'ouf.source-revision-postboot-preparation-result.v1','contextPath':str(root),'postbootSuccessorPrepared':True,'nativePlanCompilationProven':True,'effectiveFlywayConfigurationProven':True,'hostCompletionReadbackProven':True,'runtimeAuthorityIssued':False,'readyForExecution':False,'currentOriginalPreparationBinding':original,'preparedInputsBinding':private,'executorCodeBinding':{'directory':str(code),'sourceCommit':'a'*40,'packageSha256':pkgsha},'caseBinding':{'path':str(code/'case.json'),'sha256':casesha},'nativePlanBinding':{'path':str(root/'prepared-plan.json'),'sha256':plansha},'sourceClosureSha256':'c'*64}
  resultsha=put(root/'postboot-preparation-result.json',result)
  return {'contextPath':str(root),'sourceCommit':'a'*40,'executorSha256':exsha,'preparationResultSha256':resultsha,'packageSha256':pkgsha,'caseSha256':casesha,'nativePlanSha256':plansha,'sourceClosureSha256':'c'*64},result
 def exercise(self,change=None):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent))) as temp:
   root=Path(temp);profile,result=self.fixture(root);code=root/'executor-code'
   if change in ('receipt','plan','case','executor','source','loader'):
    path={'receipt':root/'postboot-preparation-result.json','plan':root/'prepared-plan.json','case':code/'case.json','executor':code/'execute.py','source':code/'member0.py','loader':code/'runtime.py'}[change];path.write_bytes(b'CANARY')
   if change=='extra':(code/'authority.json').write_text('{}')
   if change=='link':(code/'member0.py').unlink();(code/'member0.py').symlink_to(code/'member1.py')
   if change=='mode':(code/'member0.py').chmod(0o644)
   if change in ('unprepared','authority'):
    result['readyForExecution'if change=='unprepared'else'runtimeAuthorityIssued']=True;raw=m.encoded(result);(root/'postboot-preparation-result.json').write_bytes(raw);profile['preparationResultSha256']=m.digest(raw)
   output=io.StringIO()
   try:
    with contextlib.redirect_stdout(output):
     if change:
      with self.assertRaises(ValueError):m.run(profile)
     else:
      with self.assertRaises(SystemExit)as stopped:m.run(profile)
      self.assertEqual(stopped.exception.code,0)
    if change:self.assertNotIn('NATIVE_GATE_FIXTURE',output.getvalue())
    else:self.assertIn('NATIVE_GATE_FIXTURE',output.getvalue());self.assertIn('"frozenFilesVerified": 81',output.getvalue())
    self.assertNotIn('CANARY',output.getvalue())
   finally:signal.alarm(0)
 def test_exact_prepared_files_reach_only_fixture_gate(self):self.exercise()
 def test_all_six_pinned_document_or_code_classes_reject_tamper(self):
  for change in ('receipt','plan','case','executor','source','loader'):
   with self.subTest(change=change):self.exercise(change)
 def test_unknown_authority_link_and_nonprivate_mode_reject_before_gate(self):
  for change in ('extra','link','mode'):
   with self.subTest(change=change):self.exercise(change)
 def test_unprepared_or_authority_bearing_receipt_is_not_reusable(self):
  for change in ('unprepared','authority'):
   with self.subTest(change=change):self.exercise(change)
 def test_production_profile_matches_reconstructed_target_receipt_and_executor(self):
  evidence=json.loads((ROOT/'evidence/source-revision-postboot-preparation-target-success-20261019.json').read_bytes());result=evidence['result'];profile=m.PROFILE
  self.assertEqual(profile['preparationResultSha256'],m.digest(m.encoded(result)));self.assertEqual(profile['contextPath'],result['contextPath']);self.assertEqual(profile['packageSha256'],result['executorCodeBinding']['packageSha256']);self.assertEqual(profile['caseSha256'],result['caseBinding']['sha256']);self.assertEqual(profile['nativePlanSha256'],result['nativePlanBinding']['sha256']);self.assertEqual(profile['sourceClosureSha256'],result['sourceClosureSha256']);self.assertEqual(profile['executorSha256'],m.digest((ROOT/'scripts/execute-source-revision-postboot.py').read_bytes()))
if __name__=='__main__':unittest.main()
