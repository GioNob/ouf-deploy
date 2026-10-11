import hashlib,importlib.util,json,subprocess,sys,unittest,types,io,contextlib
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('entry',ROOT/'scripts/publish-native-v11-review-intake.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def raw(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def fixture():
 e=dict(m.EXPECTED);proof={'nativeEngineImageId':e['imageId'],'configImageId':e['configImageId'],'imageByteCustodyProven':True,'completeContainerOciProven':False,'transportClosureProven':False,'targetApplyAuthorized':False}
 journal={'state':'VERIFIED','version':2,'effectAttemptCount':1,'automaticReplayAllowed':False,'nativeEvidenceHash':m.digest(proof),'contextHash':'c'*64}
 decl={'schema':'ouf.discovery.private-file-secret-runtime-declaration.v1','candidateImageId':e['imageId'],'productionApplyReady':False,'applicationCutoverAuthorized':False,'completeReplacementOciProven':False,'qualifiedPackageBinding':{'sourceCommit':e['sourceCommit'],'zipSha256':e['zipSha256'],'imageId':e['configImageId']},'nativeImageBinding':{'nativeEngineImageId':e['imageId'],'configImageId':e['configImageId'],'nativeEvidenceHash':m.digest(proof),'importJournalContextHash':'c'*64}}
 request={'Image':e['imageId']};plan={'fixturePlan':True};e.update(declarationHash=m.digest(decl),requestHash=m.digest(request),planHash=m.digest(plan))
 receipt={'schema':'ouf.native-v11-current-private-plan.v1','status':'CURRENT_NATIVE_V11_DECLARATION_AND_PLAN_PREPARED_NOT_APPLY_READY','privateDeclarationHash':e['declarationHash'],'creationRequestHash':e['requestHash'],'creationPlanHash':e['planHash']}
 receipt.update({k:False for k in ('applicationCutoverAuthorized','productionApplyReady','budgetReset','r12Touched','newApplicationTransitionClaimCreated','newTransportClosureProven','completeRealizedOciProven')})
 files=dict(zip(m.NAMES,map(raw,(decl,request,{'creationPlan':plan,'imageProof':proof,'importJournal':journal},receipt))))
 return files,e
class Entry(unittest.TestCase):
 def test_partial_private_write_never_reports_zero_effect(self):
  files,e=fixture();validate=m.validate
  def interrupted(base,files,manifest,uid,checkpoint):
   checkpoint('BEFORE_FILE_private-runtime-declaration.json')
   raise ValueError('PRIVATE_WRITE_OUTCOME_UNPROVEN')
  modules={'atomic':types.SimpleNamespace(publish=interrupted),'custody':types.SimpleNamespace(file_bytes=lambda path,*a,**k:files[path.name])}
  output=io.StringIO()
  with patch.object(m,'modules',return_value=modules),patch.object(m,'validate',side_effect=lambda files:validate(files,e)),patch.object(m,'EXPECTED',e),patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'flags',types.SimpleNamespace(isolated=True)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.sys,'argv',['sealed-fixture']),patch.dict(m.__dict__,{'__sealed_program_sha__':'a'*64}),contextlib.redirect_stdout(output):
   self.assertEqual(m.main(),1)
  value=json.loads(output.getvalue().split('=',1)[1]);self.assertIsNone(value['protectedFileWrites']);self.assertTrue(value['privateWriteOutcomeRequiresReconciliation']);self.assertEqual(value['protectedFileWriteAttempts'],1);self.assertFalse(value['applicationCutoverAuthorized'])
 def test_complete_bound_fixture_is_a_review_not_authority(self):
  files,e=fixture();values=m.validate(files,e);self.assertFalse(values['receipt.json']['applicationCutoverAuthorized'])
 def test_each_missing_or_changed_file_blocks_review(self):
  for name in m.NAMES:
   files,e=fixture();del files[name]
   with self.subTest(name=name),self.assertRaises(ValueError):m.validate(files,e)
  files,e=fixture();files[m.NAMES[0]]+=b'\n'
  with self.assertRaisesRegex(ValueError,'PLAN_HASHES'):m.validate(files,e)
 def test_same_image_without_original_publisher_or_import_proof_is_denied(self):
  for key in ('qualifiedPackageBinding','nativeImageBinding'):
   files,e=fixture();decl=json.loads(files[m.NAMES[0]]);decl[key]={};files[m.NAMES[0]]=raw(decl);e['declarationHash']=m.digest(decl);receipt=json.loads(files[m.NAMES[3]]);receipt['privateDeclarationHash']=e['declarationHash'];files[m.NAMES[3]]=raw(receipt)
   with self.subTest(key=key),self.assertRaises(ValueError):m.validate(files,e)
 def test_receipt_authority_promotion_or_budget_reset_is_denied(self):
  for key in ('applicationCutoverAuthorized','productionApplyReady','budgetReset','r12Touched','newApplicationTransitionClaimCreated','newTransportClosureProven','completeRealizedOciProven'):
   files,e=fixture();receipt=json.loads(files[m.NAMES[3]]);receipt[key]=True;files[m.NAMES[3]]=raw(receipt)
   with self.subTest(key=key),self.assertRaisesRegex(ValueError,'MUST_NOT_GRANT'):m.validate(files,e)
 def test_complete_module_hashes_precede_any_execution(self):
  paths={'atomic':ROOT/'tools/semantic_application_cutover/atomic_review_intake.py','custody':ROOT/'tools/semantic_target_review/prepare_application_runtime_inputs.py'}
  if not paths['custody'].exists():paths['custody']=ROOT/'tests/fixtures/custody.py'
  source={k:p.read_bytes() for k,p in paths.items()}
  for k,b in source.items():self.assertEqual(hashlib.sha256(b).hexdigest(),m.HASHES[k])
  for k in source:
   bad=dict(source);bad[k]+=b'#tamper'
   with self.subTest(k=k),patch('builtins.exec',side_effect=AssertionError('EARLY_EXEC')),self.assertRaisesRegex(ValueError,'HASH_MISMATCH'):m.modules(bad)
  self.assertEqual(set(m.modules(source)),set(source))
 def test_entry_without_root_isolation_blocks_before_private_read(self):
  p=subprocess.run([sys.executable,str(ROOT/'scripts/publish-native-v11-review-intake.py')],capture_output=True,timeout=5)
  self.assertNotEqual(p.returncode,0);self.assertIn(b'ISOLATED_ROOT_ATOMIC_REVIEW_REQUIRED',p.stdout);self.assertNotIn(b'Traceback',p.stderr)
if __name__=='__main__':unittest.main()
