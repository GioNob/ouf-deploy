import copy,importlib.util,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
import rebase_native_manifest as r
import test_semantic_creation_plan as baseline
creation=baseline.m
spec=importlib.util.spec_from_file_location('native_plan_entry',ROOT/'scripts/prepare-native-v11-plan.py');entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
def fixture():
 d,h=baseline.CreationPlan().fixture();d['candidateImageId']=r.CONFIG
 d['qualifiedPackageBinding']={'sourceCommit':r.SOURCE,'zipSha256':r.ZIP,'imageId':r.CONFIG,'predecessorDeclarationHash':'c'*64}
 request=creation.compile_creation(d,creation.digest(d),h)[0]
 proof={'schema':'ouf.native-manifest-image-byte-custody.v1','configImageId':r.CONFIG,'nativeEngineImageId':r.NATIVE,
  'manifestDescriptor':copy.deepcopy(r.DESCRIPTOR),'sourceCommit':r.SOURCE,'archiveSha256':r.ARCHIVE,'rootfsLayerCount':10,
  'nativeConfigProjectionHash':r.CONFIG_PROJECTION,'nativeRootfsHash':r.ROOTFS,'imageByteCustodyProven':True,
  'completeContainerOciProven':False,'transportClosureProven':False,'targetApplyAuthorized':False}
 row={'schema':'ouf.image-import-journal.v1','contextHash':'a'*64,'state':'VERIFIED','version':2,'effectAttemptCount':1,
  'imageCustodyProven':True,'automaticReplayAllowed':False,'intent':{'imageId':r.CONFIG,'sourceCommit':r.SOURCE,'archiveSha256':r.ARCHIVE},
  'nativeEvidenceHash':r.digest(proof)}
 return d,request,h,proof,row
def transform(d,q,p,row):return r.rebase(d,q,row,p,'a'*64,r.digest(d),r.digest(q))
class Rebase(unittest.TestCase):
 def test_real_creation_compiler_preserves_every_field_except_image_and_keeps_original_source(self):
  d,q,h,p,row=fixture();old=copy.deepcopy((d,q,row));new,request=transform(d,q,p,row)
  self.assertEqual((d,q,row),old);self.assertEqual(request['Image'],r.NATIVE)
  self.assertEqual({k:v for k,v in request.items() if k!='Image'},{k:v for k,v in q.items() if k!='Image'})
  compiled,public=creation.compile_creation(new,r.digest(new),h);self.assertEqual(compiled,request)
  self.assertEqual(new['qualifiedPackageBinding'],d['qualifiedPackageBinding'])
  self.assertFalse(new['nativeImageBinding']['containerRuntimeCustodyProven']);self.assertFalse(public['productionApplyReady'])
 def test_stale_original_plan_hash_and_wrong_identity_or_apply_flags_block(self):
  d,q,h,p,row=fixture()
  with self.assertRaises(ValueError):r.rebase(d,q,row,p,'a'*64)
  for key in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven'):
   changed=copy.deepcopy(d);changed[key]=True
   with self.assertRaises(ValueError):transform(changed,q,p,row)
  changed=copy.deepcopy(q);changed['Image']=r.NATIVE
  with self.assertRaises(ValueError):transform(d,changed,p,row)
 def test_unverified_replayed_context_changed_or_modified_proof_cannot_admit_plan(self):
  d,q,h,p,row=fixture()
  for key,value in (('state','IN_FLIGHT'),('version',1),('effectAttemptCount',2),('contextHash','b'*64),('imageCustodyProven',False),('automaticReplayAllowed',True),('nativeEvidenceHash','0'*64)):
   changed=copy.deepcopy(row);changed[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):transform(d,q,p,changed)
  changed=copy.deepcopy(p);changed['rootfsLayerCount']=9;row['nativeEvidenceHash']=r.digest(changed)
  with self.assertRaisesRegex(ValueError,'EXACT_RECONCILED_PROOF'):transform(d,q,changed,row)
 def test_missing_or_changed_publisher_and_already_rebased_plan_block(self):
  for change in ('sourceCommit','zipSha256','imageId'):
   d,q,h,p,row=fixture();d['qualifiedPackageBinding'][change]='changed'
   with self.assertRaisesRegex(ValueError,'PUBLISHER'):transform(d,q,p,row)
  d,q,h,p,row=fixture();d['nativeImageBinding']={}
  with self.assertRaises(ValueError):transform(d,q,p,row)
 def test_current_worker_authorization_configuration_and_refresh_fences_preserved(self):
  before={k:'same' for k in ('workerGenerationHash','authorizationHash','currentSemanticFrameHash','declarationHash')};before['refreshCount']=12
  after={**before,'refreshCount':13};entry.stable(before,after)
  for key in before:
   changed=dict(after);changed[key]=11 if key=='refreshCount' else 'changed'
   with self.subTest(key=key),self.assertRaises(ValueError):entry.stable(before,changed)
if __name__=='__main__':unittest.main()
