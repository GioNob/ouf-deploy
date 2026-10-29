import hashlib,importlib.util,io,json,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('import_entry',ROOT/'scripts/import-verified-v11-image.py');e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
class Entry(unittest.TestCase):
 def test_all_five_source_hashes_are_checked_before_any_module_execution(self):
  paths={'custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py','audit':'tools/semantic_application_cutover/image_custody.py','importer':'tools/semantic_application_cutover/image_import.py','journal':'tools/semantic_lease_recovery/recovery_journal.py','engine':'tools/semantic_application_cutover/engine_creation.py'}
  fallback={'custody':'tests/fixtures/custody.py','journal':'tests/fixtures/recovery_journal.py'}
  sources={}
  for name,path in paths.items():
   file=ROOT/path
   if not file.exists():file=ROOT/fallback[name]
   sources[name]=file.read_bytes();self.assertEqual(hashlib.sha256(sources[name]).hexdigest(),e.SOURCE_HASHES[name])
  for target in sources:
   broken=dict(sources);broken[target]+=b'#drift'
   with self.subTest(target=target),patch('builtins.exec',side_effect=AssertionError('EARLY_EXECUTION')),self.assertRaisesRegex(ValueError,'SOURCE_HASH_MISMATCH'):e.modules(broken)
 def test_partial_closure_denied(self):
  with self.assertRaisesRegex(ValueError,'EXACT_IMAGE_IMPORT_SOURCE_CLOSURE'):e.modules({})
 def test_changed_or_applied_private_plan_denied_before_import(self):
  decl={'candidateImageId':e.IMAGE,'productionApplyReady':False,'applicationCutoverAuthorized':False,'completeReplacementOciProven':False};req={'Image':e.IMAGE}
  class Fake:
   def file_bytes(self,path,*args,**kwargs):return json.dumps(decl if path.name=='private-runtime-declaration.json' else req).encode()
  e.plan(Fake())
  for key in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven'):
   decl[key]=True
   with self.assertRaisesRegex(ValueError,'EXACT_UNAPPLIED'):e.plan(Fake())
   decl[key]=False
  req['Image']='other'
  with self.assertRaisesRegex(ValueError,'EXACT_UNAPPLIED'):e.plan(Fake())
 def test_growing_source_is_bounded_during_copy(self):
  dst=io.BytesIO()
  with self.assertRaisesRegex(ValueError,'BOUNDED_ORIGINAL_COPY'):e.bounded_copy(io.BytesIO(b'x'*65),dst,64)
  self.assertLessEqual(len(dst.getvalue()),64)
 def test_exact_copy_preserves_bytes(self):
  dst=io.BytesIO();self.assertEqual(e.bounded_copy(io.BytesIO(b'original'),dst,8),8);self.assertEqual(dst.getvalue(),b'original')
if __name__=='__main__':unittest.main()
