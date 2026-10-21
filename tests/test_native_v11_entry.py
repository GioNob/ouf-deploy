import hashlib,importlib.util,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('native_v11_entry',ROOT/'scripts/prepare-native-v11-plan.py');e=importlib.util.module_from_spec(s);s.loader.exec_module(e)
PATHS={'reader':'scripts/read-current-r12-cutover-custody.py','planner':'scripts/compile-semantic-creation-plan-after-r12.py',
 'prepare':'scripts/prepare-semantic-inputs-after-r12.py','custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py',
 'creation':'tools/semantic_application_cutover/creation_plan.py','original_program':'scripts/import-verified-v11-image.py',
 'audit':'tools/semantic_application_cutover/image_custody.py','importer':'tools/semantic_application_cutover/image_import.py',
 'journal':'tools/semantic_lease_recovery/recovery_journal.py','engine':'tools/semantic_application_cutover/engine_creation.py',
 'rebase':'tools/semantic_application_cutover/rebase_native_manifest.py'}
def sources():
 out={}
 for name,path in PATHS.items():
  f=ROOT/path
  if not f.exists():f=ROOT/'tests/fixtures'/(('recovery_journal' if name=='journal' else name)+'.py')
  out[name]=f.read_bytes()
 return out
class Entry(unittest.TestCase):
 def test_all_eleven_hashes_checked_before_any_execution(self):
  valid=sources()
  for k,v in valid.items():self.assertEqual(hashlib.sha256(v).hexdigest(),e.HASHES[k])
  for name in valid:
   broken=dict(valid);broken[name]+=b'#tamper'
   with self.subTest(name=name),patch('builtins.exec',side_effect=AssertionError('EARLY_EXEC')),self.assertRaisesRegex(ValueError,'HASH_MISMATCH'):e.modules(broken)
 def test_partial_closure_denied_before_execution(self):
  with patch('builtins.exec',side_effect=AssertionError('EARLY_EXEC')),self.assertRaisesRegex(ValueError,'EXACT_NATIVE_PLAN_SOURCE_SET'):e.modules({})
 def test_complete_closure_loads_original_custody_and_native_source_binding(self):
  loaded=e.modules(sources())
  self.assertEqual(loaded['rebase'].CONFIG,loaded['original_program'].IMAGE)
  self.assertEqual(loaded['rebase'].DECL,loaded['original_program'].DECL)
if __name__=='__main__':unittest.main()
