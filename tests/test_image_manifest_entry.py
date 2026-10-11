import hashlib,importlib.util,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('manifest_entry',ROOT/'scripts/reconcile-v11-manifest-image.py');e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
class Entry(unittest.TestCase):
 def test_seven_authenticated_sources_checked_before_any_exec(self):
  paths={'original_program':'scripts/import-verified-v11-image.py','custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py','audit':'tools/semantic_application_cutover/image_custody.py','importer':'tools/semantic_application_cutover/image_import.py','journal':'tools/semantic_lease_recovery/recovery_journal.py','engine':'tools/semantic_application_cutover/engine_creation.py','manifest':'tools/semantic_application_cutover/image_manifest_identity.py'}
  fallback={'custody':'tests/fixtures/custody.py','journal':'tests/fixtures/recovery_journal.py'}
  sources={}
  for name,path in paths.items():
   file=ROOT/path
   if not file.exists():file=ROOT/fallback[name]
   sources[name]=file.read_bytes();self.assertEqual(hashlib.sha256(sources[name]).hexdigest(),e.HASHES[name])
  for target in sources:
   broken=dict(sources);broken[target]+=b'#drift'
   with self.subTest(target=target),patch('builtins.exec',side_effect=AssertionError('EARLY_EXECUTION')),self.assertRaisesRegex(ValueError,'SOURCE_HASH_MISMATCH'):e.modules(broken)
 def test_missing_source_denied_before_exec(self):
  with patch('builtins.exec',side_effect=AssertionError('EARLY_EXECUTION')),self.assertRaisesRegex(ValueError,'EXACT_MANIFEST_RECONCILIATION'):e.modules({})
if __name__=='__main__':unittest.main()
