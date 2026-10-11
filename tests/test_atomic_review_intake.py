import importlib.util,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('intake',ROOT/'tools/semantic_application_cutover/atomic_review_intake.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class AtomicReview(unittest.TestCase):
 def inputs(self):
  files={name:b'private-fixture-bytes' for name in ('declaration.json','request.json','observation.json','receipt.json')}
  manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','fileHashes':{n:m.sha(v) for n,v in files.items()},'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False,'observationsAreHistorical':True}
  return files,manifest
 def test_complete_publication_and_same_content_repeat_without_writes(self):
  with tempfile.TemporaryDirectory() as folder:
   files,manifest=self.inputs();result=m.publish(folder,files,manifest,os.geteuid());self.assertEqual(result['protectedFileWrites'],5);self.assertTrue(result['publicationIsAtomic']);self.assertFalse(manifest['applicationCutoverAuthorized'])
   again=m.publish(folder,files,manifest,os.geteuid());self.assertFalse(again['newPublication']);self.assertEqual(again['protectedFileWrites'],0);self.assertEqual(result['intakeHash'],again['intakeHash'])
 def test_crash_at_every_prepublication_boundary_never_exposes_partial_intake(self):
  points=['BEFORE_FILE_'+n for n in ('declaration.json','request.json','observation.json','receipt.json','intake.json')]+['AFTER_FILE_'+n for n in ('declaration.json','request.json','observation.json','receipt.json','intake.json')]+['BEFORE_ATOMIC_PUBLICATION']
  for point in points:
   with self.subTest(point=point),tempfile.TemporaryDirectory() as folder:
    files,manifest=self.inputs()
    def crash(p):
     if p==point:raise RuntimeError('fixture-crash')
    with self.assertRaisesRegex(RuntimeError,'fixture-crash'):m.publish(folder,files,manifest,os.geteuid(),crash)
    self.assertEqual(list(Path(folder).glob('semantic-native-v11-intake-*')),[])
    result=m.publish(folder,files,manifest,os.geteuid());self.assertTrue(result['publicationIsAtomic'])
 def test_crash_after_rename_is_reconciled_without_republication(self):
  with tempfile.TemporaryDirectory() as folder:
   files,manifest=self.inputs()
   def crash(point):
    if point=='AFTER_ATOMIC_PUBLICATION':raise RuntimeError('fixture-crash')
   with self.assertRaises(RuntimeError):m.publish(folder,files,manifest,os.geteuid(),crash)
   result=m.publish(folder,files,manifest,os.geteuid());self.assertFalse(result['newPublication']);self.assertEqual(result['protectedFileWrites'],0)
 def test_existing_tampered_partial_symlink_or_permissive_file_is_denied(self):
  for mode in ('tamper','partial','link','mode'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
    files,manifest=self.inputs();result=m.publish(folder,files,manifest,os.geteuid());path=Path(result['directory'])/'request.json'
    if mode=='tamper':path.write_bytes(b'foreign')
    elif mode=='partial':path.unlink()
    elif mode=='mode':path.chmod(0o644)
    else:path.unlink();path.symlink_to('/dev/null')
    with self.assertRaises((ValueError,OSError)):m.publish(folder,files,manifest,os.geteuid())
 def test_authority_promotion_bad_names_hashes_and_oversized_inputs_are_denied(self):
  for key in ('productionApplyReady','applicationCutoverAuthorized','runtimeAuthorityIssued'):
   with tempfile.TemporaryDirectory() as folder:
    files,manifest=self.inputs();manifest[key]=True
    with self.assertRaises(ValueError):m.publish(folder,files,manifest,os.geteuid())
  with tempfile.TemporaryDirectory() as folder:
   files,manifest=self.inputs();files['../escape']=b'bad'
   with self.assertRaises(ValueError):m.publish(folder,files,manifest,os.geteuid())
if __name__=='__main__':unittest.main()
