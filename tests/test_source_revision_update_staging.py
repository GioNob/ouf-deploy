"""Stage the actual complete executable closure, without target access."""
import hashlib,json,runpy,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class Staging(unittest.TestCase):
 def test_exact_hashes_and_non_overwritable_directory(self):
  ns=runpy.run_path(str(ROOT/'scripts/stage-source-revision-executor.py'))
  with tempfile.TemporaryDirectory()as temp:
   output=Path(temp)/'code';package=ns['stage'](ROOT,output,'a'*40)
   boot=runpy.run_path(str(output/'execute.py'))
   self.assertEqual(set(package['sourceHashes']),set(boot['OVERLAYS']))
   for module,(name,relative)in boot['OVERLAYS'].items():
    self.assertEqual((output/name).read_bytes(),(ROOT/relative).read_bytes())
    self.assertEqual(hashlib.sha256((output/name).read_bytes()).hexdigest(),package['sourceHashes'][module])
   case=json.loads((output/'case.json').read_bytes())
   self.assertEqual(case['preparedPlanBinding']['sha256'],'c23ec15b43427c4558b5b06bf36c2c1b4fa73943efbc0e081ad2731b69c9bc89')
   self.assertEqual(case['schema'],'ouf.source-revision-update-selection.v1')
   self.assertEqual(package['schema'],'ouf.source-revision-executable-package.v1')
   self.assertEqual((output/'package.json').stat().st_mode&0o777,0o600)
   with self.assertRaises(AssertionError):ns['stage'](ROOT,output,'a'*40)

if __name__=='__main__':unittest.main()
