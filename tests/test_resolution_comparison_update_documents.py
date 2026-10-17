"""Real file custody regression for the VPS's 777,974-byte private plan."""
import json,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.resolution_comparison_update import preparation as m
from tools.semantic_mcp_update.entry import publish_json as old_publish

@unittest.skipUnless(os.geteuid()==0,'actual root file custody required')
class PrivateDocuments(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
  self.context=Path(self.temp.name);self.context.chmod(0o700)
 def test_observed_plan_size_survives_durable_publish_and_exact_readback(self):
  value={'padding':'x'*(777974-len(m.encoded({'padding':''})))}
  self.assertEqual(len(m.encoded(value)),777974)
  with self.assertRaisesRegex(Exception,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):
   old_publish(self.context,'old-plan.json',value)
  for name in ('prepared-plan.json','execution-plan.json'):
   m.publish_json(self.context,name,value)
   p=self.context/name
   self.assertEqual(p.read_bytes(),m.encoded(value));self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
   self.assertEqual((p.stat().st_uid,p.stat().st_gid,p.stat().st_nlink),(0,0,1))
 def test_oversize_or_nonfinite_document_is_rejected_before_creating_a_file(self):
  for value in ({'padding':'x'*m.DOCUMENT_LIMIT},{'invalid':float('nan')}):
   with self.assertRaises(ValueError):m.publish_json(self.context,'prepared-plan.json',value)
   self.assertFalse((self.context/'prepared-plan.json').exists())
 def test_existing_or_symlink_document_is_never_overwritten_or_adopted(self):
  m.publish_json(self.context,'prepared-plan.json',{'original':True})
  before=(self.context/'prepared-plan.json').read_bytes()
  with self.assertRaises(FileExistsError):m.publish_json(self.context,'prepared-plan.json',{'replacement':True})
  self.assertEqual((self.context/'prepared-plan.json').read_bytes(),before)
  (self.context/'execution-plan.json').symlink_to(self.context/'prepared-plan.json')
  with self.assertRaises(FileExistsError):m.publish_json(self.context,'execution-plan.json',{'replacement':True})
  self.assertEqual((self.context/'prepared-plan.json').read_bytes(),before)
 def test_post_write_byte_change_is_detected_by_hash_and_unknown_names_are_rejected(self):
  original=m.private_file
  def changed(binding,maximum):
   Path(binding['path']).write_bytes(b'changed after write')
   return original(binding,maximum)
  with patch.object(m,'private_file',side_effect=changed):
   with self.assertRaisesRegex(Exception,'PROCESS_ARTIFACT_CHANGED_OR_HASH_MISMATCH'):
    m.publish_json(self.context,'prepared-plan.json',{'reviewed':True})
  with self.assertRaisesRegex(ValueError,'EXACT_COMPARISON_DOCUMENT_REQUIRED'):
   m.publish_json(self.context,'authority.json',{})
  self.assertFalse((self.context/'authority.json').exists())
if __name__=='__main__':unittest.main()
