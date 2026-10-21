import importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from test_image_custody import audit,fixture,native
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
from image_import import Import
path=ROOT/'tools/semantic_lease_recovery/recovery_journal.py'
if not path.exists():path=ROOT/'tests/fixtures/recovery_journal.py'
spec=importlib.util.spec_from_file_location('import_journal',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Imports(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.audit=audit(fixture());self.auth='b'*64
  self.journal=m.Journal(self.root);self.initial=Import.initial(self.audit,self.auth);self.journal.initialize(self.initial)
  self.session=Import(self.journal,self.initial['contextHash']);self.calls=0;self.path=self.root/'image.json'
 def tearDown(self):self.temp.cleanup()
 def inspect(self,image):return json.loads(self.path.read_text()) if self.path.exists() else None
 def load(self):self.calls+=1;self.path.write_text(json.dumps(native(self.audit)))
 def check(self,phase):return self.auth
 def test_exactly_one_effect_and_durable_verification(self):
  with self.session.invocation():proof=self.session.import_once(self.audit,self.load,self.inspect,self.check)
  self.assertTrue(proof['imageByteCustodyProven']);self.assertEqual(self.calls,1)
  self.assertEqual(self.journal.read()['effectAttemptCount'],1)
  with self.session.invocation(),self.assertRaisesRegex(ValueError,'NO_REPLAY'):self.session.import_once(self.audit,self.load,self.inspect,self.check)
  self.assertEqual(self.calls,1)
 def test_existing_exact_image_requires_no_load(self):
  self.path.write_text(json.dumps(native(self.audit)))
  with self.session.invocation():self.session.import_once(self.audit,self.load,self.inspect,self.check)
  self.assertEqual(self.calls,0);self.assertEqual(self.journal.read()['effectAttemptCount'],0)
 def test_timeout_after_effect_reconciles_without_resending(self):
  def timeout():self.load();raise TimeoutError('fixture')
  with self.session.invocation(),self.assertRaises(TimeoutError):self.session.import_once(self.audit,timeout,self.inspect,self.check)
  self.assertEqual(self.journal.read()['state'],'IN_FLIGHT')
  restarted=Import(m.Journal(self.root),self.initial['contextHash'])
  with restarted.invocation():restarted.reconcile(self.audit,self.inspect,self.check)
  self.assertEqual(self.calls,1);self.assertEqual(self.journal.read()['state'],'VERIFIED')
 def test_absence_after_crash_stays_ambiguous_no_retry(self):
  def timeout():raise TimeoutError('fixture')
  with self.session.invocation(),self.assertRaises(TimeoutError):self.session.import_once(self.audit,timeout,self.inspect,self.check)
  with self.session.invocation(),self.assertRaisesRegex(ValueError,'ABSENCE'):self.session.reconcile(self.audit,self.inspect,self.check)
  self.assertEqual(self.journal.read()['state'],'IN_FLIGHT');self.assertEqual(self.calls,0)
 def test_wrong_native_image_does_not_close_in_flight(self):
  def wrong():self.load();value=native(self.audit);value['RootFS']['Layers']=[];self.path.write_text(json.dumps(value))
  with self.session.invocation(),self.assertRaises(ValueError):self.session.import_once(self.audit,wrong,self.inspect,self.check)
  self.assertEqual(self.journal.read()['state'],'IN_FLIGHT')
 def test_changed_authority_before_effect_leaves_claim_consumed(self):
  def check(phase):return '0'*64 if phase=='BEFORE_IMAGE_IMPORT_EFFECT' else self.auth
  with self.session.invocation(),self.assertRaises(ValueError):self.session.import_once(self.audit,self.load,self.inspect,check)
  self.assertEqual(self.calls,0);self.assertEqual(self.journal.read()['state'],'IN_FLIGHT')
 def test_unknown_authority_blocks_before_claim(self):
  with self.session.invocation(),self.assertRaises(ValueError):self.session.import_once(self.audit,self.load,self.inspect,lambda phase:'0'*64)
  self.assertEqual(self.journal.read(),self.initial);self.assertEqual(self.calls,0)
 def test_concurrent_invocation_is_denied(self):
  other=Import(m.Journal(self.root),self.initial['contextHash'])
  with self.session.invocation(),self.assertRaises(BlockingIOError):
   with other.invocation():pass
 def test_real_process_exit_after_effect_then_parent_reconciles(self):
  pid=os.fork()
  if pid==0:
   with self.session.invocation():
    def exit_after_effect():self.load();os._exit(71)
    self.session.import_once(self.audit,exit_after_effect,self.inspect,self.check)
   os._exit(72)
  _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),71)
  self.assertEqual(self.journal.read()['state'],'IN_FLIGHT')
  with self.session.invocation():self.session.reconcile(self.audit,self.inspect,self.check)
  self.assertEqual(self.calls,0);self.assertEqual(self.journal.read()['state'],'VERIFIED')
if __name__=='__main__':unittest.main()
