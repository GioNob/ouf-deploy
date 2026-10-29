import copy,io,unittest
import test_image_import as baseline
from test_image_custody import fixture,native
import image_manifest_identity as identity
class Reconciliation(unittest.TestCase):
 tearDown=baseline.Imports.tearDown
 check=baseline.Imports.check
 def setUp(self):
  baseline.Imports.setUp(self);self.descriptor=identity.descriptor(io.BytesIO(fixture()[0]),self.audit)
  self.actual=native(self.audit);self.actual.update(Id=self.descriptor['digest'],Descriptor=self.descriptor,RepoTags=[])
 def consume(self):
  def unavailable():raise TimeoutError('fixture')
  with self.session.invocation(),self.assertRaises(TimeoutError):self.session.import_once(self.audit,unavailable,lambda _:None,self.check)
 def reconcile(self,inspect=None,check=None):
  with self.session.invocation():return identity.reconcile_existing(self.session,self.audit,self.descriptor,inspect or (lambda _:copy.deepcopy(self.actual)),check or self.check)
 def test_preserved_consumed_intent_closes_and_verifies_without_any_second_effect(self):
  self.consume();before=self.journal.read();proof=self.reconcile();after=self.journal.read()
  for key in ('intent','authorityHash','contextHash','effectAttemptCount'):self.assertEqual(after[key],before[key])
  self.assertEqual(after['version'],2);self.assertEqual(after['state'],'VERIFIED');self.assertEqual(self.calls,0)
  self.assertEqual(proof['configImageId'],self.audit['imageId']);self.assertEqual(proof['nativeEngineImageId'],self.descriptor['digest'])
  self.assertEqual(self.reconcile(),proof);self.assertEqual(self.journal.read(),after)
 def test_ready_journal_is_not_consumed_or_initialized(self):
  with self.assertRaisesRegex(ValueError,'EXISTING_CONSUMED'):self.reconcile()
  self.assertEqual(self.journal.read(),self.initial)
 def test_absent_wrong_descriptor_changed_read_or_authority_leaves_original_in_flight(self):
  self.consume();before=self.journal.read()
  with self.assertRaises(ValueError):self.reconcile(lambda _:None)
  wrong=copy.deepcopy(self.actual);wrong['Descriptor']['digest']='sha256:'+'0'*64
  with self.assertRaises(ValueError):self.reconcile(lambda _:wrong)
  reads=iter([self.actual,wrong])
  with self.assertRaisesRegex(ValueError,'CHANGED'):self.reconcile(lambda _:next(reads))
  with self.assertRaises(ValueError):self.reconcile(check=lambda _:'0'*64)
  self.assertEqual(self.journal.read(),before);self.assertEqual(self.calls,0)
if __name__=='__main__':unittest.main()
