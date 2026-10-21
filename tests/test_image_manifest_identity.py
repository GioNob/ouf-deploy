import copy,io,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/semantic_application_cutover'))
import image_manifest_identity as m
from test_image_custody import fixture,audit,native
class ManifestIdentity(unittest.TestCase):
 def test_manifest_identity_keeps_config_identity_distinct(self):
  for compressed in (False,True):
   d=fixture(compressed=compressed);a=audit(d);descriptor=m.descriptor(io.BytesIO(d[0]),a)
   self.assertNotEqual(descriptor['digest'],a['imageId'])
   n=native(a);n.update(Id=descriptor['digest'],Descriptor=descriptor,RepoTags=[])
   proof=m.loaded(a,descriptor,n)
   self.assertEqual(proof['configImageId'],a['imageId']);self.assertEqual(proof['nativeEngineImageId'],descriptor['digest'])
   self.assertFalse(proof['targetApplyAuthorized']);self.assertNotIn('imageConfig',proof)
 def test_descriptor_id_platform_rootfs_config_and_tags_must_match(self):
  d=fixture();a=audit(d);descriptor=m.descriptor(io.BytesIO(d[0]),a)
  for change in (lambda n:n.__setitem__('Id',a['imageId']),lambda n:n['Descriptor'].__setitem__('size',0),lambda n:n.__setitem__('Os','windows'),lambda n:n['RootFS']['Layers'].clear(),lambda n:n['Config'].__setitem__('User','0'),lambda n:n.__setitem__('RepoTags',['bad:tag'])):
   n=native(a);n.update(Id=descriptor['digest'],Descriptor=copy.deepcopy(descriptor),RepoTags=[]);change(n)
   with self.assertRaises(ValueError):m.loaded(a,descriptor,n)
 def test_authenticated_archive_changes_deny_manifest_derivation(self):
  d=fixture();a=audit(d)
  with self.assertRaisesRegex(ValueError,'AUTHENTICATED_ARCHIVE_BYTES_CHANGED'):m.descriptor(io.BytesIO(d[0]+b'changed'),a)
if __name__=='__main__':unittest.main()
