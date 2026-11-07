import importlib.util
from pathlib import Path
import unittest

s=importlib.util.spec_from_file_location('inventory',Path(__file__).parents[1]/'tools/storage_migration/inventory.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def row(key='managed-files/id',**extra):
 r={'bucket':'synthetic','key':key,'versionId':None,'isLatest':True,'deleteMarker':False,'size':2,'sha256':'sha256:'+'a'*64,'metadataSha256':'sha256:'+'b'*64};r.update(extra);return r
class InventoryTest(unittest.TestCase):
 def test_safe_and_public_redaction(self):
  report=m.validate([row()]);self.assertEqual(report['namespaceGate'],'PASS');self.assertNotIn('synthetic',str(report));self.assertNotIn('managed-files',str(report))
 def test_prefix_collision_including_hidden_version(self):
  report=m.validate([row('a',versionId='old',isLatest=False),row('a/b')]);self.assertEqual(report['namespaceGate'],'HELD')
 def test_similar_prefix_is_safe(self):self.assertEqual(m.validate([row('ab'),row('a/b')])['namespaceGate'],'PASS')
 def test_unsafe_paths_and_trailing_slash(self):
  for key in ['a/../b','a//b','/a','a\\b','a\x00b','a/']:
   self.assertEqual(m.validate([row(key)])['namespaceGate'],'HELD')
 def test_duplicate_and_latest_denied(self):
  for records in [[row(),row()],[row(versionId='one'),row(versionId='two')]]:
   with self.assertRaises(ValueError):m.validate(records)
 def test_missing_hash_cannot_prove_migration(self):
  with self.assertRaises(ValueError):m.compare_verified([row(sha256=None)],[row()])
 def test_unsafe_equal_inventories_cannot_be_accepted(self):
  with self.assertRaises(ValueError):m.compare_verified([row('a/../b')],[row('a/../b')])
 def test_changed_version_id_mapping(self):
  self.assertEqual(m.compare_verified([row(versionId='old')],[row(versionId='new',sourceVersionId='old')]),{'missing':0,'extra':0,'mismatch':0})
 def test_corrupted_body_metadata_missing_and_extra(self):
  self.assertEqual(m.compare_verified([row(),row('missing')],[row(sha256='sha256:'+'c'*64),row('extra')]),{'missing':1,'extra':1,'mismatch':1})
 def test_marker_and_byte_counts(self):
  report=m.validate([row(versionId='old',isLatest=False),row(versionId='marker',deleteMarker=True,size=0,sha256=None,metadataSha256=None)])
  self.assertEqual(report['deleteMarkers'],1);self.assertEqual(report['bytesAcrossVersions'],2)
