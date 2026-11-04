"""Offline artifact and recovery-input boundaries; native WAL proof is separate."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pitr',ROOT/'tests/run_storage_postgres_pitr.py');pitr=importlib.util.module_from_spec(spec);spec.loader.exec_module(pitr)
from storage_pitr_archive import copy_wal,read_regular
NAME='000000010000000000000004'

@contextmanager
def fixture():
 with tempfile.TemporaryDirectory() as d:
  root=Path(d);(root/'pg_wal').mkdir();(root/'archive').mkdir();before=Path.cwd();os.chdir(root)
  try:yield root
  finally:os.chdir(before)

class PhysicalPitrBoundaries(unittest.TestCase):
 def test_archive_duplicate_is_verified_and_corruption_not_overwritten(self):
  with fixture() as root:
   source=root/'pg_wal'/NAME;source.write_bytes(b'wal');log=root/'events'
   self.assertEqual(copy_wal('archive',root/'archive','pg_wal/'+NAME,NAME,log),0)
   self.assertEqual(copy_wal('archive',root/'archive','pg_wal/'+NAME,NAME,log),0)
   source.write_bytes(b'bad')
   with self.assertRaisesRegex(RuntimeError,'EXISTING_ARCHIVE_BYTES_DIFFER'):copy_wal('archive',root/'archive','pg_wal/'+NAME,NAME,log)
   self.assertEqual((root/'archive'/NAME).read_bytes(),b'wal')
 def test_restore_requires_the_actual_archived_bytes(self):
  with fixture() as root:
   (root/'archive'/NAME).write_bytes(b'archived wal')
   self.assertEqual(copy_wal('restore',root/'archive','pg_wal/RECOVERYXLOG',NAME,root/'events'),0)
   self.assertEqual((root/'pg_wal/RECOVERYXLOG').read_bytes(),b'archived wal')
   event=json.loads((root/'events').read_text());self.assertEqual(event['sha256'],hashlib.sha256(b'archived wal').hexdigest())
 def test_missing_wal_returns_failure_without_making_destination(self):
  with fixture() as root:
   self.assertEqual(copy_wal('restore',root/'archive','pg_wal/RECOVERYXLOG',NAME,root/'events'),1)
   self.assertFalse((root/'pg_wal/RECOVERYXLOG').exists());self.assertEqual(json.loads((root/'events').read_text())['status'],'MISSING')
 def test_name_path_traversal_and_absolute_destination_are_rejected(self):
  with fixture() as root:
   for path,name in [('pg_wal/../outside',NAME),('/tmp/outside',NAME),('pg_wal/RECOVERYXLOG','../file'),('pg_wal/RECOVERYXLOG','x'*24)]:
    with self.subTest(path=path,name=name),self.assertRaises(RuntimeError):copy_wal('restore',root/'archive',path,name,root/'events')
 def test_symlink_wal_and_destination_are_rejected(self):
  with fixture() as root:
   (root/'target').write_bytes(b'original');(root/'archive'/NAME).symlink_to(root/'target')
   with self.assertRaises(OSError):copy_wal('restore',root/'archive','pg_wal/RECOVERYXLOG',NAME,root/'events')
   (root/'archive'/NAME).unlink();(root/'archive'/NAME).write_bytes(b'new');(root/'pg_wal/RECOVERYXLOG').symlink_to(root/'target')
   with self.assertRaisesRegex(RuntimeError,'DESTINATION_SYMLINK_DENIED'):copy_wal('restore',root/'archive','pg_wal/RECOVERYXLOG',NAME,root/'events')
   self.assertEqual((root/'target').read_bytes(),b'original')
 def test_regular_file_byte_limit(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'file';path.write_bytes(b'12345')
   with self.assertRaisesRegex(RuntimeError,'BOUNDED_REGULAR_WAL_REQUIRED'):read_regular(path,4)
 def test_packaging_retains_all_original_file_bytes(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=root/'base';source.mkdir();(source/'data').write_bytes(b'a\0\xff');(source/'empty').write_bytes(b'')
   before=pitr.inventory(source);archive=root/'original.tar.gz';self.assertEqual(pitr.package(source,archive),before)
   with tarfile.open(archive,'r:gz') as tar:
    self.assertEqual(sorted(tar.getnames()),sorted(before))
    for name,row in before.items():self.assertEqual(hashlib.sha256(tar.extractfile(name).read()).hexdigest(),row['sha256'])
 def test_backup_symlink_cannot_escape_original_tree(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'link').symlink_to('/etc/passwd')
   with self.assertRaisesRegex(RuntimeError,'BACKUP_SYMLINK_DENIED'):pitr.inventory(root)
 def test_shell_config_paths_do_not_accept_interpolation(self):
  for value in ('/tmp/something;rm','/tmp/has space',"/tmp/quote'",'/tmp/dollar$','/tmp/back`tick'):
   with self.subTest(path=value),self.assertRaisesRegex(RuntimeError,'FIXTURE_SHELL_PATH_REQUIRED'):pitr.safe_path(Path(value))

if __name__=='__main__':unittest.main()
