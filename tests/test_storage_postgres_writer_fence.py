"""Offline boundaries; native state/concurrency proof is a separate required CI step."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('writer_fence',ROOT/'tests/run_storage_postgres_writer_fence.py')
fence=importlib.util.module_from_spec(spec);spec.loader.exec_module(fence)

class FixtureBoundaryTest(unittest.TestCase):
 def test_sql_literal_escaping_is_not_a_supported_input_path(self):
  for operation in ("lab-a');DROP SCHEMA public;--",'lab-','foreign-a','lab-'+'x'*49,None):
   with self.subTest(operation=operation),self.assertRaises(RuntimeError):fence.call_sql('reserve',operation,1,'a'*64,1)
 def test_numeric_and_function_bounds(self):
  for value in (-1,2**31+1,True,1.0,None):
   with self.subTest(value=value),self.assertRaises(RuntimeError):fence.call_sql('begin_drain',1,value)
  with self.assertRaises(RuntimeError):fence.call_sql('reopen',1)
  with self.assertRaises(RuntimeError):fence.call_sql('reserve','lab-a',1,'a'*64,4097)
 def test_duplicate_local_effect_cannot_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'body';fence.persist_body(path,b'first')
   with self.assertRaises(FileExistsError):fence.persist_body(path,b'other')
   self.assertEqual(path.read_bytes(),b'first')
 def test_corrupt_equal_length_body_cannot_resolve_pending(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'body';path.write_bytes(b'wrong');digest,size=fence.body_identity(b'right')
   with self.assertRaisesRegex(RuntimeError,'BODY_RECONCILIATION_REQUIRED'):fence.reconciled_body_identity(path,digest,size)
 def test_correct_body_is_fully_read_and_bound(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'body';body=bytes(range(256))*16;path.write_bytes(body);identity=fence.body_identity(body)
   self.assertEqual(fence.reconciled_body_identity(path,*identity),identity)
   path.write_bytes(body+b'x')
   with self.assertRaisesRegex(RuntimeError,'FIXTURE_BODY_BUDGET'):fence.reconciled_body_identity(path,*identity)
 def test_symlink_and_absent_body_are_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'body';link=Path(d)/'link';path.write_bytes(b'a');link.symlink_to(path);identity=fence.body_identity(b'a')
   for input_path in (link,Path(d)/'absent',Path(d)):
    with self.subTest(path=input_path),self.assertRaisesRegex(RuntimeError,'REGULAR_FIXTURE_BODY_REQUIRED'):fence.reconciled_body_identity(input_path,*identity)
 def test_empty_body_is_not_confused_with_missing(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'body';fence.persist_body(path,b'');identity=fence.body_identity(b'')
   self.assertEqual(fence.reconciled_body_identity(path,*identity),identity)

if __name__=='__main__':unittest.main()
