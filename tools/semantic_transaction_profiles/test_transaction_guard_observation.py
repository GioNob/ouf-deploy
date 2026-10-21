"""Descriptor custody tests; no simulated native result supplies authority."""
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'semantic_frame_compiler'),str(HERE.parent/'semantic_cohort_admission/cohort-draft')]
from transaction_guard_observation import ensure_borrowed_lock
from authenticate_provider_transaction import TransactionDenied


class BorrowedLockTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()),prefix='guard-lock-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.path=self.root/'lock';self.path.touch(mode=0o600)

    def test_borrowed_descriptor_stays_exclusive_after_observation(self):
        fd=os.open(self.path,os.O_RDWR);other=os.open(self.path,os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);ensure_borrowed_lock(fd,self.path)
            with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(other);os.close(fd)

    def test_foreign_descriptor_cannot_replace_guard_lock(self):
        other=self.root/'other';other.touch(mode=0o600);fd=os.open(other,os.O_RDWR)
        try:
            with self.assertRaisesRegex(TransactionDenied,'BORROWED_GUARD_LOCK_INODE_DRIFT'):ensure_borrowed_lock(fd,self.path)
        finally:os.close(fd)

    def test_same_path_replaced_inode_rejected(self):
        fd=os.open(self.path,os.O_RDWR)
        try:
            replacement=self.root/'replacement';replacement.touch(mode=0o600);os.replace(replacement,self.path)
            with self.assertRaisesRegex(TransactionDenied,'BORROWED_GUARD_LOCK_INODE_DRIFT'):ensure_borrowed_lock(fd,self.path)
        finally:os.close(fd)


if __name__=='__main__':unittest.main()
