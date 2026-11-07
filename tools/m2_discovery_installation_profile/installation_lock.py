"""Read an existing logical fence inode without taking the worker lifetime lock.

Read-only installation observers must work while the installed worker holds its
lifetime flock. Mutation paths keep using existing_kernel_lock; this helper
neither acquires authority nor permits dispatch or state reinitialization.
"""
from contextlib import contextmanager
import os,stat
from pathlib import Path
from .custody_capture import require
from tools.semantic_registry_operational_owner.installation import directory


@contextmanager
def observed_logical_inode(path,expected):
    path=Path(path)
    with directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        def pin(s):return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink]
        def check():
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0
                and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1
                and pin(s)==expected==pin(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                'CURRENT_OBSERVED_WORKER_LOGICAL_LOCK_INODE_REQUIRED')
        try:check();yield;check()
        finally:os.close(fd)
