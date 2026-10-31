"""Root-custodied single ledger, atomic CAS and a separate lifetime flock.

No initialization, counters reset, source installation or native request API.
The installer must provision state.json and both lock files exactly once.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import uuid
from .core import require, encoded


def identity(s): return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)


def file_identity(s): return identity(s)+(s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


class Store:
    def __init__(self, root):
        self.path=Path(root);self.fds=[];self.ancestry=[];self.invocation_fd=None;self.invocation_pid=None
        require(self.path.is_absolute() and '..' not in self.path.parts and 2<=len(self.path.parts)<=48,
                'EXACT_OPERATIONAL_STORE_PATH_REQUIRED')
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.fds.append(fd)
            for name in self.path.parts[1:]:
                info=os.fstat(fd)
                require(info.st_uid==0 and stat.S_ISDIR(info.st_mode) and not info.st_mode&0o022,
                        'ROOT_PROTECTED_OPERATIONAL_ANCESTRY_REQUIRED')
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                self.fds.append(child);self.ancestry.append((fd,name,child,identity(os.fstat(child))));fd=child
            final=os.fstat(fd)
            require(final.st_uid==final.st_gid==0 and stat.S_IMODE(final.st_mode)==0o700,
                    'PRIVATE_OPERATIONAL_STORE_REQUIRED')
            self.fd=fd;self.check()
        except BaseException:
            self.close();raise

    def close(self):
        for fd in reversed(self.fds):os.close(fd)
        self.fds=[]

    def check(self):
        require(bool(self.fds),'OPERATIONAL_STORE_CLOSED')
        for parent,name,child,pin in self.ancestry:
            require(pin==identity(os.fstat(child))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'OPERATIONAL_STORE_ANCESTRY_CHANGED')

    def open_file(self,name,flags):
        self.check();require(name in('state.json','invocation.lock','cas.lock'),'CLOSED_OPERATIONAL_STORE_FILE_REQUIRED')
        fd=os.open(name,flags|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
        try:
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
                    and stat.S_IMODE(s.st_mode)==0o600,'PRIVATE_OPERATIONAL_STORE_FILE_REQUIRED')
            return fd
        except BaseException:os.close(fd);raise

    @contextmanager
    def lock(self,name):
        fd=self.open_file(name,os.O_RDONLY)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:require(False,'CONCURRENT_OPERATIONAL_OWNER')
            self.check();yield fd
        finally:os.close(fd)

    @contextmanager
    def invocation(self):
        require(self.invocation_fd is None,'NESTED_OPERATIONAL_OWNER_INVOCATION')
        with self.lock('invocation.lock') as fd:
            self.invocation_fd=fd;self.invocation_pid=os.getpid()
            try:yield self
            finally:self.invocation_fd=None;self.invocation_pid=None

    def assert_invocation(self):
        require(self.invocation_fd is not None and self.invocation_pid==os.getpid(),
                'SAME_PROCESS_OPERATIONAL_INVOCATION_REQUIRED')
        self.check()
        require(file_identity(os.fstat(self.invocation_fd))==file_identity(os.stat('invocation.lock',dir_fd=self.fd,follow_symlinks=False)),
                'OPERATIONAL_INVOCATION_LOCK_CHANGED')

    def read(self):
        self.check();fd=self.open_file('state.json',os.O_RDONLY)
        try:
            before=os.fstat(fd);require(0<before.st_size<=65536,'BOUNDED_OPERATIONAL_LEDGER_REQUIRED')
            chunks=[];count=0
            while count<before.st_size:
                part=os.read(fd,min(65536,before.st_size-count));require(bool(part),'COMPLETE_OPERATIONAL_LEDGER_REQUIRED')
                chunks.append(part);count+=len(part)
            raw=b''.join(chunks)
            require(file_identity(before)==file_identity(os.fstat(fd))
                    ==file_identity(os.stat('state.json',dir_fd=self.fd,follow_symlinks=False)),
                    'OPERATIONAL_LEDGER_CHANGED_DURING_READ')
            value=json.loads(raw)
            require(type(value) is dict and encoded(value)==raw,'CANONICAL_OPERATIONAL_LEDGER_REQUIRED')
            return value
        finally:os.close(fd)

    def cas(self,previous,following):
        self.assert_invocation()
        require(type(following) is dict and all(type(following[k]) is int for k in('version','cumulativeAttempts','attempts'))
                and following['version']==previous['version']+1
                and following['cumulativeAttempts']>=previous['cumulativeAttempts']
                and following['attempts']>=previous['attempts']
                and all(following[k]==previous[k] for k in('schema','installationHash','policyHash','predecessorInputsHash','priorControlledAttempts')),
                'OPERATIONAL_CAS_CANNOT_RESET_HISTORY')
        raw=encoded(following);require(0<len(raw)<=65536,'BOUNDED_OPERATIONAL_LEDGER_WRITE_REQUIRED')
        with self.lock('cas.lock'):
            require(self.read()==previous,'OPERATIONAL_CAS_CONFLICT')
            name='.state-'+uuid.uuid4().hex
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
            try:
                with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                self.check();require(self.read()==previous,'OPERATIONAL_LEDGER_CHANGED_BEFORE_REPLACE')
                os.replace(name,'state.json',src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)
                require(self.read()==following,'OPERATIONAL_CAS_READBACK_UNCONFIRMED')
            finally:
                os.close(fd)
                try:os.unlink(name,dir_fd=self.fd)
                except FileNotFoundError:pass
