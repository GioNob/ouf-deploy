"""Short CAS transactions in an owner-supplied sealed private directory.

Entrypoint must validate ancestor custody and bind directory/context to its new
one-use authority. This helper does not discover directories or grant restart.
No shared lease lock is used. Never hold this journal lock across external I/O.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import uuid

def require(ok, code):
    if not ok: raise ValueError(code)

def encoded(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    require(len(raw) <= 65536, 'RECOVERY_RECORD_BOUNDED_REQUIRED')
    return raw

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'DUPLICATE_RECOVERY_KEY')
        value[key] = item
    return value

class Journal:
    def __init__(self, directory):
        self.root = Path(directory)
        require(self.root.is_absolute() and self.root.resolve() == self.root and '..' not in self.root.parts,
                'SEALED_PRIVATE_DIRECTORY_REQUIRED')
        self.uid, self.gid = os.geteuid(), os.getegid()
        s = self.root.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == self.uid and s.st_gid == self.gid
                and stat.S_IMODE(s.st_mode) == 0o700, 'PRIVATE_DIRECTORY_CUSTODY_REQUIRED')
        self.directory_id = (s.st_dev, s.st_ino)
        self.record, self.lock = self.root / 'recovery.json', self.root / 'recovery.lock'

    def check_directory(self):
        s = self.root.lstat()
        require(stat.S_ISDIR(s.st_mode) and (s.st_dev, s.st_ino) == self.directory_id
                and s.st_uid == self.uid and s.st_gid == self.gid and stat.S_IMODE(s.st_mode) == 0o700,
                'RECOVERY_DIRECTORY_DRIFT')

    def check_file(self, s):
        require(stat.S_ISREG(s.st_mode) and s.st_uid == self.uid and s.st_gid == self.gid
                and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size <= 65536,
                'RECOVERY_FILE_CUSTODY_REQUIRED')

    def create(self, path, raw):
        self.check_directory()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.close(fd)

    def sync(self):
        self.check_directory()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

    def initialize(self, record):
        # Partial initialization never becomes permission to auto reinitialize.
        self.create(self.lock, b'')
        self.create(self.root / 'invocation.lock', b'')
        self.create(self.record, encoded(record))
        self.sync()

    @contextmanager
    def invocation(self):
        """Exclusive process fencing; separate from short journal/lease locks."""
        self.check_directory()
        path = self.root / 'invocation.lock'
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            self.check_file(info)
            require((info.st_dev, info.st_ino) == (path.lstat().st_dev, path.lstat().st_ino),
                    'WORKER_LOCK_IDENTITY_DRIFT')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    @contextmanager
    def transaction(self):
        self.check_directory()
        fd = os.open(self.lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            s = os.fstat(fd); self.check_file(s)
            require((s.st_dev, s.st_ino) == (self.lock.lstat().st_dev, self.lock.lstat().st_ino), 'RECOVERY_LOCK_IDENTITY_DRIFT')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
            self.check_directory()
            require((s.st_dev, s.st_ino) == (self.lock.lstat().st_dev, self.lock.lstat().st_ino), 'RECOVERY_LOCK_IDENTITY_DRIFT')
        finally:
            os.close(fd)

    def private_read(self):
        fd = os.open(self.record, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            s = os.fstat(fd); self.check_file(s)
            raw = os.read(fd, 65537); end = os.fstat(fd)
            require(len(raw) == s.st_size and (s.st_ino, s.st_size, s.st_mtime_ns) == (end.st_ino, end.st_size, end.st_mtime_ns),
                    'RECOVERY_RECORD_CHANGED')
            return json.loads(raw, object_pairs_hook=unique)
        finally:
            os.close(fd)

    def read(self):
        with self.transaction(): return self.private_read()

    def compare_and_save(self, previous, value):
        raw = encoded(value)
        with self.transaction():
            require(self.private_read() == previous, 'RECOVERY_CAS_CONFLICT')
            path = self.root / ('.recovery-' + uuid.uuid4().hex)
            self.create(path, raw)
            try:
                require(self.private_read() == previous, 'RECOVERY_CAS_CONFLICT')
                os.replace(path, self.record); self.sync()
            finally:
                if path.exists(): path.unlink()

