"""Private one-use phase payloads, bound by the Executor journal hash.

Payloads may contain runtime configuration and stay private. Partial files are
retained and denied; publication never overwrites them or issues authority.
"""
import json,os,stat
from pathlib import Path
from transition_journal import PHASES,digest,require,hash_value

class NativeEvidenceStore:
    def __init__(self,directory):
        self.root=Path(directory);self.binding=None;self.check()
    def check(self):
        s=self.root.lstat()
        require(self.root.is_absolute() and stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid()
                and stat.S_IMODE(s.st_mode)==0o700,'PRIVATE_NATIVE_EVIDENCE_DIRECTORY_REQUIRED')
        pin=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))
        require(self.binding is None or self.binding==pin,'NATIVE_EVIDENCE_DIRECTORY_BINDING_CHANGED')
        self.binding=pin
    def path(self,phase):
        require(phase in PHASES,'EXACT_NATIVE_EVIDENCE_PHASE_REQUIRED');self.check()
        return self.root/(phase+'.json')
    def _read(self,phase):
        path=self.path(phase);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1
                    and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=2097152,'PRIVATE_NATIVE_EVIDENCE_FILE_REQUIRED')
            raw=b''
            while True:
                block=os.read(fd,65536)
                if not block:break
                raw+=block;require(len(raw)<=2097152,'BOUNDED_NATIVE_EVIDENCE_REQUIRED')
            pin=lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
            require(pin(s)==pin(os.fstat(fd))==pin(path.lstat()) and len(raw)==s.st_size,'NATIVE_EVIDENCE_CHANGED_DURING_READ')
            value=json.loads(raw)
            require(raw==json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
                     ,'NATIVE_EVIDENCE_CANONICAL_BYTES_REQUIRED')
            return value
        finally:os.close(fd)
    def read(self,phase,expected_hash):
        require(hash_value(expected_hash),'EXACT_NATIVE_EVIDENCE_JOURNAL_HASH_REQUIRED')
        value=self._read(phase)
        require(digest(value)==expected_hash,'NATIVE_EVIDENCE_JOURNAL_BINDING_DRIFT');return value
    def read_baseline(self,phase,context_hash,intent_hash):
        # Only the sealed owner reads its own private pre-effect snapshot.
        # Context/intent bind this one-use baseline before any native effect;
        # a hash alone neither authorizes it nor adopts a foreign snapshot.
        require(hash_value(context_hash) and hash_value(intent_hash),'EXACT_NATIVE_BASELINE_SCOPE_REQUIRED')
        value=self._read(phase)
        require(type(value) is dict and value.get('transitionContextHash')==context_hash
                and value.get('intentHash')==intent_hash,'NATIVE_BASELINE_CONTEXT_OR_INTENT_DRIFT');return value
    def publish(self,phase,value):
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        require(len(raw)<=2097152,'BOUNDED_NATIVE_EVIDENCE_REQUIRED')
        path=self.path(phase)
        try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:return self.read(phase,digest(value))
        try:
            with os.fdopen(fd,'wb',closefd=False) as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
        parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
        return self.read(phase,digest(value))
