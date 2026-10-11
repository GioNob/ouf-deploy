"""Publish one complete immutable review intake; never runtime authority.

Linux renameat2(RENAME_NOREPLACE) makes the whole private directory visible at
once. Interrupted staging is retained privately; no partial intake is accepted.
Existing same-content publication is verified without rewriting it.
"""
import ctypes,errno,hashlib,json,os,re,stat,tempfile
from pathlib import Path

def require(ok,reason):
 if not ok:raise ValueError(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def directory(path,uid):
 s=Path(path).lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==uid and not s.st_mode&0o022,'PRIVATE_REVIEW_DIRECTORY_CUSTODY_REQUIRED')
 return s

def read(path,uid):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==uid and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=2000000,'REVIEW_FILE_CUSTODY_REQUIRED')
  raw=os.read(fd,2000001)
  after=os.fstat(fd);named=Path(path).lstat()
  identity=lambda a:(a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
  require(identity(s)==identity(after)==identity(named) and len(raw)==s.st_size,'REVIEW_FILE_CHANGED_DURING_READ')
  return raw
 finally:os.close(fd)

def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def verify(path,files,manifest_raw,uid):
 directory(path,uid)
 require(stat.S_IMODE(Path(path).lstat().st_mode)==0o700,'EXACT_PRIVATE_REVIEW_MODE_REQUIRED')
 require(set(os.listdir(path))==set(files)|{'intake.json'},'EXACT_COMPLETE_REVIEW_FILE_SET_REQUIRED')
 require(read(Path(path)/'intake.json',uid)==manifest_raw,'EXACT_REVIEW_MANIFEST_REQUIRED')
 for name,raw in files.items():require(read(Path(path)/name,uid)==raw,'EXACT_REVIEW_FILE_HASH_REQUIRED')
 return True

def publish(base,files,manifest,uid,checkpoint=lambda point:None):
 """Immutable content publication only; caller owns source authentication."""
 base=Path(base);directory(base,uid)
 require(type(files) is dict and 1<=len(files)<=16,'BOUNDED_COMPLETE_REVIEW_INPUTS_REQUIRED')
 require(all(type(n) is str and re.fullmatch('[a-z][a-z0-9_.-]{0,100}',n) and n!='intake.json' and type(raw) is bytes and len(raw)<=2000000 for n,raw in files.items()),'EXACT_BOUNDED_REVIEW_FILE_REQUIRED')
 require(type(manifest) is dict and manifest.get('schema')=='ouf.native-v11-atomic-review-intake.v1' and manifest.get('fileHashes')=={n:sha(raw) for n,raw in files.items()},'REVIEW_MANIFEST_BINDING_REQUIRED')
 require(manifest.get('applicationCutoverAuthorized') is False and manifest.get('productionApplyReady') is False and manifest.get('runtimeAuthorityIssued') is False and manifest.get('observationsAreHistorical') is True,'REVIEW_MUST_NOT_PROMOTE_RUNTIME_AUTHORITY')
 raw=encoded(manifest);require(len(raw)<=2000000,'BOUNDED_REVIEW_MANIFEST_REQUIRED');identity=sha(raw);final=base/('semantic-native-v11-intake-'+identity)
 if os.path.lexists(final):
  verify(final,files,raw,uid)
  sync(final);sync(base)
  return {'directory':str(final),'intakeHash':identity,'newPublication':False,'protectedFileWrites':0,'publicationIsAtomic':True}
 stage=Path(tempfile.mkdtemp(prefix='.semantic-native-v11-intake-staging-',dir=base));os.chmod(stage,0o700)
 for name,content in {**files,'intake.json':raw}.items():
  checkpoint('BEFORE_FILE_'+name)
  fd=os.open(stage/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   os.fchmod(fd,0o600)
   with os.fdopen(os.dup(fd),'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
  finally:os.close(fd)
  checkpoint('AFTER_FILE_'+name)
 sync(stage);verify(stage,files,raw,uid);checkpoint('BEFORE_ATOMIC_PUBLICATION')
 # No replacement even if another publisher races or an empty foreign path
 # exists. No shell, key, network, claim or transition journal is involved.
 libc=ctypes.CDLL(None,use_errno=True);rename=getattr(libc,'renameat2',None)
 require(rename is not None,'LINUX_ATOMIC_NOREPLACE_PUBLICATION_REQUIRED')
 rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
 fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  if rename(fd,os.fsencode(stage.name),fd,os.fsencode(final.name),1)!=0:
   error=ctypes.get_errno()
   require(error==errno.EEXIST,'ATOMIC_REVIEW_PUBLICATION_FAILED')
   verify(final,files,raw,uid)
   sync(final);os.fsync(fd)
   # Complete private staged evidence remains retained, never silently removed.
   return {'directory':str(final),'intakeHash':identity,'newPublication':False,'protectedFileWrites':len(files)+1,'publicationIsAtomic':True}
  checkpoint('AFTER_ATOMIC_PUBLICATION');os.fsync(fd)
 finally:os.close(fd)
 verify(final,files,raw,uid)
 return {'directory':str(final),'intakeHash':identity,'newPublication':True,'protectedFileWrites':len(files)+1,'publicationIsAtomic':True}
