"""Byte-qualified single UDP candidate preparation, with no runtime effects."""
import hashlib,http.client,io,json,os,re,socket,stat,tarfile,zipfile
from pathlib import Path,PurePosixPath
import image_custody as custody
LIMIT=1200000000
def require(ok,code):
 if not ok:raise ValueError(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def input_bytes(path,expected,maximum,protected=False):
 p=Path(path);require(p.is_absolute()and str(p)==str(path)and '..'not in p.parts,'EXACT_INPUT_PATH_REQUIRED')
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 try:
  for part in p.parts[1:-1]:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
   if protected:
    s=os.fstat(fds[-1]);require(s.st_uid==0 and not s.st_mode&0o022,'ROOT_INPUT_ANCESTRY_REQUIRED')
  fds.append(os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]))
  before=os.fstat(fds[-1]);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'BOUNDED_INPUT_REQUIRED')
  if protected:require(before.st_uid==0 and not before.st_mode&0o022,'ROOT_INPUT_CUSTODY_REQUIRED')
  raw=os.read(fds[-1],maximum+1)
  require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fds[-1]))and hashlib.sha256(raw).hexdigest()==expected,'INPUT_BYTE_DRIFT')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)

def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)

def copy_artifact(path,target,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=LIMIT,'BOUNDED_ARTIFACT_REQUIRED')
  out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();size=0
  try:
   with os.fdopen(os.dup(out),'wb')as f:
    while True:
     block=os.read(fd,1048576)
     if not block:break
     size+=len(block);require(size<=LIMIT,'ARTIFACT_LIMIT');h.update(block);f.write(block)
    f.flush();os.fsync(f.fileno())
  finally:os.close(out)
  require(size==s.st_size and pin(s)==pin(os.fstat(fd))and h.hexdigest()==expected,'ARTIFACT_COPY_DRIFT')
 finally:os.close(fd)

def zip_index(z):
 rows=z.infolist();require(0<len(rows)<=4096,'BOUNDED_ZIP_INDEX_REQUIRED');result={}
 for row in rows:
  p=PurePosixPath(row.filename);mode=row.external_attr>>16
  require(str(p)==row.filename.rstrip('/')and not p.is_absolute()and '..'not in p.parts
   and row.filename not in result and not row.flag_bits&1 and stat.S_IFMT(mode)in(0,stat.S_IFREG,stat.S_IFDIR)
   and row.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)and 0<=row.file_size<=LIMIT,'SAFE_ZIP_MEMBER_REQUIRED')
  if not row.is_dir():result[row.filename]=row
 require(sum(r.file_size for r in result.values())<=LIMIT,'ZIP_EXPANSION_BOUND')
 return result

def sums(raw):
 result={}
 for line in raw.decode('ascii').splitlines():
  m=re.fullmatch(r'([0-9a-f]{64})  (.+)',line);require(m is not None,'HASH_LIST_SHAPE')
  p=PurePosixPath(m[2]);require(str(p)==m[2]and not p.is_absolute()and '..'not in p.parts and m[2]not in result,'SAFE_HASH_LIST')
  result[m[2]]=m[1]
 return result

def member(z,index,name,maximum):
 require(name in index and 0<index[name].file_size<=maximum,'BOUNDED_PACKAGE_MEMBER_REQUIRED')
 return z.read(name)

def verified_zip(z,index):
 mapping=sums(member(z,index,'SHA256SUMS',1048576))
 require(set(mapping)==set(index)-{'SHA256SUMS','SHA256SUMS.sigstore.json'}
  and 'SHA256SUMS.sigstore.json'in index,'COMPLETE_AGGREGATE_HASH_LIST_REQUIRED')
 for name,expected in mapping.items():
  with z.open(name)as f:
   h=hashlib.sha256()
   while True:
    block=f.read(1048576)
    if not block:break
    h.update(block)
   require(h.hexdigest()==expected,'AGGREGATE_MEMBER_HASH_DRIFT')
 return mapping

def extract_member(z,index,name,target,maximum):
 require(name in index and 0<index[name].file_size<=maximum,'BOUNDED_EXTRACT_MEMBER_REQUIRED')
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with z.open(name)as source,os.fdopen(os.dup(fd),'wb')as dest:
   total=0
   while True:
    block=source.read(1048576)
    if not block:break
    total+=len(block);require(total<=maximum,'EXTRACT_BOUND');dest.write(block)
   dest.flush();os.fsync(dest.fileno())
 finally:os.close(fd)

def engine_info(ns,engine):
 path=engine['socketPath']
 def guard():
  s=os.stat(path,follow_symlinks=False);require(stat.S_ISSOCK(s.st_mode)and
   (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==tuple(engine['socketBinding']),'ENGINE_SOCKET_DRIFT')
 class Local(http.client.HTTPConnection):
  def connect(self):
   self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(path)
 guard();c=Local('localhost',timeout=10)
 try:
  c.request('GET','/v1.44/info');response=c.getresponse();raw=response.read(2097153)
  require(response.status==200 and len(raw)<=2097152,'ENGINE_INFO_UNAVAILABLE');guard()
  value=json.loads(raw);status=dict(value.get('DriverStatus')or[])
  if value.get('Driver')=='overlayfs'and status.get('driver-type')=='io.containerd.snapshotter.v1':return True
  require(value.get('Driver')=='overlay2'and status.get('driver-type')!='io.containerd.snapshotter.v1','NATIVE_IMAGE_STORE_UNQUALIFIED')
  return False
 finally:c.close()

def candidate(path,case,context,engine,ns):
 output=Path(context);copy_artifact(path,output/'candidate.zip',case['artifact']['zipSha256'])
 with zipfile.ZipFile(output/'candidate.zip')as z:
  index=zip_index(z);mapping=verified_zip(z,index)
  lock=member(z,index,'source-lock.json',1048576)
  require(hashlib.sha256(lock).hexdigest()==case['artifact']['sourceLockSha256'],'AUDIT_FIX_SOURCE_LOCK_CHANGED')
  prefix='parts/resolution-owner-context-part-udp-'+str(case['artifact']['runId'])+'/'
  meta=json.loads(member(z,index,prefix+'candidate-manifest.json',1048576))
  require(meta.get('imageId')==case['artifact']['imageId']and meta.get('sourceCommit')==case['candidateSourceCommit']and meta.get('module')=='udp'
   and meta.get('sourceLockSha256')==case['artifact']['sourceLockSha256']
   and meta.get('scanGate')=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
   and meta.get('targetApplyAuthorized')is False and meta.get('runtimeAuthorityIssued')is False,'EXACT_AUDIT_FIX_PACKAGE_REQUIRED')
  inventory=json.loads(member(z,index,prefix+'source-inventory.json',8388608))
  require(inventory.get('truncated')is False,'COMPLETE_AUDIT_FIX_SOURCE_INVENTORY_REQUIRED')
  migrated=[r for r in inventory['tree']if r['path'].startswith('src/main/resources/db/migration/')and r['path'].endswith('.sql')]
  require(migrated==case['expectedMigrationTree'],'AUDIT_FIX_MIGRATION_SOURCE_CHANGED')
  original=output/'original.tar';image=output/'candidate.tagless.tar'
  extract_member(z,index,prefix+'image.docker.tar',original,LIMIT)
  containerd=engine_info(ns,engine)
  with original.open('rb')as stream:
   audit=custody.archive(stream,mapping[prefix+'image.docker.tar'],meta['imageId'],case['candidateSourceCommit'])
   with image.open('x+b')as dest:
    os.chmod(image,0o600);derived=custody.tagless_archive(stream,dest,audit,containerd=containerd);dest.flush();os.fsync(dest.fileno())
  with image.open('rb')as stream:audit=custody.archive(stream,derived['derivedArchiveSha256'],meta['imageId'],case['candidateSourceCommit'])
  require(not audit['repositoryTags'],'TAGLESS_AUDIT_FIX_IMAGE_REQUIRED')
  if containerd:audit['nativeIdentity']=custody.native_identity(audit)
  original.unlink()
 return {'candidateMetadata':meta,'imageAudit':audit,'imageArchive':{'path':str(image),'sha256':derived['derivedArchiveSha256']},
  'nativeImageId':custody.runtime_image_id(audit),'migrationFilesUnchanged':True}
