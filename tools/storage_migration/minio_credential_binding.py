"""Bounded MinIO file/env precedence, without shells, defaults or secret exports."""
import hashlib,os,stat
from pathlib import PurePosixPath
from tools.m2_discovery_installation_profile.custody_capture import attrs,require
KEYS=('MINIO_ROOT_USER','MINIO_ROOT_PASSWORD','MINIO_ACCESS_KEY','MINIO_SECRET_KEY')
SPACE=' \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000'
def trim(value):return value.decode().strip(SPACE).encode()
class Binding:
 def __init__(self,pid,root=None,cwd=None):
  self.root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY) if root is None else os.dup(root)
  try:self.cwd=os.open('/proc/'+str(pid)+'/cwd',os.O_RDONLY|os.O_DIRECTORY) if cwd is None else os.dup(cwd)
  except BaseException:os.close(self.root);raise
  self.pid=pid if root is None else None;self.files={};self.probes={};self.opened=0;self.bytes=0;self.region=None
 def close(self):os.close(self.cwd);os.close(self.root)
 def path(self,raw):
  require(type(raw) is str and 0<len(raw.encode())<=4096 and '\x00' not in raw and '\n' not in raw and '\r' not in raw,'BOUNDED_DECLARED_CREDENTIAL_REFERENCE_REQUIRED')
  p=PurePosixPath(raw);require(not raw.startswith('//') and str(p)==raw and '..' not in p.parts and p.name not in ('','.','..'),'NO_TRAVERSAL_CREDENTIAL_REFERENCE_REQUIRED');return p
 def node(self,anchor,parts):
  fd=os.dup(anchor)
  try:
   for part in parts[:-1]:
    new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
   node=os.open(parts[-1],os.O_PATH|os.O_NOFOLLOW,dir_fd=fd)
   return fd,node
  except BaseException:os.close(fd);raise
 def read(self,raw,limit,config=False,verify=False):
  p=self.path(raw);anchor=self.root if p.is_absolute() else self.cwd;parts=p.parts[1:] if p.is_absolute() else p.parts;key=(p.is_absolute(),str(p),config)
  require(verify or key in self.probes or len(self.probes)<9,'CREDENTIAL_METADATA_CANDIDATE_LIMIT')
  if key in self.files and not verify:return self.files[key][0]
  try:parent,node=self.node(anchor,parts)
  except FileNotFoundError:
   observed=None;value=None
  else:
   try:
    info=os.fstat(node);require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o007 and info.st_nlink==1 and 0<=info.st_size<=limit,'PRIVATE_BOUNDED_REGULAR_CREDENTIAL_SOURCE_REQUIRED');observed=attrs(info)
    if verify:value=None
    else:
     require(self.opened<5,'CREDENTIAL_FILE_READ_LIMIT');self.opened+=1
     fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
     try:
      require(attrs(os.fstat(fd))==observed,'CREDENTIAL_SOURCE_REBOUND');value=os.read(fd,limit+1)
      require(len(value)==info.st_size and attrs(os.fstat(fd))==attrs(os.fstat(node))==observed,'CREDENTIAL_SOURCE_CHANGED');self.bytes+=len(value);require(self.bytes<=81920,'CREDENTIAL_BYTES_LIMIT')
     finally:os.close(fd)
   finally:os.close(node);os.close(parent)
  if verify:require(self.probes[key]==observed,'CREDENTIAL_SOURCE_METADATA_CHANGED');return None
  self.probes[key]=observed
  if value is not None:self.files[key]=(value,limit)
  return value
 def secret(self,raw):
  p=self.path(raw)
  # MinIO pathJoin preserves the /run/secrets prefix for absolute arguments too.
  candidate='/run/secrets/'+str(p).lstrip('/')
  value=self.read(candidate,4096)
  if value is None:value=self.read(str(p),4096)
  return trim(value) if value is not None else b''
 def stable(self):
  if self.pid is not None:
   require(attrs(os.stat('/proc/'+str(self.pid)+'/root'))[:5]==attrs(os.fstat(self.root))[:5] and attrs(os.stat('/proc/'+str(self.pid)+'/cwd'))[:5]==attrs(os.fstat(self.cwd))[:5],'CREDENTIAL_PROCESS_ROOT_OR_CWD_CHANGED')
  for absolute,path,config in list(self.probes):self.read(path,65536 if config else 4096,config=config,verify=True)
 def resolve(self,env):
  effective={k:env[k].encode() for k in KEYS if k in env};origins={k:'EXPLICIT_ENV' for k in effective};region={k:env[k] for k in ['MINIO_REGION_NAME','MINIO_REGION'] if k in env}
  for source,target in [('MINIO_ACCESS_KEY_FILE','MINIO_ROOT_USER'),('MINIO_SECRET_KEY_FILE','MINIO_ROOT_PASSWORD'),('MINIO_ROOT_USER_FILE','MINIO_ROOT_USER'),('MINIO_ROOT_PASSWORD_FILE','MINIO_ROOT_PASSWORD')]:
   if env.get(source):
    value=self.secret(env[source])
    if value:effective[target]=value;origins[target]='DECLARED_SECRET_FILE'
  if env.get('MINIO_CONFIG_ENV_FILE'):
   value=self.read(env['MINIO_CONFIG_ENV_FILE'],65536,config=True)
   if value is not None:
    for line in value.decode().split('\n'):
     line=line.strip(SPACE)
     if not line or line.startswith('#'):continue
     if line.startswith('export'):line=line[6:].strip(SPACE)
     require('=' in line,'MINIO_CONFIG_ENV_ENTRY_REQUIRED');key,value=line.split('=',1)
     if len(value)>=2 and value[0] in ('\"',"'") and value[-1]==value[0]:value=value[1:-1]
     if key in KEYS:effective[key]=value.encode();origins[key]='DECLARED_CONFIG_ENV'
     if key in ('MINIO_REGION_NAME','MINIO_REGION'):region[key]=value
  require(bool(effective.get(KEYS[0]))==bool(effective.get(KEYS[1])),'COMPLETE_ROOT_CREDENTIAL_PAIR_REQUIRED')
  pair=('MINIO_ROOT_USER','MINIO_ROOT_PASSWORD') if all(effective.get(k) for k in KEYS[:2]) else ('MINIO_ACCESS_KEY','MINIO_SECRET_KEY')
  require(all(effective.get(k) for k in pair),'EXPLICIT_EFFECTIVE_CREDENTIAL_PAIR_REQUIRED')
  values=[effective[k] for k in pair]
  require(all(0<len(v)<=4096 and v==trim(v) and b'\x00' not in v and b'\n' not in v and b'\r' not in v for v in values),'EXACT_SDK_CREDENTIAL_VALUE_REQUIRED')
  self.region=region.get('MINIO_REGION_NAME') or region.get('MINIO_REGION') or 'us-east-1'
  self.stable();return values,{'selectedSources':[origins[k] for k in pair],'secretFilesOpened':self.opened,'sourceBytesRead':self.bytes,'metadataCandidates':len(self.probes),'rawValuesSpooled':False}
