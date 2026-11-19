"""Read eligibility for existing declared inputs; observations are NOT custody admission.

Output custody stays root/private. Input owner/mode/link count are reported,
never changed. Only regular bounded stable no-symlink inputs may be read.
"""
import os,stat
from tools.storage_migration.minio_credential_binding import Binding,trim
from tools.m2_discovery_installation_profile.custody_capture import attrs,require,Stop
class InputBinding(Binding):
 def __init__(self,pid,root=None,cwd=None):
  super().__init__(pid,root,cwd);self.observed={};self.reference_rows=[];self.preflight_done=False;self.policy_blocked=False
 def inspect(self,raw,config=False):
  try:p=self.path(raw)
  except Stop:return None,{'kind':'INVALID_REFERENCE'}
  key=(p.is_absolute(),str(p),config)
  if key in self.observed:return key,self.observed[key]
  require(len(self.observed)<9,'INPUT_METADATA_CANDIDATE_LIMIT');anchor=self.root if p.is_absolute() else self.cwd;parts=p.parts[1:] if p.is_absolute() else p.parts
  current=os.dup(anchor);node=None
  try:
   row=None
   for index,part in enumerate(parts):
    node=os.open(part,os.O_PATH|os.O_NOFOLLOW,dir_fd=current);info=os.fstat(node)
    if index<len(parts)-1:
     if not stat.S_ISDIR(info.st_mode):row={'kind':'ANCESTOR_SYMLINK' if stat.S_ISLNK(info.st_mode) else 'ANCESTOR_NOT_DIRECTORY','metadata':attrs(info)};break
     os.close(current);current=node;node=None
    else:
     mode=info.st_mode;kind='REGULAR' if stat.S_ISREG(mode) else 'SYMLINK' if stat.S_ISLNK(mode) else 'DIRECTORY' if stat.S_ISDIR(mode) else 'SPECIAL'
     limit=65536 if config else 4096
     row={'kind':kind,'metadata':attrs(info),'sizeWithinLimit':0<=info.st_size<=limit,'hasLink':info.st_nlink>=1,'readEligible':kind=='REGULAR' and info.st_nlink>=1 and 0<=info.st_size<=limit}
  except FileNotFoundError:row={'kind':'MISSING'}
  except OSError:row={'kind':'METADATA_UNAVAILABLE'}
  finally:
   if node is not None:os.close(node)
   os.close(current)
  self.observed[key]=row;self.probes[key]=row.get('metadata');return key,row
 def preflight(self,env):
  self.reference_rows=[];self.policy_blocked=False
  for role,name in [('LEGACY_USER','MINIO_ACCESS_KEY_FILE'),('LEGACY_PASSWORD','MINIO_SECRET_KEY_FILE'),('ROOT_USER','MINIO_ROOT_USER_FILE'),('ROOT_PASSWORD','MINIO_ROOT_PASSWORD_FILE'),('CONFIG_ENV','MINIO_CONFIG_ENV_FILE')]:
   if not env.get(name):continue
   config=role=='CONFIG_ENV';raw=env[name]
   try:p=self.path(raw)
   except Stop:self.reference_rows.append({'source':role,'location':'DECLARED','kind':'INVALID_REFERENCE','required':True});self.policy_blocked=True;continue
   candidates=[('DECLARED',str(p))] if config else [('SECRETS_PREFIX','/run/secrets/'+str(p).lstrip('/')),('DECLARED',str(p))]
   scanned=[(location,*self.inspect(path,config)) for location,path in candidates]
   first=scanned[0][2];selected=0 if config or first['kind'] not in ('MISSING','DIRECTORY') else 1
   for index,(location,key,row) in enumerate(scanned):
    required=index==selected;entry={'source':role,'location':location,'kind':row['kind'],'required':required}
    if 'metadata' in row:
     meta=row['metadata'];entry.update(mode=format(stat.S_IMODE(meta[2]),'04o'),rootOwned=meta[3]==0,singleLink=meta[5]==1,sizeWithinLimit=row.get('sizeWithinLimit',False))
     failures=[]
     if row['kind']!='REGULAR':failures.append('NOT_REGULAR')
     if meta[3]!=0:failures.append('NON_ROOT_OWNER')
     if meta[2]&0o007:failures.append('OTHER_PERMISSION_BITS')
     if meta[5]!=1:failures.append('LINK_COUNT_NOT_ONE')
     if not row.get('sizeWithinLimit',False):failures.append('SIZE_OUTSIDE_LIMIT')
     entry['previousGuardFailedPredicates']=failures
    if required and row['kind']!='MISSING' and not row.get('readEligible',False):self.policy_blocked=True
    self.reference_rows.append(entry)
  self.preflight_done=True;return self.public_metadata()
 def public_metadata(self):
  return {'metadataComplete':self.preflight_done,'readPolicy':'EXISTING_DECLARED_REGULAR_BOUNDED_STABLE_INPUTS_ONLY','sourceCustodyAdmitted':False,'policyBlocked':self.policy_blocked,'candidates':self.reference_rows,'filesOpened':self.opened,'sourceBytesRead':self.bytes,'rawValuesSpooled':False}
 def read(self,raw,limit,config=False,verify=False):
  require(self.preflight_done and not self.policy_blocked,'COMPLETE_INPUT_METADATA_PREFLIGHT_REQUIRED');p=self.path(raw);key=(p.is_absolute(),str(p),config);require(key in self.observed,'DECLARED_PREFLIGHTED_INPUT_ONLY')
  initial=self.observed[key];self.observed.pop(key);self.probes.pop(key,None);_,actual=self.inspect(raw,config)
  require(actual==initial,'DECLARED_INPUT_METADATA_CHANGED')
  if verify:return None
  if key in self.files:return self.files[key][0]
  if actual['kind']=='MISSING':return None
  require(actual.get('readEligible') is True,'DECLARED_REGULAR_BOUNDED_INPUT_REQUIRED')
  anchor=self.root if p.is_absolute() else self.cwd;parts=p.parts[1:] if p.is_absolute() else p.parts
  parent,node=self.node(anchor,parts)
  try:
   require(self.opened<5,'CREDENTIAL_FILE_READ_LIMIT');observed=actual['metadata'];require(attrs(os.fstat(node))==observed,'DECLARED_INPUT_REBOUND')
   fd=os.open(parts[-1],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=parent)
   self.opened+=1
   try:
    require(attrs(os.fstat(fd))==observed and observed[6]<=81920-self.bytes,'DECLARED_INPUT_REBOUND_OR_BYTE_LIMIT');value=os.read(fd,min(limit+1,81920-self.bytes));self.bytes+=len(value)
    require(len(value)==observed[6] and attrs(os.fstat(fd))==attrs(os.fstat(node))==observed,'DECLARED_INPUT_CHANGED')
   finally:os.close(fd)
  finally:os.close(node);os.close(parent)
  self.files[key]=(value,limit);return value
 def secret(self,raw):
  p=self.path(raw);candidate='/run/secrets/'+str(p).lstrip('/');key=(True,candidate,False)
  value=self.read(candidate,4096) if self.observed[key]['kind']=='REGULAR' else self.read(str(p),4096)
  return trim(value) if value is not None else b''
