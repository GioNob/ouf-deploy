"""CAS publication for owned profile entries; caller restores nft separately."""
import os
from pathlib import Path
import stat
import uuid
from extend_empty_lease_guard import TransitionDenied,require

def read(path):
 for parent in (path.parent,*path.parent.parents):
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode & 0o022,'FILE_CUSTODY','UNSAFE_ANCESTOR')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(0,0,0o600,1) and s.st_size<=2000000,'FILE_CUSTODY','PRIVATE_FILE_REQUIRED')
  raw=os.read(fd,2000001);require(len(raw)==s.st_size,'FILE_CUSTODY','FILE_CHANGED_DURING_READ');return raw
 finally:os.close(fd)
def sync(parent):
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def create(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False) as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 sync(path.parent)
def replace(path,before,after):
 require(read(path)==before,'PROFILE_PUBLICATION','FOREIGN_FILE_PRESERVED')
 temporary=path.parent/('.ouf-transition-'+uuid.uuid4().hex)
 create(temporary,after)
 try:
  require(read(path)==before,'PROFILE_PUBLICATION','FILE_CHANGED_BEFORE_RENAME')
  os.replace(temporary,path);sync(path.parent)
 finally:
  if temporary.exists():temporary.unlink()
def publish(entries,reload,verify):
 for e in entries:require(read(e['path'])==e['old'],'PROFILE_PUBLICATION','ORIGINAL_PUBLICATION_FILE_CHANGED')
 for e in entries:replace(e['path'],e['old'],e['new'])
 reload();verify()
def restore(entries,reload,verify):
 # Validate every current file before changing any, including entries whose
 # publication had not begun when the failure happened.
 current=[read(e['path']) for e in entries]
 require(all(v in (e['old'],e['new']) for e,v in zip(entries,current)),'ROLLBACK','FOREIGN_PUBLICATION_FILE_PRESERVED')
 for e,v in reversed(list(zip(entries,current))):
  if v==e['new']:replace(e['path'],e['new'],e['old'])
 reload();verify()
