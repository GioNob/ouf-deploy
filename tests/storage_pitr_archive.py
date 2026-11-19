"""Bounded local WAL copier for a disposable PG17 fixture; no network/backend."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_WAL_BYTES=16*1024*1024
WAL_NAME=re.compile(r'(?:[0-9A-F]{24}|[0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup)')


def require(ok,code):
 if not ok:raise RuntimeError(code)


def read_regular(path,limit=MAX_WAL_BYTES):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=limit,'BOUNDED_REGULAR_WAL_REQUIRED')
  data=stream.read(limit+1);require(len(data)<=limit,'WAL_BYTE_BUDGET');return data


def emit(log,event):
 fd=os.open(log,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'ab') as stream:
  require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),'REGULAR_EVENT_LOG_REQUIRED')
  stream.write((json.dumps(event,sort_keys=True)+'\n').encode());stream.flush();os.fsync(stream.fileno())


def copy_wal(mode,archive,source_or_destination,name,log):
 require(mode in ('archive','restore') and WAL_NAME.fullmatch(name),'WAL_NAME_REQUIRED')
 require(archive.is_dir() and not archive.is_symlink(),'PRIVATE_ARCHIVE_DIRECTORY_REQUIRED')
 wal=Path(source_or_destination)
 require(not wal.is_absolute() and len(wal.parts)==2 and wal.parts[0]=='pg_wal'
         and re.fullmatch(r'[A-Za-z0-9_.]+',wal.parts[1]),'POSTGRES_WAL_RELATIVE_PATH_REQUIRED')
 if mode=='archive':require(wal.name==name,'ARCHIVE_SOURCE_NAME_REQUIRED')
 source=wal if mode=='archive' else archive/name
 destination=archive/name if mode=='archive' else wal
 try:data=read_regular(source)
 except FileNotFoundError:
  emit(log,{'mode':mode,'name':name,'status':'MISSING'});return 1
 digest=hashlib.sha256(data).hexdigest()
 if mode=='archive' and destination.exists():
  require(read_regular(destination)==data,'EXISTING_ARCHIVE_BYTES_DIFFER');status='IDENTICAL_EXISTING'
 else:
  require(not destination.is_symlink(),'DESTINATION_SYMLINK_DENIED')
  temporary=destination.with_name(destination.name+'.ouf-copy-'+str(os.getpid()))
  with temporary.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  # Archive ownership is one PostgreSQL archiver, and restore runs after its stop.
  os.replace(temporary,destination)
  fd=os.open(destination.parent,os.O_RDONLY)
  try:os.fsync(fd)
  finally:os.close(fd)
  status='COPIED'
 emit(log,{'mode':mode,'name':name,'status':status,'sha256':digest,'bytes':len(data)})
 return 0


def main():
 require(len(sys.argv)==6,'EXACT_WAL_ARGUMENTS_REQUIRED')
 mode,archive,wal,name,log=sys.argv[1:]
 return copy_wal(mode,Path(archive),wal,name,Path(log))

if __name__=='__main__':raise SystemExit(main())
