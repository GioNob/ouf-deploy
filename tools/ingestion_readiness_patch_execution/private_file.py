"""Profile-bound file custody; no Ente paths or named owner exceptions.

Bindings are private review inputs. Values/digests are not diagnostic proofs.
The default bound is1MiB; an explicitly qualified public archive caller may
select at most2GiB. No directory or permission is created or changed.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import PurePosixPath
import stat
from tools.ingestion_readiness_patch_execution.contract import require,path,hashed

def metadata(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def validate(binding,*,maximum=1048576):
    require(type(maximum)is int and 1<=maximum<=2147483648,'EXPLICIT_BOUNDED_FILE_PROFILE_REQUIRED')
    require(type(binding)is dict and set(binding)=={'path','sha256','metadata','ancestors'},
            'EXACT_PRIVATE_FILE_PROFILE_REQUIRED')
    selected=path(binding['path'])
    require(hashed(binding['sha256'])and type(binding['metadata'])is list
            and len(binding['metadata'])==9 and all(type(v)is int and v>=0 for v in binding['metadata']),
            'EXACT_PRIVATE_FILE_SEAL_REQUIRED')
    parts=PurePosixPath(selected).parts;ancestors=binding['ancestors']
    require(type(ancestors)is list and len(ancestors)==len(parts)-1,'COMPLETE_FILE_ANCESTRY_PROFILE_REQUIRED')
    expected=['/']+['/'+ '/'.join(parts[1:i])for i in range(2,len(parts))]
    for item,name in zip(ancestors,expected):
        require(type(item)is dict and set(item)=={'path','identity'}and item['path']==name
                and type(item['identity'])is list and len(item['identity'])==5
                and all(type(v)is int and v>=0 for v in item['identity']),'EXACT_DIRECTORY_CUSTODY_IDENTITY_REQUIRED')
        mode=item['identity'][4]
        require(stat.S_ISDIR(mode)and not mode&0o022,'PRIVATE_FILE_ANCESTRY_WRITABLE')
    mode=binding['metadata'][4]
    require(stat.S_ISREG(mode)and not mode&0o022 and binding['metadata'][5]==1
            and 0<binding['metadata'][6]<=maximum,'BOUNDED_CUSTODIED_REGULAR_FILE_REQUIRED')
    return binding

@contextmanager
def _opened(binding,*,maximum=1048576,verify_bytes=True):
    """Yield one already verified FD at offset0; recheck seal after consumption."""
    validate(binding,maximum=maximum);fds=[];pins=[]
    identity=lambda s:[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
        root=binding['ancestors'][0]
        require(identity(os.fstat(parent))==root['identity'],'PRIVATE_FILE_ROOT_CUSTODY_CHANGED')
        for item in binding['ancestors'][1:]:
            name=PurePosixPath(item['path']).name
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
            require(identity(os.fstat(fd))==item['identity'],'PRIVATE_FILE_DIRECTORY_CUSTODY_CHANGED')
            pins.append((parent,name,fd,item['identity']));parent=fd
        name=PurePosixPath(binding['path']).name
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);fds.append(fd)
        def recheck():
            require(metadata(os.fstat(fd))==binding['metadata']
                    ==metadata(os.stat(name,dir_fd=parent,follow_symlinks=False)),'PRIVATE_FILE_METADATA_CHANGED')
            require(identity(os.fstat(fds[0]))==root['identity'],'PRIVATE_FILE_ROOT_CHANGED')
            for directory,entry,held,seal in pins:
                require(identity(os.fstat(held))==seal==identity(os.stat(entry,dir_fd=directory,follow_symlinks=False)),
                        'PRIVATE_FILE_ANCESTRY_CHANGED_DURING_READ')
        recheck()
        if verify_bytes:
            count=0;digest=hashlib.sha256()
            while True:
                chunk=os.read(fd,65536)
                if not chunk:break
                count+=len(chunk);require(count<=maximum,'PRIVATE_FILE_BOUND_EXCEEDED');digest.update(chunk)
            require(count==binding['metadata'][6]and digest.hexdigest()==binding['sha256'],'PRIVATE_FILE_BYTES_OR_IDENTITY_CHANGED')
        recheck();os.lseek(fd,0,os.SEEK_SET)
        yield fd
        recheck()
    finally:
        for fd in reversed(fds):os.close(fd)

@contextmanager
def opened(binding,*,maximum=1048576):
    with _opened(binding,maximum=maximum,verify_bytes=True)as fd:yield fd

def check_metadata(binding,*,maximum=1048576):
    """Check retained custody/seal without rereading a previously hashed file."""
    with _opened(binding,maximum=maximum,verify_bytes=False):pass

def read(binding):
    with opened(binding)as fd:
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(1048577)
        require(len(raw)==binding['metadata'][6],'EXACT_SELECTED_FILE_READ_REQUIRED')
        return raw
