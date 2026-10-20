"""Profile-bound, read-only local file custody; no Ente paths or owner exceptions.

Bindings are private review inputs. Neither file values nor their hashes are
included in diagnostic proofs. No directory is created or permission changed.
"""
import hashlib
import os
from pathlib import PurePosixPath
import stat
from tools.ingestion_rollout_execution.contract import require,path,hashed

def metadata(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def validate(binding):
    require(type(binding)is dict and set(binding)=={'path','sha256','metadata','ancestors'},
            'EXACT_PRIVATE_FILE_PROFILE_REQUIRED')
    selected=path(binding['path'])
    require(hashed(binding['sha256'])and type(binding['metadata'])is list
            and len(binding['metadata'])==9 and all(type(v)is int and v>=0 for v in binding['metadata']),
            'EXACT_PRIVATE_FILE_SEAL_REQUIRED')
    parts=PurePosixPath(selected).parts
    ancestors=binding['ancestors']
    require(type(ancestors)is list and len(ancestors)==len(parts)-1,
            'COMPLETE_FILE_ANCESTRY_PROFILE_REQUIRED')
    expected=['/']+['/'+ '/'.join(parts[1:i])for i in range(2,len(parts))]
    for item,name in zip(ancestors,expected):
        require(type(item)is dict and set(item)=={'path','identity'}and item['path']==name
                and type(item['identity'])is list and len(item['identity'])==5
                and all(type(v)is int and v>=0 for v in item['identity']),
                'EXACT_DIRECTORY_CUSTODY_IDENTITY_REQUIRED')
        mode=item['identity'][4]
        require(stat.S_ISDIR(mode)and not mode&0o022,'PRIVATE_FILE_ANCESTRY_WRITABLE')
    mode=binding['metadata'][4]
    require(stat.S_ISREG(mode)and not mode&0o022 and binding['metadata'][5]==1
            and 0<binding['metadata'][6]<=1048576,'BOUNDED_CUSTODIED_REGULAR_FILE_REQUIRED')
    return binding

def read(binding):
    validate(binding);fds=[];pins=[]
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
        require(metadata(os.fstat(fd))==binding['metadata'],'PRIVATE_FILE_METADATA_CHANGED')
        chunks=[];count=0;digest=hashlib.sha256()
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            count+=len(chunk);require(count<=1048576,'PRIVATE_FILE_BOUND_EXCEEDED')
            chunks.append(chunk);digest.update(chunk)
        require(count==binding['metadata'][6]and digest.hexdigest()==binding['sha256']
                and metadata(os.fstat(fd))==binding['metadata']
                ==metadata(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                'PRIVATE_FILE_BYTES_OR_IDENTITY_CHANGED')
        require(identity(os.fstat(fds[0]))==root['identity'],'PRIVATE_FILE_ROOT_CHANGED')
        for directory,name,held,seal in pins:
            require(identity(os.fstat(held))==seal==identity(os.stat(name,dir_fd=directory,follow_symlinks=False)),
                    'PRIVATE_FILE_ANCESTRY_CHANGED_DURING_READ')
        return b''.join(chunks)
    finally:
        for fd in reversed(fds):os.close(fd)
