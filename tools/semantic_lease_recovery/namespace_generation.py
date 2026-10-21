"""Read sealed Docker nsfs handles without ptrace or namespace entry."""
import ctypes
import os
from pathlib import Path
import re
import stat
import sys

FORMAT=('"sandboxKey":{{json .NetworkSettings.SandboxKey}}')

def require(ok,code):
    if not ok:raise ValueError(code)

def ticks(pid):
    require(type(pid) is int and 1<pid<2147483647,'LIVE_PID_REQUIRED')
    return int((Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19])

def handle_identity(path):
    path=Path(path)
    require(re.fullmatch('/run/docker/netns/[a-f0-9]{12,64}',str(path)),'EXACT_DOCKER_NSFS_PATH_REQUIRED')
    for parent in [path.parent,*path.parent.parents]:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022,
                'DOCKER_NSFS_ANCESTOR_UNPROVEN')
    fd=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode),'DOCKER_NSFS_HANDLE_TYPE_UNPROVEN')
        libc=ctypes.CDLL(None,use_errno=True);buffer=ctypes.create_string_buffer(256)
        require(libc.fstatfs(fd,buffer)==0,'DOCKER_NSFS_FILESYSTEM_UNPROVEN')
        magic=int.from_bytes(buffer.raw[:ctypes.sizeof(ctypes.c_long)],sys.byteorder)
        require(magic==0x6e736673,'DOCKER_NSFS_FILESYSTEM_UNPROVEN')
        final=path.lstat()
        require((info.st_dev,info.st_ino)==(final.st_dev,final.st_ino),'DOCKER_NSFS_HANDLE_CHANGED')
        return {'device':info.st_dev,'inode':info.st_ino}
    finally:os.close(fd)

def capture(data,expected,generation):
    key=data['sandboxKey']
    require(type(key) is str and re.fullmatch('/(?:var/)?run/docker/netns/[a-f0-9]{12,64}',key),
            'EXACT_DOCKER_SANDBOX_KEY_REQUIRED')
    canonical=str(Path(key).resolve(strict=True))
    first=generation(expected['pid'])
    require(first==expected and data['state']['Running'] is True and data['state']['Pid']==expected['pid'],
            'DOCKER_PROCESS_GENERATION_CHANGED')
    identity=handle_identity(canonical)
    require(identity['inode']==expected['namespaceInode'] and generation(expected['pid'])==first,
            'DOCKER_NSFS_PROCESS_BINDING_UNPROVEN')
    return {'sandboxKey':key,'canonicalPath':canonical,**identity,'generation':expected}

def generation(binding,pid):
    expected=binding['generation']
    require(pid==expected['pid'],'DOCKER_PROCESS_GENERATION_CHANGED')
    first=ticks(pid)
    require(first==expected['startTicks'],'DOCKER_PROCESS_GENERATION_CHANGED')
    identity=handle_identity(binding['canonicalPath'])
    require(identity=={'device':binding['device'],'inode':binding['inode']}
            and identity['inode']==expected['namespaceInode'] and ticks(pid)==first,
            'DOCKER_NSFS_PROCESS_BINDING_CHANGED')
    return {'pid':pid,'startTicks':first,'namespaceInode':identity['inode']}

def verify_metadata(data,binding):
    require(data['sandboxKey']==binding['sandboxKey'] and data['state']['Running'] is True
            and data['state']['Pid']==binding['generation']['pid'],'DOCKER_SANDBOX_BINDING_CHANGED')
