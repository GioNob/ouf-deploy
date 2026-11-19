"""Root-private metadata only; independent no-follow FD read and immutable bytes."""
import json
import os
from pathlib import Path
import stat
from tools.ingestion_readiness_patch_execution import contract as c
from tools.ingestion_readiness_patch_execution.private_file import metadata
from tools.semantic_policy_token_owner.producer import protected_directory

def unique(pairs):
    result={}
    for key,value in pairs:
        c.require(key not in result,'DUPLICATE_PATCH_METADATA_FIELD');result[key]=value
    return result

def read(path,expected_hash=None):
    selected=Path(c.path(str(path)))
    with protected_directory(selected.parent) as directory:
        before=os.stat(selected.name,dir_fd=directory,follow_symlinks=False)
        c.require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                  and stat.S_IMODE(before.st_mode) in (0o400,0o600) and 0<before.st_size<=4_194_304,
                  'BOUNDED_ROOT_PRIVATE_PATCH_METADATA_REQUIRED')
        fd=os.open(selected.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            c.require(metadata(os.fstat(fd))==metadata(before),'PATCH_METADATA_CHANGED')
            chunks=[];count=0
            while count<=4_194_304:
                raw=os.read(fd,min(65536,4_194_305-count))
                if not raw:break
                chunks.append(raw);count+=len(raw)
            c.require(count==before.st_size and metadata(os.fstat(fd))==metadata(before)
                      ==metadata(os.stat(selected.name,dir_fd=directory,follow_symlinks=False)),
                      'PATCH_METADATA_CHANGED')
            value=json.loads(b''.join(chunks),object_pairs_hook=unique,
                             parse_constant=lambda _:c.require(False,'NONFINITE_PATCH_METADATA'))
            c.require(expected_hash is None or c.digest(value)==expected_hash,'EXACT_PATCH_METADATA_HASH_REQUIRED')
            return value
        finally:os.close(fd)
