"""Typed finite custody for this patch's larger reviewed documents.

The historical generic 512KiB reader stays unchanged. Only named patch members
have these reviewed limits; no caller-supplied limit or filename fallback.
"""
import os
import stat
from tools.ingestion_readiness_patch_execution.contract import require,encoded
from tools.ingestion_readiness_patch_execution.private_file import metadata

LIMITS={'review.json':2097152,'packet.json':4194304,'decision.json':65536,
        'human.json':65536,'authority.json':131072}


def validate_sizes(review,packet=None):
    require(len(encoded(review))<=LIMITS['review.json'],'PATCH_REVIEW_EXCEEDS_TYPED_2MIB_LIMIT')
    if packet is not None:
        require(len(encoded(packet))<=LIMITS['packet.json'],'PATCH_PACKET_EXCEEDS_TYPED_4MIB_LIMIT')


def read_member(directory,name):
    require(type(name)is str and name in LIMITS,'EXACT_TYPED_PATCH_MEMBER_REQUIRED')
    maximum=LIMITS[name];before=os.stat(name,dir_fd=directory,follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0
        and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1
        and 0<before.st_size<=maximum,'TYPED_PATCH_MEMBER_CUSTODY_UNPROVEN')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        pin=metadata(before);require(metadata(os.fstat(fd))==pin,'TYPED_PATCH_MEMBER_CHANGED')
        chunks=[];count=0
        while count<=maximum:
            raw=os.read(fd,min(65536,maximum+1-count))
            if not raw:break
            chunks.append(raw);count+=len(raw)
        require(count==before.st_size and pin==metadata(os.fstat(fd))
            ==metadata(os.stat(name,dir_fd=directory,follow_symlinks=False)),
            'TYPED_PATCH_MEMBER_CHANGED')
        return b''.join(chunks)
    finally:os.close(fd)
