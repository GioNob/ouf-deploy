"""Bounded Linux mount metadata and O_PATH primitives; no owners or mutation.

Kernel proc contract sections3.5/3.8; no content/file policy admission.
"""
import os,re,stat
from pathlib import Path
from .custody_capture import require

KERNEL_CONTRACT='https://www.kernel.org/doc/html/latest/filesystems/proc.html#proc-pid-mountinfo-information-about-mounts'
LIMITS={'maximumSeconds':90,'maximumMountinfoBytes':262144,'maximumMountRows':4096,'maximumFdinfoBytes':8192}


def canonical(value):
    require(type(value) is str and value.startswith('/') and not value.startswith('//') and value!='/' and str(Path(value))==value
        and '..' not in Path(value).parts and len(Path(value).parts)<=64,
        'EXACT_EFFECTIVE_MOUNT_DESTINATION_REQUIRED')
    return value


def unescape(value):
    require(not re.search(r'\\(?!040|011|012|134)',value),'KERNEL_MOUNTINFO_ESCAPE_UNPROVEN')
    return re.sub(r'\\(040|011|012|134)',lambda m:chr(int(m[1],8)),value)


def parse_mountinfo(raw):
    require(type(raw) is bytes and 0<len(raw)<=LIMITS['maximumMountinfoBytes'] and raw.endswith(b'\n')
        and b'\x00' not in raw,'COMPLETE_BOUNDED_KERNEL_MOUNTINFO_REQUIRED')
    rows=[];ids=set()
    for line in raw.decode('utf-8').splitlines():
        values=line.split(' ')
        require('' not in values and values.count('-')==1,'EXACT_KERNEL_MOUNTINFO_SEPARATOR_REQUIRED')
        separator=values.index('-')
        require(separator>=6 and len(values)==separator+4 and values[0].isdigit() and int(values[0])>0
            and values[1].isdigit() and re.fullmatch('[0-9]+:[0-9]+',values[2])
            and values[0] not in ids and len(rows)<LIMITS['maximumMountRows'],
            'UNIQUE_BOUNDED_KERNEL_MOUNTINFO_ROWS_REQUIRED')
        point=unescape(values[4]);require(point.startswith('/') and str(Path(point))==point
            and '..' not in Path(point).parts,'CANONICAL_KERNEL_MOUNTPOINT_REQUIRED')
        options=values[5].split(',');require(len(options)==len(set(options))
            and len({'ro','rw'}&set(options))==1,'ONE_EFFECTIVE_PER_MOUNT_ACCESS_MODE_REQUIRED')
        rows.append({'mountId':int(values[0]),'mountPoint':point,'readOnly':'ro' in options});ids.add(values[0])
    return rows


def select_mount(rows,target,readonly):
    canonical(target);found=[row for row in rows if row['mountPoint']==target]
    require(len(found)==1 and found[0]['readOnly'] is readonly
        and not any(row['mountPoint'].startswith(target+'/') for row in rows),
        'EXACT_EFFECTIVE_MOUNT_ACCESS_AND_NO_SHADOWING_REQUIRED')
    return found[0]


def kernel_read(path,maximum,budget):
    budget.check();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        pieces=[];size=0
        while size<=maximum:
            budget.check();raw=os.read(fd,min(65536,maximum+1-size))
            if not raw:break
            pieces.append(raw);size+=len(raw)
        require(0<size<=maximum,'BOUNDED_COMPLETE_KERNEL_METADATA_REQUIRED');return b''.join(pieces)
    finally:os.close(fd)


def fd_mount_id(fd,budget):
    raw=kernel_read('/proc/self/fdinfo/'+str(fd),LIMITS['maximumFdinfoBytes'],budget)
    rows=[row.split(':',1)[1].strip() for row in raw.decode('ascii').splitlines() if row.startswith('mnt_id:')]
    require(len(rows)==1 and rows[0].isdigit() and int(rows[0])>0,'EXACT_HELD_DESCRIPTOR_MOUNT_ID_REQUIRED')
    return int(rows[0])


def view_node(root,target):
    canonical(target);fds=[];fd=os.dup(root);fds.append(fd)
    try:
        for name in Path(target).parts[1:]:
            fd=os.open(name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
            require(not stat.S_ISLNK(os.fstat(fd).st_mode),'EFFECTIVE_MOUNT_VIEW_LINK_DENIED')
        return os.dup(fd)
    finally:
        for fd in reversed(fds):os.close(fd)

