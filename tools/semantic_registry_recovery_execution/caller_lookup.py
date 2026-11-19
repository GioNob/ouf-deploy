"""Caller libc lookup files bound into an isolated transport child only.

Network addresses and ports are configuration inputs. Never load caller code,
change workload mounts, or use a host resolver as an implicit fallback.
"""
import hashlib
import os
import stat
from .core import require, digest
from tools.semantic_live_route_diagnostic.reader import process_ticks

VIEWS = ('resolv.conf', 'hosts', 'nsswitch.conf')
POLICY = {'mode': 'COPIED_CALLER_FILES_PRIVATE_MOUNTS_V1', 'nssHosts': ['files', 'dns'],
          'maximumFileBytes': 16384, 'maximumFiles': 3, 'hostResolverFallbackAllowed': False}


def metadata(s):
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def validate_views(views):
    require(type(views) is dict and set(views) == set(VIEWS)
            and all(type(v) is str and 0 < len(v.encode('ascii')) <= 16384 and '\0' not in v for v in views.values()),
            'BOUNDED_PUBLIC_CALLER_LOOKUP_FILES_REQUIRED')
    hosts = [line.split('#', 1)[0].split(':', 1)[1].split()
             for line in views['nsswitch.conf'].splitlines()
             if line.split('#', 1)[0].strip().startswith('hosts:')]
    # Do not allow a caller-controlled nsswitch to load additional host modules
    # or contact nscd, systemd-resolved, mDNS or another implicit side channel.
    require(hosts == [['files', 'dns']], 'CALLER_FILES_DNS_NSS_POLICY_REQUIRED')


def _caller_views(pid, ticks):
    require(process_ticks(pid) == ticks, 'SAME_CALLER_LOOKUP_GENERATION_REQUIRED')
    fds = []; values = {}; profiles = {}
    ident = lambda s: [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]
    try:
        root = os.open('/proc/' + str(pid) + '/root', os.O_PATH | os.O_DIRECTORY); fds.append(root)
        parent = os.open('etc', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root); fds.append(parent)
        parent_pin = ident(os.fstat(parent))
        require(parent_pin[2] == 0 and not parent_pin[4] & 0o022, 'PROTECTED_CALLER_ETC_REQUIRED')
        for name in VIEWS:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                    and before.st_mode & 0o004 and not before.st_mode & 0o022 and 0 < before.st_size <= 16384,
                    'PUBLIC_CUSTODIED_CALLER_LOOKUP_FILE_REQUIRED')
            raw = os.read(fd, 16385)
            require(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
                    == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'CALLER_LOOKUP_FILE_CHANGED')
            values[name] = raw.decode('ascii')
            profiles[name] = {'metadata': metadata(before), 'sha256': hashlib.sha256(raw).hexdigest()}
        require(parent_pin == ident(os.fstat(parent)) == ident(os.stat('etc', dir_fd=root, follow_symlinks=False))
                and process_ticks(pid) == ticks, 'CALLER_LOOKUP_DIRECTORY_OR_GENERATION_CHANGED')
        validate_views(values)
        return values, profiles
    finally:
        for fd in reversed(fds): os.close(fd)


def capture(caller, expected=None):
    pid = caller['State']['Pid']; ticks = process_ticks(pid)
    views, files = _caller_views(pid, ticks)
    profile = {'policy': POLICY, 'pid': pid, 'processTicks': ticks, 'files': files}
    require(expected is None or profile == expected, 'SAME_SIGNED_CALLER_LOOKUP_VIEW_REQUIRED')
    return profile, views


def payload(caller, profile):
    if profile is None: return {}
    require(type(profile) is dict and set(profile) == {'policy', 'pid', 'processTicks', 'files'}
            and profile['policy'] == POLICY, 'EXACT_CALLER_LOOKUP_POLICY_REQUIRED')
    _, views = capture(caller, profile)
    return {'lookup': views}


CHILD_SETUP = "\nimport ctypes\nif type(v['lookup'])is not dict or set(v['lookup'])!={'resolv.conf','hosts','nsswitch.conf'}:raise ValueError()\nif not all(type(x)is str and 0<len(x.encode('ascii'))<=16384 and '\\0'not in x for x in v['lookup'].values()):raise ValueError()\nnss=[s.split('#',1)[0].split(':',1)[1].split()for s in v['lookup']['nsswitch.conf'].splitlines()if s.split('#',1)[0].strip().startswith('hosts:')]\nif nss!=[['files','dns']]:raise ValueError()\nmount_before=os.stat('/proc/self/ns/mnt').st_ino\nos.unshare(os.CLONE_NEWNS)\nif os.stat('/proc/self/ns/mnt').st_ino==mount_before:raise ValueError()\nlibc=ctypes.CDLL(None,use_errno=True)\nlibc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p]\nlibc.mount.restype=ctypes.c_int\ndef mount(source,target,flags,kind=None,data=None):\n if libc.mount(source,target,kind,flags,data)!=0:raise OSError(ctypes.get_errno(),'')\nmount(None,b'/',(1<<14)|(1<<18)) # MS_REC | MS_PRIVATE, before any bind\nmount(b'tmpfs',b'/tmp',2|4|8,b'tmpfs',b'size=64k,mode=0700')\nfor name in ('resolv.conf','hosts','nsswitch.conf'):\n data=v['lookup'][name].encode('ascii')\n fd_copy=os.open('/tmp/ouf-view-'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)\n try:\n  if os.write(fd_copy,data)!=len(data):raise ValueError()\n finally:os.close(fd_copy)\nmount(None,b'/tmp',32|1|2|4|8) # private tmpfs now read-only\nfor name in ('resolv.conf','hosts','nsswitch.conf'):\n target=('/etc/'+name).encode('ascii')\n mount(('/tmp/ouf-view-'+name).encode('ascii'),target,4096) # MS_BIND\n mount(None,target,4096|32|1|2|4|8) # bind remount, RO/nosuid/nodev/noexec\n with open(target,'rb')as check:\n  if check.read(16385)!=v['lookup'][name].encode('ascii'):raise ValueError()\n# Prevent libc nscd from providing answers outside the copied lookup view.\n# nscd is not expected on this strictly bounded host transport; fail closed.\nif os.path.exists('/var/run/nscd/socket')or os.path.exists('/run/nscd/socket'):raise ValueError()\n"


def child(source, fields):
    # Source transformation is deterministic over the sealed transport body;
    # both the module and the body are members of the reviewed source closure.
    before = 'set(v)!=' + fields
    require(source.count(before) == 1 and source.count('os.setns(fd,0);os.close(fd)\n') == 1,
            'EXACT_LOOKUP_TRANSPORT_SOURCE_REQUIRED')
    source = source.replace(before, 'set(v) not in (' + fields + ',' + fields[:-1] + ",'lookup'})")
    setup = "    if 'lookup' in v:\n" + '\n'.join('        ' + line for line in CHILD_SETUP.splitlines()) + '\n'
    return source.replace('os.setns(fd,0);os.close(fd)\n', 'os.setns(fd,0);os.close(fd)\n' + setup)
