"""Compile launch inputs from a creation request, never from observed OCI.

Bind bytes are hashed in a reusable mutable buffer and erased after every read.
No bind content is returned, decoded, copied into a launch or logged.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

MAX_BYTES = 1048576
DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


class Held(RuntimeError):
    """Public constant reason, without input values."""


def require(ok, code):
    if not ok:
        raise Held(code)


def absolute(value):
    require(type(value) is str and value.startswith('/') and '\x00' not in value
            and '..' not in value.split('/') and str(PurePosixPath(value)) == value,
            'SOURCE_ABSOLUTE_PATH_REQUIRED')
    return Path(value)


def identity(entry):
    return tuple(getattr(entry, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def parent_fd(path):
    """Walk root-owned ancestors with openat/no-follow; return pinned parent."""
    path = absolute(str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            entry = os.fstat(fd)
            require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0
                    and not entry.st_mode & 0o022, 'SOURCE_PARENT_CUSTODY_REQUIRED')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        entry = os.fstat(fd)
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0
                and not entry.st_mode & 0o022, 'SOURCE_PARENT_CUSTODY_REQUIRED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def source_binding(mount, uid, gid):
    """Hash under custody; the only root-owned source is the public CA bundle.

    This is the existing provider-v2 owner profile: role-owned private inputs,
    root:root 0644 trust-bundle.pem. HMAC is necessarily role-owned 0600.
    """
    path = absolute(mount['Source'])
    parent = None
    fd = None
    buffer = bytearray(65536)
    try:
        parent = parent_fd(path)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        owner = (0, 0) if path.name == 'trust-bundle.pem' else (uid, gid)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (before.st_uid, before.st_gid) == owner
                and mode in (0o600, 0o644)
                and (path.name != 'trust-bundle.pem' or mode == 0o644)
                and (path.name != 'provider-receipt.key' or mode == 0o600)
                and 0 <= before.st_size <= MAX_BYTES, 'SOURCE_FILE_CUSTODY_REQUIRED')
        digest, size = hashlib.sha256(), 0
        # FileIO.readinto avoids immutable copies of the HMAC bytes.
        with os.fdopen(fd, 'rb', buffering=0, closefd=False) as stream:
            while True:
                count = stream.readinto(buffer)
                if not count:
                    break
                size += count
                require(size <= MAX_BYTES, 'SOURCE_SIZE_EXCEEDED')
                digest.update(memoryview(buffer)[:count])
                buffer[:] = b'\x00' * len(buffer)
        require(size == before.st_size and identity(before) == identity(os.fstat(fd))
                and identity(before) == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                'SOURCE_CHANGED_DURING_READ')
        return {'source': str(path), 'target': mount['Target'], 'readOnly': True,
                'uid': before.st_uid, 'gid': before.st_gid, 'mode': mode,
                'sha256': digest.hexdigest(), 'maxBytes': MAX_BYTES}
    except OSError:
        raise Held('SOURCE_CUSTODY_IO_FAILED') from None
    finally:
        buffer[:] = b'\x00' * len(buffer)
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


def creation_launch(request, role, baseline_tmpfs=None, *, hash_source=source_binding):
    require(role in ('adapter', 'southbound'), 'LAUNCH_ROLE_REQUIRED')
    user = request['User']
    require(type(user) is str and re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', user),
            'NONROOT_NUMERIC_USER_REQUIRED')
    uid, gid = map(int, user.split(':'))
    args = (request.get('Entrypoint') or []) + (request.get('Cmd') or [])
    require(type(args) is list and args and all(type(v) is str and v and '\x00' not in v for v in args),
            'LAUNCH_ARGUMENTS_REQUIRED')
    cwd = request['WorkingDir']
    absolute(cwd)
    env = {}
    require(type(request['Env']) is list, 'LAUNCH_ENV_REQUIRED')
    for row in request['Env']:
        require(type(row) is str and '=' in row and '\x00' not in row, 'LAUNCH_ENV_REQUIRED')
        name, value = row.split('=', 1)
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) and name not in env
                and name != 'HOSTNAME', 'LAUNCH_ENV_REQUIRED')
        env[name] = value
    env = {'PATH': DEFAULT_PATH, 'HOSTNAME': '$OUF_HOSTNAME', **env}
    host = request['HostConfig']
    require(type(host['ReadonlyRootfs']) is bool and type(host['Memory']) is int
            and host['Memory'] > 0 and host['Memory'] == host['MemorySwap']
            and type(host['PidsLimit']) is int and host['PidsLimit'] > 0,
            'LAUNCH_RESOURCES_REQUIRED')
    mounts = host['Mounts']
    require(type(mounts) is list and 1 <= len(mounts) <= 32
            and not host.get('Binds') and all(m['Type'] == 'bind' and m['ReadOnly'] is True for m in mounts),
            'READONLY_REQUEST_BINDS_REQUIRED')
    for mount in mounts:
        absolute(mount['Source']); absolute(mount['Target'])
    require(len({m['Target'] for m in mounts}) == len(mounts), 'DUPLICATE_BIND_TARGET')
    manifest = {'user': user, 'readOnlyRoot': host['ReadonlyRootfs'],
                'memoryBytes': host['Memory'], 'pidsLimit': host['PidsLimit'],
                'mounts': [{'source': m['Source'], 'target': m['Target'], 'readOnly': True} for m in mounts]}
    if role == 'southbound':
        require(type(baseline_tmpfs) is dict and baseline_tmpfs
                and host.get('Tmpfs') == baseline_tmpfs, 'SOUTHBOUND_TMPFS_BASELINE_MISMATCH')
        manifest['tmpfs'] = dict(host['Tmpfs'])
    else:
        require(not host.get('Tmpfs'), 'ADAPTER_TMPFS_UNEXPECTED')
    return {'schema': 'ouf.semantic-creation-frame-launch.v1', 'manifest': manifest,
            'startup': {'uid': uid, 'gid': gid, 'umask': None, 'cwd': cwd, 'args': args,
                        'env': [key + '=' + value for key, value in env.items()]},
            'sources': [hash_source(mount, uid, gid) for mount in mounts]}
