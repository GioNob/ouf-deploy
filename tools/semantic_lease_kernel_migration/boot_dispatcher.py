"""Standalone, sealed boot dispatcher and shared native custody primitives.

This file is installed verbatim, outside any generation. Only stdlib imports.
The root-private CAS pointer authenticates the receipt, which seals the runner
and its complete closure. No imports from the delivery checkout at boot.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import uuid


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'DUPLICATE_JSON_FIELD')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'NONFINITE_JSON'))


def safe(path):
    path = Path(path)
    need(path.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))
         and '..' not in path.parts, 'SAFE_ABSOLUTE_PATH_REQUIRED')
    return path


def ancestors(path):
    for parent in safe(path).parents:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
             and not info.st_mode & 0o022, 'ROOT_ANCESTOR_REQUIRED')


def private(path, expected=None):
    path = safe(path)
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
             and before.st_size <= 8_388_608, 'ROOT_PRIVATE_FILE_REQUIRED')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(8_388_609)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'PRIVATE_FILE_CHANGED')
    finally:
        os.close(fd)
    need(expected is None or sha(raw) == expected, 'SEALED_FILE_CHANGED')
    return raw


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_once(path, raw):
    path = safe(path)
    ancestors(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    sync(path.parent)


def cas(path, before, after):
    # Same preflight, exclusive tempfile, recheck, rename, fsync contract as
    # publish_guard_files.py. Caller holds all common/operation locks.
    path = safe(path)
    need(private(path) == before, 'FOREIGN_PUBLICATION_PRESERVED')
    temporary = path.parent / ('.lease-kernel-' + uuid.uuid4().hex)
    write_once(temporary, after)
    try:
        need(private(path) == before, 'PUBLICATION_CHANGED_BEFORE_RENAME')
        os.replace(temporary, path)
        sync(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def lock(path):
    import fcntl
    path = safe(path)
    raw = private(path)
    need(raw == b'', 'EMPTY_LOCK_REQUIRED')
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(fd)
        actual = path.lstat()
        need((info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino), 'LOCK_INODE_CHANGED')
        private(path)
        yield
    finally:
        os.close(fd)


@contextmanager
def directory_lock(path):
    """Same directory inode flock used by the existing R3 issuer."""
    import fcntl
    path = safe(path)
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == 0o700, 'ROOT_PRIVATE_DIRECTORY_REQUIRED')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need((info.st_dev, info.st_ino) == (path.lstat().st_dev, path.lstat().st_ino), 'LOCK_INODE_CHANGED')
        yield
    finally:
        os.close(fd)


def executable(path, expected):
    path = safe(path)
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
             and info.st_nlink == 1 and not info.st_mode & 0o022 and info.st_mode & 0o111
             and info.st_size <= 33_554_432, 'ROOT_EXECUTABLE_REQUIRED')
        raw = os.read(fd, 33_554_433)
        need(len(raw) == info.st_size and sha(raw) == expected, 'EXECUTABLE_HASH_CHANGED')
    finally:
        os.close(fd)
    return str(path)


def command(binding, argv, raw=None):
    binary = executable(binding['path'], binding['sha256'])
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([binary, *argv], input=raw, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=30,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
                                    stdin=subprocess.DEVNULL if raw is None else None)
            output.seek(0)
            value = output.read(8_388_609)
        need(result.returncode == 0 and len(value) <= 8_388_608, 'BOUNDED_COMMAND_FAILED')
        return value
    finally:
        executable(binding['path'], binding['sha256'])


def structure(value):
    """Exact historical projection. In particular ALL handles are retained."""
    if isinstance(value, list):
        return [structure(v) for v in value]
    if isinstance(value, dict):
        if isinstance(value.get('set'), dict) and 'name' in value['set']:
            return {'set': structure({k: v for k, v in value['set'].items() if k != 'elem'})}
        return {k: structure(v) for k, v in value.items() if k not in ('packets', 'bytes', 'expires')}
    return value


def stable(value):
    if isinstance(value, list):
        return [stable(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes', 'expires')}
    return value


def digest(value):
    return sha(canonical(value))


def empty(tables):
    need(tables is not None and set(tables) == {'inet', 'bridge'}, 'TWO_FAMILIES_REQUIRED')
    need(not any(item['set'].get('elem') for table in tables.values()
                 for item in table['nftables'] if 'set' in item), 'LEASE_SETS_NOT_EMPTY')


def tables(nft, name):
    need(re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', name), 'INVALID_TABLE_NAME')
    inventory = document(command(nft, ['-j', 'list', 'tables']))
    present = {(r['table']['family'], r['table']['name']) for r in inventory['nftables'] if 'table' in r}
    membership = [(f, name) in present for f in ('inet', 'bridge')]
    need(all(membership) or not any(membership), 'PARTIAL_TABLE_PAIR_PRESERVED')
    if not any(membership):
        return None
    return {f: document(command(nft, ['-j', 'list', 'table', f, name])) for f in ('inet', 'bridge')}


def compiler(source_root, hashes):
    """Explicit namespace: v2's relative import must resolve the frozen compiler."""
    package = types.ModuleType('_lease_kernel_compiler')
    package.__path__ = []
    sys.modules[package.__name__] = package
    for name in ('materialize_southbound_kernel', 'materialize_southbound_kernel_v2'):
        relative = 'tools/' + name + '.py'
        path = Path(source_root) / relative
        raw = private(path, hashes[relative])
        full = package.__name__ + '.' + name
        module = types.ModuleType(full)
        module.__file__, module.__package__ = str(path), package.__name__
        sys.modules[full] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        setattr(package, name, module)
    return module


def sealed_receipt(pointer_path):
    pointer = document(private(pointer_path))
    need(set(pointer) == {'schema', 'receiptFile', 'receiptHash', 'observerFile', 'observerHash'}
         and pointer['schema'] == 'ouf.semantic-coordinated-boot-pointer.v1', 'BOOT_POINTER_SCHEMA')
    private(pointer['observerFile'], pointer['observerHash'])
    receipt = document(private(pointer['receiptFile'], pointer['receiptHash']))
    return pointer, receipt


def dispatch(pointer_path):
    pointer, receipt = sealed_receipt(pointer_path)
    need(pointer['observerHash'] == sha(private(Path(__file__))), 'DISPATCHER_POINTER_SEAL_DRIFT')
    need(receipt['schema'] == 'ouf.semantic-lease-kernel-generation.v1', 'DISPATCHER_RECEIPT_REQUIRED')
    root = Path(receipt['directory'])
    for name, expected in receipt['closure'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'CLOSURE_PATH_INVALID')
        private(root / name, expected)
    for directory in ('source', 'source/tools', 'source/scripts'):
        need(not os.path.lexists(root / directory / '__init__.py'), 'UNSEALED_INITIALIZER')
    profile_raw = private(receipt['bootProfile']['path'], receipt['bootProfile']['sha256'])
    profile = document(profile_raw)
    owner = document(private(profile['coordinatedConfiguration'], profile['coordinatedConfigurationHash']))
    with lock(owner['commonLockFile']):
        need(sealed_receipt(pointer_path) == (pointer, receipt), 'BOOT_POINTER_CHANGED')
        if receipt['generation'] == 1:
            # Retained legacy runner takes the same common lock itself.
            legacy = True
        else:
            legacy = False
            runner = receipt['runner']
            raw = private(root / runner, receipt['closure'][runner])
            namespace = {'__name__': 'sealed_generation_boot', '__file__': str(root / runner)}
            exec(compile(raw, str(root / runner), 'exec'), namespace)
            namespace['run'](receipt, sys.modules[__name__])
    if legacy:
        command(receipt['python'], ['-I', '-B', receipt['legacyRunner'], '--configuration',
                receipt['bootProfile']['path'], '--configuration-sha256', receipt['bootProfile']['sha256']])


def observe(receipt):
    """Read-only observer for the retained five-field installation pointer."""
    need(receipt['schema'] == 'ouf.semantic-lease-kernel-generation.v1', 'DISPATCHER_RECEIPT_REQUIRED')
    root = safe(receipt['directory'])
    for name, expected in receipt['closure'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'CLOSURE_PATH_INVALID')
        private(root / name, expected)
    profile = document(private(receipt['bootProfile']['path'], receipt['bootProfile']['sha256']))
    owner = document(private(profile['coordinatedConfiguration'], profile['coordinatedConfigurationHash']))
    with lock(owner['commonLockFile']):
        journal = document(private(owner['journalFile']))
        need(journal.get('state') == 'QUIESCED' and journal.get('leaseAuthorized') is False
             and journal.get('startAuthorized') is False, 'JOURNAL_NOT_QUIESCED')
        current = tables({'path': owner['nftPath'], 'sha256': owner['nftSha256']}, owner['kernel']['tableName'])
        empty(current)
        need(digest(structure(current)) == owner['expectedStructureHash'], 'LEASE_KERNEL_STRUCTURE_DRIFT')
    return {'schema': 'ouf.semantic-lease-kernel-readback.v1', 'generation': receipt['generation'],
            'kernelSha256': digest(owner['kernel']), 'leaseStructureHash': owner['expectedStructureHash'],
            'startAuthorized': False, 'leaseAuthorized': False, 'readOnly': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pointer', required=True)
    parser.add_argument('--self-sha256', required=True)
    args = parser.parse_args()
    try:
        need(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
             and sys.flags.isolated and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
        private(Path(__file__), args.self_sha256)
        dispatch(args.pointer)
        print('LEASE_KERNEL_BOOT=EMPTY START_AUTHORIZED=false LEASE_AUTHORIZED=false')
        return 0
    except Exception:
        print('LEASE_KERNEL_BOOT=HELD DOCKER_START_MUST_BE_DENIED=true')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
