#!/usr/bin/env python3
"""Remove only the observed, already-unmounted southbound namespace placeholder.

An exact current lifecycle read and existing locks precede the unlink. No
namespace is unmounted, no runtime journal advanced, no service/lease started.
"""
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
import traceback
import types
from datetime import datetime, timezone

READER = 'read-discovery-lifecycle-20261109.py'
READER_SHA = '4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67'
RECEIPT = Path('/var/lib/ouf-storage-migration/discovery-lifecycle-rman5rz0/result.json')
RECEIPT_SHA = '61976131c5f709934b6e3b598ab7874476a9affbae100aca016692caba7e593e'
CLAIM = Path('/var/lib/ouf-storage-migration/discovery-southbound-placeholder-20261109')
OBSERVED_INODE = 4040196
NSFS_MAGIC = 0x6E736673
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def identity(info):
    return [getattr(info, k) for k in FIELDS]


def open_parent(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_PRIVATE_PATH_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            need(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'ROOT_CONTROLLED_PATH_REQUIRED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_private(path, maximum=2097152):
    path = Path(path); parent = open_parent(path); fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and not before.st_mode & 0o077
             and before.st_nlink == 1 and before.st_size <= maximum, 'BOUNDED_ROOT_PRIVATE_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'PRIVATE_FILE_CHANGED')
        return raw
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def filesystem_type(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
    libc.fstatfs.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(256)
    need(libc.fstatfs(fd, buffer) == 0, 'FILESYSTEM_TYPE_READ_FAILED')
    return ctypes.c_long.from_buffer(buffer).value & 0xFFFFFFFF


def mount_id(fd):
    raw = Path('/proc/self/fdinfo/' + str(fd)).read_bytes()
    values = re.findall(rb'^mnt_id:\s*([0-9]+)\s*$', raw, re.M)
    need(len(values) == 1, 'FD_MOUNT_ID_UNPROVEN')
    return int(values[0])


def mountpoint_present(path):
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(4194305)
    need(len(raw) <= 4194304, 'MOUNTINFO_LIMIT')
    for line in raw.splitlines():
        fields = line.split()
        need(len(fields) >= 10 and b'-' in fields[6:], 'MOUNTINFO_FORMAT_UNPROVEN')
        mountpoint = re.sub(rb'\\([0-7]{3})', lambda m: bytes([int(m[1], 8)]), fields[4])
        if os.fsdecode(mountpoint) == str(path):
            return True
    return False


@contextlib.contextmanager
def placeholder(path, expected_inode):
    """Hold the inode and parent open; never open/read an nsfs object as data."""
    path = Path(path); parent = open_parent(path); fd = None
    try:
        fd = os.open(path.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode), 'REGULAR_PLACEHOLDER_REQUIRED')
        need(filesystem_type(fd) != NSFS_MAGIC, 'MOUNTED_NAMESPACE_PRESERVED')
        need(mount_id(fd) == mount_id(parent) and not mountpoint_present(path), 'MOUNTPOINT_PRESERVED')
        need(info.st_ino == expected_inode and info.st_dev == os.fstat(parent).st_dev, 'OBSERVED_PLACEHOLDER_INODE_CHANGED')
        need(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
             and info.st_size == 2, 'EXACT_PLACEHOLDER_METADATA_REQUIRED')
        raw = read_private(path, 2)
        need(raw == b'{}', 'EXACT_PREPARER_PLACEHOLDER_BYTES_REQUIRED')
        need(identity(info) == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'PLACEHOLDER_CHANGED')
        yield parent, fd, info, raw
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def remove_placeholder(path, expected_inode, before_unlink):
    with placeholder(path, expected_inode) as (parent, fd, info, raw):
        before_unlink(info, raw)
        # Re-open/check after the durable intent, retaining the first descriptor.
        with placeholder(path, expected_inode) as (_, _, second, _):
            need(identity(info) == identity(second), 'PLACEHOLDER_CHANGED_AFTER_INTENT')
            os.unlink(Path(path).name, dir_fd=parent)
            os.fsync(parent)
            need(os.fstat(fd).st_nlink == 0, 'HELD_PLACEHOLDER_INODE_NOT_UNLINKED')
            try: os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: return
            raise RuntimeError('PLACEHOLDER_PATH_REAPPEARED')


@contextlib.contextmanager
def existing_lock(path, directory=False):
    path = Path(path); parent = open_parent(path)
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=parent)
    os.close(parent)
    try:
        info = os.fstat(fd)
        need(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o077 and
             (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), 'EXISTING_PRIVATE_LOCK_REQUIRED')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def terminal_conditions(current):
    need(current.get('status') == 'DISCOVERY_LIFECYCLE_READ_COMPLETE', 'FRESH_LIFECYCLE_REQUIRED')
    expected = {'adapter': {'adapter': 'DELETED', 'admission': 'CLEANED', 'broker': 'CLEANED', 'preexec': 'ROLLED_BACK'},
                'southbound': {'adapter': 'DELETING', 'admission': 'PROTECTED', 'broker': 'PROTECTED', 'preexec': 'PROTECTED'}}
    for role in ('adapter', 'southbound'):
        row = current['components'][role]
        need(row['journalStates'] == expected[role], 'RETAINED_JOURNALS_CHANGED')
        need(not row['runc']['present'] and not row['runcDirectory']['present'] and not row['containerdTask']['present']
             and row['shimCount'] == 0 and row['ownedTableFamilies'] == [], 'NATIVE_RESIDUE_REQUIRES_DIFFERENT_RECOVERY')
        need(set(row['generations']) == {'admission', 'preexec'} and
             all(v['recordedGenerationAlive'] is False and v['recordedPidPresent'] is False for v in row['generations'].values()), 'RECORDED_PROCESSES_MUST_BE_ABSENT')
    coord = current['coordination']
    need(coord['state'] == 'BLOCKED' and coord['leaseAuthorized'] is False and coord['tableFamiliesPresent'] == ['bridge', 'inet']
         and all(coord[f] == {'setCount': 2, 'elementCount': 0} for f in ('inet', 'bridge')), 'RETAINED_BLOCKED_EMPTY_LEASE_REQUIRED')
    need(current['components']['adapter']['namespaceHandle']['present'] is False, 'ADAPTER_MUST_REMAIN_CLEAN')
    handle = current['components']['southbound']['namespaceHandle']
    need(handle['present'] is True and handle['inode'] == OBSERVED_INODE and handle['matchesRecordedInode'] is False,
         'EXACT_OBSERVED_NAMESPACE_PATH_REQUIRED')


def main():
    report = {'schema': 'ouf.discovery-placeholder-reconciliation.v1', 'status': 'HELD',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'namespacePlaceholderRemoved': False,
              'namespaceUnmounts': 0, 'runtimeJournalWrites': 0, 'serviceConfigurationChanged': False,
              'serviceStartDispatched': False, 'serviceStops': 0, 'containerdMetadataDeleted': False,
              'leaseStateChanged': False, 'nftWrites': 0, 'databaseRequests': 0, 'businessRequestsIssued': 0,
              'providerRequests': 0, 'tokenRequests': 0, 's3Requests': 0, 'credentialFileContentsRead': 0,
              'credentialValuesEmitted': False, 'historicalAuthorityReused': False, 'automaticReplayAllowed': False,
              'providerReady': False, 'newGenerationAdmitted': False, 'unlinkAttempted': False}
    work = None; native = None; intended = False
    def deadline(*_): raise RuntimeError('RECONCILIATION_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(180)
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_OPERATOR_REQUIRED')
        os.umask(0o077)
        report['phase'] = 'VERIFY_RETAINED_OBSERVATION'
        receipt_raw = read_private(RECEIPT)
        need(sha(receipt_raw) == RECEIPT_SHA, 'RETAINED_LIFECYCLE_RECEIPT_CHANGED')
        need(not os.path.lexists(CLAIM), 'PRIOR_RECONCILIATION_PRESERVED_DO_NOT_REPLAY')
        raw = Path(__file__).with_name(READER).read_bytes()
        need(sha(raw) == READER_SHA, 'PINNED_LIFECYCLE_READER_CHANGED')
        l = {'__name__': 'pinned_lifecycle', '__file__': str(Path(__file__).with_name(READER))}
        exec(compile(raw, l['__file__'], 'exec'), l)
        l = types.SimpleNamespace(**l)
        s = l.module(l.STARTUP, l.STARTUP_SHA); h = l.module(l.HELPER, l.HELPER_SHA)
        bindings = l.parse(read_private(RECEIPT.parent / 'source-bindings.private.json'))
        matches = [p for p, v in bindings.items() if v['sha256'] == l.CONFIG_SHA]
        need(len(matches) == 1, 'ONE_RETAINED_RUNTIME_CONFIGURATION_REQUIRED')
        cfg_raw = read_private(matches[0]); need(sha(cfg_raw) == l.CONFIG_SHA, 'RETAINED_RUNTIME_CONFIGURATION_CHANGED')
        cfg = l.parse(cfg_raw); registry = s.exact_path(cfg['registryRoot']); cid = s.PINS['southbound'][0]
        need(registry.is_relative_to('/etc/ouf'), 'EXACT_RETAINED_REGISTRY_REQUIRED')
        root = registry / cid
        adapter = l.parse(read_private(root / 'adapter.json')); driver_raw = read_private(root / 'driver.json')
        need(adapter['configurationHash'] == l.runtime_binding(cfg, cid) and sha(driver_raw) == adapter['driverHash'], 'CURRENT_DRIVER_BINDING_REQUIRED')
        driver = l.parse(driver_raw)
        work = Path(tempfile.mkdtemp(prefix='discovery-placeholder-', dir=CLAIM.parent))
        report['privateEvidenceDirectory'] = str(work)
        report['phase'] = 'LOCK_CURRENT_COHORT_AND_LEASE'
        with contextlib.ExitStack() as locks:
            for role in ('southbound', 'adapter'):
                locks.enter_context(existing_lock(registry / s.PINS[role][0] / 'operation.lock'))
            locks.enter_context(existing_lock(registry, directory=True))
            locks.enter_context(existing_lock(s.exact_path(driver['lockFile'])))
            report['phase'] = 'VERIFY_CURRENT_NATIVE_ABSENCE'
            current = {}; reader = s.Reader(); native = l.Native(work)
            l.collect(current, h, s, reader, native, work)
            save(work / 'preflight.json', encoded(current)); terminal_conditions(current)
            need(sha(read_private(root / 'driver.json')) == sha(driver_raw), 'DRIVER_CHANGED_BEFORE_RECOVERY')
            namespace = root / 'netns'
            report['phase'] = 'VERIFY_UNMOUNTED_PLACEHOLDER'
            with placeholder(namespace, OBSERVED_INODE): pass
            def intent(info, raw):
                nonlocal intended
                report['phase'] = 'REMOVE_EXACT_UNMOUNTED_PLACEHOLDER'
                os.mkdir(CLAIM, 0o700)
                intended = True
                save(work / 'placeholder.before', raw)
                save(work / 'source-bindings.private.json', encoded(reader.seals))
                save(CLAIM / 'intent.json', encoded({'schema': 'ouf.discovery-placeholder-intent.v1',
                    'namespacePath': str(namespace), 'identity': identity(info), 'evidenceDirectory': str(work),
                    'priorLifecycleReceiptSha256': RECEIPT_SHA, 'unmountAllowed': False, 'startAllowed': False}))
                report['unlinkAttempted'] = True
            remove_placeholder(namespace, OBSERVED_INODE, intent)
            report['namespacePlaceholderRemoved'] = True
            report['phase'] = 'VERIFY_RETAINED_JOURNALS_AND_FRAMES'
            # Source files include root-owned executable wrapper/source (not all
            # mode0600), so reuse the exact sealed read semantics of the reader.
            verifier = s.Reader(); verifier.seals = dict(reader.seals)
            for path in list(reader.seals): verifier.read(path, 'postRemovalRecheck')
            for role in ('adapter', 'southbound'):
                need(h.digest(h.frame(h.inspect(s.PINS[role][0]))) == s.PINS[role][1], 'PROVIDER_FRAME_CHANGED_AFTER_REMOVAL')
            need(not os.path.lexists(namespace), 'PLACEHOLDER_PATH_REAPPEARED')
            report.update(status='SOUTHBOUND_UNMOUNTED_PLACEHOLDER_REMOVED', phase='COMPLETE',
                          retainedRuntimeJournalsUnchanged=True, containerFramesUnchanged=True,
                          coordinationState='BLOCKED', providerLeaseSetsEmptyAtLockedRead=True)
            save(CLAIM / 'complete.json', encoded(report))
    except Exception as exc:
        reason = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=reason, operationIntentPresent=intended,
            errorLocation=[{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-3:]])
    finally:
        signal.alarm(0)
        if native is not None: report['nativeReadCommands'] = native.calls
        if work is not None: save(work / 'result.json', encoded(report))
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'SOUTHBOUND_UNMOUNTED_PLACEHOLDER_REMOVED' else 1


if __name__ == '__main__':
    sys.exit(main())
