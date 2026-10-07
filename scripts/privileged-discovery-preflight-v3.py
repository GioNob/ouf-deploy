#!/usr/bin/python3 -I
"""No-argument root readback of the explicitly installed coordinated boot cohort."""
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import stat

BACKUP = Path('/usr/local/sbin/ouf-discovery-preflight-v2')
BACKUP_HASH = 'a46d0900ca20ed13115572c9ab9b436105c820e81f066d6e67c2a5333292e893'
POINTER = Path('/etc/ouf/coordinated-boot-installation.json')


def protected(path, executable=False):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe path')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or info.st_nlink != 1 or info.st_size > 2_000_000 \
                or stat.S_IMODE(info.st_mode) != (0o755 if executable else 0o600):
            raise ValueError('unsafe file')
        raw = os.read(fd, 2_000_001)
        if len(raw) != info.st_size: raise ValueError('file drift')
        return raw
    finally: os.close(fd)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate key')
        result[key] = value
    return result


def load(path, expected, executable=False):
    raw = protected(path, executable)
    if hashlib.sha256(raw).hexdigest() != expected: raise ValueError('source drift')
    name = 'sealed_'+path.stem
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def collect():
    legacy = load(BACKUP, BACKUP_HASH, True)
    pointer = json.loads(protected(POINTER), object_pairs_hook=unique)
    if set(pointer) != {'schema', 'receiptFile', 'receiptHash', 'observerFile', 'observerHash'} \
            or pointer['schema'] != 'ouf.semantic-coordinated-boot-pointer.v1':
        raise ValueError('closed installed pointer required')
    receipt = Path(pointer['receiptFile']); observer = Path(pointer['observerFile'])
    root = receipt.parent
    if root.parent != Path('/etc/ouf/deploy-snapshots') \
            or not root.name.startswith('semantic-coordinated-boot-install-') \
            or observer != root/'transition-source.py' or receipt.name != 'installation-receipt.json':
        raise ValueError('selected installed cohort required')
    raw = protected(receipt)
    if hashlib.sha256(raw).hexdigest() != pointer['receiptHash']: raise ValueError('receipt drift')
    installed = json.loads(raw, object_pairs_hook=unique)
    runtime = load(observer, pointer['observerHash'])
    # The original generic read-only inventory is preserved. Only its native
    # runtime observation changes to an explicit, sealed installed cohort.
    legacy.selected_runtime_readiness = lambda: runtime.observe(installed, legacy)
    report = legacy.collect()
    if report['runtimeReadiness'].get('runtimeCustodyVerified') is not True:
        raise ValueError('coordinated native observation denied')
    report['schema'] = 'ouf.discovery.privileged-preflight.v3'
    return report


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        print('OUF_DISCOVERY_PRIVILEGED_PREFLIGHT=BLOCKED ROOT_AND_NO_ARGUMENTS_REQUIRED')
        return 1
    try:
        print('OUF_DISCOVERY_PRIVILEGED_PREFLIGHT='+json.dumps(collect(), sort_keys=True))
        return 0
    except Exception:
        print('OUF_DISCOVERY_PRIVILEGED_PREFLIGHT=BLOCKED READ_FAILED NO_RAW_OUTPUT=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
