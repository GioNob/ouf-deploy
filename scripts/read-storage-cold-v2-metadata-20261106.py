#!/usr/bin/env python3
"""Metadata only for target sources; one hash-pinned retained inventory read."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

INVENTORY = Path('/var/lib/ouf-storage-migration/cold-backup-20261106-v1/command-002.private')
INVENTORY_SHA = '44dc112c351eea66ec85243826222f0c8c020f8f055b41b75c7b91ea8dc8d725'
RUNTIME = {
    '41372869507d2e5c524a29d0ab5f6ebeede966c49bd35074ff140dd90f7eb03f': ['gateway-owner'],
    '6e6edfffce47aea41d118170cfc2ec1d5cde443d2ece89c2c5d8b124671f5303': ['ingestion', 'ingestion-evidence-read'],
    '13bde9e56266f9f67359e1383fee1b4c84b37d862b944dbb2d445852f88ef0ee': ['onboarding'],
    '630028add258dae74151a71fc4e08e655c8a022f28b8b17a72e55f670c0f5c45': ['onboarding'],
    '16b173b9dbb759105551bc609b4ec3f4afd6e81ef1057166dfa786cf206aa2a8': ['udp', 'udp-evidence-read'],
}


def inspect_metadata(path, limit, private=False):
    """O_PATH on leaf: do not open source contents, follow symlinks or block on FIFO."""
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(path) != str(path):
        raise ValueError('PATH')
    parent = os.open('/', os.O_PATH | os.O_DIRECTORY)
    ancestry = True
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = nxt
            s = os.fstat(parent)
            ancestry = ancestry and s.st_uid == 0 and not s.st_mode & 0o022
        leaf = os.open(path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
        try:
            s = os.fstat(leaf)
            kind = next((name for test, name in ((stat.S_ISREG, 'REGULAR'), (stat.S_ISDIR, 'DIRECTORY'),
                (stat.S_ISLNK, 'SYMLINK'), (stat.S_ISSOCK, 'SOCKET'), (stat.S_ISFIFO, 'FIFO'),
                (stat.S_ISCHR, 'CHAR_DEVICE'), (stat.S_ISBLK, 'BLOCK_DEVICE')) if test(s.st_mode)), 'OTHER')
            checks = {'regularFile': stat.S_ISREG(s.st_mode), 'rootOwner': s.st_uid == 0,
                'singleLink': s.st_nlink == 1, 'notGroupOrOtherWritable': not bool(s.st_mode & 0o022),
                'nonemptyWithinLimit': 0 < s.st_size <= limit}
            return {'status': 'METADATA_OBSERVED', 'type': kind, 'uid': s.st_uid, 'gid': s.st_gid,
                'mode': format(stat.S_IMODE(s.st_mode), '04o'), 'links': s.st_nlink, 'bytes': s.st_size,
                'protectedAncestry': bool(ancestry), 'regularInputChecks': checks,
                'failedRegularInputChecks': [k for k, v in checks.items() if not v],
                'privateModeSatisfied': stat.S_IMODE(s.st_mode) == 0o600 if private else None}
        finally:
            os.close(leaf)
    except OSError as error:
        return {'status': 'METADATA_UNAVAILABLE', 'errno': error.errno}
    finally:
        os.close(parent)


def retained_paths():
    meta = inspect_metadata(INVENTORY, 32 << 20, private=True)
    if not (meta.get('status') == 'METADATA_OBSERVED' and meta['protectedAncestry']
            and not meta['failedRegularInputChecks'] and meta['privateModeSatisfied']):
        raise ValueError('INVENTORY_METADATA')
    fd = os.open(INVENTORY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, (32 << 20) + 1)
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != INVENTORY_SHA:
        raise ValueError('INVENTORY_DIGEST')
    paths = {}
    for doc in json.loads(raw):
        for mount in doc['Mounts']:
            source = mount.get('Source', '')
            key = hashlib.sha256(source.encode()).hexdigest()
            if key in RUNTIME:
                if not (source.startswith('/run/') and mount['Type'] == 'bind'
                        and mount['RW'] is False and mount['Destination'] == source):
                    raise ValueError('BINDING')
                paths[key] = source
    if set(paths) != set(RUNTIME):
        raise ValueError('FIVE_PATHS_REQUIRED')
    return paths


def main():
    if not (os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('ROOT_ISOLATED_PYTHON')
    rows = [dict(label='v2-program', **inspect_metadata('/var/lib/ouf-storage-cold-backup-v2.py', 32 << 20)),
            dict(label='base-input', **inspect_metadata('/var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.review.json', 32 << 20, private=True))]
    for key, path in sorted(retained_paths().items()):
        rows.append(dict(label='reviewed-run-source', roles=RUNTIME[key], sourcePathSha256=key,
                         **inspect_metadata(path, 1 << 20)))
    print(json.dumps({'schema': 'ouf.storage-cold-v2-metadata.v1', 'status': 'CURRENT_LOCAL_METADATA_OBSERVED',
        'inputs': rows, 'inventorySha256': INVENTORY_SHA, 'inventoryIsRetainedObservation': True,
        'currentMetadataOnly': True, 'currentProcessBindingsProven': False, 'exactFailureSiteProven': False,
        'inventoryFilesRead': 1, 'sourceBodiesRead': 0, 'providerRequests': 0, 'filesModified': 0,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'status': 'HELD', 'reason': 'METADATA_READER_INPUT_CHECK_FAILED',
            'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(1)
