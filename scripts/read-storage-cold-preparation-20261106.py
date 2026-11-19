#!/usr/bin/env python3
"""Read retained prepare inventory only; never invoke Docker or retry prepare."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROGRAM = Path('/var/lib/ouf-storage-cold-backup.py')
PROGRAM_SHA = '3f8f255bf80cf2e077260ecf5ff2c31f14a624529864c8d3fac956877359cac8'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def category(path):
    if re.match(r'^/proc/[0-9]+/root(?:/|$)', path):
        return 'PROCESS_ROOT_VIEW'
    for root in ('/proc', '/sys', '/dev', '/run', '/tmp', '/var/run'):
        if path == root or path.startswith(root + '/'):
            return root
    return 'OTHER'


def review(base, selected, others, ids, helper):
    need = helper['need']
    need(set(base['roles']) == helper['ROLES'], 'ROSTER_MISMATCH')
    bindings = dict(base['roles'])
    bindings['etcd'] = {'containerId': helper['ETCD_ID'], 'nativeImage': helper['ETCD_IMAGE']}
    selected_ids = {v['containerId'] for v in bindings.values()}
    need(len(selected_ids) == 14 and isinstance(selected, list), 'SELECTED_SHAPE')
    need(0 < len(ids) <= 192 and len(set(ids)) == len(ids)
         and all(re.fullmatch('[a-f0-9]{64}', x) for x in ids), 'HOST_IDS')
    need(len(selected) == 14 and {d['Id'] for d in selected} == selected_ids, 'SELECTED_IDS')
    docs = selected + others
    need(len(docs) == len(ids) and {d['Id'] for d in docs} == set(ids), 'INVENTORY_INCOMPLETE')
    host = {d['Id']: d for d in docs}
    mounts = []
    for role, bound in sorted(bindings.items()):
        doc = host[bound['containerId']]
        need(doc['Image'] == bound['nativeImage'], 'BOUND_IMAGE_CHANGED')
        need(isinstance(doc['Mounts'], list) and len(doc['Mounts']) <= 128, 'MOUNT_COUNT')
        for mount in doc['Mounts']:
            source, dest = mount.get('Source', ''), mount['Destination']
            kind = mount['Type']
            need(isinstance(source, str) and isinstance(dest, str), 'MOUNT_PATH_TYPE')
            blockers = []
            if kind == 'tmpfs':
                if dest not in ('/tmp', '/run', '/var/run'):
                    blockers.append('NON_SCRATCH_TMPFS')
            elif kind not in ('bind', 'volume') or (kind == 'volume' and mount.get('Driver') != 'local'):
                blockers.append('UNSUPPORTED_DRIVER')
            else:
                if not source.startswith('/') or os.path.normpath(source) != source or len(Path(source).parts) < 3:
                    blockers.append('UNSAFE_OR_BROAD_SOURCE')
                if any(helper['overlap'](source, root) for root in ('/proc', '/sys', '/dev', '/run', '/tmp')):
                    blockers.append('EPHEMERAL_OR_DEVICE_MOUNT_REQUIRES_REVIEW')
            sharing = [d for d in others if source and any(
                m.get('Source') and helper['overlap'](source, m['Source']) for m in d['Mounts'])]
            mounts.append({'role': role, 'type': kind if kind in ('bind', 'volume', 'tmpfs') else 'OTHER',
                'readWrite': mount.get('RW'), 'sourceCategory': category(source),
                'sourcePathSha256': sha(source.encode()), 'destinationCategory': category(dest),
                'destinationPathSha256': sha(dest.encode()),
                'dockerSocketDestination': dest in ('/run/docker.sock', '/var/run/docker.sock'),
                'blockersFromRetainedMetadata': blockers,
                'sharingNonRosterContainers': len(sharing),
                'sharingNonRosterRunning': sum(bool(d['State']['Running']) for d in sharing)})
    return {'schema': 'ouf.storage-cold-preparation-readback.v1',
        'status': 'RETAINED_MOUNTS_REVIEW_REQUIRED', 'hostContainers': len(ids),
        'selectedRoles': 14, 'mounts': mounts, 'providerRequests': 0, 'filesModified': 0,
        'sourceBodiesRead': 0, 'currentLiveObservation': False,
        'historicalIntegrityAgainstPriorTrustedDigestProven': False,
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}


def main():
    if not (os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('ROOT_ISOLATED_PYTHON_REQUIRED')
    # Verify exact installed bytes BEFORE executing the qualified helper definitions.
    fd = os.open(PROGRAM, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_size == 24677
                and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1):
            raise ValueError('INSTALLED_PROGRAM_METADATA')
        raw = os.read(fd, 24678)
    finally:
        os.close(fd)
    if sha(raw) != PROGRAM_SHA:
        raise ValueError('INSTALLED_PROGRAM_DIGEST')
    h = {'__name__': 'readback_only', '__file__': str(PROGRAM)}
    exec(compile(raw, str(PROGRAM), 'exec'), h)
    need, read, decode = h['need'], h['protected'], h['decode']
    need(sha(read(PROGRAM, private=True)) == PROGRAM_SHA, 'INSTALLED_PROGRAM_CHANGED')
    base_raw = read(h['BASE'], private=True)
    need(sha(base_raw) == h['BASE_SHA'], 'RETAINED_BASE_INPUT_CHANGED')
    area = h['AREA']
    receipts = {'baseInput': sha(base_raw), 'installedProgram': PROGRAM_SHA}
    raws = {}
    for n in (1, 2, 3):
        path = area / ('command-%03d.private' % n)
        if n == 3 and not path.exists():
            continue
        raws[n] = read(path, private=True)
        receipts[path.name] = sha(raws[n])
    ids = raws[1].decode().split()
    selected = decode(raws[2])
    others = [decode(line) for line in raws.get(3, b'').splitlines()]
    result = review(decode(base_raw), selected, others, ids, h)
    result['localInputSha256'] = receipts
    result['laterStageEntriesPresent'] = [name for name in
        ('plan.private.json', 'planned-containers.private.json', 'preparation-result.json', 'capture')
        if os.path.lexists(area / name)]
    for n, raw in raws.items():
        need(read(area / ('command-%03d.private' % n), private=True) == raw, 'RETAINED_INPUT_CHANGED')
    need(read(h['BASE'], private=True) == base_raw, 'RETAINED_BASE_INPUT_CHANGED')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never echo exceptions: their text may contain private paths or JSON values.
        print(json.dumps({'status': 'HELD', 'reason': 'LOCAL_READBACK_INPUT_CHECK_FAILED',
                          'providerRequests': 0, 'filesModified': 0, 'runtimeAuthorityIssued': False,
                          'acceptanceCreditAdded': 0, 'automaticReplayAllowed': False}))
        sys.exit(1)
