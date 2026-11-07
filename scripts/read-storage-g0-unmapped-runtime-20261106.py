#!/usr/bin/env python3
"""Read two pinned retained documents; no provider, credential, process or write I/O.

Identify the one running non-roster image and application mount coverage. This
does not prove absence of external writers or current executable membership.
"""
import hashlib
import json
import os
import re
import stat
import sys

HOST = '/var/lib/ouf-g0-network-preparation-20261106/evidence/seaweedfs-g0-20261106-v2/host-before.private.json'
BASE = '/var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.review.json'
PINS = {
    HOST: '63cfa2294e173082a2891aeefcaef43747002fffc36312906b6d01c6d0342b71',
    BASE: 'dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e',
}
ROLES = {'apisix', 'caddy', 'gateway-owner', 'ingestion', 'ingestion-evidence-read',
         'keycloak', 'mcp', 'minio', 'onboarding', 'postgres', 'semantic', 'udp', 'udp-evidence-read'}

def require(value):
    if not value:
        raise ValueError('RETAINED_INPUT_MISMATCH')

def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def pairs(items):
    out = {}
    for k, v in items:
        require(k not in out)
        out[k] = v
    return out

def read_pinned(path, pin):
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        require(os.fstat(parent).st_uid == 0 and not os.fstat(parent).st_mode & 0o022)
        parts = path.split('/')[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            s = os.fstat(parent)
            require(s.st_uid == 0 and not s.st_mode & 0o022)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 32 * 1024 * 1024)
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            require(bool(chunk))
            raw.extend(chunk)
        require(identity(before) == identity(os.fstat(fd)) ==
                identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)))
        require(hashlib.sha256(raw).hexdigest() == pin)
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)

def analyze(host, base):
    require(host['schema'] == 'ouf.storage-g0-host-observation.v1' and not host['findings'])
    require(base['operationId'] == 'seaweedfs-g0-20261106-v2')
    require(set(host['roles']) == set(base['roles']) == ROLES and len(host['containers']) == 145)
    by_id = {r['id']: r for r in host['containers']}
    require(len(by_id) == 145)
    for role, record in host['roles'].items():
        require(record == by_id[record['id']])
        require(record['id'] == base['roles'][role]['containerId']
                and record['nativeImage'] == base['roles'][role]['nativeImage'])
    bound = {r['id'] for r in host['roles'].values()}
    extra = [r for r in host['containers'] if r['id'] not in bound and r['running'] is True]
    require(len(bound) == 13 and len(extra) == 1)
    record = extra[0]
    require(re.fullmatch('sha256:[0-9a-f]{64}', record['nativeImage']) is not None)
    revision = record.get('declaredRevision')
    name = record.get('name') or ''
    require(isinstance(name, str) and len(name) <= 256)
    hints = [x for x in ('registry', 'runner', 'backup') if x in name.lower()]
    def overlaps(target, mount):
        destination = mount.get('Destination')
        require(isinstance(destination, str) and destination.startswith('/'))
        require(os.path.normpath(destination) == destination)
        return target == destination or target.startswith(destination.rstrip('/') + '/')
    mounts = host['roles']['onboarding']['mounts']
    covering = [m for m in mounts if overlaps('/app/application.jar', m)]
    return {
        'schema': 'ouf.storage-g0-unmapped-runtime-readback.v1',
        'status': 'RETAINED_NON_ROSTER_IMAGE_IDENTIFIED_REVIEW_REQUIRED',
        'runningNonRoster': {'nativeImage': record['nativeImage'],
            'declaredRevision': revision if isinstance(revision, str) and re.fullmatch('[0-9a-f]{40}', revision) else None,
            'nameHintsNotAuthenticatedRole': hints,
            'nameSha256': hashlib.sha256(name.encode()).hexdigest(),
            'storageBindingCount': len(record['storageBindings']),
            'rwMounts': sum(m.get('RW') is True for m in record['mounts']),
            'containerIdSha256': hashlib.sha256(record['id'].encode()).hexdigest()},
        'onboardingApplicationJarMountCoverage': {'coveringMounts': len(covering),
            'writableCoveringMounts': sum(m.get('RW') is True for m in covering),
            'mountedFileContentsRead': False, 'writableContainerLayerChecked': False},
        'observedHostSha256': PINS[HOST], 'baseInputSha256': PINS[BASE],
        'filesRead': 2, 'filesModified': 0, 'credentialsRead': 0, 'providerRequests': 0,
        'processReads': 0, 'currentLiveObservation': False, 'writerCensusComplete': False,
        'executableMembershipProven': False, 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False, 'g0Complete': False, 'acceptanceCreditAdded': 0,
    }

def main():
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated
                and sys.flags.no_site and sys.dont_write_bytecode)
        print(json.dumps(analyze(read_pinned(HOST, PINS[HOST]), read_pinned(BASE, PINS[BASE])), sort_keys=True))
    except Exception:
        print(json.dumps({'status': 'HELD', 'reason': 'RETAINED_INPUT_OR_EXECUTION_MISMATCH',
                          'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False}))
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
