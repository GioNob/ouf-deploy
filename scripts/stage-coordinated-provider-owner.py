#!/usr/bin/env python3
"""Stage the verified coordinated owner privately; no installed guard/lease/start changes."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

SOURCE_COMMIT = 'a10df126d229dfefd9e0a4d716a07f1f535b6cd6'
SOURCE_HASHES = {
    'scripts/run_semantic_coordinated_lease_owner.py': 'c2937a39578311018d47c0d414e6687278ce8b6b103de62c422cfe7b760b6889',
    'tools/materialize_southbound_kernel.py': '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de',
    'tools/materialize_southbound_lease_refresh.py': '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084',
    'tools/semantic_provider_coordinated_supervisor.py': '25a952c9f6d1385ce7759ef61666d25c7ec24a5735d3d0d27c36ade8e1614dad',
    'tools/semantic_provider_dns.py': 'c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930',
    'tools/semantic_provider_lease_coordination.py': 'e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587',
    'tools/semantic_provider_lease_nft.py': '7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93',
    'tools/semantic_provider_lease_owner.py': '92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d',
}
SNAPSHOTS = Path('/etc/ouf/deploy-snapshots')
EXISTING_CONFIGURATION = SNAPSHOTS / 'semantic-runtime-transition-stage-20261003-160211/prepared/runtime-configuration.json'
HELPER = Path('/usr/local/sbin/ouf-discovery-preflight')
HELPER_SHA256 = 'a46d0900ca20ed13115572c9ab9b436105c820e81f066d6e67c2a5333292e893'
EXPECTED = {'configurationHash': '24968cf990a32b87f3169b9226fe63d224c93a403540afec197011fbd670b0bb',
            'journalHash': '4ccb05b0a28b6e7e823de3d9af81f29255d60b38271d0a74a00f64e2e5828a74',
            'leaseStructureHash': '26f6f80af9d1e4898c1a6fe6dc8721cd6f67f1ceed05c7eea35e3b9f4a040e54'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parents(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe absolute path')
    for p in (path.parent, *path.parent.parents):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('unsafe protected parent')


def read(path, *, protected=False, executable=False, limit=2_000_000):
    if protected:
        parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > limit:
            raise ValueError('unsafe input file')
        if protected and (s.st_uid != 0 or s.st_gid != 0 or
                          (s.st_mode & 0o022 if executable else stat.S_IMODE(s.st_mode) != 0o600)):
            raise ValueError('unsafe protected input')
        if executable and not s.st_mode & 0o111:
            raise ValueError('executable required')
        raw = os.read(fd, limit + 1)
        if len(raw) != s.st_size:
            raise ValueError('input drift')
        return raw
    finally:
        os.close(fd)


def json_unique(raw):
    def unique(pairs):
        value = {}
        for k, v in pairs:
            if k in value:
                raise ValueError('duplicate key')
            value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=unique)


def current_native():
    if digest(read(HELPER, protected=True, executable=True)) != HELPER_SHA256:
        raise ValueError('installed helper drift')
    p = subprocess.run([str(HELPER)], stdin=subprocess.DEVNULL, capture_output=True, timeout=90,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    prefix = b'OUF_DISCOVERY_PRIVILEGED_PREFLIGHT='
    if p.returncode or len(p.stdout) > 131072 or not p.stdout.startswith(prefix):
        raise ValueError('native custody unavailable')
    report = json_unique(p.stdout[len(prefix):])
    validate_native(report)
    return report


def validate_native(report):
    if report.get('schema') != 'ouf.discovery.privileged-preflight.v2' or report.get('releaseApplied') is not False:
        raise ValueError('native report binding')
    r = report.get('runtimeReadiness', {})
    if any(r.get(k) != v for k, v in EXPECTED.items()) or any(r.get(k) is not True for k in
            ('runtimeCustodyVerified', 'stableAcrossReads', 'candidatesNeverStarted', 'providerSetsEmpty')) \
            or r.get('candidateCount') != 2 or r.get('runtimeState') != 'RUNTIME_EMPTY' \
            or r.get('guardProfile') != 'EMPTY_ONLY' or r.get('startAuthorized') is not False:
        raise ValueError('selected native cohort changed')


def dns_profile(kernel):
    flows = kernel['providerFlows']
    if not flows or any(f['addresses'] for f in flows):
        raise ValueError('empty provider flows required')
    resolver_sets = []
    for provider in flows:
        protocols = {}
        for flow in kernel['staticFlows']:
            if flow['purpose'] == 'DNS' and flow['source'] == provider['source']:
                if flow['port'] != 53:
                    raise ValueError('unexpected DNS port')
                address = str(ipaddress.ip_address(flow['destination']))
                protocols.setdefault(address, set()).add(flow['protocol'])
        resolvers = sorted(address for address, kinds in protocols.items() if kinds == {'tcp', 'udp'})
        if not resolvers or len(resolvers) > 8 or set(resolvers) != set(protocols):
            raise ValueError('governed UDP and TCP resolver bindings required')
        resolver_sets.append(resolvers)
    if any(row != resolver_sets[0] for row in resolver_sets):
        raise ValueError('one explicit resolver profile required')
    ceiling = min(f['leaseSeconds'] for f in flows)
    if type(ceiling) is not int or not 2 <= ceiling <= 3600:
        raise ValueError('bounded lease ceiling required')
    return {'resolvers': resolver_sets[0], 'resolverPort': 53, 'timeoutSeconds': 2,
            'maxLeaseSeconds': ceiling, 'applyBudgetSeconds': 1}


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)


def stage(source_directory):
    if os.geteuid() != 0:
        raise ValueError('root required')
    os.umask(0o077)
    # Verify all bytes before importing code or creating a snapshot.
    sources = {name: read(source_directory / name) for name in SOURCE_HASHES}
    if any(digest(raw) != SOURCE_HASHES[name] for name, raw in sources.items()):
        raise ValueError('reviewed source mismatch')
    before = current_native()
    raw = read(EXISTING_CONFIGURATION, protected=True)
    if digest(raw) != EXPECTED['configurationHash']:
        raise ValueError('existing runtime configuration drift')
    original = json_unique(raw)
    kernel = original['kernel']; profile = dns_profile(kernel)
    nft = Path(original['nftPath'])
    nft_hash = digest(read(nft, protected=True, executable=True, limit=16_777_216))
    lock = Path(original['lockFile']); read(lock, protected=True)
    parents(SNAPSHOTS / 'unused')
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    root = None
    try:
        info = os.fstat(fd); now = lock.lstat()
        if info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 \
                or not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (now.st_dev, now.st_ino):
            raise ValueError('common lock changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        root = Path(tempfile.mkdtemp(prefix='semantic-coordinated-owner-package-', dir=SNAPSHOTS))
        os.chmod(root, 0o700)
        source = root / 'source'; source.mkdir(mode=0o700)
        for name, contents in sources.items():
            path = source / name; path.parent.mkdir(mode=0o700, exist_ok=True); write_new(path, contents)
        configuration = {'schema': 'ouf.semantic-coordinated-owner-runtime.v1', 'kernel': kernel, 'dns': profile,
            'expectedStructureHash': EXPECTED['leaseStructureHash'], 'nftPath': str(nft), 'nftSha256': nft_hash,
            'readBudgetSeconds': 5, 'pollSeconds': min(30, profile['maxLeaseSeconds'] // 2),
            'commonLockFile': str(lock), 'journalFile': str(root / 'coordination-journal.json'), 'sourceHashes': SOURCE_HASHES}
        binding = {'transactionId': digest(os.urandom(32)), 'configurationHash': digest(encoded(configuration)),
                   'leaseStructureHash': EXPECTED['leaseStructureHash']}
        configuration['binding'] = binding
        journal = {'schema': 'ouf.semantic-lease-coordination.v1', **binding, 'state': 'QUIESCED',
                   'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[] for _ in kernel['providerFlows']]}
        configuration_hash = digest(encoded(configuration))
        write_new(root / 'coordinated-configuration.json', encoded(configuration))
        write_new(root / 'coordination-journal.json', encoded(journal))
    finally:
        os.close(fd)
    # Exercise only read-only guard mode; supervise/quiesce are never invoked.
    checked = subprocess.run(['/usr/bin/python3', '-I', '-B', str(root / 'source/scripts/run_semantic_coordinated_lease_owner.py'),
        '--mode', 'guard', '--configuration', str(root / 'coordinated-configuration.json'),
        '--configuration-sha256', configuration_hash], capture_output=True, timeout=45)
    if checked.returncode or b'SEMANTIC_COORDINATED_GUARD=PASS QUIESCED=true' not in checked.stdout:
        raise ValueError('staged read-only guard failed')
    after = current_native()
    if before['runtimeReadiness'] != after['runtimeReadiness']:
        raise ValueError('original custody changed during staging')
    receipt = {'schema': 'ouf.semantic-coordinated-owner-package.v1', 'sourceCommit': SOURCE_COMMIT,
        'sourceHashes': SOURCE_HASHES, 'originalRuntime': EXPECTED, 'configurationHash': configuration_hash,
        'journalHash': digest(encoded(journal)), 'readOnlyGuardVerified': True,
        'daemonStarted': False, 'guardInstalled': False, 'leaseAuthorized': False, 'startAuthorized': False,
        'rulesChanged': False, 'containerLifecycleOperations': 0, 'providerCalls': 0, 'notReleaseAcceptance': True}
    write_new(root / 'source-package-receipt.json', encoded(receipt))
    for directory in (root / 'source/scripts', root / 'source/tools', root / 'source', root):
        d = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    return {'status': 'PRIVATE_PACKAGE_STAGED', 'snapshotDirectory': str(root), **receipt}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = stage(args.source_directory)
        print('OUF_COORDINATED_OWNER_PACKAGE=' + json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('OUF_COORDINATED_OWNER_PACKAGE=BLOCKED PARTIAL_EVIDENCE_RETAINED=true NO_RAW_OUTPUT=true START_AUTHORIZED=false')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
