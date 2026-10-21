"""Read bounded retained worker metadata; no operational code is executed."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import traceback

BASE = Path('/etc/ouf/deploy-snapshots')
CONTEXT = BASE/'semantic-provider-v2-approved-context-mf9x0eqd'
OUTPUT = BASE/'semantic-provider-v2-transaction-mf9x0eqd'
GUARD = BASE/'semantic-coordinated-boot-install-v2-e4repg0a'
POINTER = Path('/etc/ouf/coordinated-boot-installation.json')
OWNER_HASH = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
APPROVAL = 'OUF_PROVIDER_PREPARED_MOUNTPOINT_APPROVED_20261009T203804_CEST_R8'
TARGETS = {
    'adapter': ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
                'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc'),
    'southbound': ('1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
                   'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366')}
UNIT_PATHS = {
    'guard.service': Path('/etc/systemd/system/ouf-semantic-boot-guard.service'),
    'docker-drop-in.conf': Path('/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf')}
FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},'
          '"runtime":{{json .HostConfig.Runtime}},"state":{{json .State}},'
          '"restartCount":{{json .RestartCount}},"networks":{{json .NetworkSettings.Networks}}}')
PHASE = 'READ_CONSUMED_R8_CONTEXT'
SAVED = {}
DIAGNOSIS = {}


class ReadDenied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise ReadDenied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ReadDenied('NONFINITE_JSON_VALUE')))


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                                          'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def private(path, expected=None, executable=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'EXPLICIT_SAFE_PATH_REQUIRED')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'ROOT_OWNED_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        limit = 64000000 if executable else 2000000
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and info.st_size <= limit and (bool(info.st_mode & 0o111) and not info.st_mode & 0o022
                if executable else stat.S_IMODE(info.st_mode) == 0o600), 'ROOT_FILE_CUSTODY_UNPROVEN')
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit, 'BOUNDED_FILE_REQUIRED')
        raw = b''.join(chunks)
        require(size == info.st_size and identity(info) == identity(os.fstat(fd)) == identity(path.lstat()),
                'FILE_CHANGED_DURING_READ')
    finally:
        os.close(fd)
    if expected is not None:
        if sha(raw) != expected:
            DIAGNOSIS.update(inputFileName=path.name, expectedSha256=expected, actualSha256=sha(raw))
            raise ReadDenied('EXACT_FILE_HASH_DRIFT')
    return raw


def bound(binding):
    require(type(binding) is dict and set(binding) == {'path', 'sha256'}
            and re.fullmatch('[0-9a-f]{64}', binding['sha256']), 'EXACT_FILE_BINDING_REQUIRED')
    raw = private(binding['path'], binding['sha256'])
    SAVED[binding['path']] = raw
    return raw


def safe_source(root, name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'SOURCE_PATH_ESCAPE_DENIED')
    return root/path


"""Observe only the consumed worker's retained diagnostics; never restart it."""
LEASE_ROOT = BASE / 'semantic-r8-lease-8wfsv1aa'
LEASE_CLAIM = Path('/etc/ouf/provider-r8-network-lease-readback-recovery.claim')
LEASE_APPROVAL = 'OUF_R8_LEASE_READBACK_RECOVERY_APPROVED_20261009T225847_CEST'
UNIT = 'ouf-semantic-provider-lease-r8.service'
PROGRAM_HASHES = {
    'activate.py': '58ec8285357ba8fdceb35dbe1af92138a1aff3f91b742c1ae3f425c073e56528',
    'activation_core.py': '51259c988eae4b506f2696ad3f5bf6e954eca9c4396cb36da75e0845ff49e50b',
    'reader.py': 'ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8',
    'materialize_southbound_lease_refresh.py': 'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079'}
SERVICE_PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'Restart', 'Result',
    'ExecMainCode', 'ExecMainStatus', 'NRestarts', 'ActiveEnterTimestamp', 'ActiveExitTimestamp',
    'InactiveEnterTimestamp', 'ExecMainStartTimestamp', 'ExecMainExitTimestamp',
    'StateChangeTimestamp', 'InvocationID', 'Transient')
PHASE = 'READ_EXACT_CONSUMED_LEASE_WORKER'


def safe_word(value, pattern, fallback):
    return value if type(value) is str and re.fullmatch(pattern, value) else fallback


def failure_projection(value):
    require(type(value) is dict, 'BOUNDED_DIAGNOSTIC_OBJECT_REQUIRED')
    projected = {}
    for key in ('schema', 'status', 'phase', 'reason', 'errorType', 'cleanup'):
        if key in value:
            pattern = '[A-Za-z][A-Za-z0-9_.-]{0,119}' if key in ('schema', 'errorType') else '[A-Z][A-Z0-9_]{0,119}'
            projected[key] = safe_word(value[key], pattern, 'DETAIL_REDACTED')
    for key in ('refreshCount', 'workerPid', 'errno'):
        if key in value and type(value[key]) is int and 0 <= value[key] <= 2147483647:
            projected[key] = value[key]
    for key in ('freshDnsObserved', 'leaseAuthorized', 'setsRevoked', 'doNotRerunApply', 'startAuthorized'):
        if key in value and type(value[key]) is bool:
            projected[key] = value[key]
    if 'journalHash' in value:
        projected['journalHash'] = safe_word(value['journalHash'], '[0-9a-f]{64}', 'DETAIL_REDACTED')
    if 'flowAddressCounts' in value:
        counts = value['flowAddressCounts']
        if type(counts) is list and len(counts) == 2 and all(type(n) is int and 0 <= n <= 32 for n in counts):
            projected['flowAddressCounts'] = counts
    chain = value.get('exceptionChain', [])
    require(type(chain) is list and len(chain) <= 6, 'BOUNDED_FAILURE_CHAIN_REQUIRED')
    if chain:
        projected['exceptionChain'] = []
        for row in chain:
            require(type(row) is dict, 'FAILURE_CHAIN_OBJECT_REQUIRED')
            clean = {key: safe_word(row.get(key), pattern, 'DETAIL_REDACTED') for key, pattern in (
                ('reason', '[A-Z][A-Z0-9_]{0,119}'), ('errorType', '[A-Za-z][A-Za-z0-9_]{0,79}'))}
            if type(row.get('errno')) is int and 0 <= row['errno'] <= 4096:
                clean['errno'] = row['errno']
            points = row.get('exceptionPoints', [])
            require(type(points) is list and len(points) <= 6, 'BOUNDED_EXCEPTION_POINTS_REQUIRED')
            clean['exceptionPoints'] = []
            for point in points:
                require(type(point) is dict, 'EXCEPTION_POINT_OBJECT_REQUIRED')
                clean['exceptionPoints'].append({
                    'file': safe_word(point.get('file'), '[A-Za-z0-9_.-]{1,100}', 'DETAIL_REDACTED'),
                    'function': safe_word(point.get('function'), '[A-Za-z_][A-Za-z0-9_]{0,99}', 'DETAIL_REDACTED'),
                    'line': point['line'] if type(point.get('line')) is int and 0 < point['line'] < 1000000 else None})
            projected['exceptionChain'].append(clean)
    return projected


def service_read(binding, argv):
    expected = [['show', unit, '--property=' + ','.join((*SERVICE_PROPERTIES, 'ExecStart'))]
                for unit in (UNIT, 'docker.service')]
    require(argv in expected, 'EXACT_SYSTEMD_METADATA_ONLY_REQUIRED')
    private(binding['path'], binding['sha256'], executable=True)
    result = subprocess.run([binding['path'], *argv], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) <= 131072 and len(result.stderr) <= 131072, 'SYSTEMD_OUTPUT_UNBOUNDED')
    private(binding['path'], binding['sha256'], executable=True)
    values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
    output = {key: values.get(key) for key in SERVICE_PROPERTIES}
    output.update(exitCode=result.returncode, stderrSha256=sha(result.stderr), stderrBytes=len(result.stderr))
    if argv[1] == UNIT:
        output['execStartMatchesConsumedSnapshot'] = str(LEASE_ROOT / 'activate.py') in values.get('ExecStart', '')
    return output


def collect_worker():
    global PHASE
    SAVED.clear()
    DIAGNOSIS.clear()
    PHASE = 'VERIFY_EXACT_CONSUMED_WORKER_CLAIM_AND_SOURCE_CLOSURE'
    claim_raw = private(LEASE_CLAIM)
    claim = parse(claim_raw)
    require(claim == {'schema': 'ouf.provider-r8-lease-activation-claim.v1',
        'approvalRef': LEASE_APPROVAL, 'directory': str(LEASE_ROOT), 'startAuthorized': False},
        'EXACT_RETAINED_RECOVERY_CLAIM_REQUIRED')
    SAVED[str(LEASE_CLAIM)] = claim_raw
    auth_raw = private(LEASE_ROOT / 'authorization.json')
    auth = parse(auth_raw)
    require(auth['schema'] == 'ouf.provider-r8-lease-authorization.v1'
            and auth['approvalRef'] == LEASE_APPROVAL and auth['ownerConfigurationHash'] == OWNER_HASH
            and auth['serviceUnit'] == UNIT and auth['programHashes'] == PROGRAM_HASHES
            and auth['automaticRestart'] is False and auth['enableAtBoot'] is False,
            'EXACT_CONSUMED_WORKER_AUTHORIZATION_REQUIRED')
    SAVED[str(LEASE_ROOT / 'authorization.json')] = auth_raw
    for name, expected in PROGRAM_HASHES.items():
        bound({'path': str(LEASE_ROOT / name), 'sha256': expected})
    PHASE = 'PROJECT_ONLY_RETAINED_WORKER_STATUS_AND_DENIAL_RECORDS'
    records = {}
    names = ('cycle-1.json', 'cycle-2.json', 'worker-status.json', 'worker-denial.json',
             'operator-denial.json', 'cleanup-denial.json', 'activation-receipt.json',
             'worker-activation-claim.json', 'final-worker-readback.json')
    missing = []
    for name in names:
        path = LEASE_ROOT / name
        if not os.path.lexists(path):
            records[name] = {'present': False}
            missing.append(path)
            continue
        raw = private(path)
        SAVED[str(path)] = raw
        records[name] = {'present': True, 'sha256': sha(raw), **failure_projection(parse(raw))}
    PHASE = 'READ_CURRENT_JOURNAL_AND_TWO_EXACT_SYSTEMD_UNITS_WITHOUT_LOCK'
    human = parse(private(CONTEXT / 'human-approval-binding.json'))
    require(human['approvalRef'] == APPROVAL, 'EXACT_R8_CONTEXT_REQUIRED')
    cfg = parse(bound({'path': str(CONTEXT / 'execution-configuration.json'), 'sha256': human['configurationHash']}))
    owner = parse(bound({'path': str(GUARD / 'coordinated-configuration.json'), 'sha256': OWNER_HASH}))
    journal_raw = private(owner['journalFile'])
    journal = parse(journal_raw)
    require(journal['schema'] == 'ouf.semantic-lease-coordination.v1'
            and all(journal[k] == v for k, v in owner['binding'].items())
            and journal['state'] in ('QUIESCED', 'QUIESCING', 'LEASE_READY', 'LEASE_UPDATING', 'BLOCKED')
            and type(journal['leaseAuthorized']) is bool and journal['startAuthorized'] is False,
            'EXISTING_LEASE_JOURNAL_UNPROVEN')
    services = {unit: service_read(cfg['commandBindings']['systemctl'],
        ['show', unit, '--property=' + ','.join((*SERVICE_PROPERTIES, 'ExecStart'))])
        for unit in (UNIT, 'docker.service')}
    PHASE = 'RECHECK_OBSERVATIONAL_RECORDS_WITHOUT_LOCK_OR_REPLAY'
    require(private(owner['journalFile']) == journal_raw, 'JOURNAL_CHANGED_DURING_READ')
    for path, raw in SAVED.items():
        require(private(path) == raw, 'WORKER_RECORD_CHANGED_DURING_READ')
    require(not any(os.path.lexists(path) for path in missing), 'WORKER_RECORD_APPEARED_DURING_READ')
    return {'evidenceDirectory': str(LEASE_ROOT), 'ownerConfigurationHash': OWNER_HASH,
        'claimHash': sha(claim_raw), 'authorizationHash': sha(auth_raw), 'programClosureVerified': True,
        'retainedRecords': records, 'currentServices': services,
        'currentJournal': {'state': journal['state'], 'leaseAuthorized': journal['leaseAuthorized'],
                           'startAuthorized': False, 'sha256': sha(journal_raw)},
        'executionWindowIsStartupGate': True,
        'workerAuthorityLifetime': auth.get('authorityLifetime')}


def worker_read_main():
    base = {'schema': 'ouf.provider-r8-worker-quiescence-read.v1', 'commonLockAcquired': False,
        'containerLifecycleOperations': 0, 'existingConfigurationWrites': 0, 'firewallWrites': 0,
        'privateKeysRead': 0, 'providerCalls': 0, 'dnsQueries': 0, 'signaturesIssued': 0,
        'claimReset': False, 'leaseGrantedHere': False, 'startAuthorized': False, 'applyAuthorized': False,
        'doNotRerunApply': True, 'notReleaseAcceptance': True, 'privateValuesPrinted': False,
        'readConsistencyMode': 'STABLE_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY'}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_READ_ONLY_REQUIRED')
        result = {**base, **collect_worker(), 'status': 'CONSUMED_WORKER_DIAGNOSTICS_CAPTURED', 'phase': PHASE}
        code = 0
    except Exception as error:
        result = {**base, 'status': 'READ_BLOCKED', 'phase': PHASE, 'errorType': type(error).__name__,
            'reason': str(error) if isinstance(error, ReadDenied) else 'WORKER_DIAGNOSTICS_UNPROVEN',
            'exceptionPoints': [{'file': Path(t.filename).name, 'function': t.name, 'line': t.lineno}
                for t in traceback.extract_tb(error.__traceback__)[-5:]]}
        if isinstance(error, OSError):
            result['errno'] = error.errno
            if error.filename: result['inputFileName'] = Path(error.filename).name
        result.update(DIAGNOSIS)
        code = 1
    print('OUF_R8_WORKER_QUIESCENCE_READ=' + encoded(result).decode())
    return code


if __name__ == '__main__':
    raise SystemExit(worker_read_main())
