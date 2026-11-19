"""Private implementation of fixed R3 readers; no CLI or runtime imports."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1')
WRAPPER = Path('/usr/local/sbin/ouf-semantic-admitted-v2')
PROC = Path('/proc')
ROLES = ('adapter', 'southbound')
SENSITIVE = re.compile(r'token|secret|password|authorization', re.I)
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
ADAPTER_V2 = 'ouf.semantic-docker-runtime-journal.v2'
ADAPTER_V3 = 'ouf.semantic-docker-runtime-journal.v3'
ADAPTER_FIELDS = {'schema', 'containerId', 'epoch', 'bootId', 'authorizationSha256', 'configurationHash',
                  'state', 'runtimeRoot', 'bundleHash', 'driverHash', 'generation', 'openedAt', 'failure'}
ADAPTER_STATES = ('OPENING', 'PREPARING', 'CREATING', 'CREATED', 'ADMITTED', 'STARTING', 'STARTED',
                  'DELETING', 'DELETED', 'FAILED', 'ABANDONED')
BOOT_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
HEX64 = re.compile(r'[0-9a-f]{64}')
DRIVER_CODE = re.compile(r'[A-Z0-9_]{1,80}')
RECOVERY_STATES = ('NEW', 'ATTEMPTING', 'PUBLISHING', 'ACTIVE', 'RETRY_WAIT',
                   'PAUSED_EXHAUSTED', 'BLOCKED', 'RECONCILE_REQUIRED', 'CANCELLED')
INCIDENT_SCHEMA = 'ouf.semantic-lease-recovery-incident.v1'
INCIDENT_PHASES = ('PLAN', 'DNS', 'LOCK_ACQUIRE', 'COMPILE', 'APPLY', 'READBACK', 'COMMIT', 'REVOKE')
INCIDENT_CODES = (
    'DNS_UNAVAILABLE', 'DNS_WINDOW_TOO_SHORT', 'DEPENDENCY_UNAVAILABLE', 'DEPENDENCY_TIMEOUT',
    'RATE_LIMITED', 'SERVICE_UNAVAILABLE', 'AUTHORITY_REVOKED', 'AUTHORITY_EXPIRED',
    'GENERATION_CHANGED', 'CONFIGURATION_DRIFT', 'INTEGRITY_UNPROVEN', 'PERMANENT_FAILURE',
    'COMMON_LOCK_TIMEOUT', 'NFT_ATTEMPT_DEADLINE_UNPROVEN', 'RECOVERY_SCOPE_TIME_EXHAUSTED',
    'RETRY_BUDGET_EXHAUSTED', 'LOCAL_AUTHORITY_UNPROVEN', 'LOCAL_STATE_UNPROVEN',
    'CLOCK_REGRESSION', 'GENERATION_RECONCILIATION_REQUIRED',
    'WORKER_INVOCATION_RECONCILIATION_REQUIRED', 'INTERRUPTED_ATTEMPT_REQUIRES_RECONCILIATION',
    'PUBLICATION_DEADLINE_UNPROVEN', 'PUBLICATION_OUTCOME_AMBIGUOUS', 'DURABLE_RESULT_UNPROVEN',
    'SAFE_PAUSE_UNPROVEN', 'UNCLASSIFIED_FAILURE',
)
INCIDENT_FIELDS = (
    'schema', 'scopeRef', 'authorizationSequence', 'epochs', 'incidentCount',
    'failedAt', 'pausedAt', 'resumedAt', 'nextRetryAt', 'phase', 'code',
    'revocation', 'stateAtFailure', 'leaseRemainingMs', 'lockWaitMs', 'deadlineMonotonic',
)
RECOVERY_LIMIT = 65536


def positive(value):
    if not re.fullmatch(r'[0-9]+', value, re.ASCII) or int(value) < 1:
        raise ValueError('INTEGER_REQUIRED')
    return int(value)


def arguments(args, roles, epoch=False):
    if len(args) != (2 if epoch else 1) or args[0] not in roles:
        raise ValueError('ARGUMENTS_INVALID')
    return (args[0], positive(args[1])) if epoch else args[0]


def read(path):
    # Never follow a final symlink to a private file or device.
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('DOCUMENT_TOO_LARGE')
    return raw


def document(path):
    return json.loads(read(path))


def bound(binding):
    raw = read(binding['path'])
    if hashlib.sha256(raw).hexdigest() != binding['sha256']:
        raise ValueError('BINDING_DRIFT')
    return json.loads(raw)


def configuration():
    # Same canonical root / numeric-version selection as operate.observe.
    text = read(WRAPPER).decode('ascii')
    match = re.fullmatch(r'#!/bin/sh\nexec (/[^\s]+) -I -B (/[^\s]+)/source/([^\s]+) --configuration \2/runtime-configuration.json "\$@"\n', text)
    if not match:
        raise ValueError('WRAPPER_INVALID')
    if match[3] != 'tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py':
        raise ValueError('WRAPPER_RUNTIME_INVALID')
    base = Path(match[2])
    relative = base.relative_to(ROOT)
    if relative.parts and not (len(relative.parts) == 2 and relative.parts[0] == 'versions'
                               and re.fullmatch(r'[2-9]|[1-9][0-9]+', relative.parts[1])):
        raise ValueError('WRAPPER_ROOT_INVALID')
    cfg = document(base / 'runtime-configuration.json')
    if cfg['registryRoot'] != str(ROOT / 'registry') or cfg['operation']['authorizationRoot'] != str(ROOT / 'authorization'):
        raise ValueError('ROOT_DRIFT')
    return cfg


def candidates(cfg):
    result = {}
    for cid, item in cfg['candidates'].items():
        if not re.fullmatch(r'[0-9a-f]{64}', cid) or item['role'] not in ROLES or item['role'] in result:
            raise ValueError('CANDIDATE_INVALID')
        result[item['role']] = cid
    if set(result) != set(ROLES):
        raise ValueError('ROLES_INVALID')
    return result


def scalar(value):
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, str) and len(value) <= 160 and re.fullmatch(r'[A-Za-z0-9_.:-]+', value) and not SENSITIVE.search(value):
        return value
    return '[REDACTED]'


def fields(value, names):
    return {k: scalar(value[k]) for k in names if k in value and not isinstance(value[k], (dict, list))}


def adapter_journal(raw, cid, epoch):
    """Check the record identity and closed shape before diagnostic projection."""
    def unique(pairs):
        row = {}
        for key, value in pairs:
            if key in row:
                raise ValueError('DUPLICATE_EPOCH_KEY')
            row[key] = value
        return row

    if len(raw) > 65536:
        raise ValueError('EPOCH_DOCUMENT_TOO_LARGE')
    row = json.loads(raw, object_pairs_hook=unique)
    if (type(row) is not dict or row.get('schema') not in (ADAPTER_V2, ADAPTER_V3)
            or row.get('containerId') != cid or type(row.get('epoch')) is not int or row['epoch'] != epoch):
        raise ValueError('EPOCH_IDENTITY_INVALID')
    expected = ADAPTER_FIELDS | {'driverDenial'} if row['schema'] == ADAPTER_V3 else ADAPTER_FIELDS
    if set(row) != expected:
        raise ValueError('EPOCH_FIELDS_INVALID')
    if (type(row['bootId']) is not str or not BOOT_ID.fullmatch(row['bootId'])
            or row['state'] not in ADAPTER_STATES or type(row['openedAt']) is not int or row['openedAt'] <= 0):
        raise ValueError('EPOCH_FIELDS_INVALID')
    for name in ('authorizationSha256', 'configurationHash', 'bundleHash', 'driverHash'):
        value = row[name]
        if value is None and name in ('bundleHash', 'driverHash'):
            continue
        if type(value) is not str or not HEX64.fullmatch(value):
            raise ValueError('EPOCH_HASH_INVALID')
    root = row['runtimeRoot']
    if root is not None and (type(root) is not str or not root.startswith('/')):
        raise ValueError('EPOCH_RUNTIME_ROOT_INVALID')
    generation = row['generation']
    if generation is None:
        if row['state'] == 'STARTED':
            raise ValueError('EPOCH_GENERATION_INVALID')
    elif (type(generation) is not dict or set(generation) != {'pid', 'startTicks'}
          or type(generation['pid']) is not int or not 1 < generation['pid'] < 2**22
          or type(generation['startTicks']) is not int or generation['startTicks'] <= 0):
        raise ValueError('EPOCH_GENERATION_INVALID')
    failure = row['failure']
    if row['state'] == 'FAILED':
        if type(failure) is not str or not DRIVER_CODE.fullmatch(failure):
            raise ValueError('EPOCH_FAILURE_INVALID')
    elif failure is not None:
        raise ValueError('EPOCH_FAILURE_INVALID')
    return row


def driver_denial_fields(row):
    if row['schema'] == ADAPTER_V2:
        return {}
    denial = row['driverDenial']
    if denial is None:
        return {'driverDenial': None}
    if (row['state'] != 'FAILED' or type(denial) is not dict or set(denial) != {'phase', 'code'}
            or denial['phase'] not in ('hook', 'start') or type(denial['code']) is not str
            or not DRIVER_CODE.fullmatch(denial['code'])):
        raise ValueError('EPOCH_DRIVER_DENIAL_INVALID')
    return {'driverDenial': {'phase': denial['phase'], 'code': denial['code']}}


def recovery_integer(value, minimum=1):
    return type(value) is int and minimum <= value < 2**63


def recovery_time(value):
    return type(value) in (int, float) and 0 <= value < 2**63


TIMING_SCHEMA = 'ouf.lease-renewal-timing.v1'
# Each event begins with a fixed tag and a monotonic timestamp in seconds.
TIMING_EVENTS = {
    'dnsSend': 'resolver flow kind depth attempt signed signed',
    'dnsRecv': 'resolver flow kind depth attempt signed signed bool',
    'dnsTimeout': 'resolver flow kind depth attempt signed signed',
    'dnsTcpFallback': 'resolver flow kind depth attempt signed signed',
    'dnsTcpSend': 'resolver flow kind depth attempt signed signed',
    'dnsTcpRecv': 'resolver flow kind depth attempt signed signed',
    'tick': '', 'plan': 'duration', 'wait': 'duration', 'wake': '', 'renew': '',
    'deny': '', 'guardEnd': '', 'dnsStart': '', 'dnsRound': '', 'dnsEnd': 'count',
    'ttl': 'flow ttl bool', 'compile': '', 'timeout': 'flow lease',
    'lockStart': 'site', 'acquired': 'site', 'released': 'site',
    'apply': '', 'applyEnd': 'bool', 'dump': 'family', 'dumpEnd': 'family bool',
    'verify': '', 'verifyEnd': '', 'ready': '', 'readyEnd': '',
    'sampleBefore': 'margin', 'expires': 'flow lease lease', 'sampleAfter': 'signed time',
    'attemptLimit': 'time', 'planLimit': 'time', 'leaseLimit': 'time',
}
TIMING_MAX_EVENTS = 1024
TIMING_LIMITS = {'resolver': 7, 'kind': 1, 'depth': 8, 'attempt': 3, 'flow': 31, 'family': 1, 'site': 6, 'ttl': 2**31-1, 'lease': 3600,
                 'margin': 300, 'count': 2**31-1}
TIMING_MODULES = ('adaptive_supervisor', 'continuous_supervisor', 'resilient_lease_adapter',
                  'dns', 'nft_seconds_backend', 'deadline_backend', 'readback_margin_compiler',
                  'bounded_recovery', 'lease_recovery_budget', 'semantic_common_lock_v2',
                  'semantic_provider_lease_coordination', 'lease_supervisor', 'recovery_journal')


def timing_scalar(kind, value):
    if kind == 'bool':
        return type(value) is bool
    if kind in ('time', 'duration', 'signed'):
        low = -2**63 if kind == 'signed' else 0
        return type(value) in (int, float) and low <= value < 2**63
    lower = 1 if kind == 'attempt' else 0
    return type(value) is int and lower <= value <= TIMING_LIMITS[kind]


def valid_timing_frame(frame):
    if (type(frame) is not dict or set(frame) != {'sequence', 'events', 'truncated'}
            or type(frame['sequence']) is not int or not 0 < frame['sequence'] < 2**63
            or type(frame['truncated']) is not bool or type(frame['events']) is not list
            or len(frame['events']) > TIMING_MAX_EVENTS):
        return False
    return all(map(valid_timing_event, frame['events']))


def valid_timing_event(event):
    if (type(event) is not list or len(event) < 2 or type(event[0]) is not str
            or event[0] not in TIMING_EVENTS or not timing_scalar('time', event[1])):
        return False
    kinds = TIMING_EVENTS[event[0]].split()
    return len(event) == len(kinds) + 2 and all(
        timing_scalar(kind, value) for kind, value in zip(kinds, event[2:]))


def valid_timing(value):
    if (type(value) is not dict or set(value) != {'schema', 'branch', 'previous', 'current'}
            or value['schema'] != TIMING_SCHEMA or not valid_timing_frame(value['current'])):
        return False
    branch, previous = value['branch'], value['previous']
    return (type(branch) is list and len(branch) == 2
            and type(branch[0]) is int and 0 <= branch[0] < len(TIMING_MODULES)
            and type(branch[1]) is int and 0 < branch[1] <= 65535
            and (previous is None or valid_timing_frame(previous)
                 and previous['sequence'] < value['current']['sequence']))


def recovery_incident(value, scope_ref):
    if value is None:
        return None
    if (type(value) is not dict or set(value) not in (set(INCIDENT_FIELDS), set(INCIDENT_FIELDS) | {'timing'})
            or ('timing' in value and not valid_timing(value['timing']))
            or value['schema'] != INCIDENT_SCHEMA or value['scopeRef'] != scope_ref
            or not recovery_integer(value['authorizationSequence']) or not recovery_integer(value['incidentCount'])
            or type(value['epochs']) is not dict or set(value['epochs']) != set(ROLES)
            or not all(map(recovery_integer, value['epochs'].values()))
            or value['phase'] not in INCIDENT_PHASES or value['code'] not in INCIDENT_CODES
            or value['stateAtFailure'] not in RECOVERY_STATES or not recovery_time(value['failedAt'])
            or value['revocation'] not in ('VERIFIED', 'UNPROVEN')
            or (value['pausedAt'] is not None) != (value['revocation'] == 'VERIFIED')
            or not all(value[key] is None or recovery_time(value[key])
                       for key in ('pausedAt', 'resumedAt', 'nextRetryAt', 'deadlineMonotonic'))
            or not all(value[key] is None or recovery_integer(value[key], 0)
                       for key in ('leaseRemainingMs', 'lockWaitMs'))):
        raise ValueError('RECOVERY_INCIDENT_INVALID')
    return {**{key: value[key] for key in INCIDENT_FIELDS}, 'timing': value.get('timing')}


def read_recovery(scope_dir):
    """Open every component relative to a verified directory descriptor."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    directory_flags = flags | os.O_DIRECTORY
    directory = os.open('/', directory_flags)
    try:
        for name in scope_dir.parts[1:]:
            child = os.open(name, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('RECOVERY_DIRECTORY_CUSTODY_INVALID')
        if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('RECOVERY_SCOPE_CUSTODY_INVALID')
        fd = os.open('recovery.json', flags, dir_fd=directory)
        try:
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                    or not 0 < info.st_size <= RECOVERY_LIMIT):
                raise ValueError('RECOVERY_FILE_CUSTODY_INVALID')
            raw = os.read(fd, RECOVERY_LIMIT + 1)
            if (len(raw) != info.st_size or identity(info) != identity(os.fstat(fd))
                    or identity(info) != identity(os.stat('recovery.json', dir_fd=directory, follow_symlinks=False))):
                raise ValueError('RECOVERY_FILE_CHANGED')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def lease_recovery(sup, status, configuration_sha):
    scope = status.get('recoveryScope')
    if scope is None:
        return None
    root = ROOT / 'supervisor/state/recovery'
    if (type(scope) is not str or not re.fullmatch(r'[0-9a-f]{48}', scope)
            or sup.get('recoveryJournalRoot') != str(root)):
        raise ValueError('RECOVERY_SCOPE_INVALID')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('DUPLICATE_RECOVERY_KEY')
            result[key] = value
        return result

    selector = json.dumps({'configuration': configuration_sha, 'invocation': scope},
                          sort_keys=True, separators=(',', ':')).encode('ascii')
    scope_ref = hashlib.sha256(selector).hexdigest()
    try:
        row = json.loads(read_recovery(root / scope), object_pairs_hook=unique)
    except RecursionError:
        raise ValueError('RECOVERY_CHECKPOINT_INVALID') from None
    if (type(row) is not dict or row.get('schema') != 'ouf.bounded-recovery.v1'
            or row.get('contextRef') != scope_ref or row.get('state') not in RECOVERY_STATES
            or not recovery_integer(row.get('attempts'), 0)):
        raise ValueError('RECOVERY_CHECKPOINT_INVALID')
    next_retry = row.get('nextWall')
    if row['state'] == 'RETRY_WAIT' and not recovery_time(next_retry):
        raise ValueError('RECOVERY_RETRY_INVALID')
    return {'scopeRef': scope_ref, 'state': row['state'], 'attempts': row['attempts'],
            'nextRetryAt': next_retry if row['state'] == 'RETRY_WAIT' else None,
            'lastIncident': recovery_incident(row.get('lastIncident'), scope_ref)}


def emit(**row):
    print(json.dumps(row, sort_keys=True), flush=True)


def command(argv, timeout=10):
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=timeout, env=ENV).stdout


def epoch_base(cfg, cid, number):
    return Path(cfg['registryRoot']) / cid / 'epochs' / str(number)


def ticks(pid):
    positive(str(pid))
    text = read(PROC / str(pid) / 'stat')
    return int(text[text.rindex(b')') + 2:].split()[19])


def entry(main):
    try:
        return main()
    except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError) as exc:
        # Exception messages may contain private document content.
        emit(error=type(exc).__name__)
        return 2
