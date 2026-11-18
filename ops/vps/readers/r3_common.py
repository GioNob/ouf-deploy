"""Private implementation of fixed R3 readers; no CLI or runtime imports."""
import hashlib
import json
import os
from pathlib import Path
import re
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
