#!/usr/bin/env python3
"""Restore only the existing Semantic token producer after exact binding checks."""
import ast
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import time
from urllib.parse import urlsplit

SERVICE = 'ouf-policy-token@semantic.service'
TIMER = 'ouf-policy-token@semantic.timer'
PRODUCER = '/opt/ouf/ops/refresh-policy-token.py'
PRODUCER_SHA = '728b4c44d0e24b3c3bfc31769346c0c05752e870e93c096fac1c2897250e5c79'
KEYS = {'OUF_POLICY_TOKEN_' + name for name in
        ('CLIENT_ID', 'ENDPOINT', 'REQUIRED_SCOPE', 'RUNTIME_DIR', 'RUNTIME_GID', 'SECRET_FILE')}
COMMON = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState')
SERVICE_PROPERTIES = COMMON + ('Type', 'User', 'ExecStart', 'EnvironmentFiles', 'Environment',
    'UnsetEnvironment', 'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths',
    'TemporaryFileSystem', 'ExecStartPre', 'ExecStartPost', 'ExecCondition', 'Restart',
    'TimeoutStartUSec', 'Result', 'ExecMainStatus')
TIMER_PROPERTIES = COMMON + ('Unit', 'TimersMonotonic', 'TimersCalendar')
ATTEMPTS = Path('/var/lib/ouf-storage-migration/semantic-policy-renewals')

def need(ok, code):
    if not ok:
        raise RuntimeError(code)

def command(*args, timeout=15):
    return subprocess.run(('/usr/bin/systemctl', '--no-pager', *args),
                          capture_output=True, timeout=timeout)

def unit_read(unit, properties):
    result = command('--all', 'show', unit, '--property=' + ','.join(properties))
    need(result.returncode == 0 and len(result.stdout) <= 131072, 'UNIT_METADATA_READ_FAILED')
    fields = {}
    for line in result.stdout.decode().splitlines():
        key, sep, value = line.partition('=')
        if sep:
            need(key in properties and (key not in fields or key in ('TimersMonotonic', 'TimersCalendar')),
                 'UNIT_PROPERTY_MULTIPLICITY_CHANGED')
            fields[key] = (fields[key] + ' ' + value).strip() if key in fields else value
    need(all(key in fields for key in COMMON), 'UNIT_STATE_FIELDS_MISSING')
    return fields

def public_unit(fields):
    keys = COMMON + ('Type', 'User', 'Restart', 'Result', 'ExecMainStatus')
    return {key: value for key, value in fields.items() if key in keys
            and re.fullmatch('[A-Za-z0-9_-]{0,80}', value)}

def read_file(path, maximum, private=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_SOURCE_PATH_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
             and 0 < before.st_size <= maximum, 'ROOT_OWNED_BOUNDED_SOURCE_REQUIRED')
        if private:
            need(not before.st_mode & 0o077, 'PRIVATE_CONFIGURATION_REQUIRED')
        raw = os.read(fd, maximum + 1)
        frame = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd))
             == frame(path.lstat()), 'SOURCE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)

def parse_config(raw):
    result = {}
    for line in raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
        need(match, 'CONFIGURATION_ASSIGNMENT_INVALID')
        key, value = match.groups()
        need(key in KEYS and key not in result, 'CONFIGURATION_KEY_SET_CHANGED')
        value = value.strip()
        if value.startswith(('"', "'")):
            need(len(value) >= 2 and value[-1] == value[0], 'CONFIGURATION_QUOTE_INVALID')
            value = value[1:-1]
        need(not any(c in value for c in ('\\', '"', "'", '\x00', '\r', '\n')),
             'CONFIGURATION_ESCAPE_UNSUPPORTED')
        result[key] = value.strip()
    need(set(result) == KEYS and all(v for k, v in result.items()
         if k != 'OUF_POLICY_TOKEN_REQUIRED_SCOPE'), 'CONFIGURATION_FIELDS_REQUIRED')
    return result

def output_member(raw):
    # Same AST binding used in the historical output-correspondence reader.
    tree = ast.parse(raw)
    config = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'config')
    refresh = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'refresh')
    assign = next(n for n in config.body if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) == 'runtime_dir')
    need(ast.unparse(assign.value) == "Path(required('OUF_POLICY_TOKEN_RUNTIME_DIR'))", 'OUTPUT_DIRECTORY_SOURCE_CHANGED')
    returned = next(n.value for n in config.body if isinstance(n, ast.Return))
    need(isinstance(returned, ast.Dict), 'PRODUCER_CONFIG_RETURN_CHANGED')
    key = next(k.value for k, v in zip(returned.keys, returned.values)
               if isinstance(k, ast.Constant) and isinstance(v, ast.Name) and v.id == 'runtime_dir')
    directory = next(n for n in refresh.body if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) == 'directory')
    need(isinstance(directory.value, ast.Subscript) and ast.unparse(directory.value.value) == 'cfg'
         and isinstance(directory.value.slice, ast.Constant) and directory.value.slice.value == key,
         'OUTPUT_DIRECTORY_BINDING_CHANGED')
    calls = [n for n in ast.walk(refresh) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'os.replace']
    need(len(calls) == 1 and len(calls[0].args) == 2, 'ONE_ATOMIC_PUBLICATION_REQUIRED')
    target = calls[0].args[1]
    need(isinstance(target, ast.BinOp) and isinstance(target.op, ast.Div)
         and ast.unparse(target.left) == 'directory' and isinstance(target.right, ast.Constant),
         'OUTPUT_MEMBER_BINDING_CHANGED')
    member = target.right.value
    need(type(member) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}', member)
         and member not in ('.', '..'), 'OUTPUT_MEMBER_INVALID')
    return member

def producer_route(fields):
    need(fields['LoadState'] == 'loaded' and fields['UnitFileState'] not in ('masked', 'masked-runtime'),
         'EXISTING_UNMASKED_SERVICE_REQUIRED')
    need(fields.get('Type') == 'oneshot' and fields.get('User') == 'root'
         and fields.get('Restart') == 'no', 'EXISTING_ROOT_ONESHOT_REQUIRED')
    for key in ('UnsetEnvironment', 'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths',
                'TemporaryFileSystem', 'ExecStartPre', 'ExecStartPost', 'ExecCondition'):
        need(key in fields and not fields[key], 'UNSUPPORTED_SERVICE_OVERRIDE_' + key.upper())
    line = fields.get('ExecStart', '')
    executable = re.search(r'\bpath=([^ ;}]+)', line)
    argv = re.search(r'argv\[\]=(.*?);', line)
    need(line.count('argv[]=') == 1 and executable and executable.group(1) == '/usr/bin/python3'
         and argv, 'DIRECT_KNOWN_PYTHON_PRODUCER_REQUIRED')
    args = shlex.split(argv.group(1))
    need(args and args[0] == '/usr/bin/python3', 'PYTHON_ARGUMENTS_INVALID')
    args = args[1:]
    while args and args[0] in ('-I', '-B', '-u', '-E', '-s', '-S'):
        args = args[1:]
    need(args in ([PRODUCER], [PRODUCER, 'semantic']), 'PRODUCER_ARGUMENTS_CHANGED')
    match = re.fullmatch(r'(/[A-Za-z0-9_./@:-]+) \(ignore_errors=no\)', fields.get('EnvironmentFiles', ''))
    need(match, 'ONE_REQUIRED_ENVIRONMENT_FILE_EXPECTED')
    return Path(match.group(1))

def timer_guard(fields):
    need(fields['LoadState'] == 'loaded' and fields['UnitFileState'] not in ('masked', 'masked-runtime')
         and fields.get('Unit') == SERVICE, 'EXISTING_SEMANTIC_TIMER_REQUIRED')
    need(not fields.get('TimersCalendar') and re.search(r'OnUnitActiveUSec=1min\s*;',
         fields.get('TimersMonotonic', '')), 'EXISTING_ONE_MINUTE_RENEWAL_REQUIRED')

def jwt_claims(token):
    part = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))

def verify_binding(doc, values, cfg, member, claims, token_mount):
    target = values['ouf.authorization.registry-token-file']
    mounts = sorted([m for m in doc['Mounts'] if target.startswith(m['Destination'].rstrip('/') + '/')],
                    key=lambda m: len(m['Destination']), reverse=True)
    need(mounts and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is False,
         'ROTATING_TOKEN_DIRECTORY_MOUNT_REQUIRED')
    mount = mounts[0]
    source = Path(mount['Source'] + target[len(mount['Destination']):])
    directory = Path(cfg['OUF_POLICY_TOKEN_RUNTIME_DIR'])
    need(directory.is_absolute() and '..' not in directory.parts and directory / member == source,
         'PRODUCER_OUTPUT_NOT_CURRENT_MOUNTED_TOKEN')
    need(cfg['OUF_POLICY_TOKEN_RUNTIME_GID'] == str(token_mount['gid']) == '10001'
         and token_mount['sameFileAsCurrentHostSource'], 'CURRENT_TOKEN_FILE_OR_GROUP_DIFFERS')
    issuer = values['ouf.iam.issuer'].rstrip('/')
    expected = issuer + '/protocol/openid-connect/token'
    url = urlsplit(cfg['OUF_POLICY_TOKEN_ENDPOINT'])
    need(cfg['OUF_POLICY_TOKEN_ENDPOINT'] == expected and url.scheme == 'https'
         and url.hostname and not url.username and not url.password and not url.query and not url.fragment,
         'TOKEN_ENDPOINT_NOT_CURRENT_ISSUER')
    need(claims.get('iss', '').rstrip('/') == issuer
         and cfg['OUF_POLICY_TOKEN_CLIENT_ID'] in (claims.get('azp'), claims.get('client_id')),
         'PRODUCER_IDENTITY_NOT_MOUNTED_TOKEN_IDENTITY')
    need(set(cfg['OUF_POLICY_TOKEN_REQUIRED_SCOPE'].split()) <= set(claims.get('scope', '').split()),
         'PRODUCER_REQUESTED_SCOPE_DIFFERS_FROM_RETAINED_TOKEN')

def claim_attempt(doc, raw):
    ATTEMPTS.mkdir(mode=0o700, exist_ok=True)
    need(ATTEMPTS.is_dir() and not ATTEMPTS.is_symlink() and ATTEMPTS.stat().st_uid == 0
         and not ATTEMPTS.stat().st_mode & 0o077, 'PRIVATE_ATTEMPT_DIRECTORY_REQUIRED')
    name = hashlib.sha256(doc['Id'].encode() + b'\0' + raw).hexdigest() + '.json'
    path = ATTEMPTS / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'schema': 'ouf.semantic-token-renewal-attempt.v1', 'service': SERVICE,
                   'containerId': doc['Id'], 'automaticManualRetry': False}, stream)
        stream.flush(); os.fsync(stream.fileno())
    directory_fd = os.open(ATTEMPTS, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return str(path)

def unchanged(doc, runtime):
    current = runtime['inspect'](doc['Id'])[doc['Id']]
    need(all(current[key] == doc[key] for key in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings'))
         and all(current['State'][key] == doc['State'][key] for key in ('Pid', 'StartedAt', 'Running', 'Restarting')),
         'SEMANTIC_RUNTIME_CHANGED')

def execute(report, runtime, reader):
    check = {}
    bound, docs = runtime['retained_semantic'](check)
    doc = docs[bound['semantic']]
    need(runtime['semantic_process'](doc)['processKind'] == 'APPLICATION_RUNNING', 'SEMANTIC_JAVA_REQUIRED')
    values, _ = reader['declarations'](doc)
    raw, mount = reader['mounted_read'](doc, values['ouf.authorization.registry-token-file'], 65536)
    token, before = reader['token_metadata'](raw, time.time())
    report['tokenBefore'] = before
    service = unit_read(SERVICE, SERVICE_PROPERTIES)
    timer = unit_read(TIMER, TIMER_PROPERTIES)
    report.update(serviceBefore=public_unit(service), timerBefore=public_unit(timer))
    config_path = producer_route(service)
    timer_guard(timer)
    source = read_file(PRODUCER, 131072)
    report['producerSourceSha256'] = hashlib.sha256(source).hexdigest()
    report['producerMatchesHistoricallyReadSource'] = report['producerSourceSha256'] == PRODUCER_SHA
    need(report['producerMatchesHistoricallyReadSource'], 'PRODUCER_SOURCE_CHANGED')
    config_raw = read_file(config_path, 65536, private=True)
    cfg = parse_config(config_raw)
    for assignment in shlex.split(service.get('Environment', '')):
        key, sep, value = assignment.partition('=')
        need(sep and (key not in KEYS or value == cfg[key]), 'CONFLICTING_INLINE_PRODUCER_ENVIRONMENT')
    verify_binding(doc, values, cfg, output_member(source), jwt_claims(token), mount)
    report['existingProducerMatchesCurrentTokenBinding'] = True
    url = reader['endpoint'](values['ouf.authorization.registry-url'])
    delay = int(values.get('ouf.authorization.refresh-seconds') or '30')
    need(1 <= delay <= 60, 'REFRESH_WAIT_OUT_OF_RANGE')
    need(service['ActiveState'] in ('inactive', 'failed') and service['SubState'] not in ('start', 'stop'),
         'TOKEN_PRODUCER_ALREADY_ACTIVE')
    need(read_file(PRODUCER, 131072) == source and read_file(config_path, 65536, private=True) == config_raw,
         'PRODUCER_CHANGED_BEFORE_RENEWAL')
    need(producer_route(unit_read(SERVICE, SERVICE_PROPERTIES)) == config_path, 'SERVICE_ROUTE_CHANGED')
    unchanged(doc, runtime)
    if before['expiryEpoch'] <= time.time() + 60:
        report['privateAttemptFile'] = claim_attempt(doc, raw)
        report['serviceStartDispatched'] = True
        result = command('start', SERVICE, timeout=120)
        report['serviceStartExitCode'] = result.returncode
        report['serviceAfter'] = public_unit(unit_read(SERVICE, SERVICE_PROPERTIES))
        need(result.returncode == 0, 'EXISTING_TOKEN_PRODUCER_FAILED')
    else:
        report['freshTokenAlreadyPresent'] = True
    new_raw, new_mount = reader['mounted_read'](doc, values['ouf.authorization.registry-token-file'], 65536)
    new_token, after = reader['token_metadata'](new_raw, time.time())
    report['tokenAfter'] = after
    report['mountedTokenChanged'] = new_raw != raw
    need(after['expiryEpoch'] > time.time() + 60 and not after['notYetValidAtRead']
         and new_mount['sameFileAsCurrentHostSource'], 'FRESH_MOUNTED_TOKEN_NOT_PROVEN')
    verify_binding(doc, values, cfg, output_member(source), jwt_claims(new_token), new_mount)
    report['policyGetAttempts'] = 1
    report['policyGet'] = reader['policy_get'](url, new_token)
    need(report['policyGet'].get('httpStatus') == 200 and report['policyGet'].get('activePolicyResponseRead'),
         'RENEWED_TOKEN_POLICY_READ_NOT_SUCCESSFUL')
    need(read_file(PRODUCER, 131072) == source and read_file(config_path, 65536, private=True) == config_raw,
         'PRODUCER_CHANGED_BEFORE_TIMER_ENABLE')
    need(producer_route(unit_read(SERVICE, SERVICE_PROPERTIES)) == config_path, 'SERVICE_ROUTE_CHANGED')
    unchanged(doc, runtime)
    timer_guard(unit_read(TIMER, TIMER_PROPERTIES))
    report['timerEnableDispatched'] = True
    result = command('enable', '--now', TIMER, timeout=30)
    need(result.returncode == 0, 'EXISTING_TOKEN_TIMER_ENABLE_FAILED')
    report['timerAfter'] = public_unit(unit_read(TIMER, TIMER_PROPERTIES))
    need(report['timerAfter'].get('ActiveState') == 'active'
         and report['timerAfter'].get('UnitFileState') == 'enabled', 'TIMER_ENABLED_ACTIVE_NOT_PROVEN')
    time.sleep(delay + 2)
    report['normalPolicyRefreshWaitSeconds'] = delay + 2
    unchanged(doc, runtime)
    report.update(status='SEMANTIC_TOKEN_RENEWED_POLICY_GET_OK_TIMER_ACTIVE',
                  semanticRuntimeUnchanged=True, automaticRenewalCycleProven=False,
                  applicationLoadedPolicyProven=False)

def main():
    report = {'schema': 'ouf.semantic-token-renewal.v1', 'status': 'HELD',
              'credentialValuesEmitted': False, 'applicationConfigurationChanged': False,
              'permissionChanges': 0, 'serviceStops': 0, 'serviceStartDispatched': False,
              'timerEnableDispatched': False, 'businessRequestsIssued': 0,
              'databaseQueriesIssuedByScript': 0, 's3Requests': 0, 'policyGetAttempts': 0,
              'existingProducerMayRequestTokens': True, 'applicationLoadedPolicyProven': False}
    signal.alarm(210)
    try:
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        with open('/run/lock/ouf-runtime-e2e.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            execute(report, globals()['RUNTIME_READER'], globals()['POLICY_READER'])
    except Exception as exc:
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z0-9_]{1,120}', str(exc)) else type(exc).__name__
    report['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'SEMANTIC_TOKEN_RENEWED_POLICY_GET_OK_TIMER_ACTIVE' else 1

if __name__ == '__main__':
    raise SystemExit(main())
