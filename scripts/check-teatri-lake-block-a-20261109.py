#!/usr/bin/env python3
"""Two bounded read-only operator steps: prerequisites, then one Teatri run readback.

No service changes, IAM publication, application POST, database writes, or S3 PUT.
Only stdout is emitted. Credential values and object bodies stay in memory.
"""
import argparse
import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid
import posixpath

DOCKER = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent']
APPS = {
    'ingestion': ('a1bec344c54493232e52117d7e515c4f465ff0e9136eecc67dd86efa6aae9020', 'sha256:562e4c6e19d5227f00fb3159deb506da256d2245ee4a40a652b0c03865704baa'),
    'udp': ('ab8549a93e83ecf43dfb2d7d89e469405736c39bed3815fa9d15d7f8b92005e7', 'sha256:c99b53016a1928e1536ab2cdae316b48e441e7ee80f41f0b10581afc324bbdec'),
}
SEA_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
TRUST_HASH = '3c1a048732b8db22d785de8fd087459901ac6a79e16f3b904435c660b039c083'
CA_HASH = 'c1ab769d4b76565f717e2600266e11afd0f2042829f486f22fe8596f369cbccf'
ALIASES = {
    **{'OUF_UDP_S3_' + k.upper().replace('-', '_'): 'ouf.udp.lake.s3.' + k for k in ('endpoint', 'bucket', 'region', 'path-style')},
    **{'OUF_UDP_RAW_' + k.upper().replace('-', '_'): 'ouf.udp.lake.raw-' + k for k in ('retention-days', 'retention-class', 'access-label')},
    'OUF_UDP_TENANT_ID': 'ouf.udp.lake.tenant-id',
    'OUF_UDP_IAM_ENABLED': 'ouf.udp.iam.enabled', 'OUF_ING_IAM_ENABLED': 'ouf.ingestion.iam.enabled',
    'OUF_UDP_DB_URL': 'spring.datasource.url', 'OUF_UDP_DB_USER': 'spring.datasource.username',
    'PORT': 'server.port',
}
REPORT = {'mode': None, 'steps': [], 'snapshotAtomic': False, 'applicationRunDispatched': False}
CACHE = {}
OLD_WRITERS = ('d69c3f763d75f8c8f8db382fef0159a4dd5a3b99ee62ae8737a24421f4285c14', 'ab0ce29e39cfd616e5eee4bff32c0babdd04a0efe5d918dcc85e9e363d488005', '946fd69972ada2e310c32f72da27f19a04e7a2043dc330f116e8ba1c507e6e3b')


class Held(Exception):
    def __init__(self, code, observation=None):
        super().__init__(code)
        self.observation = observation


def need(ok, code):
    if not ok:
        raise Held(code)


def command(args, data=None, timeout=15):
    p = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    need(p.returncode == 0, 'COMMAND_EXIT_' + str(p.returncode))
    return p.stdout


def step(name, container, fn):
    row = {'step': name, 'container': container}
    try:
        value = fn()
        row.update(status='PASS', result=value)
    except Exception as exc:
        row.update(status='FAILED', reason=str(exc) if isinstance(exc, Held) else type(exc).__name__)
        if isinstance(exc, Held) and exc.observation is not None:
            row['observation'] = exc.observation
        value = None
    REPORT['steps'].append(row)
    print(json.dumps(row, sort_keys=True), flush=True)
    return value


def skipped(name, container, reason):
    row = {'step': name, 'container': container, 'status': 'SKIPPED', 'reason': reason}
    REPORT['steps'].append(row)
    print(json.dumps(row, sort_keys=True), flush=True)


def inspect(ref, expected=None):
    docs = json.loads(command(DOCKER + ['container', 'inspect', ref]))
    need(len(docs) == 1, 'CONTAINER_NOT_UNIQUE')
    doc = docs[0]
    need(doc['State']['Running'], 'CONTAINER_NOT_RUNNING')
    need(expected is None or doc['Image'] == expected, 'IMAGE_CHANGED')
    return doc


def flatten(obj, prefix=''):
    for key, value in obj.items():
        if isinstance(value, dict):
            yield from flatten(value, prefix + key + '.')
        else:
            yield prefix + key, value


def canon(key):
    return re.sub('[._-]', '', ALIASES.get(key, key)).lower()


def settings(doc):
    env = dict(x.split('=', 1) for x in (doc['Config'].get('Env') or []) if '=' in x)
    raw = Path('/proc', str(doc['State']['Pid']), 'cmdline').read_bytes()
    args = raw.rstrip(b'\0').decode().split('\0')
    need(args and Path(args[0]).name == 'java', 'RUNNING_PID_IS_NOT_JAVA')
    groups = [('ENV', list(env.items()))]
    groups.append(('SPRING_JSON', list(flatten(json.loads(env.get('SPRING_APPLICATION_JSON') or '{}')))))
    options = []
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'):
        options += shlex.split(env.get(key, ''))
    options += args[1:]
    pairs = []
    for i, arg in enumerate(options):
        if arg.startswith(('--', '-D')):
            if '=' in arg:
                pairs.append(arg[2:].split('=', 1))
            elif arg.startswith('--') and i + 1 < len(options):
                pairs.append((arg[2:], options[i + 1]))
    groups.append(('RUNNING_JAVA', pairs))
    values = {}
    for origin, pairs in groups:
        for key, value in pairs:
            values.setdefault(canon(key), []).append((str(value).lower() if isinstance(value, bool) else str(value), origin))
    return values, env


INGESTION_KEYS = ('ouf.ingestion.execution.enabled', 'ouf.ingestion.activation.gateway-url',
                  'ouf.ingestion.activation.token-file')
CONFIG_KEYS = ('spring.config.location', 'spring.config.additional-location', 'spring.config.import')


def properties(raw, suffix):
    """Read scalar property files, rejecting constructs whose semantics are unknown."""
    text = raw.decode('utf-8-sig')
    if suffix == '.json':
        return dict(flatten(json.loads(text)))
    if suffix in ('.yaml', '.yml'):
        result, stack = {}, []
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            need('\t' not in line and not line.lstrip().startswith(('---', '...', '-', '&', '*', '!')), 'CONFIG_YAML_UNSUPPORTED_CONSTRUCT')
            match = re.fullmatch(r'( *)([A-Za-z0-9_.-]+):(?:\s+(.*))?', line)
            need(match is not None, 'CONFIG_YAML_SCALAR_MAPPING_REQUIRED')
            indent, key, value = len(match[1]), match[2], match[3]
            while stack and stack[-1][0] >= indent:
                stack.pop()
            full = '.'.join([x[1] for x in stack] + [key])
            if value is None or not value.strip():
                stack.append((indent, key))
            else:
                value = value.strip()
                need(not value.startswith(('|', '>', '[', '{', '&', '*', '!')), 'CONFIG_YAML_NONSCALAR_UNSUPPORTED')
                if value.startswith('"'):
                    value = json.loads(value)
                elif value.startswith("'"):
                    need(value.endswith("'"), 'CONFIG_YAML_QUOTE_INVALID')
                    value = value[1:-1].replace("''", "'")
                else:
                    value = re.split(r'\s+#', value, maxsplit=1)[0]
                result[full] = value
        return result
    need(suffix == '.properties', 'CONFIG_FILE_FORMAT_UNSUPPORTED')
    # Java Properties logical lines and escaped separators; no execution/evaluation.
    lines, pending = [], ''
    for line in text.splitlines():
        line = pending + line.lstrip() if pending else line
        if (len(line) - len(line.rstrip('\\'))) % 2:
            pending = line[:-1]
        else:
            lines.append(line); pending = ''
    need(not pending, 'CONFIG_PROPERTIES_UNTERMINATED_CONTINUATION')
    def unescape(value):
        def replace(m):
            code = m[1]
            return chr(int(code[1:], 16)) if code.startswith('u') else {'t': '\t', 'n': '\n', 'r': '\r', 'f': '\f'}.get(code, code)
        need(not re.search(r'\\u(?![0-9a-fA-F]{4})', value), 'CONFIG_UNICODE_ESCAPE_INVALID')
        return re.sub(r'\\(u[0-9a-fA-F]{4}|.)', replace, value)
    result = {}
    for line in lines:
        line = line.lstrip()
        need(line not in ('#---', '!---'), 'CONFIG_MULTIDOCUMENT_UNSUPPORTED')
        if not line or line.startswith(('#', '!')):
            continue
        match = re.match(r'((?:\\.|[^\s:=])+)(?:\s*[:=]\s*|\s+)?(.*)$', line)
        need(match is not None, 'CONFIG_PROPERTY_INVALID')
        result[unescape(match[1])] = unescape(match[2])
    return result


def config_sources():
    doc, direct, env = CACHE['ingestion']
    observation = {'declarations': {}, 'files': [], 'configurationWrites': 0, 'effectiveSpringEnvironmentQueried': False}
    CACHE['ingestionConfigurationObservation'] = observation
    loaded, seen = {}, set()
    cwd = doc['Config'].get('WorkingDir') or '/'
    def substitute(value, universe):
        value = str(value)
        for _ in range(8):
            if '${' not in value:
                return value
            def resolve(match):
                key, sep, default = match[1].partition(':')
                found = setting(direct, key, universe.get(canon(key)))
                need(found is not None or sep, 'CONFIG_PLACEHOLDER_UNRESOLVED')
                return str(found if found is not None else default)
            value, count = re.subn(r'\$\{([^{}]+)\}', resolve, value)
            need(count > 0, 'CONFIG_PLACEHOLDER_UNSUPPORTED')
        raise Held('CONFIG_PLACEHOLDER_DEPTH')
    def visit(location, base=cwd, optional=False, imported_by=None):
        location = substitute(location.strip(), {k: v[0] for k, v in loaded.items()})
        if location.startswith('optional:'):
            optional, location = True, location[len('optional:'):]
        if location.startswith('file:'):
            location = location[5:]
        need(not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', location) and not any(c in location for c in ('*', '\x00', '\n', '\r')), 'CONFIG_LOCATION_SCHEME_OR_WILDCARD_UNSUPPORTED')
        path = posixpath.normpath(location if location.startswith('/') else posixpath.join(base, location))
        need(re.fullmatch(r'/[A-Za-z0-9_./-]+', path), 'CONFIG_LOCATION_PATH_INVALID')
        if location.endswith('/'):
            for ext in ('.yml', '.yaml', '.properties'):
                visit(path + '/application' + ext, optional=True, imported_by=imported_by)
            return
        if path in seen:
            return
        need(len(seen) < 24, 'CONFIG_FILE_COUNT_LIMIT')
        seen.add(path)
        row = {'containerPath': path, 'importedBy': imported_by}
        mounts = [m for m in doc['Mounts'] if path == m['Destination'] or path.startswith(m['Destination'].rstrip('/') + '/')]
        if mounts:
            m = max(mounts, key=lambda x: len(x['Destination']))
            row.update(mountDestination=m['Destination'], hostPath=m['Source'] + path[len(m['Destination']):], readOnlyMount=not m['RW'])
        observation['files'].append(row)
        try:
            raw, _ = mounted(doc, path, 262144)
        except FileNotFoundError:
            row['present'] = False
            if optional:
                return
            raise Held('REQUIRED_CONFIG_FILE_MISSING', observation) from None
        row.update(present=True, sha256=hashlib.sha256(raw).hexdigest())
        parsed = properties(raw, Path(path).suffix)
        need(not any(canon(k) in ('springprofilesactive', 'springprofilesinclude', 'springconfigactivateonprofile') or canon(k).startswith('springprofilesgroup') for k in parsed), 'CONFIG_PROFILE_SELECTION_REQUIRES_REVIEW')
        row['selectedKeys'] = [k for k in INGESTION_KEYS if any(canon(p) == canon(k) for p in parsed)]
        for key, value in parsed.items():
            loaded[canon(key)] = (str(value), path)
        for key, value in parsed.items():
            if canon(key) == canon('spring.config.import'):
                for item in re.split('[,;]', str(value)):
                    visit(item, posixpath.dirname(path), imported_by=path)
    try:
        need(not setting(direct, 'spring.profiles.active') and not setting(direct, 'spring.profiles.include') and not setting(direct, 'spring.config.name'), 'CONFIG_CUSTOM_NAME_OR_PROFILES_REQUIRE_REVIEW')
        declarations = {}
        for key in CONFIG_KEYS:
            value = setting(direct, key)
            if value:
                declarations[key] = value
                safe_parts = []
                for part in re.split('[,;]', value):
                    candidate = re.sub(r'^(?:optional:)?(?:file:)?', '', part.strip())
                    safe_parts.append(part.strip() if re.fullmatch(r'[A-Za-z0-9_./*-]+', candidate) else '<unsupported-or-unresolved-location>')
                observation['declarations'][key] = safe_parts
        need(observation['declarations'], 'NO_EXPLICIT_CONFIG_LOCATION_FOUND')
        for key in CONFIG_KEYS:
            for location in re.split('[,;]', declarations.get(key, '')):
                if location.strip():
                    visit(location)
        merged = dict(direct)
        for key, (value, origin) in loaded.items():
            if key not in direct and key in {canon(k) for k in (*INGESTION_KEYS, 'server.port')}:
                merged[key] = [(substitute(value, {k: v[0] for k, v in loaded.items()}), origin)]
        CACHE['ingestion'] = (doc, merged, env)
        observation['selectedProperties'] = {
            key: {'present': setting(merged, key) is not None,
                  'origins': sorted({origin for _, origin in merged.get(canon(key), [])})}
            for key in INGESTION_KEYS}
        enabled = setting(merged, INGESTION_KEYS[0])
        observation['executionEnabled'] = enabled if enabled in ('true', 'false') else 'ABSENT' if enabled is None else 'INVALID'
        return observation
    except Exception as exc:
        raise Held(str(exc) if isinstance(exc, Held) else type(exc).__name__, observation) from None


def setting(values, name, default=None):
    found = {v for v, _ in values.get(canon(name), [])}
    need(len(found) <= 1, 'CONFLICTING_' + re.sub('[^A-Z0-9]', '_', name.upper()))
    return next(iter(found)) if found else default


def mounted(doc, target, maximum):
    need(isinstance(target, str) and target.startswith('/') and '..' not in Path(target).parts, 'MOUNT_PATH_INVALID')
    mounts = [m for m in doc['Mounts'] if target == m['Destination'] or target.startswith(m['Destination'].rstrip('/') + '/')]
    need(bool(mounts), 'MOUNT_MISSING')
    mount = max(mounts, key=lambda m: len(m['Destination']))
    need(mount['Type'] == 'bind' and not mount['RW'], 'READ_ONLY_BIND_REQUIRED')
    path = Path('/proc', str(doc['State']['Pid']), 'root') / target.lstrip('/')
    descriptors = [os.open('/proc/' + str(doc['State']['Pid']) + '/root', os.O_PATH | os.O_DIRECTORY)]
    try:
        parts = Path(target).parts[1:]
        for part in parts[:-1]:
            descriptors.append(os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1])
        descriptors.append(fd)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'FILE_SIZE_OR_TYPE_INVALID')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns), 'FILE_CHANGED_DURING_READ')
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
    return raw, str(path)


def load_app(role):
    ref, image = APPS[role]
    doc = inspect(ref, image)
    values, env = settings(doc)
    CACHE[role] = (doc, values, env)
    return {'id': doc['Id'], 'name': doc['Name'], 'expectedImage': True, 'runningJava': True}


def old_writers():
    running = set(command(DOCKER + ['ps', '--quiet', '--no-trunc']).decode().split())
    for cid in OLD_WRITERS:
        need(cid not in running, 'PREDECESSOR_RUNNING_' + cid[:12])
    return {'knownPredecessorWritersRunning': 0, 'checked': len(OLD_WRITERS)}


def readiness(role):
    doc, values, _ = CACHE[role]
    port = setting(values, 'server.port', '8080')
    need(re.fullmatch('[0-9]{1,5}', port) and 0 < int(port) < 65536, 'PORT_INVALID')
    raw = command(['/usr/bin/nsenter', '--target', str(doc['State']['Pid']), '--net', '/usr/bin/curl', '-q', '--silent', '--show-error', '--noproxy', '*', '--connect-timeout', '3', '--max-time', '8', '--max-filesize', '65536', '--write-out', '\n%{http_code}', 'http://127.0.0.1:' + port + '/actuator/health/readiness'])
    body, code = raw.rsplit(b'\n', 1)
    need(code == b'200', 'READINESS_HTTP_' + code.decode('ascii', errors='replace')[:3])
    need(json.loads(body).get('status') == 'UP', 'READINESS_NOT_UP')
    return {'httpStatus': 200, 'status': 'UP'}


def find_peer(app, host):
    ids = command(DOCKER + ['ps', '--quiet', '--no-trunc']).decode().split()
    need(0 < len(ids) <= 64, 'CONTAINER_COUNT_OUT_OF_BOUND')
    docs = json.loads(command(DOCKER + ['container', 'inspect'] + ids))
    matches = []
    for doc in docs:
        for name, net in doc['NetworkSettings']['Networks'].items():
            aliases = (net.get('Aliases') or []) + (net.get('DNSNames') or []) + [doc['Name'].lstrip('/'), net.get('IPAddress')]
            if name in app['NetworkSettings']['Networks'] and host in aliases:
                matches.append((doc, net['IPAddress']))
    need(len(matches) == 1, 'PEER_ALIAS_NOT_UNIQUE_OR_MISSING')
    return matches[0]


def seaweed():
    udp, values, env = CACHE['udp']
    expected = {'endpoint': 'https://ouf-seaweedfs-stage:9002', 'bucket': 'ouf-udp', 'region': 'us-east-1', 'path-style': 'true'}
    for key, value in expected.items():
        need(setting(values, 'ouf.udp.lake.s3.' + key) == value, 'UDP_S3_' + key.upper().replace('-', '_') + '_MISMATCH')
    sea, address = find_peer(udp, 'ouf-seaweedfs-stage')
    need(sea['Image'] == SEA_IMAGE, 'SEAWEEDFS_IMAGE_CHANGED')
    ca, ca_path = mounted(sea, '/config/tls/ca.pem', 65536)
    need(hashlib.sha256(ca).hexdigest() == CA_HASH, 'CA_CHANGED')
    trust_path = setting(values, 'javax.net.ssl.trustStore')
    trust, _ = mounted(udp, trust_path, 4 * 1024 * 1024)
    need(hashlib.sha256(trust).hexdigest() == TRUST_HASH, 'UDP_JAVA_TRUSTSTORE_CHANGED')
    CACHE['seaweedfs'] = (sea, address, ca_path)
    return {'id': sea['Id'], 'name': sea['Name'], 'expectedImage': True, 'udpEndpointMatches': True, 'javaTruststoreMatches': True}


def tls():
    udp = CACHE['udp'][0]
    _, address, ca_path = CACHE['seaweedfs']
    command(['/usr/bin/nsenter', '--target', str(udp['State']['Pid']), '--net', '/usr/bin/openssl', 's_client', '-brief', '-connect', address + ':9002', '-servername', 'ouf-seaweedfs-stage', '-verify_hostname', 'ouf-seaweedfs-stage', '-verify_return_error', '-CAfile', ca_path], data=b'', timeout=12)
    return {'chainAndHostnameVerified': True, 'fromUdpNetworkNamespace': True, 'applicationJvmRequest': False}


def token_metadata(role, property_name):
    doc, values, _ = CACHE[role]
    target = setting(values, property_name)
    need(target is not None, 'TOKEN_PATH_NOT_RESOLVED_FROM_CONFIGURATION')
    raw, _ = mounted(doc, target, 16384)
    token = raw.decode('ascii').strip()
    need(re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token), 'TOKEN_FORMAT_INVALID')
    payload = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    now = time.time()
    need(type(claims.get('exp')) is int and now < claims['exp'], 'TOKEN_EXPIRED_OR_EXPIRY_MISSING')
    need(claims.get('nbf', 0) <= now, 'TOKEN_NOT_YET_VALID')
    CACHE[role + 'TokenSample'] = {'exp': claims['exp'], 'fingerprint': hashlib.sha256(raw).hexdigest()}
    return {'unexpiredAtRead': True, 'secondsRemaining': int(claims['exp'] - now), 'expiryEpoch': claims['exp'], 'signatureVerified': False, 'grantAuthorizationProven': False}


def ingestion_config():
    _, values, _ = CACHE['ingestion']
    enabled = setting(values, 'ouf.ingestion.execution.enabled')
    if enabled != 'true':
        raise Held('INGESTION_EXECUTION_FALSE' if enabled == 'false' else 'INGESTION_EXECUTION_ABSENT_IN_INSPECTED_SOURCES' if enabled is None else 'INGESTION_EXECUTION_INVALID',
                   {'executionEnabled': enabled, 'configurationWrites': 0, 'requiresUserDecisionBeforeAnyEnablement': True})
    uri = urlsplit(setting(values, 'ouf.ingestion.activation.gateway-url', ''))
    need(uri.scheme in ('http', 'https') and uri.hostname and not uri.username and not uri.password and not uri.query and not uri.fragment and uri.path in ('', '/'), 'GATEWAY_URL_INVALID_OR_MISSING')
    return {'executionEnabled': True, 'gateway': {'scheme': uri.scheme, 'host': uri.hostname, 'port': uri.port}, 'externalConfigurationDeclared': any(setting(values, k) for k in ('spring.config.location', 'spring.config.additional-location', 'spring.config.import')), 'effectiveSpringConfigurationProven': False}


def systemd_read(unit, names):
    raw = command(['/usr/bin/systemctl', 'show', unit, '--no-pager', '--all', '--property=' + ','.join(names)])
    return dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)


def duration(value):
    if value == '0':
        return 0.0
    factors = {'us': 0.000001, 'ms': 0.001, 's': 1, 'min': 60, 'h': 3600, 'd': 86400, 'w': 604800}
    parts = re.findall(r'([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h|d|w)', value)
    need(parts and re.sub(r'([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h|d|w)|\s+', '', value) == '', 'TIMER_DURATION_FORMAT_UNSUPPORTED')
    return sum(float(number) * factors[unit] for number, unit in parts)


def udp_renewal_units():
    service_name, timer_name = 'ouf-policy-token@udp.service', 'ouf-policy-token@udp.timer'
    service = systemd_read(service_name, ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainStatus', 'ExecMainExitTimestamp', 'TriggeredBy', 'ExecStart', 'EnvironmentFiles', 'NeedDaemonReload'))
    timer = systemd_read(timer_name, ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'Unit', 'TimersMonotonic', 'TimersCalendar', 'LastTriggerUSec', 'NextElapseUSecMonotonic', 'AccuracyUSec', 'RandomizedDelayUSec', 'NeedDaemonReload'))
    public_service = {k: v for k, v in service.items() if k not in ('ExecStart', 'EnvironmentFiles')}
    public_service['expectedProducerScriptInExecStart'] = '/opt/ouf/ops/refresh-policy-token.py' in service.get('ExecStart', '')
    result = {'service': public_service, 'timer': timer, 'expectedProducer': '/opt/ouf/ops/refresh-policy-token.py', 'serviceChanges': 0}
    CACHE['udpRenewalUnits'] = result
    try:
        need(service.get('LoadState') == timer.get('LoadState') == 'loaded', 'UDP_RENEWAL_UNITS_NOT_LOADED')
        need(timer.get('ActiveState') == 'active' and timer.get('Unit') == service_name, 'UDP_RENEWAL_TIMER_NOT_ACTIVE_OR_WRONG_UNIT')
        need(service.get('NeedDaemonReload') == timer.get('NeedDaemonReload') == 'no', 'UDP_RENEWAL_LOADED_UNITS_NOT_SETTLED')
        need(public_service['expectedProducerScriptInExecStart'], 'UDP_RENEWAL_PRODUCER_UNEXPECTED')
        intervals = re.findall(r'(On(?:UnitActive|UnitInactive|Active|Boot|Startup)USec)=([^;}]+)', timer.get('TimersMonotonic', ''))
        result['intervalsSeconds'] = {key: duration(value.strip()) for key, value in intervals}
        need(bool(result['intervalsSeconds']) or bool(timer.get('TimersCalendar')), 'UDP_TIMER_SCHEDULE_NOT_READ')
        due = duration(timer['NextElapseUSecMonotonic']) - time.monotonic()
        result['nextTriggerInSeconds'] = max(0, round(due, 3))
        result['schedulingSlackSeconds'] = duration(timer.get('AccuracyUSec', '0')) + duration(timer.get('RandomizedDelayUSec', '0'))
        return result
    except Exception as exc:
        raise Held(str(exc) if isinstance(exc, Held) else type(exc).__name__, result) from None


def udp_renewal_observation():
    units = CACHE['udpRenewalUnits']
    initial = token_metadata('udp', 'ouf.authorization.registry-token-file')
    before = dict(CACHE['udpTokenSample'])
    need(units['nextTriggerInSeconds'] + units['schedulingSlackSeconds'] < initial['secondsRemaining'], 'NEXT_UDP_RENEWAL_NOT_BEFORE_TOKEN_EXPIRY')
    doc, values, _ = CACHE['udp']
    target = setting(values, 'ouf.authorization.registry-token-file')
    mount = max((m for m in doc['Mounts'] if target == m['Destination'] or target.startswith(m['Destination'].rstrip('/') + '/')), key=lambda m: len(m['Destination']))
    result = {'containerTokenPath': target, 'hostTokenPath': mount['Source'] + target[len(mount['Destination']):], 'beforeExpiryEpoch': before['exp'], 'automaticRenewalObserved': False, 'tokenGrantRequestsByReader': 0}
    deadline = min(time.monotonic() + 360, time.monotonic() + initial['secondsRemaining'])
    last_notice = 0
    while time.monotonic() < deadline:
        time.sleep(min(5, max(0, deadline - time.monotonic())))
        try:
            sample = token_metadata('udp', 'ouf.authorization.registry-token-file')
        except Held as exc:
            if str(exc) == 'FILE_CHANGED_DURING_READ':
                continue
            raise Held(str(exc), result) from None
        after = CACHE['udpTokenSample']
        if after['fingerprint'] != before['fingerprint'] and after['exp'] > before['exp']:
            refreshed = udp_renewal_units()
            service, timer = refreshed['service'], refreshed['timer']
            if service.get('ActiveState') == 'activating':
                continue
            need(service.get('Result') == 'success' and service.get('ExecMainStatus') == '0', 'UDP_RENEWAL_SERVICE_LAST_EXECUTION_FAILED')
            need(timer.get('LastTriggerUSec') != units['timer'].get('LastTriggerUSec'), 'UDP_TOKEN_CHANGED_WITHOUT_OBSERVED_TIMER_TRIGGER')
            need(refreshed['nextTriggerInSeconds'] + refreshed['schedulingSlackSeconds'] < sample['secondsRemaining'], 'NEXT_UDP_RENEWAL_NOT_BEFORE_NEW_TOKEN_EXPIRY')
            result.update(automaticRenewalObserved=True, afterExpiryEpoch=after['exp'], secondsRemaining=sample['secondsRemaining'], tokenChangedInContainer=True, timerTriggeredDuringObservation=True, nextTriggerInSeconds=refreshed['nextTriggerInSeconds'])
            return result
        if time.monotonic() - last_notice >= 30:
            print(json.dumps({'step': 'UDP_TOKEN_RENEWAL_OBSERVATION', 'container': 'udp', 'status': 'WAITING', 'secondsRemaining': sample['secondsRemaining']}), flush=True)
            last_notice = time.monotonic()
    raise Held('UDP_RENEWAL_NOT_OBSERVED_BEFORE_EXPIRY_OR_360S_LIMIT', result)


def policy_config():
    _, values, _ = CACHE['udp']
    days = setting(values, 'ouf.udp.lake.raw-retention-days', '')
    need(days.isdigit() and 1 <= int(days) <= 36500, 'UDP_RETENTION_CONFIG_INVALID')
    need(setting(values, 'ouf.udp.iam.enabled') == 'true', 'UDP_IAM_NOT_ENABLED')
    need(setting(values, 'ouf.udp.lake.tenant-id') == 'ouf-lab', 'UDP_TENANT_CHANGED')
    label = setting(values, 'ouf.udp.lake.raw-access-label')
    need(label in ('OPEN', 'ANONYMOUS', 'PERSONAL', 'SENSITIVE', 'RESTRICTED'), 'UDP_LAKE_LABEL_INVALID')
    return {'retentionDays': int(days), 'rawAccessLabel': label, 'tenantMatches': True, 'iamEnabled': True, 'fieldMappingOpenIsSeparateFromRawLakeLabel': True}


def readback(run, source):
    need(str(uuid.UUID(run)) == run, 'CANONICAL_RUN_UUID_REQUIRED')
    need(re.fullmatch(r'teatri-seaweedfs-[a-z0-9-]{1,100}', source), 'TEATRI_SOURCE_REQUIRED')
    udp, values, env = CACHE['udp']
    jdbc = setting(values, 'spring.datasource.url', '')
    need(jdbc.startswith('jdbc:postgresql://'), 'POSTGRES_BINDING_REQUIRED')
    db = urlsplit(jdbc[5:])
    user = setting(values, 'spring.datasource.username', '')
    name = db.path.lstrip('/')
    need(re.fullmatch('[a-z_][a-z0-9_]{0,62}', user) and user != 'postgres' and re.fullmatch('[a-z_][a-z0-9_]{0,62}', name), 'ORDINARY_DB_ROLE_AND_DATABASE_REQUIRED')
    pg, _ = find_peer(udp, db.hostname)
    sql = f"""BEGIN READ ONLY;
SET LOCAL statement_timeout='8s';
SET LOCAL lock_timeout='2s';
SELECT coalesce(json_agg(q),'[]'::json) FROM (
 SELECT o.lake_object_id AS id,o.tier,o.content_hash AS hash,o.logical_size_bytes AS bytes,o.locator,o.state
 FROM ouf_udp.lake_object o
 WHERE o.tenant_id='ouf-lab' AND o.source_id='{source}'
 AND EXISTS (SELECT 1 FROM ouf_udp.lake_object_event e WHERE e.lake_object_id=o.lake_object_id AND e.correlation_id='{run}')
 ORDER BY o.tier,o.lake_object_id LIMIT 101
) q;
ROLLBACK;
"""
    try:
        raw = command(DOCKER + ['exec', '-i', '-e', 'PGOPTIONS=-c default_transaction_read_only=on', '-e', 'PGAPPNAME=ouf-teatri-lake-readback', pg['Id'], 'psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-h', '/var/run/postgresql', '-U', user, '-d', name], data=sql.encode(), timeout=12)
    except Exception as exc:
        raise Held('POSTGRES_' + pg['Id'][:12] + '_CATALOG_' + (str(exc) if isinstance(exc, Held) else type(exc).__name__)) from None
    rows = json.loads(raw)
    need(0 < len(rows) <= 100, 'NO_RUN_LAKE_OBJECTS_OR_TOO_MANY')
    need(env.get('AWS_PROFILE') == 'default' and not any(env.get(k) for k in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_WEB_IDENTITY_TOKEN_FILE')), 'EXPECTED_S3_CREDENTIAL_PROVIDER_REQUIRED')
    credential, _ = mounted(udp, env.get('AWS_SHARED_CREDENTIALS_FILE'), 16384)
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(credential.decode())
    access, secret = parser['default']['aws_access_key_id'], parser['default']['aws_secret_access_key']
    need(all(re.fullmatch('[A-Za-z0-9/+=_.-]{1,256}', v) for v in (access, secret)) and not parser['default'].get('aws_session_token'), 'CREDENTIAL_SHAPE_UNSUPPORTED')
    _, address, ca_path = CACHE['seaweedfs']
    counts = {'RAW': 0, 'NORMALIZED': 0, 'CURATED': 0}
    total = 0
    for index, obj in enumerate(rows, 1):
        need(obj['state'] == 'VERIFIED' and obj['tier'] in counts, 'OBJECT_' + str(index) + '_STATE_OR_TIER')
        need(re.fullmatch('sha256:[a-f0-9]{64}', obj['hash']), 'OBJECT_HASH_INVALID')
        key = 'lake/ouf-lab/' + obj['tier'].lower() + '/' + obj['hash'][7:]
        need(obj['locator'] == key and type(obj['bytes']) is int and 0 <= obj['bytes'] <= 1048576, 'OBJECT_' + str(index) + '_LOCATOR_OR_SIZE')
        config = '\n'.join(['silent', 'show-error', 'request = "GET"', 'url = "https://ouf-seaweedfs-stage:9002/ouf-udp/' + key + '"', 'aws-sigv4 = "aws:amz:us-east-1:s3"', 'user = "' + access + ':' + secret + '"', 'header = "X-Amz-Content-Sha256: ' + hashlib.sha256(b'').hexdigest() + '"', 'write-out = "\\n%{http_code}"']) + '\n'
        try:
            data = command(['/usr/bin/nsenter', '--target', str(udp['State']['Pid']), '--net', '/usr/bin/curl', '-q', '--config', '-', '--noproxy', '*', '--cacert', ca_path, '--resolve', 'ouf-seaweedfs-stage:9002:' + address, '--connect-timeout', '3', '--max-time', '10', '--max-filesize', '1048576'], data=config.encode(), timeout=12)
            body, code = data.rsplit(b'\n', 1)
            need(code == b'200', 'HTTP_' + code.decode('ascii', errors='replace')[:3])
            need(len(body) == obj['bytes'] and 'sha256:' + hashlib.sha256(body).hexdigest() == obj['hash'], 'BODY_HASH_OR_SIZE_MISMATCH')
        except Exception as exc:
            raise Held('SEAWEEDFS_' + CACHE['seaweedfs'][0]['Id'][:12] + '_OBJECT_' + str(index) + '_' + (str(exc) if isinstance(exc, Held) else type(exc).__name__)) from None
        counts[obj['tier']] += 1
        total += len(body)
    need(all(n == 13 for n in counts.values()), 'TEATRI_COUNTS_' + '_'.join(k + '_' + str(v) for k, v in counts.items()))
    return {'runId': run, 'sourceId': source, 'bodyMatchesByTier': counts, 'bytesRead': total, 'bodiesEmitted': False, 'catalogReadOnly': True, 'materializationProven': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('preflight', 'readback'))
    parser.add_argument('--run-id')
    parser.add_argument('--source-id')
    args = parser.parse_args()
    REPORT['mode'] = args.mode
    REPORT['observedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    need(os.geteuid() == 0, 'SUDO_REQUIRED')
    if args.mode == 'readback':
        need(args.run_id and args.source_id, 'RUN_AND_SOURCE_REQUIRED')
    for role in APPS:
        step('RUNNING_PROCESS', role + ':' + APPS[role][0][:12], lambda r=role: load_app(r))
    if args.mode == 'preflight':
        step('PREDECESSOR_WRITERS', 'historical ingestion/udp', old_writers)
        config_ok = False
        if 'ingestion' in CACHE:
            config_ok = step('INGESTION_CONFIGURATION_SOURCES', 'ingestion', config_sources) is not None
        for role in APPS:
            if role in CACHE:
                step('READINESS', role, lambda r=role: readiness(r))
        if 'ingestion' in CACHE:
            execution_ok = config_ok and step('EXECUTION_CONFIGURATION', 'ingestion', ingestion_config) is not None
            if not config_ok:
                skipped('EXECUTION_CONFIGURATION', 'ingestion', 'CONFIGURATION_SOURCE_READ_FAILED')
            if execution_ok:
                step('EXECUTION_TOKEN_EXPIRY', 'ingestion', lambda: token_metadata('ingestion', 'ouf.ingestion.activation.token-file'))
            else:
                skipped('EXECUTION_TOKEN_EXPIRY', 'ingestion', 'EXECUTION_CONFIGURATION_NOT_CONFIRMED_NO_ENABLEMENT_ATTEMPTED')
        if 'udp' in CACHE:
            step('LAKE_POLICY_CONFIGURATION', 'udp', policy_config)
            token_ok = step('POLICY_TOKEN_EXPIRY', 'udp', lambda: token_metadata('udp', 'ouf.authorization.registry-token-file')) is not None
            timer_ok = step('UDP_TOKEN_RENEWAL_UNITS', 'host:ouf-policy-token@udp', udp_renewal_units) is not None
            if token_ok and timer_ok:
                step('UDP_TOKEN_RENEWAL_OBSERVATION', 'udp / ouf-policy-token@udp.service', udp_renewal_observation)
            else:
                skipped('UDP_TOKEN_RENEWAL_OBSERVATION', 'udp', 'TOKEN_OR_RENEWAL_UNITS_NOT_CONFIRMED')
    if 'udp' in CACHE:
        step('SEAWEEDFS_ALIAS_AND_TRUST', 'udp -> ouf-seaweedfs-stage', seaweed)
    if 'seaweedfs' in CACHE:
        if args.mode == 'preflight':
            step('TLS_FROM_UDP', 'udp -> ' + CACHE['seaweedfs'][0]['Name'], tls)
        else:
            step('RUN_CATALOG_AND_BODY_READBACK', 'udp/postgres/seaweedfs', lambda: readback(args.run_id, args.source_id))
    failed = any(row['status'] != 'PASS' for row in REPORT['steps'])
    REPORT['status'] = 'FAILED' if failed else ('PRECHECKS_PASSED_NOT_F2' if args.mode == 'preflight' else 'TEATRI_LAKE_39_BODY_HASHES_MATCH')
    print(json.dumps({'summary': REPORT}, sort_keys=True))
    return 1 if failed else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status': 'FAILED', 'step': 'INPUT_OR_INITIALIZATION', 'container': 'host', 'reason': str(exc) if isinstance(exc, Held) else type(exc).__name__}), flush=True)
        sys.exit(1)
