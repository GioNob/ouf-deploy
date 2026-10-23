"""Installation-bound historical readiness log classification; GET only, no replay."""
import collections
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import sys
from urllib.parse import urlencode


class Stop(Exception):
    pass


def require(value, code):
    if not value:
        raise Stop(code)


def private_json(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'PRIVATE_PATH_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
                and s.st_size <= 8_388_608, 'ROOT_OWNED_BOUNDED_METADATA_REQUIRED')
        raw = os.read(fd, 8_388_609)
        require(len(raw) == s.st_size, 'METADATA_CHANGED')
        return json.loads(raw), raw
    finally:
        os.close(fd)


def unframe(raw, multiplexed):
    if not multiplexed:
        return raw
    result = bytearray()
    offset = 0
    while offset < len(raw):
        require(len(raw) - offset >= 8, 'INCOMPLETE_LOG_FRAME')
        kind, a, b, c, length = struct.unpack('>BBBBI', raw[offset:offset + 8])
        require(kind in (1, 2) and (a, b, c) == (0, 0, 0)
                and offset + 8 + length <= len(raw), 'INVALID_LOG_FRAME')
        result.extend(raw[offset + 8:offset + 8 + length])
        offset += 8 + length
    return bytes(result)


# Closed vocabulary: never return raw log lines, URIs, arbitrary messages or token-like strings.
SAFE_CODE = re.compile(r'(?<![A-Z0-9_])(?:'
    r'ONB_READINESS_(?:DEPENDENCY_[1-5][0-9]{2}|CAPACITY_PAUSED|COMPATIBILITY_UNPROVEN|'
    r'IDENTITY_UNPROVEN|DEPENDENCY_UNAVAILABLE|RESPONSE_INVALID|RESPONSE_TOO_LARGE|INTERRUPTED)|'
    r'ING_READINESS_(?:CAPACITY_PAUSED|DEADLINE|CANCELLED|UNPROVEN|FROZEN_IDENTITY_CHANGED|'
    r'CONFIGURATION_HASH_MISMATCH|EXISTING_ATTESTATION_REJECTED|ATTESTATION_UNPROVEN)|'
    r'ING_ACTIVATION_(?:GATEWAY_[1-5][0-9]{2}|TIMEOUT|RESPONSE_FAILED|INTERRUPTED|IO_FAILED)|'
    r'ING_EXECUTION_(?:GATEWAY_[1-5][0-9]{2}|GATEWAY_UNAVAILABLE|INTERRUPTED|IO_FAILED)|'
    r'ING_COMPAT_CANCELLED)(?![A-Z0-9_])')
CATEGORIES = {
    'UPSTREAM_CONNECT_REFUSED': 'connect() failed (111: Connection refused)',
    'UPSTREAM_TIMED_OUT': 'upstream timed out',
    'UPSTREAM_NO_LIVE_BACKEND': 'no live upstreams',
    'UPSTREAM_PREMATURE_CLOSE': 'upstream prematurely closed connection',
    'DNS_RESOLUTION_FAILED': 'could not be resolved',
    'JAVA_CONNECT_EXCEPTION': 'java.net.ConnectException',
    'JAVA_HTTP_TIMEOUT': 'java.net.http.HttpTimeoutException',
    'JAVA_UNKNOWN_HOST': 'java.net.UnknownHostException',
    'CONNECT_REFUSED_GENERIC': 'connection refused',
    'DNS_RESOLUTION_GENERIC': 'failed to resolve',
    'DNS_LOOKUP_FAILED': 'dns lookup failed',
    'DNS_NAME_ERROR': 'name error',
    'APISIX_NO_VALID_UPSTREAM': 'no valid upstream node',
    'APISIX_SET_PEER_FAILED': 'failed to set server peer',
    'APISIX_PICK_SERVER_FAILED': 'failed to pick server',
    'UPSTREAM_CONNECTION_FAILED': 'failed to connect to upstream',
    'RESTY_CONNECT_FAILED': 'failed to connect',
    'NETWORK_UNREACHABLE': 'network is unreachable',
    'NO_ROUTE_TO_HOST': 'no route to host',
    'READ_TIMEOUT': 'read timed out',
    'CONNECT_TIMEOUT': 'connect timed out',
    'CONNECTION_RESET': 'connection reset by peer',
    'HTTP_CLIENT_RESPONSE_EXCEPTION': 'org.springframework.web.server.ResponseStatusException',
    'TLS_CERTIFICATE_FAILED': 'certificate verify failed',
    'SQL_CONNECTION_FAILED': 'cannotgetjdbcconnectionexception',
}

# Only enum labels are emitted; concrete URLs, queries and identifiers stay in memory.
ROUTES = {
    'INGESTION_READINESS': '/api/trusted-human/v1/ingestion/onboarding-readiness',
    'SOURCE_REVIEW': '/api/trusted-human/v1/approval-challenges/',
    'SOURCE_VERSION': '/api/onboarding/v1/sources/',
    'COMPATIBILITY': '/api/internal/v1/onboarding/compatibility/ingestion-runtime',
    'SEMANTIC_REFERENCE': '/api/semantic/v1/references:resolve',
    'MANAGED_CONTENT': '/internal/object-storage/v1/content',
    'IDENTITY_PREFLIGHT': '/api/udp/v1/governance/identity/preflight',
}


def http_observations(text):
    result = []
    for line in text.splitlines():
        route = next((name for name, path in ROUTES.items() if path in line), None)
        if route is None:
            continue
        status = re.search(r'\b(?:status|status_code|response_status)[\s\"\x27:=]+([1-5][0-9]{2})(?![0-9])', line)
        if status is None:
            status = re.search(r'HTTP/[0-9.]+\"\s+([1-5][0-9]{2})(?![0-9])', line)
        duration = re.search(r'\bdurationMs[\s\"\x27:=]+([0-9]{1,8})(?![0-9])', line)
        method = re.search(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', line)
        timestamp = re.match(r'(20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z)', line)
        result.append({'routeClass': route, 'status': int(status[1]) if status else None,
                       'durationMs': int(duration[1]) if duration else None,
                       'method': method[1] if method else None,
                       'timestamp': timestamp[1] if timestamp else None})
        require(len(result) <= 4000, 'HTTP_OBSERVATION_LIMIT')
    return result


def classify(raw):
    text = raw.decode('utf-8', errors='replace')
    codes = collections.Counter(SAFE_CODE.findall(text))
    lowered = text.lower()
    categories = {key: lowered.count(needle.lower()) for key, needle in CATEGORIES.items()
                  if needle.lower() in lowered}
    return {'safeCodes': dict(sorted(codes.items())), 'transportCategories': categories,
            'httpObservations': http_observations(text),
            'lineCount': len(text.splitlines()),
            'logBytes': len(raw), 'rawLinesPrinted': False,
            'absenceOfCodeIsNotProofOfHealth': True}


class Engine:
    def __init__(self, binding, ids, since, until):
        self.binding, self.ids = binding, ids
        query = urlencode({'stdout': 'true', 'stderr': 'true', 'timestamps': 'true',
                           'follow': 'false', 'since': since, 'until': until, 'tail': 4000})
        self.paths = {'/v1.44/containers/' + cid + '/json' for cid in ids}
        self.logs = {cid: '/v1.44/containers/' + cid + '/logs?' + query for cid in ids}
        self.paths.update(self.logs.values())
        self.calls = 0

    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
                'EXACT_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'ENGINE_BINDING_CHANGED')

    def get(self, path):
        require(path in self.paths and self.calls < 9, 'CLOSED_NINE_GET_BUDGET')
        self.check()
        selected = self.binding['socketPath']

        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(selected)

        connection = Connection('retained-engine', timeout=4)
        try:
            self.calls += 1
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(2_097_153)
            require(len(raw) <= 2_097_152, 'LOG_OR_METADATA_LIMIT_REACHED')
            self.check()
            require(response.status == 200, 'ENGINE_GET_STATUS_' + str(response.status))
            return raw
        finally:
            connection.close()

    def inspect(self, cid):
        return json.loads(self.get('/v1.44/containers/' + cid + '/json'))


def generation(actual, expected):
    s = actual['State']
    require(actual['Id'] == expected['containerId'] and s['Pid'] == expected['pid']
            and s['StartedAt'] == expected['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead'),
            'RUNTIME_GENERATION_CHANGED')


def run(case):
    require(case['schema'] == 'ouf.readiness-log-diagnostic-case.v1', 'EXACT_CASE_REQUIRED')
    require(type(case['since']) is int and type(case['until']) is int
            and 0 < case['since'] < case['until'] <= case['since'] + 180,
            'BOUNDED_HISTORICAL_WINDOW_REQUIRED')
    root = case['contextPath']
    review, before_review = private_json(root + '/review.json')
    row, before_row = private_json(root + '/recovery.json')
    native = review['executionReview']
    require(row['nextStage'] == len(native['stages']) == 28 and len(row['effects']) == 28
            and all(e['state'] == 'APPLIED' for e in row['effects']), 'COMPLETED_ROLLOUT_REQUIRED')
    pins = {}
    for name in ('ingestion', 'gateway'):
        i = next(i for i, s in enumerate(native['stages']) if s['name'] == name + '.START_REPLACEMENT')
        pins[name] = row['effects'][i]['nativeResource']
        require(pins[name]['containerId'] == case['replacementIds'][name], 'EXACT_REPLACEMENT_REQUIRED')
    pins['onboarding'] = native['runtimeGuardProfile']['unchangedApplications']['onboarding']['binding']
    require(set(pins['onboarding']) >= {'containerId', 'pid', 'startedAt'}, 'OWNER_PROCESS_PIN_REQUIRED')
    ids = {v['containerId'] for v in pins.values()}
    require(len(ids) == 3 and all(re.fullmatch('[a-f0-9]{64}', c) for c in ids), 'EXACT_THREE_CONTAINERS_REQUIRED')
    engine = Engine(native['engineBinding'], ids, case['since'], case['until'])
    before = {name: engine.inspect(pin['containerId']) for name, pin in pins.items()}
    for name, pin in pins.items():
        generation(before[name], pin)
    results = {}
    for name, pin in pins.items():
        raw = engine.get(engine.logs[pin['containerId']])
        results[name] = classify(unframe(raw, not before[name]['Config'].get('Tty', False)))
    for name, pin in pins.items():
        generation(engine.inspect(pin['containerId']), pin)
    require(private_json(root + '/review.json')[1] == before_review
            and private_json(root + '/recovery.json')[1] == before_row, 'RETAINED_CONTEXT_CHANGED')
    return {'schema': 'ouf.readiness-log-diagnostic-result.v2', 'status': 'BOUNDED_LOG_AND_HTTP_CLASSIFICATION_ONLY',
            'complete': True, 'readOnly': True, 'contextPath': root, 'since': case['since'], 'until': case['until'],
            'engineGets': engine.calls, 'maximumEngineGets': 9, 'containers': results,
            'rootCauseEstablished': False, 'runtimeEffectsDispatched': 0, 'oauthRequests': 0,
            'bearerFilesOpened': 0, 'privateKeysRead': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'releaseAcceptance': False}


if __name__ == '__main__':
    try:
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('DIAGNOSTIC_DEADLINE')))
        signal.alarm(50)
        require(len(sys.argv) == 2, 'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1], encoding='utf-8') as source:
            case = json.load(source)
        print(json.dumps(run(case), sort_keys=True))
    except Exception as error:
        # Arbitrary exception messages can contain private values. Only our closed code is printable.
        code = str(error) if isinstance(error, Stop) else 'DIAGNOSTIC_UNCONFIRMED_' + type(error).__name__
        print(json.dumps({'schema': 'ouf.readiness-log-diagnostic-result.v2', 'status': 'STOP_RECONCILE',
                          'reasonCode': code, 'readOnly': True, 'runtimeEffectsDispatched': 0,
                          'activationResubmitted': False, 'automaticReplayAllowed': False}))
        sys.exit(1)
