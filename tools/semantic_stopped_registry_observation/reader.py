"""Distinct GET-only observation after HISTORICAL_REGISTRY_NOT_RUNNING.

Stopped metadata is evidence to describe, never a live endpoint binding.
No container discovery, substitute registry, probe, credential or runtime effect.
"""
import datetime
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
from urllib.parse import urlencode, urlsplit

SCHEMA = 'ouf.semantic-stopped-registry-observation-result.v1'
CASE_SCHEMA = 'ouf.semantic-stopped-registry-observation-case.v1'
OPERATION = '/api/semantic/v1/references:resolve'
MAX_GETS = 5
MAX_BYTES = 2_097_152
STATE_FIELDS = ('Status', 'Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled',
                'Pid', 'ExitCode', 'Error', 'StartedAt', 'FinishedAt')
TIMESTAMP = re.compile(r'(20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z')
REQUEST = re.compile(r'request:\s*"GET ' + re.escape(OPERATION) + r'(?:\?[^ "\r\n]*)? HTTP/[0-9.]+"')


class Stop(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Stop(code)


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def private_json(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
            'EXACT_PRIVATE_PATH_REQUIRED')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and not before.st_mode & 0o022 and 0 < before.st_size <= 8_388_608,
                'ROOT_OWNED_BOUNDED_METADATA_REQUIRED')
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65_536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()),
                'PRIVATE_METADATA_CHANGED')
        return decode(raw), bytes(raw)
    finally:
        os.close(fd)


class Engine:
    def __init__(self, binding, gateway_id, registry_id, since, until):
        self.binding = binding
        self.calls = 0
        self.inspects = {'/v1.44/containers/' + cid + '/json' for cid in (gateway_id, registry_id)}
        self.log_path = '/v1.44/containers/' + gateway_id + '/logs?' + urlencode({
            'stdout': 'true', 'stderr': 'true', 'timestamps': 'true', 'follow': 'false',
            'since': since, 'until': until, 'tail': 4000})
        self.paths = self.inspects | {self.log_path}

    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
                'EXACT_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0
                and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'ENGINE_BINDING_CHANGED')

    def get(self, path):
        require(path in self.paths and self.calls < MAX_GETS, 'CLOSED_FIVE_GET_BUDGET')
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
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, 'LOG_OR_METADATA_LIMIT_REACHED')
            self.check()
            require(response.status == 200, 'ENGINE_GET_STATUS_' + str(response.status))
            return raw
        finally:
            connection.close()

    def inspect(self, cid):
        path = '/v1.44/containers/' + cid + '/json'
        require(path in self.inspects, 'EXACT_INSPECT_ID_REQUIRED')
        value = decode(self.get(path))
        require(value['Id'] == cid, 'EXACT_INSPECT_ID_REQUIRED')
        return value


def unframe(raw, multiplexed):
    if not multiplexed:
        return raw
    result = bytearray()
    offset = 0
    while offset < len(raw):
        require(len(raw) - offset >= 8, 'INCOMPLETE_LOG_FRAME')
        kind, a, b, c, size = struct.unpack('>BBBBI', raw[offset:offset + 8])
        require(kind in (1, 2) and (a, b, c) == (0, 0, 0)
                and offset + 8 + size <= len(raw), 'INVALID_LOG_FRAME')
        result.extend(raw[offset + 8:offset + 8 + size])
        offset += 8 + size
    return bytes(result)


def timestamp(value):
    if type(value) is not str:
        return None
    m = TIMESTAMP.fullmatch(value)
    if not m:
        return None
    try:
        seconds = int(datetime.datetime.strptime(m[1], '%Y-%m-%dT%H:%M:%S')
                      .replace(tzinfo=datetime.timezone.utc).timestamp())
        return seconds * 1_000_000_000 + int((m[2] or '').ljust(9, '0'))
    except ValueError:
        return None


def generation(actual, pin):
    s = actual['State']
    require(actual['Id'] == pin['containerId'] and s['Pid'] == pin['pid']
            and s['StartedAt'] == pin['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead'),
            'GATEWAY_GENERATION_CHANGED')


def stable_fields(actual):
    # Omit continuously changing health-check history; bind lifecycle/config/network.
    return {'Id': actual['Id'], 'Image': actual['Image'], 'Config': actual['Config'],
            'NetworkSettings': actual['NetworkSettings'], 'RestartCount': actual['RestartCount'],
            'State': {key: actual['State'].get(key) for key in STATE_FIELDS}}


def registry_state(actual):
    s = actual['State']
    statuses = {'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'}
    require(s.get('Status') in statuses
            and all(type(s.get(k)) is bool for k in ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled'))
            and type(s.get('Pid')) is int and s['Pid'] >= 0
            and type(s.get('ExitCode')) is int and 0 <= s['ExitCode'] <= 255
            and type(actual['RestartCount']) is int and actual['RestartCount'] >= 0,
            'BOUNDED_REGISTRY_STATE_REQUIRED')
    return {'status': s['Status'], 'running': s['Running'], 'paused': s['Paused'],
            'restarting': s['Restarting'], 'dead': s['Dead'], 'oomKilled': s['OOMKilled'],
            'exitCode': s['ExitCode'], 'restartCount': actual['RestartCount'],
            'hasProcess': s['Pid'] > 0,
            'startedAt': s['StartedAt'] if timestamp(s.get('StartedAt')) is not None else None,
            'finishedAt': s['FinishedAt'] if timestamp(s.get('FinishedAt')) is not None else None,
            'rawErrorPrinted': False, 'currentEndpointBindingEstablished': False}


def observe_logs(raw, registry, since, until):
    result = []
    text = raw.decode('utf-8', errors='replace')
    lines = text.splitlines()
    require(len(lines) <= 8000, 'LOG_LINE_LIMIT_REACHED')
    state = registry['State']
    finished = timestamp(state.get('FinishedAt'))
    for line in lines:
        if 'no route to host' not in line.lower() or REQUEST.search(line) is None:
            continue
        m = TIMESTAMP.match(line)
        observed = m[0] if m else None
        ns = timestamp(observed)
        require(ns is not None and since * 1_000_000_000 <= ns < until * 1_000_000_000,
                'MATCHING_LOG_TIMESTAMP_OUTSIDE_WINDOW_OR_UNPROVEN')
        upstream = re.search(r'upstream:\s*"([^"\r\n]{1,4096})"', line)
        operation_matches = None
        if upstream:
            try:
                endpoint = urlsplit(upstream[1])
                operation_matches = endpoint.path == OPERATION
            except ValueError:
                pass
        result.append({'timestamp': observed, 'routeClass': 'SEMANTIC_REFERENCE',
                       'category': 'NO_ROUTE_TO_HOST', 'upstreamOperationMatches': operation_matches,
                       'atOrAfterObservedRegistryFinish': None if finished is None else ns >= finished,
                       'upstreamAddressMatchesCurrentRegistry': None})
        require(len(result) <= 4000, 'CORRELATION_LIMIT_REACHED')
    return {'sameLineSemanticReferenceFailures': result, 'lineCount': len(lines),
            'logBytes': len(raw), 'logTailMayBeTruncated': len(lines) >= 4000,
            'absenceOfMatchIsNotProofOfHealth': True, 'rawLinesPrinted': False,
            'addressesPrinted': False, 'historicalLogIsCurrentRouteMap': False}


def run(case):
    require(type(case) is dict and set(case) == {'schema', 'contextPath', 'since', 'until', 'historicalRegistryId'}
            and case['schema'] == CASE_SCHEMA, 'EXACT_CASE_REQUIRED')
    since, until = case['since'], case['until']
    require(type(since) is int and type(until) is int and 0 < since < until <= since + 180,
            'BOUNDED_HISTORICAL_WINDOW_REQUIRED')
    root = case['contextPath']
    review, before_review = private_json(root + '/review.json')
    row, before_row = private_json(root + '/recovery.json')
    native = review['executionReview']
    require(row['nextStage'] == len(native['stages']) == 12 and len(row['effects']) == 12
            and all(e['state'] == 'APPLIED' for e in row['effects']), 'COMPLETED_PATCH_REQUIRED')
    gateway_pin = native['runtimeGuardProfile']['unchangedApplications']['gateway']['binding']
    registry_id, gateway_id = case['historicalRegistryId'], gateway_pin['containerId']
    require(all(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) for cid in (registry_id, gateway_id))
            and registry_id != gateway_id, 'TWO_EXACT_DISTINCT_CONTAINERS_REQUIRED')
    engine = Engine(native['engineBinding'], gateway_id, registry_id, since, until)
    gateway = engine.inspect(gateway_id)
    generation(gateway, gateway_pin)
    registry = engine.inspect(registry_id)
    state = registry_state(registry)
    raw = engine.get(engine.log_path)
    logs = observe_logs(unframe(raw, not gateway['Config'].get('Tty', False)), registry, since, until)
    following = engine.inspect(gateway_id)
    generation(following, gateway_pin)
    registry_after = engine.inspect(registry_id)
    require(stable_fields(gateway) == stable_fields(following)
            and stable_fields(registry) == stable_fields(registry_after),
            'LIFECYCLE_CONFIG_OR_NETWORK_CHANGED')
    require(private_json(root + '/review.json')[1] == before_review
            and private_json(root + '/recovery.json')[1] == before_row, 'RETAINED_CONTEXT_CHANGED')
    return {'schema': SCHEMA, 'status': 'BOUNDED_HISTORICAL_OBSERVATION_ONLY', 'complete': True,
            'readOnly': True, 'engineGets': engine.calls, 'maximumEngineGets': MAX_GETS,
            'since': since, 'until': until, 'historicalRegistry': state, **logs,
            'registrySelectionSource': 'EXACT_HISTORICAL_ID_NOT_CURRENT_SERVICE_DISCOVERY',
            'registrySubstituted': False, 'currentRegistryIdentityEstablished': False,
            'rootCauseEstablished': False, 'serviceReadinessEstablished': False,
            'oauthRequests': 0, 'credentialFilesOpened': 0, 'gatewayWrites': 0,
            'runtimeEffectsDispatched': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False,
            'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4}


def stopped(error):
    reason = str(error) if type(error) is Stop else 'DIAGNOSTIC_UNCONFIRMED_' + type(error).__name__
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'DIAGNOSTIC_UNCONFIRMED'
    return {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'readOnly': True, 'runtimeEffectsDispatched': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'rootCauseEstablished': False}


if __name__ == '__main__':
    try:
        require(os.geteuid() == 0 and sys.flags.isolated, 'ROOT_ISOLATED_READER_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('DIAGNOSTIC_DEADLINE')))
        signal.alarm(35)
        require(len(sys.argv) == 2, 'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1], 'rb') as source:
            raw = source.read(8193)
        require(len(raw) <= 8192, 'BOUNDED_CASE_REQUIRED')
        print(json.dumps(run(decode(raw)), sort_keys=True), flush=True)
    except Exception as error:
        print(json.dumps(stopped(error), sort_keys=True), flush=True)
        sys.exit(1)
