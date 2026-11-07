#!/usr/bin/env python3
"""Inventory the retained rollout target. Docker GET only; no application calls.

Configuration declarations are not effective Spring configuration. MAC deltas
are described, never normalized or admitted as an authorization to replace.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import stat
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

ROOT = Path('/var/lib/ouf-storage-migration')
PLAN = ROOT / 'cold-host-bound-20261107-v1/plan.private.json'
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
ROSTER = {'postgres', 'minio', 'etcd', 'keycloak', 'udp', 'udp-evidence-read',
          'ingestion', 'ingestion-evidence-read', 'onboarding', 'gateway-owner',
          'apisix', 'caddy', 'semantic', 'mcp'}
SELECTED = ('mcp', 'onboarding', 'semantic', 'gateway-owner', 'apisix', 'ingestion', 'udp')
PROVIDER = 'ouf.semantic.providers.schema-gov.'
ALIASES = {
    'OUF_SCHEMA_GOV_ENABLED': PROVIDER + 'enabled',
    'OUF_SCHEMA_GOV_GATEWAY_BASE_URL': PROVIDER + 'gateway-base-url',
    'OUF_SCHEMA_GOV_SEARCH_PATH': PROVIDER + 'search-path',
    'OUF_SCHEMA_GOV_FETCH_PATH': PROVIDER + 'fetch-path',
    'OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED': PROVIDER + 'gateway-auth.enabled',
    'OUF_SCHEMA_GOV_TOKEN_ENDPOINT': PROVIDER + 'gateway-auth.token-endpoint',
    'OUF_SCHEMA_GOV_CLIENT_ID': PROVIDER + 'gateway-auth.client-id',
    'OUF_SCHEMA_GOV_CLIENT_SECRET_FILE': PROVIDER + 'gateway-auth.client-secret-file',
    'OUF_SCHEMA_GOV_WORKLOAD_SCOPE': PROVIDER + 'gateway-auth.scope',
    'OUF_DISCOVERY_WORKER_ENABLED': 'ouf.semantic.discovery-worker.enabled',
    'OUF_DISCOVERY_WORKER_DELAY': 'ouf.semantic.discovery-worker.fixed-delay',
}
FIELDS = set(ALIASES.values()) | {PROVIDER + name for name in (
    'max-candidates', 'max-attempts', 'request-timeout', 'max-response-bytes')}
FIELDS |= {'javax.net.ssl.trustStore', 'spring.config.import', 'spring.config.location',
           'spring.config.additional-location', 'spring.profiles.active'}


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'BOUNDED_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        pin = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and pin(before) == pin(after), 'INPUT_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_KEY')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def inspect(cid):
    need(isinstance(cid, str) and re.fullmatch('[a-f0-9]{64}', cid), 'EXACT_CONTAINER_ID_REQUIRED')
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(8)
            self.sock.connect('/run/docker.sock')
    connection = Local('localhost', timeout=8)
    try:
        connection.request('GET', '/v1.44/containers/' + cid + '/json')
        response = connection.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        need(response.status == 200 and len(raw) <= 2 * 1024 * 1024, 'DOCKER_INSPECT_FAILED')
        doc = parse(raw)
        need(doc['Id'] == cid, 'DOCKER_ID_MISMATCH')
        return doc
    finally:
        connection.close()


def digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False) + '\n').encode()).hexdigest()


def fingerprint(doc):
    host = dict(doc['HostConfig'])
    host.pop('RestartPolicy', None)  # Exact existing retained fingerprint format.
    result = {k: doc.get(k) for k in ('Id', 'Image', 'Config', 'Mounts', 'Path', 'Args')}
    result.update(HostConfig=host, StartedAt=doc['State']['StartedAt'])
    return digest(result)


def frame(doc):
    result = {k: doc.get(k) for k in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts',
                                     'Path', 'Args', 'NetworkSettings')}
    result['State'] = {k: doc['State'].get(k) for k in
                       ('Running', 'Restarting', 'Paused', 'Status', 'Pid', 'StartedAt', 'FinishedAt')}
    return result


def mac_shape(doc):
    config = doc['Config']
    value = config.get('MacAddress')
    kind = ('ABSENT' if 'MacAddress' not in config else 'NULL' if value is None else
            'EMPTY_STRING' if value == '' else 'STRING' if isinstance(value, str) else 'OTHER')
    valid = isinstance(value, str) and re.fullmatch(r'(?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}', value) is not None
    endpoints = doc['NetworkSettings'].get('Networks', {})
    return {'kind': kind, 'formatValid': valid,
            'unicastNonzero': bool(valid and int(value.replace(':', ''), 16) and not (int(value[:2], 16) & 1)),
            'matchingEndpointCount': sum(valid and str(n.get('MacAddress', '')).lower() == value.lower()
                                         for n in endpoints.values()),
            'endpointCount': len(endpoints)}


def environment(doc):
    return unique(row.split('=', 1) for row in doc['Config'].get('Env') or [])


def canonical(key):
    return re.sub('[._-]', '', key).lower()


def summarize_value(key, value):
    """Never emit arbitrary configuration values, URL queries or credential paths."""
    if key.endswith('.enabled'):
        return str(value).lower() if str(value).lower() in ('true', 'false') else 'UNRECOGNIZED'
    if key.endswith(('max-candidates', 'max-attempts', 'max-response-bytes')):
        return int(value) if re.fullmatch('[0-9]{1,10}', str(value)) else 'UNRECOGNIZED'
    if key.endswith(('request-timeout', 'fixed-delay')):
        return str(value) if re.fullmatch('[0-9]{1,6}(ms|s|m)', str(value)) else 'UNRECOGNIZED'
    if key.endswith(('gateway-base-url', 'token-endpoint')):
        url = urlsplit(str(value))
        safe = (url.scheme in ('http', 'https') and bool(url.hostname) and
                not (url.username or url.password or url.query or url.fragment))
        known = url.hostname in ('api.ouf-lab.it', 'auth.ouf-lab.it', 'ouf-apisix', 'apisix',
                                 'ouf-keycloak', 'keycloak')
        return {'validUrlWithoutCredentials': safe, 'scheme': url.scheme if safe else None,
                'knownHost': url.hostname if safe and known else None,
                'otherHostPresent': bool(safe and not known), 'pathPresent': bool(url.path)}
    if key.endswith('search-path'):
        return 'EXPECTED_SCHEMA_GOV_PATH' if value == '/semantic-providers/schema-gov/sparql' else 'OTHER_PRESENT'
    if key.endswith('fetch-path'):
        return 'EXPECTED_SCHEMA_GOV_PATH' if value == '/semantic-providers/schema-gov/fetch' else 'OTHER_PRESENT'
    return 'PRESENT' if value not in ('', None) else 'EMPTY'


def declarations(doc):
    env, found = environment(doc), {}
    def add(key, value, origin):
        for field in FIELDS:
            if canonical(key) == canonical(field):
                found.setdefault(field, []).append({'origin': origin, 'summary': summarize_value(field, value)})
    for key, value in env.items():
        add(key, value, 'ENV_DIRECT')
        if key in ALIASES:
            add(ALIASES[key], value, 'ENV_PACKAGED_YAML_VARIABLE')
    def flatten(value, prefix='', depth=0):
        need(isinstance(value, dict) and depth <= 16, 'SPRING_JSON_SHAPE')
        for key, child in value.items():
            if isinstance(child, dict):
                flatten(child, prefix + key + '.', depth + 1)
            else:
                add(prefix + key, child, 'SPRING_APPLICATION_JSON')
    if env.get('SPRING_APPLICATION_JSON'):
        need(len(env['SPRING_APPLICATION_JSON']) <= 1024 * 1024, 'SPRING_JSON_LIMIT')
        flatten(parse(env['SPRING_APPLICATION_JSON']))
    args = list(doc['Config'].get('Entrypoint') or []) + list(doc['Config'].get('Cmd') or [])
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'JAVA_OPTS'):
        args.extend(shlex.split(env.get(key, '')))
    for arg in args:
        if arg.startswith(('-D', '--')) and '=' in arg:
            key, value = arg[2:].split('=', 1)
            add(key, value, 'DECLARED_ARGUMENT')
    return {'scope': 'DECLARATIONS_NOT_EFFECTIVE_SPRING_CONFIGURATION',
            'precedenceResolved': False, 'packagedDefaultsApplied': False,
            'springApplicationJsonPresent': bool(env.get('SPRING_APPLICATION_JSON')),
            'properties': found}


def changes(before, after):
    return sorted(k for k in set(before) | set(after)
                  if (k in before, before.get(k)) != (k in after, after.get(k)))


def summary(doc, baseline, expected_image):
    env = environment(doc)
    names = changes(environment(baseline), env)
    return {'containerId': doc['Id'], 'imageId': doc['Image'],
            'imageMatchesRetained': doc['Image'] == expected_image,
            'running': doc['State']['Running'], 'startedAt': doc['State']['StartedAt'],
            'currentFrameSha256': digest(frame(doc)),
            'changedConfigFields': changes(baseline['Config'], doc['Config']),
            'changedHostConfigFields': changes(baseline['HostConfig'], doc['HostConfig']),
            'changedEnvironmentKeys': [n for n in names if re.fullmatch('[A-Z_][A-Z0-9_]{0,99}', n)],
            'otherChangedEnvironmentKeyCount': sum(not bool(re.fullmatch('[A-Z_][A-Z0-9_]{0,99}', n)) for n in names),
            'mountsMatchBaseline': doc['Mounts'] == baseline['Mounts'],
            'launchMatchesBaseline': (doc.get('Path'), doc.get('Args')) == (baseline.get('Path'), baseline.get('Args')),
            'baselineLegacyMac': mac_shape(baseline), 'currentLegacyMac': mac_shape(doc),
            'networkSettingsMatchBaseline': doc['NetworkSettings'] == baseline['NetworkSettings'],
            'backendNetworkPresent': 'ouf-backend' in doc['NetworkSettings'].get('Networks', {}),
            'seaweedfsNetworkPresent': 'ouf-seaweedfs-private' in doc['NetworkSettings'].get('Networks', {}),
            'mountCount': len(doc['Mounts']), 'readOnlyMountCount': sum(not m['RW'] for m in doc['Mounts']),
            'memoryLimitBytes': doc['HostConfig'].get('Memory'),
            'restartPolicyName': doc['HostConfig'].get('RestartPolicy', {}).get('Name'),
            'declaredConfiguration': declarations(doc)}


def collect(report, root=ROOT, plan_path=PLAN):
    raw = read(plan_path, 1024 * 1024)
    need(hashlib.sha256(raw).hexdigest() == PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    roles = parse(raw)['roles']
    need(set(roles) == ROSTER, 'RETAINED_ROSTER_MISMATCH')
    ids = [r['containerId'] for r in roles.values()]
    need(len(set(ids)) == len(ids) and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'RETAINED_IDS_INVALID')
    originals = {doc['Id']: doc for doc in parse(read(plan_path.parent / 'stop/command-182.private', 16 * 1024 * 1024))}
    need(set(originals) == set(ids), 'RETAINED_INSPECT_ROSTER_MISMATCH')
    bound, baselines, old = {}, {}, {}
    for role in SELECTED:
        baseline = originals[roles[role]['containerId']]
        need(baseline['Image'] == roles[role]['nativeImage'] and
             fingerprint(baseline) == roles[role]['fingerprint'], 'RETAINED_BASELINE_MISMATCH')
        if role in ('onboarding', 'udp'):
            marker = parse(read(root / (role + '-seaweedfs-current.json'), 128 * 1024))
            work = Path(marker['privateEvidenceDirectory'])
            need(work.parent == root and work.name.startswith(role + '-seaweedfs-switch-') and
                 work.resolve(strict=True) == work, 'STORAGE_RECEIPT_PATH_INVALID')
            replacement = parse(read(work / 'replacement-container.private.json', 2 * 1024 * 1024))
            need(marker['status'] == role.upper() + '_SEAWEEDFS_READY' and
                 marker['originalContainerId'] == baseline['Id'] and
                 marker['replacementContainerId'] == replacement['Id'] and
                 marker['switchToken'] and
                 replacement['Image'] == roles[role]['nativeImage'] and
                 (replacement['Config'].get('Labels') or {}).get('ouf.storage.switch') == marker['switchToken'],
                 'STORAGE_RECEIPT_IDENTITY_MISMATCH')
            old[role] = inspect(baseline['Id'])
            baseline = replacement
        baselines[role] = baseline
        bound[role] = baseline['Id']
    current = {role: inspect(cid) for role, cid in bound.items()}
    work = Path(tempfile.mkdtemp(prefix='analysis-discovery-read-', dir=root))
    os.chmod(work, 0o700)
    report['privateEvidenceDirectory'] = str(work)
    for role, doc in current.items():
        with (work / (role + '.private.json')).open('x', encoding='utf-8') as stream:
            os.chmod(stream.name, 0o600)
            json.dump(doc, stream, sort_keys=True)
            stream.write('\n')
    report['services'] = {role: summary(doc, baselines[role], roles[role]['nativeImage'])
                          for role, doc in current.items()}
    report['storageDeclarations'] = {}
    for role, prefix, bucket in (('onboarding', 'OUF_ONBOARDING_STAGING_', 'ouf-managed-files'),
                                 ('udp', 'OUF_UDP_S3_', 'ouf-udp')):
        env = environment(current[role])
        report['storageDeclarations'][role] = {
            'scope': 'DOCKER_ENV_NOT_EFFECTIVE_SPRING_CONFIGURATION',
            'endpointMatchesSeaweedfs': env.get(prefix + 'ENDPOINT') == 'https://ouf-seaweedfs-stage:9002',
            'bucketMatchesExpected': env.get(prefix + 'BUCKET') == bucket,
            'oldWriterStoppedAtFirstRead': not old[role]['State']['Running']}
    final = {role: inspect(cid) for role, cid in bound.items()}
    old_final = {role: inspect(doc['Id']) for role, doc in old.items()}
    report['runtimeUnchangedDuringRead'] = all(frame(current[r]) == frame(final[r]) for r in current)
    report['oldWriterStateUnchangedDuringRead'] = all(frame(old[r]) == frame(old_final[r]) for r in old)
    report['oldWritersStoppedAtBothReads'] = all(not d['State']['Running'] for d in (*old.values(), *old_final.values()))
    report['status'] = 'ANALYSIS_DISCOVERY_RUNTIME_READ_COMPLETE'
    if not (report['runtimeUnchangedDuringRead'] and report['oldWriterStateUnchangedDuringRead']):
        report.update(status='READ_INCOMPLETE', reason='RUNTIME_CHANGED_DURING_READ')


def deadline(_signum, _frame):
    raise RuntimeError('READ_DEADLINE')


def main():
    report = {'schema': 'ouf.analysis-discovery-runtime-read.v1', 'status': 'READ_INCOMPLETE',
              'credentialValuesEmitted': False, 'credentialFilesRead': 0,
              'serviceConfigurationChanged': False, 'serviceStops': 0, 'databaseRequests': 0,
              'businessRequestsIssued': 0, 's3Requests': 0, 'providerRequests': 0,
              'runtimeConfigurationEffectiveRead': False, 'routesRead': False,
              'policyGrantsRead': False, 'readinessTested': False, 'deploymentAuthorizedByReader': False}
    try:
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(55)
        collect(report)
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError, http.client.HTTPException) as exc:
        report.update(status='READ_INCOMPLETE', reason=str(exc) if type(exc) is RuntimeError else type(exc).__name__)
    finally:
        signal.alarm(0)
    report['observedAt'] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
