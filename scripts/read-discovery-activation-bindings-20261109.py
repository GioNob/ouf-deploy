#!/usr/bin/env python3
"""Read current discovery dependencies; no token, SQL, business or lifecycle calls.

The known application generations come from the latest operator receipts.
Dependency names are observations to resolve, not retained identity assertions.
Only Docker GET and file metadata are used. Full selected inspect responses stay
in a root-only evidence directory. Credentials/config contents are never opened.
"""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

HELPERS = {
    'read-analysis-discovery-runtime-20261107.py': 'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4',
    'read-discovery-contract-20261108.py': '468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277',
}
APPLICATIONS = {
    'semantic': ('ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a',
                 'sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048'),
    'mcp': ('41c1e01dfd86535d75d2db6d7bd0f9e3eae27c24684af0b149d6b51c54d90943',
            'sha256:d76fda00f9340dcea62ed1be58b1db3ebfb4d64d4be5449ffc07ab2c845254ff'),
}
DEPENDENCIES = ('ouf-semantic-southbound-v2', 'ouf-semantic-provider-v2',
                'ouf-semantic-provider')
SAFE_ENV = ('OUF_SCHEMA_GOV_CLIENT_ID', 'OUF_SCHEMA_GOV_WORKLOAD_SCOPE',
            'OUF_SCHEMA_GOV_CLIENT_SECRET_FILE', 'OUF_SCHEMA_GOV_TOKEN_ENDPOINT',
            'SPRING_CONFIG_IMPORT', 'SPRING_CONFIG_LOCATION',
            'SPRING_CONFIG_ADDITIONAL_LOCATION', 'JAVA_TOOL_OPTIONS',
            'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS')
CONFIG_PATHS = ('/usr/local/apisix/conf/config.yaml', '/usr/local/apisix/conf/apisix.yaml')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def safe_reason(exc):
    return str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__


def load_helpers():
    modules = []
    for name, expected in HELPERS.items():
        path = Path(__file__).with_name(name)
        raw = path.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == expected, 'READER_HELPER_HASH_MISMATCH')
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name.replace('.', '_'), path))
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        modules.append(module)
    return modules


def docker_get(identity):
    need(identity in DEPENDENCIES or re.fullmatch('[a-f0-9]{64}', identity), 'BOUNDED_DOCKER_ID_REQUIRED')
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect('/run/docker.sock')
    connection = Local('localhost', timeout=5)
    try:
        connection.request('GET', '/v1.44/containers/' + identity + '/json')
        response = connection.getresponse()
        raw = response.read(2097153)
        need(len(raw) <= 2097152, 'DOCKER_RESPONSE_LIMIT')
        if response.status == 404:
            return None
        need(response.status == 200, 'DOCKER_READ_FAILED')
        doc = json.loads(raw)
        need(re.fullmatch('[a-f0-9]{64}', doc['Id']), 'DOCKER_ID_INVALID')
        if identity in DEPENDENCIES:
            need(doc['Name'] == '/' + identity, 'DOCKER_NAME_CHANGED')
        else:
            need(doc['Id'] == identity, 'DOCKER_ID_CHANGED')
        return doc
    finally:
        connection.close()


def endpoint(value, origin_only=False):
    if not value:
        return {'declared': False}
    try:
        u = urlsplit(value)
        valid = (u.scheme in ('http', 'https') and u.hostname is not None
                 and re.fullmatch('[A-Za-z0-9.-]{1,253}', u.hostname) is not None
                 and not (u.username or u.password or u.query or u.fragment)
                 and (not origin_only or u.path in ('', '/')))
        port = u.port or (443 if u.scheme == 'https' else 80)
        valid = valid and 1 <= port <= 65535
        return {'declared': True, 'validWithoutCredentialsOrExtraParts': valid,
                'scheme': u.scheme if valid else None, 'host': u.hostname if valid else None,
                'port': port if valid else None, 'pathPresent': bool(u.path) if valid else None}
    except (TypeError, ValueError):
        return {'declared': True, 'validWithoutCredentialsOrExtraParts': False}


def metadata(doc, path, c, maximum=1048576):
    if not path:
        return {'status': 'NOT_DECLARED', 'contentsRead': False}
    if not doc['State']['Running'] or doc['State']['Pid'] <= 0:
        return {'status': 'APPLICATION_VIEW_UNAVAILABLE_STOPPED', 'contentsRead': False}
    try:
        _, result = c.mount_file(doc, path, read_content=False, maximum=maximum)
        return result
    except Exception as exc:
        return {'status': 'METADATA_READ_INCOMPLETE', 'reason': safe_reason(exc), 'contentsRead': False}


def process_and_listeners(doc):
    result = {'scope': 'CONTAINER_INIT_AND_NETWORK_NAMESPACE_ONLY', 'contentsAreNotApplicationHealth': True}
    if not doc['State']['Running'] or doc['State']['Pid'] <= 0:
        return dict(result, status='STOPPED')
    pid = doc['State']['Pid']
    try:
        with open('/proc/' + str(pid) + '/comm', 'rb') as stream:
            comm = stream.read(65).strip()
        known = {b'java': 'java', b'python3': 'python', b'python': 'python', b'nginx': 'nginx',
                 b'openresty': 'openresty', b'sh': 'sh', b'bash': 'bash', b'sleep': 'sleep', b'mcp-server': 'mcp-server'}
        result['initKind'] = known.get(comm, 'OTHER')
        listeners = []
        for family in ('tcp', 'tcp6'):
            with open('/proc/' + str(pid) + '/net/' + family, 'rb') as stream:
                raw = stream.read(262145)
            need(len(raw) <= 262144, 'SOCKET_METADATA_LIMIT')
            for row in raw.decode('ascii').splitlines()[1:]:
                cols = row.split()
                if cols[3] != '0A':
                    continue
                address, port = cols[1].split(':')
                scope = 'wildcard' if set(address) == {'0'} else 'loopback' if address in ('0100007F', '00000000000000000000000001000000') else 'other'
                listeners.append({'family': family, 'port': int(port, 16), 'bindScope': scope})
        result.update(status='READ', listeners=sorted(listeners, key=lambda row: (row['port'], row['family'])))
    except Exception as exc:
        result.update(status='READ_INCOMPLETE', reason=safe_reason(exc))
    return result


def basic(doc, h):
    return {'containerId': doc['Id'], 'imageId': doc['Image'], 'running': doc['State']['Running'],
            'state': doc['State']['Status'], 'currentFrameSha256': h.digest(h.frame(doc)),
            'networks': sorted(doc['NetworkSettings'].get('Networks', {})),
            'publishedPortBindings': bool(doc['HostConfig'].get('PortBindings')),
            'mountCount': len(doc['Mounts']), 'readOnlyMountCount': sum(not m['RW'] for m in doc['Mounts'])}


def collect(report, work, h, c, get=docker_get, processes=process_and_listeners):
    docs = {}
    components = report.setdefault('components', {})
    for role, (cid, expected) in APPLICATIONS.items():
        doc = get(cid)
        need(doc is not None and doc['Image'] == expected, 'CURRENT_APPLICATION_GENERATION_CHANGED')
        docs[role] = doc
        components[role] = dict(basic(doc, h), imageMatchesLatestReceipt=True)
    sem = docs['semantic']
    env = h.environment(sem)
    components['semantic'].update(declaredConfiguration=h.declarations(sem),
        providerGateway=endpoint(env.get('OUF_SCHEMA_GOV_GATEWAY_BASE_URL'), True),
        tokenEndpoint=endpoint(env.get('OUF_SCHEMA_GOV_TOKEN_ENDPOINT')),
        selectedEnvironmentPresent={key: bool(env.get(key)) for key in SAFE_ENV},
        credentialMount=metadata(sem, env.get('OUF_SCHEMA_GOV_CLIENT_SECRET_FILE'), c, 4096),
        process=processes(sem))
    for field in ('OUF_SCHEMA_GOV_SEARCH_PATH', 'OUF_SCHEMA_GOV_FETCH_PATH'):
        value = env.get(field)
        components['semantic'][field] = value if value in ('/internal/providers/schema-gov/search', '/internal/providers/schema-gov/fetch', '/semantic-providers/schema-gov/sparql', '/semantic-providers/schema-gov/fetch') else ('OTHER_PRESENT' if value else 'NOT_DECLARED')
    for name in DEPENDENCIES:
        doc = get(name)
        if doc is None:
            components[name] = {'status': 'NAMED_CONTAINER_NOT_FOUND', 'absenceOfOtherProvidersProven': False}
            continue
        docs[name] = doc
        components[name] = dict(basic(doc, h), status='CONTAINER_METADATA_READ',
            sharesNetworkWithSemantic=bool(set(doc['NetworkSettings']['Networks']) & set(sem['NetworkSettings']['Networks'])),
            process=processes(doc), configurationMounts={p: metadata(doc, p, c) for p in CONFIG_PATHS})
    south = docs.get('ouf-semantic-southbound-v2')
    if south:
        for name in ('ouf-semantic-provider-v2', 'ouf-semantic-provider'):
            if name in docs:
                components[name]['sharesNetworkWithSouthbound'] = bool(set(docs[name]['NetworkSettings']['Networks']) & set(south['NetworkSettings']['Networks']))
    for role, doc in docs.items():
        c.save_private(work, role + '.inspect.private.json', (json.dumps(doc, sort_keys=True) + '\n').encode())
    # Same Docker API view throughout. No MAC normalization or lifecycle authority.
    for role, doc in docs.items():
        after = get(doc['Id'])
        need(after is not None and h.frame(doc) == h.frame(after), 'CONTAINER_CHANGED_DURING_READ')
    for name in DEPENDENCIES:
        after = get(name)
        need((after['Id'] if after else None) == (docs[name]['Id'] if name in docs else None), 'DEPENDENCY_NAME_CHANGED_DURING_READ')
    report.update(status='DISCOVERY_ACTIVATION_BINDINGS_READ', runtimeUnchangedDuringRead=True,
                  privateEvidenceDirectory=str(work))


def main():
    report = {'schema': 'ouf.discovery-activation-bindings.v1', 'status': 'READ_INCOMPLETE',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'serviceConfigurationChanged': False,
              'serviceStops': 0, 'serviceStartDispatched': False, 'databaseRequests': 0,
              'businessRequestsIssued': 0, 'providerRequests': 0, 'tokenRequests': 0,
              's3Requests': 0, 'adminRequests': 0, 'credentialFileContentsRead': 0,
              'configurationFileContentsRead': 0, 'credentialValuesEmitted': False,
              'effectiveSpringConfigurationProven': False, 'connectivityTested': False,
              'workerBacklogRead': False, 'runtimeUnchangedDuringRead': False}
    def deadline(*_):
        raise RuntimeError('READ_DEADLINE')
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(90)
    try:
        need(os.geteuid() == 0, 'ROOT_METADATA_READER_REQUIRED')
        os.umask(0o077)
        h, c = load_helpers()
        root = Path('/var/lib/ouf-storage-migration')
        need(root.is_dir(), 'EXISTING_EVIDENCE_DIRECTORY_REQUIRED')
        work = Path(tempfile.mkdtemp(prefix='discovery-activation-bindings-', dir=root))
        report['privateEvidenceDirectory'] = str(work)
        collect(report, work, h, c)
    except Exception as exc:
        report.update(status='READ_INCOMPLETE', reason=safe_reason(exc))
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'DISCOVERY_ACTIVATION_BINDINGS_READ' else 1


if __name__ == '__main__':
    sys.exit(main())
