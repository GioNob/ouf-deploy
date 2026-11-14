#!/usr/bin/env python3
"""Read exact stopped v2 startup inputs. No startup, grant, token or DB request.

Host sources of stopped mounts are inspected; this is not the mounted application
view or runtime admission. Embedded TLS keys in APISIX resources stay in memory.
One exact previously prepared credential may be read for equality, never emitted.
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
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

HELPER = 'read-analysis-discovery-runtime-20261107.py'
HELPER_SHA = 'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4'
PINS = {
 'semantic': ('ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a', '1ff2ed51293a5295016c0cfe713c87dba519322543b2d0c3ccbb802f3f63c3e7'),
 'adapter': ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67', 'd1bcd2f2a288eeb22fcfaae01a86275d5e3371c56ebf353f8bdeb73852a6adbf'),
 'southbound': ('1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916', '446e80d16964a334e528243309c74c330f896642957fea9b247522f17fb8c9de'),
}
MATERIAL_ROOT = Path('/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1')
MATERIAL_HASH = '68daa9c9af2e3d5b41aceff988405e78a6fd3cb90a8c71f922816dd85964d392'
TRUST_PATH = Path('/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1/provider-trust.p12')
TRUST_SHA = '33418234a5428623b3f82e4219b1c29e014a14de1a537452366d9e54878c9559'
KNOWN_STATES = {'STAGED','PREPARING','CREATING','ADMITTED','CREATED','STARTING','STARTED','DELETING','DELETED'}


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def reason(exc):
    return str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def exact_path(value):
    need(isinstance(value, str) and re.fullmatch('/[A-Za-z0-9_./-]+', value)
         and str(Path(value)) == value and '..' not in Path(value).parts, 'EXACT_ABSOLUTE_PATH_REQUIRED')
    return Path(value)


class Reader:
    def __init__(self):
        self.seals = {}
        self.raw = {}
        self.counts = {}
        self.bytes = 0

    def read(self, path, kind, maximum=1048576):
        path = exact_path(str(path))
        need(any(path.is_relative_to(root) for root in ('/etc/ouf', '/opt/ouf', '/usr/local/sbin')), 'BOUND_SOURCE_ROOT_REQUIRED')
        need(sum(self.counts.values()) < 40, 'FILE_COUNT_LIMIT')
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        fd = None
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'BOUNDED_REGULAR_SOURCE_REQUIRED')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(maximum + 1)
            pin = lambda s: [getattr(s, k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
            need(len(raw) == before.st_size and pin(before) == pin(os.fstat(fd)) == pin(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'SOURCE_CHANGED_DURING_READ')
            meta = {'uid': before.st_uid, 'gid': before.st_gid, 'modeOctal': format(stat.S_IMODE(before.st_mode), '04o'), 'bytes': before.st_size, 'links': before.st_nlink}
            record = {'sha256': sha(raw), 'identity': pin(before), 'metadata': meta}
            need(str(path) not in self.seals or self.seals[str(path)] == record, 'SOURCE_CHANGED_BETWEEN_READS')
            self.seals[str(path)] = record
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.bytes += len(raw)
            need(self.bytes <= 16777216, 'READ_BYTE_LIMIT')
            return raw
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def value(self, path, kind='runtimeMetadata', maximum=1048576):
        raw = self.read(path, kind, maximum)
        return json.loads(raw.removesuffix(b'\n#END\n').removesuffix(b'\n#END'))


def host_source(doc, destination):
    path = exact_path(destination)
    matches = [m for m in doc['Mounts'] if path == Path(m['Destination']) or path.is_relative_to(Path(m['Destination']))]
    need(bool(matches), 'NO_DECLARED_MOUNT')
    m = max(matches, key=lambda x: len(x['Destination']))
    need(m['Type'] == 'bind' and m['RW'] is False, 'READ_ONLY_BIND_REQUIRED')
    return exact_path(str(Path(m['Source']) / path.relative_to(m['Destination'])))


def engine_info():
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect('/run/docker.sock')
    conn = Local('localhost', timeout=5)
    try:
        conn.request('GET', '/v1.44/info')
        response = conn.getresponse()
        raw = response.read(2097153)
        need(response.status == 200 and len(raw) <= 2097152, 'ENGINE_INFO_READ_FAILED')
        return json.loads(raw)
    finally:
        conn.close()


def runtime(doc, info, reader):
    name = doc['HostConfig'].get('Runtime')
    if name in (None, '', 'runc', 'io.containerd.runc.v2'):
        return {'classification': 'STANDARD_RUNTIME', 'startAdmitted': False}
    registration = info.get('Runtimes', {}).get(name)
    need(isinstance(registration, dict), 'REGISTERED_RUNTIME_MISSING')
    wrapper = exact_path(registration['path'])
    need(wrapper.parent == Path('/usr/local/sbin') and wrapper.name.startswith('ouf-'), 'OUF_RUNTIME_WRAPPER_REQUIRED')
    raw = reader.read(wrapper, 'runtimeMetadata', 65536)
    match = re.fullmatch(rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+/scripts/semantic_provider_docker_runtime.py) --configuration (/[A-Za-z0-9_./-]+) "\$@"\n', raw)
    need(match is not None, 'RUNTIME_WRAPPER_SHAPE_UNRECOGNIZED')
    source = exact_path(match[2].decode())
    cfg_path = exact_path(match[3].decode())
    need(source.is_relative_to('/etc/ouf') and cfg_path.is_relative_to('/etc/ouf'), 'RUNTIME_METADATA_ROOT_REQUIRED')
    cfg = reader.value(cfg_path)
    need(cfg.get('schema') in ['ouf.semantic-docker-runtime-adapter.v' + str(n) for n in range(1, 5)], 'RUNTIME_SCHEMA_UNRECOGNIZED')
    source_matches = sha(reader.read(source, 'runtimeSource')) == cfg.get('sourceHash')
    candidates = cfg.get('candidates')
    need(isinstance(candidates, dict) and len(candidates) <= 16, 'BOUNDED_CANDIDATES_REQUIRED')
    result = {'classification': 'OUF_CUSTOM_RUNTIME', 'adapterSchema': cfg['schema'], 'sourceMatchesConfiguration': source_matches,
              'wrapperSha256': sha(raw), 'configurationSha256': reader.seals[str(cfg_path)]['sha256'],
              'candidateCount': len(candidates), 'candidatePresent': doc['Id'] in candidates, 'startAdmitted': False}
    if doc['Id'] not in candidates:
        return result
    registry = exact_path(cfg['registryRoot'])
    need(registry.is_relative_to('/etc/ouf'), 'RUNTIME_REGISTRY_ROOT_REQUIRED')
    entry = cfg if cfg['schema'].endswith('.v1') else candidates[doc['Id']]
    broker_path = registry / doc['Id'] / 'broker.json'
    need(entry.get('admissionConfiguration') == str(broker_path), 'EXACT_CANDIDATE_BROKER_REQUIRED')
    broker_raw = reader.read(broker_path, 'runtimeMetadata')
    result['brokerHashMatchesConfiguration'] = sha(broker_raw) == entry.get('admissionConfigurationHash')
    broker = json.loads(broker_raw)
    result['brokerSchemaRecognized'] = broker.get('schema') == 'ouf.semantic-deployment-broker.v1'
    try:
        journal = reader.value(registry / doc['Id'] / 'adapter.json')
    except FileNotFoundError:
        return dict(result, journalState='FILE_NOT_FOUND')
    need(journal.get('schema') == 'ouf.semantic-docker-runtime-journal.v1' and journal.get('containerId') == doc['Id'], 'CURRENT_CANDIDATE_JOURNAL_REQUIRED')
    result['journalState'] = journal.get('state') if journal.get('state') in KNOWN_STATES else 'UNRECOGNIZED'
    result['historicalAuthorityReused'] = False
    return result


def certificate(pem, hostname):
    need(isinstance(pem, str) and len(pem) <= 65536 and 'PRIVATE KEY' not in pem, 'PUBLIC_CERTIFICATE_ONLY')
    need(re.fullmatch('[A-Za-z0-9.-]{1,253}', hostname), 'CERTIFICATE_HOST_REQUIRED')
    result = subprocess.run(['/usr/bin/openssl', 'x509', '-noout', '-dates', '-checkhost', hostname], input=pem.encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, env={'PATH':'/usr/bin:/bin', 'LC_ALL':'C'})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and len(result.stderr) <= 4096, 'CERTIFICATE_PARSE_FAILED')
    lines = result.stdout.decode('ascii').splitlines()
    dates = {k: v for row in lines if '=' in row for k, v in [row.split('=', 1)] if k in ('notBefore', 'notAfter')}
    need(set(dates) == {'notBefore', 'notAfter'}, 'CERTIFICATE_DATES_REQUIRED')
    parsed = {k: datetime.strptime(v, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc) for k, v in dates.items()}
    now = datetime.now(timezone.utc)
    return {'notBefore': parsed['notBefore'].isoformat(), 'notAfter': parsed['notAfter'].isoformat(),
            'validAtRead': parsed['notBefore'] <= now <= parsed['notAfter'],
            'hostnameMatches': any(row == 'Hostname ' + hostname + ' does match certificate' for row in lines),
            'chainVerified': False, 'tlsHandshakeTested': False}


def config_summary(adapter, south, semantic, reader, h):
    adapter_path = '/run/ouf-semantic-provider/adapter.json'
    need(adapter['Config'].get('Cmd') == ['--configuration', adapter_path], 'KNOWN_ADAPTER_ARGUMENTS_REQUIRED')
    cfg = reader.value(host_source(adapter, adapter_path), 'applicationConfig', 32768)
    sb = reader.value(host_source(south, '/usr/local/apisix/conf/config.yaml'), 'applicationConfig')
    resources = reader.value(host_source(south, '/usr/local/apisix/conf/apisix.yaml'), 'applicationConfigWithEmbeddedTlsKey')
    env = h.environment(semantic)
    result = {'scope': 'CURRENT_HOST_SOURCES_OF_STOPPED_MOUNTS_NOT_APPLICATION_VIEW',
              'adapterLaunchMatchesHistoricalSource': adapter['Config'].get('Entrypoint') == ['python3','-B','-m','tools.semantic_provider_adapter'],
              'southboundLaunchMatchesHistoricalSource': south['Config'].get('Entrypoint') == ['/docker-entrypoint.sh'] and south['Config'].get('Cmd') == ['docker-start'],
              'adapterListenPort': cfg.get('listenPort') if type(cfg.get('listenPort')) is int else None,
              'adapterSearchPathMatchesSemantic': cfg.get('searchPath') == env.get('OUF_SCHEMA_GOV_SEARCH_PATH'),
              'adapterFetchPathMatchesSemantic': cfg.get('fetchPath') == env.get('OUF_SCHEMA_GOV_FETCH_PATH'),
              'adapterWorkloadMatchesSemanticClient': cfg.get('admission', {}).get('workload') == env.get('OUF_SCHEMA_GOV_CLIENT_ID'),
              'adapterScopeMatchesSemantic': cfg.get('admission', {}).get('scope') == env.get('OUF_SCHEMA_GOV_WORKLOAD_SCOPE'),
              'southboundTlsEnabled': sb.get('apisix', {}).get('ssl', {}).get('enable') is True,
              'southboundAdminEnabled': sb.get('apisix', {}).get('enable_admin'), 'routes': []}
    snippet = sb.get('nginx_config', {}).get('http_configuration_snippet', '')
    result['nginxDeclaredProxySslVerify'] = re.findall(r'^\s*proxy_ssl_verify\s+(on|off)\s*;', snippet, re.M)
    expected = {env.get('OUF_SCHEMA_GOV_SEARCH_PATH'): 'POST', env.get('OUF_SCHEMA_GOV_FETCH_PATH'): 'GET'}
    routes = resources.get('routes', [])
    need(isinstance(routes, list) and len(routes) <= 16, 'BOUNDED_PROVIDER_ROUTES_REQUIRED')
    for path, method in expected.items():
        found = [v for v in routes if v.get('uri') == path]
        row = {'operation': 'search' if method == 'POST' else 'fetch', 'matchingRoutes': len(found)}
        if len(found) == 1:
            route = found[0]; oidc = route.get('plugins', {}).get('openid-connect', {})
            upstream = route.get('upstream', {})
            secret_ref = oidc.get('client_secret', '')
            row.update(methodMatches=route.get('methods') == [method], upstreamHttps=upstream.get('scheme') == 'https',
                upstreamHostMatchesAdapter=upstream.get('upstream_host') == 'ouf-semantic-provider-v2',
                audienceMatchesAdapter=oidc.get('client_id') == cfg.get('admission', {}).get('audience'),
                requiredScopesMatchSemantic=oidc.get('required_scopes') == [env.get('OUF_SCHEMA_GOV_WORKLOAD_SCOPE')],
                oidcTlsVerify=oidc.get('ssl_verify'), bearerOnly=oidc.get('bearer_only'),
                secretEnvironmentReferencePresent=bool(re.fullmatch(r'\$ENV://[A-Z][A-Z0-9_]{1,127}', secret_ref) and h.environment(south).get(secret_ref[7:])))
        result['routes'].append(row)
    ssls = resources.get('ssls', [])
    need(isinstance(ssls, list) and len(ssls) == 1, 'SINGLE_SOUTHBOUND_CERTIFICATE_REQUIRED')
    result['southboundSniMatches'] = ssls[0].get('snis') == ['ouf-semantic-southbound-v2']
    for name, operation in (
            ('southboundCertificate', lambda: certificate(ssls[0].get('cert'), 'ouf-semantic-southbound-v2')),
            ('adapterCertificate', lambda: certificate(reader.read(host_source(adapter, cfg['tlsCertificateFile']), 'publicCertificate', 65536).decode('ascii'), 'ouf-semantic-provider-v2'))):
        try:
            result[name] = operation()
        except Exception as exc:
            result[name] = {'status': 'READ_INCOMPLETE', 'reason': reason(exc)}
    # Standalone key and receipt-key contents are not opened.
    result['adapterKeyMountsDeclared'] = all(any(m['Destination'] == cfg[k] and m['Type'] == 'bind' and not m['RW'] for m in adapter['Mounts']) for k in ('tlsPrivateKeyFile', 'receiptKeyFile'))
    return result


def prepared_material(semantic, reader, h):
    value = reader.value(MATERIAL_ROOT / 'prepared-inputs.private.json', 'retainedPreparationMetadata', 4194304)
    need(sha(encoded(value)) == MATERIAL_HASH, 'PREPARED_MATERIAL_METADATA_CHANGED')
    need(value.get('schema') == 'ouf.m2-discovery-private-material-role-preparation.v1', 'PREPARED_MATERIAL_SCHEMA_REQUIRED')
    retained = value['preparedCopies']['providerCredential']
    source = MATERIAL_ROOT / 'schema-gov-client-secret'
    need(retained.get('path') == str(source), 'EXACT_PREPARED_CREDENTIAL_REFERENCE_REQUIRED')
    raw = reader.read(source, 'preparedCredential', 4096)
    meta = reader.seals[str(source)]['metadata']
    before = h.environment(value['selectedInstallationObservations']['semantic'])
    current = h.environment(semantic)
    matching = {key: before.get(key) == current.get(key) and bool(current.get(key)) for key in ('OUF_SCHEMA_GOV_CLIENT_ID', 'OUF_SCHEMA_GOV_WORKLOAD_SCOPE', 'OUF_SCHEMA_GOV_TOKEN_ENDPOINT')}
    result = {'status': 'PREPARED_MATERIAL_READ_NOT_INSTALLED', 'credentialBytesMatchRetained': sha(raw) == retained.get('sha256'),
            'credentialMetadata': meta, 'credentialAcceptedCustody': meta['uid'] == 0 and meta['gid'] == 10001 and meta['modeOctal'] == '0440' and meta['links'] == 1,
            'credentialIdentityDeclarationsMatchRetained': matching, 'credentialValidityAtIssuerTested': False,
            'credentialInstalled': False, 'truststoreInstalled': False}
    try:
        public_store = reader.read(TRUST_PATH, 'preparedPublicTruststore', 1048576)
        result.update(preparedPublicTruststoreMatchesRetained=sha(public_store) == TRUST_SHA,
                      preparedPublicTruststoreMetadata=reader.seals[str(TRUST_PATH)]['metadata'])
    except Exception as exc:
        result['preparedPublicTruststore'] = {'status': 'READ_INCOMPLETE', 'reason': reason(exc)}
    return result


def collect(report, h, reader, inspect=None, get_info=engine_info):
    inspect = inspect or h.inspect
    docs = {}
    for role, (cid, frame) in PINS.items():
        doc = inspect(cid)
        need(h.digest(h.frame(doc)) == frame, 'CURRENT_RECEIPT_FRAME_CHANGED')
        docs[role] = doc
    need(not docs['adapter']['State']['Running'] and not docs['southbound']['State']['Running'], 'STOPPED_V2_COMPONENTS_REQUIRED')
    info = get_info()
    report['runtime'] = {}
    for role in ('adapter', 'southbound'):
        try:
            report['runtime'][role] = runtime(docs[role], info, reader)
        except Exception as exc:
            report['runtime'][role] = {'status': 'READ_INCOMPLETE', 'reason': reason(exc), 'startAdmitted': False}
    for name, operation in (
            ('configuration', lambda: config_summary(docs['adapter'], docs['southbound'], docs['semantic'], reader, h)),
            ('preparedMaterial', lambda: prepared_material(docs['semantic'], reader, h))):
        try:
            report[name] = operation()
        except Exception as exc:
            report[name] = {'status': 'READ_INCOMPLETE', 'reason': reason(exc)}
    for role, before in docs.items():
        need(h.frame(inspect(before['Id'])) == h.frame(before), 'CONTAINER_CHANGED_DURING_READ')
    after_info = get_info()
    need(all(info.get(k) == after_info.get(k) for k in ('ID','ServerVersion','Driver','Runtimes')), 'RUNTIME_REGISTRATION_CHANGED_DURING_READ')
    report.update(status='DISCOVERY_STARTUP_INPUTS_READ', runtimeUnchangedDuringRead=True, fileReads=reader.counts,
                  hostFileBytesRead=reader.bytes, serviceStartDispatched=False)


def main():
    report = {'schema': 'ouf.discovery-startup-inputs.v1', 'status': 'READ_INCOMPLETE',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'serviceConfigurationChanged': False,
              'serviceStartDispatched': False, 'serviceStops': 0, 'credentialValuesEmitted': False,
              'rawConfigurationEmitted': False, 'embeddedPrivateTlsKeyMayBeRead': True,
              'databaseRequests': 0, 'providerRequests': 0, 'tokenRequests': 0, 'businessRequestsIssued': 0,
              's3Requests': 0, 'legacyProviderTouched': False, 'currentRuntimeCodeExecuted': False,
              'historicalAuthorityReused': False, 'runtimeUnchangedDuringRead': False}
    def deadline(*_):
        raise RuntimeError('READ_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(90)
    reader = Reader()
    try:
        need(os.geteuid() == 0, 'ROOT_READER_REQUIRED')
        os.umask(0o077)
        p = Path(__file__).with_name(HELPER); raw = p.read_bytes()
        need(sha(raw) == HELPER_SHA, 'HELPER_HASH_MISMATCH')
        h = importlib.util.module_from_spec(importlib.util.spec_from_file_location('pinned_inspect', p))
        exec(compile(raw, str(p), 'exec'), h.__dict__)
        root = Path('/var/lib/ouf-storage-migration')
        need(root.is_dir(), 'EXISTING_EVIDENCE_ROOT_REQUIRED')
        work = Path(tempfile.mkdtemp(prefix='discovery-startup-inputs-', dir=root))
        report['privateEvidenceDirectory'] = str(work)
        collect(report, h, reader)
        # Paths and file digests (including the credential digest) remain private.
        (work / 'source-bindings.private.json').write_bytes(encoded(reader.seals) + b'\n')
    except Exception as exc:
        report.update(status='READ_INCOMPLETE', reason=reason(exc))
    finally:
        signal.alarm(0)
        report['fileReads'] = reader.counts
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'DISCOVERY_STARTUP_INPUTS_READ' else 1


if __name__ == '__main__':
    sys.exit(main())
