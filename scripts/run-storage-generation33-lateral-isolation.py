#!/usr/bin/env python3
"""Disposable five-namespace OCI33 fixture with pre-launch nft role boundaries.

IPv4 connection-level matrix only; allowed internal APIs remain trusted/plaintext.
No target policy, production topology or application-level gRPC authorization claim.
"""
import argparse
import errno
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lateral_credentials33', ROOT / 'scripts/run-storage-generation33-credential-rotation.py')
keys = importlib.util.module_from_spec(spec); spec.loader.exec_module(keys)
stream_spec = importlib.util.spec_from_file_location('interrupted_stream33', ROOT / 'scripts/storage-generation33-stream-interruption.py')
stream = importlib.util.module_from_spec(stream_spec); stream_spec.loader.exec_module(stream)
cleanup_spec = importlib.util.spec_from_file_location('orphan_cleanup33', ROOT / 'scripts/storage-generation33-orphan-cleanup.py')
cleanup = importlib.util.module_from_spec(cleanup_spec); cleanup_spec.loader.exec_module(cleanup)
compact_spec = importlib.util.spec_from_file_location('compaction33', ROOT / 'scripts/storage-generation33-compaction.py')
compact = importlib.util.module_from_spec(compact_spec); compact_spec.loader.exec_module(compact)
labs, require, binding = keys.labs, keys.require, keys.binding
LOCK_SHA, COHORT_SHA = keys.LOCK_SHA, keys.COHORT_SHA
COHORT_ARTIFACT_ID, COHORT_ARCHIVE_SHA, COHORT_ARCHIVE_BYTES = keys.COHORT_ARTIFACT_ID, keys.COHORT_ARCHIVE_SHA, keys.COHORT_ARCHIVE_BYTES
ROLES = ('master', 'volume', 'filer', 's3', 'client')
SERVICES = ROLES[:-1]
IPS = {role: '172.30.233.' + str(10 + i) for i, role in enumerate(ROLES)}
PORTS = {'master': (19333, 29333), 'volume': (18080, 28080), 'filer': (18888, 28888), 's3': (18333, 28333)}
ALLOW = {('client', 's3', 18333), ('volume', 'master', 29333), ('master', 'volume', 28080),
         ('filer', 'master', 29333), ('filer', 'volume', 18080), ('filer', 'volume', 28080),
         ('s3', 'master', 29333), ('s3', 'filer', 18888), ('s3', 'filer', 28888), ('s3', 'volume', 18080)}
GATEWAY = '172.30.233.1'
VOLUME_KEY = 'staging/volume-crash.bin'
VOLUME_BYTES = 8 * 1024 * 1024 + 257


def volume_body():
    # Deterministic, incompressible fixture; exceeds inline/small-object paths.
    return keys.hashlib.shake_256(b'OUF OCI33 volume crash fixture v1').digest(VOLUME_BYTES)


def validate_killed_role(before, killed):
    require(killed['Id'] == before['Id'] and before['State']['Running']
            and not killed['State']['Running'] and killed['State']['ExitCode'] == 137
            and not killed['State']['OOMKilled'] and not killed['State']['Error'], 'EXACT_ROLE_SIGKILL_REQUIRED')


validate_killed_volume = validate_killed_role


def validate_retained_roles(before, after, replaced='volume'):
    require(replaced in ('volume', 'filer', 'master', 'all'), 'BOUNDED_CRASH_ROLE_REQUIRED')
    replaced_roles = SERVICES if replaced == 'all' else (replaced,)
    require(set(before) == set(after) == set(ROLES), 'EXACT_ROLE_SET_REQUIRED')
    for role in ROLES:
        old, new = before[role], after[role]
        require(new['State']['Running'] and not new['State']['OOMKilled'], 'LIVE_ROLES_REQUIRED')
        if role in replaced_roles:
            require(old['Id'] != new['Id'], 'NEW_ROLE_CONTAINER_REQUIRED')
        else:
            require(old['Id'] == new['Id'] and old['State']['StartedAt'] == new['State']['StartedAt']
                    and old['RestartCount'] == new['RestartCount'] == 0, 'OTHER_ROLES_MUST_NOT_RESTART')


def validate_all_killed(before, killed):
    require(set(before) == set(ROLES) and set(killed) == set(SERVICES), 'EXACT_KILLED_SERVICE_SET_REQUIRED')
    require(len({x['Id'] for x in killed.values()}) == 4, 'FOUR_DISTINCT_KILLED_SERVICES_REQUIRED')
    for role in SERVICES: validate_killed_role(before[role], killed[role])


def validate_replacement_namespaces(old, new, host):
    require(set(old) == set(ROLES) and set(new) == set(SERVICES), 'EXACT_REPLACEMENT_NAMESPACE_SET_REQUIRED')
    require(len(set(new.values())) == 4 and host not in new.values()
            and not set(new.values()).intersection(old.values()), 'FOUR_FRESH_NONHOST_NAMESPACES_REQUIRED')


def validate_closed_gate(path):
    require(path.is_dir() and not path.is_symlink() and all(not (path/name).exists() and not (path/name).is_symlink()
            for name in ('open','open.tmp')), 'FRESH_CLOSED_REPLACEMENT_GATES_REQUIRED')


def publish_gate(path):
    validate_closed_gate(path)
    temporary=path/'open.tmp'
    with temporary.open('x') as output: output.write('READY\n')
    temporary.replace(path/'open')


def release_replacement_gates(gates):
    require(set(gates) in ({'master'}, {'volume'}, {'filer'}, set(SERVICES)), 'EXACT_GATE_SET_REQUIRED')
    for path in gates.values(): validate_closed_gate(path)
    for path in gates.values(): publish_gate(path)


def volume_inventory(root, previous=None):
    require(root.is_dir() and not root.is_symlink(), 'REGULAR_VOLUME_ROOT_REQUIRED')
    paths = sorted(root.glob('*.dat'))
    require(0 < len(paths) <= 64 and all(p.is_file() and not p.is_symlink() for p in paths), 'BOUNDED_DAT_FILES_REQUIRED')
    require(sum(p.stat().st_size for p in paths) <= 128 * 1024 * 1024, 'VOLUME_DATA_BUDGET')
    result = {}
    for path in paths:
        size = path.stat().st_size
        length = previous[path.name]['bytes'] if previous and path.name in previous else size
        require(0 <= length <= size <= 32 * 1024 * 1024 + 1024 * 1024, 'DAT_PREFIX_LENGTH_REQUIRED')
        with path.open('rb') as stream: raw = stream.read(length)
        require(len(raw) == length, 'COMPLETE_DAT_PREFIX_REQUIRED')
        result[path.name] = {'bytes': length, 'sha256': keys.sha(raw)}
    if previous is not None:
        require(all(result.get(name) == value for name, value in previous.items()), 'ORIGINAL_DAT_PREFIX_MUST_SURVIVE')
    return result


def filer_inventory(root):
    """Hash the stopped LevelDB tree; never open it with a database client."""
    require(root.is_dir() and not root.is_symlink(), 'REGULAR_FILER_ROOT_REQUIRED')
    paths = sorted(root.rglob('*'))
    require(0 < len(paths) <= 512 and not any(p.is_symlink() for p in paths), 'BOUNDED_FILER_TREE_REQUIRED')
    require(all(p.is_dir() or p.is_file() for p in paths), 'REGULAR_FILER_FILES_REQUIRED')
    files = [p for p in paths if p.is_file()]
    require(sum(p.stat().st_size for p in files) <= 32 * 1024 * 1024, 'FILER_METADATA_BUDGET')
    result = {str(p.relative_to(root)): {'bytes': p.stat().st_size, 'sha256': keys.sha(p.read_bytes())} for p in files}
    require(any(p.name == 'CURRENT' for p in files) and any(p.name.startswith('MANIFEST-') for p in files)
            and any(p.suffix in ('.log', '.ldb', '.sst') and p.stat().st_size > 0 for p in files),
            'PERSISTED_LEVELDB_FILES_REQUIRED')
    return result


def validate_filer_metadata(value, bucket):
    require(value.get('FullPath') == '/buckets/' + bucket + '/' + VOLUME_KEY
            and value.get('FileSize') == VOLUME_BYTES and value.get('Mime') == keys.MIME
            and not value.get('Content') and isinstance(value.get('chunks'), list)
            and 0 < len(value['chunks']) <= 64, 'EXACT_PERSISTED_FILER_METADATA_REQUIRED')
    require(all(isinstance(c, dict) and c.get('file_id') and isinstance(c.get('size'), int)
                and c['size'] > 0 for c in value['chunks']), 'PERSISTED_CHUNK_REFERENCES_REQUIRED')
    require(sum(c['size'] for c in value['chunks']) == VOLUME_BYTES, 'COMPLETE_CHUNK_BYTES_REQUIRED')


def filer_metadata():
    module = keys.tls_rotation.load('filer_metadata_signer', ROOT / 'scripts/run-seaweedfs-452-identity-tls.py')
    connection = http.client.HTTPConnection(IPS['filer'], 18888, timeout=10)
    try:
        path = '/buckets/' + module.BUCKET + '/' + VOLUME_KEY + '?metadata=true'
        connection.request('GET', path, headers={'Accept': 'application/json'})
        response = connection.getresponse(); raw = response.read(256 * 1024 + 1)
        require(response.status == 200 and len(raw) <= 256 * 1024, 'BOUNDED_DIRECT_FILER_METADATA_REQUIRED')
        value = json.loads(raw); validate_filer_metadata(value, module.BUCKET)
        return {'status': 200, 'metadata': value, 'mutatingRequests': 0, 'bodyReads': 0}
    finally: connection.close()


def master_inventory(root):
    require(root.is_dir() and not root.is_symlink(), 'REGULAR_MASTER_ROOT_REQUIRED')
    paths = sorted(root.rglob('*'))
    require(0 < len(paths) <= 128 and not any(p.is_symlink() for p in paths)
            and all(p.is_dir() or p.is_file() for p in paths), 'BOUNDED_REGULAR_MASTER_TREE_REQUIRED')
    files = [p for p in paths if p.is_file()]
    require(0 < sum(p.stat().st_size for p in files) <= 32 * 1024 * 1024, 'MASTER_STORAGE_BUDGET')
    return {str(p.relative_to(root)): {'bytes': p.stat().st_size, 'sha256': keys.sha(p.read_bytes())} for p in files}


def master_lookup_ids(metadata):
    value = metadata['metadata']
    validate_filer_metadata(value, 'ouf-identity-fixture')
    ids = sorted({c['file_id'].split(',')[0] for c in value['chunks']})
    require(0 < len(ids) <= 64 and all(v.isascii() and v.isdigit() and 0 < int(v) <= 2**32-1 for v in ids),
            'BOUNDED_CHUNK_VOLUME_IDS_REQUIRED')
    return ids


def master_http(path):
    require(path in ('/readyz', '/dir/status') or
            (path.startswith('/dir/lookup?volumeId=') and path.removeprefix('/dir/lookup?volumeId=').isascii()
             and path.removeprefix('/dir/lookup?volumeId=').isdigit()), 'READ_ONLY_MASTER_PATH_REQUIRED')
    connection = http.client.HTTPConnection('127.0.0.1', 19333, timeout=5)
    try:
        connection.request('GET', path, headers={'Accept': 'application/json'})
        response = connection.getresponse(); raw = response.read(256 * 1024 + 1)
        require(len(raw) <= 256 * 1024, 'BOUNDED_MASTER_RESPONSE_REQUIRED')
        retry = response.getheader('Retry-After')
        require(retry is None or (retry.isascii() and retry.isdigit()), 'VALID_MASTER_RETRY_AFTER_REQUIRED')
        return {'path': path, 'status': response.status, 'retryAfterSeconds': int(retry or '0'),
                'body': json.loads(raw) if raw else None}
    finally: connection.close()


def master_topology(metadata, requester=master_http):
    ids = master_lookup_ids(metadata); replies = []
    def get(path):
        value = requester(path); replies.append(value); return value
    def waiting(response):
        return {'status': 'MASTER_REGISTRATION_PENDING', 'responses': replies,
                'retryAfterSeconds': response['retryAfterSeconds'], 'mutatingRequests': 0}
    ready = get('/readyz')
    if ready['status'] == 503: return waiting(ready)
    require(ready['status'] == 200, 'MASTER_READY_REQUIRED')
    status = get('/dir/status')
    require(status['status'] == 200 and isinstance(status['body'], dict)
            and status['body'].get('TopologyId') and isinstance(status['body'].get('Topology'), dict),
            'MASTER_TOPOLOGY_ID_REQUIRED')
    locations = {}
    for vid in ids:
        result = get('/dir/lookup?volumeId=' + vid)
        if result['status'] in (404, 503): return waiting(result)
        body = result['body']
        require(result['status'] == 200 and body.get('volumeOrFileId') == vid and not body.get('error')
                and len(body.get('locations', [])) == 1, 'EXACT_VOLUME_REGISTRATION_REQUIRED')
        location = body['locations'][0]
        require(location.get('url') == IPS['volume'] + ':18080' and location.get('grpcPort') == 28080
                and not location.get('dataInRemote') and not location.get('readOnly'), 'SAME_LOCAL_VOLUME_REQUIRED')
        locations[vid] = body
    return {'status': 'MASTER_TOPOLOGY_READY', 'topologyId': status['body']['TopologyId'],
            'locations': locations, 'responses': replies, 'mutatingRequests': 0}


def validate_master_recovery(before, after):
    require(before['status'] == after['status'] == 'MASTER_TOPOLOGY_READY'
            and before['topologyId'] == after['topologyId']
            and before['locations'] == after['locations'], 'MASTER_TOPOLOGY_AND_LOCATIONS_MUST_SURVIVE')


def master_registration_log(log):
    # Only the new container's log is accepted by the controller.
    required = ['+ client .filer@' + IPS['filer'] + ':18888.28888',
                '+ client .s3@' + IPS['s3'] + ':28333']
    return all(marker in log for marker in required)


def master_retry_delay(attempt, retry_after, now, deadline):
    require(1 <= attempt < 10 and isinstance(retry_after, int) and retry_after >= 0, 'BOUNDED_MASTER_RETRY_REQUIRED')
    base = (1, 2, 4, 8, 15, 15, 15, 15, 15)[attempt - 1]
    delay = max(base * (1 + int.from_bytes(os.urandom(2), 'big') / 65535 * 0.2), retry_after)
    require(now + delay < deadline, 'MASTER_RETRY_AFTER_EXCEEDS_TIME_BUDGET')
    return delay


def allow_links(cleanup_stream=False):
    return ALLOW | ({('s3', 'volume', 28080)} if cleanup_stream else set())


def matrix(cleanup_stream=False):
    return [(src, dst, port, (src, dst, port) in allow_links(cleanup_stream))
            for src in ROLES for dst, ports in PORTS.items() if src != dst for port in ports]


def nft_rules(role, cleanup_stream=False):
    require(role in ROLES, 'KNOWN_ROLE_REQUIRED')
    counters = ['dns_tcp', 'dns_udp', 'egress_tcp', 'other_denied'] + [
        f'deny_{dst}_{port}' for src, dst, port, allowed in matrix(cleanup_stream) if src == role and not allowed]
    if role == 'volume': counters.append('volume_http_response_bytes')
    if role == 'filer': counters.append('filer_http_response_bytes')
    if cleanup_stream and role in ('s3','volume'): counters.append('cleanup_grpc_bytes')
    lines = ['table inet ouf_roles {'] + [f' counter {name} {{ }}' for name in counters]
    # -150 precedes Docker's OUTPUT destination NAT, including embedded DNS.
    lines += [' chain output { type filter hook output priority -150; policy drop;',
              ' tcp dport 53 counter name dns_tcp reject with icmpx type admin-prohibited',
              ' udp dport 53 counter name dns_udp reject with icmpx type admin-prohibited',
              f' ip daddr {GATEWAY} tcp dport 443 counter name egress_tcp reject with icmpx type admin-prohibited',
              ' oifname "lo" accept']
    if role == 'volume':
        lines.append(f' ip daddr {{ {IPS["filer"]}, {IPS["s3"]} }} tcp sport 18080 counter name volume_http_response_bytes')
    if role == 'filer':
        lines.append(f' ip daddr {IPS["s3"]} tcp sport 18888 counter name filer_http_response_bytes')
    if cleanup_stream and role == 's3':
        lines.append(f' ip daddr {IPS["volume"]} tcp dport 28080 counter name cleanup_grpc_bytes')
    if cleanup_stream and role == 'volume':
        lines.append(f' ip daddr {IPS["s3"]} tcp sport 28080 counter name cleanup_grpc_bytes')
    lines += [' ct state established,related accept']
    for src, dst, port, allowed in matrix(cleanup_stream):
        if src == role:
            action = 'accept' if allowed else f'counter name deny_{dst}_{port} reject with icmpx type admin-prohibited'
            lines.append(f' ip daddr {IPS[dst]} tcp dport {port} {action}')
    lines += [' counter name other_denied reject with icmpx type admin-prohibited', ' }',
              ' chain input { type filter hook input priority 0; policy drop;',
              ' iifname "lo" accept', ' ct state established,related accept']
    for src, dst, port in sorted(allow_links(cleanup_stream)):
        if dst == role: lines.append(f' ip saddr {IPS[src]} tcp dport {port} accept')
    lines += [' counter reject with icmpx type admin-prohibited', ' }',
              ' chain forward { type filter hook forward priority 0; policy drop; }', '}']
    return '\n'.join(lines) + '\n'


def role_args(role):
    ip = IPS[role]; master = IPS['master'] + ':19333'
    common = [role, '-ip=' + ip, '-ip.bind=0.0.0.0']
    if role == 'master': return common + ['-port=19333', '-port.grpc=29333', '-mdir=/data', '-peers=none',
        '-telemetry=false', '-volumeSizeLimitMB=32', '-defaultReplication=000']
    if role == 'volume': return common + ['-port=18080', '-port.grpc=28080', '-master=' + master,
        '-dir=/data', '-max=24', '-preStopSeconds=1']
    if role == 'filer': return common + ['-port=18888', '-port.grpc=28888', '-master=' + master, '-defaultStoreDir=/data']
    require(role == 's3', 'KNOWN_SERVICE_ROLE_REQUIRED')
    return common + ['-port=18333', '-port.grpc=28333', '-port.https=0', '-port.iceberg=0', '-port.lance=0',
        '-filer=' + IPS['filer'] + ':18888', '-config=/config/s3.json',
        '-key.file=/config/tls/server.key', '-cert.file=/config/tls/server.pem']


def s3_request(module, tls, credentials, method, key='', body=b'', query=None):
    path = '/' + module.BUCKET + ('/' + quote(key, safe='/~') if key else '')
    query = urlencode(sorted((query or {}).items()), quote_via=quote, safe='~')
    context = ssl.create_default_context(cafile=str(tls / 'ca.pem'))
    connection = http.client.HTTPConnection('localhost', 18333, timeout=10)
    try:
        raw = socket.create_connection((IPS['s3'], 18333), timeout=10)
        try: connection.sock = context.wrap_socket(raw, server_hostname='localhost')
        except Exception: raw.close(); raise
        connection.sock.settimeout(30 if key == VOLUME_KEY else 10)
        peer = keys.sha(connection.sock.getpeercert(binary_form=True))
        require(peer == keys.sha(ssl.PEM_cert_to_DER_cert((tls / 'server.pem').read_text())), 'EXACT_TLS_PEER_REQUIRED')
        headers = module.signed_headers(method, path, query, body, credentials); headers['content-type'] = keys.MIME
        connection.request(method, path + ('?' + query if query else ''), body=body, headers=headers)
        response = connection.getresponse(); payload = response.read(16 * 1024 * 1024 + 1)
        require(len(payload) <= 16 * 1024 * 1024, 'BOUNDED_S3_RESPONSE_REQUIRED')
        return {'status': response.status, 'body': payload, 'headers': {k.lower(): v for k, v in response.getheaders()},
                'peerSha256': peer}
    finally: connection.close()


def socket_probe(ip, port, protocol):
    require(ip in {*IPS.values(), GATEWAY, '127.0.0.1', '127.0.0.11'} and 0 < port < 65536, 'BOUNDED_PROBE_REQUIRED')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        try:
            sock.connect((ip, port))
            if protocol == 'udp': sock.send(b'OUF fixture DNS-deny probe'); sock.recv(1)
            return {'connected': True, 'errno': 0}
        except OSError as error:
            return {'connected': False, 'errno': error.errno, 'errorClass': type(error).__name__}


def client(action, config):
    module = keys.tls_rotation.load('lateral_s3_signer', ROOT / 'scripts/run-seaweedfs-452-identity-tls.py')
    if action == 'absent-interrupted':
        return stream.verify_absent(module, config / 'tls', s3_request, VOLUME_KEY, VOLUME_BYTES)
    if action == 'seed-volume':
        body = volume_body()
        for credentials, key, data in [(module.OWNER, '', b''), (module.APP, VOLUME_KEY, body)]:
            require(s3_request(module, config / 'tls', credentials, 'PUT', key, data)['status'] == 200,
                    'ACKNOWLEDGED_VOLUME_SEED_REQUIRED')
        return {'putStatus': 200, 'acknowledgedObject': {'key': VOLUME_KEY, 'bytes': len(body),
                'sha256': keys.sha(body), 'mime': keys.MIME}, 'mutatingRequests': 2, 'bodyReadsBeforeCrash': 0}
    if action == 'read-volume':
        class TransientRead(Exception): pass
        def checked(*args, **kwargs):
            response = s3_request(*args, **kwargs)
            if response['status'] in (500, 502, 503, 504): raise TransientRead(response['status'])
            return response
        try:
            result = keys.read_objects(module, config / 'tls', module.APP, {VOLUME_KEY: volume_body()}, checked)
        except TransientRead as error:
            return {'status': 'TRANSIENT_READ_FAILURE', 'httpStatus': error.args[0], 'mutatingRequests': 0}
        return {**result, 'mutatingRequests': 0}
    if action == 'seed':
        for credentials, key, body in [(module.OWNER, '', b''), (module.APP, keys.KEY, keys.BODY)]:
            require(s3_request(module, config / 'tls', credentials, 'PUT', key, body)['status'] == 200, 'ONE_TIME_S3_SEED_REQUIRED')
    require(action in ('seed', 'read'), 'KNOWN_CLIENT_ACTION_REQUIRED')
    result = keys.read_objects(module, config / 'tls', module.APP, {keys.KEY: keys.BODY}, s3_request)
    result['mutatingRequests'] = 2 if action == 'seed' else 0
    return result


def container_argv(image, name, network, data, config, gate_binary, role, gate_dir):
    require(role in ROLES, 'KNOWN_CONTAINER_ROLE_REQUIRED')
    args = ['--hold'] if role == 'client' else ['/usr/local/bin/weed', '-logtostderr=true', *role_args(role)]
    return ['docker', 'run', '--detach', '--name', name, '--network', network, '--ip', IPS[role],
                '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '128', '--memory', '512m', '--cpus', '1', '--log-opt', 'max-size=8m',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864,mode=1777',
                '--mount', 'type=bind,src=' + str(data / role) + ',dst=/data',
                '--mount', 'type=bind,src=' + str(config) + ',dst=/config,readonly',
                '--mount', 'type=bind,src=' + str(gate_dir) + ',dst=/gate,readonly',
                '--mount', 'type=bind,src=' + str(gate_binary) + ',dst=/network-gate,readonly',
                '--entrypoint', '/network-gate', image, '/gate/open', *args]


def pin_network_namespace(pid, path, expected, command):
    # Keep the old namespace alive so its inode cannot be recycled before comparison.
    require(str(pid).isdigit() and int(pid)>0 and expected.startswith('net:[') and expected.endswith(']'), 'EXACT_NAMESPACE_PIN_ID_REQUIRED')
    require(path.parent.is_dir() and not path.parent.is_symlink() and not path.exists() and not path.is_symlink(), 'FRESH_NAMESPACE_PIN_REQUIRED')
    path.touch(exist_ok=False)
    command(['sudo','-n','mount','--bind','/proc/'+str(pid)+'/ns/net',str(path)])
    try:
        inode=command(['sudo','-n','stat','-Lc','%i',str(path)]).strip()
        require('net:['+inode+']'==expected, 'PINNED_NAMESPACE_IDENTITY_REQUIRED')
    except Exception:
        command(['sudo','-n','umount',str(path)]);raise
    return {'namespace':expected,'sourcePid':int(pid),'bindMountVerified':True}


def run(archive, work, receipt, gate_binary, *, crash_volume=False, crash_filer=False, crash_master=False, crash_all=False, interrupt_stream=False, cleanup_stream=False, compact_stream=False):
    require(sum((crash_volume, crash_filer, crash_master, crash_all, interrupt_stream, cleanup_stream, compact_stream)) <= 1, 'ONE_CRASH_ROLE_PER_LAB_REQUIRED')
    cleanup_stream = cleanup_stream or compact_stream
    interrupt_stream = interrupt_stream or cleanup_stream
    crash_all = crash_all or interrupt_stream
    crash_role = 'volume' if crash_volume else 'filer' if crash_filer else 'master' if crash_master else 'all' if crash_all else None
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() != 0, 'UNPRIVILEGED_ISOLATED_CI_REQUIRED')
    require(not work.exists() and not work.is_symlink(), 'FRESH_WORK_REQUIRED')
    bound = binding(receipt); module = keys.tls_rotation.configure(bound); cold = module.cold
    work.mkdir(parents=True); evidence = work / 'evidence'; evidence.mkdir()
    data = work / 'fixture'; config = data / 'config'; config.mkdir(parents=True)
    prefix = 'ouf-lateral33-' + str(os.getpid()); network = prefix + '-net'; created_network = False
    lab = cold.Lab(prefix, data, evidence); pids = {}; failure = None; namespace_pins = []
    report = {'status': 'SYNTHETIC_LATERAL33_FAILED', 'targetOperations': 0}
    def save(name, value): module.write_json(evidence / (name + '.json'), value)
    def ns(role, args, **kwargs):
        require(role in pids, 'KNOWN_LIVE_NAMESPACE_REQUIRED')
        return cold.command(['sudo', '-n', 'nsenter', '-t', pids[role], '-n', *args], **kwargs)
    def counter_value(role, name):
        value = json.loads(ns(role, ['nft', '-j', 'list', 'counter', 'inet', 'ouf_roles', name]))
        items = [x['counter'] for x in value['nftables'] if 'counter' in x]
        require(len(items) == 1 and items[0]['name'] == name, 'EXACT_COUNTER_REQUIRED')
        return items[0]
    def counter(role, name): return counter_value(role, name)['packets']
    def probe(role, ip, port, protocol='tcp'):
        return json.loads(ns(role, [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                                   'probe', ip, str(port), protocol]))
    def s3(action, output=None):
        try: result = json.loads(ns('client', [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                                            'client', action, str(config)], timeout=60))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            (evidence / (action + '-stderr.log')).write_text(cold.bounded_diagnostic(error.stderr, 'LATERAL_S3_FAILED')); raise
        save(output or action, result); return result
    def metadata(output):
        # Trusted internal API, reached only from the already allowed S3 namespace.
        value = json.loads(ns('s3', [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()), 'metadata']))
        save(output, value); return value
    cleanup_evidence = {}; cleanup_chunk = None; compaction_evidence = {}
    def chunk_index(output):
        value = json.loads(cold.command(['sudo', '-n', sys.executable, '-I', '-B', '-S',
            str(Path(__file__).resolve()), 'chunk-index', str(data / 'volume'), str(evidence / 'cleanup-chunk.json')]))
        save(output, value); return value
    def chunk_read(expected, output):
        value = json.loads(ns('s3', [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
            'chunk-read', str(evidence / 'cleanup-chunk.json'), expected]))
        save(output, value); return value
    def interrupt_upload():
        nonlocal cleanup_chunk
        control = work / 'stream-control'; control.mkdir()
        baseline = json.loads(cold.command(['sudo', '-n', sys.executable, '-I', '-B', '-S',
            str(Path(__file__).resolve()), 'stream-progress', str(data / 'volume')]))
        save('stream-prefix-before', baseline)
        require(not baseline['persistedPrefixFound'], 'NEW_STREAM_PREFIX_REQUIRED')
        child_args = ['sudo', '-n', 'nsenter', '-t', pids['client'], '-n', sys.executable, '-I', '-B', '-S',
                      str(Path(__file__).resolve()), 'stream-client', str(config), str(control)]
        def abort_client():
            (control / 'abort.tmp').write_text('ABORT\n')
            (control / 'abort.tmp').replace(control / 'abort')
        with (evidence / 'stream-client-stderr.log').open('w') as stderr:
            process = subprocess.Popen(child_args, stdout=subprocess.PIPE, stderr=stderr, text=True)
            try:
                deadline = time.monotonic() + 60
                while not (control / 'prefix-sent.json').exists():
                    require(process.poll() is None and time.monotonic() < deadline, 'STREAM_PREFIX_SEND_BUDGET')
                    time.sleep(0.1)
                marker = json.loads((control / 'prefix-sent.json').read_bytes()); save('stream-prefix-sent', marker)
                for observation in range(1, 31):
                    require(process.poll() is None, 'STREAM_MUST_REMAIN_OPEN_UNTIL_VOLUME_EVIDENCE')
                    progress = json.loads(cold.command(['sudo', '-n', sys.executable, '-I', '-B', '-S',
                        str(Path(__file__).resolve()), 'stream-progress', str(data / 'volume')]))
                    save('stream-prefix-observation-' + str(observation), progress)
                    if progress['persistedPrefixFound']: break
                    require(observation < 30 and time.monotonic() < deadline, 'STREAM_NATIVE_CHUNK_BUDGET')
                    time.sleep(1)
                if cleanup_stream:
                    cleanup_chunk = json.loads(cold.command(['sudo', '-n', sys.executable, '-I', '-B', '-S',
                        str(Path(__file__).resolve()), 'chunk-identify', str(data / 'volume'),
                        str(evidence / ('stream-prefix-observation-' + str(observation) + '.json'))]))
                    save('cleanup-chunk', cleanup_chunk)
                    live_index = chunk_index('cleanup-index-live'); require(not live_index['tombstoned'], 'LIVE_CHUNK_BEFORE_ABORT_REQUIRED')
                    chunk_read('present', 'cleanup-chunk-live')
                    grpc_before = {r:counter_value(r, 'cleanup_grpc_bytes')['bytes'] for r in ('s3','volume')}
                    save('cleanup-grpc-before', grpc_before)
                require(process.poll() is None, 'STREAM_MUST_STILL_BE_OPEN_AT_ABORT')
                abort_client()
                stdout, _ = process.communicate(timeout=15)
                require(process.returncode == 0, 'EXACT_STREAM_CLIENT_EXIT_REQUIRED')
                result = json.loads(stdout); save('stream-interrupted-put', result)
                require(result['sentBodyBytes'] == stream.PREFIX_BYTES < result['declaredBodyBytes'] == stream.BODY_BYTES
                        and result['clientConnectionClosed'] and not result['ackObserved']
                        and result['putAttempts'] == 1 and result['mutatingRetries'] == 0, 'INCOMPLETE_SINGLE_PUT_REQUIRED')
                if cleanup_stream:
                    for attempt in range(1,21):
                        deleted = chunk_index('cleanup-index-attempt-' + str(attempt))
                        if deleted['tombstoned']: break
                        require(attempt < 20, 'ORPHAN_CLEANUP_BUDGET'); time.sleep(1)
                    chunk_read('absent', 'cleanup-chunk-deleted')
                    grpc_after = {r:counter_value(r, 'cleanup_grpc_bytes')['bytes'] for r in ('s3','volume')}
                    save('cleanup-grpc-after', grpc_after)
                    require(all(grpc_after[r] > grpc_before[r] for r in grpc_before), 'REAL_CLEANUP_GRPC_TRAFFIC_REQUIRED')
                    for r in ('s3','volume'):
                        save('cleanup-' + r + '-rules', json.loads(ns(r, ['nft', '-j', 'list', 'table', 'inet', 'ouf_roles'])))
                    cleanup_evidence.update(fileId=cleanup_chunk['fileId'], indexPollAttempts=attempt,
                        directChunkReadBeforeAbort=True, directChunk404AfterCleanup=True, originalIndexEntryPreserved=True,
                        exactTombstoneObserved=True, grpcBytesBefore=grpc_before, grpcBytesAfter=grpc_after,
                        clientDeleteRequests=0, clientMutatingRetries=0, physicalSpaceReclaimed=False)
                return {'putAttempts': 1, 'mutatingRetries': 0, 'ackObserved': False,
                        'sentBodyBytes': result['sentBodyBytes'], 'declaredBodyBytes': result['declaredBodyBytes'],
                        'actualPersistedChunkBytes': stream.CHUNK_BYTES, 'prefixObservations': observation,
                        'clientConnectionClosedBeforeCrash': True}
            finally:
                if process.poll() is None:
                    abort_client()
                    try: process.communicate(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.communicate(timeout=5)
    try:
        save('exact-image', cold.prepare_image(archive, work))
        module.write_json(config / 's3.json', module.fixture_config()); module.certificates(config)
        for name in ('ca.pem', 'server.pem'): (evidence / name).write_bytes((config / 'tls' / name).read_bytes())
        save('policy', {'ips': IPS, 'ports': PORTS, 'allow': sorted(allow_links(cleanup_stream)), 'matrix': matrix(cleanup_stream),
                        'gateSha256': keys.sha(gate_binary.read_bytes()), 'subnet': '172.30.233.0/24'})
        (evidence / 'nft-version.txt').write_text(cold.command(['sudo', '-n', 'nft', '--version']) + '\n')
        cold.command(['docker', 'network', 'create', '--internal', '--subnet', '172.30.233.0/24', '--gateway', GATEWAY, network])
        created_network = True
        for role in ROLES:
            (data / role).mkdir(); (data / ('gate-' + role)).mkdir()
        cold.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(config), *[str(data / r) for r in ROLES]])
        for role in ROLES:
            name = prefix + '-' + role
            cold.command(container_argv(cold.IMAGE_ID, name, network, data, config, gate_binary, role, data / ('gate-' + role)))
            lab.names.append(name)
            item = json.loads(cold.command(['docker', 'inspect', name]))[0]; pids[role] = str(item['State']['Pid'])
        snapshots = json.loads(cold.command(['docker', 'inspect', *lab.names])); save('gated-containers', snapshots)
        inodes = [cold.command(['sudo', '-n', 'readlink', '/proc/' + pids[r] + '/ns/net']) for r in ROLES]
        host_ns = cold.command(['readlink', '/proc/self/ns/net'])
        require(len(set(inodes)) == 5 and host_ns not in inodes, 'FIVE_DISTINCT_NONHOST_NAMESPACES_REQUIRED')
        save('namespace-identities', dict(zip(ROLES, inodes)))
        for role, item in zip(ROLES, snapshots):
            host = item['HostConfig']; mounts = {m['Destination']: m for m in item['Mounts']}
            require(item['Image'] == cold.IMAGE_ID and item['Config']['User'] == '65532:65532'
                    and host['ReadonlyRootfs'] and host['CapDrop'] == ['ALL'] and not host['PortBindings']
                    and host['NetworkMode'] == network and not mounts['/config']['RW'] and not mounts['/gate']['RW'],
                    'EXACT_CONTAINER_BOUNDARY_REQUIRED')
            require(item['NetworkSettings']['Networks'][network]['IPAddress'] == IPS[role], 'EXACT_STATIC_IP_REQUIRED')
            rules = nft_rules(role, cleanup_stream); (evidence / (role + '-rules.nft')).write_text(rules)
            ns(role, ['nft', '-f', str(evidence / (role + '-rules.nft'))])
            save(role + '-rules-before', json.loads(ns(role, ['nft', '-j', 'list', 'table', 'inet', 'ouf_roles'])))
            require('NETWORK_GATE_RELEASED' not in cold.command(['docker', 'logs', prefix + '-' + role]),
                    'SERVICES_MUST_WAIT_FOR_ALL_RULES')
        for role in ROLES: validate_closed_gate(data / ('gate-' + role))
        for role in ROLES: publish_gate(data / ('gate-' + role))
        # Read-only readiness uses each destination namespace's loopback. All
        # advertised service ports must be live before the deny matrix is tested.
        readiness = []
        for role, ports in PORTS.items():
            for port in ports:
                deadline = time.monotonic() + 75; attempts = 0
                while True:
                    attempts += 1; result = probe(role, '127.0.0.1', port)
                    if result['connected']: break
                    require(time.monotonic() < deadline and attempts < 60, 'LISTENER_READINESS_BUDGET:' + role)
                    time.sleep(1)
                readiness.append({'role': role, 'port': port, 'attempts': attempts})
        save('live-listeners', readiness)
        deadline = time.monotonic() + 60
        while True:
            log = subprocess.run(['docker', 'logs', '--tail', '200', prefix + '-filer'], check=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10).stdout
            if 'LockRing: applying master ring update' in log and IPS['filer'] + ':18888' in log: break
            require(time.monotonic() < deadline, 'FILER_RING_READINESS_BUDGET'); time.sleep(1)
        save('ring-ready', {'filer': IPS['filer'] + ':18888', 'mutatingProbes': 0})
        crash_evidence = {}
        before = s3('seed-volume' if crash_role else 'seed')
        stream_evidence = {}
        if interrupt_stream:
            stream_evidence = interrupt_upload()
            s3('absent-interrupted', 'stream-absence-before-crash')
        if crash_role:
            if crash_filer or crash_master or crash_all: metadata_before = metadata(crash_role + '-metadata-before')
            if crash_master or crash_all:
                topology_before = json.loads(ns('master', [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                    'topology', str(evidence / (crash_role + '-metadata-before.json'))]))
                save(crash_role + '-topology-before', topology_before)
                require(topology_before['status'] == 'MASTER_TOPOLOGY_READY', 'BASELINE_MASTER_TOPOLOGY_REQUIRED')
            replaced_roles = SERVICES if crash_all else (crash_role,)
            by_role = dict(zip(ROLES, json.loads(cold.command(['docker', 'inspect', *lab.names]))))
            save(crash_role + '-before-crash', by_role)
            old_names = {role: prefix + '-' + role for role in replaced_roles}
            old_indexes = {role: lab.names.index(name) for role, name in old_names.items()}
            retained_ns = {}
            for role in replaced_roles:
                pin = work / ('retained-' + role + '.netns')
                retained_ns[role] = pin_network_namespace(pids[role], pin, inodes[ROLES.index(role)], cold.command)
                namespace_pins.append(pin)
            save('retained-network-namespaces', retained_ns)
            # One bounded Docker batch, not an assertion of physical simultaneity.
            cold.command(['docker', 'kill', '--signal', 'KILL', *old_names.values()])
            killed_roles = dict(zip(replaced_roles, json.loads(cold.command(['docker', 'inspect', *old_names.values()]))))
            if crash_all:
                validate_all_killed(by_role, killed_roles); save('all-killed', killed_roles)
            for role, killed in killed_roles.items():
                save(role + '-killed', killed); validate_killed_role(by_role[role], killed)
                log = subprocess.run(['docker', 'logs', old_names[role]], check=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=30)
                (evidence / (role + '-killed.log')).write_bytes(log.stdout)
            inventories = {}; inventory_commands = {}
            for role in replaced_roles:
                if role == 's3': continue  # Stateless gateway; configuration is reused read-only.
                operation = {'volume': 'inventory', 'filer': 'filer-inventory', 'master': 'master-inventory'}[role]
                storage = data / role / 'filerldb2' if role == 'filer' else data / role
                args = ['sudo', '-n', sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()), operation, str(storage)]
                inventory_commands[role] = args
                inventories[role] = json.loads(cold.command(args)); save(role + '-stopped-storage', inventories[role])
            if crash_volume or crash_all:
                dat = inventories['volume']; save('volume-stopped-dat', dat)
                require(sum(item['bytes'] for item in dat.values()) >= VOLUME_BYTES, 'REAL_VOLUME_DATA_REQUIRED')
            # All killed states and all stopped inventories precede every replacement.
            for name in old_names.values():
                cold.command(['docker', 'rm', name]); lab.names.remove(name)
            gates = {}; replacements = {}; replacement_names = {}; replacement_ns = {}
            for role in replaced_roles:
                gate_dir = data / ('gate-' + role + '-recovered'); gate_dir.mkdir(); gates[role] = gate_dir
                new_name = prefix + '-' + role + '-recovered'; replacement_names[role] = new_name
                cold.command(container_argv(cold.IMAGE_ID, new_name, network, data, config, gate_binary, role, gate_dir))
                lab.names.insert(old_indexes[role], new_name)
                recovered = json.loads(cold.command(['docker', 'inspect', new_name]))[0]; replacements[role] = recovered
                pids[role] = str(recovered['State']['Pid'])
                inode = cold.command(['sudo', '-n', 'readlink', '/proc/' + pids[role] + '/ns/net'])
                require(inode not in inodes and inode != host_ns, 'FRESH_NONHOST_REPLACEMENT_NAMESPACE_REQUIRED')
                replacement_ns[role] = inode
                save(role + '-replacement-namespace', {'old': inodes[ROLES.index(role)], 'new': inode})
                mounts = {m['Destination']: m for m in recovered['Mounts']}
                require(recovered['Image'] == cold.IMAGE_ID and recovered['Config']['User'] == '65532:65532'
                        and recovered['HostConfig']['CapDrop'] == ['ALL'] and recovered['HostConfig']['ReadonlyRootfs']
                        and not recovered['HostConfig']['PortBindings'] and recovered['HostConfig']['NetworkMode'] == network
                        and mounts['/data']['Source'] == str(data / role)
                        and mounts['/gate']['Source'] == str(gate_dir) and not mounts['/gate']['RW']
                        and mounts['/config']['Source'] == str(config) and not mounts['/config']['RW']
                        and not mounts['/network-gate']['RW']
                        and recovered['NetworkSettings']['Networks'][network]['IPAddress'] == IPS[role],
                        'SAME_ROLE_ROOT_WITH_FRESH_GATE_REQUIRED')
                ns(role, ['nft', '-f', str(evidence / (role + '-rules.nft'))])
                save(role + '-replacement-rules-before', json.loads(ns(role, ['nft', '-j', 'list', 'table', 'inet', 'ouf_roles'])))
                require('NETWORK_GATE_RELEASED' not in cold.command(['docker', 'logs', new_name]), 'REPLACEMENT_MUST_WAIT_FOR_RULES')
                blocked = [probe(role, '127.0.0.1', port) for port in PORTS[role]]
                require(all(not x['connected'] and x['errno'] == errno.ECONNREFUSED for x in blocked), 'NO_ROLE_LISTENER_BEFORE_RELEASE')
                save(role + '-replacement-closed-listeners', blocked)
            if crash_all: validate_replacement_namespaces(dict(zip(ROLES, inodes)), replacement_ns, host_ns)
            for pin in list(namespace_pins):
                cold.command(['sudo','-n','umount',str(pin)]); namespace_pins.remove(pin)
            save('released-network-namespaces', {'roles':list(replaced_roles),'allReleased':True,'beforeAnyReplacementExec':True})
            current_roles = dict(zip(ROLES, json.loads(cold.command(['docker', 'inspect', *lab.names]))))
            validate_retained_roles(by_role, current_roles, crash_role); save(crash_role + '-replacement-gated', current_roles)
            for role, args in inventory_commands.items():
                gated_storage = json.loads(cold.command(args)); save(role + '-gated-storage', gated_storage)
                require(gated_storage == inventories[role], 'STORAGE_UNCHANGED_BEFORE_EXEC')
            # Every firewall and every closed listener was checked before this global release.
            release_replacement_gates(gates)
            for role in replaced_roles:
                readiness = []
                for port in PORTS[role]:
                    for attempt in range(1, 61):
                        result = probe(role, '127.0.0.1', port)
                        if result['connected']: break
                        require(attempt < 60, 'RECOVERED_ROLE_LISTENER_BUDGET'); time.sleep(1)
                    readiness.append({'port': port, 'attempts': attempt})
                save(role + '-replacement-live-listeners', readiness)
            if crash_filer or crash_all:
                metadata_bytes_before = counter_value('filer', 'filer_http_response_bytes')['bytes']
                metadata_after = metadata(crash_role + '-metadata-recovered')
                metadata_bytes_after = counter_value('filer', 'filer_http_response_bytes')['bytes']
                require(metadata_after == metadata_before, 'PERSISTED_FILER_METADATA_MUST_SURVIVE')
                require(metadata_bytes_after > metadata_bytes_before, 'NEW_FILER_MUST_SERVE_METADATA')
            if crash_master or crash_all:
                deadline = time.monotonic() + 120
                for topology_attempt in range(1, 11):
                    topology_after = json.loads(ns('master', [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                        'topology', str(evidence / (crash_role + '-metadata-before.json'))], timeout=45))
                    save(crash_role + '-topology-attempt-' + str(topology_attempt), topology_after)
                    log = subprocess.run(['docker', 'logs', replacement_names['master']], check=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, timeout=10).stdout
                    registered = master_registration_log(log)
                    save(crash_role + '-registration-attempt-' + str(topology_attempt), {'filerAndS3Registered': registered})
                    if topology_after['status'] == 'MASTER_TOPOLOGY_READY' and registered: break
                    require(topology_attempt < 10, 'MASTER_REGISTRATION_ATTEMPTS_EXHAUSTED')
                    delay = master_retry_delay(topology_attempt, topology_after.get('retryAfterSeconds', 0),
                                               time.monotonic(), deadline)
                    save(crash_role + '-wait-' + str(topology_attempt), {'delaySeconds': delay, 'mutatingRequests': 0})
                    time.sleep(delay)
                require(time.monotonic() <= deadline, 'MASTER_REGISTRATION_TIME_BUDGET')
                validate_master_recovery(topology_before, topology_after)
                save(crash_role + '-topology-recovered', topology_after)
                (evidence / (crash_role + '-registration-recovered.log')).write_text(log)
                metadata_after = metadata(crash_role + '-metadata-recovered')
                require(metadata_after == metadata_before, 'METADATA_MUST_SURVIVE_MASTER_RESTART')
            bytes_before = counter_value('volume', 'volume_http_response_bytes')['bytes']
            for attempt in range(1, 7):
                observed = s3('read-volume', crash_role + '-recovery-read-' + str(attempt))
                if observed.get('status') != 'TRANSIENT_READ_FAILURE': break
                require(attempt < 6, 'ROLE_RECOVERY_READ_BUDGET'); time.sleep((1, 2, 4, 8, 15)[attempt - 1])
            expected = before['acknowledgedObject']
            require(observed['objects'] == {VOLUME_KEY: {k:v for k,v in expected.items() if k != 'key'}}, 'ACKNOWLEDGED_BODY_MUST_SURVIVE')
            bytes_after = counter_value('volume', 'volume_http_response_bytes')['bytes']
            require(bytes_after - bytes_before >= VOLUME_BYTES, 'RECOVERY_MUST_READ_REAL_VOLUME_RESPONSE_BYTES')
            if crash_volume or crash_all: save('volume-recovered-dat-prefix', json.loads(cold.command(inventory_commands['volume'] + ['--previous', str(evidence / 'volume-stopped-dat.json')])))
            save(crash_role + '-recovered-read', observed)
            crash_evidence = {'signal': 'SIGKILL', 'exitCode': 137, 'oomKilled': False,
                'sameStorageRoot': True, 'rulesBeforeRestartExec': True,
                'volumeResponseBytesBefore': bytes_before, 'volumeResponseBytesAfter': bytes_after,
                'recoveryReadAttempts': attempt, 'recoveryPutRequests': 0, 'bodyReadsBeforeCrash': 0}
            if crash_all:
                crash_evidence.update(oldContainerIds={r:x['Id'] for r,x in killed_roles.items()},
                    newContainerIds={r:x['Id'] for r,x in replacements.items()}, allServicesStoppedBeforeReplacement=True,
                    allRulesBeforeAnyRestartExec=True, clientUnchanged=True, applicationProcessesReplaced=4,
                    stoppedStorageFiles={r:len(v) for r,v in inventories.items()},
                    stoppedStorageBytes={r:sum(x['bytes'] for x in v.values()) for r,v in inventories.items()})
            else:
                crash_evidence.update(oldContainerId=killed_roles[crash_role]['Id'],
                    newContainerId=replacements[crash_role]['Id'], otherRolesUnchanged=True)
            if crash_volume or crash_all:
                crash_evidence.update(sameVolumeRoot=True, stoppedDatBytes=sum(x['bytes'] for x in dat.values()),
                                      datPrefixesPreserved=True)
            if crash_filer or crash_all:
                persisted = inventories['filer']
                crash_evidence.update(sameFilerRoot=True, gatedStorageUnchanged=True, directMetadataIdentical=True,
                    filerResponseBytesBefore=metadata_bytes_before, filerResponseBytesAfter=metadata_bytes_after)
                if not crash_all: crash_evidence.update(stoppedMetadataFiles=len(persisted),
                    stoppedMetadataBytes=sum(x['bytes'] for x in persisted.values()))
            if crash_master or crash_all:
                persisted = inventories['master']
                crash_evidence.update(sameMasterRoot=True, gatedStorageUnchanged=True, topologyIdPreserved=True,
                    chunkVolumeLocationsPreserved=True, filerAndS3Reregistered=True, directMetadataIdentical=True,
                    topologyReadAttempts=topology_attempt)
                if not crash_all: crash_evidence.update(stoppedMetadataFiles=len(persisted),
                    stoppedMetadataBytes=sum(x['bytes'] for x in persisted.values()))
            if interrupt_stream: s3('absent-interrupted', 'stream-absence-after-restart')
            if cleanup_stream:
                recovered_index = chunk_index('cleanup-index-after-restart')
                require(recovered_index['tombstoned'], 'TOMBSTONE_SURVIVES_RESTART_REQUIRED')
                chunk_read('absent', 'cleanup-chunk-after-restart')
                cleanup_evidence.update(tombstoneSurvivesRestart=True, directChunk404AfterRestart=True)
            final_roles = dict(zip(ROLES, json.loads(cold.command(['docker', 'inspect', *lab.names]))))
            validate_retained_roles(by_role, final_roles, crash_role); save(crash_role + '-recovered-roles', final_roles)
        probes = []
        for src, dst, port, allowed in matrix(cleanup_stream):
            name = f'deny_{dst}_{port}'
            prior = None if allowed else counter(src, name)
            result = probe(src, IPS[dst], port)
            after = None if allowed else counter(src, name)
            if allowed: require(result['connected'], 'REQUIRED_ROLE_LINK_FAILED')
            else: require(not result['connected'] and result['errno'] is not None and after > prior,
                          'FIREWALL_COUNTER_AND_DENIAL_REQUIRED')
            probes.append({'source': src, 'destination': dst, 'port': port, 'allowed': allowed,
                           'counterBefore': prior, 'counterAfter': after, **result})
        save('role-probes', probes)
        dns = []
        for role in ROLES:
            for proto, ip, port, name in [('tcp', '127.0.0.11', 53, 'dns_tcp'), ('udp', '127.0.0.11', 53, 'dns_udp'),
                                         ('tcp', GATEWAY, 443, 'egress_tcp')]:
                prior = counter(role, name); result = probe(role, ip, port, proto); after = counter(role, name)
                require(not result['connected'] and result['errno'] is not None and after > prior, 'DNS_OR_HOST_EGRESS_DENIAL_REQUIRED')
                dns.append({'role': role, 'protocol': proto, 'ip': ip, 'port': port,
                            'counterBefore': prior, 'counterAfter': after, **result})
        save('dns-host-probes', dns)
        after = s3('read-volume' if crash_role else 'read')
        if interrupt_stream: s3('absent-interrupted', 'stream-absence-after-probes')
        if cleanup_stream:
            require(chunk_index('cleanup-index-after-probes')['tombstoned'], 'TOMBSTONE_REMAINS_REQUIRED')
            chunk_read('absent', 'cleanup-chunk-after-probes')
        if compact_stream:
            def compact_snapshot(output):
                value = json.loads(cold.command(['sudo', '-n', sys.executable, '-I', '-B', '-S',
                    str(Path(__file__).resolve()), 'compaction-snapshot', str(data / 'volume'),
                    str(evidence / 'cleanup-chunk.json'), pids['volume']]))
                save(output, value); return value
            compact_before = compact_snapshot('compaction-before')
            compact_metadata = metadata('compaction-metadata-before')
            script = compact.command_script(cleanup_chunk)
            (evidence / 'compaction-command.txt').write_text(script)
            command = ['docker', 'exec', '-i', prefix + '-master-recovered', '/usr/local/bin/weed',
                       'shell', '-master=127.0.0.1:19333', '-connectTimeout=10s']
            try:
                completed = subprocess.run(command, input=script, text=True, capture_output=True, timeout=90)
            except subprocess.TimeoutExpired as error:
                (evidence / 'compaction-timeout.log').write_text(cold.bounded_diagnostic(error.stderr, 'COMPACTION_TIMEOUT'))
                raise
            (evidence / 'compaction-stdout.log').write_text(completed.stdout)
            (evidence / 'compaction-stderr.log').write_text(completed.stderr)
            save('compaction-execution', {'argv':command,'exitCode':completed.returncode,'vacuumCommands':1,'mutatingRetries':0,'timeoutSeconds':90})
            require(completed.returncode == 0 and len(completed.stdout)+len(completed.stderr)<=262144, 'NATIVE_COMPACTION_COMMAND_SUCCESS_REQUIRED')
            compact_after = compact_snapshot('compaction-after')
            compaction_evidence = compact.validate(compact_before, compact_after, cleanup_chunk)
            chunk_read('absent', 'compaction-chunk-absent')
            s3('absent-interrupted', 'compaction-s3-absence')
            compact_read = s3('read-volume', 'compaction-baseline-read')
            require(compact_read == after, 'COMPACTION_BASELINE_PARITY_REQUIRED')
            require(metadata('compaction-metadata-after') == compact_metadata, 'COMPACTION_METADATA_PARITY_REQUIRED')
            require(compact_snapshot('compaction-after-reads') == compact_after, 'COMPACTION_STATE_STABLE_AFTER_READS')
            final_compact_roles = dict(zip(ROLES, json.loads(cold.command(['docker','inspect',*lab.names]))))
            require(all(final_compact_roles[r]['Id']==final_roles[r]['Id'] and
                        final_compact_roles[r]['State']['StartedAt']==final_roles[r]['State']['StartedAt'] and
                        final_compact_roles[r]['RestartCount']==0 for r in ROLES), 'NO_RESTART_DURING_COMPACTION')
            save('compaction-roles', final_compact_roles)
            compaction_evidence.update(baselineS3Parity=True, directMetadataIdentical=True, s3ObjectAbsent=True, directChunk404=True)
        baseline = observed if crash_role else before
        require({k:v for k,v in baseline.items() if k != 'mutatingRequests'} ==
                {k:v for k,v in after.items() if k != 'mutatingRequests'}, 'OBJECT_PARITY_REQUIRED')
        for role in ROLES:
            save(role + '-rules-after', json.loads(ns(role, ['nft', '-j', 'list', 'table', 'inet', 'ouf_roles'])))
        save('network', json.loads(cold.command(['docker', 'network', 'inspect', network])))
        require(json.loads(cold.command(['docker', 'network', 'inspect', network]))[0]['Internal'] is True, 'INTERNAL_NETWORK_REQUIRED')
        lab.stop(); cold.command(['docker', 'network', 'rm', network]); created_network = False
        report = {'schema': 'ouf.storage-generation33-lateral-isolation.v1', 'status': 'SYNTHETIC_ROLE_NETWORK_ISOLATION_PASS',
            'candidateLockSha256': LOCK_SHA, 'cohortReceiptSha256': COHORT_SHA,
            'ociManifestDigest': bound['lock']['image']['manifestDigest'], 'distinctNetworkNamespaces': 5,
            'cleanContainerStops': 5, 'requiredRoleLinks': len(allow_links(cleanup_stream)), 'deniedRoleLinks': len(probes) - len(allow_links(cleanup_stream)),
            'dnsAndHostDenials': len(dns), 'allDenialsHaveFirewallCounterEvidence': True,
            'rulesInstalledBeforeServiceExec': True, 'unprivilegedServiceContainers': True,
            'successfulObjectPuts': 1, 'bucketCreates': 1, 'mutatingRequestRetries': 0, 'object': after,
            'volumeCrashInjected': crash_volume, 'volumeCrashEvidence': crash_evidence if crash_volume else {},
            'filerCrashInjected': crash_filer, 'filerCrashEvidence': crash_evidence if crash_filer else {},
            'masterCrashInjected': crash_master, 'masterCrashEvidence': crash_evidence if crash_master else {},
            'allCrashInjected': crash_all, 'allCrashEvidence': crash_evidence if crash_all else {},
            'compactionQualified': compact_stream, 'compactionEvidence': compaction_evidence,
            'orphanLogicalCleanupQualified': cleanup_stream, 'orphanCleanupEvidence': cleanup_evidence,
            'streamInterruptionInjected': interrupt_stream, 'streamInterruptionEvidence': stream_evidence,
            'totalDistinctContainerCount': 9 if crash_all else 6 if crash_role else 5,
            'forcedContainerDeaths': 4 if crash_all else 1 if crash_role else 0,
            'powerLossQualified': False, 'rpoMeasured': False, 'rtoMeasured': False,
            'networkRemoved': True, 'retainedNamespacePinsReleased': not namespace_pins, 'targetOperations': 0, 'gatesClosed': 0, 'acceptanceTestsPassed': 0,
            'releaseAdmitted': False, 'runtimeAuthorityIssued': False, 'productionTopologyQualified': False,
            'internalMtlsQualified': False, 'allowedPortMethodAuthorizationQualified': False,
            'ipv6MatrixQualified': False, 'hostCompromiseIsolationQualified': False}
    except Exception as error:
        failure = error; report['failure'] = type(error).__name__ + ': ' + str(error)[:512]
    finally:
        for pin in list(namespace_pins):
            try: cold.command(['sudo','-n','umount',str(pin)]); namespace_pins.remove(pin)
            except Exception as error: report['namespacePinCleanupFailure'] = str(error)[:256]; failure = failure or error
        if lab.names:
            try: lab.stop()
            except Exception as error: report['cleanupFailure'] = str(error)[:256]; failure = failure or error
        if created_network:
            try: cold.command(['docker', 'network', 'rm', network])
            except Exception as error: report['networkCleanupFailure'] = str(error)[:256]; failure = failure or error
        if failure: report['status'] = 'SYNTHETIC_LATERAL33_FAILED'
        save('receipt', report)
    if failure: raise failure


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='operation', required=True)
    runner = sub.add_parser('run')
    for name in ('archive', 'work', 'receipt', 'gate_binary'): runner.add_argument(name, type=Path)
    crash = runner.add_mutually_exclusive_group()
    crash.add_argument('--crash-volume', action='store_true'); crash.add_argument('--crash-filer', action='store_true')
    crash.add_argument('--crash-master', action='store_true'); crash.add_argument('--crash-all', action='store_true')
    crash.add_argument('--interrupt-stream', action='store_true'); crash.add_argument('--cleanup-stream', action='store_true'); crash.add_argument('--compact-stream', action='store_true')
    comp = sub.add_parser('compaction-snapshot'); comp.add_argument('root', type=Path); comp.add_argument('chunk', type=Path); comp.add_argument('pid')
    identify = sub.add_parser('chunk-identify'); identify.add_argument('root', type=Path); identify.add_argument('observation', type=Path)
    index = sub.add_parser('chunk-index'); index.add_argument('root', type=Path); index.add_argument('chunk', type=Path)
    chunk = sub.add_parser('chunk-read'); chunk.add_argument('chunk', type=Path); chunk.add_argument('expected', choices=('present','absent'))
    stream_child = sub.add_parser('stream-client'); stream_child.add_argument('config', type=Path); stream_child.add_argument('control', type=Path)
    progress = sub.add_parser('stream-progress'); progress.add_argument('root', type=Path)
    master_inv = sub.add_parser('master-inventory'); master_inv.add_argument('root', type=Path)
    topology = sub.add_parser('topology'); topology.add_argument('metadata', type=Path)
    sub.add_parser('metadata')
    filer_inv = sub.add_parser('filer-inventory'); filer_inv.add_argument('root', type=Path)
    inventory = sub.add_parser('inventory'); inventory.add_argument('root', type=Path); inventory.add_argument('--previous', type=Path)
    child = sub.add_parser('client'); child.add_argument('action', choices=('seed', 'read', 'seed-volume', 'read-volume', 'absent-interrupted')); child.add_argument('config', type=Path)
    prober = sub.add_parser('probe'); prober.add_argument('ip'); prober.add_argument('port', type=int); prober.add_argument('protocol', choices=('tcp', 'udp'))
    args = parser.parse_args()
    if args.operation == 'run': run(args.archive.resolve(), args.work.absolute(), args.receipt.resolve(), args.gate_binary.resolve(), crash_volume=args.crash_volume, crash_filer=args.crash_filer, crash_master=args.crash_master, crash_all=args.crash_all, interrupt_stream=args.interrupt_stream, cleanup_stream=args.cleanup_stream, compact_stream=args.compact_stream)
    elif args.operation == 'compaction-snapshot': print(json.dumps(compact.snapshot(args.root, json.loads(args.chunk.read_bytes()), args.pid)))
    elif args.operation == 'chunk-identify': print(json.dumps(cleanup.identify(args.root, json.loads(args.observation.read_bytes()))))
    elif args.operation == 'chunk-index': print(json.dumps(cleanup.index_state(args.root, json.loads(args.chunk.read_bytes()))))
    elif args.operation == 'chunk-read': print(json.dumps(cleanup.read_chunk(IPS['volume'], json.loads(args.chunk.read_bytes()), args.expected)))
    elif args.operation == 'stream-progress': print(json.dumps(stream.persisted_prefix(args.root)))
    elif args.operation == 'stream-client':
        signer = keys.tls_rotation.load('stream_s3_signer', ROOT / 'scripts/run-seaweedfs-452-identity-tls.py')
        print(json.dumps(stream.send_prefix(args.config / 'tls', signer, IPS['s3'], args.control)))
    elif args.operation == 'topology': print(json.dumps(master_topology(json.loads(args.metadata.read_bytes()))))
    elif args.operation == 'master-inventory': print(json.dumps(master_inventory(args.root)))
    elif args.operation == 'metadata': print(json.dumps(filer_metadata()))
    elif args.operation == 'filer-inventory': print(json.dumps(filer_inventory(args.root)))
    elif args.operation == 'inventory':
        print(json.dumps(volume_inventory(args.root, json.loads(args.previous.read_bytes()) if args.previous else None)))
    elif args.operation == 'probe': print(json.dumps(socket_probe(args.ip, args.port, args.protocol)))
    else: print(json.dumps(client(args.action, args.config)))


if __name__ == '__main__': main()
