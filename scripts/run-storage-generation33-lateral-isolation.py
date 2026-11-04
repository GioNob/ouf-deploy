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
labs, require, binding = keys.labs, keys.require, keys.binding
LOCK_SHA, COHORT_SHA = keys.LOCK_SHA, keys.COHORT_SHA
COHORT_ARTIFACT_ID, COHORT_ARCHIVE_SHA, COHORT_ARCHIVE_BYTES = keys.COHORT_ARTIFACT_ID, keys.COHORT_ARCHIVE_SHA, keys.COHORT_ARCHIVE_BYTES
ROLES = ('master', 'volume', 'filer', 's3', 'client')
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


def validate_killed_volume(before, killed):
    require(killed['Id'] == before['Id'] and before['State']['Running']
            and not killed['State']['Running'] and killed['State']['ExitCode'] == 137
            and not killed['State']['OOMKilled'] and not killed['State']['Error'], 'EXACT_VOLUME_SIGKILL_REQUIRED')


def validate_retained_roles(before, after):
    require(set(before) == set(after) == set(ROLES), 'EXACT_ROLE_SET_REQUIRED')
    for role in ROLES:
        old, new = before[role], after[role]
        require(new['State']['Running'] and not new['State']['OOMKilled'], 'LIVE_ROLES_REQUIRED')
        if role == 'volume':
            require(old['Id'] != new['Id'], 'NEW_VOLUME_CONTAINER_REQUIRED')
        else:
            require(old['Id'] == new['Id'] and old['State']['StartedAt'] == new['State']['StartedAt']
                    and old['RestartCount'] == new['RestartCount'] == 0, 'OTHER_ROLES_MUST_NOT_RESTART')


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


def matrix():
    return [(src, dst, port, (src, dst, port) in ALLOW)
            for src in ROLES for dst, ports in PORTS.items() if src != dst for port in ports]


def nft_rules(role):
    require(role in ROLES, 'KNOWN_ROLE_REQUIRED')
    counters = ['dns_tcp', 'dns_udp', 'egress_tcp', 'other_denied'] + [
        f'deny_{dst}_{port}' for src, dst, port, allowed in matrix() if src == role and not allowed]
    if role == 'volume': counters.append('volume_http_response_bytes')
    lines = ['table inet ouf_roles {'] + [f' counter {name} {{ }}' for name in counters]
    # -150 precedes Docker's OUTPUT destination NAT, including embedded DNS.
    lines += [' chain output { type filter hook output priority -150; policy drop;',
              ' tcp dport 53 counter name dns_tcp reject with icmpx type admin-prohibited',
              ' udp dport 53 counter name dns_udp reject with icmpx type admin-prohibited',
              f' ip daddr {GATEWAY} tcp dport 443 counter name egress_tcp reject with icmpx type admin-prohibited',
              ' oifname "lo" accept']
    if role == 'volume':
        lines.append(f' ip daddr {{ {IPS["filer"]}, {IPS["s3"]} }} tcp sport 18080 counter name volume_http_response_bytes')
    lines += [' ct state established,related accept']
    for src, dst, port, allowed in matrix():
        if src == role:
            action = 'accept' if allowed else f'counter name deny_{dst}_{port} reject with icmpx type admin-prohibited'
            lines.append(f' ip daddr {IPS[dst]} tcp dport {port} {action}')
    lines += [' counter name other_denied reject with icmpx type admin-prohibited', ' }',
              ' chain input { type filter hook input priority 0; policy drop;',
              ' iifname "lo" accept', ' ct state established,related accept']
    for src, dst, port in sorted(ALLOW):
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


def run(archive, work, receipt, gate_binary, *, crash_volume=False):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() != 0, 'UNPRIVILEGED_ISOLATED_CI_REQUIRED')
    require(not work.exists() and not work.is_symlink(), 'FRESH_WORK_REQUIRED')
    bound = binding(receipt); module = keys.tls_rotation.configure(bound); cold = module.cold
    work.mkdir(parents=True); evidence = work / 'evidence'; evidence.mkdir()
    data = work / 'fixture'; config = data / 'config'; config.mkdir(parents=True)
    prefix = 'ouf-lateral33-' + str(os.getpid()); network = prefix + '-net'; created_network = False
    lab = cold.Lab(prefix, data, evidence); pids = {}; failure = None
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
    try:
        save('exact-image', cold.prepare_image(archive, work))
        module.write_json(config / 's3.json', module.fixture_config()); module.certificates(config)
        for name in ('ca.pem', 'server.pem'): (evidence / name).write_bytes((config / 'tls' / name).read_bytes())
        save('policy', {'ips': IPS, 'ports': PORTS, 'allow': sorted(ALLOW), 'matrix': matrix(),
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
            rules = nft_rules(role); (evidence / (role + '-rules.nft')).write_text(rules)
            ns(role, ['nft', '-f', str(evidence / (role + '-rules.nft'))])
            save(role + '-rules-before', json.loads(ns(role, ['nft', '-j', 'list', 'table', 'inet', 'ouf_roles'])))
            require('NETWORK_GATE_RELEASED' not in cold.command(['docker', 'logs', prefix + '-' + role]),
                    'SERVICES_MUST_WAIT_FOR_ALL_RULES')
        for role in ROLES: (data / ('gate-' + role) / 'open').write_text('READY\n')
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
        before = s3('seed-volume' if crash_volume else 'seed')
        if crash_volume:
            by_role = dict(zip(ROLES, json.loads(cold.command(['docker', 'inspect', *lab.names]))))
            save('volume-before-crash', by_role)
            old_name = prefix + '-volume'; old_index = lab.names.index(old_name)
            # Intentional SIGKILL only after the sole object PUT returned HTTP200.
            cold.command(['docker', 'kill', '--signal', 'KILL', old_name])
            killed = json.loads(cold.command(['docker', 'inspect', old_name]))[0]
            save('volume-killed', killed); validate_killed_volume(by_role['volume'], killed)
            log = subprocess.run(['docker', 'logs', old_name], check=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=30)
            (evidence / 'volume-killed.log').write_bytes(log.stdout)
            inventory_args = ['sudo', '-n', sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                              'inventory', str(data / 'volume')]
            dat = json.loads(cold.command(inventory_args)); save('volume-stopped-dat', dat)
            require(sum(item['bytes'] for item in dat.values()) >= VOLUME_BYTES, 'REAL_VOLUME_DATA_REQUIRED')
            cold.command(['docker', 'rm', old_name]); lab.names.remove(old_name)
            gate_dir = data / 'gate-volume-recovered'; gate_dir.mkdir()
            new_name = prefix + '-volume-recovered'
            cold.command(container_argv(cold.IMAGE_ID, new_name, network, data, config, gate_binary, 'volume', gate_dir))
            lab.names.insert(old_index, new_name)
            recovered = json.loads(cold.command(['docker', 'inspect', new_name]))[0]
            pids['volume'] = str(recovered['State']['Pid'])
            inode = cold.command(['sudo', '-n', 'readlink', '/proc/' + pids['volume'] + '/ns/net'])
            require(inode not in inodes and inode != host_ns, 'FRESH_NONHOST_VOLUME_NAMESPACE_REQUIRED')
            save('volume-replacement-namespace', {'old': inodes[1], 'new': inode})
            current_roles = dict(zip(ROLES, json.loads(cold.command(['docker', 'inspect', *lab.names]))))
            validate_retained_roles(by_role, current_roles); save('volume-replacement-gated', current_roles)
            mounts = {m['Destination']: m for m in recovered['Mounts']}
            require(recovered['Image'] == cold.IMAGE_ID and recovered['Config']['User'] == '65532:65532'
                    and recovered['HostConfig']['CapDrop'] == ['ALL'] and recovered['HostConfig']['ReadonlyRootfs']
                    and not recovered['HostConfig']['PortBindings'] and recovered['HostConfig']['NetworkMode'] == network
                    and mounts['/data']['Source'] == str(data / 'volume')
                    and mounts['/gate']['Source'] == str(gate_dir) and not mounts['/gate']['RW']
                    and recovered['NetworkSettings']['Networks'][network]['IPAddress'] == IPS['volume'],
                    'SAME_VOLUME_ROOT_WITH_FRESH_GATE_REQUIRED')
            ns('volume', ['nft', '-f', str(evidence / 'volume-rules.nft')])
            save('volume-replacement-rules-before', json.loads(ns('volume', ['nft', '-j', 'list', 'table', 'inet', 'ouf_roles'])))
            require('NETWORK_GATE_RELEASED' not in cold.command(['docker', 'logs', new_name]), 'REPLACEMENT_MUST_WAIT_FOR_RULES')
            blocked = [probe('volume', '127.0.0.1', port) for port in PORTS['volume']]
            require(all(not x['connected'] and x['errno'] == errno.ECONNREFUSED for x in blocked), 'NO_VOLUME_LISTENER_BEFORE_RELEASE')
            save('volume-replacement-closed-listeners', blocked)
            (gate_dir / 'open').write_text('READY\n')
            readiness = []
            for port in PORTS['volume']:
                for attempt in range(1, 61):
                    result = probe('volume', '127.0.0.1', port)
                    if result['connected']: break
                    require(attempt < 60, 'RECOVERED_VOLUME_LISTENER_BUDGET'); time.sleep(1)
                readiness.append({'port': port, 'attempts': attempt})
            save('volume-replacement-live-listeners', readiness)
            bytes_before = counter_value('volume', 'volume_http_response_bytes')['bytes']
            for attempt in range(1, 7):
                observed = s3('read-volume', 'volume-recovery-read-' + str(attempt))
                if observed.get('status') != 'TRANSIENT_READ_FAILURE': break
                require(attempt < 6, 'VOLUME_RECOVERY_READ_BUDGET'); time.sleep((1, 2, 4, 8, 15)[attempt - 1])
            expected = before['acknowledgedObject']
            require(observed['objects'] == {VOLUME_KEY: {k:v for k,v in expected.items() if k != 'key'}}, 'ACKNOWLEDGED_BODY_MUST_SURVIVE')
            bytes_after = counter_value('volume', 'volume_http_response_bytes')['bytes']
            require(bytes_after - bytes_before >= VOLUME_BYTES, 'RECOVERY_MUST_READ_REAL_VOLUME_RESPONSE_BYTES')
            save('volume-recovered-dat-prefix', json.loads(cold.command(inventory_args + ['--previous', str(evidence / 'volume-stopped-dat.json')])))
            save('volume-recovered-read', observed)
            crash_evidence = {'signal': 'SIGKILL', 'exitCode': 137, 'oomKilled': False,
                'oldContainerId': killed['Id'], 'newContainerId': recovered['Id'],
                'sameVolumeRoot': True, 'otherRolesUnchanged': True, 'rulesBeforeRestartExec': True,
                'stoppedDatBytes': sum(x['bytes'] for x in dat.values()), 'datPrefixesPreserved': True,
                'volumeResponseBytesBefore': bytes_before, 'volumeResponseBytesAfter': bytes_after,
                'recoveryReadAttempts': attempt, 'recoveryPutRequests': 0, 'bodyReadsBeforeCrash': 0}
        probes = []
        for src, dst, port, allowed in matrix():
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
        after = s3('read-volume' if crash_volume else 'read')
        baseline = observed if crash_volume else before
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
            'cleanContainerStops': 5, 'requiredRoleLinks': len(ALLOW), 'deniedRoleLinks': len(probes) - len(ALLOW),
            'dnsAndHostDenials': len(dns), 'allDenialsHaveFirewallCounterEvidence': True,
            'rulesInstalledBeforeServiceExec': True, 'unprivilegedServiceContainers': True,
            'successfulObjectPuts': 1, 'bucketCreates': 1, 'mutatingRequestRetries': 0, 'object': after,
            'volumeCrashInjected': crash_volume, 'volumeCrashEvidence': crash_evidence,
            'totalDistinctContainerCount': 6 if crash_volume else 5, 'forcedContainerDeaths': 1 if crash_volume else 0,
            'powerLossQualified': False, 'rpoMeasured': False, 'rtoMeasured': False,
            'networkRemoved': True, 'targetOperations': 0, 'gatesClosed': 0, 'acceptanceTestsPassed': 0,
            'releaseAdmitted': False, 'runtimeAuthorityIssued': False, 'productionTopologyQualified': False,
            'internalMtlsQualified': False, 'allowedPortMethodAuthorizationQualified': False,
            'ipv6MatrixQualified': False, 'hostCompromiseIsolationQualified': False}
    except Exception as error:
        failure = error; report['failure'] = type(error).__name__ + ': ' + str(error)[:512]
    finally:
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
    runner.add_argument('--crash-volume', action='store_true')
    inventory = sub.add_parser('inventory'); inventory.add_argument('root', type=Path); inventory.add_argument('--previous', type=Path)
    child = sub.add_parser('client'); child.add_argument('action', choices=('seed', 'read', 'seed-volume', 'read-volume')); child.add_argument('config', type=Path)
    prober = sub.add_parser('probe'); prober.add_argument('ip'); prober.add_argument('port', type=int); prober.add_argument('protocol', choices=('tcp', 'udp'))
    args = parser.parse_args()
    if args.operation == 'run': run(args.archive.resolve(), args.work.absolute(), args.receipt.resolve(), args.gate_binary.resolve(), crash_volume=args.crash_volume)
    elif args.operation == 'inventory':
        print(json.dumps(volume_inventory(args.root, json.loads(args.previous.read_bytes()) if args.previous else None)))
    elif args.operation == 'probe': print(json.dumps(socket_probe(args.ip, args.port, args.protocol)))
    else: print(json.dumps(client(args.action, args.config)))


if __name__ == '__main__': main()
