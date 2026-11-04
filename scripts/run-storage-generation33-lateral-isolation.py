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


def matrix():
    return [(src, dst, port, (src, dst, port) in ALLOW)
            for src in ROLES for dst, ports in PORTS.items() if src != dst for port in ports]


def nft_rules(role):
    require(role in ROLES, 'KNOWN_ROLE_REQUIRED')
    counters = ['dns_tcp', 'dns_udp', 'egress_tcp', 'other_denied'] + [
        f'deny_{dst}_{port}' for src, dst, port, allowed in matrix() if src == role and not allowed]
    lines = ['table inet ouf_roles {'] + [f' counter {name} {{ }}' for name in counters]
    # -150 precedes Docker's OUTPUT destination NAT, including embedded DNS.
    lines += [' chain output { type filter hook output priority -150; policy drop;',
              ' tcp dport 53 counter name dns_tcp reject with icmpx type admin-prohibited',
              ' udp dport 53 counter name dns_udp reject with icmpx type admin-prohibited',
              f' ip daddr {GATEWAY} tcp dport 443 counter name egress_tcp reject with icmpx type admin-prohibited',
              ' oifname "lo" accept', ' ct state established,related accept']
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
        peer = keys.sha(connection.sock.getpeercert(binary_form=True))
        require(peer == keys.sha(ssl.PEM_cert_to_DER_cert((tls / 'server.pem').read_text())), 'EXACT_TLS_PEER_REQUIRED')
        headers = module.signed_headers(method, path, query, body, credentials); headers['content-type'] = keys.MIME
        connection.request(method, path + ('?' + query if query else ''), body=body, headers=headers)
        response = connection.getresponse(); payload = response.read(16385)
        require(len(payload) <= 16384, 'BOUNDED_S3_RESPONSE_REQUIRED')
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
    if action == 'seed':
        for credentials, key, body in [(module.OWNER, '', b''), (module.APP, keys.KEY, keys.BODY)]:
            require(s3_request(module, config / 'tls', credentials, 'PUT', key, body)['status'] == 200, 'ONE_TIME_S3_SEED_REQUIRED')
    require(action in ('seed', 'read'), 'KNOWN_CLIENT_ACTION_REQUIRED')
    result = keys.read_objects(module, config / 'tls', module.APP, {keys.KEY: keys.BODY}, s3_request)
    result['mutatingRequests'] = 2 if action == 'seed' else 0
    return result


def run(archive, work, receipt, gate_binary):
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
    def counter(role, name):
        value = json.loads(ns(role, ['nft', '-j', 'list', 'counter', 'inet', 'ouf_roles', name]))
        items = [x['counter'] for x in value['nftables'] if 'counter' in x]
        require(len(items) == 1 and items[0]['name'] == name, 'EXACT_COUNTER_REQUIRED')
        return items[0]['packets']
    def probe(role, ip, port, protocol='tcp'):
        return json.loads(ns(role, [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                                   'probe', ip, str(port), protocol]))
    def s3(action):
        try: result = json.loads(ns('client', [sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                                            'client', action, str(config)], timeout=60))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            (evidence / (action + '-stderr.log')).write_text(cold.bounded_diagnostic(error.stderr, 'LATERAL_S3_FAILED')); raise
        save(action, result); return result
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
            args = ['--hold'] if role == 'client' else ['/usr/local/bin/weed', '-logtostderr=true', *role_args(role)]
            name = prefix + '-' + role
            cold.command(['docker', 'run', '--detach', '--name', name, '--network', network, '--ip', IPS[role],
                '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '128', '--memory', '512m', '--cpus', '1', '--log-opt', 'max-size=8m',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864,mode=1777',
                '--mount', 'type=bind,src=' + str(data / role) + ',dst=/data',
                '--mount', 'type=bind,src=' + str(config) + ',dst=/config,readonly',
                '--mount', 'type=bind,src=' + str(data / ('gate-' + role)) + ',dst=/gate,readonly',
                '--mount', 'type=bind,src=' + str(gate_binary) + ',dst=/network-gate,readonly',
                '--entrypoint', '/network-gate', cold.IMAGE_ID, '/gate/open', *args])
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
        before = s3('seed'); probes = []
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
        after = s3('read'); require({k:v for k,v in before.items() if k != 'mutatingRequests'} ==
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
    child = sub.add_parser('client'); child.add_argument('action', choices=('seed', 'read')); child.add_argument('config', type=Path)
    prober = sub.add_parser('probe'); prober.add_argument('ip'); prober.add_argument('port', type=int); prober.add_argument('protocol', choices=('tcp', 'udp'))
    args = parser.parse_args()
    if args.operation == 'run': run(args.archive.resolve(), args.work.absolute(), args.receipt.resolve(), args.gate_binary.resolve())
    elif args.operation == 'probe': print(json.dumps(socket_probe(args.ip, args.port, args.protocol)))
    else: print(json.dumps(client(args.action, args.config)))


if __name__ == '__main__': main()
