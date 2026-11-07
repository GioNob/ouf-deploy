#!/usr/bin/env python3
"""Bounded read of the current semantic upstream after the storage switch."""
import datetime
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys

PLAN = Path('/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1/plan.private.json')
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
ROUTE = '/internal/capabilities/v1/execute/semantic/search'
ADMIN_KEY = Path('/opt/ouf/secrets/apisix-admin-key')
CONFIG_TARGET = '/usr/local/apisix/conf/config.yaml'
HINTS = {
    'connectionRefused': r'connection refused',
    'nameResolutionFailed': r'host not found|name or service not known|no such host|failed to resolve|could not be resolved',
    'upstreamUnavailable': r'no live upstreams|failed to set peer|upstream timed out',
    'tlsFailure': r'SSLHandshakeException|certificate verify failed|unable to find valid certification path',
    'databaseAuthenticationFailed': r'password authentication failed|no pg_hba.conf entry',
    'databaseConnectionFailed': r'CannotGetJdbcConnectionException|PSQLException',
    'schemaMigrationFailed': r'FlywayException|FlywayValidateException|migration failed',
    'applicationStartupFailed': r'APPLICATION FAILED TO START|Application run failed',
    'authorizationDenied': r'authorization denied|access denied|access_denied',
    'expiredToken': r'token expired|token has expired|Jwt expired|JWT expired',
}

def need(ok, code):
    if not ok:
        raise RuntimeError(code)

def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'BOUNDED_REGULAR_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and
             (before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns), 'FILE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)

def inspect(cid):
    need(re.fullmatch('[a-f0-9]{64}', cid), 'EXACT_CONTAINER_ID_REQUIRED')
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(8)
            self.sock.connect('/run/docker.sock')
    connection = Local('localhost', timeout=8)
    try:
        connection.request('GET', '/v1.44/containers/' + cid + '/json')
        response = connection.getresponse()
        raw = response.read(2*1024*1024 + 1)
        need(response.status == 200 and len(raw) <= 2*1024*1024, 'CONTAINER_READ_FAILED')
        return json.loads(raw)
    finally:
        connection.close()

def pin(doc):
    return hashlib.sha256(json.dumps({k: doc[k] for k in
        ('Id', 'Image', 'State', 'Config', 'HostConfig', 'NetworkSettings', 'Mounts')},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def stable_pin(doc):
    data = dict(doc)
    data['State'] = {k: doc['State'].get(k) for k in
                     ('Running', 'Restarting', 'Status', 'Pid', 'StartedAt', 'FinishedAt', 'ExitCode')}
    return pin(data)

def runtime_summary(doc, expected):
    state = doc['State']
    return {'running': state['Running'], 'state': state['Status'],
            'exitCode': state['ExitCode'], 'oomKilled': state['OOMKilled'],
            'imageMatchesRetained': doc['Image'] == expected,
            'health': state.get('Health', {}).get('Status')}

def log_summary(cid):
    command = subprocess.run((*DOCKER, 'logs', '--since', '30m', '--tail', '200', cid),
                             capture_output=True, timeout=12)
    raw = command.stdout + command.stderr
    need(len(raw) <= 3*1024*1024, 'LOG_RESPONSE_LIMIT')
    if command.returncode != 0:
        return {'read': False}
    text = raw.decode('utf-8', errors='replace')
    return {'read': True, 'tailLimit': 200, 'window': '30m',
            'linesRead': len(text.splitlines()),
            'hints': {key: len(re.findall(pattern, text, re.I))
                      for key, pattern in HINTS.items() if re.search(pattern, text, re.I)},
            'rawLogsEmitted': False, 'correlationWithFailedRequestProven': False}

def selected_key(config):
    # The existing installation uses this exact external key when the literal list is empty.
    lines = config.decode().splitlines()
    starts = [(i, len(line)-len(line.lstrip(' '))) for i, line in enumerate(lines)
              if re.fullmatch(r' *admin_key: *(?:#.*)?', line)]
    need(len(starts) == 1, 'ONE_ADMIN_KEY_SECTION_REQUIRED')
    start, indent = starts[0]
    parents = []
    for line in lines[:start]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        depth = len(line)-len(line.lstrip(' '))
        parents = [row for row in parents if row[0] < depth]
        match = re.fullmatch(r'( *)([A-Za-z_][A-Za-z0-9_]*): *(?:#.*)?', line)
        if match:
            parents.append((depth, match[2]))
    need([p[1] for p in parents if p[0] < indent] == ['deployment', 'admin'], 'ADMIN_SECTION_INVALID')
    records, row = [], None
    for line in lines[start+1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if len(line)-len(line.lstrip(' ')) <= indent:
            break
        match = re.fullmatch(r' +(- +)?(name|key|role): *(.*?) *', line)
        need(match is not None, 'UNSUPPORTED_ADMIN_KEY_SYNTAX')
        if match[1]:
            if row is not None:
                records.append(row)
            row = {}
        need(row is not None and match[2] not in row, 'DUPLICATE_ADMIN_KEY_FIELD')
        value = match[3]
        if value.startswith('"'):
            value = json.loads(value)
        elif value.startswith("'"):
            need(value.endswith("'"), 'ADMIN_SCALAR_INVALID')
            value = value[1:-1].replace("''", "'")
        else:
            value = value.split(' #', 1)[0].strip()
        row[match[2]] = value
    if row is not None:
        records.append(row)
    if not records:
        key = read(ADMIN_KEY, 8192).decode('ascii').strip()
    else:
        need(len(records) <= 8 and all(set(row) == {'name', 'key', 'role'} for row in records),
             'ADMIN_KEY_RECORD_INVALID')
        admins = [row for row in records if row['role'] == 'admin']
        need(len(admins) == 1, 'ONE_ADMIN_KEY_REQUIRED')
        key = admins[0]['key']
    need(isinstance(key, str) and 16 <= len(key) <= 4096 and
         all(33 <= ord(c) <= 126 for c in key) and not key.startswith(('$ENV', '${', '$secret')),
         'LITERAL_ADMIN_KEY_REQUIRED')
    return key

ADMIN_CHILD = r'''import http.client,json,sys
data=json.loads(sys.stdin.buffer.read(8193))
connection=http.client.HTTPConnection('127.0.0.1',9180,timeout=8)
try:
    connection.request('GET','/apisix/admin/routes',headers={'X-API-KEY':data['key']})
    response=connection.getresponse()
    raw=response.read(8388609)
    if response.status!=200 or len(raw)>8388608: raise RuntimeError('ADMIN_READ_FAILED')
    sys.stdout.buffer.write(raw)
finally: connection.close()
'''

def route_read(gateway, report):
    mounts = [m for m in gateway['Mounts'] if m['Destination'] == CONFIG_TARGET]
    need(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and not mounts[0]['RW'], 'CONFIG_MOUNT_CHANGED')
    key = selected_key(read(Path(mounts[0]['Source']), 1024*1024))
    report['adminRouteGetAttempts'] = report.get('adminRouteGetAttempts', 0) + 1
    response = subprocess.run(('/usr/bin/nsenter', '--target', str(gateway['State']['Pid']), '--net',
         sys.executable, '-I', '-B', '-S', '-c', ADMIN_CHILD),
         input=json.dumps({'key': key}).encode(), capture_output=True, timeout=12)
    need(response.returncode == 0 and len(response.stdout) <= 8*1024*1024, 'ADMIN_ROUTE_READ_FAILED')
    data = json.loads(response.stdout)
    need(isinstance(data.get('list'), list) and data.get('total') == len(data['list'])
         and len(data['list']) <= 512, 'COMPLETE_ROUTE_LIST_REQUIRED')
    rows = []
    for entry in data['list']:
        value = entry.get('value', entry)
        if isinstance(value.get('value'), dict):
            value = value['value']
        if value.get('uri') == ROUTE or ROUTE in (value.get('uris') or []):
            rows.append(value)
    need(len(rows) == 1, 'ONE_SEMANTIC_SEARCH_ROUTE_REQUIRED')
    report['semanticRouteFound'] = True
    return rows[0]

DNS_CHILD=r'''import ipaddress,json,os,re,signal,socket,struct,sys
signal.alarm(25)
try:
    data=json.loads(sys.stdin.buffer.read(32769))
    queries=data['queries'];allowed=set(data['registryAddresses']);resolver=str(ipaddress.ip_address(data['resolver']))
    if not 0<len(queries)<=4 or not 0<len(allowed)<=4:raise ValueError()
    result=[]
    def skip_name(raw,pos):
        for _ in range(128):
            n=raw[pos];pos+=1
            if n==0:return pos
            if n&192==192:return pos+1
            if n>63:raise ValueError()
            pos+=n
        raise ValueError()
    for query in queries:
        host=query['host'];port=query['port'];addresses=[];rcode=0;dns_unavailable=False
        if type(port)is not int or not 1<=port<=65535:raise ValueError()
        try:addresses=[str(ipaddress.ip_address(host))]
        except ValueError:
            if type(host)is not str or len(host)>253 or not re.fullmatch(r'[A-Za-z0-9_.-]+',host):raise ValueError()
            labels=host.rstrip('.').split('.')
            if not all(0<len(v)<=63 for v in labels):raise ValueError()
            token=os.urandom(2);name=b''.join(bytes([len(v)])+v.encode('ascii')for v in labels)+b'\0'
            request=token+struct.pack('!HHHHH',256,1,0,0,0)+name+struct.pack('!HH',1,1)
            family=socket.AF_INET6 if ':'in resolver else socket.AF_INET
            try:
                with socket.socket(family,socket.SOCK_DGRAM)as conn:
                    conn.settimeout(2);conn.connect((resolver,53));conn.send(request);raw=conn.recv(8192)
            except OSError:
                dns_unavailable=True;raw=token+struct.pack('!HHHHH',0x8002,0,0,0,0)
            if raw[:2]!=token or len(raw)<12:raise ValueError()
            flags,questions,answers,_,_=struct.unpack('!HHHHH',raw[2:12]);rcode=flags&15;pos=12
            if questions>4 or answers>32 or flags&512:raise ValueError()
            for _ in range(questions):pos=skip_name(raw,pos)+4
            for _ in range(answers):
                pos=skip_name(raw,pos);kind,klass,ttl,size=struct.unpack('!HHIH',raw[pos:pos+10]);pos+=10
                value=raw[pos:pos+size];pos+=size
                if klass==1 and kind==1 and size==4:addresses.append(socket.inet_ntop(socket.AF_INET,value))
        addresses=sorted(set(addresses));matches=[v for v in addresses if v in allowed];reachable=False
        for value in matches[:4]:
            try:
                with socket.create_connection((value,port),timeout=2):reachable=True
            except OSError:pass
        direct=False
        for value in sorted(allowed)[:4]:
            try:
                with socket.create_connection((value,port),timeout=2):direct=True
            except OSError:pass
        result.append({'rcode':rcode,'dnsUnavailable':dns_unavailable,'addressCount':len(addresses),'matchesRegistry':bool(matches),
            'onlyRegistryAddresses':bool(addresses)and set(addresses)<=allowed,
            'matchedTcpReachable':reachable,'directRegistryTcpReachable':direct})
    sys.stdout.write(json.dumps(result));sys.stdout.flush()
except BaseException:os._exit(1)
os._exit(0)
'''


def topology(route, gateway, registry, report):
    upstream = route.get('upstream')
    need(isinstance(upstream, dict) and isinstance(upstream.get('nodes'), dict)
         and 0 < len(upstream['nodes']) <= 4, 'INLINE_UPSTREAM_REQUIRED')
    queries = []
    aliases = {registry['Name'].lstrip('/')}
    addresses, common = set(), []
    for name, endpoint in registry['NetworkSettings']['Networks'].items():
        peer = gateway['NetworkSettings']['Networks'].get(name)
        if peer and peer['NetworkID'] == endpoint['NetworkID']:
            common.append(name)
            aliases.update(endpoint.get('Aliases') or [])
            if endpoint.get('IPAddress'):
                addresses.add(str(ipaddress.ip_address(endpoint['IPAddress'])))
    for node, weight in upstream['nodes'].items():
        host, sep, port = node.rpartition(':')
        need(sep and re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', host) and port.isdigit()
             and 0 < int(port) < 65536 and isinstance(weight, (int, float)) and weight > 0,
             'UPSTREAM_NODE_INVALID')
        queries.append({'host': host, 'port': int(port)})
    report['upstream'] = {
        'nodeCount': len(queries), 'scheme': upstream.get('scheme', 'http'),
        'commonNetworkCount': len(common),
        'configuredNamesMatchRegistry': [q['host'] in aliases or q['host'] in addresses for q in queries],
        'activeHealthCheckConfigured': bool((upstream.get('checks') or {}).get('active'))}
    if not registry['State']['Running'] or not addresses:
        report['upstream']['connectivitySkipped'] = 'REGISTRY_STOPPED_OR_NO_SHARED_ADDRESS'
        return
    resolver_path = Path(gateway['ResolvConfPath'])
    need(resolver_path.name == 'resolv.conf' and resolver_path.parent.name == gateway['Id'],
         'RESOLVER_PATH_INVALID')
    resolvers = [str(ipaddress.ip_address(line.split()[1]))
                 for line in read(resolver_path, 16384).decode('ascii').splitlines()
                 if re.match(r'^nameserver\s+', line)]
    need(0 < len(resolvers) <= 3, 'RESOLVER_SELECTION_REQUIRED')
    result = subprocess.run(('/usr/bin/nsenter', '--target', str(gateway['State']['Pid']), '--net',
        sys.executable, '-I', '-B', '-S', '-c', DNS_CHILD),
        input=json.dumps({'queries': queries, 'registryAddresses': sorted(addresses),
                          'resolver': resolvers[0]}).encode(),
        capture_output=True, timeout=28)
    need(result.returncode == 0 and len(result.stdout) <= 32768, 'DNS_TCP_READ_FAILED')
    report['upstream']['dnsAndTcp'] = json.loads(result.stdout)
    report['upstream']['httpBusinessRequestMade'] = False

def execute(report):
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    raw = read(PLAN, 1024*1024)
    need(hashlib.sha256(raw).hexdigest() == PLAN_SHA, 'RETAINED_PLAN_CHANGED')
    roles = json.loads(raw)['roles']
    selected = {name: inspect(roles[name]['containerId']) for name in ('semantic', 'apisix', 'gateway-owner')}
    report['services'] = {name: runtime_summary(doc, roles[name]['nativeImage'])
                          for name, doc in selected.items()}
    need(all(doc['Image'] == roles[name]['nativeImage'] for name, doc in selected.items()), 'RETAINED_IMAGE_CHANGED')
    for name in ('semantic', 'apisix'):
        report['services'][name]['recentLogSummary'] = log_summary(selected[name]['Id'])
    need(selected['apisix']['State']['Running'], 'APISIX_NOT_RUNNING')
    route = route_read(selected['apisix'], report)
    topology(route, selected['apisix'], selected['semantic'], report)
    need(all(stable_pin(inspect(doc['Id'])) == stable_pin(doc) for doc in selected.values()),
         'RUNTIME_CHANGED_DURING_READ')
    report.update(status='SEMANTIC_UPSTREAM_READ_COMPLETE', runtimeUnchangedDuringRead=True)

def main():
    report = {'schema': 'ouf.current-semantic-upstream-read.v1', 'status': 'READ_INCOMPLETE',
              'serviceConfigurationChanged': False, 'serviceStops': 0, 'databaseRequests': 0,
              's3Requests': 0, 'permissionChanges': 0, 'credentialValuesEmitted': False,
              'rawLogsEmitted': False, 'businessRequestsIssued': 0}
    signal.alarm(110)
    try:
        with open('/run/lock/ouf-runtime-e2e.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            execute(report)
    except Exception as exc:
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z0-9_]{1,120}', str(exc)) else type(exc).__name__
    report['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'SEMANTIC_UPSTREAM_READ_COMPLETE' else 1

if __name__ == '__main__':
    raise SystemExit(main())

