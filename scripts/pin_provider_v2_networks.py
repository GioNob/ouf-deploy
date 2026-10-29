"""Declare fixed NIC metadata on exactly two owned, never-started candidates.

No start, exec, image, firewall, root file or key operation is implemented.
A durable claim prevents replay after any partially completed API operation.
"""
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import tempfile

CANDIDATES = {
 'adapter': ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67', 'ouf-semantic-provider-v2', 'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc'),
 'southbound': ('1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916', 'ouf-semantic-southbound-v2', 'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366')}
NETWORKS = {
 'ouf-backend': ('113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3', 'br-113b5f0a3c53', True, '172.18.0.0/16'),
 'ouf-semantic-provider-internal': ('2a6652422b45db6f359d94d779ab8625b1ad99b1750bb54582b4b8c4e8aa9307', 'oufsp-int', True, '172.21.0.0/16'),
 'ouf-semantic-provider-egress': ('db8bc9f8feccc3c14f2818a5c843f5c08e5eb2e192530858d88a70ce1cc0a86d', 'oufsp-egress', False, '172.22.0.0/16')}
PLAN = {
 'adapter': {'ouf-semantic-provider-internal': ('172.21.0.3', '02:42:ac:15:00:03', 'oufint0'), 'ouf-semantic-provider-egress': ('172.22.0.3', '02:42:ac:16:00:03', 'oufeg0')},
 'southbound': {'ouf-backend': ('172.18.0.14', '02:42:ac:12:00:0e', 'oufback0'), 'ouf-semantic-provider-internal': ('172.21.0.2', '02:42:ac:15:00:02', 'oufint0'), 'ouf-semantic-provider-egress': ('172.22.0.2', '02:42:ac:16:00:02', 'oufeg0')}}
def require(ok, code):
    if not ok: raise ValueError(code)
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15); self.sock.connect('/var/run/docker.sock')
class API:
    def __init__(self):
        v = self.request('GET', '/version', versioned=False)
        require(v['Version'] == '29.8.1' and re.fullmatch(r'1\.[0-9]{2}', v['ApiVersion']), 'ENGINE_DRIFT')
        self.version = v['ApiVersion']
    def request(self, method, path, value=None, versioned=True):
        # Callers supply only fixed IDs or Docker-generated 64-hex IDs.
        c = Connection('localhost', timeout=15)
        try:
            c.request(method, ('/v' + self.version if versioned else '') + path,
                      body=encoded(value) if value is not None else None,
                      headers={'Content-Type': 'application/json'})
            r = c.getresponse(); b = r.read(2097153)
            require(r.status in (200, 201, 204) and len(b) <= 2097152, 'BOUNDED_DOCKER_API_FAILED')
            return json.loads(b) if b else None
        finally: c.close()
    def inspect(self, cid):
        require(bool(re.fullmatch('[0-9a-f]{64}', cid)), 'CONTAINER_ID_INVALID')
        return self.request('GET', '/containers/' + cid + '/json')
def candidate(row, role):
    cid, name, image = CANDIDATES[role]; s = row['State']; h = row['HostConfig']
    require(row['Id'] == cid and row['Name'] == '/' + name and row['Image'] == image, 'CANDIDATE_IDENTITY_DRIFT')
    require(s['Status'] == 'created' and s['Pid'] == 0 and not s['Running'] and not s['Restarting'] and s['StartedAt'].startswith('0001-'), 'CANDIDATE_NOT_NEVER_STARTED')
    require(h['Runtime'] == 'ouf-semantic-admitted-v2' and h['RestartPolicy']['Name'] == 'no', 'RUNTIME_DRIFT')
    require(row['Config']['Labels'].get('ouf.semantic.provider.v2.creation') == 'semantic-provider-v2-stopped-resume-k5mmsudx', 'OWNERSHIP_DRIFT')
    require(set(row['NetworkSettings']['Networks']) == set(PLAN[role]), 'NETWORK_SET_DRIFT')
def immutable(row): return digest({k: row[k] for k in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'State')})
def endpoint(role, name, row, pinned):
    ip, mac, interface = PLAN[role][name]; n = row['NetworkSettings']['Networks'][name]
    require(n['NetworkID'] in ('', NETWORKS[name][0]) and n['IPAMConfig'] == {'IPv4Address': ip}, 'ENDPOINT_ADDRESS_DRIFT')
    require(n['Aliases'] == [CANDIDATES[role][1]] and not n.get('Links') and n.get('GwPriority', 0) == 0, 'ENDPOINT_BINDING_DRIFT')
    require(not n['IPAddress'] and not n['EndpointID'], 'ENDPOINT_ALREADY_ALLOCATED')
    wanted = {'com.docker.network.endpoint.ifname': interface} if pinned else {}
    require((n.get('DriverOpts') or {}) == wanted and n['MacAddress'] == (mac if pinned else ''), 'ENDPOINT_DECLARATION_DRIFT')
    return {'IPAMConfig': {'IPv4Address': ip}, 'Aliases': n['Aliases'], 'MacAddress': mac,
            'DriverOpts': {'com.docker.network.endpoint.ifname': interface}, 'GwPriority': 0}
def apply(api, claim):
    ids = [r['Id'] for r in api.request('GET', '/containers/json?all=1')]
    require(len(ids) == 98 and len(set(ids)) == 98, 'FLEET_COUNT_DRIFT')
    old = {}; rows = {}; known = {v[0] for v in CANDIDATES.values()}
    for cid in sorted(ids):
        row = api.inspect(cid)
        if cid not in known: old[cid] = digest(row['State'])
        else: rows[cid] = row
        for name, n in row['NetworkSettings']['Networks'].items():
            if name in NETWORKS and cid not in known:
                for role in PLAN:
                    if name not in PLAN[role]: continue
                    ip, mac, _ = PLAN[role][name]
                    require((n.get('IPAMConfig') or {}).get('IPv4Address') != ip and n.get('IPAddress') != ip and n.get('MacAddress') != mac, 'NETWORK_COLLISION')
    operations = []
    for role, (cid, _, _) in CANDIDATES.items():
        row = rows[cid]; candidate(row, role)
        for name in PLAN[role]:
            n = api.request('GET', '/networks/' + NETWORKS[name][0]); nid, bridge, internal, subnet = NETWORKS[name]
            require(n['Id'] == nid and n['Name'] == name and n['Driver'] == 'bridge' and n['Internal'] == internal and n['EnableIPv6'] is False, 'NETWORK_DRIFT')
            require((n['Options'] or {}).get('com.docker.network.bridge.name', 'br-' + nid[:12]) == bridge and n['IPAM']['Config'][0]['Subnet'] == subnet, 'NETWORK_COORDINATE_DRIFT')
            operations.append((role, cid, name, endpoint(role, name, row, False)))
    # Durable claim before any mutation. A failure never auto-adopts or replays it.
    claim({'state': 'CLAIMED', 'operationCount': len(operations)})
    for role, cid, name, settings in operations:
        current = api.inspect(cid); candidate(current, role)
        require(immutable(current) == immutable(rows[cid]), 'CANDIDATE_CONFIGURATION_DRIFT')
        endpoint(role, name, current, False)
        nid = NETWORKS[name][0]
        api.request('POST', '/networks/' + nid + '/disconnect', {'Container': cid, 'Force': False})
        api.request('POST', '/networks/' + nid + '/connect', {'Container': cid, 'EndpointConfig': settings})
        current = api.inspect(cid); candidate(current, role); endpoint(role, name, current, True)
        require(immutable(current) == immutable(rows[cid]), 'CANDIDATE_CONFIGURATION_DRIFT')
    require(set(r['Id'] for r in api.request('GET', '/containers/json?all=1')) == set(ids), 'FLEET_ID_DRIFT')
    for cid, state_hash in old.items(): require(digest(api.inspect(cid)['State']) == state_hash, 'EXISTING_STATE_DRIFT')
    report = {'schema': 'ouf.semantic-provider-v2-network-declarations.v1', 'status': 'DECLARED_AND_READBACK_VERIFIED',
        'candidateCount': 2, 'candidatesNeverStarted': True, 'declarationCount': 5, 'networkAttachmentOperations': 10,
        'containerLifecycleOperations': 0, 'existingContainerCount': 96, 'existingContainerStatesUnchanged': True,
        'liveAddressAllocationProven': False, 'liveInterfaceBindingProven': False, 'startAuthorized': False,
        'acceptanceGranted': False, 'privateKeysRead': 0, 'rulesChanged': False, 'providerCalls': 0,
        'declarations': PLAN, 'secretValuesPrinted': False}
    claim({'state': 'COMPLETED', 'report': report}); return report
def main():
    os.umask(0o077)
    directory = None
    try:
        require(os.getuid() == 1000 and os.environ.get('USER') == 'oufadmin', 'RUNNER_IDENTITY_DRIFT')
        path = Path.home() / '.ouf-v2-network-declarations.claim'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as claim_file:
            fcntl.flock(claim_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def claim(value):
                claim_file.seek(0); claim_file.truncate(); claim_file.write(encoded(value)); claim_file.flush(); os.fsync(claim_file.fileno())
            directory = tempfile.mkdtemp(prefix='ouf-v2-network-declarations-', dir=Path.home())
            report = apply(API(), claim)
            Path(directory, 'report.json').write_bytes(encoded(report))
            print('OUF_PROVIDER_V2_NETWORK_DECLARATIONS=' + encoded(report).decode())
            return 0
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z_]+', str(error)) else 'CLAIM_EXISTS_OR_BOUNDED_OPERATION_FAILED'
        print('OUF_PROVIDER_V2_NETWORK_DECLARATIONS=BLOCKED REASON=' + code + ' DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true')
        return 1
if __name__ == '__main__': raise SystemExit(main())
