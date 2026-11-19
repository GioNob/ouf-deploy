"""Installation-specific retained endpoint inventory; never current route authority."""
import datetime
import hashlib
import ipaddress

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
import subprocess

from urllib.parse import urlencode, urlsplit

SCHEMA = 'ouf.semantic-registry-recovery-inputs-result.v1'
CASE_SCHEMA = 'ouf.semantic-registry-recovery-inputs-case.v1'
OPERATION = '/api/semantic/v1/references:resolve'
MAX_GETS = 6
MAX_BYTES = 2_097_152
STATE_FIELDS = ('Status', 'Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled',
                'Pid', 'ExitCode', 'Error', 'StartedAt', 'FinishedAt')

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

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
    for parent in p.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'ROOT_CONTROLLED_METADATA_ANCESTRY_REQUIRED')
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

class BaseEngine:
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
        require(path in self.paths and self.calls < MAX_GETS, 'CLOSED_SIX_GET_BUDGET')
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

def generation(actual, pin):
    s = actual['State']
    require(actual['Id'] == pin['containerId'] and s['Pid'] == pin['pid']
            and s['StartedAt'] == pin['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead'),
            'GATEWAY_GENERATION_CHANGED')
    require(actual['Image'] == pin['imageId'] and all(digest(actual[field]) == pin[key]
            for field,key in [('Config','configHash'),('HostConfig','hostConfigHash'),
                              ('NetworkSettings','networkSettingsHash')]), 'GATEWAY_BINDING_CHANGED')

def stable_fields(actual):
    # Omit continuously changing health-check history; bind lifecycle/config/network.
    return {'Id': actual['Id'], 'Image': actual['Image'], 'Config': actual['Config'],
            'HostConfig':actual['HostConfig'], 'Mounts':actual['Mounts'],
            'NetworkSettings': actual['NetworkSettings'], 'RestartCount': actual['RestartCount'],
            'State': {key: actual['State'].get(key) for key in STATE_FIELDS}}

def stopped(error):
    reason = str(error) if type(error) is Stop else 'DIAGNOSTIC_UNCONFIRMED_' + type(error).__name__
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'DIAGNOSTIC_UNCONFIRMED'
    return {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'readOnly': True, 'runtimeEffectsDispatched': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'rootCauseEstablished': False}


class Engine(BaseEngine):
    def __init__(self, binding, gateway_id, historical_id):
        self.binding, self.calls = binding, 0
        self.inspects = {'/v1.44/containers/' + cid + '/json' for cid in (gateway_id,historical_id)}
        self.inventory_path = '/v1.44/containers/json?all=true&size=false'
        self.paths = self.inspects | {self.inventory_path}

    def inventory(self):
        rows = decode(self.get(self.inventory_path))
        require(type(rows) is list and len(rows) <= 256, 'BOUNDED_CONTAINER_INVENTORY_REQUIRED')
        result = {}
        for row in rows:
            cid = row['Id']
            require(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid)
                    and cid not in result, 'UNIQUE_EXACT_INVENTORY_IDS_REQUIRED')
            require(row['State'] in {'created','running','paused','restarting','removing','exited','dead'},
                    'KNOWN_INVENTORY_STATE_REQUIRED')
            networks = row['NetworkSettings']['Networks']
            require(type(networks) is dict and len(networks) <= 32, 'BOUNDED_NETWORKS_REQUIRED')
            labels=row.get('Labels') or {}
            require(type(labels) is dict, 'INVENTORY_LABEL_OBJECT_REQUIRED')
            source=labels.get('org.opencontainers.image.source')
            require(source is None or type(source) is str and len(source)<=4096, 'BOUNDED_SOURCE_LABEL_REQUIRED')
            # Source-label equality is a discovery hint, never authenticated ownership.
            result[cid] = {'imageId': row['ImageID'], 'state': row['State'],
                           'networks': networks,'sourceLabel':source}
        return result


def retained_nodes(routes):
    # NativeGatewayTransport.routes() returns route_map(), keyed by exact route ID.
    # Never reinterpret a list/envelope or guess an alternative representation.
    require(type(routes) is dict and 0 < len(routes) <= 256, 'BOUNDED_RETAINED_ROUTE_MAP_REQUIRED')
    selected = []
    for rid, row in routes.items():
        require(type(rid) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,128}',rid)
                and type(row) is dict and row.get('id') == rid
                and len(encoded(row)) <= 262144, 'EXACT_RETAINED_ROUTE_ID_AND_BOUND_REQUIRED')
        uris = row.get('uris', [])
        require(type(uris) is list, 'RETAINED_URIS_LIST_REQUIRED')
        methods = row.get('methods', ['GET'])
        require(type(methods) is list, 'RETAINED_METHODS_LIST_REQUIRED')
        if OPERATION in [row.get('uri'), *uris] and 'GET' in methods and row.get('status', 1) == 1:
            selected.append(row)
    require(len(selected) == 1, 'ONE_EXACT_ACTIVE_RETAINED_SEMANTIC_GET_ROUTE_REQUIRED')
    row = selected[0]
    require('upstream_id' not in row and 'service_id' not in row,
            'INLINE_RETAINED_UPSTREAM_REQUIRED_NO_ADMIN_FALLBACK')
    upstream = row.get('upstream', {})
    require(type(upstream) is dict and not upstream.get('discovery_type')
            and not upstream.get('service_name'), 'STATIC_RETAINED_NODES_REQUIRED')
    raw = upstream.get('nodes')
    nodes = []
    if type(raw) is dict:
        for hostport, weight in raw.items():
            require(type(hostport) is str and type(weight) in (int,float) and weight > 0,
                    'VALID_RETAINED_NODE_REQUIRED')
            try:
                parsed = urlsplit('//'+hostport)
                require(not parsed.username and not parsed.password and not parsed.path
                        and not parsed.query and not parsed.fragment, 'VALID_RETAINED_NODE_REQUIRED')
                nodes.append((parsed.hostname, parsed.port))
            except ValueError:
                raise Stop('VALID_RETAINED_NODE_REQUIRED') from None
    elif type(raw) is list:
        for node in raw:
            require(type(node) is dict and type(node.get('weight')) in (int,float)
                    and node['weight'] > 0, 'VALID_RETAINED_NODE_REQUIRED')
            nodes.append((node.get('host'), node.get('port')))
    require(0 < len(nodes) <= 8 and len(set(nodes)) == len(nodes), 'BOUNDED_UNIQUE_RETAINED_NODES_REQUIRED')
    for host, port in nodes:
        require(type(host) is str and 0 < len(host) <= 253 and type(port) is int
                and 0 < port < 65536, 'VALID_RETAINED_NODE_REQUIRED')
    return nodes


def compare(nodes, inventory, gateway):
    gateway_networks = {v['NetworkID'] for v in gateway['NetworkSettings']['Networks'].values()
                        if v.get('NetworkID')}
    result = []
    for host, port in nodes:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            result.append({'nodeOrdinal':len(result), 'literalAddress':False,
                           'dnsResolutionPerformed':False, 'candidates':[]})
            continue
        matches = []
        for cid, item in inventory.items():
            endpoints = []
            for network in item['networks'].values():
                values = [network.get('IPAddress'), network.get('GlobalIPv6Address')]
                if str(address) in values:
                    endpoints.append(network.get('NetworkID') in gateway_networks)
            if endpoints:
                matches.append({'containerId':cid, 'state':item['state'],
                                'sharesObservedGatewayNetwork':any(endpoints),
                                'portListenerProven':False, 'serviceIdentityProven':False})
        require(len(matches) <= 16, 'BOUNDED_ADDRESS_CANDIDATES_REQUIRED')
        result.append({'nodeOrdinal':len(result), 'literalAddress':True,
                       'candidates':sorted(matches,key=lambda x:x['containerId']),
                       'noCandidateDoesNotProveUnreachable':True})
    return result


def boot_inputs(case):
    profile,raw=private_json(case['bootProfilePath'])
    require(hashlib.sha256(raw).hexdigest()==case['bootProfileSha256']
            and profile['schema']=='ouf.semantic-coordinated-boot-profile.v1','EXACT_BOOT_PROFILE_REQUIRED')
    saved={case['bootProfilePath']:raw}
    values=[]
    for key in ('coordinatedConfiguration','bootConfiguration'):
        path=profile[key]
        require(Path(path).is_relative_to('/etc/ouf/deploy-snapshots'), 'EXACT_BOOT_METADATA_SCOPE_REQUIRED')
        value,raw=private_json(path)
        require(hashlib.sha256(raw).hexdigest()==profile[key+'Hash'],'BOOT_CONFIGURATION_HASH_CHANGED')
        saved[path]=raw;values.append(value)
    owner,boot=values
    require(owner['kernel']==boot['kernel'] and owner['commonLockFile']==boot['lockFile']
            and owner['journalFile']!=boot['journalFile'], 'PAIRED_OWNER_BOOT_CONFIGURATION_REQUIRED')
    journals={}
    states={'BLOCKED','QUIESCED','ACTIVE','READY','PAUSED','RUNTIME_EMPTY','RUNTIME_COORDINATED_EMPTY',
            'RUNTIME_STAGED','RUNTIME_REGISTERED','LEASE_ACTIVE','EMPTY','RECONCILE_REQUIRED'}
    for role,config in [('coordinatedOwner',owner),('bootGuard',boot)]:
        path=config['journalFile']
        require(Path(path).is_relative_to('/etc/ouf/deploy-snapshots'),'EXACT_JOURNAL_SCOPE_REQUIRED')
        value,raw=private_json(path);saved[path]=raw
        state=value.get('state')
        out={'state':state if state in states else 'UNRECOGNIZED_STATE_REDACTED',
             'startAuthorizedObserved':value.get('startAuthorized') if type(value.get('startAuthorized')) is bool else None,
             'leaseAuthorizedObserved':value.get('leaseAuthorized') if type(value.get('leaseAuthorized')) is bool else None}
        addresses=value.get('leaseAddresses')
        if type(addresses) is list:
            require(len(addresses)<=16 and all(type(v) is list and len(v)<=256 for v in addresses),
                    'BOUNDED_LEASE_METADATA_REQUIRED')
            out['leaseAddressCounts']=[len(v) for v in addresses]
        journals[role]=out
    return {'journals':journals,'journalObservationIsRuntimeAuthority':False,
            'providerRegistryAssociationEstablished':False},saved


def loaded_guard(case):
    program=Path('/usr/bin/systemctl')
    for path in [program,*program.parents]:
        info=path.lstat()
        require(info.st_uid==0 and not info.st_mode&0o022
                and (stat.S_ISREG(info.st_mode) if path==program else stat.S_ISDIR(info.st_mode)),
                'ROOT_CONTROLLED_SYSTEMCTL_REQUIRED')
    reply=subprocess.run([str(program),'show','--no-pager','--property=ExecStart,ActiveState,SubState,Result',
                          'ouf-semantic-boot-guard.service'],stdin=subprocess.DEVNULL,
                         capture_output=True,timeout=6,env={'LC_ALL':'C'})
    require(reply.returncode==0 and len(reply.stdout)<=65536 and len(reply.stderr)<=65536,'BOUNDED_GUARD_SHOW_REQUIRED')
    values={}
    for line in reply.stdout.decode().splitlines():
        require('=' in line,'GUARD_SHOW_SHAPE_REQUIRED')
        key,value=line.split('=',1)
        require(key not in values,'DUPLICATE_GUARD_PROPERTY');values[key]=value
    require(set(values)=={'ExecStart','ActiveState','SubState','Result'},'EXACT_GUARD_PROPERTIES_REQUIRED')
    command=values['ExecStart']
    paths=re.findall(r'--configuration\s+(/[^\s;]+)',command)
    hashes=re.findall(r'--configuration-sha256\s+([a-f0-9]{64})(?:\s|;|$)',command)
    sources=re.findall(r'(/[^\s;]+/source/scripts/run_semantic_coordinated_boot_guard\.py)',command)
    expected_source=str(Path(case['bootProfilePath']).parent/'source/scripts/run_semantic_coordinated_boot_guard.py')
    require(paths==[case['bootProfilePath']] and hashes==[case['bootProfileSha256']]
            and sources==[expected_source], 'LOADED_BOOT_PROFILE_CHANGED')
    allowed={'active','inactive','failed','activating','deactivating','exited','dead','running','success',
             'exit-code','signal','timeout','start-limit-hit','condition','resources'}
    return {k:values[k] if values[k] in allowed else 'OTHER_REDACTED' for k in ('ActiveState','SubState','Result')}


def historical_projection(actual,nodes,inventory):
    state=actual['State'];labels=actual['Config'].get('Labels') or {}
    require(state.get('Status') in {'created','running','paused','restarting','removing','exited','dead'}
            and type(state.get('Running')) is bool and type(state.get('OOMKilled')) is bool
            and type(state.get('Pid')) is int and state['Pid']>=0
            and type(state.get('ExitCode')) is int and 0<=state['ExitCode']<=255
            and type(actual.get('RestartCount')) is int and actual['RestartCount']>=0,
            'BOUNDED_HISTORICAL_LIFECYCLE_REQUIRED')
    require(type(labels) is dict,'HISTORICAL_LABEL_OBJECT_REQUIRED')
    source=labels.get('org.opencontainers.image.source')
    require(source is None or type(source) is str and len(source)<=4096,'BOUNDED_HISTORICAL_SOURCE_LABEL_REQUIRED')
    configured=set()
    for network in actual['NetworkSettings']['Networks'].values():
        ipam=network.get('IPAMConfig') or {}
        configured.update(v for k,v in ipam.items() if k in ('IPv4Address','IPv6Address') and type(v) is str and v)
    candidates=[]
    for cid,item in inventory.items():
        same_image=item['imageId']==actual['Image']
        same_source=bool(source) and item['sourceLabel']==source
        if same_image or same_source:
            candidates.append({'containerId':cid,'state':item['state'],'sameHistoricalImage':same_image,
                               'sameHistoricalSourceLabel':same_source,'serviceIdentityProven':False})
    require(len(candidates)<=32,'BOUNDED_IMAGE_FAMILY_CANDIDATES_REQUIRED')
    return {'status':state['Status'],'running':state['Running'],'hasProcess':state['Pid']>0,
            'exitCode':state['ExitCode'],'oomKilled':state['OOMKilled'],'restartCount':actual['RestartCount'],
            'retainedNodeMatchesConfiguredAddress':[host in configured for host,port in nodes],
            'sourceLabelComparisonAvailable':bool(source),'imageFamilyCandidates':sorted(candidates,key=lambda c:c['containerId']),
            'otherRegistryImagesNotExcluded':True,'startupAuthorityIssued':False}


def run(case):
    require(type(case) is dict and set(case) == {'schema','contextPath','historicalRegistryId',
            'bootProfilePath','bootProfileSha256'}
            and case['schema'] == CASE_SCHEMA, 'EXACT_CASE_REQUIRED')
    root = case['contextPath']
    review, before_review = private_json(root+'/review.json')
    row, before_row = private_json(root+'/recovery.json')
    packet, before_packet = private_json(root+'/packet.json')
    native = review['executionReview']
    require(row['nextStage'] == len(native['stages']) == len(row['effects']) == 12
            and all(e['state']=='APPLIED' for e in row['effects']), 'COMPLETED_PATCH_REQUIRED')
    require(native['packetBinding']['path'] == root+'/packet.json'
            and native['packetBinding']['sha256'] == digest(packet), 'EXACT_RETAINED_PACKET_REQUIRED')
    nodes = retained_nodes(packet['routeDraft']['beforeRoutes'])
    require(packet['routeDraft']['beforeRoutes'] == packet['routeDraft']['afterRoutes'],
            'UNCHANGED_PATCH_ROUTES_REQUIRED')
    pin = native['runtimeGuardProfile']['unchangedApplications']['gateway']['binding']
    cid = pin['containerId']
    require(type(cid) is str and re.fullmatch('[a-f0-9]{64}',cid), 'EXACT_GATEWAY_ID_REQUIRED')
    historical_id=case['historicalRegistryId']
    require(type(historical_id) is str and re.fullmatch('[a-f0-9]{64}',historical_id)
            and historical_id!=cid,'EXACT_DISTINCT_HISTORICAL_ID_REQUIRED')
    boot,saved=boot_inputs(case)
    guard=loaded_guard(case)
    engine = Engine(native['engineBinding'],cid,historical_id)
    gateway = engine.inspect(cid)
    generation(gateway,pin)
    registry=engine.inspect(historical_id)
    first = engine.inventory()
    comparison = compare(nodes,first,gateway)
    historical=historical_projection(registry,nodes,first)
    second = engine.inventory()
    registry_after=engine.inspect(historical_id)
    after = engine.inspect(cid)
    generation(after,pin)
    require(first == second and stable_fields(gateway) == stable_fields(after)
            and stable_fields(registry)==stable_fields(registry_after), 'INVENTORY_OR_PROCESS_DRIFT')
    require(loaded_guard(case)==guard,'LOADED_GUARD_STATE_CHANGED')
    for path,raw in saved.items():require(private_json(path)[1]==raw,'BOOT_METADATA_CHANGED')
    for name, before in [('review',before_review),('recovery',before_row),('packet',before_packet)]:
        require(private_json(root+'/'+name+'.json')[1] == before, 'RETAINED_CONTEXT_CHANGED')
    return {'schema':SCHEMA,'status':'REGISTRY_RECOVERY_INPUTS_OBSERVED','complete':True,
            'readOnly':True,'engineGets':engine.calls,'maximumEngineGets':MAX_GETS,
            'maximumGuardShows':2,'guardShows':2,'loadedGuard':guard,'semanticBoot':boot,
            'historicalRegistry':historical,
            'inventoryContainerCount':len(first),'retainedSemanticNodeComparisons':comparison,
            'liveGatewayRouteMapRead':False,'currentRegistryIdentityEstablished':False,
            'historicalRegistrySubstituted':False,'serviceReadinessEstablished':False,
            'rootCauseEstablished':False,'addressesPrinted':False,'rawInventoryPrinted':False,
            'credentialFilesOpened':0,'oauthRequests':0,'databaseCalls':0,'gatewayWrites':0,
            'runtimeEffectsDispatched':0,'activationResubmitted':False,'automaticReplayAllowed':False,
            'budgetReset':False,'releaseAcceptance':False,'completedTechnicalPhases':8,
            'functionalMilestonesProven':4}


if __name__ == '__main__':
    try:
        require(os.geteuid() == 0 and sys.flags.isolated, 'ROOT_ISOLATED_READER_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('DIAGNOSTIC_DEADLINE')))
        signal.alarm(50)
        require(len(sys.argv) == 2, 'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1], 'rb') as source:
            raw = source.read(8193)
        require(len(raw) <= 8192, 'BOUNDED_CASE_REQUIRED')
        print(json.dumps(run(decode(raw)), sort_keys=True), flush=True)
    except Exception as error:
        print(json.dumps(stopped(error), sort_keys=True), flush=True)
        sys.exit(1)
