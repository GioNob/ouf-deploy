"""Bounded live Engine metadata for a stopped rollout; no continuation authority.

Loaded separately from the immutable native executor. Only pure native frame/
generation predicates are called. No NativePorts, HUMAN reader, issuer, key
reader, SQL, HTTP owner/Gateway control or lifecycle component is instantiated.
"""
import copy
import http.client
import os
from pathlib import Path
import re
import socket
import stat
import time
from urllib.parse import quote


class Denied(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Denied(code)


class EngineMetadata:
    def __init__(self, binding, containers, image, decode):
        self.binding = copy.deepcopy(binding)
        self.decode = decode
        self.containers = set(containers)
        require(len(self.containers) == 8 and all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v)
                for v in self.containers), 'EXACT_EIGHT_DURABLE_CONTAINER_IDS_REQUIRED')
        require(type(image) is str and re.fullmatch('sha256:[0-9a-f]{64}', image),
                'EXACT_RETAINED_GATEWAY_IMAGE_REQUIRED')
        self.paths = {'/v1.44/containers/' + v + '/json' for v in self.containers}
        self.image_path = '/v1.44/images/' + quote(image, safe='') + '/json'
        self.paths.add(self.image_path)
        self.calls = 0
        self.maximum = 18
        self.check()

    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and str(p.resolve()) == str(p) and '..' not in p.parts,
                'EXACT_NO_SYMLINK_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                    == self.binding['socketBinding'], 'PINNED_ENGINE_SOCKET_REQUIRED')

    def get(self, path):
        require(path in self.paths and self.calls < self.maximum, 'CLOSED_FINITE_ENGINE_GET_ONLY')
        self.check()
        engine_path = self.binding['socketPath']
        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(engine_path)
        connection = Connection('retained-engine', timeout=5)
        try:
            self.calls += 1
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(4194305)
            require(response.status == 200 and 0 < len(raw) <= 4194304, 'BOUNDED_ENGINE_METADATA_REPLY_REQUIRED')
            self.check()
            return self.decode(raw)
        finally:
            connection.close()

    def container(self, cid):
        require(cid in self.containers, 'EXACT_DURABLE_CONTAINER_ID_ONLY')
        value = self.get('/v1.44/containers/' + cid + '/json')
        require(type(value) is dict and value.get('Id') == cid, 'ENGINE_REPLY_IDENTITY_DRIFT')
        return value


def namespace(pid):
    require(type(pid) is int and pid > 0, 'EXACT_RECORDED_PROCESS_PID_REQUIRED')
    s = os.stat('/proc/' + str(pid) + '/ns/net')
    return {'device': s.st_dev, 'inode': s.st_ino}


def key_metadata(path, expected):
    """Stat the original key inode; never open its bytes or return its hash."""
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts, 'EXACT_RETAINED_KEY_REFERENCE_REQUIRED')
    fds = []
    ancestors = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        for part in p.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            fds.append(child)
            s = os.fstat(child)
            require(s.st_uid == 0 and not s.st_mode & 0o022, 'RETAINED_KEY_ANCESTRY_REQUIRED')
            identity = (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)
            ancestors.append((fd, part, child, identity))
            fd = child
        s = os.stat(p.name, dir_fd=fd, follow_symlinks=False)
        actual = [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                  s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == 64
                and stat.S_IMODE(s.st_mode) == 0o400 and actual == expected,
                'EXACT_ORIGINAL_DEDICATED_KEY_METADATA_REQUIRED')
        for parent, name, child, pin in ancestors:
            for observed in (os.fstat(child), os.stat(name, dir_fd=parent, follow_symlinks=False)):
                require(pin == (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_gid, observed.st_mode),
                        'KEY_ANCESTRY_CHANGED_DURING_STAT')
        return True
    finally:
        for fd in reversed(fds): os.close(fd)


def resources(native, row):
    result = {}
    for module in ('ingestion', 'gateway'):
        for kind in ('CREATE_REPLACEMENT', 'START_REPLACEMENT'):
            name = module + '.' + kind
            i = next(i for i, s in enumerate(native['stages']) if s['name'] == name)
            require(i < row['nextStage'] and row['effects'][i]['stage'] == name
                    and row['effects'][i]['state'] == 'APPLIED', 'APPLIED_DURABLE_REPLACEMENT_REQUIRED')
            result[name] = row['effects'][i]['nativeResource']
        require(result[module + '.CREATE_REPLACEMENT']['containerId']
                == result[module + '.START_REPLACEMENT']['containerId'], 'SAME_DURABLE_FIRST_PROCESS_REQUIRED')
    return result


def runtime_snapshot(native, packet, row, modules, engine, *, namespace_read=namespace):
    c, guard, replacement, bindings = modules
    c.scope(native)
    guard.validate_profile(native['runtimeGuardProfile'], packet)
    allocated = resources(native, row)
    values = {}
    for name, pin in native['runtimeGuardProfile']['unchangedApplications'].items():
        actual = engine.container(pin['binding']['containerId'])
        guard.unchanged(actual, pin)
        values['unchanged.' + name] = {'binding': bindings.observed(actual, pin['bindingProfile']),
                                     'restartCount': actual['RestartCount']}
    database = native['databaseControlProfile']
    actual = engine.container(database['postgresRuntimeBinding']['containerId'])
    pin = {'binding': database['postgresRuntimeBinding'], 'restartCount': database['postgresRestartCount'],
           'bindingProfile': database['runtimeBindingProfile']}
    guard.unchanged(actual, pin)
    values['unchanged.postgres'] = {'binding': bindings.observed(actual, pin['bindingProfile']),
                                  'restartCount': actual['RestartCount']}
    image_id = packet['expectedRuntimeBindings']['gateway']['imageId']
    image = engine.get(engine.image_path)
    require(type(image) is dict and image.get('Id') == image_id and type(image.get('Config')) is dict,
            'EXACT_GATEWAY_IMAGE_CONFIG_REQUIRED')
    for module in ('ingestion', 'gateway'):
        old = engine.container(packet['expectedRuntimeBindings'][module]['containerId'])
        guard.predecessor(module, old, native['runtimeGuardProfile'], packet, native, row)
        frame = packet['frames'][module]
        require(old['State']['Running'] is False and not old['NetworkSettings']['Networks'],
                'RETAINED_PREDECESSOR_MUST_REMAIN_STOPPED_DETACHED')
        values['retained.' + module] = {k: old[k] for k in ('Id', 'Name', 'Image', 'HostConfig', 'Mounts', 'NetworkSettings')}
        values['retained.' + module]['state'] = {k: old['State'][k] for k in ('Running', 'Pid', 'StartedAt')}
        cid = allocated[module + '.CREATE_REPLACEMENT']['containerId']
        process = allocated[module + '.START_REPLACEMENT']
        actual = engine.container(cid)
        # The key file is not opened. Config is compared to the frame except for
        # its resolved key slot, whose VALUE is deliberately not reverified here.
        key = None
        if module == 'gateway':
            env = [v.split('=', 1)[1] for v in actual['Config']['Env']
                   if v.startswith('OUF_INGESTION_READ_OWNER_KEY=')]
            require(len(env) == 1 and re.fullmatch('[0-9a-f]{64}', env[0]), 'ONE_RESOLVED_GATEWAY_KEY_SLOT_REQUIRED')
            key = env[0]
        replacement.validate(frame, actual, packet['candidate']['imageConfig'] if module == 'ingestion' else image['Config'],
            packet['expectedRuntimeBindings'][module]['containerId'], created_id=cid, process=process,
            phase='RUNNING', restart_restored=False, resolved_owner_key=key)
        values['replacement.' + module] = {'process': process, 'binding': bindings.observed(actual, bindings.SORTED),
                                         'restartCount': actual['RestartCount']}
    owner_namespace = namespace_read(native['ownerControlProfile']['runtimeBinding']['pid'])
    require(owner_namespace == native['ownerControlProfile']['networkNamespace'], 'OWNER_NAMESPACE_GENERATION_CHANGED')
    gateway_namespace = namespace_read(allocated['gateway.START_REPLACEMENT']['pid'])
    require(gateway_namespace != native['retainedGatewayNamespace'], 'REPLACEMENT_GATEWAY_MUST_USE_NEW_NAMESPACE')
    values['namespaces'] = {'owner': owner_namespace, 'gateway': gateway_namespace}
    return values


def inspect(case, snapshot, modules, *, engine_type=EngineMetadata, namespace_read=namespace,
            key_stat=key_metadata, clock=time.time):
    started = clock()
    monotonic_started = time.monotonic()
    previous = snapshot['inspect'](snapshot['CASE'])
    require(previous['journalHash'] == case['journalHash'] and previous['reviewHash'] == case['reviewHash']
            and previous['logicalOperationRef'] == case['logicalOperationRef'] and previous['sameBoot'] is True
            and previous['wallClockConsistent'] is True and previous['recordedSecondsRemaining'] == 0
            and previous['recordedMonotonicSecondsRemaining'] == 0 and previous['pendingStageClaim'] is False,
            'EXACT_EXPIRED_STAGE18_SNAPSHOT_REQUIRED')
    context = previous['contextPath']
    read = snapshot['private_read']; decode = snapshot['decode']; digest = snapshot['digest']
    selected = {name: read(context + '/' + name) for name in ('review.json', 'recovery.json')}
    review, row = [decode(selected[k]) for k in ('review.json', 'recovery.json')]
    require(digest(review) == case['reviewHash'] and digest(row) == case['journalHash'], 'EXACT_IMMUTABLE_STOPPED_INPUTS_REQUIRED')
    native = review['executionReview']
    binding = native['packetBinding']
    packet_raw = read(binding['path']); packet = decode(packet_raw)
    require(digest(packet) == binding['sha256'], 'ORIGINAL_PRIVATE_PACKET_REQUIRED')
    allocated = resources(native, row)
    ids = [p['binding']['containerId'] for p in native['runtimeGuardProfile']['unchangedApplications'].values()]
    ids += [native['databaseControlProfile']['postgresRuntimeBinding']['containerId']]
    ids += [packet['expectedRuntimeBindings'][m]['containerId'] for m in ('ingestion', 'gateway')]
    ids += [allocated[m + '.CREATE_REPLACEMENT']['containerId'] for m in ('ingestion', 'gateway')]
    engine = engine_type(native['engineBinding'], ids, packet['expectedRuntimeBindings']['gateway']['imageId'], decode)
    key_i = next(i for i, s in enumerate(native['stages']) if s['name'] == 'CREATE_DEDICATED_KEY')
    def check_key():
        return key_stat(packet['dedicatedOwnerKey']['path'], row['effects'][key_i]['nativeFinalMetadata'])
    require(check_key() is True, 'DEDICATED_KEY_METADATA_UNPROVEN')
    first = runtime_snapshot(native, packet, row, modules, engine, namespace_read=namespace_read)
    second = runtime_snapshot(native, packet, row, modules, engine, namespace_read=namespace_read)
    require(first == second and check_key() is True, 'LIVE_GENERATION_CHANGED_DURING_PREFLIGHT')
    require(all(read(context + '/' + k) == v for k, v in selected.items())
            and read(binding['path']) == packet_raw, 'RETAINED_CONTEXT_CHANGED_DURING_PREFLIGHT')
    after = snapshot['inspect'](snapshot['CASE'])
    require(after['journalHash'] == previous['journalHash'] and after['reviewHash'] == previous['reviewHash']
            and after['sameBoot'] is True and after['wallClockConsistent'] is True,
            'STOPPED_PREFIX_CHANGED_DURING_LIVE_READ')
    return {'schema': 'ouf.ingestion-rollout-continuation-input-read.v1', 'complete': True,
        'status': 'RETAINED_STAGE18_LIVE_INPUTS_MATCHED_NO_AUTHORITY', 'readOnly': True,
        'startedAtUnix': started, 'finishedAtUnix': clock(),
        'elapsedSeconds': time.monotonic() - monotonic_started, 'contextPath': context,
        'predecessorJournalHash': case['journalHash'], 'predecessorReviewHash': case['reviewHash'],
        'logicalOperationRef': case['logicalOperationRef'], 'nextStage': 18, 'remainingStages': previous['remainingStages'],
        'unchangedApplicationsMatched': ['onboarding', 'mcp', 'udp'], 'postgresGenerationMatched': True,
        'retainedPredecessorsStoppedAndDetached': True,
        'replacementGenerations': {m: first['replacement.' + m]['process'] for m in ('ingestion', 'gateway')},
        'replacementRestartPoliciesDisabled': True, 'newGatewayNamespaceMatched': first['namespaces']['gateway'],
        'dedicatedKeyMetadataMatched': True, 'gatewayKeyValueReverified': False,
        'runtimeMetadataObserved': True, 'applicationReadinessReverified': False,
        'ownerControlReverified': False, 'databaseAdmissionProven': False, 'gatewayRoutesReverified': False,
        'engineRequests': engine.calls, 'maximumEngineRequests': 18, 'oauthRequests': 0,
        'priorOAuthAttempts': 288, 'proposedAdditionalOAuthAttempts': 4, 'proposedCumulativeOAuthCeiling': 292,
        'additionalOAuthBudgetGranted': False, 'humanWindowOpened': False,
        'bearerFilesOpened': 0, 'humanCredentialJournalsRead': 0, 'privateKeysRead': 0,
        'gatewayRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0,
        'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False,
        'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4, 'notReleaseAcceptance': True}
