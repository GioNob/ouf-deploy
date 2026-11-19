#!/usr/bin/env python3
"""Read-only plan / human hash approved, single-attempt Ingestion replacement.

The USR1 gate is copied unchanged from upgrade-ingestion-wide-20261108.py.
Only the pure, hash-checked retained_mac policy is imported from that lifecycle.
No SQL, image import, credential mutation, business call, rollback or retry.
"""
import argparse
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import quote

SOURCE = '01756a5a22ddc88beba270b7645a64440b1e5a7b'
REVISION = 'org.opencontainers.image.revision'
ENABLE = 'OUF_SUMMARY_ENABLED=true'
KEYS = tuple('ouf.summary.' + k for k in
             ('receipt-key-file', 'tenant-id', 'issuer', 'audience', 'workload'))
GATE = 'OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY = ['/bin/sh', '-c', GATE, 'ouf-gated-application']
MAC_SHA = 'cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce'


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class IdentityHeld(RuntimeError):
    def __init__(self, reason, checks):
        super().__init__(reason)
        self.checks = checks


def read(path, maximum=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'BOUNDED_REGULAR_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(after), 'FILE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def mac_helper():
    path = Path(__file__).resolve().parents[1] / 'tools/acquisition_read_native/retained_mac.py'
    raw = path.read_bytes()
    need(sha(raw) == MAC_SHA, 'MAC_HELPER_HASH_CHANGED')
    spec = importlib.util.spec_from_file_location('receipt_retained_mac', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class Engine:
    """All inspect/create operations use the SAME API1.44 view, never CLI inspect."""
    def __init__(self, path):
        self.socket = path

    def api(self, method, path, body=None):
        socket_path = self.socket

        class Unix(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(socket_path)

        conn = Unix('localhost', timeout=90)
        try:
            conn.request(method, '/v1.44' + path, None if body is None else encoded(body),
                         {'Content-Type': 'application/json'})
            response = conn.getresponse()
            raw = response.read(8 * 1048576 + 1)
            need(response.status in (200, 201, 204) and len(raw) <= 8 * 1048576,
                 'ENGINE_RESPONSE_UNPROVEN')
            return json.loads(raw) if raw else None
        finally:
            conn.close()

    def inspect(self, name):
        return self.api('GET', '/containers/' + quote(name, safe='') + '/json')

    def image(self, image):
        return self.api('GET', '/images/' + quote(image, safe=':') + '/json')


def environment(doc):
    rows = doc['Config']['Env']
    need(isinstance(rows, list) and all(isinstance(x, str) and '=' in x for x in rows), 'ENV_SHAPE_REQUIRED')
    result = dict(x.split('=', 1) for x in rows)
    need(len(result) == len(rows), 'DUPLICATE_ENV_KEY')
    return result


def properties(raw):
    """Parse Java properties, including escapes/continuations; never print values."""
    def unescape(text):
        def replace(m):
            value = m.group(1)
            if value.startswith('u'):
                need(re.fullmatch(r'u[0-9a-fA-F]{4}', value) is not None, 'PROPERTY_ESCAPE_INVALID')
                return chr(int(value[1:], 16))
            return {'t': '\t', 'r': '\r', 'n': '\n', 'f': '\f'}.get(value, value)
        return re.sub(r'\\(u.{0,4}|.)', replace, text)

    result, pending = {}, ''
    for physical in raw.decode('utf-8-sig').splitlines():
        line = pending + physical.lstrip(' \t\f')
        if not pending and (not line or line.startswith(('#', '!'))):
            continue
        trailing = len(line) - len(line.rstrip('\\'))
        if trailing % 2:
            pending = line[:-1]
            continue
        pending = ''
        match = re.match(r'((?:\\.|[^:=\s\\])*)(.*)', line)
        need(match is not None and bool(match[1]), 'PROPERTY_NAME_INVALID')
        key = unescape(match[1])
        value = match[2].lstrip(' \t\f')
        if value.startswith(('=', ':')):
            value = value[1:].lstrip(' \t\f')
        need(key not in result, 'DUPLICATE_PROPERTY_KEY')
        result[key] = unescape(value)
    need(not pending, 'PROPERTY_CONTINUATION_INCOMPLETE')
    return result


def mounted_source(doc, target):
    p = PurePosixPath(target)
    need(p.is_absolute() and '..' not in p.parts and str(p) == target, 'CANONICAL_MOUNT_PATH_REQUIRED')
    matches = [m for m in doc['Mounts'] if target == m['Destination'] or
               target.startswith(m['Destination'].rstrip('/') + '/')]
    need(len(matches) == 1, 'UNAMBIGUOUS_MOUNT_REQUIRED')
    mount = matches[0]
    need(mount['Type'] == 'bind' and mount['RW'] is False, 'READONLY_BIND_REQUIRED')
    relative = target[len(mount['Destination']):].lstrip('/')
    return Path(mount['Source']) / relative if relative else Path(mount['Source'])


def identity(doc, target, reader=read):
    raw = reader(mounted_source(doc, target))
    props = properties(raw)
    checks = {k: k in props for k in KEYS}
    if not all(checks.values()):
        raise IdentityHeld('SUMMARY_PROPERTIES_MISSING', checks)
    need(all(props[k].strip() and '${' not in props[k] for k in KEYS), 'SUMMARY_PROPERTIES_UNRESOLVED_OR_EMPTY')
    source = mounted_source(doc, props[KEYS[0]])
    key = reader(source, 4096)
    need(re.fullmatch(b'[a-fA-F0-9]{64}', key.strip()) is not None, 'SUMMARY_KEY_NOT_64_HEX')
    return {'requiredPropertiesPresent': checks, 'keyPathMountedReadOnly': True, 'keyValid64Hex': True,
            'propertiesSha256': sha(raw), 'keySha256': sha(key),
            'propertiesSourceSha256': digest(str(mounted_source(doc, target))),
            'keySourceSha256': digest(str(source))}


def mounts(doc):
    return sorted(doc['Mounts'], key=lambda m: m['Destination'])


def frame(doc):
    # Exclude only volatile health counters/PID; generation and running state are bound.
    return {k: doc[k] for k in ('Id', 'Name', 'Image', 'Created', 'Config', 'HostConfig', 'Mounts', 'Path', 'Args', 'NetworkSettings')}, {
        k: doc['State'].get(k) for k in ('Running', 'Paused', 'Restarting', 'StartedAt', 'OOMKilled')}


def process(doc):
    return Path('/proc', str(doc['State']['Pid']), 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')


def gate_armed(doc):
    # A shell cmdline alone can be observed before it has installed its trap.
    # Its sleep child proves execution has reached the loop *after* trap USR1.
    pid = str(doc['State']['Pid'])
    for child in Path('/proc', pid, 'task', pid, 'children').read_text().split():
        try:
            cmd = Path('/proc', child, 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
            if Path(cmd[0]).name == 'sleep' and cmd[1:] == ['1']:
                return True
        except FileNotFoundError:
            pass
    return False


def readiness(doc, args):
    # Run host Python in the target network namespace only: no Docker exec or TLS bypass.
    code = ('import http.client; c=http.client.HTTPConnection("127.0.0.1",%d,timeout=2); '
            'c.request("GET",%r); r=c.getresponse(); print(r.status); c.close()') % (args.readiness_port, args.readiness_path)
    run = subprocess.run((args.nsenter_bin, '--target', str(doc['State']['Pid']), '--net',
                          sys.executable, '-I', '-B', '-S', '-c', code), capture_output=True, timeout=4)
    return run.returncode == 0 and run.stdout.strip() == b'200'


def request(old, image, mac):
    mac.policy(old)  # One network, legacy STRING valid/unicast/nonzero equal to endpoint.
    config, host = copy.deepcopy(old['Config']), copy.deepcopy(old['HostConfig'])
    need(config.get('Entrypoint') == ENTRY and bool(config.get('Cmd')), 'EXACT_USR1_GATE_REQUIRED')
    need(host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0} and
         not host.get('AutoRemove') and not host.get('VolumesFrom'), 'SUPPORTED_RETAINED_LIFECYCLE_REQUIRED')
    net, ep = next(iter(old['NetworkSettings']['Networks'].items()))
    need(host['NetworkMode'] == net and bool(ep.get('IPAddress')), 'SINGLE_NAMED_IPV4_NETWORK_REQUIRED')
    need(all(m['Type'] == 'bind' and not m['RW'] for m in old['Mounts']), 'READONLY_BIND_MOUNTS_REQUIRED')
    declared = {m['Target'] for m in host.get('Mounts') or []}
    declared.update(b.split(':')[1] for b in host.get('Binds') or [])
    need(all(m['Destination'] in declared for m in old['Mounts']), 'EXPLICIT_MOUNT_DECLARATIONS_REQUIRED')
    env = environment(old)
    canonical = lambda s: re.sub('[._-]', '', s).lower()
    need(not any(canonical(k) == canonical('ouf.summary.enabled') for k in env), 'SUMMARY_ENABLE_ALREADY_DECLARED')
    need(env.get('SPRING_FLYWAY_ENABLED') == 'false' and
         [a for a in config['Cmd'] if a.startswith('--spring.flyway.enabled')] == ['--spring.flyway.enabled=false'] and
         [a for a in config['Cmd'] if a.startswith('--ouf.ingestion.startup.schema-mode')] ==
         ['--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'], 'VALIDATE_ONLY_FLYWAY_DISABLED_REQUIRED')
    # Keep Config.MacAddress too: API1.44 CREATE supports the observed single-network legacy field.
    # Unlike the old upgrade, there is no label/JAVA_VERSION/command/user delta here.
    config['Image'] = image
    config['Env'].append(ENABLE)
    ipam = copy.deepcopy(ep.get('IPAMConfig') or {})
    ipam['IPv4Address'] = ep['IPAddress']
    if ep.get('GlobalIPv6Address'):
        ipam['IPv6Address'] = ep['GlobalIPv6Address']
    endpoint = {'IPAMConfig': ipam, 'Aliases': list(ep.get('Aliases') or []), 'MacAddress': ep['MacAddress']}
    for k in ('Links', 'DriverOpts'):
        if ep.get(k):
            endpoint[k] = copy.deepcopy(ep[k])
    return dict(config, HostConfig=host, NetworkingConfig={'EndpointsConfig': {net: endpoint}})


def delta_guard(old, req, image, mac):
    need(req == request(old, image, mac), 'UNEXPECTED_CREATE_DELTA')


def image_defaults_guard(req, image):
    """Docker merges image defaults on CREATE. Detect additions BEFORE stopping.

    Explicit Config values override image defaults; Env and map fields merge.
    Unfamiliar defaults fail closed rather than silently extending the delta.
    """
    current_env = dict(x.split('=', 1) for x in req['Env'])
    for row in image['Config'].get('Env') or []:
        need(row.split('=', 1)[0] in current_env, 'CANDIDATE_WOULD_ADD_ENV')
    for key in ('Labels', 'Volumes', 'ExposedPorts'):
        need(set(image['Config'].get(key) or {}) <= set(req.get(key) or {}), 'CANDIDATE_WOULD_ADD_CONFIG_MAP_KEYS')
    for key, value in image['Config'].items():
        if key in ('Env', 'Labels', 'Volumes', 'ExposedPorts') or not value:
            continue
        need(bool(req.get(key)), 'CANDIDATE_WOULD_ADD_CONFIG_DEFAULT')


def image_state_guard(old, candidate, predecessor, args, ready):
    need(old['Image'] == args.expected_current_image and predecessor['Id'] == old['Image'] and
         (predecessor['Config'].get('Labels') or {}).get(REVISION) == args.expected_current_revision,
         'CURRENT_IMAGE_OR_REVISION_MISMATCH')
    state = old['State']
    need(state['Running'] is True and not state.get('Paused') and not state.get('Restarting') and ready,
         'CURRENT_RUNNING_READY_REQUIRED')
    need(candidate['Id'] == args.candidate_image and (candidate['Config'].get('Labels') or {}).get(REVISION) == SOURCE,
         'CANDIDATE_IMAGE_OR_REVISION_MISMATCH')
    need(candidate.get('Architecture') and candidate['Architecture'] == predecessor.get('Architecture') and
         candidate.get('Os') and candidate['Os'] == predecessor.get('Os'), 'CANDIDATE_PLATFORM_MISMATCH')


def compile_plan(old, candidate, predecessor, args, ident, mac, ready, running_args):
    image_state_guard(old, candidate, predecessor, args, ready)
    need(running_args == old['Config']['Cmd'], 'RUNNING_ARGUMENTS_CHANGED')
    need(environment(old).get('SPRING_CONFIG_ADDITIONAL_LOCATION') == 'file:' + args.properties_target,
         'EXACT_PROPERTIES_LOCATION_REQUIRED')
    need(not any(a.startswith(('--ouf.summary.', '-Douf.summary.')) for a in running_args) and
         not any(re.sub('[._-]', '', k).lower().startswith('oufsummary') for k in environment(old)) and
         not environment(old).get('SPRING_APPLICATION_JSON'), 'SUMMARY_OVERRIDE_REQUIRES_REVIEW')
    req = request(old, args.candidate_image, mac)
    delta_guard(old, req, args.candidate_image, mac)
    image_defaults_guard(req, candidate)
    # A whole inspect contains polling health counters. Bind only deployment data
    # and generation, so two read-only plans of the same runtime have the same hash.
    old = {k: copy.deepcopy(old[k]) for k in
           ('Id', 'Name', 'Image', 'Created', 'Config', 'HostConfig', 'Mounts', 'Path', 'Args', 'NetworkSettings', 'State')}
    old['State'] = {k: old['State'].get(k) for k in ('Running', 'Paused', 'Restarting', 'StartedAt', 'OOMKilled', 'Pid')}
    return {'schema': 'ouf.ingestion-operational-receipt-plan.v1', 'sourceCommit': SOURCE,
            'controllerSha256': sha(Path(__file__).read_bytes()), 'macHelperSha256': MAC_SHA,
            'oldFrame': frame(old), 'old': old, 'request': req, 'identity': ident,
            'candidateImageSha256': digest(candidate), 'predecessorImageSha256': digest(predecessor),
            'parameters': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                           if k not in ('plan', 'apply', 'plan_sha256')}}


def public_plan(plan):
    req = plan['request']
    return {'planSha256': digest(plan), 'sourceCommit': SOURCE, 'candidateImageId': req['Image'],
            'oldContainerId': plan['old']['Id'], 'oldImageId': plan['old']['Image'],
            'beforeFrameSha256': digest(plan['oldFrame']), 'createRequestSha256': digest(req),
            'privateFieldDigests': {k: digest(req[k]) for k in req if k != 'Image'},
            'identityChecks': {k: v for k, v in plan['identity'].items() if not k.endswith('Sha256')},
            'identityEvidenceSha256': digest(plan['identity']),
            'delta': ['Image', 'Env:+OUF_SUMMARY_ENABLED=true'],
            'legacyMacPresentStringMatchingEndpoint': True,
            'containerLabelsPreservedImageRevisionCheckedSeparately': True}


def collect(engine, args, mac, reader=read, ready=readiness, proc=process):
    old = engine.inspect(args.container)
    candidate, predecessor = engine.image(args.candidate_image), engine.image(old['Image'])
    is_ready = ready(old, args) if old['State']['Running'] else False
    # Establish the intended images/running target before opening identity files.
    image_state_guard(old, candidate, predecessor, args, is_ready)
    ident = identity(old, args.properties_target, reader)
    plan = compile_plan(old, candidate, predecessor, args, ident, mac, is_ready, proc(old))
    need(frame(engine.inspect(old['Id'])) == frame(old), 'CONTAINER_CHANGED_DURING_PLAN')
    return plan


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record(work, name, value):
    fd = os.open(work / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    fsync_dir(work)


def begin_attempt(root, plan_sha):
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         'ROOT_OWNED_0700_JOURNAL_PARENT_REQUIRED')
    path = root / ('apply-' + plan_sha)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        need(False, 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
    os.chmod(path, 0o700)
    fsync_dir(root)
    return path


def verify_replacement(old, req, actual, started):
    expected = {k: v for k, v in req.items() if k not in ('HostConfig', 'NetworkingConfig')}
    need(actual['Config'] == expected, 'REPLACEMENT_CONFIG_CHANGED')
    host = copy.deepcopy(req['HostConfig'])
    # API1.44 CREATE materializes null as false, START restores null on cgroup v2.
    # Only the created observation admits this exact transport form; running is exact.
    if not started and host.get('OomKillDisable') is None and actual['HostConfig'].get('OomKillDisable') is False:
        host['OomKillDisable'] = False
    need(actual['HostConfig'] == host and actual['Image'] == req['Image'] and mounts(actual) == mounts(old),
         'REPLACEMENT_HOST_IMAGE_MOUNTS_CHANGED')
    net, endpoint = next(iter(req['NetworkingConfig']['EndpointsConfig'].items()))
    need(set(actual['NetworkSettings']['Networks']) == {net}, 'REPLACEMENT_NETWORK_SET_CHANGED')
    ep = actual['NetworkSettings']['Networks'][net]
    need(ep.get('IPAMConfig') == endpoint['IPAMConfig'] and
         set(ep.get('Aliases') or []) == set(endpoint['Aliases']) | {actual['Id'][:12]},
         'REPLACEMENT_IPAM_ALIASES_CHANGED')
    for k in ('Links', 'DriverOpts'):
        need((ep.get(k) or None) == (endpoint.get(k) or None), 'REPLACEMENT_ENDPOINT_OPTIONS_CHANGED')
    if started:
        need(ep['IPAddress'] == endpoint['IPAMConfig']['IPv4Address'] and ep['MacAddress'] == endpoint['MacAddress'] and
             (ep.get('GlobalIPv6Address') or '') == endpoint['IPAMConfig'].get('IPv6Address', ''),
             'REPLACEMENT_ENDPOINT_CHANGED')
    need(actual['State']['Running'] is started, 'REPLACEMENT_RUNNING_STATE_CHANGED')
    need(actual['Path'] == old['Path'] and actual['Args'] == old['Args'], 'REPLACEMENT_LAUNCH_CHANGED')


def detached(mac, old, actual, name):
    result = mac.verify_detached(old, actual, expected_name=name)
    need(actual['HostConfig'] == old['HostConfig'] and actual['Path'] == old['Path'] and actual['Args'] == old['Args'],
         'DETACHED_HOST_OR_LAUNCH_CHANGED')
    return result


def apply_plan(plan, approved, engine, args, mac, report, recollect=collect,
               ready=readiness, proc=process):
    need(digest(plan) == approved, 'FRESH_PLAN_HASH_MISMATCH')
    # Reserve before any Docker write; identical/concurrent apply cannot replay.
    work = begin_attempt(args.journal_root, approved)
    report['privateEvidenceDirectory'] = str(work)
    record(work, 'plan.private.json', plan)
    old, req = plan['old'], plan['request']
    cid, name = old['Id'], old['Name']
    # Persistent per-generation claim also excludes concurrent *different* plans.
    try:
        record(args.journal_root, 'container-' + cid + '.claim', {'approvedPlanSha256': approved})
    except FileExistsError:
        need(False, 'CONTAINER_ATTEMPT_EXISTS_DO_NOT_REPLAY')
    need(re.fullmatch('/[A-Za-z0-9_.-]{1,120}', name) is not None, 'BOUNDED_CONTAINER_NAME_REQUIRED')
    retained = name + '-before-receipt-' + approved[:16]
    names = {n for c in engine.api('GET', '/containers/json?all=true') for n in c['Names']}
    need(retained not in names, 'RETAINED_NAME_ALREADY_EXISTS')
    need(digest(recollect(engine, args, mac)) == approved, 'PLAN_CHANGED_BEFORE_STOP')
    record(work, 'stop-intent.private.json', {'containerId': cid})
    report.update(oldStopDispatched=True, runtimeChanged=None,
                  recovery='MANUAL_RECONCILIATION_REQUIRED_NO_REPLAY; inspect journal and observed containers; see runbook')
    engine.api('POST', '/containers/' + cid + '/stop?t=' + str(args.stop_timeout))
    stopped = engine.inspect(cid)
    if stopped['State']['Running'] is False and stopped['State']['Pid'] == 0:
        report['runtimeChanged'] = True
    need(not stopped['State']['Running'] and stopped['State']['Pid'] == 0 and
         stopped['State']['StartedAt'] == old['State']['StartedAt'] and
         all(stopped[k] == old[k] for k in ('Config', 'HostConfig', 'Path', 'Args')) and
         mounts(stopped) == mounts(old), 'STOPPED_FRAME_CHANGED')
    record(work, 'stopped.private.json', stopped)
    report['oldLegacyMacPresentStringAfterStop'] = True
    net = next(iter(old['NetworkSettings']['Networks']))
    record(work, 'detach-intent.private.json', {'containerId': cid, 'network': net})
    engine.api('POST', '/networks/' + quote(net, safe='') + '/disconnect', {'Container': cid, 'Force': False})
    detached(mac, old, engine.inspect(cid), name)
    report['oldLegacyMacAbsentAfterDetach'] = True
    record(work, 'detached.private.json', engine.inspect(cid))
    record(work, 'rename-intent.private.json', {'name': retained})
    engine.api('POST', '/containers/' + cid + '/rename?name=' + quote(retained[1:], safe=''))
    detached(mac, old, engine.inspect(cid), retained)
    record(work, 'create-intent.private.json', {'requestSha256': digest(req)})
    new = engine.api('POST', '/containers/create?name=' + quote(name[1:], safe=''), req)['Id']
    report['replacementContainerId'] = new
    record(work, 'created-id.private.json', {'containerId': new})
    current = engine.inspect(new)
    verify_replacement(old, req, current, False)
    record(work, 'created.private.json', current)
    record(work, 'gate-start-intent.private.json', {'containerId': new})
    engine.api('POST', '/containers/' + new + '/start')
    deadline = time.monotonic() + args.readiness_timeout
    while True:
        current = engine.inspect(new)
        verify_replacement(old, req, current, True)
        need(time.monotonic() <= deadline, 'GATE_NOT_PROVEN')
        if proc(current) == ENTRY + req['Cmd'] and gate_armed(current):
            break
        need(time.monotonic() < deadline, 'GATE_NOT_PROVEN')
        time.sleep(0.2)
    record(work, 'gated.private.json', current)
    need(identity(current, args.properties_target) == plan['identity'], 'IDENTITY_CHANGED_BEFORE_USR1')
    record(work, 'usr1-intent.private.json', {'containerId': new})
    engine.api('POST', '/containers/' + new + '/kill?signal=USR1')
    deadline = time.monotonic() + args.readiness_timeout
    while True:
        current = engine.inspect(new)
        need(current['State']['Running'], 'APPLICATION_EXITED')
        is_ready = ready(current, args)
        need(time.monotonic() <= deadline, 'READINESS_TIMEOUT')
        if is_ready:
            break
        need(time.monotonic() < deadline, 'READINESS_TIMEOUT')
        time.sleep(0.5)
    verify_replacement(old, req, current, True)
    need(proc(current) == req['Cmd'], 'APPLICATION_ARGUMENTS_CHANGED')
    need(identity(current, args.properties_target) == plan['identity'], 'IDENTITY_CHANGED_AFTER_START')
    image = engine.image(current['Image'])
    need(image['Id'] == args.candidate_image and image['Config']['Labels'][REVISION] == SOURCE, 'FINAL_IMAGE_CHANGED')
    detached(mac, old, engine.inspect(cid), retained)
    record(work, 'replacement.private.json', current)
    report.update(status='INGESTION_OPERATIONAL_RECEIPT_READY', reason='REPLACEMENT_VERIFIED',
                  imageId=current['Image'], imageRevision=SOURCE, summaryEnabled=True,
                  mountsPreserved=True, environmentPreservedExceptSummaryEnabled=True,
                  argumentsPreserved=True, configAndHostConfigPreservedExceptApprovedDelta=True,
                  addressMacAliasesPreserved=True, readinessHttpStatus=200, oldRetainedStopped=True,
                  replacementLegacyMacPresentStringMatchingEndpoint=True,
                  flywayDisabledDeclarationsPreserved=True,
                  recovery='MANUAL_ONLY_SEE_RUNBOOK')
    record(work, 'complete.private.json', report)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        need(False, 'INVALID_CLI_ARGUMENTS')


def arguments(argv):
    p = Parser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256')
    for k in ('container', 'expected-current-image', 'expected-current-revision', 'candidate-image',
              'properties-target', 'docker-socket', 'nsenter-bin', 'readiness-path'):
        p.add_argument('--' + k, required=True)
    p.add_argument('--journal-root', type=Path, required=True)
    p.add_argument('--readiness-port', type=int, required=True)
    p.add_argument('--readiness-timeout', type=int, required=True)
    p.add_argument('--stop-timeout', type=int, required=True)
    args = p.parse_args(argv)
    need(bool(args.plan_sha256) == args.apply and (not args.apply or re.fullmatch('[a-f0-9]{64}', args.plan_sha256)),
         'HUMAN_APPROVED_PLAN_HASH_REQUIRED')
    need(all(re.fullmatch('sha256:[a-f0-9]{64}', x) for x in (args.candidate_image, args.expected_current_image)) and
         re.fullmatch('[a-f0-9]{40}', args.expected_current_revision), 'EXACT_IMAGE_AND_SOURCE_IDS_REQUIRED')
    need(args.candidate_image != args.expected_current_image and 1 <= args.readiness_port <= 65535 and
         1 <= args.readiness_timeout <= 1800 and 1 <= args.stop_timeout <= 60 and args.readiness_path.startswith('/') and
         args.journal_root.is_absolute() and args.docker_socket.startswith('/') and args.nsenter_bin.startswith('/'),
         'BOUNDED_ABSOLUTE_PARAMETERS_REQUIRED')
    return args


def main(argv=None):
    report = {'schema': 'ouf.ingestion-operational-receipt-result.v1', 'status': 'HELD',
              'runtimeChanged': False, 'oldStopDispatched': False, 'automaticRollback': False,
              'automaticReplay': False, 'databaseReads': 0, 'databaseWrites': 0,
              'credentialValuesEmitted': False, 'businessRequestsIssued': 0,
              'applicationStartupMayAccessDatabaseAndExistingWork': True}
    engine = args = plan = None
    try:
        args = arguments(argv)
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        if args.apply:
            need(not (args.journal_root / ('apply-' + args.plan_sha256)).exists(), 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
        mac = mac_helper()
        engine = Engine(args.docker_socket)
        plan = collect(engine, args, mac)
        report.update(public_plan(plan))
        if args.apply:
            apply_plan(plan, args.plan_sha256, engine, args, mac, report)
        else:
            report.update(status='INGESTION_OPERATIONAL_RECEIPT_PLANNED', reason='HUMAN_HASH_APPROVAL_REQUIRED')
    except (Exception, KeyboardInterrupt) as exc:
        safe = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=safe)
        if isinstance(exc, IdentityHeld):
            report['requiredPropertiesPresent'] = exc.checks
        if report['oldStopDispatched']:
            # Observations only, no rollback. Unknown response after STOP remains null.
            for label, cid in [('old', plan['old']['Id']), ('replacement', report.get('replacementContainerId') or args.container)]:
                try:
                    doc = engine.inspect(cid)
                    report[label + 'ObservedState'] = {'containerId': doc['Id'], 'running': doc['State']['Running'],
                                                       'networkCount': len(doc['NetworkSettings']['Networks'])}
                except Exception:
                    report[label + 'ObservedState'] = None
        if report.get('privateEvidenceDirectory'):
            try:
                record(Path(report['privateEvidenceDirectory']), 'failed.private.json', report)
            except Exception:
                pass  # Keep the original failure and durable intents; never overwrite.
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 1 if report['status'] == 'HELD' else 0


if __name__ == '__main__':
    sys.exit(main())
