#!/usr/bin/env python3
"""Resume the retained OUF stack or start the pinned SeaweedFS service."""
import hashlib
import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
PLAN = Path('/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1/plan.private.json')
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
ORIGINAL_INSPECT = PLAN.parent / 'stop/command-182.private'
STAGE = Path('/var/lib/ouf-storage-migration/seaweedfs/staging-oci33-20261107-v1')
LIVE = STAGE.parent / 'runtime-oci33-v1'
IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
NETWORK = 'ouf-seaweedfs-private'
SERVICE = 'ouf-seaweedfs-stage'
SEMANTIC_IMAGE = 'sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3'
SEMANTIC_JAVA = ['java', '-XX:MaxRAMPercentage=75', '-jar', '/app/application.jar']
SEMANTIC_GATE = 'OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
SEMANTIC_ENTRY = ['/bin/sh', '-c', SEMANTIC_GATE, 'ouf-gated-application']
SEMANTIC_STARTS = PLAN.parent.parent / 'semantic-application-starts'
LABEL = 'ouf.storage.oci33.runtime'
TOKEN_SERVICES = (
    'ouf-gateway-policy-token.service',
    'ouf-ingestion-policy-token.service',
    'ouf-onboarding-identity-token.service',
    'ouf-policy-token@onboarding.service',
    'ouf-policy-token@udp.service',
)
GROUPS = (
    ('postgres', 'minio', 'etcd', 'keycloak'),
    ('udp', 'udp-evidence-read', 'ingestion', 'ingestion-evidence-read'),
    ('onboarding',),
    ('gateway-owner',),
    ('apisix',),
    ('caddy',),
    ('semantic',),
    ('mcp',),
)
MCP_BOOT_MESSAGES = {
    'database connection failed', 'database schema is not ready; run the migration role first',
    'manifest load failed', 'manifest persistence failed', 'workload identity initialization failed',
    'authorization policy bundle client initialization failed', 'authorization policy bundle bootstrap failed',
    'invalid authorization bundle refresh configuration', 'Gateway client initialization failed',
    'fingerprint key initialization failed', 'kernel initialization failed', 'HTTP server failed',
    'OUF MCP server listening',
}
MCP_ERROR_HINT = re.compile(r'\b(?:401|403|404|500|502|503|504|invalid_client|invalid_grant|'
                            r'token expired|connection refused|i/o timeout|context deadline exceeded|'
                            r'no such host|certificate signed by unknown authority|permission denied|'
                            r'password authentication failed|no pg_hba.conf entry)\b', re.I)


def require(condition, code):
    if not condition:
        raise ValueError(code)

def process_bytes(path):
    with open(path, 'rb') as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, 'SEMANTIC_PROCESS_READ_LIMIT')
    return raw

def semantic_process(doc):
    require(doc['Image'] == SEMANTIC_IMAGE and doc['Config'].get('Entrypoint') == SEMANTIC_ENTRY
            and doc['Config'].get('Cmd') == SEMANTIC_JAVA and doc['Config'].get('User') == '10001:10001',
            'SEMANTIC_RETAINED_GATE_CONFIGURATION_CHANGED')
    state = doc['State']
    require(state['Running'] and not state.get('Paused') and not state.get('Restarting')
            and state['Pid'] > 1, 'SEMANTIC_PROCESS_NOT_RUNNING')
    root = Path('/proc') / str(state['Pid'])
    def generation():
        fields = process_bytes(root / 'stat').decode().rsplit(')', 1)[1].split()
        return {'pid': state['Pid'], 'startTicks': int(fields[19]),
                'networkNamespaceInode': (root / 'ns/net').stat().st_ino}
    before = generation()
    raw = process_bytes(root / 'cmdline')
    require(raw.endswith(b'\0'), 'SEMANTIC_PROCESS_ARGUMENTS_INVALID')
    args = [value.decode() for value in raw[:-1].split(b'\0')]
    status = dict(line.split(':', 1) for line in process_bytes(root / 'status').decode().splitlines() if ':' in line)
    require(status.get('Uid', '').split() == ['10001']*4 and status.get('NoNewPrivs', '').strip() == '1'
            and all(int(status.get(key, '-1').strip(), 16) == 0
                    for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')),
            'SEMANTIC_PROCESS_IDENTITY_CHANGED')
    caught = int(status.get('SigCgt', '0').strip(), 16) & (1 << (signal.SIGUSR1 - 1))
    kind = 'GATE_WAITING' if args == SEMANTIC_ENTRY + SEMANTIC_JAVA and caught else 'APPLICATION_RUNNING' if args == SEMANTIC_JAVA else 'UNPROVEN'
    require(before == generation() and raw == process_bytes(root / 'cmdline'), 'SEMANTIC_PROCESS_CHANGED_DURING_READ')
    require(kind != 'UNPROVEN', 'SEMANTIC_GATE_OR_APPLICATION_NOT_PROVEN')
    return {'generation': before, 'processKind': kind}

def semantic_readiness(doc):
    endpoint = doc['NetworkSettings']['Networks'].get('ouf-backend') or {}
    require(endpoint.get('IPAddress'), 'SEMANTIC_BACKEND_ADDRESS_MISSING')
    connection = http.client.HTTPConnection(endpoint['IPAddress'], 8080, timeout=3)
    try:
        connection.request('GET', '/actuator/health/readiness')
        response = connection.getresponse()
        raw = response.read(65537)
        try:
            up = len(raw) <= 65536 and json.loads(raw).get('status') == 'UP'
        except (ValueError, AttributeError):
            up = False
        return response.status, response.status == 200 and up
    except (OSError, http.client.HTTPException):
        return None, False
    finally:
        connection.close()

def semantic_startup_details(cid, since, report):
    result = subprocess.run((*DOCKER, 'logs', '--since', since, '--tail', '100', cid),
                            capture_output=True, timeout=12)
    raw = result.stdout + result.stderr
    require(len(raw) <= 3*1024*1024, 'SEMANTIC_LOG_READ_LIMIT')
    categories = {
        'startupFailed': r'APPLICATION FAILED TO START|Application run failed',
        'databaseAuthenticationFailed': r'password authentication failed|no pg_hba.conf entry',
        'databaseOrMigrationError': r'PSQLException|FlywayException|FlywayValidateException|migration failed',
        'connectionRefused': r'connection refused',
        'tlsFailure': r'SSLHandshakeException|unable to find valid certification path',
        'authorizationDenied': r'authorization denied|access denied|access_denied',
        'expiredToken': r'token expired|token has expired|Jwt expired|JWT expired',
        'requiredConfigurationMissing': r'Could not resolve placeholder|APPLICATION_CONFIGURATION_REQUIRED',
        'applicationStarted': r'Started SemanticRegistryApplication',
    }
    text = raw.decode(errors='replace') if result.returncode == 0 else ''
    report['semanticStartupLog'] = {'read': result.returncode == 0, 'tailLimit': 100,
        'hints': {key: len(re.findall(pattern, text, re.I)) for key, pattern in categories.items()
                  if re.search(pattern, text, re.I)}, 'rawLogsEmitted': False}

def claim_semantic_start(cid, observed, doc):
    SEMANTIC_STARTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity = {'containerId': cid, 'generation': observed['generation'], 'startedAt': doc['State']['StartedAt']}
    name = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    path = SEMANTIC_STARTS / (name + '.json')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise ValueError('SEMANTIC_SIGNAL_ALREADY_CLAIMED_READBACK_REQUIRED') from None
    with os.fdopen(fd, 'w') as stream:
        json.dump({'schema': 'ouf.semantic-application-start-attempt.v1', **identity,
                   'signal': 'SIGUSR1', 'signalMayBeDispatched': True, 'automaticSignalReplayAllowed': False}, stream)
        stream.flush(); os.fsync(stream.fileno())
    fd = os.open(SEMANTIC_STARTS, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return path

def ensure_semantic_application(cid, report):
    doc = inspect(cid)[cid]
    observed = semantic_process(doc)
    report.update(semanticProcessBefore=observed['processKind'], semanticSameContainer=True,
                  semanticSameImage=True, semanticConfigurationChanged=False,
                  semanticApplicationMayAccessDatabase=True, credentialValuesEmitted=False)
    if observed['processKind'] == 'GATE_WAITING':
        path = claim_semantic_start(cid, observed, doc)
        report['semanticStartAttemptFile'] = str(path)
        fresh = inspect(cid)[cid]
        require(fresh['State']['StartedAt'] == doc['State']['StartedAt']
                and semantic_process(fresh) == observed, 'SEMANTIC_GATE_CHANGED_BEFORE_SIGNAL')
        report['semanticGateSignalDispatched'] = True
        docker('kill', '--signal=SIGUSR1', cid, timeout=15)
        report['semanticGateSignalAcknowledged'] = True
    deadline = time.monotonic() + 150
    try:
        while time.monotonic() < deadline:
            actual = inspect(cid)[cid]
            report.update(semanticStateAfter=actual['State'].get('Status'),
                          semanticExitCode=actual['State'].get('ExitCode'),
                          semanticOomKilled=actual['State'].get('OOMKilled'))
            require(actual['State']['Running'], 'SEMANTIC_EXITED_DURING_START')
            require(actual['State']['Pid'] == doc['State']['Pid']
                    and actual['State']['StartedAt'] == doc['State']['StartedAt'], 'SEMANTIC_GENERATION_CHANGED')
            # exec replaces the shell in the same process; a transition read can straddle exec.
            try:
                current = semantic_process(actual)
            except ValueError as error:
                if str(error) != 'SEMANTIC_PROCESS_CHANGED_DURING_READ':
                    raise
                time.sleep(1)
                continue
            require(current['generation'] == observed['generation'], 'SEMANTIC_PROCESS_GENERATION_CHANGED')
            report['semanticProcessAfter'] = current['processKind']
            if current['processKind'] == 'APPLICATION_RUNNING':
                status, ready = semantic_readiness(actual)
                report['semanticReadinessHttpStatus'] = status
                if ready:
                    report.update(semanticReadinessUp=True, semanticJavaIsContainerInit=True)
                    return
            time.sleep(2)
        raise ValueError('SEMANTIC_APPLICATION_READINESS_TIMEOUT')
    finally:
        semantic_startup_details(cid, doc['State']['StartedAt'], report)


def docker(*args, timeout=30):
    result = subprocess.run((*DOCKER, *args), capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'DOCKER_' + args[0].upper().replace('-', '_') + '_FAILED')
    return result.stdout


def inspect(*ids):
    return {doc['Id']: doc for doc in json.loads(docker('container', 'inspect', *ids))}


def fingerprint(doc, started_at):
    host = dict(doc['HostConfig'])
    host.pop('RestartPolicy', None)
    frame = {key: doc.get(key) for key in ('Id', 'Image', 'Config', 'Mounts', 'Path', 'Args')}
    frame.update(HostConfig=host, StartedAt=started_at)
    raw = (json.dumps(frame, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    return hashlib.sha256(raw).hexdigest()


def wait_started(cid, role):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        state = inspect(cid)[cid]['State']
        require(state['Running'] and not state['Restarting'], 'STOPPED_' + role.upper().replace('-', '_'))
        health = state.get('Health', {}).get('Status')
        if role == 'postgres':
            result = subprocess.run((*DOCKER, 'exec', cid, 'pg_isready', '-h', '127.0.0.1'),
                                    capture_output=True, timeout=10)
            if result.returncode == 0 and health in (None, 'healthy'):
                return
        elif health in (None, 'healthy'):
            return
        time.sleep(2)
    raise ValueError('START_DEADLINE_' + role.upper().replace('-', '_'))


def mcp_details(cid, state, report):
    report['mcpState'] = state['Status']
    report['mcpExitCode'] = state['ExitCode']
    report['mcpOomKilled'] = state['OOMKilled']
    logs = subprocess.run((*DOCKER, 'logs', '--since', state['StartedAt'], '--tail', '40', cid),
                          capture_output=True, text=True, timeout=15)
    report['mcpLogsRead'] = logs.returncode == 0
    messages, hints = set(), set()
    if logs.returncode == 0:
        for line in (logs.stdout + '\n' + logs.stderr).splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            message = row.get('msg') if isinstance(row, dict) else None
            if isinstance(message, str) and message in MCP_BOOT_MESSAGES:
                messages.add(message)
                hints.update(match.lower() for match in MCP_ERROR_HINT.findall(str(row.get('error', ''))))
    report['mcpStartupMessages'] = sorted(messages)
    report['mcpErrorHints'] = sorted(hints)


def wait_mcp(cid, report):
    probe = ('import http.client; c=http.client.HTTPConnection("127.0.0.1",8080,timeout=2); '
             'c.request("GET","/health/ready"); raise SystemExit(c.getresponse().status != 204)')
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = inspect(cid)[cid]['State']
        if not state['Running']:
            mcp_details(cid, state, report)
            raise ValueError('MCP_EXITED_DURING_START')
        result = subprocess.run(('/usr/bin/nsenter', '--target', str(state['Pid']), '--net', sys.executable,
                                 '-I', '-B', '-S', '-c', probe), capture_output=True, timeout=5)
        if result.returncode == 0:
            report['mcpReadyHttpStatus'] = 204
            return
        time.sleep(2)
    mcp_details(cid, inspect(cid)[cid]['State'], report)
    raise ValueError('MCP_READINESS_DEADLINE')


def restore_token_refresh(report):
    timers = [unit.removesuffix('.service') + '.timer' for unit in TOKEN_SERVICES]
    report['tokenRefreshServicesStarted'] = 0
    for unit in TOKEN_SERVICES:
        report['currentUnit'] = unit
        command = subprocess.run(('/usr/bin/systemctl', 'start', unit), capture_output=True, timeout=120)
        if command.returncode != 0:
            state = subprocess.run(('/usr/bin/systemctl', 'show', unit, '--property=Result,ExecMainStatus'),
                                   capture_output=True, text=True, timeout=15)
            if state.returncode == 0:
                report['unitResult'] = dict(line.split('=', 1) for line in state.stdout.splitlines() if '=' in line)
            raise ValueError('TOKEN_REFRESH_FAILED')
        report['tokenRefreshServicesStarted'] += 1
    report.pop('currentUnit')
    command = subprocess.run(('/usr/bin/systemctl', 'enable', '--now', *timers), capture_output=True, timeout=120)
    require(command.returncode == 0, 'TOKEN_TIMERS_ENABLE_FAILED')
    report['tokenTimersEnabled'] = len(timers)


def retained_stack():
    with PLAN.open('rb') as stream:
        raw = stream.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20 and hashlib.sha256(raw).hexdigest() == PLAN_SHA, 'ORIGINAL_PLAN_MISMATCH')
    roles = json.loads(raw)['roles']
    require(set(roles) == {role for group in GROUPS for role in group}, 'ORIGINAL_ROSTER_MISMATCH')
    bound = {role: row['containerId'] for role, row in roles.items()}
    require(len(set(bound.values())) == len(roles) and
            all(re.fullmatch('[a-f0-9]{64}', cid) for cid in bound.values()), 'ORIGINAL_IDS_MISMATCH')
    retained = {doc['Id']: doc for doc in json.loads(ORIGINAL_INSPECT.read_bytes())}
    require(set(retained) == set(bound.values()), 'ORIGINAL_INSPECT_MISMATCH')
    replacements = {}
    for role in ('onboarding', 'udp'):
        marker_path = PLAN.parent.parent / (role + '-seaweedfs-current.json')
        if not marker_path.exists():
            continue
        marker = json.loads(marker_path.read_bytes())
        require(marker.get('status') == role.upper() + '_SEAWEEDFS_READY', role.upper() + '_STORAGE_SWITCH_INCOMPLETE')
        work = Path(marker['privateEvidenceDirectory'])
        require(work.parent == PLAN.parent.parent and work.name.startswith(role + '-seaweedfs-switch-')
                and work.resolve(strict=True) == work, role.upper() + '_STORAGE_RECEIPT_PATH_INVALID')
        replacement = json.loads((work / 'replacement-container.private.json').read_bytes())
        old_id = bound[role]
        require(marker['originalContainerId'] == old_id
                and marker['replacementContainerId'] == replacement['Id']
                and replacement['Image'] == roles[role]['nativeImage']
                and (replacement['Config'].get('Labels') or {}).get('ouf.storage.switch') == marker['switchToken']
                and not inspect(old_id)[old_id]['State']['Running'], role.upper() + '_STORAGE_BINDING_NOT_PROVEN')
        bound[role] = replacement['Id']
        retained[replacement['Id']] = replacement
        replacements[role] = replacement
    docs = inspect(*bound.values())
    for role, cid in bound.items():
        doc = docs[cid]
        started_at = retained[cid]['State']['StartedAt']
        expected = fingerprint(replacements[role], started_at) if role in replacements else roles[role]['fingerprint']
        require(doc['State']['Status'] in ('running', 'exited') and doc['Image'] == roles[role]['nativeImage']
                and fingerprint(doc, started_at) == expected, 'RETAINED_CONFIGURATION_CHANGED')
        if role in replacements:
            require(set(doc['NetworkSettings']['Networks']) == set(replacements[role]['NetworkSettings']['Networks']),
                    role.upper() + '_STORAGE_NETWORKS_CHANGED')
    return bound, docs


def start_role(role, bound, docs, report):
    report['currentRole'] = role
    cid = bound[role]
    if docs[cid]['State']['Running']:
        report['alreadyRunningRoles'].append(role)
    else:
        docker('start', cid, timeout=60)
        report['startedRoles'].append(role)
    if role == 'mcp':
        wait_mcp(cid, report)
    elif role == 'semantic':
        ensure_semantic_application(cid, report)
    else:
        wait_started(cid, role)


def e2e(report):
    bound, docs = retained_stack()
    running = docker('ps', '-q', '--no-trunc').decode().split()
    others = sorted(set(running) - set(bound.values()))
    require(not others or all(
        doc['Name'] == '/' + SERVICE and doc['Image'] == IMAGE
        and (doc['Config']['Labels'] or {}).get(LABEL) == 'true'
        for doc in inspect(*others).values()), 'UNEXPECTED_RUNNING_CONTAINER')
    if any((docs[bound[role]]['Config'].get('Labels') or {}).get('ouf.storage.backend') == 'seaweedfs'
           for role in ('onboarding', 'udp')):
        seaweedfs(report)
    for index, group in enumerate(GROUPS):
        for role in group:
            start_role(role, bound, docs, report)
        if index == 0:
            report['currentRole'] = 'host-token-refresh'
            restore_token_refresh(report)
    report.pop('currentRole')
    report['status'] = 'ORIGINAL_OUF_STACK_STARTED'


def start_mcp(report):
    bound, docs = retained_stack()
    require(all(docs[bound[role]]['State']['Running'] for role in ('postgres', 'keycloak', 'gateway-owner',
                'apisix', 'caddy')), 'MCP_DEPENDENCIES_NOT_RUNNING')
    start_role('mcp', bound, docs, report)
    report.pop('currentRole')
    report['status'] = 'OUF_MCP_READY'


def seaweedfs(report):
    stage_receipt = json.loads((STAGE / 'result.json').read_bytes())
    bundle = STAGE / 'application-s3-v1'
    binding_receipt = json.loads((bundle / 'access-proof-v2/result.json').read_bytes())
    require(stage_receipt['status'] == 'ISOLATED_OCI33_STAGE_READY'
            and stage_receipt['objectsListed'] == 120
            and binding_receipt['status'] == 'ISOLATED_OCI33_APP_BINDINGS_READY', 'STAGED_DATA_OR_BINDINGS_MISSING')
    config = bundle / 'config'
    for path in (STAGE / 'data', config):
        require(path.is_dir() and path.resolve(strict=True) == path and path.stat().st_uid == 10001,
                'STAGED_DIRECTORY_CHANGED')
    require(docker('image', 'inspect', '--format', '{{.Id}}', IMAGE).decode().strip() == IMAGE,
            'EXACT_IMAGE_MISSING')
    networks = docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()
    names = docker('ps', '-a', '--format', '{{.Names}}').decode().splitlines()
    LIVE.mkdir(mode=0o700, exist_ok=True)
    require(LIVE.resolve(strict=True) == LIVE and LIVE.stat().st_uid == 0, 'SEPARATE_RUNTIME_DIRECTORY_REQUIRED')
    data = LIVE / 'data'
    if not data.exists():
        with tempfile.TemporaryDirectory(dir=LIVE) as temp:
            pending = Path(temp) / 'data'
            subprocess.run(('/usr/bin/cp', '-a', '--reflink=auto', '--sparse=always', '--',
                            str(STAGE / 'data'), str(pending)), check=True, capture_output=True, timeout=180)
            pending.rename(data)
    require(data.is_dir() and data.resolve(strict=True) == data and data.stat().st_uid == 10001,
            'RUNTIME_DATA_DIRECTORY_REQUIRED')
    if NETWORK not in networks:
        docker('network', 'create', '--internal', '--label', LABEL + '=true', NETWORK)
        report['networkCreated'] = True
    network, = json.loads(docker('network', 'inspect', NETWORK))
    require(network['Internal'] and network['Driver'] == 'bridge' and (network['Labels'] or {}).get(LABEL) == 'true',
            'EXACT_PRIVATE_NETWORK_REQUIRED')
    if SERVICE in names:
        doc, = inspect(SERVICE).values()
        cid = doc['Id']
    else:
        cid = docker('create', '--name', SERVICE, '--network', NETWORK, '--label', LABEL + '=true',
                 '--pull=never', '--restart=no', '--read-only', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--user', '10001:10001',
                 '--memory=1g', '--cpus=2', '--pids-limit=256',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777', '--workdir', '/config',
                 '--mount', f'type=bind,src={data},dst=/data',
                 '--mount', f'type=bind,src={config},dst=/config,readonly',
                 IMAGE, '-logtostderr=true', 'server', '-ip=127.0.0.1', '-ip.bind=0.0.0.0',
                 '-dir=/data', '-master.port=19332', '-master.volumeSizeLimitMB=32', '-volume.port=18082',
                 '-volume.max=128', '-filer', '-filer.port=18882', '-s3', '-s3.port=9002',
                 '-s3.port.https=0', '-s3.port.iceberg=0', '-s3.port.lance=0', '-s3.config=/config/s3.json',
                 '-s3.key.file=/config/tls/server.key', '-s3.cert.file=/config/tls/server.pem').decode().strip()
        require(re.fullmatch('[a-f0-9]{64}', cid), 'CREATED_CONTAINER_ID')
        doc = inspect(cid)[cid]
        report['containerCreated'] = True
    mounts = {(m['Source'], m['Destination'], m['RW']) for m in doc['Mounts']}
    require(doc['Image'] == IMAGE and (doc['Config']['Labels'] or {}).get(LABEL) == 'true'
            and doc['HostConfig']['NetworkMode'] == NETWORK and not doc['HostConfig']['PortBindings']
            and not doc['HostConfig']['PublishAllPorts']
            and mounts == {(str(data), '/data', True), (str(config), '/config', False)}, 'EXACT_SEAWEEDFS_RUNTIME_REQUIRED')
    if not doc['State']['Running']:
        docker('start', cid)
    wait_started(cid, 'seaweedfs')
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        doc = inspect(cid)[cid]
        require(doc['State']['Running'] and not doc['HostConfig']['PortBindings']
                and set(doc['NetworkSettings']['Networks']) == {NETWORK}, 'SEAWEEDFS_NETWORK_OR_STATE')
        result = subprocess.run(('/usr/bin/nsenter', '--target', str(doc['State']['Pid']), '--net',
                                 '/usr/bin/openssl', 's_client', '-brief', '-connect', '127.0.0.1:9002',
                                 '-servername', SERVICE, '-verify_hostname', SERVICE, '-verify_return_error',
                                 '-CAfile', str(config / 'tls/ca.pem')),
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
        if result.returncode == 0:
            break
        time.sleep(2)
    else:
        raise ValueError('SEAWEEDFS_TLS_NOT_READY')
    report['status'] = 'SEAWEEDFS_PRIVATE_SERVICE_STARTED'


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    report = {'status': 'HELD', 'mode': mode, 'startedRoles': [], 'alreadyRunningRoles': []}
    try:
        require(os.geteuid() == 0 and mode in ('e2e', 'seaweedfs', 'auth', 'mcp', 'semantic'), 'ROOT_AND_EXACT_MODE_REQUIRED')
        lock_mode = 'seaweedfs' if mode == 'seaweedfs' else 'e2e'
        with open('/run/lock/ouf-runtime-' + lock_mode + '.lock', 'a', opener=lambda path, flags:
                  os.open(path, flags | os.O_NOFOLLOW, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if mode == 'auth':
                restore_token_refresh(report)
                report['status'] = 'OUF_TOKEN_REFRESH_RESTORED'
            elif mode == 'mcp':
                start_mcp(report)
            elif mode == 'semantic':
                bound, docs = retained_stack()
                start_role('semantic', bound, docs, report)
                report['status'] = 'OUF_SEMANTIC_APPLICATION_READY'
            else:
                (e2e if mode == 'e2e' else seaweedfs)(report)
    except (OSError, KeyError, subprocess.SubprocessError, ValueError) as exc:
        reason = str(exc)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]+', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())

