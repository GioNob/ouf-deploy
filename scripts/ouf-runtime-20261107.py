#!/usr/bin/env python3
"""Resume the retained OUF stack or start the pinned SeaweedFS service."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
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
    ('semantic', 'udp', 'udp-evidence-read', 'ingestion', 'ingestion-evidence-read'),
    ('onboarding',),
    ('gateway-owner',),
    ('apisix',),
    ('caddy',),
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
        require(os.geteuid() == 0 and mode in ('e2e', 'seaweedfs', 'auth', 'mcp'), 'ROOT_AND_EXACT_MODE_REQUIRED')
        lock_mode = 'seaweedfs' if mode == 'seaweedfs' else 'e2e'
        with open('/run/lock/ouf-runtime-' + lock_mode + '.lock', 'a', opener=lambda path, flags:
                  os.open(path, flags | os.O_NOFOLLOW, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if mode == 'auth':
                restore_token_refresh(report)
                report['status'] = 'OUF_TOKEN_REFRESH_RESTORED'
            elif mode == 'mcp':
                start_mcp(report)
            else:
                (e2e if mode == 'e2e' else seaweedfs)(report)
    except (OSError, KeyError, subprocess.SubprocessError, ValueError) as exc:
        reason = str(exc)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]+', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())

