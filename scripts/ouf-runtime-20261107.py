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
GROUPS = (
    ('postgres', 'minio', 'etcd'),
    ('keycloak', 'semantic', 'udp', 'udp-evidence-read', 'ingestion', 'ingestion-evidence-read'),
    ('onboarding',),
    ('gateway-owner', 'mcp'),
    ('apisix',),
    ('caddy',),
)


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


def e2e(report):
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
    running = docker('ps', '-q', '--no-trunc').decode().split()
    others = sorted(set(running) - set(bound.values()))
    require(not others or all(
        doc['Name'] == '/' + SERVICE and doc['Image'] == IMAGE
        and (doc['Config']['Labels'] or {}).get(LABEL) == 'true'
        for doc in inspect(*others).values()), 'UNEXPECTED_RUNNING_CONTAINER')
    docs = inspect(*bound.values())
    for role, cid in bound.items():
        doc = docs[cid]
        started_at = retained[cid]['State']['StartedAt']
        require(doc['State']['Status'] in ('running', 'exited') and doc['Image'] == roles[role]['nativeImage']
                and fingerprint(doc, started_at) == roles[role]['fingerprint'], 'RETAINED_CONFIGURATION_CHANGED')
    for group in GROUPS:
        for role in group:
            report['currentRole'] = role
            if docs[bound[role]]['State']['Running']:
                report['alreadyRunningRoles'].append(role)
            else:
                docker('start', bound[role], timeout=60)
                report['startedRoles'].append(role)
            wait_started(bound[role], role)
    report.pop('currentRole')
    report['status'] = 'ORIGINAL_OUF_STACK_STARTED'


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
        require(os.geteuid() == 0 and mode in ('e2e', 'seaweedfs'), 'ROOT_AND_EXACT_MODE_REQUIRED')
        with open('/run/lock/ouf-runtime-' + mode + '.lock', 'a', opener=lambda path, flags:
                  os.open(path, flags | os.O_NOFOLLOW, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            (e2e if mode == 'e2e' else seaweedfs)(report)
    except (OSError, KeyError, subprocess.SubprocessError, ValueError) as exc:
        reason = str(exc)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]+', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())
