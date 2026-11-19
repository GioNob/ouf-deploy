#!/usr/bin/env python3
"""Read current Onboarding/SeaweedFS bindings; no credentials or raw logs emitted."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

PLAN = Path('/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1/plan.private.json')
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
SEAWEEDFS = 'ouf-seaweedfs-stage'


def docker(*args):
    result = subprocess.run((*DOCKER, *args), capture_output=True, timeout=20)
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError('DOCKER_READ_FAILED')
    return result.stdout


def inspect(ref):
    rows = json.loads(docker('container', 'inspect', ref))
    if len(rows) != 1:
        raise RuntimeError('CONTAINER_NOT_UNIQUE')
    return rows[0]


def endpoint(value):
    if not value:
        return None
    u = urlsplit(value)
    return {'scheme': u.scheme, 'host': u.hostname, 'port': u.port,
            'hasUnexpectedUrlParts': bool(u.username or u.password or u.query or u.fragment or u.path not in ('', '/'))}


def network_names(doc):
    return sorted(doc.get('NetworkSettings', {}).get('Networks', {}))


def run():
    if os.geteuid() != 0:
        raise RuntimeError('ROOT_READ_REQUIRED')
    raw = PLAN.read_bytes()
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != PLAN_SHA:
        raise RuntimeError('RETAINED_PLAN_MISMATCH')
    binding = json.loads(raw)['roles']['onboarding']
    cid = binding['containerId']
    if not re.fullmatch('[a-f0-9]{64}', cid):
        raise RuntimeError('INVALID_RETAINED_ID')
    app, sea = inspect(cid), inspect(SEAWEEDFS)
    env = dict(item.split('=', 1) for item in app['Config'].get('Env', []) if '=' in item)
    args = ' '.join([app.get('Path', ''), *app.get('Args', []),
                     *(env.get(key, '') for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS'))])
    bucket = env.get('OUF_ONBOARDING_STAGING_BUCKET')
    if bucket is not None and not re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket):
        bucket = '<noncanonical>'
    tools = []
    if app['State']['Running']:
        probe = 'for name in java keytool curl aws; do command -v "$name" >/dev/null 2>&1 && printf "%s\\n" "$name"; done; exit 0'
        tools = docker('exec', cid, '/bin/sh', '-c', probe).decode().splitlines()
        if any(name not in ('java', 'keytool', 'curl', 'aws') for name in tools):
            raise RuntimeError('UNEXPECTED_TOOL_PROBE')
    return {
        'schema': 'ouf.current-storage-bindings.v1',
        'status': 'BINDINGS_READ_ONLY',
        'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'onboarding': {
            'imageId': app['Image'], 'matchesRetainedImage': app['Image'] == binding['nativeImage'],
            'running': app['State']['Running'], 'networks': network_names(app),
            'stagingEndpoint': endpoint(env.get('OUF_ONBOARDING_STAGING_ENDPOINT')),
            'stagingBucket': bucket,
            'accessKeyFileConfigured': bool(env.get('OUF_ONBOARDING_STAGING_ACCESS_KEY_FILE')),
            'secretKeyFileConfigured': bool(env.get('OUF_ONBOARDING_STAGING_SECRET_KEY_FILE')),
            'customJvmTrustStoreDeclaredInContainerConfig': '-Djavax.net.ssl.trustStore=' in args,
            'toolsAvailable': tools,
            'configurationScope': 'DOCKER_ENV_AND_COMMAND_NOT_EFFECTIVE_JVM_SPRING_CONFIGURATION',
        },
        'seaweedfs': {'imageId': sea['Image'], 'running': sea['State']['Running'],
                      'networks': network_names(sea),
                      'publishedPortBindings': bool(sea['HostConfig'].get('PortBindings'))},
        'sharedDockerNetworks': sorted(set(network_names(app)) & set(network_names(sea))),
        's3Requests': 0, 'databaseRequests': 0, 'serviceConfigurationChanged': False,
        'directConnectivityTested': False, 'credentialValuesEmitted': False,
    }


if __name__ == '__main__':
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as exc:
        known = {'DOCKER_READ_FAILED', 'CONTAINER_NOT_UNIQUE', 'ROOT_READ_REQUIRED',
                 'RETAINED_PLAN_MISMATCH', 'INVALID_RETAINED_ID', 'UNEXPECTED_TOOL_PROBE'}
        print(json.dumps({'status': 'READ_INCOMPLETE',
                          'reason': str(exc) if str(exc) in known else type(exc).__name__}))
        raise SystemExit(1)
