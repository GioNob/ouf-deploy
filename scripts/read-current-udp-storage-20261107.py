#!/usr/bin/env python3
"""Read the retained UDP container and prepared SeaweedFS binding, without mutation.

Only allowlisted configuration values and credential-presence flags are emitted.
Docker config is not asserted to be effective Spring/JVM configuration.
"""
import configparser
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
import zipfile

ROOT = Path('/var/lib/ouf-storage-migration')
PLAN = ROOT / 'cold-host-bound-20261107-v1/plan.private.json'
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
BINDINGS = ROOT / 'seaweedfs/staging-oci33-20261107-v1/application-s3-v1'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
FIELDS = ('endpoint', 'bucket', 'region', 'path-style')
SAFE_CODES = set()


def need(ok, code):
    SAFE_CODES.add(code)
    if not ok:
        raise RuntimeError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=1024 * 1024):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'INPUT_TOO_LARGE')
    return raw


def docker(*args):
    p = subprocess.run((*DOCKER, *args), capture_output=True, timeout=20)
    need(p.returncode == 0, 'DOCKER_READ_FAILED')
    need(len(p.stdout) <= 4 * 1024 * 1024, 'DOCKER_OUTPUT_TOO_LARGE')
    return json.loads(p.stdout)


def inspect(ref):
    rows = docker('container', 'inspect', ref)
    need(len(rows) == 1, 'CONTAINER_NOT_UNIQUE')
    return rows[0]


def environment(doc):
    rows = doc['Config'].get('Env') or []
    values = dict(row.split('=', 1) for row in rows if '=' in row)
    need(len(values) == len(rows), 'DUPLICATE_OR_INVALID_ENVIRONMENT')
    return values


def safe_value(field, value):
    if value is None:
        return None
    if field == 'endpoint':
        try:
            u = urlsplit(value)
            host = u.hostname
            valid = bool(u.scheme in ('http', 'https') and host and
                         re.fullmatch(r'[A-Za-z0-9._:-]{1,253}', host))
            unexpected = bool(u.username or u.password or u.query or u.fragment or
                              u.path not in ('', '/'))
            if not valid or unexpected:
                return {'validEndpointWithoutCredentialsOrExtraParts': False}
            return {'scheme': u.scheme, 'host': host, 'port': u.port,
                    'validEndpointWithoutCredentialsOrExtraParts': True}
        except (ValueError, TypeError):
            return {'validEndpointWithoutCredentialsOrExtraParts': False}
    pattern = {'bucket': r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',
               'region': r'[a-z0-9-]{1,40}', 'path-style': r'true|false'}[field]
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else '<noncanonical>'


def selected_environment(env, prefix):
    return {field: safe_value(field, env.get(prefix + field.upper().replace('-', '_')))
            for field in FIELDS}


def arguments(args):
    # Preserve duplicate declarations for review; do not claim to resolve Spring precedence.
    declarations = []
    for index, value in enumerate(args):
        for field in FIELDS:
            for prefix in ('--ouf.udp.lake.s3.', '-Douf.udp.lake.s3.'):
                key = prefix + field
                if value.startswith(key + '='):
                    declarations.append({'field': field, 'value': safe_value(field, value[len(key) + 1:])})
                elif value == key:
                    declarations.append({'field': field, 'value': safe_value(field, args[index + 1] if index + 1 < len(args) else None)})
    return declarations


def jar_summary(app):
    args = [app.get('Path', ''), *(app.get('Args') or [])]
    need('-jar' in args and '/app/application.jar' in args, 'KNOWN_UDP_JAR_LAUNCH_REQUIRED')
    # Read installed bytes through the running mount namespace; no Java process is launched.
    pid = app['State']['Pid']
    need(isinstance(pid, int) and pid > 0, 'UDP_PID_REQUIRED')
    jar = Path('/proc') / str(pid) / 'root/app/application.jar'
    need(jar.stat().st_size <= 512 * 1024 * 1024, 'JAR_TOO_LARGE')
    with zipfile.ZipFile(jar) as archive:
        names = archive.namelist()
        libs = [name.removeprefix('BOOT-INF/lib/') for name in names
                if re.fullmatch(r'BOOT-INF/lib/(s3|sdk-core|auth|apache-client|url-connection-client|netty-nio-client)-[0-9][A-Za-z0-9.+_-]*\.jar', name)]
        hashes = {}
        for name in ('S3LakeConfiguration', 'S3LakeObjectStorageAdapter'):
            path = 'BOOT-INF/classes/it/comune/trieste/ouf/udp/' + name + '.class'
            entry = archive.getinfo(path)
            need(entry.file_size <= 256 * 1024, 'CLASS_TOO_LARGE')
            hashes[name] = digest(archive.read(entry))
        entry = archive.getinfo('BOOT-INF/classes/application.yml')
        need(entry.file_size <= 256 * 1024, 'YAML_TOO_LARGE')
        raw = archive.read(entry)
        config_keys = sorted(set(re.findall(rb'\$\{(OUF_UDP_(?:LAKE_)?S3_[A-Z_]+)(?::|\})', raw)))
        return {'selectedLibraries': sorted(libs), 'adapterClassSha256': hashes,
                'applicationYamlSha256': digest(raw),
                'storageEnvironmentPlaceholders': [key.decode('ascii') for key in config_keys]}


def run():
    need(os.geteuid() == 0, 'ROOT_READ_REQUIRED')
    raw = read(PLAN)
    need(digest(raw) == PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    binding = json.loads(raw)['roles']['udp']
    cid = binding['containerId']
    need(re.fullmatch('[a-f0-9]{64}', cid), 'RETAINED_ID_INVALID')
    app, sea = inspect(cid), inspect('ouf-seaweedfs-stage')
    need(app['Image'] == binding['nativeImage'], 'UDP_IMAGE_CHANGED')
    need(app['State']['Running'], 'UDP_NOT_RUNNING')
    env = environment(app)
    args = [app.get('Path', ''), *(app.get('Args') or [])]
    jvm = ' '.join(args + [env.get(k, '') for k in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS')])
    candidate = json.loads(read(BINDINGS / 'clients/udp/binding.private.json'))['environment']
    credentials = configparser.ConfigParser(interpolation=None)
    credentials.read_string(read(BINDINGS / 'clients/udp/credentials', 16384).decode())
    need(credentials.has_section('default'), 'TARGET_CREDENTIAL_PROFILE_MISSING')
    ca = read(BINDINGS / 'config/tls/ca.pem', 16384)
    installed = jar_summary(app)
    networks = sorted(app['NetworkSettings']['Networks'])
    sea_networks = sorted(sea['NetworkSettings']['Networks'])
    network_details = docker('network', 'inspect', *sorted(set(networks + sea_networks)))
    after = inspect(cid)
    need((after['Id'], after['Image'], after['State']['Pid'], after['State']['StartedAt']) ==
         (app['Id'], app['Image'], app['State']['Pid'], app['State']['StartedAt']) and
         after['State']['Running'], 'UDP_CHANGED_DURING_READ')
    return {
        'schema': 'ouf.current-udp-storage-bindings.v1', 'status': 'UDP_BINDINGS_READ_ONLY',
        'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'udp': {'containerId': cid, 'imageId': app['Image'], 'matchesRetainedImage': True,
                'running': True, 'networks': networks,
                'health': app['State'].get('Health', {}).get('Status'),
                'yamlVariableEnvironment': selected_environment(env, 'OUF_UDP_S3_'),
                'directPropertyEnvironment': selected_environment(env, 'OUF_UDP_LAKE_S3_'),
                'launchStorageDeclarations': arguments(args),
                'customJvmTrustStoreDeclared': 'javax.net.ssl.trustStore=' in jvm,
                'jvmStoragePropertiesDeclaredOutsideLaunchArgs': any('ouf.udp.lake.s3.' in env.get(k, '') for k in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS')),
                'springApplicationJsonConfigured': bool(env.get('SPRING_APPLICATION_JSON')),
                'externalSpringConfigDeclared': any(env.get(k) for k in ('SPRING_CONFIG_LOCATION', 'SPRING_CONFIG_ADDITIONAL_LOCATION', 'SPRING_CONFIG_IMPORT')) or any('spring.config.' in a for a in args),
                'credentialDeclarations': {key: bool(env.get(key)) for key in (
                    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                    'AWS_SHARED_CREDENTIALS_FILE', 'AWS_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE',
                    'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI')},
                'installedJar': installed,
                'configurationScope': 'DOCKER_ENV_LAUNCH_AND_PACKAGED_YAML_NOT_EFFECTIVE_JVM_SPRING_CONFIGURATION'},
        'preparedTarget': {'environment': selected_environment(candidate, 'OUF_UDP_S3_'),
                           'defaultProfileHasAccessKey': bool(credentials.get('default', 'aws_access_key_id', fallback='')),
                           'defaultProfileHasSecretKey': bool(credentials.get('default', 'aws_secret_access_key', fallback='')),
                           'caPemPresent': b'-----BEGIN CERTIFICATE-----' in ca,
                           'caFileSha256': digest(ca)},
        'seaweedfs': {'imageId': sea['Image'], 'running': sea['State']['Running'],
                      'networks': sea_networks,
                      'publishedPortBindings': bool(sea['HostConfig'].get('PortBindings'))},
        'networksInternal': {row['Name']: bool(row['Internal']) for row in network_details},
        'sharedDockerNetworks': sorted(set(networks) & set(sea_networks)),
        's3Requests': 0, 'databaseRequests': 0, 'serviceStops': 0,
        'serviceConfigurationChanged': False, 'directConnectivityTested': False,
        'credentialValuesEmitted': False, 'applicationUnchangedDuringRead': True,
    }


if __name__ == '__main__':
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as exc:
        print(json.dumps({'schema': 'ouf.current-udp-storage-bindings.v1',
                          'status': 'READ_INCOMPLETE',
                          'reason': str(exc) if str(exc) in SAFE_CODES else type(exc).__name__,
                          'serviceConfigurationChanged': False, 'credentialValuesEmitted': False}))
        raise SystemExit(1)
