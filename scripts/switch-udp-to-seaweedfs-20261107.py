#!/usr/bin/env python3
"""Move only the installed UDP container to SeaweedFS, preserving its image.

Reuses the verified current-object copier. No application upload is synthesized.
Before replacement start, failure restores the original. After start dispatch,
never automatically restore a MinIO writer: application writes may have begun.
"""
import base64
import copy
import configparser
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import subprocess
import tempfile
import time
import types
import uuid
import zlib
import zipfile

HELPER_SHA = '13ee203be367eaf0c8679d163ca5b664c4b91ac5100efd61146e1c97c61e4fcc'
HELPER_ZLIB64 = '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'
ROOT = Path('/var/lib/ouf-storage-migration')
MARKER = ROOT / 'udp-seaweedfs-current.json'
PREVIOUS = ROOT / 'udp-client-probe-bbi8ny8f'
APP_IMAGE = 'sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'
DIAGNOSTIC_KEY = 'diagnostics/seaweedfs-client/3d9691ec-db79-4567-8c25-ed1695dea208'
DIAGNOSTIC_SHA = 'ec54d13fec98713f96235e0fd7adbc5dfd3437270bc0d66a39a473074a01145a'
CA_SHA = 'c1ab769d4b76565f717e2600266e11afd0f2042829f486f22fe8596f369cbccf'
DEST = '/run/ouf-seaweedfs'
BACKEND, PRIVATE = 'ouf-backend', 'ouf-seaweedfs-private'
LABEL = 'ouf.storage.switch'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
DEADLINE = 0


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def copier():
    raw = zlib.decompress(base64.b64decode(HELPER_ZLIB64))
    need(digest(raw) == HELPER_SHA, 'COPY_HELPER_MISMATCH')
    module = types.ModuleType('ouf_copy_helper')
    exec(compile(raw, 'verified-copy-helper.py', 'exec'), module.__dict__)
    module.APP_IMAGE = APP_IMAGE
    module.BUCKET = 'ouf-udp'
    base_s3 = module.S3
    class UdpS3(base_s3):
        def request(self, method, path, body=b'', extra=None, maximum=64*1024*1024):
            return super().request(method, path, body, extra, maximum)
    module.S3 = UdpS3
    module.listing = lambda client, report: udp_listing(module, client, report)
    return module


def docker(*args, data=None, timeout=25, checked=True):
    remaining = DEADLINE - time.monotonic()
    need(remaining > 0, 'SWITCH_DEADLINE')
    p = subprocess.run((*DOCKER, *args), input=data, capture_output=True,
                       timeout=min(timeout, remaining))
    need(len(p.stdout) + len(p.stderr) <= 8 << 20, 'COMMAND_OUTPUT_LIMIT')
    if checked:
        need(p.returncode == 0, 'DOCKER_COMMAND_FAILED')
    return p


class Engine:
    def request(self, method, path, body=None, expected=(200,), timeout=30):
        class Connection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect('/run/docker.sock')
        remaining = DEADLINE - time.monotonic()
        need(remaining > 0, 'SWITCH_DEADLINE')
        connection = Connection('localhost', timeout=min(timeout, remaining))
        try:
            raw = json.dumps(body).encode() if body is not None else None
            connection.request(method, '/v1.44' + path, body=raw,
                               headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            payload = response.read((2 << 20) + 1)
            need(len(payload) <= 2 << 20, 'ENGINE_RESPONSE_LIMIT')
            need(response.status in expected, 'ENGINE_HTTP_' + str(response.status))
            return json.loads(payload) if payload else None
        finally:
            connection.close()

    def inspect(self, ref):
        return self.request('GET', '/containers/' + ref + '/json')


def environment(doc):
    rows = doc['Config'].get('Env') or []
    values = dict(row.split('=', 1) for row in rows)
    need(len(rows) == len(values), 'DUPLICATE_ENVIRONMENT_KEYS')
    return values


def certificates(raw):
    pems = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', raw, re.S)
    return {digest(ssl.PEM_cert_to_DER_cert(p.decode())) for p in pems}


def prepare_truststore(app, folder, ca, report):
    cid = app['Id']
    settings = docker('exec', cid, 'java', '-XshowSettings:properties', '-version')
    homes = re.findall(rb'^\s*java.home = (\S+)\s*$', settings.stdout + settings.stderr, re.M)
    need(len(homes) == 1, 'JAVA_HOME_NOT_UNIQUE')
    home = homes[0].decode()
    need(home.startswith('/') and '..' not in Path(home).parts, 'JAVA_HOME_INVALID')
    selected = home + '/lib/security/cacerts'
    # JSSE prefers jssecacerts when present. Read the actual running image's files.
    probe = docker('exec', cid, 'test', '-f', home + '/lib/security/jssecacerts', checked=False)
    need(probe.returncode in (0, 1), 'JAVA_DEFAULT_TRUSTSTORE_PROBE_FAILED')
    if probe.returncode == 0:
        selected = home + '/lib/security/jssecacerts'
    original = docker('exec', cid, 'keytool', '-list', '-rfc', '-keystore', selected,
                      '-storepass', 'changeit').stdout
    original_certs = certificates(original)
    ca_certs = certificates(ca)
    need(len(original_certs) > 0 and len(ca_certs) == 1, 'TRUST_CERTIFICATE_SET_INVALID')
    temp = '/tmp/ouf-seaweedfs-trust-' + uuid.uuid4().hex + '.p12'
    try:
        docker('exec', cid, 'keytool', '-importkeystore', '-noprompt', '-srckeystore', selected,
               '-srcstorepass', 'changeit', '-destkeystore', temp, '-deststoretype', 'PKCS12',
               '-deststorepass', 'changeit', timeout=45)
        docker('exec', '-i', cid, 'keytool', '-importcert', '-noprompt', '-alias',
               'ouf-seaweedfs-' + next(iter(ca_certs))[:16], '-keystore', temp,
               '-storepass', 'changeit', data=ca)
        result = docker('exec', cid, 'keytool', '-list', '-rfc', '-keystore', temp,
                        '-storepass', 'changeit').stdout
        need(certificates(result) == original_certs | ca_certs, 'PUBLIC_CA_SET_NOT_PRESERVED')
        raw = docker('exec', cid, 'cat', temp).stdout
        need(1000 < len(raw) <= 4 << 20, 'TRUSTSTORE_SIZE_INVALID')
        (folder / 'truststore.p12').write_bytes(raw)
        report.update(existingTrustCertificates=len(original_certs), privateCaAdded=True,
                      existingTrustCertificatesPreserved=True, truststoreSha256=digest(raw))
    finally:
        cleanup = docker('exec', cid, 'rm', '-f', temp, checked=False)
        report['temporaryTruststoreRemoved'] = cleanup.returncode == 0


def endpoint(original):
    ep = original['NetworkSettings']['Networks'][BACKEND]
    ipam = copy.deepcopy(ep.get('IPAMConfig') or {})
    need(ep.get('IPAddress'), 'ORIGINAL_BACKEND_IPV4_REQUIRED')
    ipam['IPv4Address'] = ep['IPAddress']
    if ep.get('GlobalIPv6Address'):
        ipam['IPv6Address'] = ep['GlobalIPv6Address']
    result = {'IPAMConfig': ipam, 'Aliases': list(ep.get('Aliases') or []),
              'MacAddress': ep['MacAddress']}
    for key in ('Links', 'DriverOpts'):
        if ep.get(key):
            result[key] = copy.deepcopy(ep[key])
    return result


def make_request(app, folder, token, app_image):
    values = environment(app)
    need(set(app['NetworkSettings']['Networks']) == {BACKEND}, 'UDP_NETWORK_SET_CHANGED')
    need(app['HostConfig']['NetworkMode'] == BACKEND and not app['HostConfig'].get('AutoRemove')
         and not app['HostConfig'].get('VolumesFrom'), 'UNSUPPORTED_CONTAINER_LIFECYCLE')
    config, host = copy.deepcopy(app['Config']), copy.deepcopy(app['HostConfig'])
    entrypoint, cmd = config.get('Entrypoint') or [], config.get('Cmd') or []
    combined = entrypoint + cmd
    need('-jar' in combined and '/app/app.jar' in combined
         and all(isinstance(v, str) for v in combined), 'INSTALLED_JAR_LAUNCH_REQUIRED')
    need(not any('javax.net.ssl.trustStore' in v for v in combined + list(values.values())),
         'EXISTING_CUSTOM_TRUSTSTORE_REQUIRES_MERGE')
    need(not any('add-command-line-properties=false' in v.lower() for v in combined),
         'SPRING_COMMAND_LINE_DISABLED')
    # Remove the old static AWS identity so DefaultCredentialsProvider reaches the target profile.
    for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN', 'AWS_ROLE_SESSION_NAME',
                'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'):
        values.pop(key, None)
    values.update(OUF_UDP_S3_ENDPOINT='https://ouf-seaweedfs-stage:9002', OUF_UDP_S3_BUCKET='ouf-udp',
                  OUF_UDP_S3_REGION='us-east-1', OUF_UDP_S3_PATH_STYLE='true',
                  AWS_SHARED_CREDENTIALS_FILE=DEST + '/credentials', AWS_PROFILE='default',
                  AWS_CONFIG_FILE=DEST + '/aws-config', AWS_EC2_METADATA_DISABLED='true')
    values['JAVA_TOOL_OPTIONS'] = (values.get('JAVA_TOOL_OPTIONS', '') +
        ' -Djavax.net.ssl.trustStore=' + DEST + '/truststore.p12'
        ' -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit').strip()
    config['Env'] = [key + '=' + value for key, value in values.items()]
    # Spring command-line properties override environment and external YAML for this one binding.
    props = {'endpoint': values['OUF_UDP_S3_ENDPOINT'], 'bucket': 'ouf-udp',
             'region': 'us-east-1', 'path-style': 'true'}
    bare = {'--ouf.udp.lake.s3.' + key for key in props}
    prefixes = tuple(key + '=' for key in bare)
    need(not any(arg.startswith(prefixes) or arg in bare for arg in entrypoint), 'STORAGE_OVERRIDE_IN_ENTRYPOINT')
    need(not any('aws.accessKeyId' in v or 'aws.secretAccessKey' in v or 'aws.sessionToken' in v
                 for v in combined + list(values.values())), 'JVM_AWS_IDENTITY_REQUIRES_REVIEW')
    remaining = []
    index = 0
    while index < len(cmd):
        if cmd[index] in bare:
            need(index + 1 < len(cmd), 'STORAGE_ARGUMENT_VALUE_MISSING')
            index += 2
        elif cmd[index].startswith(prefixes):
            index += 1
        else:
            remaining.append(cmd[index]); index += 1
    config['Cmd'] = remaining + [
        '--ouf.udp.lake.s3.' + key + '=' + value for key, value in props.items()]
    config['Image'] = app_image
    config['Labels'] = dict(config.get('Labels') or {}, **{LABEL: token, 'ouf.storage.backend': 'seaweedfs'})
    mounts = copy.deepcopy(host.get('Mounts') or [])
    covered = {m['Target'] for m in mounts}
    for bind in host.get('Binds') or []:
        parts = bind.split(':')
        need(len(parts) in (2, 3), 'BIND_FORMAT_REQUIRES_REVIEW')
        covered.add(parts[1])
    covered.update((host.get('Tmpfs') or {}).keys())
    for mount in app['Mounts']:
        destination = mount['Destination']
        need(destination != DEST and not DEST.startswith(destination.rstrip('/') + '/'),
             'STORAGE_MOUNT_PATH_CONFLICT')
        if destination in covered:
            continue
        need(mount['Type'] in ('bind', 'volume'), 'UNSUPPORTED_RETAINED_MOUNT')
        mounts.append({'Type': mount['Type'], 'Source': mount.get('Name') if mount['Type'] == 'volume'
                       else mount['Source'], 'Target': destination, 'ReadOnly': not mount['RW']})
    mounts.append({'Type': 'bind', 'Source': str(folder), 'Target': DEST, 'ReadOnly': True})
    host['Mounts'] = mounts
    config.update(HostConfig=host, NetworkingConfig={'EndpointsConfig': {
        BACKEND: endpoint(app), PRIVATE: {'Aliases': ['ouf-udp-seaweedfs']}}})
    return config


def verify_created(original, request, actual, started=False):
    need(actual['Image'] == original['Image'], 'REPLACEMENT_IMAGE_CHANGED')
    for key, value in request.items():
        if key not in ('HostConfig', 'NetworkingConfig'):
            need(actual['Config'].get(key) == value, 'REPLACEMENT_CONFIG_DIFFERS')
    for key, value in request['HostConfig'].items():
        current = actual['HostConfig'].get(key)
        if key == 'OomKillDisable' and value in (None, False) and current in (None, False):
            continue
        if key == 'Mounts':
            expected_mounts = {m['Target']: m for m in value or []}
            actual_mounts = {m['Target']: m for m in current or []}
            need(set(expected_mounts) == set(actual_mounts), 'HOST_MOUNT_REQUEST_SET_DIFFERS')
            for target, spec in expected_mounts.items():
                observed = actual_mounts[target]
                for field, wanted in spec.items():
                    got = observed.get(field, False if field == 'ReadOnly' else None)
                    need(got == wanted, 'HOST_MOUNT_REQUEST_DIFFERS')
            continue
        need(current == value, 'REPLACEMENT_HOST_CONFIG_DIFFERS')
    mounts = {m['Destination']: m for m in actual['Mounts']}
    need(set(mounts) == {m['Destination'] for m in original['Mounts']} | {DEST}, 'REPLACEMENT_MOUNT_SET_DIFFERS')
    for old in original['Mounts']:
        new = mounts[old['Destination']]
        need(all(new.get(k) == old.get(k) for k in ('Type', 'Source', 'Name', 'RW', 'Propagation')),
             'RETAINED_MOUNT_DIFFERS')
    need(mounts[DEST]['Type'] == 'bind' and not mounts[DEST]['RW']
         and mounts[DEST]['Source'] == request['HostConfig']['Mounts'][-1]['Source'],
         'STORAGE_MOUNT_NOT_READ_ONLY')
    if started:
        need(actual['State']['Running'] and not actual['State']['Restarting'], 'REPLACEMENT_NOT_RUNNING')
        networks = actual['NetworkSettings']['Networks']
        need(set(networks) == {BACKEND, PRIVATE}, 'REPLACEMENT_NETWORK_SET_DIFFERS')
        previous = original['NetworkSettings']['Networks'][BACKEND]
        for key in ('NetworkID', 'IPAddress', 'GlobalIPv6Address', 'MacAddress', 'Gateway'):
            need(networks[BACKEND].get(key) == previous.get(key), 'REPLACEMENT_BACKEND_ADDRESS_DIFFERS')
        need(set(previous.get('Aliases') or []) <= set(networks[BACKEND].get('Aliases') or []),
             'REPLACEMENT_BACKEND_ALIASES_DIFFER')
    else:
        need(actual['State']['Status'] == 'created' and not actual['State']['Running'], 'REPLACEMENT_ALREADY_STARTED')


def readiness(address, port):
    connection = http.client.HTTPConnection(address, port, timeout=3)
    try:
        connection.request('GET', '/actuator/health/readiness')
        response = connection.getresponse()
        raw = response.read(65537)
        return response.status == 200 and len(raw) <= 65536 and json.loads(raw).get('status') == 'UP'
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def readiness_port(app):
    values = environment(app)
    server = values.get('SERVER_PORT', values.get('PORT', '8080'))
    management = values.get('MANAGEMENT_SERVER_PORT')
    jvm_args = (app.get('Args') or []) + shlex.split(values.get('JAVA_TOOL_OPTIONS', '')) + shlex.split(values.get('JDK_JAVA_OPTIONS', ''))
    for arg in jvm_args:
        if arg.startswith('-Dserver.port='):
            server = arg.split('=', 1)[1]
        if arg.startswith('-Dmanagement.server.port='):
            management = arg.split('=', 1)[1]
    properties = json_properties(values.get('SPRING_APPLICATION_JSON', '{}'))
    server = properties.get('server.port') or server
    management = properties.get('management.server.port') or management
    for arg in (app['Config'].get('Entrypoint') or []) + (app['Config'].get('Cmd') or []):
        if arg.startswith('--server.port='):
            server = arg.split('=', 1)[1]
        if arg.startswith('--management.server.port='):
            management = arg.split('=', 1)[1]
    port = management or server
    need(str(port).isdigit() and 0 < int(port) < 65536, 'READINESS_PORT_INVALID')
    return int(port)


def restore_before_start(engine, original, replacement_name, token, state, report):
    need(not state['startDispatched'], 'POST_START_ROLLBACK_FORBIDDEN')
    # A lost create response is resolved by the exclusive replacement name and label.
    listed = [json.loads(line) for line in docker('container', 'ls', '-a', '--no-trunc',
              '--format', 'json').stdout.decode().splitlines() if line]
    candidates = [r for r in listed if r['Names'] == replacement_name]
    if candidates:
        candidate = engine.inspect(candidates[0]['ID'])
        if candidate['Id'] != original['Id']:
            need(candidate['Config'].get('Labels', {}).get(LABEL) == token
                 and candidate['State']['Status'] == 'created', 'CREATED_REPLACEMENT_NOT_PROVEN')
            engine.request('DELETE', '/containers/' + candidate['Id'] + '?v=false', expected=(204,))
    old = engine.inspect(original['Id'])
    need(not old['State']['Running'], 'ORIGINAL_UNEXPECTEDLY_RUNNING')
    if BACKEND not in old['NetworkSettings']['Networks']:
        engine.request('POST', '/networks/' + BACKEND + '/connect',
                       {'Container': old['Id'], 'EndpointConfig': endpoint(original)}, expected=(200,))
    if old['Name'] != original['Name']:
        engine.request('POST', '/containers/' + old['Id'] + '/rename?name=' + original['Name'].lstrip('/'), expected=(204,))
    engine.request('POST', '/containers/' + old['Id'] + '/update',
                   {'RestartPolicy': original['HostConfig']['RestartPolicy']})
    engine.request('POST', '/containers/' + old['Id'] + '/start', expected=(204,), timeout=45)
    need(engine.inspect(old['Id'])['State']['Running'], 'ORIGINAL_RESTORE_NOT_RUNNING')
    report.update(originalRestoredBeforeReplacementStart=True, applicationBindingsChanged=False)
    MARKER.unlink(missing_ok=True)


def json_properties(raw):
    need(len(raw) <= 1024 * 1024, 'SPRING_JSON_TOO_LARGE')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'SPRING_JSON_DUPLICATE_KEY')
            result[key] = value
        return result
    parsed = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(parsed, dict), 'SPRING_JSON_NOT_OBJECT')
    result = {}
    def walk(node, prefix='', depth=0):
        need(depth <= 20, 'SPRING_JSON_TOO_DEEP')
        for key, value in node.items():
            name = prefix + key
            if isinstance(value, dict):
                walk(value, name + '.', depth + 1)
            else:
                need(name not in result, 'SPRING_JSON_FLATTENED_COLLISION')
                result[name] = value
    walk(parsed)
    return result


def verify_source_binding(app):
    values = environment(app)
    expected = {'endpoint': 'http://ouf-minio:9000', 'bucket': 'ouf-udp',
                'region': 'us-east-1', 'path-style': 'true'}
    for key, value in expected.items():
        need(values.get('OUF_UDP_S3_' + key.upper().replace('-', '_')) == value,
             'UDP_SOURCE_BINDING_CHANGED')
    properties = json_properties(values.get('SPRING_APPLICATION_JSON', '{}'))
    normalized = lambda value: re.sub('[._-]', '', value).lower()
    for key, value in properties.items():
        if value is None:
            continue
        if normalized(key).startswith(('oufudplakes3', 'oufudps3')):
            raise RuntimeError('UDP_STORAGE_JSON_CHANGED_SINCE_PROBE')
    need(not any('ouf.udp.lake.s3.' in value for value in (app.get('Args') or []) +
                 [values.get(k, '') for k in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS')]),
         'UDP_SOURCE_LAUNCH_OVERRIDE_CHANGED')


def verify_installed_classes(app):
    path = Path('/proc') / str(app['State']['Pid']) / 'root/app/app.jar'
    need(path.stat().st_size <= 512 * 1024 * 1024, 'UDP_JAR_TOO_LARGE')
    hashes = {'S3LakeConfiguration': '5036160bbd46809ee87adb285e489547fc0a713e97a85327d6097be59b1530e6',
              'S3LakeObjectStorageAdapter': '5a6bd871ce01e2235ab98f74e6307016ebec9996e62e42fccc11ca951eaa7bf8'}
    with zipfile.ZipFile(path) as jar:
        for name, expected in hashes.items():
            item = jar.getinfo('BOOT-INF/classes/it/comune/trieste/ouf/udp/' + name + '.class')
            need(item.file_size <= 262144 and digest(jar.read(item)) == expected, 'UDP_INSTALLED_CLASS_CHANGED')


def udp_listing(m, client, report):
    raw, _ = m.success(client.request('GET', '/ouf-udp?list-type=2&max-keys=1000', maximum=1048576), report)
    root = m.ET.fromstring(raw)
    need(root.tag.rsplit('}', 1)[-1] == 'ListBucketResult' and root.findtext('{*}Name') == 'ouf-udp'
         and root.findtext('{*}IsTruncated') == 'false', 'UDP_LIST_SHAPE_OR_LIMIT')
    rows = []
    for item in root.findall('{*}Contents'):
        row = {name: item.findtext('{*}' + name) for name in ('Key', 'ETag', 'LastModified', 'Size')}
        row['Size'] = int(row['Size'])
        key = row['Key']
        need(key and len(key.encode()) <= 1024 and all(ord(c) >= 32 for c in key)
             and not any(part in ('.', '..') for part in key.split('/'))
             and row['ETag'] and row['LastModified'] and 0 <= row['Size'] <= 64*1024*1024,
             'UDP_OBJECT_SCOPE_OR_SIZE')
        rows.append(row)
    need(len(rows) <= 512 and len({r['Key'] for r in rows}) == len(rows)
         and sum(r['Size'] for r in rows) <= 256*1024*1024, 'UDP_LIST_SIZE')
    return sorted(rows, key=lambda r: r['Key'])


def target_credentials(m):
    client = m.BINDINGS / 'clients/udp'
    target = json.loads(m.read(client / 'binding.private.json'))['environment']
    need(target['OUF_UDP_S3_ENDPOINT'] == 'https://ouf-seaweedfs-stage:9002'
         and target['OUF_UDP_S3_BUCKET'] == 'ouf-udp' and target['OUF_UDP_S3_REGION'] == 'us-east-1'
         and target['OUF_UDP_S3_PATH_STYLE'] == 'true', 'TARGET_BINDING_CHANGED')
    raw = m.read(client / 'credentials', 16384)
    parsed = configparser.ConfigParser(interpolation=None)
    parsed.read_string(raw.decode())
    need(set(parsed.sections()) == {'default'} and not parsed.defaults()
         and set(parsed['default']) == {'aws_access_key_id', 'aws_secret_access_key'}, 'TARGET_PROFILE_CHANGED')
    auth = tuple(parsed['default'][key] for key in ('aws_access_key_id', 'aws_secret_access_key'))
    need(all(value and not any(c in value for c in '\r\n\x00') for value in auth), 'TARGET_CREDENTIAL_INVALID')
    return raw, auth


def clean_own_diagnostic(m, destination, report):
    path = '/ouf-udp/' + DIAGNOSTIC_KEY
    result = destination.request('GET', path)
    if result[0] == 404 and m.provider_code(result[1]) == 'NoSuchKey':
        report['ownDiagnosticObjectRemoved'] = True
        return
    body, _ = m.success(result, report)
    need(len(body) == 33 and digest(body) == DIAGNOSTIC_SHA, 'OWN_DIAGNOSTIC_OBJECT_CHANGED')
    deleted = destination.request('DELETE', path)
    need(deleted[0] == 204, 'OWN_DIAGNOSTIC_DELETE_FAILED')
    after = destination.request('GET', path)
    need(after[0] == 404 and m.provider_code(after[1]) == 'NoSuchKey', 'OWN_DIAGNOSTIC_DELETE_NOT_VERIFIED')
    report['ownDiagnosticObjectRemoved'] = True


def require_host_tls_tools():
    need(Path('/usr/bin/nsenter').is_file() and Path('/usr/bin/openssl').is_file(), 'HOST_TLS_TOOLS_MISSING')


def network_tls(actual, sea, ca):
    require_host_tls_tools()
    check = subprocess.run(('/usr/bin/nsenter', '--target', str(actual['State']['Pid']), '--net',
        '/usr/bin/openssl', 's_client', '-brief', '-connect',
        sea['NetworkSettings']['Networks'][PRIVATE]['IPAddress'] + ':9002',
        '-servername', 'ouf-seaweedfs-stage', '-verify_hostname', 'ouf-seaweedfs-stage',
        '-verify_return_error', '-CAfile', str(ca)), stdin=subprocess.DEVNULL,
        capture_output=True, timeout=12)
    need(check.returncode == 0, 'REPLACEMENT_NETWORK_TLS_FAILED')


def execute(report):
    global DEADLINE
    DEADLINE = time.monotonic() + 600
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    need(not MARKER.exists(), 'EXISTING_UDP_SWITCH_REQUIRES_READBACK')
    require_host_tls_tools()
    m, engine = copier(), Engine()
    m.DEADLINE = DEADLINE
    raw = m.read(m.PLAN)
    need(digest(raw) == m.PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    roles = json.loads(raw)['roles']
    app, minio, sea = [engine.inspect(ref) for ref in (
        roles['udp']['containerId'], roles['minio']['containerId'], 'ouf-seaweedfs-stage')]
    need(app['State']['Running'] and app['Image'] == APP_IMAGE and minio['State']['Running']
         and minio['Image'] == roles['minio']['nativeImage'] and sea['State']['Running']
         and sea['Image'] == m.SEA_IMAGE, 'CURRENT_RUNTIME_CHANGED')
    prior = json.loads(m.read(PREVIOUS / 'result.json'))
    need(prior['status'] == 'UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH' and prior['udpImage'] == APP_IMAGE
         and prior['diagnosticObjectKey'] == DIAGNOSTIC_KEY and prior['payloadSha256'] == DIAGNOSTIC_SHA
         and prior['javaTransfer']['bodyMatches'] and prior['javaTransfer']['metadataMatches']
         and prior['sourceApplicationJsonStorage']['storageDeclarations'] == [], 'PREVIOUS_CLIENT_PROBE_NOT_VERIFIED')
    verify_source_binding(app)
    verify_installed_classes(app)
    network = engine.request('GET', '/networks/' + PRIVATE)
    need(network['Internal'] and network['Driver'] == 'bridge' and not sea['HostConfig'].get('PortBindings')
         and set(sea['NetworkSettings']['Networks']) == {PRIVATE}, 'PRIVATE_SEAWEEDFS_NETWORK_REQUIRED')
    port = readiness_port(app)
    address = app['NetworkSettings']['Networks'][BACKEND]['IPAddress']
    need(readiness(address, port), 'ORIGINAL_READINESS_NOT_UP')
    report['originalReadinessUp'] = True
    work = Path(tempfile.mkdtemp(prefix='udp-seaweedfs-switch-', dir=ROOT))
    os.chmod(work, 0o700)
    report['privateEvidenceDirectory'] = str(work)
    token = uuid.uuid4().hex
    folder = work / 'application'; folder.mkdir(mode=0o700)
    save(work / 'original-container.private.json', app)
    save(work / 'original-minio.private.json', minio)
    report['phase'] = 'PREPARE_TRUST_AND_BINDING'
    request = make_request(app, folder, token, APP_IMAGE)
    ca = m.read(m.BINDINGS / 'config/tls/ca.pem', 65536)
    need(digest(ca) == CA_SHA, 'TARGET_CA_CHANGED')
    credential_file, target_auth = target_credentials(m)
    prepare_truststore(app, folder, ca, report)
    (folder / 'ca.pem').write_bytes(ca)
    (folder / 'credentials').write_bytes(credential_file)
    (folder / 'aws-config').write_bytes(b'')
    uid = int(docker('exec', app['Id'], 'id', '-u').stdout.strip())
    gid = int(docker('exec', app['Id'], 'id', '-g').stdout.strip())
    need(uid == 10004 and gid == 10004, 'OBSERVED_UDP_IDENTITY_CHANGED')
    for path in [folder, *folder.iterdir()]:
        os.chown(path, uid, gid); os.chmod(path, 0o700 if path.is_dir() else 0o400)
    auth, region = m.source_credentials(minio, report)
    source = m.S3(minio['NetworkSettings']['Networks'][BACKEND]['IPAddress'], 'ouf-minio', 9000,
                  auth, region=region, read_only=True)
    destination = m.S3(sea['NetworkSettings']['Networks'][PRIVATE]['IPAddress'], 'ouf-seaweedfs-stage',
                       9002, target_auth, folder / 'ca.pem')
    report['phase'] = 'PRECHECK_CURRENT_SOURCE_AND_TARGET'
    rows = m.listing(source, report)
    need(rows, 'UNEXPECTED_EMPTY_SOURCE_BUCKET')
    report.update(sourceObjectsBeforeStop=len(rows), sourceBytesBeforeStop=sum(r['Size'] for r in rows))
    target_before = m.listing(destination, report)
    report['targetObjectsBeforeStop'] = len(target_before)
    if any(row['Key'] == DIAGNOSTIC_KEY for row in target_before):
        body, _ = m.success(destination.request('GET', '/ouf-udp/' + DIAGNOSTIC_KEY), report)
        need(len(body) == 33 and digest(body) == DIAGNOSTIC_SHA, 'DESTINATION_PROBE_PRECHECK_DIFFERS')
    save(work / 'replacement-request.private.json', request)
    need(m.generation(engine.inspect(app['Id'])) == m.generation(app), 'ORIGINAL_CHANGED_BEFORE_STOP')
    need(m.generation(engine.inspect(minio['Id'])) == m.generation(minio)
         and m.generation(engine.inspect(sea['Id'])) == m.generation(sea), 'STORAGE_CHANGED_BEFORE_STOP')
    state = {'startDispatched': False, 'stopDispatched': False}
    name = app['Name'].lstrip('/')
    backup = name + '-minio-retained-' + token[:8]
    marker = {'schema': 'ouf.udp-storage-binding.v1', 'status': 'SWITCH_IN_PROGRESS',
              'originalContainerId': app['Id'], 'privateEvidenceDirectory': str(work),
              'replacementName': name, 'imageId': APP_IMAGE, 'switchToken': token}
    try:
        report['phase'] = 'STOP_ORIGINAL_UDP'
        save(MARKER, marker)
        engine.request('POST', '/containers/' + app['Id'] + '/update',
                       {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}})
        state['stopDispatched'] = True
        engine.request('POST', '/containers/' + app['Id'] + '/stop?t=60', expected=(204,), timeout=75)
        report['originalStopped'] = not engine.inspect(app['Id'])['State']['Running']
        need(report['originalStopped'], 'ORIGINAL_NOT_STOPPED')
        report['phase'] = 'ALIGN_WHILE_UDP_STOPPED'
        rows = m.listing(source, report)
        need(rows, 'UNEXPECTED_EMPTY_SOURCE_BUCKET')
        save(work / 'source-at-stop.private.json', rows)
        report.update(sourceObjects=len(rows), sourceBytes=sum(r['Size'] for r in rows))
        with (work / 'copy-journal.private.jsonl').open('x') as journal:
            manifest = m.align(source, destination, rows, report, journal)
        need(m.listing(source, report) == rows, 'SOURCE_CHANGED_WHILE_UDP_STOPPED')
        save(work / 'objects-verified.private.json', manifest)
        report['manifestSha256'] = digest((work / 'objects-verified.private.json').read_bytes())
        report['sourceSnapshotUnchangedWhileStopped'] = True
        source_keys = {r['Key'] for r in rows}
        need(DIAGNOSTIC_KEY not in source_keys, 'DIAGNOSTIC_KEY_PRESENT_IN_SOURCE')
        clean_own_diagnostic(m, destination, report)
        target_rows = m.listing(destination, report)
        extras = [r for r in target_rows if r['Key'] not in source_keys]
        save(work / 'target-additional-objects.private.json', extras)
        report['additionalTargetObjectsRetained'] = len(extras)
        report['phase'] = 'REPLACE_UDP_CONTAINER'
        engine.request('POST', '/networks/' + BACKEND + '/disconnect',
                       {'Container': app['Id'], 'Force': False}, expected=(200,))
        engine.request('POST', '/containers/' + app['Id'] + '/rename?name=' + backup, expected=(204,))
        created = engine.request('POST', '/containers/create?name=' + name, request, expected=(201,))
        cid = created['Id']
        report['replacementContainerId'] = cid
        marker['replacementContainerId'] = cid; save(MARKER, marker)
        verify_created(app, request, engine.inspect(cid))
        need(not engine.inspect(app['Id'])['State']['Running'], 'ORIGINAL_RESTARTED')
        need(m.listing(source, report) == rows, 'SOURCE_CHANGED_BEFORE_REPLACEMENT_START')
        need(m.generation(engine.inspect(minio['Id'])) == m.generation(minio)
             and m.generation(engine.inspect(sea['Id'])) == m.generation(sea), 'STORAGE_CHANGED_DURING_ALIGNMENT')
        report['phase'] = 'START_SEAWEEDFS_UDP'
        state['startDispatched'] = True
        report['applicationBindingsChanged'] = None
        save(work / 'start-intent.private.json', {'containerId': cid, 'automaticMinioRollbackAllowed': False})
        report['replacementStartDispatched'] = True
        engine.request('POST', '/containers/' + cid + '/start', expected=(204,), timeout=45)
        report['applicationBindingsChanged'] = True
        ready_until = min(DEADLINE - 20, time.monotonic() + 180)
        while time.monotonic() < ready_until:
            actual = engine.inspect(cid)
            need(actual['State']['Running'], 'REPLACEMENT_EXITED')
            if readiness(address, port):
                break
            time.sleep(2)
        else:
            raise RuntimeError('REPLACEMENT_READINESS_TIMEOUT')
        verify_created(app, request, actual, started=True)
        network_tls(actual, sea, folder / 'ca.pem')
        need(not engine.inspect(app['Id'])['State']['Running'], 'ORIGINAL_RESTARTED_AFTER_SWITCH')
        save(work / 'replacement-container.private.json', actual)
        marker.update(status='UDP_SEAWEEDFS_READY', endpoint='https://ouf-seaweedfs-stage:9002',
                      bucket='ouf-udp', applicationHttpLakeOperationTested=False)
        save(MARKER, marker)
        report.update(status='UDP_SEAWEEDFS_READY', phase='COMPLETE', readinessUp=True,
                      containerNetworkTlsVerified=True, sameApplicationImage=True,
                      backendAddressAliasesPreserved=True, originalRetainedStopped=True,
                      endpoint=marker['endpoint'], bucket='ouf-udp')
    except Exception:
        report['failurePhase'] = report['phase']
        if state['stopDispatched'] and not state['startDispatched']:
            try:
                DEADLINE = time.monotonic() + 90  # Reserved restore time, never a copy retry.
                report['phase'] = 'RESTORE_ORIGINAL_BEFORE_REPLACEMENT_START'
                restore_before_start(engine, app, name, token, state, report)
            except Exception as error:
                report['restoreReason'] = m.failure_reason(error)
        raise
    finally:
        report.update(sourceS3Requests=source.calls, destinationS3Requests=destination.calls)


def main():
    os.umask(0o077)
    report = {'schema': 'ouf.udp-seaweedfs-switch.v1', 'status': 'INCOMPLETE',
              'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'applicationBindingsChanged': False, 'applicationPermissionsChanged': False,
              'credentialValuesEmitted': False, 'applicationHttpLakeOperationTested': False,
              'databaseQueriesIssuedByScript': 0, 'applicationRestartMayAccessDatabase': True,
              'objectsAlreadyMatched': 0, 'objectsCopiedAndVerified': 0, 'putAttempts': 0,
              'sourceObjectsModified': False, 'existingTargetObjectsOverwritten': False,
              'targetTagsFreshlyCompared': False, 'onboardingBindingsChanged': False}
    try:
        with open('/run/lock/ouf-runtime-e2e.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            execute(report)
    except Exception as exc:
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z0-9_]{1,120}', str(exc)) else type(exc).__name__
    report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'privateEvidenceDirectory' in report:
        save(Path(report['privateEvidenceDirectory']) / 'result.json', report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'UDP_SEAWEEDFS_READY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
