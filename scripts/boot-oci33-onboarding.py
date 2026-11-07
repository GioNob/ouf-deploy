#!/usr/bin/env python3
"""Boot the exact Onboarding image against isolated copies of PostgreSQL and OCI33."""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit
from urllib.request import urlopen
import uuid
from xml.etree import ElementTree as ET

SCHEMA = 'ouf.storage-oci33-onboarding-boot.v1'
UPLOAD_SCHEMA = 'ouf.storage-oci33-onboarding-upload.v1'
READBACK_SCHEMA = 'ouf.storage-oci33-onboarding-upload-readback.v1'
ROOT = Path('/var/lib/ouf-storage-migration')
STAGE = ROOT / 'seaweedfs/staging-oci33-20261107-v1'
BINDINGS = STAGE / 'application-s3-v1'
SCOPE = STAGE / 'onboarding-stack-v1'
UPLOAD_SCOPE = SCOPE / 'upload-proof-v1'
PG_IMAGE = 'sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'
PG_CONFIG = 'sha256:823c9d80930ce5f5fb4ed0f54a091abb79cfde1e34189aaeb69aeaf2720400a2'
S3_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
ONB_IMAGE = 'sha256:2dd55525d4a6969cf59f4d5e811c5f502976211c0cb49f9ba081dab5e4806c15'
ONB_TESTED = '69b099b04f1823b127ef4af4a9c44861ff4cdc67'
ONB_CONFIG = 'sha256:0a29a90a48a69a6ed757748bdac97cf029b6e7d633b6bc9a9b1d706fa00837db'
S3_CONFIG = 'sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6'
SOURCE_MANIFEST = 'c54d67b9ec8448e884a296c37e588845e3d128283af14e92c29b9bb3e3a8281f'
UPLOAD_PATH = '/api/internal/v1/onboarding/managed-file-mcp/upload'
CAPABILITY = 'ouf.managed-source.file.upload'
ISSUER = 'https://ouf-isolated.invalid/issuer'
AUDIENCE = 'ouf-isolated-owner'
WORKLOAD = 'ouf-isolated-upload-driver'
SUBJECT = 'human:ouf-isolated-fixture'
TENANT = 'ouf-isolated-theatres'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
CLIENT = r"""
import base64, http.client, json, socket, ssl, sys
if sys.argv[1] == 'request':
    method, port, path, headers, encoded, ca, maximum = json.load(sys.stdin)
    if ca:
        c = http.client.HTTPSConnection('localhost', port, timeout=20,
                                       context=ssl.create_default_context(cafile=ca))
    else:
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=55)
    try:
        body = base64.b64decode(encoded, validate=True) if encoded else None
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read(maximum + 1)
        if len(data) > maximum:
            raise SystemExit(75)
        print(json.dumps([r.status, base64.b64encode(data).decode()]))
    except (ConnectionRefusedError, TimeoutError, ConnectionResetError):
        raise SystemExit(70)
    finally:
        c.close()
elif sys.argv[1] == 's3':
    try:
        context = ssl.create_default_context(cafile=sys.argv[2])
        with socket.create_connection(('127.0.0.1', 9002), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname='localhost'):
                print('TLS_OK')
    except (ConnectionRefusedError, TimeoutError, ConnectionResetError):
        raise SystemExit(70)
else:
    c = http.client.HTTPConnection('127.0.0.1', 8080, timeout=3)
    try:
        c.request('GET', '/actuator/health/readiness')
        r = c.getresponse()
        body = r.read(32769)
        status = json.loads(body).get('status') if len(body) <= 32768 and r.status == 200 else None
        print('UP' if status == 'UP' else 'WAIT')
    except (ConnectionRefusedError, TimeoutError, ConnectionResetError):
        raise SystemExit(70)
    finally:
        c.close()
"""


def need(ok, code):
    if not ok:
        raise ValueError(code)


def pinned(ref, name, size, sha):
    url = f'https://raw.githubusercontent.com/GioNob/ouf-deploy/{ref}/scripts/{name}'
    with urlopen(url, timeout=25) as response:
        raw = response.read(size + 1)
    need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha, 'PINNED_HELPER_DIGEST')
    namespace = {'__name__': 'isolated_stack_helper'}
    exec(compile(raw, name, 'exec'), namespace)
    return namespace


def clone(source, target, timeout):
    need(stat.S_ISDIR(source.lstat().st_mode) and source.resolve(strict=True) == source,
         'WORKING_COPY_SOURCE_REQUIRED')
    c = subprocess.run(['/usr/bin/cp', '-a', '--reflink=auto', '--sparse=always', '--',
                        str(source), str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env=ENV, timeout=timeout)
    need(c.returncode == 0, 'WORKING_COPY_FAILED')


def receipt(key, token, checksum, size):
    def b64(raw):
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    now = int(time.time())
    payload = b64(json.dumps({'v': 1, 'purpose': 'managed-file-upload-owner', 'method': 'POST',
        'path': UPLOAD_PATH, 'capability': CAPABILITY, 'expectedHash': checksum, 'expectedLength': size,
        'fileId': 'file_' + token, 'iat': now - 1, 'exp': now + 24, 'issuer': ISSUER,
        'audience': AUDIENCE, 'workload': WORKLOAD, 'subject': SUBJECT, 'tenant': TENANT, 'acr': '1',
        'roles': '', 'scope': CAPABILITY, 'idempotencyKey': token}, separators=(',', ':')).encode())
    signature = hmac.digest(key.encode('ascii'), ('ouf-managed-file-upload-v1.' + payload).encode('ascii'), 'sha256')
    return payload + '.' + b64(signature)


def snapshot(h, pg, read):
    old = ROOT / 'historical-minio-restore-20261107-v1'
    members = read(old / 'verified-members.private.json')
    evidence = {'custody-claim.private.json': pg['SEALED'] / 'claim.private.json',
                'original-claim.private.json': pg['OLD'] / 'claim.private.json',
                'original-producer-claim.private.json': pg['OLD'] / 'capture/capture-claim.private.json'}
    manifest = {'schema': 'ouf.storage-retained-capture-custody.v1', 'members': members,
                'evidenceSha256': {name: h['digest'](h['protected'](path, private=True, limit=8192))
                                   for name, path in evidence.items()},
                'captureEventCoverageProven': False, 'liveSourceContinuityProven': False,
                'historicalCustodyOnly': True, 'restorePerformed': False}
    need(len(members) == 53 and h['digest'](h['canonical'](manifest)) == pg['MANIFEST_SHA'], 'CUSTODY_BINDING')
    payload = pg['PAYLOAD']
    plan = read(payload / 'plan.private.json', members['plan.private.json']['sha256'])
    configs = read(payload / 'containers.private.json', members['containers.private.json']['sha256'])
    postgres = configs[plan['roles']['postgres']['containerId']]
    onboarding = configs[plan['roles']['onboarding']['containerId']]
    pg_env = dict(item.split('=', 1) for item in postgres['Config']['Env'] if '=' in item)
    onb_env = dict(item.split('=', 1) for item in onboarding['Config']['Env'] if '=' in item)
    admin = pg_env.get('POSTGRES_USER', 'postgres')
    user = onb_env.get('OUF_ONB_DB_USER', '')
    jdbc = onb_env.get('OUF_ONB_DB_URL', 'jdbc:postgresql://localhost/ouf_onboarding')
    url = urlsplit(jdbc[5:])
    database = url.path.lstrip('/')
    need(url.scheme == 'postgresql' and all(re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', name)
         for name in (admin, user, database)) and user != admin and database not in ('postgres', 'template0', 'template1'),
         'ISOLATED_DATABASE_ROLE_BINDING')
    return plan, members, admin, user, database


def run(report, upload, readback):
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
    pg = pinned('5ae47689adeaf39f241527c9364a2c0c9e9b0b9b', 'restore-retained-postgres.py', 19046,
                '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d')
    h = pg['load_producer']()

    def read(path, pin=None):
        raw = h['protected'](path, private=True, limit=8 << 20)
        need(pin is None or h['digest'](raw) == pin, 'PRIVATE_INPUT_BINDING')
        return h['decode'](raw)

    binding = read(BINDINGS / 'access-proof-v2/result.json')
    need(binding.get('status') == 'ISOLATED_OCI33_APP_BINDINGS_READY'
         and binding.get('tlsVerified') is True and binding.get('ownBucketBodiesVerified') == 2
         and binding.get('crossBucketAccessDenied') == 2 and binding.get('temporaryContainerRemoved') is True,
         'S3_BINDING_RECEIPT_REQUIRED')
    private_client = BINDINGS / 'clients/onboarding'
    client = read(private_client / 'binding.private.json')['environment']
    bucket = client['OUF_ONBOARDING_STAGING_BUCKET']
    need(re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
         and client['OUF_ONBOARDING_STAGING_ENDPOINT'] == 'https://ouf-seaweedfs-stage:9002',
         'ONBOARDING_BUCKET_BINDING')
    plan, members, admin, user, database = snapshot(h, pg, read)
    scope = UPLOAD_SCOPE / 'readback-v1' if readback else UPLOAD_SCOPE if upload else SCOPE
    schema = READBACK_SCHEMA if readback else UPLOAD_SCHEMA if upload else SCHEMA
    if upload or readback:
        prior = read(SCOPE / 'result.json')
        need(prior.get('status') == 'ISOLATED_ONBOARDING_STACK_READY'
             and prior.get('flywayVersionsVerified') == [39, 40, 41]
             and prior.get('containersRemoved') == 3 and prior.get('onboardingReadinessUp') is True,
             'ONBOARDING_BOOT_RECEIPT_REQUIRED')
        rehearsal = pinned('09386c72b54e703dbab4bdd296a493ccdf1f0e05', 'rehearse-oci33-retained.py', 25800,
                           'd22e0b380dacf0dce6f3c84de069d19c8eca4c39c759f6200ef9255019f2950d')
        manifest = ROOT / 'historical-minio-restore-20261107-v1/s3-proof-v2/s3-bodies.private.json'
        rows = read(manifest, SOURCE_MANIFEST)
        samples = [row for row in rows if row['bucket'] == bucket and row['key'].startswith('managed-files/')]
        need(len(rows) == 120 and samples, 'SEAWEEDFS_READY_OBJECT_BINDING')
        sample = min(samples, key=lambda item: (item['size'], item['key']))
        need(0 <= sample['size'] <= 1 << 20, 'SEAWEEDFS_READY_OBJECT_SIZE')
    if readback:
        failed = read(UPLOAD_SCOPE / 'claim.private.json')
        original = read(UPLOAD_SCOPE / 'upload-intent.private.json')
        attempt = failed['scopeToken']
        need(failed.get('schema') == UPLOAD_SCHEMA and failed.get('onboardingImage') == ONB_IMAGE
             and failed.get('postgresImage') == PG_IMAGE and failed.get('storageImage') == S3_IMAGE
             and failed.get('custodyManifestSha256') == pg['MANIFEST_SHA']
             and re.fullmatch('[a-f0-9]{24}', attempt) and original.get('idempotencyKey') == attempt
             and original.get('fileId') == 'file_' + attempt and original.get('maximumRequests') == 1
             and original.get('isolatedIdentity') is True and re.fullmatch('[a-f0-9]{64}', original['sha256'])
             and 0 < original['bytes'] <= 4096 and not os.path.lexists(UPLOAD_SCOPE / 'result.json'),
             'HELD_UPLOAD_BINDING')
        log_patterns = {
            'tlsHandshake': rb'SSLHandshakeException|PKIX|certificate_unknown|bad certificate|x509:',
            'accessDenied': rb'AccessDenied|access denied',
            'signature': rb'SignatureDoesNotMatch|InvalidAccessKeyId|signature mismatch',
            'requestEncoding': rb'MissingContentLength|XAmzContentSHA256Mismatch|aws-chunked|unsupported.*header',
            'volumeAllocation': rb'failed to assign|no (free|writable) volumes|failed to allocate.*volume',
            'backendConnection': rb'connection refused|connection reset|failed to connect',
            'storageWrite': rb'ONB_STAGING_WRITE_FAILED|PutObject[^\n]*(error|failed)|failed to (store|write|save)',
        }
        for service in ('onboarding', 'postgres', 'seaweedfs'):
            raw = h['protected'](UPLOAD_SCOPE / (service + '.log.private'), private=True, limit=262144)
            report['retainedLogHints'][service] = [name for name, pattern in log_patterns.items()
                                                   if re.search(pattern, raw, re.IGNORECASE)]
    need(shutil.disk_usage(STAGE).free >= 3 << 30, 'ISOLATED_STACK_FREE_SPACE')
    sock = Path('/run/docker.sock').stat()
    need(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o007,
         'LOCAL_DOCKER_SOCKET_REQUIRED')
    docker_base = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent']

    def call(*args, data=None, timeout=15):
        now = Path('/run/docker.sock').stat()
        need(h['frame'](now) == h['frame'](sock), 'DOCKER_SOCKET_CHANGED')
        return subprocess.run(docker_base + list(args), input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=ENV, timeout=timeout)

    def docker(*args, data=None, timeout=15):
        result = call(*args, data=data, timeout=timeout)
        need(result.returncode == 0, 'DOCKER_' + args[0].upper() + '_FAILED')
        return result.stdout

    def image_id(expected):
        row, = json.loads(docker('image', 'inspect', expected))
        need(row['Id'] == expected, 'LOCAL_IMAGE_ID_CHANGED')
        return row

    need(not docker('ps', '-q').strip(), 'OTHER_CONTAINERS_RUNNING')
    if readback:
        need(not docker('ps', '-aq', '--filter', 'label=ouf.oci33-stack=' + attempt).strip(),
             'HELD_UPLOAD_CONTAINERS_PRESENT')
    image_id(PG_IMAGE)
    sea = image_id(S3_IMAGE)
    need(sea['Config']['User'] == '10001:10001', 'STACK_STORAGE_IMAGE_BINDING')
    if not readback:
        onb = image_id(ONB_IMAGE)
        need(onb['Config']['User'] == '10003:10003'
             and onb['Config']['Labels']['org.opencontainers.image.revision'] == ONB_TESTED, 'STACK_IMAGE_BINDING')

    parent = h['runtime_parent'](scope)
    try:
        os.mkdir(scope.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    token = secrets.token_hex(12)
    h['new'](scope / 'claim.private.json', h['canonical']({'schema': schema, 'scopeToken': token,
        'onboardingImage': ONB_IMAGE, 'postgresImage': PG_IMAGE, 'storageImage': S3_IMAGE,
        'custodyManifestSha256': pg['MANIFEST_SHA']}))
    if upload or readback:
        image, _, source, suffix = pg['source_binding'](h, plan, members)
        origin = UPLOAD_SCOPE / 'postgres' if readback else SCOPE / 'postgres/data' / source.name / str(suffix)
        if not readback:
            need(not os.path.lexists(origin / 'postmaster.pid'), 'PRIOR_WORKING_POSTGRES_NOT_STOPPED')
        cluster = scope / 'postgres'
        clone(origin, cluster, 120)
        info = cluster.lstat()
        uid, gid = info.st_uid, info.st_gid
        need(uid > 0 and (cluster / 'PG_VERSION').is_file(), 'POSTGRES_WORKING_COPY_REQUIRED')
        stale = cluster / 'postmaster.pid'
        if readback and os.path.lexists(stale):
            info = stale.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1,
                 'COPIED_POSTMASTER_PID_UNSAFE')
            stale.unlink()
    else:
        pg['NEW'] = scope / 'postgres'
        pg['NEW'].mkdir(mode=0o700)
        image, cluster, uid, gid, _ = pg['extract_cluster'](h, plan, members, time.monotonic() + 190)
    need(image == PG_IMAGE and not os.path.lexists(cluster / 'postmaster.pid'), 'ISOLATED_POSTGRES_COPY_BINDING')
    work_source = UPLOAD_SCOPE if readback else SCOPE
    data_source = work_source / 'seaweed-data' if upload or readback else STAGE / 'data'
    info = data_source.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 10001 and data_source.resolve(strict=True) == data_source,
         'STAGED_STORAGE_DATA_BINDING')
    storage = scope / 'seaweed-data'
    clone(data_source, storage, 45)
    need((storage / 'metadata').is_dir(), 'ISOLATED_STORAGE_COPY_FAILED')
    report['postgresCopyPrepared'] = report['storageCopyPrepared'] = True

    pg_files = scope / 'pg-config'
    pg_files.mkdir(mode=0o700)
    pg_hba = f'local all {admin} trust\n'
    if not readback:
        pg_hba += f'host {database} {user} 127.0.0.1/32 scram-sha-256\n'
    h['new'](pg_files / 'pg_hba.conf', pg_hba.encode())
    for p in (pg_files / 'pg_hba.conf', pg_files):
        os.chown(p, uid, gid)
    storage_config = BINDINGS / 'config'
    for path in (storage_config, storage_config / 'tls'):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 10001 and stat.S_IMODE(info.st_mode) == 0o700,
             'ISOLATED_STORAGE_CONFIG_BINDING')
    for path in (storage_config / 'filer.toml', storage_config / 's3.json',
                 *(storage_config / 'tls' / name for name in ('ca.pem', 'server.pem', 'server.key'))):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 10001 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 32768, 'ISOLATED_STORAGE_CONFIG_FILE')
    if readback:
        original_config = storage_config
        storage_config = scope / 'seaweed-config'
        storage_config.mkdir(mode=0o700)
        clone(original_config / 'tls', storage_config / 'tls', 10)
        h['new'](storage_config / 'filer.toml', (original_config / 'filer.toml').read_bytes())
        s3_auth = ('oufreadback' + secrets.token_hex(8), secrets.token_hex(24))
        h['new'](storage_config / 's3.json', h['canonical']({'identities': [{
            'name': 'upload-readback', 'credentials': [{'accessKey': s3_auth[0], 'secretKey': s3_auth[1]}],
            'actions': ['Read:' + bucket, 'List:' + bucket]}]}))
        for path in (storage_config / 'filer.toml', storage_config / 's3.json', storage_config):
            os.chown(path, 10001, 10001)
        ca_file = storage_config / 'tls/ca.pem'
    else:
        files = scope / 'onboarding-secrets'
        files.mkdir(mode=0o700)
        s3_auth = []
        for name in ('access-key', 'secret-key'):
            raw = h['protected'](private_client / name, private=True, limit=4096)
            h['new'](files / name, raw)
            s3_auth.append(raw.decode('ascii').strip())
        h['new'](files / 'ca.pem', (storage_config / 'tls/ca.pem').read_bytes())
        if upload:
            key = secrets.token_hex(32)
            h['new'](files / 'upload-receipt-key', (key + '\n').encode())
        for p in (*files.iterdir(), files):
            os.chown(p, 10003, 10003)
        password = secrets.token_hex(24)
        app_env = scope / 'onboarding.env.private'
        variables = {'OUF_ONB_DB_URL': f'jdbc:postgresql://127.0.0.1:5432/{database}',
                     'OUF_ONB_DB_USER': user, 'OUF_ONB_DB_PASSWORD': password,
                     'OUF_ONBOARDING_STAGING_ENDPOINT': 'https://localhost:9002',
                     'OUF_ONBOARDING_STAGING_BUCKET': bucket,
                     'OUF_ONBOARDING_STAGING_ACCESS_KEY_FILE': '/run/stage-s3/access-key',
                     'OUF_ONBOARDING_STAGING_SECRET_KEY_FILE': '/run/stage-s3/secret-key',
                     'OUF_IAM_ENABLED': 'false', 'SERVER_ADDRESS': '127.0.0.1'}
        if upload:
            variables.update({'OUF_IAM_ISSUER': ISSUER, 'OUF_IAM_AUDIENCE': AUDIENCE,
                              'OUF_AUTHORIZATION_DELEGATION_WORKLOAD': WORKLOAD,
                              'OUF_AUTHORIZATION_DELEGATION_KEY_FILE': '/run/stage-s3/upload-receipt-key'})
        h['new'](app_env, ''.join(f'{key}={value}\n' for key, value in variables.items()).encode())
        ca_file = files / 'ca.pem'

    common = ['--pull=never', '--restart=no', '--read-only', '--cap-drop=ALL',
              '--security-opt=no-new-privileges', '--memory=1g', '--cpus=2', '--pids-limit=256',
              '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777',
              '--label', 'ouf.oci33-stack=' + token]
    containers = []
    net = None

    def inspect(cid, network, images):
        item, = json.loads(docker('container', 'inspect', cid))
        need(item['Id'] == cid and item['Image'] in images
             and item['Config']['Labels']['ouf.oci33-stack'] == token
             and item['HostConfig']['NetworkMode'] == network
             and not item['HostConfig']['PortBindings'] and not item['HostConfig']['PublishAllPorts'],
             'STACK_CONTAINER_ISOLATION')
        return item['State']

    def start(role, network, images, *args):
        cid = docker('create', '--name', f'ouf-oci33-stack-{role}-{token}', '--network=' + network,
                     *common, *args).decode().strip()
        need(re.fullmatch(r'[a-f0-9]{64}', cid), 'STACK_CONTAINER_ID')
        containers.append((role, cid, network, images))
        inspect(cid, network, images)
        docker('start', cid)
        report['containersStarted'] += 1
        if role == 'onboarding':
            report['applicationContainersStarted'] += 1
        state = inspect(cid, network, images)
        need(state['Running'] and state['Pid'] > 0, role.upper() + '_CONTAINER_START')
        return cid, state['Pid']

    def psql(db, sql, role=admin):
        return call('exec', '-i', '--user', f'{uid}:{gid}', pg_id, 'psql', '-h', '/tmp',
                    '-U', role, '-d', db, '-X', '-Atq', '-v', 'ON_ERROR_STOP=1', '-f', '-',
                    data=(sql + '\n').encode(), timeout=10)

    def ready(mode, cid, network, images, maximum):
        end = time.monotonic() + maximum
        while time.monotonic() < end:
            p = subprocess.run(['/usr/bin/nsenter', f'--net=/proc/self/fd/{net}', '/usr/bin/python3',
                                '-I', '-B', '-S', '-c', CLIENT, mode, str(ca_file)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(net,), env=ENV, timeout=7)
            if p.returncode == 0 and p.stdout.strip() in (b'UP', b'TLS_OK'):
                return
            need(p.returncode in (0, 70) and inspect(cid, network, images)['Running'],
                 mode.upper() + '_READINESS_FAILED')
            time.sleep(2)
        raise ValueError(mode.upper() + '_READINESS_TIMEOUT')

    def request(method, port, path, headers, body=b'', ca=None, limit=32768):
        params = [method, port, path, headers, base64.b64encode(body).decode(), ca, limit]
        p = subprocess.run(['/usr/bin/nsenter', f'--net=/proc/self/fd/{net}', '/usr/bin/python3',
                            '-I', '-B', '-S', '-c', CLIENT, 'request'], input=json.dumps(params).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(net,), env=ENV, timeout=62)
        if p.returncode == 70:
            return None
        need(p.returncode == 0, method + '_HTTP_CLIENT_' + str(p.returncode))
        status, raw = json.loads(p.stdout)
        return status, base64.b64decode(raw, validate=True)

    def get_object(object_key, limit):
        report['s3GetRequests'] += 1
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        path = '/' + bucket + '/' + quote(object_key, safe='/')
        url, headers = rehearsal['signed']('GET', path, 'localhost:9002', tuple(s3_auth), b'', {}, stamp)
        return request('GET', 9002, url, headers, ca=str(ca_file), limit=max(limit, 16384))

    def wait_for_object_reads(reason):
        until = time.monotonic() + 45
        existing = get_object(sample['key'], sample['size'])
        while ((existing is None or existing[0] in (500, 502, 503, 504))
               and time.monotonic() < until and report['s3GetRequests'] < 15):
            time.sleep(2)
            existing = get_object(sample['key'], sample['size'])
        need(existing is not None and existing[0] == 200 and h['digest'](existing[1]) == sample['sha256'], reason)

    def prove_upload():
        wait_for_object_reads('SEAWEEDFS_PREUPLOAD_BODY_NOT_READY')
        report['seaweedfsPreUploadBodyVerified'] = True

        body = b'id,teatro,comune\n1,Teatro di prova,Trieste\n'
        sha = h['digest'](body)
        checksum = 'sha256:' + sha
        h['new'](scope / 'upload-intent.private.json', h['canonical']({
            'idempotencyKey': token, 'fileId': 'file_' + token, 'sha256': sha, 'bytes': len(body),
            'maximumRequests': 1, 'isolatedIdentity': True}))
        headers = {'Content-Type': 'text/csv', 'X-OUF-Managed-File-Receipt': receipt(key, token, checksum, len(body))}
        report['uploadRequests'] = 1
        response = request('POST', 8080, UPLOAD_PATH, headers, body)
        need(response is not None, 'ONBOARDING_UPLOAD_OUTCOME_UNKNOWN')
        status, raw = response
        report['onboardingUploadHttpStatus'] = status
        need(status == 201, 'ONBOARDING_UPLOAD_HTTP_' + str(status))
        asset = str(uuid.UUID(json.loads(raw)['assetId']))
        report['onboardingAssetCreated'] = True

        rows = psql(database, f"""SELECT json_build_object('state', i.state, 'ref', i.staging_ref)
            FROM ouf_onboarding.managed_file_upload_intent i
            JOIN ouf_onboarding.managed_file_asset a ON a.asset_id=i.asset_id
            JOIN ouf_onboarding.managed_file_upload_attempt t
              ON t.asset_id=a.asset_id AND t.tenant_id=i.tenant_id
               AND t.subject_id=i.subject_id AND t.idempotency_key=i.idempotency_key
            WHERE i.upload_kind='DELEGATED' AND i.idempotency_key='{token}'
              AND i.file_id='file_{token}' AND t.file_id=i.file_id AND i.asset_id='{asset}'
              AND i.tenant_id='{TENANT}' AND a.tenant_id=i.tenant_id
              AND i.subject_id='{SUBJECT}' AND a.uploaded_by=i.subject_id
              AND i.acknowledged_at IS NOT NULL AND i.staging_ref=a.staging_ref
              AND i.content_hash='{checksum}' AND a.content_hash=i.content_hash AND t.content_hash=i.content_hash
              AND i.size_bytes={len(body)} AND a.size_bytes=i.size_bytes AND t.size_bytes=i.size_bytes;""")
        need(rows.returncode == 0 and len(rows.stdout.splitlines()) == 1, 'ONBOARDING_UPLOAD_DB_RECEIPT_REQUIRED')
        row = json.loads(rows.stdout)
        ref = row['ref']
        need(row['state'] == 'ACKED' and re.fullmatch(r'object://managed-files/[a-f0-9-]{36}', ref),
             'ONBOARDING_UPLOAD_DB_ACK_REQUIRED')
        report['postgresUploadAckVerified'] = True
        stored = get_object(ref.removeprefix('object://'), len(body))
        need(stored is not None and stored[0] == 200 and len(stored[1]) == len(body)
             and h['digest'](stored[1]) == sha, 'SEAWEEDFS_UPLOAD_BODY_MISMATCH')
        report['seaweedfsUploadBodyVerified'] = True
        report['uploadedBytesVerified'] = len(body)

    def read_outcome():
        result = psql(database, f"""WITH selected AS (
            SELECT state, staging_ref, file_id, content_hash, size_bytes, asset_id IS NOT NULL AS asset_linked,
                   acknowledged_at IS NOT NULL AS acknowledged
              FROM ouf_onboarding.managed_file_upload_intent
             WHERE upload_kind='DELEGATED' AND tenant_id='{TENANT}' AND subject_id='{SUBJECT}'
               AND idempotency_key='{attempt}')
          SELECT json_build_object(
            'intents', COALESCE((SELECT json_agg(selected) FROM selected), '[]'::json),
            'attempts', (SELECT count(*) FROM ouf_onboarding.managed_file_upload_attempt
              WHERE tenant_id='{TENANT}' AND subject_id='{SUBJECT}' AND idempotency_key='{attempt}'),
            'assets', (SELECT count(*) FROM ouf_onboarding.managed_file_asset
              WHERE staging_ref IN (SELECT staging_ref FROM selected)));""")
        need(result.returncode == 0 and len(result.stdout.splitlines()) == 1, 'READBACK_POSTGRES_QUERY_FAILED')
        record = json.loads(result.stdout)
        rows = record['intents']
        report['databaseIntentCount'] = len(rows)
        report['databaseUploadAttemptCount'] = record['attempts']
        report['databaseReferencedAssetCount'] = record['assets']
        need(len(rows) <= 1 and record['attempts'] <= 1 and record['assets'] <= 1, 'READBACK_DATABASE_BINDING_CONFLICT')
        if not rows:
            report['databaseIntentState'] = 'MISSING'
            report['seaweedfsReservedObjectState'] = 'UNBOUND'
            return
        row, = rows
        ref = row['staging_ref']
        need(row['file_id'] == original['fileId'] and row['content_hash'] == 'sha256:' + original['sha256']
             and row['size_bytes'] == original['bytes'] and row['state'] in ('DISPATCHED', 'ACKED')
             and re.fullmatch(r'object://managed-files/[a-f0-9-]{36}', ref), 'READBACK_UPLOAD_INTENT_MISMATCH')
        report['databaseIntentState'] = row['state']
        report['databaseAckTimestampPresent'] = row['acknowledged']
        report['databaseIntentLinksAsset'] = row['asset_linked']
        reserved = ref.rsplit('/', 1)[1].encode('ascii')
        report['retainedSeaweedfsLogMentionsReservedKey'] = reserved in h['protected'](
            UPLOAD_SCOPE / 'seaweedfs.log.private', private=True, limit=262144)
        wait_for_object_reads('SEAWEEDFS_READBACK_REFERENCE_NOT_READY')
        result = get_object(ref.removeprefix('object://'), original['bytes'])
        need(result is not None, 'READBACK_RESERVED_OBJECT_OUTCOME_UNKNOWN')
        status, body = result
        report['reservedObjectHttpStatus'] = status
        if status == 200:
            match = len(body) == original['bytes'] and h['digest'](body) == original['sha256']
            report['seaweedfsReservedObjectState'] = 'PRESENT_MATCH' if match else 'PRESENT_MISMATCH'
        elif status == 404:
            code = ET.fromstring(body).findtext('{*}Code')
            need(code == 'NoSuchKey', 'READBACK_UNEXPECTED_S3_404')
            report['seaweedfsReservedObjectState'] = 'ABSENT'
        else:
            raise ValueError('READBACK_RESERVED_OBJECT_HTTP_' + str(status))

    def keep_logs():
        for role, cid, _, _ in containers:
            try:
                p = call('logs', '--tail', '100', cid, timeout=7)
                if p.returncode == 0 and (p.stderr or p.stdout):
                    h['new'](scope / (role + '.log.private'), (p.stderr + p.stdout)[-262144:])
                    report['privateContainerLogsRetained'] += 1
                    lower = (p.stderr + p.stdout).lower()
                    hints = {'migration': b'flyway', 'databaseRole': b'password authentication failed',
                             'permission': b'permission denied', 'tls': b'pkix path building failed',
                             'bind': b'address already in use', 'readiness': b'connection refused'}
                    report['diagnosticHints'][role] = [key for key, value in hints.items() if value in lower]
            except (OSError, ValueError, subprocess.SubprocessError):
                pass

    try:
        need(not docker('ps', '-q').strip(), 'OTHER_CONTAINERS_RUNNING')
        pg_ids = (PG_IMAGE, PG_CONFIG)
        pg_settings = ['-c', 'default_transaction_read_only=on'] if readback else []
        pg_listen = 'listen_addresses=' if readback else 'listen_addresses=127.0.0.1'
        pg_id, pid = start('postgres', 'none', pg_ids,
            '--user', f'{uid}:{gid}', '--mount', f'type=bind,src={cluster},dst=/isolated-pg',
            '--mount', f'type=bind,src={pg_files},dst=/config,readonly',
            '--entrypoint', 'postgres', PG_IMAGE, '-D', '/isolated-pg', '-c', 'config_file=/dev/null',
            '-c', 'hba_file=/config/pg_hba.conf', '-c', 'ident_file=/dev/null', '-c', pg_listen,
            '-c', 'unix_socket_directories=/tmp', '-c', 'port=5432', '-c', 'ssl=off',
            '-c', 'archive_mode=off', '-c', 'autovacuum=off', *pg_settings)
        end = time.monotonic() + 50
        while True:
            row = psql(database, 'SELECT 1;')
            if row.returncode == 0 and row.stdout.strip() == b'1':
                break
            need(time.monotonic() < end and inspect(pg_id, 'none', pg_ids)['Running'], 'POSTGRES_SQL_READINESS')
            time.sleep(2)
        if not readback:
            role_guard = psql(database, f"SELECT count(*) FROM pg_roles WHERE rolname='{user}' AND rolcanlogin AND NOT rolsuper;")
            need(role_guard.returncode == 0 and role_guard.stdout.strip() == b'1', 'ONBOARDING_DATABASE_ROLE_REQUIRED')
            guard = psql(database, "SELECT count(*) FROM ouf_onboarding.protected_log_export_job "
                                    "WHERE state IN ('READY','RETRY_WAIT','RUNNING');")
            need(guard.returncode == 0 and guard.stdout.strip() == b'0', 'ISOLATED_ONBOARDING_LOG_QUEUE_NOT_EMPTY')
            changed = psql(database, f"SET password_encryption='scram-sha-256'; ALTER ROLE \"{user}\" PASSWORD '{password}';")
            need(changed.returncode == 0, 'ISOLATED_ONBOARDING_DATABASE_CREDENTIAL')
        report['postgresReady'] = True

        net = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY)
        need(inspect(pg_id, 'none', pg_ids)['Pid'] == pid, 'STACK_NAMESPACE_CHANGED')
        network = 'container:' + pg_id
        sea_id, _ = start('seaweedfs', network, (S3_IMAGE, S3_CONFIG),
            '--user', '10001:10001', '--workdir', '/config',
            '--mount', f'type=bind,src={storage},dst=/data',
            '--mount', f'type=bind,src={storage_config},dst=/config,readonly',
            S3_IMAGE, '-logtostderr=true', 'server', '-ip=127.0.0.1', '-ip.bind=127.0.0.1',
            '-dir=/data', '-master.port=19332', '-master.volumeSizeLimitMB=32', '-volume.port=18082',
            '-volume.max=128', '-filer', '-filer.port=18882', '-s3', '-s3.port=9002',
            '-s3.port.https=0', '-s3.port.iceberg=0', '-s3.port.lance=0', '-s3.config=/config/s3.json',
            '-s3.key.file=/config/tls/server.key', '-s3.cert.file=/config/tls/server.pem')
        ready('s3', sea_id, network, (S3_IMAGE, S3_CONFIG), 50)
        report['seaweedfsTlsReady'] = True

        if readback:
            read_outcome()
        else:
            app_id, _ = start('onboarding', network, (ONB_IMAGE, ONB_CONFIG),
                '--user', '10003:10003', '--env-file', str(app_env),
                '--mount', f'type=bind,src={files},dst=/run/stage-s3,readonly',
                '--entrypoint', '/bin/sh', ONB_IMAGE, '-ec',
                'keytool -importcert -noprompt -alias ouf-stage -file /run/stage-s3/ca.pem '
                '-keystore /tmp/ouf-stage.p12 -storetype PKCS12 -storepass changeit; '
                'exec java -Xmx512m -Djavax.net.ssl.trustStore=/tmp/ouf-stage.p12 '
                '-Djavax.net.ssl.trustStorePassword=changeit -jar /app/application.jar')
            ready('onboarding', app_id, network, (ONB_IMAGE, ONB_CONFIG), 110)
            report['onboardingReadinessUp'] = True
            rows = psql(database, "SELECT version FROM ouf_onboarding.flyway_schema_history "
                                  "WHERE success AND version IN ('39','40','41') ORDER BY version;")
            need(rows.returncode == 0 and rows.stdout.splitlines() == [b'39', b'40', b'41'], 'ONBOARDING_MIGRATIONS_REQUIRED')
            report['flywayVersionsVerified'] = [39, 40, 41]
            if upload:
                prove_upload()
    except Exception:
        keep_logs()
        raise
    finally:
        if net is not None:
            os.close(net)
        for role, cid, network, images in reversed(containers):
            try:
                if inspect(cid, network, images)['Running']:
                    docker('stop', '--time=15', cid, timeout=23)
                docker('rm', cid)
                report['containersRemoved'] += 1
            except Exception:
                report['cleanupIncomplete'] = True

    need(not report['cleanupIncomplete'] and not docker('ps', '-q').strip(), 'ISOLATED_STACK_CLEANUP')
    if readback:
        report['status'] = 'ONBOARDING_UPLOAD_OUTCOME_READ_BACK'
    else:
        report['status'] = 'ISOLATED_ONBOARDING_UPLOAD_VERIFIED' if upload else 'ISOLATED_ONBOARDING_STACK_READY'
    h['new'](scope / 'result.json', h['canonical'](report))


def main(upload=False, readback=False):
    os.umask(0o077)
    need(not (upload and readback), 'EXCLUSIVE_STACK_MODE_REQUIRED')
    schema = READBACK_SCHEMA if readback else UPLOAD_SCHEMA if upload else SCHEMA
    report = {'schema': schema, 'status': 'HELD',
              'applicationContainersStarted': 0, 'containersStarted': 0,
              'containersRemoved': 0, 'cleanupIncomplete': False, 'privateContainerLogsRetained': 0,
              'diagnosticHints': {}, 'postgresCopyPrepared': False, 'storageCopyPrepared': False,
              'postgresReady': False, 'seaweedfsTlsReady': False, 'onboardingReadinessUp': False,
              'flywayVersionsVerified': [], 'acceptanceCreditAdded': 0}
    if upload:
        report.update({'uploadRequests': 0, 's3GetRequests': 0, 'onboardingAssetCreated': False,
                       'seaweedfsPreUploadBodyVerified': False, 'postgresUploadAckVerified': False,
                       'seaweedfsUploadBodyVerified': False})
    if readback:
        report.update({'uploadRequests': 0, 's3GetRequests': 0, 'retainedLogHints': {},
                       'databaseIntentState': 'UNREAD', 'seaweedfsReservedObjectState': 'UNREAD'})
    try:
        run(report, upload, readback)
    except Exception as exc:
        report['status'] = 'HELD'
        reason = str(exc)
        report['reason'] = reason if re.fullmatch(r'[A-Z][A-Z0-9_]{5,80}', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())
