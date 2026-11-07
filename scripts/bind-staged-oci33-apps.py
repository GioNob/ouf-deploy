#!/usr/bin/env python3
"""Prepare private S3 application bindings and verify them against staged OCI33."""

import base64
import configparser
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
from xml.etree import ElementTree as ET

SCHEMA = 'ouf.storage-oci33-app-bindings.v1'
BASE_INPUT = Path('/var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.review.json')
BASE_SHA = 'dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e'
RUNTIME_SHA = 'c958f52f6fc25c07a42a0a2b48ddab2f185316895dc449df1a14defe6b22ba97'
DNS = 'ouf-seaweedfs-stage'
PORT = 9002
ROLES = ('onboarding', 'udp')
SECRETS_MOUNT = '/run/secrets/ouf-stage-s3'
CLIENT = r"""
import base64, http.client, json, ssl, sys
port, path, headers, ca, maximum = json.load(sys.stdin)
conn = http.client.HTTPSConnection('localhost', port, timeout=8,
                                   context=ssl.create_default_context(cafile=ca))
try:
    conn.request('GET', path, headers=headers)
    response = conn.getresponse()
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise SystemExit(75)
    print(json.dumps([response.status, base64.b64encode(body).decode()]))
except ConnectionRefusedError:
    raise SystemExit(70)
except TimeoutError:
    raise SystemExit(71)
except ssl.SSLError:
    raise SystemExit(72)
finally:
    conn.close()
"""


def identities(h, bundle, buckets, reuse=False):
    endpoint = f'https://{DNS}:{PORT}'
    clients = bundle / 'clients'
    if not reuse:
        clients.mkdir(mode=0o700)
    auth, entries, policies = {}, [], []
    for role in ROLES:
        bucket = buckets[role]
        arn = 'arn:aws:s3:::' + bucket
        root = clients / role

        def private(name):
            return h['protected'](root / name, private=True, limit=4096)

        if not reuse:
            root.mkdir(mode=0o700)
            key, secret = ('ouf' + role + secrets.token_hex(8), secrets.token_hex(24))
        elif role == 'onboarding':
            key, secret = (private(name).decode('ascii').removesuffix('\n')
                           for name in ('access-key', 'secret-key'))
        else:
            credentials = configparser.ConfigParser(interpolation=None)
            credentials.read_string(private('credentials').decode('ascii'))
            key = credentials['default']['aws_access_key_id']
            secret = credentials['default']['aws_secret_access_key']
        if not (re.fullmatch('ouf' + role + '[a-f0-9]{16}', key) and re.fullmatch('[a-f0-9]{48}', secret)):
            raise ValueError('STAGING_CREDENTIAL_FORMAT')
        auth[role] = key, secret

        def bind(name, raw):
            if reuse:
                if private(name) != raw:
                    raise ValueError('STAGING_CLIENT_BINDING_CHANGED')
            else:
                h['new'](root / name, raw)

        policy_name = 'ouf-stage-' + role
        actions = ['s3:GetObject', 's3:PutObject']
        if role == 'onboarding':
            actions += ['s3:AbortMultipartUpload', 's3:ListMultipartUploadParts']
            resources = arn + '/managed-files/*'
            bucket_actions = ['s3:GetBucketLocation']
        else:
            actions.append('s3:DeleteObject')
            resources = arn + '/*'
            bucket_actions = ['s3:ListBucket', 's3:GetBucketLocation']
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': actions, 'Resource': [resources]},
            {'Effect': 'Allow', 'Action': bucket_actions, 'Resource': [arn]}]}
        entries.append({'name': policy_name, 'credentials': [{'accessKey': key, 'secretKey': secret}],
                        'policyNames': [policy_name]})
        policies.append({'name': policy_name, 'content': json.dumps(policy)})

        if role == 'onboarding':
            bind('access-key', (key + '\n').encode())
            bind('secret-key', (secret + '\n').encode())
            env = {'OUF_ONBOARDING_STAGING_ENDPOINT': endpoint, 'OUF_ONBOARDING_STAGING_BUCKET': bucket,
                   'OUF_ONBOARDING_STAGING_ACCESS_KEY_FILE': SECRETS_MOUNT + '/access-key',
                   'OUF_ONBOARDING_STAGING_SECRET_KEY_FILE': SECRETS_MOUNT + '/secret-key'}
        else:
            bind('credentials', (f'[default]\naws_access_key_id = {key}\n'
                                 f'aws_secret_access_key = {secret}\n').encode())
            env = {'OUF_UDP_S3_ENDPOINT': endpoint, 'OUF_UDP_S3_BUCKET': bucket,
                   'OUF_UDP_S3_REGION': 'us-east-1', 'OUF_UDP_S3_PATH_STYLE': 'true',
                   'AWS_SHARED_CREDENTIALS_FILE': SECRETS_MOUNT + '/credentials',
                   'AWS_PROFILE': 'default', 'AWS_EC2_METADATA_DISABLED': 'true'}
        bind('binding.private.json', h['canonical']({
            'environment': env, 'privateSecretMount': SECRETS_MOUNT, 'caFile': 'config/tls/ca.pem'}))
    return auth, {'identities': entries, 'policies': policies}


def tls(h, config, env, need):
    dest = config / 'tls'
    dest.mkdir(mode=0o700)

    def openssl(*args):
        p = subprocess.run(['/usr/bin/openssl', *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env=env, timeout=20)
        need(p.returncode == 0, 'STAGING_CERTIFICATE_GENERATION')

    with tempfile.TemporaryDirectory(dir=dest, prefix='signing-') as tmp:
        private = Path(tmp)
        ca_key, ca = private / 'ca.key', dest / 'ca.pem'
        csr, key, cert = private / 'server.csr', dest / 'server.key', dest / 'server.pem'
        ext = private / 'server.ext'
        h['new'](ext, (f'subjectAltName=DNS:{DNS},DNS:localhost\nbasicConstraints=critical,CA:FALSE\n'
                       'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n').encode())
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-sha256',
                '-subj', '/CN=OUF OCI33 staging CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(ca_key), '-out', str(ca))
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', f'/CN={DNS}',
                '-keyout', str(key), '-out', str(csr))
        openssl('x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key),
                '-set_serial', '0x' + secrets.token_hex(16), '-days', '30', '-sha256',
                '-extfile', str(ext), '-out', str(cert))
    return dest


def execute(stage, report, resume):
    need, load, env = stage['need'], stage['load'], stage['ENV']
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
    pg = load('5ae47689adeaf39f241527c9364a2c0c9e9b0b9b', 'restore-retained-postgres.py', 19046,
              '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d')
    r = load('09386c72b54e703dbab4bdd296a493ccdf1f0e05', 'rehearse-oci33-retained.py', 25800,
             'd22e0b380dacf0dce6f3c84de069d19c8eca4c39c759f6200ef9255019f2950d')
    h = pg['load_producer']()

    def read(path, pin=None):
        raw = h['protected'](path, private=True, limit=1 << 20)
        need(pin is None or h['digest'](raw) == pin, 'PRIVATE_INPUT_BINDING')
        return h['decode'](raw)

    scope = stage['SCOPE']
    receipt = read(scope / 'result.json')
    need(receipt.get('status') == 'ISOLATED_OCI33_STAGE_READY' and receipt.get('objectsListed') == 120
         and receipt.get('stagedDataVerified') is True and receipt.get('stagingContainerRemoved') is True,
         'STAGE_SUCCESS_RECEIPT_REQUIRED')
    base = read(BASE_INPUT, BASE_SHA)
    runtime = read(Path(base['operatorEvidenceFiles']['runtime']), RUNTIME_SHA)
    buckets = runtime['storageBuckets']
    need(runtime['installationRef'] == base['installationRef'] and runtime['section'] == 'RUNTIME'
         and set(buckets) == set(ROLES) and len(set(buckets.values())) == 2
         and all(re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', value) for value in buckets.values()),
         'APPLICATION_BUCKET_BINDING')
    manifest = stage['ROOT'] / 'historical-minio-restore-20261107-v1/s3-proof-v2/s3-bodies.private.json'
    objects = read(manifest, r['BODY_MANIFEST'])
    need(len(objects) == 120 and {item['bucket'] for item in objects} == set(buckets.values()),
         'STAGE_MANIFEST_BUCKET_MISMATCH')
    samples = {}
    for role in ROLES:
        choices = [row for row in objects if row['bucket'] == buckets[role]
                   and (role == 'udp' or row['key'].startswith('managed-files/'))]
        need(choices, 'ROLE_SAMPLE_REQUIRED')
        row = min(choices, key=lambda item: (item['size'], item['key']))
        need(0 <= row['size'] <= 16 << 20, 'ROLE_SAMPLE_BUDGET')
        samples[role] = row

    data = scope / 'data'
    need(stat.S_ISDIR(data.lstat().st_mode) and data.resolve(strict=True) == data
         and data.stat().st_uid == 10001, 'STAGED_DATA_BINDING')
    image = stage['DAEMON_IMAGE']
    sock = Path('/run/docker.sock').stat()
    need(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o007,
         'LOCAL_DOCKER_SOCKET_REQUIRED')
    docker_base = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent']

    def docker(*args, timeout=15):
        need(h['frame'](Path('/run/docker.sock').stat()) == h['frame'](sock), 'DOCKER_SOCKET_CHANGED')
        p = subprocess.run(docker_base + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, env=env, timeout=timeout)
        need(p.returncode == 0, 'DOCKER_' + args[0].upper() + '_FAILED')
        return p.stdout.decode().strip()

    need(not docker('ps', '-q'), 'OTHER_CONTAINERS_RUNNING')
    img, = json.loads(docker('image', 'inspect', image))
    need(img['Id'] == image and img['Config']['User'] == '10001:10001', 'LOCAL_IMAGE_BINDING')

    bundle = scope / 'application-s3-v1'
    proof = bundle / 'access-proof-v2' if resume else bundle
    config = bundle / 'config'
    if resume:
        prior = read(bundle / 'claim.private.json')
        prior_name = prior['containerName']
        need(prior.get('schema') == SCHEMA and prior.get('manifestSha256') == r['BODY_MANIFEST']
             and prior.get('daemonImageId') == image and re.fullmatch('ouf-oci33-bind-[a-f0-9]{24}', prior_name)
             and not os.path.lexists(bundle / 'result.json'), 'HELD_STAGING_CLAIM_MISMATCH')
        need(not docker('ps', '-aq', '--filter', 'name=^/' + prior_name + '$'), 'PRIOR_BINDING_CONTAINER_PRESENT')
    parent = h['runtime_parent'](proof)
    try:
        os.mkdir(proof.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    token = secrets.token_hex(12)
    name = 'ouf-oci33-bind-' + token
    h['new'](proof / 'claim.private.json', h['canonical']({
        'schema': SCHEMA, 'containerName': name, 'manifestSha256': r['BODY_MANIFEST'],
        'daemonImageId': image}))
    filer_config = b'[leveldb2]\nenabled = true\ndir = "/data/metadata"\n'
    if resume:
        auth, iam = identities(h, bundle, buckets, reuse=True)
        certs = config / 'tls'
        for path in (config, certs):
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 10001
                 and stat.S_IMODE(info.st_mode) == 0o700, 'STAGING_SERVER_CONFIG_DIRECTORY')
        for path in (config / 'filer.toml', config / 's3.json', *(certs / name for name in ('ca.pem', 'server.key', 'server.pem'))):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                need(stat.S_ISREG(info.st_mode) and info.st_uid == 10001 and info.st_nlink == 1
                     and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 32768,
                     'STAGING_SERVER_CONFIG_FILE')
                raw = stream.read(32769)
                need(h['frame'](path.lstat()) == h['frame'](os.fstat(stream.fileno())) == h['frame'](info),
                     'STAGING_SERVER_CONFIG_CHANGED')
            if path.name == 'filer.toml':
                need(raw == filer_config, 'STAGING_FILER_CONFIG_CHANGED')
            if path.name == 's3.json':
                need(raw == h['canonical'](iam), 'STAGING_IAM_CONFIG_CHANGED')
        report['existingBindingsReused'] = True
    else:
        config.mkdir(mode=0o700)
        auth, iam = identities(h, bundle, buckets)
        certs = tls(h, config, env, need)
        h['new'](config / 'filer.toml', filer_config)
        h['new'](config / 's3.json', h['canonical'](iam))
        for path in (*config.rglob('*'), config):
            os.chown(path, 10001, 10001)
    report['privateBindingsPrepared'] = 2

    need(not docker('ps', '-q'), 'STAGING_RUNTIME_PRECONDITION')
    cid = docker('create', '--name', name, '--label', 'ouf.oci33-bind=' + token, '--network=none',
                 '--pull=never', '--restart=no', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                 '--memory=1g', '--cpus=2', '--pids-limit=256', '--user', '10001:10001', '--workdir', '/config',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
                 '--mount', f'type=bind,src={data},dst=/data',
                 '--mount', f'type=bind,src={config},dst=/config,readonly',
                 image, '-logtostderr=true', 'server', '-ip=127.0.0.1', '-ip.bind=127.0.0.1',
                 '-dir=/data', '-master.port=19332', '-master.volumeSizeLimitMB=32', '-volume.port=18082',
                 '-volume.max=128', '-filer', '-filer.port=18882', '-s3', f'-s3.port={PORT}',
                 '-s3.port.https=0', '-s3.port.iceberg=0', '-s3.port.lance=0', '-s3.config=/config/s3.json',
                 '-s3.key.file=/config/tls/server.key', '-s3.cert.file=/config/tls/server.pem')
    need(re.fullmatch('[a-f0-9]{64}', cid), 'BINDING_CONTAINER_ID')
    net = None

    def state():
        item, = json.loads(docker('container', 'inspect', cid))
        need(item['Id'] == cid and item['Image'] in (image, r['IMAGE'])
             and item['Config']['Labels']['ouf.oci33-bind'] == token
             and item['HostConfig']['NetworkMode'] == 'none'
             and not item['HostConfig']['PortBindings'] and not item['HostConfig']['PublishAllPorts'],
             'BINDING_CONTAINER_ISOLATION')
        return item['State']

    def get(role, row, expected=200):
        need(report['s3GetRequests'] < 18, 'STAGING_S3_GET_BUDGET')
        report['s3GetRequests'] += 1
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        path = '/' + row['bucket'] + '/' + quote(row['key'], safe='/')
        url, headers = r['signed']('GET', path, f'localhost:{PORT}', auth[role], b'', {}, stamp)
        params = [PORT, url, headers, str(certs / 'ca.pem'), max(row['size'], 16384)]
        p = subprocess.run(['/usr/bin/nsenter', f'--net=/proc/self/fd/{net}', '/usr/bin/python3',
                            '-I', '-B', '-S', '-c', CLIENT], input=json.dumps(params).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                           pass_fds=(net,), timeout=12)
        if p.returncode in (70, 71):
            return None
        need(p.returncode == 0, 'STAGED_TLS_CLIENT_' + str(p.returncode))
        status, body = json.loads(p.stdout)
        report['tlsVerified'] = True
        body = base64.b64decode(body, validate=True)
        if status >= 400 and status != expected:
            report['lastHttpErrorStatus'] = status
            try:
                code = ET.fromstring(body).findtext('{*}Code')
            except ET.ParseError:
                code = None
            known = {'InternalError', 'ServiceUnavailable', 'AccessDenied', 'NoSuchKey', 'NoSuchBucket',
                     'InvalidAccessKeyId', 'SignatureDoesNotMatch', 'SlowDown'}
            report['lastS3ErrorCode'] = code if code in known else 'UNCLASSIFIED'
        return status, body

    try:
        state()
        docker('start', cid)
        running = state()
        need(running['Running'] and running['Pid'] > 0, 'BINDING_CONTAINER_START')
        net = os.open(f"/proc/{running['Pid']}/ns/net", os.O_RDONLY)
        need(state()['Pid'] == running['Pid'], 'BINDING_NAMESPACE_CHANGED')
        until = time.monotonic() + 45
        for index, role in enumerate(ROLES):
            result = get(role, samples[role])
            while (index == 0 and (result is None or result[0] in (500, 502, 503, 504))
                   and time.monotonic() < until and report['s3GetRequests'] < 15):
                report['startupReadinessRetries'] += 1
                time.sleep(2)
                result = get(role, samples[role])
            need(result is not None, 'STAGING_TLS_READY_TIMEOUT')
            status, body = result
            need(status == 200 and h['digest'](body) == samples[role]['sha256'],
                 role.upper() + '_OWN_OBJECT_READ_' + str(status))
            report['ownBucketBodiesVerified'] += 1
            other = ROLES[1 - index]
            result = get(role, samples[other], expected=403)
            need(result is not None and result[0] == 403
                 and ET.fromstring(result[1]).findtext('{*}Code') == 'AccessDenied',
                 role.upper() + '_CROSS_BUCKET_DENIAL_REQUIRED')
            report['crossBucketAccessDenied'] += 1
    except Exception:
        # Keep the exact process diagnostics private even when the public receipt is redacted.
        try:
            logs = subprocess.run(docker_base + ['logs', '--tail', '80', cid], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=8)
            if logs.returncode == 0 and logs.stdout:
                retained = logs.stdout[-262144:]
                h['new'](proof / 'container-log.private', retained)
                report['privateContainerLogRetained'] = True
                patterns = {
                    'volumeLookup': rb'failed to (lookup|locate).*volume|no (volume )?location|volume.*not found',
                    'connectionRefused': rb'connection refused|failed to connect',
                    'filerError': rb'filer.*(unavailable|failed|error)|failed.*filer',
                    'objectReadError': rb'fail(ed)? to read|failed to fetch|no such file',
                    'permissionDenied': rb'permission denied|access denied',
                }
                report['privateLogHints'] = [label for label, pattern in patterns.items()
                                             if re.search(pattern, retained, re.IGNORECASE)]
        except (OSError, subprocess.SubprocessError):
            pass
        raise
    finally:
        if net is not None:
            os.close(net)
        if state()['Running']:
            docker('stop', '--time=15', cid, timeout=23)
        docker('rm', cid)
        report['temporaryContainerRemoved'] = True

    need(not docker('ps', '-q'), 'OTHER_CONTAINERS_RUNNING_AFTER_BINDING')
    report['status'] = 'ISOLATED_OCI33_APP_BINDINGS_READY'
    h['new'](proof / 'result.json', h['canonical'](report))


def main(stage, resume=False):
    os.umask(0o077)
    report = {'schema': SCHEMA, 'status': 'HELD', 'privateBindingsPrepared': 0,
              'ownBucketBodiesVerified': 0, 'crossBucketAccessDenied': 0, 's3GetRequests': 0,
              'tlsVerified': False, 'temporaryContainerRemoved': False, 'startupReadinessRetries': 0,
              'existingBindingsReused': False, 'privateContainerLogRetained': False,
              'applicationContainersStarted': 0, 'acceptanceCreditAdded': 0}
    try:
        execute(stage, report, resume)
    except Exception as exc:
        report['status'] = 'HELD'
        reason = str(exc)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]{5,70}', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'ISOLATED_OCI33_APP_BINDINGS_READY')
