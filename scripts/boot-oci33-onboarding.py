#!/usr/bin/env python3
"""Boot the exact Onboarding image against isolated copies of PostgreSQL and OCI33."""
import hashlib
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
from urllib.parse import urlsplit
from urllib.request import urlopen

SCHEMA = 'ouf.storage-oci33-onboarding-boot.v1'
ROOT = Path('/var/lib/ouf-storage-migration')
STAGE = ROOT / 'seaweedfs/staging-oci33-20261107-v1'
BINDINGS = STAGE / 'application-s3-v1'
SCOPE = STAGE / 'onboarding-stack-v1'
PG_IMAGE = 'sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'
PG_CONFIG = 'sha256:823c9d80930ce5f5fb4ed0f54a091abb79cfde1e34189aaeb69aeaf2720400a2'
S3_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
ONB_IMAGE = 'sha256:2dd55525d4a6969cf59f4d5e811c5f502976211c0cb49f9ba081dab5e4806c15'
ONB_TESTED = '69b099b04f1823b127ef4af4a9c44861ff4cdc67'
ONB_CONFIG = 'sha256:0a29a90a48a69a6ed757748bdac97cf029b6e7d633b6bc9a9b1d706fa00837db'
S3_CONFIG = 'sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
CLIENT = r"""
import http.client, json, socket, ssl, sys
if sys.argv[1] == 's3':
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


def postgres_helper():
    url = ('https://raw.githubusercontent.com/GioNob/ouf-deploy/'
           '5ae47689adeaf39f241527c9364a2c0c9e9b0b9b/scripts/restore-retained-postgres.py')
    with urlopen(url, timeout=25) as response:
        raw = response.read(19047)
    need(len(raw) == 19046 and hashlib.sha256(raw).hexdigest() ==
         '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d', 'POSTGRES_HELPER_DIGEST')
    pg = {'__name__': 'isolated_postgres_helper'}
    exec(compile(raw, 'restore-retained-postgres.py', 'exec'), pg)
    return pg


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


def run(report):
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
    pg = postgres_helper()
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
    image_id(PG_IMAGE)
    sea = image_id(S3_IMAGE)
    onb = image_id(ONB_IMAGE)
    need(sea['Config']['User'] == '10001:10001' and onb['Config']['User'] == '10003:10003'
         and onb['Config']['Labels']['org.opencontainers.image.revision'] == ONB_TESTED, 'STACK_IMAGE_BINDING')

    parent = h['runtime_parent'](SCOPE)
    try:
        os.mkdir(SCOPE.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    token = secrets.token_hex(12)
    h['new'](SCOPE / 'claim.private.json', h['canonical']({'schema': SCHEMA, 'scopeToken': token,
        'onboardingImage': ONB_IMAGE, 'postgresImage': PG_IMAGE, 'storageImage': S3_IMAGE,
        'custodyManifestSha256': pg['MANIFEST_SHA']}))
    pg['NEW'] = SCOPE / 'postgres'
    pg['NEW'].mkdir(mode=0o700)
    image, cluster, uid, gid, _ = pg['extract_cluster'](h, plan, members, time.monotonic() + 190)
    need(image == PG_IMAGE and not os.path.lexists(cluster / 'postmaster.pid'), 'ISOLATED_POSTGRES_COPY_BINDING')
    data_source = STAGE / 'data'
    info = data_source.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 10001 and data_source.resolve(strict=True) == data_source,
         'STAGED_STORAGE_DATA_BINDING')
    storage = SCOPE / 'seaweed-data'
    c = subprocess.run(['/usr/bin/cp', '-a', '--reflink=auto', '--sparse=always', '--',
                        str(data_source), str(storage)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env=ENV, timeout=45)
    need(c.returncode == 0 and (storage / 'metadata').is_dir(), 'ISOLATED_STORAGE_COPY_FAILED')
    report['postgresCopyPrepared'] = report['storageCopyPrepared'] = True

    pg_files = SCOPE / 'pg-config'
    pg_files.mkdir(mode=0o700)
    h['new'](pg_files / 'pg_hba.conf',
             (f'local all {admin} trust\n'
              f'host {database} {user} 127.0.0.1/32 scram-sha-256\n').encode())
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
    files = SCOPE / 'onboarding-secrets'
    files.mkdir(mode=0o700)
    for name in ('access-key', 'secret-key'):
        h['new'](files / name, h['protected'](private_client / name, private=True, limit=4096))
    h['new'](files / 'ca.pem', (storage_config / 'tls/ca.pem').read_bytes())
    for p in (*files.iterdir(), files):
        os.chown(p, 10003, 10003)
    password = secrets.token_hex(24)
    app_env = SCOPE / 'onboarding.env.private'
    variables = {'OUF_ONB_DB_URL': f'jdbc:postgresql://127.0.0.1:5432/{database}',
                 'OUF_ONB_DB_USER': user, 'OUF_ONB_DB_PASSWORD': password,
                 'OUF_ONBOARDING_STAGING_ENDPOINT': 'https://localhost:9002',
                 'OUF_ONBOARDING_STAGING_BUCKET': bucket,
                 'OUF_ONBOARDING_STAGING_ACCESS_KEY_FILE': '/run/stage-s3/access-key',
                 'OUF_ONBOARDING_STAGING_SECRET_KEY_FILE': '/run/stage-s3/secret-key',
                 'OUF_IAM_ENABLED': 'false', 'SERVER_ADDRESS': '127.0.0.1'}
    h['new'](app_env, ''.join(f'{key}={value}\n' for key, value in variables.items()).encode())

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
                                '-I', '-B', '-S', '-c', CLIENT, mode, str(files / 'ca.pem')],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(net,), env=ENV, timeout=7)
            if p.returncode == 0 and p.stdout.strip() in (b'UP', b'TLS_OK'):
                return
            need(p.returncode in (0, 70) and inspect(cid, network, images)['Running'],
                 mode.upper() + '_READINESS_FAILED')
            time.sleep(2)
        raise ValueError(mode.upper() + '_READINESS_TIMEOUT')

    def keep_logs():
        for role, cid, _, _ in containers:
            try:
                p = call('logs', '--tail', '100', cid, timeout=7)
                if p.returncode == 0 and (p.stderr or p.stdout):
                    h['new'](SCOPE / (role + '.log.private'), (p.stderr + p.stdout)[-262144:])
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
        pg_id, pid = start('postgres', 'none', pg_ids,
            '--user', f'{uid}:{gid}', '--mount', f'type=bind,src={cluster},dst=/isolated-pg',
            '--mount', f'type=bind,src={pg_files},dst=/config,readonly',
            '--entrypoint', 'postgres', PG_IMAGE, '-D', '/isolated-pg', '-c', 'config_file=/dev/null',
            '-c', 'hba_file=/config/pg_hba.conf', '-c', 'ident_file=/dev/null', '-c', 'listen_addresses=127.0.0.1',
            '-c', 'unix_socket_directories=/tmp', '-c', 'port=5432', '-c', 'ssl=off',
            '-c', 'archive_mode=off', '-c', 'autovacuum=off')
        end = time.monotonic() + 50
        while True:
            row = psql(database, 'SELECT 1;')
            if row.returncode == 0 and row.stdout.strip() == b'1':
                break
            need(time.monotonic() < end and inspect(pg_id, 'none', pg_ids)['Running'], 'POSTGRES_SQL_READINESS')
            time.sleep(2)
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
    report['status'] = 'ISOLATED_ONBOARDING_STACK_READY'
    h['new'](SCOPE / 'result.json', h['canonical'](report))


def main():
    os.umask(0o077)
    report = {'schema': SCHEMA, 'status': 'HELD', 'applicationContainersStarted': 0, 'containersStarted': 0,
              'containersRemoved': 0, 'cleanupIncomplete': False, 'privateContainerLogsRetained': 0,
              'diagnosticHints': {}, 'postgresCopyPrepared': False, 'storageCopyPrepared': False,
              'postgresReady': False, 'seaweedfsTlsReady': False, 'onboardingReadinessUp': False,
              'flywayVersionsVerified': [], 'acceptanceCreditAdded': 0}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'HELD'
        reason = str(exc)
        report['reason'] = reason if re.fullmatch(r'[A-Z][A-Z0-9_]{5,80}', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'ISOLATED_ONBOARDING_STACK_READY')


if __name__ == '__main__':
    raise SystemExit(main())
