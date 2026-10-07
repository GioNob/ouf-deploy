#!/usr/bin/env python3
"""Private, read-only Semantic schema dump; never restores or changes the live DB."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

SEMANTIC_IMAGE = 'sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6'
POSTGRES_IMAGE = 'sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'


def call(argv, data=None, output=None, timeout=30):
    p = subprocess.run(argv, input=data, stdout=output or subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode:
        raise RuntimeError('COMMAND_FAILED_NO_RAW_OUTPUT')
    return p.stdout


def inspect(name):
    values = json.loads(call(['docker', 'inspect', '--type', 'container', name]))
    if len(values) != 1 or values[0]['Name'] != '/' + name:
        raise RuntimeError('CONTAINER_BINDING_MISMATCH')
    return values[0]


def binding(semantic, postgres):
    if semantic['Image'] != SEMANTIC_IMAGE or postgres['Image'] != POSTGRES_IMAGE:
        raise RuntimeError('LIVE_IMAGE_CHANGED')
    if not all(c['State']['Running'] for c in (semantic, postgres)):
        raise RuntimeError('LIVE_SERVICE_NOT_RUNNING')
    mounts = {m['Destination']: m for m in semantic['Mounts']}
    if set(mounts) != {'/run/ouf-semantic-auth', '/run/secrets/semantic-read-owner.key'} or any(m['RW'] for m in mounts.values()):
        raise RuntimeError('SEMANTIC_MOUNTS_CHANGED')
    env = dict(x.split('=', 1) for x in semantic['Config'].get('Env', []) if '=' in x)
    url = env.get('OUF_SEM_DB_URL', '')
    if not url.startswith('jdbc:postgresql://'):
        raise RuntimeError('EXPLICIT_DATABASE_BINDING_REQUIRED')
    parsed = urlsplit(url[5:])
    database = parsed.path.removeprefix('/')
    user, password = env.get('OUF_SEM_DB_USER', ''), env.get('OUF_SEM_DB_PASSWORD', '')
    if parsed.username or parsed.password or parsed.fragment or (parsed.port or 5432) != 5432:
        raise RuntimeError('UNSUPPORTED_DATABASE_BINDING')
    if not all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', x) for x in (database, user)):
        raise RuntimeError('UNSUPPORTED_DATABASE_IDENTIFIER')
    if not password or '\n' in password or '\r' in password or '\x00' in password:
        raise RuntimeError('EXPLICIT_DATABASE_CREDENTIAL_REQUIRED')
    matching = False
    for network, s in semantic['NetworkSettings']['Networks'].items():
        p = postgres['NetworkSettings']['Networks'].get(network)
        if p and s['NetworkID'] == p['NetworkID'] and parsed.hostname in set(p.get('Aliases') or []) | {p.get('IPAddress'), 'ouf-postgres'}:
            matching = True
    if not matching:
        raise RuntimeError('DATABASE_HOST_NOT_BOUND_TO_POSTGRES')
    return database, user, password.encode() + b'\n'


def pg(container_id, program, args, credential, output=None, timeout=30):
    # Credential travels through stdin only, never argv or a host environment.
    script = 'IFS= read -r PGPASSWORD || exit 1; export PGPASSWORD; export PGOPTIONS="-c default_transaction_read_only=on"; exec "$@"'
    return call(['docker', 'exec', '-i', container_id, 'sh', '-c', script, 'ouf-backup', program, *args],
                credential, output, timeout)


def main():
    os.umask(0o077)
    report = {'schema': 'ouf.discovery.semantic-target-backup.v1', 'releaseApplied': False,
              'databaseWrites': 0, 'containerLifecycleOperations': 0, 'secretValuesPrinted': False,
              'dumpUploaded': False, 'liveRestorePerformed': False, 'targetRestoreProven': False}
    try:
        semantic, postgres = inspect('ouf-semantic'), inspect('ouf-postgres')
        database, user, credential = binding(semantic, postgres)
        base = ['--host=127.0.0.1', '--port=5432', '--username=' + user, '--dbname=' + database]
        versions = pg(postgres['Id'], 'psql', [*base, '-X', '-A', '-t', '--set=ON_ERROR_STOP=1', '-c',
                       'SELECT version FROM ouf_sem.flyway_schema_history WHERE success ORDER BY installed_rank'], credential)
        if versions.decode().split() != [str(i) for i in range(1, 10)]:
            raise RuntimeError('EXPECTED_V1_V9_SCHEMA_REQUIRED')
        home = Path.home()
        if shutil.disk_usage(home).free < 1_073_741_824:
            raise RuntimeError('BACKUP_FREE_SPACE_REQUIRED')
        directory = Path(tempfile.mkdtemp(prefix='ouf-semantic-backup-', dir=home))
        archive = directory / 'semantic.dump.partial'
        with archive.open('xb') as stream:
            pg(postgres['Id'], 'pg_dump', [*base, '--schema=ouf_sem', '--format=custom',
               '--no-owner', '--no-acl', '--lock-wait-timeout=5s'], credential, stream, 300)
            stream.flush()
            os.fsync(stream.fileno())
        if archive.stat().st_size < 100:
            raise RuntimeError('EMPTY_DUMP')
        # Parse every archive payload into /dev/null; no database connection/restore.
        with archive.open('rb') as stream:
            p = subprocess.run(['docker', 'exec', '-i', postgres['Id'], 'pg_restore', '--file=/dev/null'],
                               stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
        if p.returncode:
            raise RuntimeError('ARCHIVE_PAYLOAD_VALIDATION_FAILED')
        after_s, after_p = inspect('ouf-semantic'), inspect('ouf-postgres')
        if semantic != after_s or postgres != after_p:
            # Full inspect contains changing health/counter fields: compare only installed identity/config/state binding.
            for before, after in ((semantic, after_s), (postgres, after_p)):
                for key in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings'):
                    if before[key] != after[key]:
                        raise RuntimeError('LIVE_BINDING_CHANGED_DURING_BACKUP')
                if before['State']['StartedAt'] != after['State']['StartedAt'] or not after['State']['Running']:
                    raise RuntimeError('SERVICE_CHANGED_DURING_BACKUP')
        h = hashlib.sha256()
        with archive.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1_048_576), b''):
                h.update(chunk)
        completed = directory / 'semantic.dump'
        os.rename(archive, completed)
        report.update(status='PRIVATE_BACKUP_VALIDATED', backupDirectory=str(directory), archiveSha256=h.hexdigest(),
                      archiveBytes=completed.stat().st_size, archiveMode=oct(completed.stat().st_mode & 0o777),
                      schemaOnly='ouf_sem', migrationsVerified=list(range(1, 10)), archivePayloadParsed=True,
                      semanticImage=SEMANTIC_IMAGE, postgresImage=POSTGRES_IMAGE)
        receipt = directory / 'backup-receipt.json'
        with receipt.open('x') as stream:
            stream.write(json.dumps(report, sort_keys=True) + '\n'); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception as exc:
        report.update(status='BLOCKED', reason=str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__,
                      partialEvidenceRetained=True)
    print('OUF_SEMANTIC_TARGET_BACKUP=' + json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PRIVATE_BACKUP_VALIDATED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
