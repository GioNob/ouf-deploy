#!/usr/bin/env python3
"""Probe the retained PostgreSQL cluster on a separate, networkless copy."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time


ROOT = Path('/var/lib/ouf-storage-migration')
OLD = ROOT / 'capture-after-held-stop-20261107-v1'
SEALED = ROOT / 'capture-historical-custody-20261107-v1'
NEW = ROOT / 'historical-postgres-restore-20261107-v1'
PAYLOAD = OLD / 'capture/payload'
PRODUCER = Path('/var/lib/ouf-storage-cold-backup-v3.py')
DOCKER = '/usr/bin/docker'
SCHEMA = 'ouf.storage-retained-postgres-restore.v1'
DECISION = 'GIOVANNI-NONPROD-ISOLATED-POSTGRES-RESTORE-20261107-01'
MANIFEST_SHA = '58484aea53aefeb1fff390578ba6562efabffd914caf64944eee7c9d9a2e0d79'
ARCHIVE_SHA = 'c3b0de7ab9fceb9c566431a4ed5ebf8f7720dae5eee52c1a0a5c76a5eb99a886'
SECONDS = 900


class Held(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Held(reason)


def load_producer():
    for parent in PRODUCER.parents:
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PRODUCER_ANCESTRY')
    fd = os.open(PRODUCER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
             and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 32524, 'PRODUCER_METADATA')
        raw = stream.read(32525)
    need(hashlib.sha256(raw).hexdigest() == 'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac',
         'PRODUCER_DIGEST')
    h = {'__name__': 'restore_producer_definitions', '__file__': str(PRODUCER)}
    exec(compile(raw, str(PRODUCER), 'exec'), h)
    return h


def private_hash(h, path, until):
    parent = h['runtime_parent'](path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
                 and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 8 << 30, 'PAYLOAD_METADATA')
            sha = hashlib.sha256()
            while block := stream.read(1 << 20):
                need(time.monotonic() < until, 'PAYLOAD_HASH_TIMEOUT')
                sha.update(block)
            need(h['frame'](s) == h['frame'](os.fstat(fd)) ==
                 h['frame'](os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'PAYLOAD_CHANGED')
            return {'bytes': s.st_size, 'sha256': sha.hexdigest()}
    finally:
        os.close(parent)


def bind_payload(h, until):
    proof = h['decode'](h['protected'](SEALED / 'result.json', private=True, limit=8192))
    need(proof.get('status') == 'HISTORICAL_CUSTODY_ARCHIVE_SEALED'
         and proof.get('archiveBytes') == 6544578724 and proof.get('archiveSha256') == ARCHIVE_SHA
         and proof.get('privateManifestSha256') == MANIFEST_SHA, 'SEALED_RECEIPT_MISMATCH')
    plan_raw = h['protected'](PAYLOAD / 'plan.private.json', private=True)
    plan = h['decode'](plan_raw)
    roles = sorted(plan['roles'])
    need(roles == sorted(h['ROLES'] | {'etcd'}) and len(plan['sources']) == 34, 'RETAINED_ROSTER_MISMATCH')
    names = {*(f'source-{i:03d}.tar' for i in range(34)), *(role + '.rootfs.tar' for role in roles),
             'images.tar', 'plan.private.json', 'containers.private.json',
             'networks.private.json', 'source-manifests.private.json'}
    members = {name: private_hash(h, PAYLOAD / name, until) for name in sorted(names)}
    need(h['digest'](plan_raw) == members['plan.private.json']['sha256'], 'RETAINED_PLAN_CHANGED')
    evidence = {'custody-claim.private.json': SEALED / 'claim.private.json',
                'original-claim.private.json': OLD / 'claim.private.json',
                'original-producer-claim.private.json': OLD / 'capture/capture-claim.private.json'}
    manifest = h['canonical']({'schema': 'ouf.storage-retained-capture-custody.v1', 'members': members,
        'evidenceSha256': {name: h['digest'](h['protected'](path, private=True, limit=8192))
                           for name, path in evidence.items()},
        'captureEventCoverageProven': False, 'liveSourceContinuityProven': False,
        'historicalCustodyOnly': True, 'restorePerformed': False})
    need(h['digest'](manifest) == MANIFEST_SHA, 'WINDOWS_VERIFIED_MANIFEST_MISMATCH')
    return plan, members


def source_binding(h, plan, members):
    row = plan['roles']['postgres']
    source_id, image = row['containerId'], row['nativeImage']
    need(re.fullmatch(r'[a-f0-9]{64}', source_id) and re.fullmatch(r'sha256:[a-f0-9]{64}', image),
         'POSTGRES_IMAGE_BINDING')
    raw = h['protected'](PAYLOAD / 'containers.private.json', private=True)
    need(h['digest'](raw) == members['containers.private.json']['sha256'], 'RETAINED_CONTAINER_CONFIG_CHANGED')
    config = h['decode'](raw)[source_id]
    need(config['Id'] == source_id and config['Image'] == image, 'POSTGRES_CONTAINER_BINDING')
    paths = [s[7:] for s in config['Config']['Env'] if s.startswith('PGDATA=')]
    need(len(paths) == 1, 'POSTGRES_PGDATA_REQUIRED')
    pgdata = PurePosixPath(paths[0])
    need(pgdata.is_absolute() and '..' not in pgdata.parts, 'POSTGRES_PGDATA_INVALID')
    mounts = [(PurePosixPath(m['Destination']), m) for m in config['Mounts']]
    covering = [(target, m) for target, m in mounts if pgdata.is_relative_to(target)]
    need(covering and not any(target != pgdata and target.is_relative_to(pgdata) for target, _ in mounts),
         'POSTGRES_NESTED_MOUNT_REQUIRES_REVIEW')
    target, mount = max(covering, key=lambda pair: len(pair[0].parts))
    need(mount['Type'] in ('bind', 'volume'), 'POSTGRES_SOURCE_MOUNT_REQUIRED')
    data_source = PurePosixPath(mount['Source']) / pgdata.relative_to(target)
    found = [(i, PurePosixPath(src)) for i, src in enumerate(plan['sources'])
             if data_source.is_relative_to(PurePosixPath(src))]
    need(len(found) == 1, 'POSTGRES_SOURCE_ARCHIVE_REQUIRED')
    i, source = found[0]
    return image, i, source, data_source.relative_to(source)


def extract_cluster(h, plan, members, until):
    image, i, source, suffix = source_binding(h, plan, members)
    member = f'source-{i:03d}.tar'
    tar = PAYLOAD / member
    need(private_hash(h, tar, until) == members[member], 'POSTGRES_SOURCE_TAR_CHANGED')
    raw = h['protected'](PAYLOAD / 'source-manifests.private.json', private=True)
    need(h['digest'](raw) == members['source-manifests.private.json']['sha256'], 'SOURCE_MANIFEST_CHANGED')
    rows = h['decode'](raw)[str(source)]
    need(0 < len(rows) <= 100000 and sum(r['size'] for r in rows) <= 1 << 30, 'POSTGRES_RESTORE_SIZE_LIMIT')
    h['verify_source_archive'](tar, source.name, rows, until)
    with tarfile.open(tar, 'r:') as archive:
        for entry in archive:
            need(not entry.issym() and (entry.isdir() or entry.isfile() or entry.islnk()),
                 'POSTGRES_SOURCE_LINK_REQUIRES_REVIEW')
            if entry.islnk():
                link = PurePosixPath(entry.linkname)
                need(not link.is_absolute() and '..' not in link.parts and link.parts
                     and link.parts[0] == source.name, 'POSTGRES_HARDLINK_REQUIRES_REVIEW')
    data = NEW / 'data'
    data.mkdir(mode=0o700)
    with (NEW / 'extract.stderr.private').open('xb') as log:
        result = subprocess.run(['/usr/bin/tar', '--extract', '--numeric-owner', '--same-owner',
            '--same-permissions', '--acls', '--xattrs', '--xattrs-include=*', '-f', str(tar), '-C', str(data)],
            stdout=subprocess.DEVNULL, stderr=log, timeout=min(120, until - time.monotonic()))
    need(result.returncode == 0 and private_hash(h, tar, until) == members[member], 'POSTGRES_EXTRACT_FAILED')
    cluster = data / source.name / str(suffix)
    s = cluster.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid > 0 and (cluster / 'PG_VERSION').is_file(),
         'RESTORED_POSTGRES_CLUSTER_REQUIRED')
    return image, cluster, s.st_uid, s.st_gid, member


def docker_probe(until, token, image, cluster, uid, gid, ordinal, entrypoint, args, sql=None):
    name = f'ouf-pg-historical-{token}-{ordinal}'
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    cmd = [DOCKER, '--host', 'unix:///run/docker.sock', '--config', str(NEW / 'docker-client')]
    argv = cmd + ['run', '--rm', '-i', '--name', name, '--pull=never', '--network=none',
        '--label', 'ouf.restore-run=' + token, '--log-driver=none',
        '--restart=no', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--memory=1g', '--cpus=1', '--pids-limit=64', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
        '--user', f'{uid}:{gid}', '-e', 'LC_ALL=C', '--mount',
        'type=bind,src=' + str(cluster) + ',dst=/isolated-pg', '--entrypoint', entrypoint, image, *args]
    path = NEW / f'docker-{ordinal:02d}.private'
    try:
        with path.open('xb') as log:
            result = subprocess.run(argv, input=sql, stdout=log, stderr=subprocess.STDOUT,
                env=env, timeout=min(60, until - time.monotonic()))
    except subprocess.TimeoutExpired:
        owner = subprocess.run(cmd + ['inspect', '--format',
            '{{.Id}} {{index .Config.Labels "ouf.restore-run"}}', name], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        identity = owner.stdout.decode('ascii').split()
        if (owner.returncode == 0 and len(identity) == 2 and identity[1] == token
                and re.fullmatch('[a-f0-9]{64}', identity[0])):
            subprocess.run(cmd + ['rm', '-f', identity[0]], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        raise Held('ISOLATED_POSTGRES_TIMEOUT') from None
    need(result.returncode == 0 and 0 < path.stat().st_size <= 1 << 20, 'ISOLATED_POSTGRES_COMMAND_FAILED')
    content = path.read_bytes()
    need(not re.search(rb'\b(?:ERROR|FATAL|PANIC):', content), 'ISOLATED_POSTGRES_SQL_FAILED')
    return content


def execute(h, decision):
    need(decision == DECISION, 'EXACT_RESTORE_DECISION_REQUIRED')
    need(not os.path.lexists(NEW), 'RESTORE_SCOPE_ALREADY_CLAIMED')
    until = time.monotonic() + SECONDS
    plan, members = bind_payload(h, until)
    need(shutil.disk_usage(ROOT).free >= 2 << 30, 'RESTORE_FREE_SPACE_REQUIRED')
    parent = h['runtime_parent'](NEW)
    try:
        os.mkdir(NEW.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    token = secrets.token_hex(8)
    h['new'](NEW / 'claim.private.json', h['canonical']({'schema': SCHEMA, 'decisionReference': decision,
        'manifestSha256': MANIFEST_SHA, 'maximumSeconds': SECONDS, 'maximumContainerRuns': 18,
        'networkMode': 'none', 'historicalRestoreOnly': True, 'isolatedRunToken': token}))
    (NEW / 'docker-client').mkdir(mode=0o700)
    image, cluster, uid, gid, member = extract_cluster(h, plan, members, until)
    control = docker_probe(until, token, image, cluster, uid, gid, 1, 'pg_controldata', ['/isolated-pg'])
    need(re.search(rb'^Database cluster state:\s+shut down\s*$', control, re.M), 'POSTGRES_COLD_SHUTDOWN_REQUIRED')
    single = ['--single', '-D', '/isolated-pg', '-c', 'config_file=/dev/null',
              '-c', 'shared_preload_libraries=', '-c', 'exit_on_error=on']
    catalog = docker_probe(until, token, image, cluster, uid, gid, 2, 'postgres', single + ['template1'],
        b"SELECT 'OUF_DB_HEX=' || encode(convert_to(datname,'UTF8'),'hex') FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname;\n")
    names = [bytes.fromhex(v.decode()).decode('utf-8') for v in re.findall(rb'OUF_DB_HEX=([0-9a-f]+)', catalog)]
    need(1 <= len(names) <= 16 and len(set(names)) == len(names) and all(
        re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}', n) for n in names), 'POSTGRES_DATABASE_SET_REQUIRES_REVIEW')
    probe = (b"DO $$ DECLARE t record; n bigint; BEGIN SELECT s.nspname, c.relname INTO t FROM pg_class c "
        b"JOIN pg_namespace s ON s.oid=c.relnamespace WHERE c.relkind='r' AND s.nspname NOT IN "
        b"('pg_catalog','information_schema') AND s.nspname NOT LIKE 'pg_toast%' ORDER BY c.reltuples DESC LIMIT 1; "
        b"IF FOUND THEN EXECUTE format('SELECT count(*) FROM (SELECT 1 FROM %I.%I LIMIT 1) q', "
        b"t.nspname,t.relname) INTO n; RAISE NOTICE 'OUF_SAMPLE_ROWS=%',n; "
        b"ELSE RAISE NOTICE 'OUF_SAMPLE_ROWS=0'; END IF; END $$;\n")
    samples = 0
    for i, name in enumerate(names, 3):
        out = docker_probe(until, token, image, cluster, uid, gid, i, 'postgres', single + [name], probe)
        match = re.findall(rb'OUF_SAMPLE_ROWS=([01])\b', out)
        need(len(match) == 1, 'POSTGRES_ROW_READ_NOT_PROVEN')
        samples += int(match[0])
    need(samples > 0 and time.monotonic() < until, 'POSTGRES_APPLICATION_ROW_REQUIRED')
    result = {'schema': SCHEMA, 'status': 'ISOLATED_HISTORICAL_POSTGRES_RESTORED',
        'privateManifestSha256': MANIFEST_SHA, 'verifiedPayloadMembers': len(members),
        'sourceArchiveSha256': members[member]['sha256'], 'coldControlStateVerified': True,
        'databasesOpened': len(names), 'databasesWithSampleRow': samples, 'containerRuns': 2 + len(names),
        'networkMode': 'none', 'historicalRestoreOnly': True, 'minioRestored': False,
        'captureEventCoverageProven': False, 'g3Complete': False, 'acceptanceCreditAdded': 0}
    h['new'](NEW / 'result.json', h['canonical'](result))
    return result


if __name__ == '__main__':
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
             and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
        parser = argparse.ArgumentParser()
        parser.add_argument('--decision-reference', required=True)
        args = parser.parse_args()
        os.umask(0o077)
        print(json.dumps(execute(load_producer(), args.decision_reference), sort_keys=True))
    except Exception as error:
        code = str(error)
        if not (type(error).__name__ == 'Held' and re.fullmatch('[A-Z0-9_]{1,96}', code)):
            code = 'LOCAL_ISOLATED_RESTORE_FAILED'
        print(json.dumps({'schema': SCHEMA, 'status': 'HELD', 'reason': code, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
