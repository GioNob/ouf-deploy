#!/usr/bin/env python3
"""Restore the retained MinIO data in an isolated network and read its object bodies."""
import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import resource
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import quote, unquote, urlencode
import xml.etree.ElementTree as ET


SCHEMA = 'ouf.storage-retained-minio-restore.v1'
DECISION = 'GIOVANNI-NONPROD-ISOLATED-MINIO-RESTORE-20261107-01'
READ_DECISION = 'GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-02'
SECONDS = 600
BODY_LIMIT = 64 << 20
TOTAL_LIMIT = 512 << 20
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


class Held(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Held(code)


def minio_source(h, pg, plan, members):
    role = plan['roles']['minio']
    image, cid = role['nativeImage'], role['containerId']
    need(re.fullmatch('sha256:[a-f0-9]{64}', image) and re.fullmatch('[a-f0-9]{64}', cid),
         'MINIO_CAPTURE_BINDING')
    raw = h['protected'](pg['PAYLOAD'] / 'containers.private.json', private=True)
    need(h['digest'](raw) == members['containers.private.json']['sha256'], 'MINIO_CONFIG_CHANGED')
    config = h['decode'](raw)[cid]
    need(config['Id'] == cid and config['Image'] == image, 'MINIO_CONFIG_BINDING')
    args = config.get('Args') or config.get('Config', {}).get('Cmd') or []
    need('server' in args, 'MINIO_SERVER_COMMAND_REQUIRED')
    destinations = {m['Destination']: m for m in config['Mounts'] if m['Type'] in ('volume', 'bind')}
    data_args = [arg for arg in args[args.index('server') + 1:] if arg in destinations]
    need(len(data_args) == 1, 'MINIO_SINGLE_DATA_MOUNT_REQUIRED')
    data = PurePosixPath(data_args[0])
    need(not any(PurePosixPath(m['Destination']) != data and PurePosixPath(m['Destination']).is_relative_to(data)
                 for m in config['Mounts']), 'MINIO_NESTED_DATA_MOUNT')
    source = PurePosixPath(destinations[str(data)]['Source'])
    found = [(i, PurePosixPath(path)) for i, path in enumerate(plan['sources'])
             if source.is_relative_to(PurePosixPath(path))]
    need(len(found) == 1, 'MINIO_SOURCE_TAR_REQUIRED')
    ordinal, root = found[0]
    return image, ordinal, root, source.relative_to(root)


def extract(h, pg, plan, members, scope, until):
    image, ordinal, source, relative = minio_source(h, pg, plan, members)
    name = f'source-{ordinal:03d}.tar'
    path = pg['PAYLOAD'] / name
    need(pg['private_hash'](h, path, until) == members[name], 'MINIO_TAR_CHANGED')
    raw = h['protected'](pg['PAYLOAD'] / 'source-manifests.private.json', private=True)
    need(h['digest'](raw) == members['source-manifests.private.json']['sha256'], 'SOURCE_MANIFEST_CHANGED')
    rows = h['decode'](raw)[str(source)]
    need(0 < len(rows) <= 100000 and sum(row['size'] for row in rows) <= 1 << 30, 'MINIO_SOURCE_SIZE_LIMIT')
    h['verify_source_archive'](path, source.name, rows, until)
    with tarfile.open(path, 'r:') as archive:
        for entry in archive:
            need(not entry.issym() and (entry.isdir() or entry.isfile() or entry.islnk()), 'MINIO_SOURCE_LINK')
            if entry.islnk():
                link = PurePosixPath(entry.linkname)
                need(not link.is_absolute() and '..' not in link.parts and link.parts
                     and link.parts[0] == source.name, 'MINIO_SOURCE_HARDLINK')
    data = scope / 'data'
    data.mkdir(mode=0o700)
    with (scope / 'extract.stderr.private').open('xb') as log:
        p = subprocess.run(['/usr/bin/tar', '--extract', '--numeric-owner', '--same-owner',
            '--same-permissions', '--acls', '--xattrs', '--xattrs-include=*', '-f', str(path), '-C', str(data)],
            stdout=subprocess.DEVNULL, stderr=log, timeout=min(120, until - time.monotonic()))
    need(p.returncode == 0 and pg['private_hash'](h, path, until) == members[name], 'MINIO_EXTRACT_FAILED')
    volume = data / source.name / str(relative)
    info = volume.lstat()
    need(stat.S_ISDIR(info.st_mode) and volume.resolve(strict=True) == volume
         and (volume / '.minio.sys').is_dir(), 'MINIO_RESTORED_DATA_REQUIRED')
    return image, volume, info, members[name]['sha256']


def request(net, auth, path, limit, until):
    need(time.monotonic() < until and path.startswith('/'), 'MINIO_READ_WINDOW')
    maximum = max(limit, 16384)

    def restrict_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum + 1, maximum + 1))

    with tempfile.TemporaryFile() as raw:
        fd = raw.fileno()
        argv = ['/usr/bin/nsenter', f'--net=/proc/self/fd/{net}', '/usr/bin/curl',
            '--disable', '--globoff', '--path-as-is', '--noproxy', '*', '--proto', '=http',
            '--max-time', '8', '--max-filesize', str(maximum), '--silent', '--show-error',
            '--output', f'/proc/self/fd/{fd}', '--write-out', '%{http_code}']
        if auth:
            argv.extend(['--config', str(auth), '--aws-sigv4', 'aws:amz:us-east-1:s3'])
        p = subprocess.run(argv + ['http://127.0.0.1:9000' + path], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV,
            pass_fds=(net, fd), preexec_fn=restrict_output, timeout=min(10, until - time.monotonic()))
        if p.returncode:
            if p.stderr.startswith(b'nsenter:'):
                raise Held('MINIO_NAMESPACE_ENTRY_FAILED')
            raise Held(f'MINIO_CURL_EXIT_{p.returncode}' if 0 < p.returncode < 100 else 'MINIO_CURL_INTERRUPTED')
        need(re.fullmatch(rb'[1-5][0-9]{2}', p.stdout), 'MINIO_HTTP_STATUS_MISSING')
        raw.seek(0)
        body = raw.read(maximum + 1)
        status = int(p.stdout)
        if status != 200:
            error = None
            if auth:
                try:
                    error = ET.fromstring(body).findtext('{*}Code')
                except ET.ParseError:
                    pass
            labels = {'AccessDenied': 'ACCESS_DENIED', 'SignatureDoesNotMatch': 'SIGNATURE_MISMATCH',
                      'InvalidAccessKeyId': 'INVALID_ACCESS_KEY', 'AuthorizationHeaderMalformed': 'AUTH_HEADER',
                      'RequestTimeTooSkewed': 'CLOCK_SKEW', 'XMinioServerNotInitialized': 'NOT_INITIALIZED'}
            raise Held(f'MINIO_HTTP_{status}' + ('_' + labels[error] if error in labels else ''))
        need(len(body) <= limit, 'MINIO_HTTP_BODY_LIMIT')
        return body


def inventory(get):
    root = ET.fromstring(get('/', 1 << 20))
    need(root.tag.rsplit('}', 1)[-1] == 'ListAllMyBucketsResult', 'MINIO_BUCKET_LIST_SHAPE')
    buckets = [p.text for p in root.findall('{*}Buckets/{*}Bucket/{*}Name')]
    need(0 < len(buckets) <= 32 and len(set(buckets)) == len(buckets) and all(
        b and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', b) for b in buckets), 'MINIO_BUCKET_LIST')
    records, seen, total, deleted = [], set(), 0, 0
    for bucket in sorted(buckets):
        root = ET.fromstring(get(f'/{bucket}?versions&max-keys=1000&encoding-type=url', 2 << 20))
        need(root.tag.rsplit('}', 1)[-1] == 'ListVersionsResult'
             and root.findtext('{*}IsTruncated') == 'false', 'MINIO_VERSION_LIST_INCOMPLETE')
        encoded = root.findtext('{*}EncodingType') == 'url'
        for item in root:
            kind = item.tag.rsplit('}', 1)[-1]
            if kind not in ('Version', 'DeleteMarker'):
                continue
            key, version, latest = (item.findtext('{*}' + field) for field in ('Key', 'VersionId', 'IsLatest'))
            need(key and version and latest in ('true', 'false'), 'MINIO_VERSION_FIELDS')
            key = unquote(key, errors='strict') if encoded else key
            need(len(key.encode()) <= 1024 and (bucket, key, version) not in seen
                 and len(seen) < 256, 'MINIO_VERSION_LIMIT_OR_DUPLICATE')
            seen.add((bucket, key, version))
            row = {'bucket': bucket, 'key': key, 'versionId': version, 'isLatest': latest == 'true',
                   'deleteMarker': kind == 'DeleteMarker'}
            if row['deleteMarker']:
                deleted += 1
            else:
                size = int(item.findtext('{*}Size', '-1'))
                need(0 <= size <= BODY_LIMIT and total + size <= TOTAL_LIMIT, 'MINIO_BODY_BUDGET')
                url = f'/{bucket}/' + quote(key, safe='/')
                if version != 'null' or latest != 'true':
                    url += '?' + urlencode({'versionId': version})
                body = get(url, size)
                need(len(body) == size, 'MINIO_BODY_LENGTH_MISMATCH')
                row.update(size=size, sha256=hashlib.sha256(body).hexdigest())
                total += size
            records.append(row)
    need(len(records) > deleted, 'MINIO_OBJECT_BODY_REQUIRED')
    return records, len(buckets), deleted, total


def execute(h, pg, decision):
    need(decision == DECISION, 'EXACT_MINIO_DECISION_REQUIRED')
    until = time.monotonic() + SECONDS
    scope = pg['ROOT'] / 'historical-minio-restore-20261107-v1'
    need(not os.path.lexists(scope), 'MINIO_RESTORE_SCOPE_ALREADY_CLAIMED')
    plan, members = pg['bind_payload'](h, until)
    need(shutil.disk_usage(pg['ROOT']).free >= 2 << 30, 'MINIO_RESTORE_FREE_SPACE')
    parent = h['runtime_parent'](scope)
    try:
        os.mkdir(scope.name, 0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    h['new'](scope / 'verified-members.private.json', h['canonical'](members))
    image, volume, info, source_sha = extract(h, pg, plan, members, scope, until)
    return run_server(h, pg, scope, decision, until, image, volume, info, source_sha)


def finish_s3_proof(h, pg, decision):
    need(decision == READ_DECISION, 'EXACT_MINIO_S3_DECISION_REQUIRED')
    old = pg['ROOT'] / 'historical-minio-restore-20261107-v1'
    scope = old / 's3-proof-v1'
    need(not os.path.lexists(scope) and not os.path.lexists(old / 'result.json'),
         'MINIO_S3_PROOF_ALREADY_CLAIMED')
    claim = h['decode'](h['protected'](old / 'claim.private.json', private=True, limit=8192))
    need(claim.get('schema') == SCHEMA and claim.get('decisionReference') == DECISION
         and claim.get('manifestSha256') == pg['MANIFEST_SHA'] and claim.get('networkMode') == 'none'
         and claim.get('maximumContainerRuns') == 1 and re.fullmatch('ouf-minio-historical-[a-f0-9]{16}',
                                                                   claim.get('containerName', '')),
         'PRIOR_MINIO_CLAIM_MISMATCH')
    log = h['protected'](old / 'minio.stderr.private', private=True, limit=1 << 20)
    need(re.search(rb'API:\s+http://127\.0\.0\.1:9000\b', log)
         and b'Exiting on signal' in log, 'PRIOR_MINIO_START_STOP_NOT_PROVEN')
    members = h['decode'](h['protected'](old / 'verified-members.private.json', private=True, limit=32768))
    sealed = pg['SEALED']
    capture = pg['OLD']
    evidence = {'custody-claim.private.json': sealed / 'claim.private.json',
                'original-claim.private.json': capture / 'claim.private.json',
                'original-producer-claim.private.json': capture / 'capture/capture-claim.private.json'}
    manifest = h['canonical']({'schema': 'ouf.storage-retained-capture-custody.v1', 'members': members,
        'evidenceSha256': {name: h['digest'](h['protected'](path, private=True, limit=8192))
                           for name, path in evidence.items()},
        'captureEventCoverageProven': False, 'liveSourceContinuityProven': False,
        'historicalCustodyOnly': True, 'restorePerformed': False})
    need(h['digest'](manifest) == pg['MANIFEST_SHA'], 'RETAINED_MINIO_MANIFEST_MISMATCH')
    raw = h['protected'](pg['PAYLOAD'] / 'plan.private.json', private=True)
    need(h['digest'](raw) == members['plan.private.json']['sha256'], 'RETAINED_MINIO_PLAN_CHANGED')
    image, ordinal, source, relative = minio_source(h, pg, h['decode'](raw), members)
    volume = old / 'data' / source.name / str(relative)
    info = volume.lstat()
    need(stat.S_ISDIR(info.st_mode) and volume.resolve(strict=True) == volume
         and (volume / '.minio.sys').is_dir(), 'MINIO_RESTORED_DATA_REQUIRED')
    prior = subprocess.run(['/usr/bin/docker', '--host', 'unix:///run/docker.sock',
        '--config', str(old / 'docker-client'), 'ps', '-aq', '--filter',
        'name=^/' + claim['containerName'] + '$'], env=ENV, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=10)
    need(prior.returncode == 0 and not prior.stdout.strip(), 'PRIOR_MINIO_CONTAINER_STILL_PRESENT')
    parent = h['runtime_parent'](scope)
    try:
        os.mkdir(scope.name, 0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    return run_server(h, pg, scope, decision, time.monotonic() + 300, image, volume,
                      info, members[f'source-{ordinal:03d}.tar']['sha256'])


def run_server(h, pg, scope, decision, until, image, volume, info, source_sha):
    token = secrets.token_hex(8)
    name = 'ouf-minio-historical-' + token
    h['new'](scope / 'claim.private.json', h['canonical']({'schema': SCHEMA, 'decisionReference': decision,
        'manifestSha256': pg['MANIFEST_SHA'], 'networkMode': 'none',
        'maximumSeconds': 300 if decision == READ_DECISION else SECONDS,
        'maximumContainerRuns': 1, 'containerName': name}))
    (scope / 'docker-client').mkdir(mode=0o700)
    key, password = 'restore' + secrets.token_hex(8), secrets.token_hex(24)
    h['new'](scope / 'minio.env.private',
             (f'MINIO_ROOT_USER={key}\nMINIO_ROOT_PASSWORD={password}\n'
              'MINIO_API_ROOT_ACCESS=on\nMINIO_REGION_NAME=us-east-1\n').encode())
    auth = scope / 'curl-auth.private'
    h['new'](auth, f'user = "{key}:{password}"\n'.encode())
    docker = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', str(scope / 'docker-client')]

    def call(args, timeout=20):
        return subprocess.run(docker + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=ENV, timeout=timeout)

    def identity():
        p = call(['inspect', '--format',
            '{{.Id}} {{index .Config.Labels "ouf.restore-run"}} {{.HostConfig.NetworkMode}} {{.State.Pid}}', name])
        fields = p.stdout.decode('ascii').split()
        if p.returncode != 0:
            return None
        need(len(fields) == 4 and re.fullmatch('[a-f0-9]{64}', fields[0])
             and fields[1:3] == [token, 'none'] and fields[3].isdigit(), 'MINIO_ISOLATED_CONTAINER_IDENTITY')
        return fields[0], int(fields[3])

    calls = 0
    health_calls = 0
    net = None
    try:
        p = call(['run', '-d', '--name', name, '--label', 'ouf.restore-run=' + token, '--pull=never',
            '--network=none', '--restart=no', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--memory=1g', '--cpus=1', '--pids-limit=128',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m', '--user', f'{info.st_uid}:{info.st_gid}',
            '--env-file', str(scope / 'minio.env.private'), '--mount',
            'type=bind,src=' + str(volume) + ',dst=/isolated-minio',
            '--entrypoint', '/usr/bin/minio', image, 'server', '/isolated-minio',
            '--address', '127.0.0.1:9000', '--console-address', '127.0.0.1:9001'])
        active = identity()
        need(p.returncode == 0 and active and active[0] == p.stdout.decode('ascii').strip() and active[1] > 0,
             'MINIO_ISOLATED_START_FAILED')
        net = os.open(f'/proc/{active[1]}/ns/net', os.O_RDONLY)
        need(identity() == active, 'MINIO_NETWORK_NAMESPACE_CHANGED')

        def get(path, limit):
            nonlocal calls
            calls += 1
            need(calls + health_calls <= 320, 'MINIO_HTTP_REQUEST_BUDGET')
            return request(net, auth, path, limit, until)

        ready = False
        last = 'MINIO_HTTP_NOT_PROBED'
        for _ in range(12):
            health_calls += 1
            try:
                request(net, None, '/minio/health/ready', 4096, until)
                ready = True
                break
            except Held as error:
                last = str(error)
                if last not in ('MINIO_CURL_EXIT_7', 'MINIO_CURL_EXIT_28', 'MINIO_HTTP_429', 'MINIO_HTTP_503'):
                    raise
                time.sleep(1)
        need(ready, last)
        records, buckets, markers, total = inventory(get)
    finally:
        if net is not None:
            os.close(net)
        owned = identity()
        if owned:
            try:
                if owned[1] > 0:
                    call(['stop', '--time', '10', owned[0]])
                with (scope / 'minio.stderr.private').open('xb') as log:
                    subprocess.run(docker + ['logs', '--tail', '40', owned[0]], stdout=log,
                                   stderr=subprocess.STDOUT, env=ENV, timeout=10)
            finally:
                removed = call(['rm', '-f', '-v', owned[0]])
                need(removed.returncode == 0, 'MINIO_ISOLATED_CONTAINER_CLEANUP')
    manifest = h['canonical'](records)
    h['new'](scope / 's3-bodies.private.json', manifest)
    bodies = len(records) - markers
    result = {'schema': SCHEMA, 'status': 'ISOLATED_HISTORICAL_MINIO_RESTORED',
        'privateManifestSha256': pg['MANIFEST_SHA'], 'sourceArchiveSha256': source_sha,
        's3BodyManifestSha256': h['digest'](manifest), 'bucketsRead': buckets, 'versionsRead': bodies,
        'deleteMarkersObserved': markers, 'bytesRead': total, 's3GetRequests': calls,
        'httpReadinessVerified': True, 'httpReadinessRequests': health_calls,
        'reusedExtractedVolume': decision == READ_DECISION,
        'matchesPrior120Bodies': bodies == 120, 'networkMode': 'none', 'historicalRestoreOnly': True,
        'g3Complete': False, 'acceptanceCreditAdded': 0}
    h['new'](scope / 'result.json', h['canonical'](result))
    return result


def main(pg):
    parser = argparse.ArgumentParser()
    parser.add_argument('--decision-reference', required=True)
    parser.add_argument('--finish-s3-proof', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        need(os.geteuid() == os.getegid() == 0, 'ROOT_REQUIRED')
        run = finish_s3_proof if args.finish_s3_proof else execute
        print(json.dumps(run(pg['load_producer'](), pg, args.decision_reference), sort_keys=True))
    except Exception as error:
        code = str(error)
        if not (type(error).__name__ == 'Held' and re.fullmatch('[A-Z0-9_]{1,96}', code)):
            code = 'LOCAL_ISOLATED_MINIO_RESTORE_FAILED'
        print(json.dumps({'schema': SCHEMA, 'status': 'HELD', 'reason': code, 'acceptanceCreditAdded': 0}))
        raise SystemExit(2)
