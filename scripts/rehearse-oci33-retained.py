#!/usr/bin/env python3
"""Copy the manifest-bound historical objects into one isolated OCI33 sandbox."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode
import xml.etree.ElementTree as ET
import zipfile


SCHEMA = 'ouf.storage-retained-to-oci33-rehearsal.v1'
DECISION = 'GIOVANNI-NONPROD-RETAINED-TO-OCI33-20261107-01'
ZIP_PATH = 'ouf-oci33-d3ebc0e7c1174d638fd84f1f8d44ad89/candidate.zip'
ZIP_SHA = '4175ae9f0f5e4f6e71729084e0bfc2d9e8a2d39d3c5908dc51e5c4c695bd6121'
TAR_SHA = '5683622c9924be6192babb5a49588c7cb1ec53e5bf9257ed48225aa61ed26b12'
IMAGE = 'sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6'
BODY_MANIFEST = 'c54d67b9ec8448e884a296c37e588845e3d128283af14e92c29b9bb3e3a8281f'
SECONDS = 900
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
HEADERS = {'cache-control', 'content-disposition', 'content-encoding',
           'content-language', 'content-type', 'expires'}
CLIENT = r"""
import base64, http.client, json, sys
method, port, path, headers, encoded, maximum = json.load(sys.stdin)
connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
try:
    body = base64.b64decode(encoded, validate=True) if method == 'PUT' else None
    connection.request(method, path, body=body, headers=headers)
    result = connection.getresponse()
    output = result.read(maximum + 1)
    if len(output) > maximum:
        raise SystemExit(73)
    print(json.dumps([result.status, result.getheaders(), base64.b64encode(output).decode()]))
except ConnectionRefusedError:
    raise SystemExit(70)
except TimeoutError:
    raise SystemExit(71)
except (OSError, http.client.HTTPException):
    raise SystemExit(72)
finally:
    connection.close()
"""


class Held(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Held(code)


def signed(method, path, host, auth, body, extra, stamp):
    uri, _, query = path.partition('?')
    params = sorted((quote(k, safe='-_.~'), quote(v, safe='-_.~'))
                    for k, v in parse_qsl(query, keep_blank_values=True))
    query = '&'.join(f'{k}={v}' for k, v in params)
    payload = hashlib.sha256(body).hexdigest()
    headers = dict(extra, host=host)
    headers.update({'x-amz-content-sha256': payload, 'x-amz-date': stamp})
    names = sorted(headers)
    selected = ';'.join(names)
    lines = ''.join(f'{k}:{" ".join(headers[k].split())}\n' for k in names)
    canonical = '\n'.join((method, uri, query, lines, selected, payload))
    key, secret = auth
    day = stamp[:8]
    scope = f'{day}/us-east-1/s3/aws4_request'
    message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()))
    signing = ('AWS4' + secret).encode()
    for component in (day, 'us-east-1', 's3', 'aws4_request'):
        signing = hmac.digest(signing, component.encode(), 'sha256')
    signature = hmac.digest(signing, message.encode(), 'sha256').hex()
    headers['authorization'] = (
        f'AWS4-HMAC-SHA256 Credential={key}/{scope},SignedHeaders={selected},Signature={signature}')
    return uri + ('?' + query if query else ''), headers


def copy_checked(src, dst, digest, maximum, until, expected=None):
    sha, size = hashlib.sha256(), 0
    with dst.open('xb') as out:
        while block := src.read(1 << 20):
            size += len(block)
            need(size <= maximum and time.monotonic() < until, 'IMAGE_ARCHIVE_BUDGET')
            sha.update(block)
            out.write(block)
        need(sha.hexdigest() == digest and (expected is None or size == expected), 'IMAGE_ARCHIVE_DIGEST')
        out.flush()
        os.fsync(out.fileno())


def archive_config(archive):
    with tarfile.open(archive, 'r:') as tar:
        manifest = tar.getmember('manifest.json')
        need(manifest.isfile() and 0 < manifest.size <= 1 << 20, 'OCI33_DOCKER_MANIFEST_MEMBER')
        doc = json.load(tar.extractfile(manifest))
        need(isinstance(doc, list) and len(doc) == 1, 'OCI33_DOCKER_MANIFEST')
        info = tar.getmember(doc[0]['Config'])
        need(info.isfile() and 0 < info.size <= 1 << 20, 'OCI33_IMAGE_CONFIG_MEMBER')
        raw = tar.extractfile(info).read()
        need('sha256:' + hashlib.sha256(raw).hexdigest() == IMAGE, 'OCI33_IMAGE_CONFIG_DIGEST')
    return json.loads(raw), doc[0].get('RepoTags') or []


def prepare_image(scope, docker, until):
    account = pwd.getpwnam('oufadmin')
    supplied = os.path.join(account.pw_dir, ZIP_PATH)
    folder = os.path.dirname(supplied)
    need(os.path.realpath(folder) == folder, 'OCI33_STAGE_DIRECTORY_SYMLINK')
    directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        need(info.st_uid == account.pw_uid and stat.S_IMODE(info.st_mode) == 0o700, 'OCI33_STAGE_DIRECTORY')
        fd = os.open('candidate.zip', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as src:
            info = os.fstat(src.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == account.pw_uid and info.st_nlink == 1
                 and info.st_size == 174223468 and not info.st_mode & 0o022, 'OCI33_STAGE_FILE')
            copy_checked(src, scope / 'candidate.zip', ZIP_SHA, 174223468, until, 174223468)
    finally:
        os.close(directory)
    archive = scope / 'runtime.docker.tar'
    with zipfile.ZipFile(scope / 'candidate.zip') as z:
        candidates = [m for m in z.infolist() if m.filename == 'runtime.docker.tar']
        need(len(candidates) == 1 and 0 < candidates[0].file_size <= 512 << 20, 'OCI33_DOCKER_ARCHIVE_MEMBER')
        with z.open(candidates[0]) as src:
            copy_checked(src, archive, TAR_SHA, 512 << 20, until, candidates[0].file_size)
    _, tags = archive_config(archive)
    rows = [json.loads(line) for line in docker('image', 'ls', '--no-trunc', '--format', '{{json .}}').splitlines()]
    existing = {row['Repository'] + ':' + row['Tag']: row['ID'] for row in rows}
    need(all(isinstance(tag, str) and existing.get(tag, IMAGE) == IMAGE for tag in tags), 'OCI33_TAG_CONFLICT')
    docker('load', '--input', str(archive), timeout=120)
    checked = docker('image', 'inspect', '--format', '{{.Id}} {{.Config.User}}', IMAGE)
    need(checked.split() == [IMAGE, '10001:10001'], 'OCI33_LOADED_IDENTITY')
    return IMAGE


def reuse_loaded_image(h, pg, prior, scope, docker, until):
    archive = prior / 'runtime.docker.tar'
    need(pg['private_hash'](h, archive, until)['sha256'] == TAR_SHA, 'RETAINED_DOCKER_ARCHIVE_CHANGED')
    config, tags = archive_config(archive)
    need(len(tags) == 1 and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/:-]{0,199}', tags[0]),
         'OCI33_EXACT_ARCHIVE_TAG_REQUIRED')
    tag = tags[0]

    def inspect():
        raw = docker('image', 'inspect', tag)
        rows = json.loads(raw)
        need(len(rows) == 1, 'OCI33_INSPECT_CARDINALITY')
        row = rows[0]
        need(re.fullmatch('sha256:[a-f0-9]{64}', row.get('Id', ''))
             and row['Config']['User'] == config['config']['User'] == '10001:10001'
             and row['RootFS']['Layers'] == config['rootfs']['diff_ids'],
             'OCI33_LOADED_LAYER_OR_USER_MISMATCH')
        return row['Id']

    image_id = inspect()
    exported = scope / 'loaded-image-proof.tar'
    docker('image', 'save', '--output', str(exported), tag, timeout=min(120, until-time.monotonic()))
    need(0 < exported.stat().st_size <= 512 << 20, 'OCI33_EXPORTED_IMAGE_SIZE')
    exported_config, _ = archive_config(exported)
    need(exported_config == config and inspect() == image_id, 'OCI33_LOADED_CONFIG_OR_TAG_CHANGED')
    h['new'](scope / 'loaded-image.private.json', h['canonical']({
        'expectedConfigDigest': IMAGE, 'daemonImageId': image_id, 'tag': tag,
        'retainedArchiveSha256': TAR_SHA, 'rawConfigVerifiedFromImageSave': True}))
    return image_id


def objects(h, pg, mi):
    old = pg['ROOT'] / 'historical-minio-restore-20261107-v1'
    proof = old / 's3-proof-v2'
    result = h['decode'](h['protected'](proof / 'result.json', private=True, limit=8192))
    need(result.get('status') == 'ISOLATED_HISTORICAL_MINIO_RESTORED'
         and result.get('privateManifestSha256') == pg['MANIFEST_SHA']
         and result.get('s3BodyManifestSha256') == BODY_MANIFEST and result.get('versionsRead') == 120,
         'SOURCE_RESTORE_RECEIPT')
    raw = h['protected'](proof / 's3-bodies.private.json', private=True, limit=1 << 20)
    need(h['digest'](raw) == BODY_MANIFEST, 'SOURCE_BODY_MANIFEST_CHANGED')
    rows = h['decode'](raw)
    need(len(rows) == 120 and sum(r['size'] for r in rows) == 203743
         and all(r['versionId'] == 'null' and r['isLatest'] is True and r['deleteMarker'] is False
                 and 0 <= r['size'] <= 16 << 20 and re.fullmatch('[a-f0-9]{64}', r['sha256'])
                 and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', r['bucket'])
                 and r['key'] and not r['key'].endswith('/')
                 and all(part not in ('', '.', '..') for part in r['key'].split('/')) for r in rows),
         'SOURCE_OBJECT_PROFILE_REQUIRES_REVIEW')
    keys = {(r['bucket'], r['key']) for r in rows}
    need(len(keys) == 120 and len({b for b, _ in keys}) == 2, 'SOURCE_NAMESPACE_SET')
    for bucket, key in keys:
        parts = key.split('/')
        need(all((bucket, '/'.join(parts[:i])) not in keys for i in range(1, len(parts))),
             'SOURCE_NAMESPACE_PREFIX_COLLISION')
    members = h['decode'](h['protected'](old / 'verified-members.private.json', private=True, limit=32768))
    plan = h['protected'](pg['PAYLOAD'] / 'plan.private.json', private=True)
    seal = h['decode'](h['protected'](pg['SEALED'] / 'claim.private.json', private=True, limit=8192))
    need(h['digest'](plan) == members['plan.private.json']['sha256'] == seal['originalPlanSha256'],
         'RETAINED_SOURCE_PLAN_CHANGED')
    image, ordinal, source, relative = mi['minio_source'](h, pg, h['decode'](plan), members)
    need(members[f'source-{ordinal:03d}.tar']['sha256'] == result.get('sourceArchiveSha256'),
         'SOURCE_TAR_RECEIPT_MISMATCH')
    volume = old / 'data' / source.name / str(relative)
    info = volume.lstat()
    need(stat.S_ISDIR(info.st_mode) and volume.resolve(strict=True) == volume
         and (volume / '.minio.sys').is_dir(), 'SOURCE_ISOLATED_DATA_REQUIRED')
    return rows, image, volume, info


def object_metadata(headers):
    selected = {}
    for k, value in headers:
        name = k.lower()
        need(not name.startswith(('x-amz-server-side-encryption', 'x-amz-object-lock'))
             and name != 'x-amz-website-redirect-location', 'OBJECT_SPECIAL_METADATA_REQUIRES_REVIEW')
        if name in HEADERS or name.startswith('x-amz-meta-'):
            need(name not in selected and re.fullmatch('[a-z0-9_-]+', name)
                 and all(32 <= ord(c) < 127 for c in value), 'OBJECT_METADATA_REQUIRES_REVIEW')
            selected[name] = value
    return selected


def object_tags(body):
    root = ET.fromstring(body)
    need(root.tag.rsplit('}', 1)[-1] == 'Tagging', 'OBJECT_TAGGING_RESPONSE')
    tags = [(row.findtext('{*}Key'), row.findtext('{*}Value', ''))
            for row in root.findall('{*}TagSet/{*}Tag')]
    need(len(tags) <= 10 and all(k for k, _ in tags) and len(dict(tags)) == len(tags), 'OBJECT_TAG_SET')
    return dict(tags)


def run(h, pg, mi, decision, resume=False):
    need(decision == DECISION, 'EXACT_REHEARSAL_DECISION_REQUIRED')
    until = time.monotonic() + SECONDS
    prior = pg['ROOT'] / 'historical-oci33-rehearsal-20261107-v1'
    scope = prior / 'copy-proof-v1' if resume else prior
    need(not os.path.lexists(scope) and shutil.disk_usage(pg['ROOT']).free >= 3 << 30,
         'FRESH_REHEARSAL_SCOPE_AND_SPACE_REQUIRED')
    if resume:
        claim = h['decode'](h['protected'](prior / 'claim.private.json', private=True, limit=8192))
        need(claim.get('schema') == SCHEMA and claim.get('decisionReference') == DECISION
             and claim.get('sourceManifestSha256') == BODY_MANIFEST and claim.get('destinationImage') == IMAGE
             and claim.get('maximumContainerRuns') == 2 and re.fullmatch('[a-f0-9]{16}', claim.get('runToken', ''))
             and not any(os.path.lexists(prior / name) for name in
                         ('config', 'destination-data', 'result.json', 'copy-journal.private.jsonl')),
             'PRIOR_REHEARSAL_PHASE_REQUIRES_REVIEW')
    rows, source_image, volume, info = objects(h, pg, mi)
    token = secrets.token_hex(8)
    parent = h['runtime_parent'](scope)
    try:
        os.mkdir(scope.name, 0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    h['new'](scope / 'claim.private.json', h['canonical']({'schema': SCHEMA, 'decisionReference': decision,
        'sourceManifestSha256': BODY_MANIFEST, 'destinationImage': IMAGE, 'runToken': token,
        'maximumSeconds': SECONDS, 'maximumHttpRequests': 700, 'maximumContainerRuns': 2}))
    (scope / 'docker-client').mkdir(mode=0o700)
    docker_base = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock',
                   '--config', str(scope / 'docker-client')]

    def docker(*args, timeout=20):
        result = subprocess.run(docker_base + list(args), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=ENV, timeout=timeout)
        action = '_'.join(args[:2]) if args[0] == 'image' else args[0]
        need(result.returncode == 0, 'DOCKER_' + action.upper() + '_FAILED')
        return result.stdout.decode().strip()

    if resume:
        need(not docker('ps', '-aq', '--filter', 'label=ouf.rehearsal=' + claim['runToken']),
             'PRIOR_REHEARSAL_CONTAINER_PRESENT')
        destination_image = reuse_loaded_image(h, pg, prior, scope, docker, until)
    else:
        destination_image = prepare_image(scope, docker, until)
    source_name, dest_name = ('ouf-oci33-' + token + '-' + role for role in ('source', 'destination'))
    source_auth = ('restore' + secrets.token_hex(8), secrets.token_hex(24))
    dest_auth = ('rehearsal' + secrets.token_hex(8), secrets.token_hex(24))
    h['new'](scope / 'minio.env.private', (f'MINIO_ROOT_USER={source_auth[0]}\n'
        f'MINIO_ROOT_PASSWORD={source_auth[1]}\nMINIO_API_ROOT_ACCESS=on\n'
        'MINIO_REGION_NAME=us-east-1\n').encode())
    config, data = scope / 'config', scope / 'destination-data'
    for directory in (config, data):
        directory.mkdir(mode=0o700)
        os.chown(directory, 10001, 10001)
    h['new'](config / 'filer.toml', b'[leveldb2]\nenabled = true\ndir = "/data/metadata"\n')
    h['new'](config / 's3.json', h['canonical']({'identities': [{'name': 'rehearsal-admin',
        'credentials': [{'accessKey': dest_auth[0], 'secretKey': dest_auth[1]}],
        'actions': ['Admin', 'Read', 'Write', 'List', 'Tagging']}]}))
    for path in (config / 'filer.toml', config / 's3.json'):
        os.chown(path, 10001, 10001)

    def identity(name, required=True):
        result = subprocess.run(docker_base + ['inspect', '--format',
            '{{.Id}} {{index .Config.Labels "ouf.rehearsal"}} {{.HostConfig.NetworkMode}} {{.State.Pid}}',
            name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, timeout=10)
        if result.returncode != 0 and not required:
            return None
        fields = result.stdout.decode().split()
        need(result.returncode == 0 and len(fields) == 4 and fields[1] == token
             and re.fullmatch('[a-f0-9]{64}', fields[0]) and fields[3].isdigit(), 'ISOLATED_CONTAINER_IDENTITY')
        return fields

    common = ['--pull=never', '--restart=no', '--read-only', '--cap-drop=ALL',
              '--security-opt=no-new-privileges', '--memory=1g', '--cpus=2', '--pids-limit=256',
              '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
              '--label', 'ouf.rehearsal=' + token]
    net = None
    requests = 0

    def request(port, auth, method, path, body=b'', extra=None, cap=2 << 20):
        nonlocal requests
        requests += 1
        need(requests <= 700 and time.monotonic() < until and method in ('GET', 'PUT'), 'REHEARSAL_HTTP_BUDGET')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        url, headers = signed(method, path, f'127.0.0.1:{port}', auth, body, extra or {}, stamp)
        data = json.dumps([method, port, url, headers, base64.b64encode(body).decode(), cap]).encode()
        result = subprocess.run(['/usr/bin/nsenter', f'--net=/proc/self/fd/{net}', '/usr/bin/python3',
            '-I', '-B', '-S', '-c', CLIENT], input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=(net,), env=ENV, timeout=min(12, until-time.monotonic()))
        if result.returncode:
            raise Held(f'S3_{method}_TRANSPORT_{result.returncode}' if result.returncode > 0 else 'S3_TRANSPORT_INTERRUPTED')
        status, raw_headers, encoded = json.loads(result.stdout)
        if not 200 <= status <= 299:
            raise Held(f'S3_{method}_HTTP_{status}')
        return base64.b64decode(encoded, validate=True), raw_headers

    def wait(port, auth):
        last = None
        for _ in range(15):
            try:
                body, _ = request(port, auth, 'GET', '/')
                node = ET.fromstring(body)
                need(node.tag.rsplit('}', 1)[-1] == 'ListAllMyBucketsResult', 'S3_BUCKET_LIST_RESPONSE')
                return node
            except Held as error:
                last = error
                if str(error) not in ('S3_GET_TRANSPORT_70', 'S3_GET_TRANSPORT_71', 'S3_GET_HTTP_503'):
                    raise
                time.sleep(1)
        raise last

    def listed_keys(port, auth, bucket):
        doc = ET.fromstring(request(port, auth, 'GET',
            '/' + bucket + '?list-type=2&max-keys=1000&encoding-type=url')[0])
        need(doc.tag.rsplit('}', 1)[-1] == 'ListBucketResult'
             and doc.findtext('{*}IsTruncated') == 'false', 'BUCKET_LIST_INCOMPLETE')
        listed = [(item.findtext('{*}Key'), int(item.findtext('{*}Size')))
                  for item in doc.findall('{*}Contents')]
        if doc.findtext('{*}EncodingType') == 'url':
            listed = [(unquote(k, errors='strict'), v) for k, v in listed]
        expected = {(r['key'], r['size']) for r in rows if r['bucket'] == bucket}
        return set(listed) == expected and len(listed) == len(expected)

    def require_unversioned(port, auth, bucket):
        doc = ET.fromstring(request(port, auth, 'GET', '/' + bucket + '?versioning')[0])
        need(doc.tag.rsplit('}', 1)[-1] == 'VersioningConfiguration'
             and not doc.findtext('{*}Status'), 'BUCKET_VERSIONING_REQUIRES_REVIEW')

    verified = 0
    total = 0
    try:
        docker('run', '-d', '--name', source_name, '--network=none', *common,
               '--user', f'{info.st_uid}:{info.st_gid}', '--env-file', str(scope / 'minio.env.private'),
               '--mount', 'type=bind,src=' + str(volume) + ',dst=/isolated-minio',
               '--entrypoint', '/usr/bin/minio', source_image, 'server', '/isolated-minio',
               '--address', '127.0.0.1:9000', '--console-address', '127.0.0.1:9001')
        original = identity(source_name)
        need(original[2] == 'none' and int(original[3]) > 0, 'SOURCE_NAMESPACE_REQUIRED')
        net = os.open(f'/proc/{original[3]}/ns/net', os.O_RDONLY)
        need(identity(source_name) == original, 'SOURCE_NAMESPACE_CHANGED')
        docker('run', '-d', '--name', dest_name, '--network=container:' + original[0], *common,
               '--user', '10001:10001', '--workdir', '/config',
               '--mount', 'type=bind,src=' + str(data) + ',dst=/data',
               '--mount', 'type=bind,src=' + str(config) + ',dst=/config,readonly',
               destination_image, '-logtostderr=true', 'server', '-ip=127.0.0.1', '-ip.bind=127.0.0.1',
               '-dir=/data', '-master.port=19332', '-master.volumeSizeLimitMB=32', '-volume.port=18082',
               '-volume.max=128', '-filer', '-filer.port=18882', '-s3', '-s3.port=9002',
               '-s3.port.iceberg=0', '-s3.port.lance=0', '-s3.config=/config/s3.json')
        dest = identity(dest_name)
        need(dest[2] == 'container:' + original[0] and int(dest[3]) > 0, 'DESTINATION_NAMESPACE_REQUIRED')
        buckets = sorted({r['bucket'] for r in rows})
        source_buckets = wait(9000, source_auth)
        need(sorted(x.text for x in source_buckets.findall('{*}Buckets/{*}Bucket/{*}Name')) == buckets,
             'SOURCE_BUCKET_SET_CHANGED')
        empty = wait(9002, dest_auth)
        need(not empty.findall('{*}Buckets/{*}Bucket'), 'DESTINATION_NOT_EMPTY')
        for bucket in buckets:
            require_unversioned(9000, source_auth, bucket)
            need(listed_keys(9000, source_auth, bucket), 'SOURCE_KEY_SET_CHANGED')
        source_data = []
        for row in rows:
            url = '/' + row['bucket'] + '/' + quote(row['key'], safe='/')
            body, headers = request(9000, source_auth, 'GET', url, cap=max(row['size'], 16384))
            need(len(body) == row['size'] and h['digest'](body) == row['sha256'], 'SOURCE_BODY_CHANGED')
            meta = object_metadata(headers)
            tags = object_tags(request(9000, source_auth, 'GET', url + '?tagging')[0])
            source_data.append((row, url, body, meta, tags))
        for bucket in buckets:
            request(9002, dest_auth, 'PUT', '/' + bucket)
            require_unversioned(9002, dest_auth, bucket)
        with (scope / 'copy-journal.private.jsonl').open('xb') as journal:
            for index, (row, url, body, meta, tags) in enumerate(source_data, 1):
                headers = dict(meta, **{'if-none-match': '*'})
                if tags:
                    headers['x-amz-tagging'] = urlencode(sorted(tags.items()), quote_via=quote)
                journal.write(h['canonical']({'ordinal': index, 'status': 'PUT_INTENT', 'sha256': row['sha256']}))
                journal.flush()
                os.fsync(journal.fileno())
                request(9002, dest_auth, 'PUT', url, body, headers)
                actual, actual_headers = request(9002, dest_auth, 'GET', url, cap=max(row['size'], 16384))
                actual_tags = object_tags(request(9002, dest_auth, 'GET', url + '?tagging')[0])
                need(len(actual) == row['size'] and h['digest'](actual) == row['sha256']
                     and object_metadata(actual_headers) == meta and actual_tags == tags,
                     'DESTINATION_BODY_METADATA_OR_TAGS_MISMATCH')
                verified += 1
                total += len(actual)
                journal.write(h['canonical']({'ordinal': index, 'status': 'VERIFIED'}))
                journal.flush()
                os.fsync(journal.fileno())
        for bucket in buckets:
            need(listed_keys(9002, dest_auth, bucket), 'DESTINATION_KEY_SET_MISMATCH')
        destination_buckets = ET.fromstring(request(9002, dest_auth, 'GET', '/')[0])
        need(sorted(x.text for x in destination_buckets.findall('{*}Buckets/{*}Bucket/{*}Name')) == buckets,
             'DESTINATION_BUCKET_SET_MISMATCH')
    finally:
        if net is not None:
            os.close(net)
        cleanup_ok = True
        for label, name in (('destination', dest_name), ('source', source_name)):
            try:
                owned = identity(name, required=False)
                if owned:
                    try:
                        if int(owned[3]) > 0:
                            docker('stop', '--time', '10', owned[0])
                        with (scope / (label + '-log.private')).open('xb') as log:
                            subprocess.run(docker_base + ['logs', '--tail', '40', owned[0]], env=ENV,
                                           stdout=log, stderr=subprocess.STDOUT, timeout=10)
                    finally:
                        docker('rm', '-f', '-v', owned[0])
            except Exception:
                cleanup_ok = False
        need(cleanup_ok, 'REHEARSAL_CONTAINER_CLEANUP')
    need(verified == 120 and total == 203743, 'REHEARSAL_TOTAL_MISMATCH')
    result = {'schema': SCHEMA, 'status': 'HISTORICAL_OCI33_REHEARSAL_PARITY_VERIFIED',
        'bucketsVerified': 2, 'objectsVerified': verified, 'bytesVerified': total,
        'bodyMetadataAndTagsMatch': True, 'destinationKeySetMatches': True,
        'sourceManifestSha256': BODY_MANIFEST, 'imageId': IMAGE, 'httpRequests': requests,
        'daemonImageId': destination_image, 'existingImageReused': resume,
        'historicalRehearsalOnly': True, 'productionObjectsMigrated': 0,
        'g4Complete': False, 'acceptanceCreditAdded': 0}
    h['new'](scope / 'result.json', h['canonical'](result))
    return result


def main(pg, mi):
    parser = argparse.ArgumentParser()
    parser.add_argument('--decision-reference', required=True)
    parser.add_argument('--finish-loaded-image', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        need(os.geteuid() == os.getegid() == 0, 'ROOT_REQUIRED')
        print(json.dumps(run(pg['load_producer'](), pg, mi, args.decision_reference,
                             resume=args.finish_loaded_image), sort_keys=True))
    except Exception as error:
        code = str(error)
        if not (type(error).__name__ == 'Held' and re.fullmatch('[A-Z0-9_]{1,96}', code)):
            code = 'LOCAL_OCI33_REHEARSAL_FAILED'
        print(json.dumps({'schema': SCHEMA, 'status': 'HELD', 'reason': code, 'acceptanceCreditAdded': 0}))
        raise SystemExit(2)
