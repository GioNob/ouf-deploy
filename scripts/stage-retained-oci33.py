#!/usr/bin/env python3
"""Stage the verified SeaweedFS rehearsal on the VPS and read it in isolation."""

import base64
from datetime import datetime, timezone
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
from urllib.parse import unquote
from urllib.request import urlopen
from xml.etree import ElementTree as ET

SCHEMA = 'ouf.storage-retained-oci33-stage.v1'
ROOT = Path('/var/lib/ouf-storage-migration')
REHEARSAL = ROOT / 'historical-oci33-rehearsal-20261107-v1/copy-proof-v1'
SCOPE = ROOT / 'seaweedfs/staging-oci33-20261107-v1'
DAEMON_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


class Held(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Held(reason)


def load(ref, name, size, sha):
    url = f'https://raw.githubusercontent.com/GioNob/ouf-deploy/{ref}/scripts/{name}'
    with urlopen(url, timeout=25) as response:
        raw = response.read(size + 1)
    need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha, 'DEPENDENCY_DIGEST')
    namespace = {'__name__': 'stage_dependency'}
    exec(compile(raw, name, 'exec'), namespace)
    return namespace


def comparable_manifest(rows):
    result = {}
    for row in rows:
        need(stat.S_ISDIR(row['mode']) or stat.S_ISREG(row['mode']), 'REHEARSAL_LAYOUT_REQUIRES_REVIEW')
        ignore = {'inode', 'ctimeNs'}
        if stat.S_ISDIR(row['mode']):
            ignore.add('size')
        result[row['path']] = {key: value for key, value in row.items() if key not in ignore}
    return result


def stage(report):
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
    pg = load('5ae47689adeaf39f241527c9364a2c0c9e9b0b9b', 'restore-retained-postgres.py', 19046,
              '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d')
    r = load('09386c72b54e703dbab4bdd296a493ccdf1f0e05', 'rehearse-oci33-retained.py', 25800,
             'd22e0b380dacf0dce6f3c84de069d19c8eca4c39c759f6200ef9255019f2950d')
    h = pg['load_producer']()

    def read(path, limit=8192):
        return h['decode'](h['protected'](path, private=True, limit=limit))

    receipt = read(REHEARSAL / 'result.json')
    image_proof = read(REHEARSAL / 'loaded-image.private.json')
    need(receipt.get('status') == 'HISTORICAL_OCI33_REHEARSAL_PARITY_VERIFIED'
         and receipt.get('bodyMetadataAndTagsMatch') is True
         and receipt.get('destinationKeySetMatches') is True
         and receipt.get('objectsVerified') == 120 and receipt.get('bucketsVerified') == 2
         and receipt.get('bytesVerified') == 203743
         and receipt.get('sourceManifestSha256') == r['BODY_MANIFEST']
         and receipt.get('imageId') == image_proof.get('expectedConfigDigest') == r['IMAGE']
         and receipt.get('daemonImageId') == image_proof.get('daemonImageId') == DAEMON_IMAGE
         and image_proof.get('rawConfigVerifiedFromImageSave') is True, 'REHEARSAL_RECEIPT_BINDING')
    manifest = ROOT / 'historical-minio-restore-20261107-v1/s3-proof-v2/s3-bodies.private.json'
    raw = h['protected'](manifest, private=True, limit=1 << 20)
    need(h['digest'](raw) == r['BODY_MANIFEST'], 'SOURCE_OBJECT_MANIFEST_BINDING')
    expected = {}
    for row in h['decode'](raw):
        need(re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', row['bucket']), 'BUCKET_BINDING')
        expected.setdefault(row['bucket'], set()).add((row['key'], row['size']))
    need(len(expected) == 2 and sum(map(len, expected.values())) == 120, 'OBJECT_SET_BINDING')

    until = time.monotonic() + 420
    sock = Path('/run/docker.sock').stat()
    need(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o007,
         'LOCAL_DOCKER_SOCKET_REQUIRED')
    docker_base = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent']

    def docker(*args, timeout=15):
        now = Path('/run/docker.sock').stat()
        need(h['frame'](now) == h['frame'](sock), 'DOCKER_SOCKET_CHANGED')
        call = subprocess.run(docker_base + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=ENV, timeout=timeout)
        need(call.returncode == 0, 'DOCKER_' + args[0].upper() + '_FAILED')
        return call.stdout.decode().strip()

    need(not docker('ps', '-q'), 'OTHER_CONTAINERS_RUNNING')
    img = json.loads(docker('image', 'inspect', DAEMON_IMAGE))
    need(len(img) == 1 and img[0]['Id'] == DAEMON_IMAGE
         and img[0]['Config']['User'] == '10001:10001', 'LOCAL_IMAGE_BINDING')
    origin = REHEARSAL / 'destination-data'
    before = h['tree_manifest'](origin, until)
    source = comparable_manifest(before)
    total = sum(row['size'] for row in before if stat.S_ISREG(row['mode']))
    need(stat.S_ISDIR(source.get('metadata', {}).get('mode', 0))
         and 0 < total <= 8 << 30 and shutil.disk_usage(SCOPE.parent).free >= total + (1 << 30),
         'STAGING_LAYOUT_OR_CAPACITY')
    parent = h['runtime_parent'](SCOPE)
    try:
        os.mkdir(SCOPE.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    token = secrets.token_hex(12)
    name = 'ouf-oci33-stage-' + token
    h['new'](SCOPE / 'claim.private.json', h['canonical']({
        'schema': SCHEMA, 'containerName': name, 'sourceManifestSha256': r['BODY_MANIFEST'],
        'imageConfigDigest': r['IMAGE'], 'daemonImageId': DAEMON_IMAGE}))
    data = SCOPE / 'data'
    copy = subprocess.run(['/usr/bin/cp', '-a', '--reflink=auto', '--sparse=always', '--',
                           str(origin), str(data)], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV,
                          timeout=max(1, min(240, until - time.monotonic())))
    need(copy.returncode == 0 and comparable_manifest(h['tree_manifest'](data, until)) == source,
         'STAGED_DATA_MISMATCH')
    need(h['tree_manifest'](origin, until) == before, 'REHEARSAL_DATA_CHANGED')
    report['stagedDataVerified'] = True
    report['stagedFileBytes'] = total

    config = SCOPE / 'config'
    config.mkdir(mode=0o700)
    auth = ('stage' + secrets.token_hex(10), secrets.token_hex(24))
    h['new'](config / 'filer.toml', b'[leveldb2]\nenabled = true\ndir = "/data/metadata"\n')
    h['new'](config / 's3.json', h['canonical']({'identities': [{
        'name': 'staging-reader', 'credentials': [{'accessKey': auth[0], 'secretKey': auth[1]}],
        'actions': ['Read', 'List']}]}))
    for path in (config / 'filer.toml', config / 's3.json', config):
        os.chown(path, 10001, 10001)

    need(not docker('ps', '-q') and time.monotonic() < until, 'STAGING_RUNTIME_PRECONDITION')
    cid = docker('create', '--name', name, '--label', 'ouf.oci33-stage=' + token,
                 '--network=none', '--pull=never', '--restart=no', '--read-only', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--memory=1g', '--cpus=2', '--pids-limit=256',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
                 '--user', '10001:10001', '--workdir', '/config',
                 '--mount', f'type=bind,src={data},dst=/data',
                 '--mount', f'type=bind,src={config},dst=/config,readonly',
                 DAEMON_IMAGE, '-logtostderr=true', 'server', '-ip=127.0.0.1', '-ip.bind=127.0.0.1',
                 '-dir=/data', '-master.port=19332', '-master.volumeSizeLimitMB=32', '-volume.port=18082',
                 '-volume.max=128', '-filer', '-filer.port=18882', '-s3', '-s3.port=9002',
                 '-s3.port.iceberg=0', '-s3.port.lance=0', '-s3.config=/config/s3.json')
    need(re.fullmatch('[a-f0-9]{64}', cid), 'STAGING_CONTAINER_ID')
    started = False
    net = None

    def inspect():
        info, = json.loads(docker('container', 'inspect', cid))
        need(info['Id'] == cid and info['Image'] in (DAEMON_IMAGE, r['IMAGE'])
             and info['Config']['Labels']['ouf.oci33-stage'] == token
             and info['HostConfig']['NetworkMode'] == 'none'
             and not info['HostConfig']['PortBindings'] and not info['HostConfig']['PublishAllPorts'],
             'STAGING_CONTAINER_ISOLATION')
        return info['State']

    def get(path):
        need(report['s3GetRequests'] < 30 and time.monotonic() < until, 'S3_READ_BUDGET')
        report['s3GetRequests'] += 1
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        url, headers = r['signed']('GET', path, '127.0.0.1:9002', auth, b'', {}, stamp)
        req = json.dumps(['GET', 9002, url, headers, '', 1 << 20]).encode()
        p = subprocess.run(['/usr/bin/nsenter', f'--net=/proc/self/fd/{net}', '/usr/bin/python3',
                            '-I', '-B', '-S', '-c', r['CLIENT']], input=req, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, env=ENV, pass_fds=(net,), timeout=12)
        if p.returncode in (70, 71):
            return None
        need(p.returncode == 0, 'STAGING_S3_TRANSPORT')
        status, _, body = json.loads(p.stdout)
        if status == 503:
            return None
        need(status == 200, f'STAGING_S3_HTTP_{status}')
        return ET.fromstring(base64.b64decode(body, validate=True))

    try:
        inspect()
        started = True
        docker('start', cid)
        state = inspect()
        need(state['Running'] and state['Pid'] > 0, 'STAGING_CONTAINER_START')
        net = os.open(f"/proc/{state['Pid']}/ns/net", os.O_RDONLY)
        need(inspect()['Pid'] == state['Pid'], 'STAGING_NAMESPACE_CHANGED')
        report['loopbackOnlyVerified'] = True
        for _ in range(20):
            listed = get('/')
            if listed is not None:
                break
            time.sleep(1)
        need(listed is not None, 'STAGING_S3_READY_TIMEOUT')
        buckets = [b.text for b in listed.findall('{*}Buckets/{*}Bucket/{*}Name')]
        need(listed.tag.rsplit('}', 1)[-1] == 'ListAllMyBucketsResult'
             and len(buckets) == 2 and set(buckets) == set(expected), 'STAGED_BUCKET_SET')
        for bucket in sorted(buckets):
            doc = get('/' + bucket + '?list-type=2&max-keys=1000&encoding-type=url')
            need(doc is not None and doc.tag.rsplit('}', 1)[-1] == 'ListBucketResult'
                 and doc.findtext('{*}IsTruncated') == 'false', 'STAGED_LIST_INCOMPLETE')
            items = [(item.findtext('{*}Key'), int(item.findtext('{*}Size'))) for item in doc.findall('{*}Contents')]
            if doc.findtext('{*}EncodingType') == 'url':
                items = [(unquote(key, errors='strict'), size) for key, size in items]
            need(len(items) == len(expected[bucket]) and set(items) == expected[bucket], 'STAGED_KEY_SET')
            report['objectsListed'] += len(items)
        report['bucketsListed'] = len(buckets)
    finally:
        if net is not None:
            os.close(net)
        if started and inspect()['Running']:
            docker('stop', '--time=15', cid, timeout=23)
        docker('rm', cid)
        report['stagingContainerRemoved'] = True

    need(not docker('ps', '-q'), 'OTHER_CONTAINERS_RUNNING_AFTER_STAGING')
    report['status'] = 'ISOLATED_OCI33_STAGE_READY'
    h['new'](SCOPE / 'result.json', h['canonical'](report))


def main():
    report = {'schema': SCHEMA, 'status': 'HELD', 'stagedDataVerified': False,
              'stagingContainerRemoved': False, 'objectsListed': 0, 's3GetRequests': 0,
              'commonCutProven': False, 'productionObjectsMigrated': 0, 'acceptanceCreditAdded': 0}
    try:
        stage(report)
    except Exception as exc:
        report['status'] = 'HELD'
        reason = str(exc)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]{5,70}', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'ISOLATED_OCI33_STAGE_READY')


if __name__ == '__main__':
    raise SystemExit(main())
