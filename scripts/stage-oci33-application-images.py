#!/usr/bin/env python3
"""Stage the exact tested Onboarding image and locate the retained UDP image."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit
from urllib.request import urlopen
import zipfile

SCHEMA = 'ouf.storage-oci33-application-images.v1'
STAGE = Path('/var/lib/ouf-storage-migration/seaweedfs/staging-oci33-20261107-v1')
SCOPE = STAGE / 'application-images-v1'
TESTED = '69b099b04f1823b127ef4af4a9c44861ff4cdc67'
REVIEWED = 'd5155899b09dda298494b68cefa7e1f281167652'
TREE = '78f1771f9188d8f3010f7db0d745275a86833019'
TAG = 'ouf-source-onboarding:' + TESTED
ONBOARDING = 'sha256:0a29a90a48a69a6ed757748bdac97cf029b6e7d633b6bc9a9b1d706fa00837db'
UDP = 'sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'
ZIP = (215265641, 'a87876f836b90cd597a5729cc693cc1219456f8bccd2da1eb91c4ea1e040ba73')
TAR = (215264020, 'bb9bc97f68d7f40ca64b05bf4b7d81d70ac8e36e9932fc6c3f8d37d5b5753cea')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def root_dirs(path):
    for p in (*reversed(path.parents), path):
        s = p.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'STAGING_PATH_GUARD')


def read_private(path, maximum):
    root_dirs(path.parent)
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
         and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= maximum, 'PRIVATE_FILE_GUARD')
    return path.read_bytes()


def receive(stream, destination, size, digest):
    if os.path.lexists(destination):
        root_dirs(destination.parent)
        info = destination.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == size,
             'EXISTING_ARCHIVE_METADATA')
        checksum = hashlib.sha256()
        with destination.open('rb') as f:
            while data := f.read(1 << 20):
                checksum.update(data)
        need(checksum.hexdigest() == digest, 'EXISTING_ARCHIVE_DIGEST')
        return
    temporary = destination.with_suffix(destination.suffix + '.partial')
    checksum = hashlib.sha256()
    total = 0
    with temporary.open('xb') as out:
        try:
            while data := stream.read(1 << 20):
                total += len(data)
                need(total <= size, 'ARCHIVE_SIZE_LIMIT')
                checksum.update(data)
                out.write(data)
            need(total == size and checksum.hexdigest() == digest, 'ARCHIVE_DIGEST')
            out.flush()
            os.fsync(out.fileno())
            temporary.rename(destination)
        except BaseException:
            temporary.unlink()
            raise


def raw_config(archive, mode):
    with tarfile.open(archive, mode) as t:
        manifest, = json.load(t.extractfile('manifest.json'))
        need(manifest['RepoTags'] == [TAG], 'ONBOARDING_ARCHIVE_TAG')
        member = t.getmember(manifest['Config'])
        need(member.isfile() and 0 < member.size <= 65536, 'ONBOARDING_ARCHIVE_CONFIG')
        raw = t.extractfile(member).read()
    need('sha256:' + hashlib.sha256(raw).hexdigest() == ONBOARDING, 'ONBOARDING_CONFIG_DIGEST')
    return json.loads(raw)


def run(url, report):
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'ISOLATED_ROOT_REQUIRED')
    p = STAGE / 'application-s3-v1/access-proof-v2/result.json'
    proof = json.loads(read_private(p, 8192))
    need(proof.get('status') == 'ISOLATED_OCI33_APP_BINDINGS_READY'
         and proof.get('ownBucketBodiesVerified') == 2 and proof.get('crossBucketAccessDenied') == 2
         and proof.get('tlsVerified') is True and proof.get('temporaryContainerRemoved') is True,
         'S3_BINDING_RECEIPT_REQUIRED')
    root_dirs(STAGE)
    need(shutil.disk_usage(STAGE).free >= 2 << 30, 'IMAGE_STAGING_FREE_SPACE')
    sock = Path('/run/docker.sock').stat()
    need(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o007,
         'LOCAL_DOCKER_SOCKET_REQUIRED')
    docker_base = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent']

    def docker(*args, timeout=15, allow_missing=False):
        current = Path('/run/docker.sock').stat()
        need((current.st_dev, current.st_ino, current.st_mode, current.st_uid)
             == (sock.st_dev, sock.st_ino, sock.st_mode, sock.st_uid), 'DOCKER_SOCKET_CHANGED')
        p = subprocess.run(docker_base + list(args), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, timeout=timeout)
        if allow_missing and p.returncode == 1 and b'No such image' in p.stderr:
            return None
        need(p.returncode == 0, 'DOCKER_' + '_'.join(args[:2]).upper()[:32] + '_FAILED'
             if args[0] == 'image' else 'DOCKER_' + args[0].upper() + '_FAILED')
        return p.stdout

    def inspect(name):
        raw = docker('image', 'inspect', name, allow_missing=True)
        if raw is None:
            return None
        row, = json.loads(raw)
        return row

    need(not docker('ps', '-q').strip(), 'OTHER_CONTAINERS_RUNNING')
    SCOPE.mkdir(mode=0o700, exist_ok=True)
    root_dirs(SCOPE)
    candidate = SCOPE / 'onboarding-tested.zip'
    if os.path.lexists(candidate):
        receive(None, candidate, *ZIP)
    else:
        parsed = urlsplit(url)
        need(parsed.scheme == 'https' and parsed.hostname is not None
             and parsed.hostname.endswith('.oaiusercontent.com') and parsed.path.startswith('/files/')
             and parsed.username is None and parsed.password is None, 'PRIVATE_ARTIFACT_URL_REQUIRED')
        with urlopen(url, timeout=30) as response:
            need(response.geturl() == url and response.status == 200, 'ARTIFACT_DOWNLOAD_RESPONSE')
            receive(response, candidate, *ZIP)
    report['onboardingZipVerified'] = True
    archive = SCOPE / 'onboarding-tested.tar.gz'
    with zipfile.ZipFile(candidate) as z:
        need(sorted(z.namelist()) == ['SHA256SUMS', 'image.tar.gz', 'manifest.json'], 'ARTIFACT_ZIP_LAYOUT')
        m = json.loads(z.read('manifest.json'))
        need(m['schema'] == 'ouf.onboarding-tested-image.v1' and m['reviewedSourceCommit'] == REVIEWED
             and m['testedCommit'] == TESTED and m['testedTree'] == TREE and m['imageTag'] == TAG
             and m['imageId'] == ONBOARDING and (m['archiveBytes'], m['archiveSha256']) == TAR,
             'ONBOARDING_MANIFEST_BINDING')
        with z.open('image.tar.gz') as source:
            receive(source, archive, *TAR)
    config = raw_config(archive, 'r:gz')

    def bind_image(row):
        need(row is not None and row['Config']['User'] == config['config']['User'] == '10003:10003'
             and row['Config']['Labels']['org.opencontainers.image.revision'] == TESTED
             and row['RootFS']['Layers'] == config['rootfs']['diff_ids']
             and re.fullmatch(r'sha256:[a-f0-9]{64}', row['Id']), 'LOADED_ONBOARDING_IMAGE_BINDING')
        if row['Id'] != ONBOARDING:
            saved = SCOPE / 'loaded-onboarding-proof.tar'
            need(not os.path.lexists(saved), 'ONBOARDING_PROOF_PATH_OCCUPIED')
            try:
                docker('image', 'save', '--output', str(saved), TAG, timeout=150)
                need(raw_config(saved, 'r:') == config and inspect(TAG)['Id'] == row['Id'],
                     'LOADED_ONBOARDING_CONFIG_CHANGED')
            finally:
                saved.unlink(missing_ok=True)
        return row['Id']

    row = inspect(TAG)
    if row is None:
        docker('image', 'load', '--input', str(archive), timeout=150)
        report['onboardingImageLoaded'] = True
        row = inspect(TAG)
    report['onboardingDaemonImageId'] = bind_image(row)
    report['onboardingImageBound'] = True
    udp = inspect(UDP)
    report['udpImagePresent'] = udp is not None and udp['Id'] == UDP
    need(report['udpImagePresent'], 'RETAINED_UDP_IMAGE_MISSING')
    need(not docker('ps', '-q').strip(), 'OTHER_CONTAINERS_RUNNING')
    report['status'] = 'ISOLATED_APPLICATION_IMAGES_READY'


def main():
    os.umask(0o077)
    report = {'schema': SCHEMA, 'status': 'HELD', 'onboardingZipVerified': False,
              'onboardingImageLoaded': False, 'onboardingImageBound': False, 'udpImagePresent': False,
              'applicationContainersStarted': 0, 'acceptanceCreditAdded': 0}
    try:
        run(sys.stdin.readline(2048).strip(), report)
    except Exception as exc:
        reason = str(exc)
        report['reason'] = reason if re.fullmatch(r'[A-Z][A-Z0-9_]{5,80}', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'ISOLATED_APPLICATION_IMAGES_READY')


if __name__ == '__main__':
    raise SystemExit(main())
