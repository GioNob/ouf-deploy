#!/usr/bin/env python3
"""Install pinned age once and bind a public recipient; no application/provider IO."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tarfile

ARCHIVE_SIZE = 19405817
ARCHIVE_SHA = 'cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10'
AREA = Path('/var/lib/ouf-storage-cipher-preparation-20261106')
AGE = Path('/usr/bin/age')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def protected_directory(path):
    for p in [path, *path.parents]:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('PROTECTED_DIRECTORY_REQUIRED')


def create(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fchmod(f.fileno(), mode)
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def binary_from_archive(data):
    if len(data) != ARCHIVE_SIZE or digest(data) != ARCHIVE_SHA:
        raise ValueError('PINNED_ARCHIVE_MISMATCH')
    # Never extract paths from the tar. Read only the exact regular binary member.
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
        members = [m for m in tf.getmembers() if m.name == 'age/age']
        if len(members) != 1 or not members[0].isreg() or not 0 < members[0].size <= 67108864:
            raise ValueError('EXACT_REGULAR_AGE_MEMBER_REQUIRED')
        body = tf.extractfile(members[0]).read(67108865)
        if len(body) != members[0].size:
            raise ValueError('AGE_MEMBER_SIZE_MISMATCH')
        return body


def recipient_bytes(recipient, expected):
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}', recipient):
        raise ValueError('ED25519_PUBLIC_RECIPIENT_REQUIRED')
    raw = base64.b64decode(recipient.split()[1], validate=True)
    if len(raw) != 51 or raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('INVALID_ED25519_PUBLIC_KEY')
    data = (recipient + '\n').encode('ascii')
    if digest(data) != expected:
        raise ValueError('RECIPIENT_DIGEST_MISMATCH')
    return data


def prepare(archive_path, recipient, expected, area=AREA, age=AGE):
    if os.geteuid() != 0 or platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('ROOT_LINUX_AMD64_REQUIRED')
    public = recipient_bytes(recipient, expected)
    protected_directory(area.parent)
    protected_directory(age.parent)
    if os.path.lexists(area) or os.path.lexists(age):
        raise ValueError('EXISTING_PATH_PRESERVED_NO_REPLAY')
    # The user-owned download is read once, then authenticated before any execution/write.
    fd = os.open(archive_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size != ARCHIVE_SIZE:
            raise ValueError('BOUNDED_REGULAR_ARCHIVE_REQUIRED')
        binary = binary_from_archive(f.read(ARCHIVE_SIZE + 1))
    area.mkdir(mode=0o700)
    create(area / 'claim.json', json.dumps({'schema': 'ouf.storage-backup-cipher-claim.v1',
           'recipientFileSha256': expected, 'ageArchiveSha256': ARCHIVE_SHA,
           'automaticReplayAllowed': False}).encode() + b'\n')
    create(age, binary, 0o755)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(area), 'LANG': 'C'}
    version = subprocess.run([str(age), '--version'], env=env, capture_output=True,
                             check=True, timeout=10).stdout.decode().strip()
    if version != 'v1.3.2':
        raise ValueError('AGE_VERSION_MISMATCH')
    create(area / 'recipient.pub', public)
    probe = os.urandom(512)
    create(area / 'probe.bin', probe)
    cipher = subprocess.run([str(age), '-R', str(area / 'recipient.pub')], input=probe,
                            env=env, capture_output=True, check=True, timeout=15).stdout
    if not 512 < len(cipher) < 4096:
        raise ValueError('CIPHERTEXT_SIZE_UNEXPECTED')
    create(area / 'probe.bin.age', cipher)
    result = {
        'schema': 'ouf.storage-backup-linux-cipher.v1',
        'status': 'LINUX_CIPHER_PREPARED_WINDOWS_DECRYPT_REQUIRED',
        'ageVersion': version, 'ageArchiveSha256': ARCHIVE_SHA,
        'ageBinarySha256': digest(binary), 'recipientFileSha256': expected,
        'probeBytes': len(probe), 'probeSha256': digest(probe),
        'ciphertextBytes': len(cipher), 'ciphertextSha256': digest(cipher),
        'ciphertextBase64': base64.b64encode(cipher).decode('ascii'),
        'privateKeyRead': False, 'applicationDataReads': 0, 'providerRequests': 0,
        'targetCapturePerformed': False, 'crossPlatformDecryptProven': False,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
        'acceptanceCreditAdded': 0,
    }
    create(area / 'result.json', (json.dumps(result, sort_keys=True) + '\n').encode())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--recipient', required=True)
    parser.add_argument('--recipient-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = prepare(args.archive, args.recipient, args.recipient_sha256)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as e:
        # No paths, input key or captured child stderr in the public diagnostic.
        reason = str(e) if isinstance(e, ValueError) else type(e).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason,
                          'partialFilesPreserved': True, 'automaticReplayAllowed': False,
                          'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
