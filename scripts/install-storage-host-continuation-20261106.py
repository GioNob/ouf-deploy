#!/usr/bin/env python3
"""Install exact qualified tools only. Never invokes host continuation, Docker, stop or capture."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import urllib.request

COMMIT = '7887bf88a20d776745e6bb3e09158ecd6a712ff2'
FILES = [('scripts/storage-host-containment-20261106.py', '/var/lib/ouf-storage-host-containment-fixed-20261106.py', 21751, '05f4e5166a4818d6d6b5a33651e4d4d39888245b2ebe0a3d1ae07a9c28a148ec'), ('scripts/continue-storage-host-containment-20261106.py', '/var/lib/ouf-storage-host-continuation-20261106.py', 9124, '5522fde506a439651a923f929bed5d13fe3029a2be508fcebe0c1ec956e5c2c5')]


def need(condition, reason):
    if not condition: raise ValueError(reason)


def exact(path, size, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == size, 'INSTALLED_METADATA')
        need(hashlib.sha256(f.read(size + 1)).hexdigest() == digest, 'INSTALLED_DIGEST')


def main():
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and
         sys.dont_write_bytecode, 'ROOT_ISOLATED_PYTHON_REQUIRED')
    os.umask(0o077)
    for p in (Path('/'), Path('/var'), Path('/var/lib')):
        s = p.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROTECTED_ANCESTRY')
    exact('/var/lib/ouf-storage-cold-backup-v3.py', 32524,
          'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac')
    exact('/var/lib/ouf-storage-host-containment-20261106.py', 20994,
          '6d5e41d71150c8e59394002473e6eee728981f540bad94a09fd633f493004004')
    payloads, existing = {}, 0
    for source, destination, size, digest in FILES:
        if os.path.lexists(destination):
            exact(destination, size, digest)
            existing += 1
        else:
            url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/' + COMMIT + '/' + source
            with urllib.request.urlopen(url, timeout=30) as response:
                raw = response.read(size + 1)
            need(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, 'DOWNLOAD_DIGEST')
            payloads[destination] = raw
    for destination, raw in payloads.items():
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    fd = os.open('/var/lib', os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    for _, destination, size, digest in FILES: exact(destination, size, digest)
    print(json.dumps({'schema': 'ouf.storage-host-continuation-installation.v1',
        'status': 'PINNED_TOOLS_INSTALLED_NO_STOP_OR_CAPTURE', 'filesInstalled': len(payloads),
        'exactExistingFilesReused': existing, 'providerRequests': 0, 'legacyPlanModified': False,
        'runtimeAuthorityIssued': False, 'targetStopPerformed': False, 'targetCapturePerformed': False,
        'acceptanceCreditAdded': 0}))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'status': 'HELD', 'reason': str(error) if isinstance(error, ValueError) else type(error).__name__,
            'partialInstallationPreserved': True, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
