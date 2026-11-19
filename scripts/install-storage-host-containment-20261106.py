#!/usr/bin/env python3
"""Install exact qualified tools only. Never invokes host containment, Docker, stop or capture."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import urllib.request

COMMIT = 'c742943800252099c56ac60ef448b712d9d007f3'
FILES = [
    ('scripts/prepare-storage-host-containment-20261106.py', '/var/lib/ouf-storage-host-preparation-reader-20261106.py', 18228,
     'caac2981e43b96150bc0875405facfc4cb34ad8b188adc210e4ed214bb5bf5b1'),
    ('scripts/storage-host-containment-20261106.py', '/var/lib/ouf-storage-host-containment-20261106.py', 20994,
     '6d5e41d71150c8e59394002473e6eee728981f540bad94a09fd633f493004004'),
]


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
    print(json.dumps({'schema': 'ouf.storage-host-containment-installation.v1',
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
