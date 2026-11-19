#!/usr/bin/env python3
"""Install exact qualified tools only. Never invokes host or Docker actions, stop or capture."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import urllib.request

COMMIT = '0e1c3bdb587b3d6e8a360f8f9a7af4dd3a4b97ac'
FILES = [('scripts/read-storage-cold-event-held-20261107.py', '/var/lib/ouf-storage-cold-event-reader-20261107.py', 15318, '3d96e397c3331c4ab17c32a517338f56135c7d9c9120e236be2295af30ff794a'),
         ('scripts/capture-storage-after-held-stop-20261107.py', '/var/lib/ouf-storage-capture-after-held-stop-20261107.py', 11182, '583a5e26ab18bfdb09d868fb3d7fabd9acf347f64dbf01b8caf0bf8cbec80184')]


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
    exact('/var/lib/ouf-storage-host-containment-fixed-20261106.py', 21751,
          '05f4e5166a4818d6d6b5a33651e4d4d39888245b2ebe0a3d1ae07a9c28a148ec')
    exact('/var/lib/ouf-storage-test-cold-stop-20261106.py', 15186,
          'b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5')
    exact('/var/lib/ouf-storage-host-bound-cold-backup-20261107.py', 14686,
          'ef76ef3efbbad2caebbfbabbb5c6d40a00fd5cbe09e486cb6ed94e43903af53d')
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
    print(json.dumps({'schema': 'ouf.storage-capture-after-held-stop-installation.v1',
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
