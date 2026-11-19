#!/usr/bin/env python3
"""Install exact qualified tools only. Never invokes Docker, stop or capture."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import urllib.request

COMMIT = 'd57e127ddf244f6bd9218abb7f60c67b418a20b4'
FILES = [
    ('scripts/storage-cold-backup-v4.py', '/var/lib/ouf-storage-cold-backup-v4.py', 4095,
     '8786a65a8bcde2706a3dc05a96a60ad04682cab6baa697e286b2dc525b17b3b9'),
    ('scripts/storage-test-cold-stop.py', '/var/lib/ouf-storage-test-cold-stop-20261106.py', 15186,
     'b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5'),
    ('tools/storage_planning/cold_stop_proposal.py', '/var/lib/ouf-storage-stop-planner-20261106.py', 7161,
     '121f998eabb7f09b00d6e2cc22bbeaa49c78cec3b535f02c46e57e6eb9c71e68'),
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
    print(json.dumps({'schema': 'ouf.storage-test-cold-stop-installation.v1',
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
