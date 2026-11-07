#!/usr/bin/env python3
"""Publish one verified copy of the sealed ciphertext to the existing SCP account."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys


SOURCE = Path('/var/lib/ouf-storage-migration/capture-historical-custody-20261107-v1')
TRANSFER = Path('/var/tmp/ouf-historical-transfer-20261107-v1')
NAME = 'retained-historical.tar.age'
SIZE = 6544578724
SHA256 = 'c3b0de7ab9fceb9c566431a4ed5ebf8f7720dae5eee52c1a0a5c76a5eb99a886'
MANIFEST = '58484aea53aefeb1fff390578ba6562efabffd914caf64944eee7c9d9a2e0d79'
SCHEMA = 'ouf.storage-retained-custody-scp-stage.v1'


class Held(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Held(reason)


def directory(stack, path, parent=None, sticky=False, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    need(info.st_uid == 0 and (mode & stat.S_ISVTX if sticky else not mode & 0o022)
         and (not private or mode == 0o700), 'UNPROTECTED_DIRECTORY')
    return fd


def protected_file(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=parent)
    stream = os.fdopen(fd, 'rb')
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= limit):
        stream.close()
        raise Held('UNPROTECTED_SOURCE_FILE')
    return stream


def frame(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def stage(source, transfer, uid, gid, size, digest, manifest, sticky_parent=True):
    need(uid > 0, 'NONROOT_TRANSFER_ACCOUNT_REQUIRED')
    with contextlib.ExitStack() as stack:
        root = directory(stack, '/')
        src = root
        for part in source.parts[1:-1]:
            src = directory(stack, part, src)
        src = directory(stack, source.name, src, private=True)
        with protected_file(src, 'result.json', 8192) as stream:
            receipt = json.loads(stream.read(8193))
        need(receipt.get('status') == 'HISTORICAL_CUSTODY_ARCHIVE_SEALED'
             and receipt.get('schema') == 'ouf.storage-retained-capture-custody.v1'
             and receipt.get('archive') == str(source / NAME) and receipt.get('archiveBytes') == size
             and receipt.get('archiveSha256') == digest
             and receipt.get('privateManifestSha256') == manifest, 'SEALED_RECEIPT_MISMATCH')
        parent = root
        for part in transfer.parts[1:-2]:
            parent = directory(stack, part, parent)
        parent = directory(stack, transfer.parent.name, parent, sticky=sticky_parent)
        space = os.fstatvfs(parent)
        need(space.f_bavail * space.f_frsize >= size + (64 << 20), 'TRANSFER_SPACE_REQUIRED')
        with protected_file(src, NAME, size) as original:
            info = os.fstat(original.fileno())
            need(info.st_size == size, 'SOURCE_SIZE_MISMATCH')
            try:
                os.mkdir(transfer.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                raise Held('TRANSFER_SCOPE_ALREADY_EXISTS') from None
            os.fsync(parent)
            out = directory(stack, transfer.name, parent, private=True)
            fd = os.open(NAME + '.partial', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=out)
            sha, written = hashlib.sha256(), 0
            with os.fdopen(fd, 'wb') as staged:
                while block := original.read(1 << 20):
                    written += len(block)
                    need(written <= size, 'SOURCE_SIZE_CHANGED')
                    sha.update(block)
                    staged.write(block)
                need(written == size and sha.hexdigest() == digest, 'SOURCE_DIGEST_MISMATCH')
                need(frame(info) == frame(os.fstat(original.fileno())) ==
                     frame(os.stat(NAME, dir_fd=src, follow_symlinks=False)), 'SOURCE_FILE_CHANGED')
                staged.flush()
                os.fchmod(fd, 0o400)
                os.fchown(fd, uid, gid)
                os.fsync(fd)
            os.rename(NAME + '.partial', NAME, src_dir_fd=out, dst_dir_fd=out)
            os.fsync(out)
            # This is the publication boundary. The directory was root-private until now.
            os.fchown(out, uid, gid)
            os.fsync(out)
            os.fsync(parent)
    return {'schema': SCHEMA, 'status': 'SCP_SOURCE_STAGED', 'remoteArchive': str(transfer / NAME),
            'bytes': size, 'sha256': digest, 'archiveOriginalModified': False, 'acceptanceCreditAdded': 0}


def main():
    account = pwd.getpwnam('oufadmin')
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode and os.environ.get('SUDO_UID') == str(account.pw_uid),
         'RUN_WITH_SUDO_AS_OUFADMIN')
    os.umask(0o077)
    print(json.dumps(stage(SOURCE, TRANSFER, account.pw_uid, account.pw_gid, SIZE, SHA256, MANIFEST),
                     sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Held, OSError, ValueError, KeyError, AttributeError) as error:
        reason = str(error) if isinstance(error, Held) else 'LOCAL_TRANSFER_STAGE_FAILED'
        print(json.dumps({'schema': SCHEMA, 'status': 'HELD', 'reason': reason,
                          'acceptanceCreditAdded': 0}))
        sys.exit(2)
