"""Resolve non-root image identities from verified ordered layer bytes, without extraction."""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time

ROOT = Path('/home/oufadmin/ouf-crypto-v2.zjJNdo')
ROLES = {
    'adapter': ('8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207', '62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320'),
    'southbound': ('1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641', 'd4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04'),
}

def require(ok):
    if not ok:
        raise ValueError('ROLE_ACCOUNT_UNPROVEN')

def path(value):
    require(type(value) is str and len(value) <= 4096 and '\x00' not in value)
    p = PurePosixPath(value)
    require(not p.is_absolute() and '..' not in p.parts)
    return str(p)

def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result); result[key] = value
        return result
    require(0 < len(raw) <= 131072)
    return json.loads(raw, object_pairs_hook=unique)

class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + 150
        self.bytes = self.entries = 0
    def check(self, size=0, entry=False):
        self.bytes += size; self.entries += int(entry)
        require(time.monotonic() < self.deadline and self.bytes <= 8589934592 and self.entries <= 100000)

class Reader:
    def __init__(self, stream, budget, prefix=b''):
        self.stream, self.budget, self.prefix = stream, budget, prefix
        self.hash = hashlib.sha256(); self.size = 0
    def read(self, size):
        require(type(size) is int and 0 <= size <= 131072)
        take, self.prefix = self.prefix[:size], self.prefix[size:]
        raw = take + self.stream.read(size-len(take))
        self.budget.check(len(raw)); self.hash.update(raw); self.size += len(raw)
        return raw
    def drain(self):
        while self.read(65536):
            pass

def small(stream):
    parts = []
    size = 0
    while chunk := stream.read(min(65536, 131073-size)):
        parts.append(chunk); size += len(chunk); require(size <= 131072)
    return b''.join(parts)

def layer(stream, prefix, budget):
    source = Reader(stream, budget, prefix)
    if prefix[:2] == b'\x1f\x8b':
        source = gzip.GzipFile(fileobj=source)
    plain = Reader(source, budget)
    seen, accounts, whiteouts = set(), {}, []
    with tarfile.open(fileobj=plain, mode='r|') as archive:
        for item in archive:
            budget.check(entry=True); name = path(item.name)
            require(name not in seen and item.size >= 0); seen.add(name)
            base, parent = PurePosixPath(name).name, str(PurePosixPath(name).parent)
            if base.startswith('.wh.'):
                require(item.isfile() and item.size == 0)
                whiteouts.append((parent if base == '.wh..wh..opq' else path(str(PurePosixPath(parent)/base[4:])), base == '.wh..wh..opq'))
            elif name == 'etc':
                require(item.isdir())
            elif name in ('etc/passwd', 'etc/group'):
                require(item.isfile() and item.size <= 131072)
                accounts[name] = small(archive.extractfile(item))
            archive.members.clear()
    plain.drain()
    return {'diffId': 'sha256:'+plain.hash.hexdigest(), 'accounts': accounts, 'whiteouts': whiteouts}

def overlay(layers):
    final = {}
    for row in layers:
        for target, opaque in row['whiteouts']:
            prefix = '' if target == '.' else target+'/'
            for name in list(final):
                if (name == target and not opaque) or name.startswith(prefix):
                    final.pop(name)
        final.update(row['accounts'])
    return final

def identity(user, files):
    require(type(user) is str and 0 < len(user) <= 128)
    parts = user.split(':'); require(1 <= len(parts) <= 2 and all(parts))
    passwd = files.get('etc/passwd', b'').decode('utf-8').splitlines()
    groups = files.get('etc/group', b'').decode('utf-8').splitlines()
    parsed = [row.split(':') for row in passwd if row and not row.startswith('#')]
    require(all(len(row) == 7 for row in parsed))
    if parts[0].isdigit():
        uid = int(parts[0]); matches = [row for row in parsed if row[2].isdigit() and int(row[2]) == uid]
    else:
        matches = [row for row in parsed if row[0] == parts[0]]
        require(len(matches) == 1 and matches[0][2].isdigit()); uid = int(matches[0][2])
    if len(parts) == 2 and parts[1].isdigit():
        gid = int(parts[1])
    elif len(parts) == 2:
        rows = [row.split(':') for row in groups if row and not row.startswith('#')]
        matches_g = [row for row in rows if len(row) == 4 and row[0] == parts[1] and row[2].isdigit()]
        require(len(matches_g) == 1); gid = int(matches_g[0][2])
    else:
        require(len(matches) == 1 and matches[0][3].isdigit()); gid = int(matches[0][3])
    require(1 <= uid <= 2147483647 and 1 <= gid <= 2147483647)
    return {'uid': uid, 'gid': gid, 'runtimeUser': f'{uid}:{gid}'}

def inspect_stream(stream, archive_hash, config_hash):
    require(hashlib.file_digest(stream, 'sha256').hexdigest() == archive_hash); stream.seek(0)
    budget = Budget(); blobs = {}; manifest = None; names = set()
    with gzip.GzipFile(fileobj=stream) as plain, tarfile.open(fileobj=plain, mode='r|') as archive:
        for item in archive:
            budget.check(entry=True); name = path(item.name)
            require(name not in names); names.add(name)
            if item.isdir():
                continue
            require(item.isfile() and 0 <= item.size <= 8589934592 and len(blobs) < 512)
            incoming = Reader(archive.extractfile(item), budget)
            prefix = incoming.read(min(512, item.size))
            if name == 'manifest.json' or prefix.lstrip().startswith((b'{', b'[')):
                doc = decode(prefix+small(incoming)); row = {'json': doc}
                if name == 'manifest.json':
                    manifest = doc
            elif name.endswith('/VERSION'):
                require(prefix+small(incoming) == b'1.0'); row = {}
            else:
                row = layer(incoming, prefix, budget)
            incoming.drain(); require(incoming.size == item.size)
            row['hash'] = incoming.hash.hexdigest(); blobs[name] = row
            if name.startswith('blobs/sha256/'):
                require(name == 'blobs/sha256/'+row['hash'])
            archive.members.clear()
    require(type(manifest) is list and len(manifest) == 1)
    item = manifest[0]; cfg_row = blobs[path(item['Config'])]; cfg = cfg_row['json']
    require(cfg_row['hash'] == config_hash and cfg['os'] == 'linux' and cfg['architecture'] == 'amd64')
    names = item['Layers']; diffs = cfg['rootfs']['diff_ids']
    require(cfg['rootfs']['type'] == 'layers' and type(names) is list and 1 <= len(names) <= 256 and len(names) == len(diffs) and len(set(names)) == len(names))
    layers = [blobs[path(name)] for name in names]
    require(all(re.fullmatch(r'sha256:[0-9a-f]{64}', expected) and row['diffId'] == expected for row, expected in zip(layers, diffs)))
    files = overlay(layers)
    return {**identity(cfg['config']['User'], files), 'packagedUser': cfg['config']['User'], 'layerCount': len(layers), 'accountFilesHash': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}, 'layerBytesVerified': True}

def inspect(role):
    archive_hash, config_hash = ROLES[role]; filename = ROOT/(role+'.image.tar.gz')
    fd = os.open(filename, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 536870912)
        result = inspect_stream(incoming, archive_hash, config_hash)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(tuple(getattr(before, k) for k in fields) == tuple(getattr(os.fstat(incoming.fileno()), k) for k in fields) == tuple(getattr(filename.lstat(), k) for k in fields))
    return {'role': role, 'imageId': 'sha256:'+config_hash, **result}

def main():
    try:
        print('OUF_PROVIDER_ROLE_ACCOUNTS='+json.dumps({'schema': 'ouf.discovery.provider-role-accounts.v1', 'roles': [inspect(role) for role in ROLES], 'filesExtracted': 0, 'imageImportPerformed': False, 'containerLifecycleOperations': 0, 'secretValuesPrinted': False, 'acceptanceGranted': False, 'startAuthorized': False}, sort_keys=True))
        return 0
    except Exception:
        print('OUF_PROVIDER_ROLE_ACCOUNTS=BLOCKED NO_RAW_OUTPUT=true'); return 1

if __name__ == '__main__':
    raise SystemExit(main())
