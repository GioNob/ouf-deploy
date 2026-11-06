#!/usr/bin/env python3
"""Prepare and capture an OFFLINE recovery set. Never stops or starts services.

This root-operated maintenance utility is not an OUF HUMAN/THS authority issuer.
Its capture command requires separately approved containment and window. A plan
digest/decision reference records the invocation; neither authenticates approval.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

BASE = Path('/var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.review.json')
BASE_SHA = 'dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e'
AREA = Path('/var/lib/ouf-storage-migration/cold-backup-20261106-v1')
ETCD_ID = 'e1ae2262714c841c7fec72d911221191bf69a892434a7c59da1aed8b53afa88f'
ETCD_IMAGE = 'sha256:a3ccd299377af4b9968d8cbaaf9722fe354297f11908f74a846075e1e5f4ee89'
ROLES = {'apisix', 'caddy', 'gateway-owner', 'ingestion', 'ingestion-evidence-read',
         'keycloak', 'mcp', 'minio', 'onboarding', 'postgres', 'semantic', 'udp', 'udp-evidence-read'}
LIMIT = 64 << 30
MAX_FILES = 100000
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


class Held(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Held(code)


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs)


def frame(s):
    return tuple(getattr(s, k) for k in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def protected(path, private=False, limit=32 << 20):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(path), 'CANONICAL_PATH_REQUIRED')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = nxt
            s = os.fstat(parent)
            need(s.st_uid == 0 and not s.st_mode & 0o022, 'PROTECTED_INPUT_ANCESTRY_REQUIRED')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and not before.st_mode & 0o022 and 0 < before.st_size <= limit, 'PROTECTED_REGULAR_INPUT_REQUIRED')
        if private:
            need(stat.S_IMODE(before.st_mode) == 0o600, 'PRIVATE_INPUT_REQUIRED')
        raw = os.read(fd, limit + 1)
        need(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd))
             and before.st_ino == os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_ino,
             'INPUT_CHANGED')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    d = os.open(Path(path).parent, os.O_DIRECTORY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


class Runner:
    def __init__(self, area, seconds=3600):
        self.area = Path(area)
        self.until = time.monotonic() + seconds
        self.calls = 0
        self.total = 0
        self.config = self.area / 'docker-client'
        self.config.mkdir(mode=0o700)
        self.socket = Path('/run/docker.sock').stat()
        need(stat.S_ISSOCK(self.socket.st_mode) and self.socket.st_uid == 0
             and not self.socket.st_mode & 0o007, 'ROOT_ENGINE_SOCKET_REQUIRED')

    def check(self):
        need(time.monotonic() < self.until and self.calls < 256 and self.total <= LIMIT,
             'CAPTURE_BUDGET_EXHAUSTED')
        now = Path('/run/docker.sock').stat()
        need((now.st_dev, now.st_ino, now.st_uid, now.st_mode) ==
             (self.socket.st_dev, self.socket.st_ino, self.socket.st_uid, self.socket.st_mode), 'ENGINE_SOCKET_CHANGED')
        need(shutil.disk_usage(self.area).free > 1 << 30, 'FREE_SPACE_FLOOR')

    def run(self, argv, output=None, cap=32 << 20, timeout=120):
        self.check()
        self.calls += 1
        target = output or self.area / ('command-%03d.private' % self.calls)
        err = self.area / ('command-%03d.stderr.private' % self.calls)
        cap = min(cap, LIMIT - self.total)
        need(cap > 0, 'BYTE_BUDGET_EXHAUSTED')
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
        with open(target, 'xb') as out, open(err, 'xb') as error:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=error,
                                 env=ENV, start_new_session=True, preexec_fn=limits)
            deadline = min(self.until, time.monotonic() + timeout)
            try:
                while p.poll() is None:
                    need(time.monotonic() < deadline, 'CHILD_TIMEOUT')
                    self.check()
                    need(self.total + target.stat().st_size + err.stat().st_size <= LIMIT, 'BYTE_BUDGET_EXHAUSTED')
                    time.sleep(0.2)
                need(p.returncode == 0, 'COMMAND_FAILED_%03d' % self.calls)
                out.flush()
                os.fsync(out.fileno())
            finally:
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=5)
                self.total += target.stat().st_size + err.stat().st_size
        if output is None:
            return target.read_bytes()

    def docker(self, *args, **kw):
        # Explicit local endpoint and empty config: never use caller contexts or credentials.
        return self.run(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', str(self.config), *args], **kw)

    def inventory(self, selected_ids):
        ids = self.docker('ps', '-aq', '--no-trunc').decode().split()
        need(0 < len(ids) <= 192 and len(set(ids)) == len(ids)
             and all(re.fullmatch('[a-f0-9]{64}', x) for x in ids), 'HOST_CONTAINER_LIMIT_OR_ID')
        need(set(selected_ids) <= set(ids), 'BOUND_CONTAINER_MISSING')
        docs = decode(self.docker('inspect', *sorted(selected_ids)))
        others = sorted(set(ids) - set(selected_ids))
        if others:
            fmt = '{"Id":{{json .Id}},"Mounts":{{json .Mounts}},"State":{{json .State}},"HostConfig":{"RestartPolicy":{{json .HostConfig.RestartPolicy}}}}'
            docs += [decode(line) for line in self.docker('inspect', '--format', fmt, *others).splitlines()]
        need(len(docs) == len(ids) and {d['Id'] for d in docs} == set(ids), 'INVENTORY_INCOMPLETE')
        return {d['Id']: d for d in docs}


def fingerprint(doc):
    # Stop and restart=no are the ONLY expected changes between plan and capture.
    host = dict(doc['HostConfig'])
    host.pop('RestartPolicy', None)
    return digest(canonical({k: doc.get(k) for k in ('Id', 'Image', 'Config', 'Mounts', 'Path', 'Args')} |
                            {'HostConfig': host, 'StartedAt': doc['State']['StartedAt']}))


def overlap(a, b):
    return a == b or a.startswith(b.rstrip('/') + '/') or b.startswith(a.rstrip('/') + '/')


def source_path(value):
    p = Path(value)
    need(p.is_absolute() and str(p) == os.path.normpath(p) and len(p.parts) >= 3,
         'UNSAFE_OR_BROAD_MOUNT_SOURCE')
    need(not any(overlap(str(p), x) for x in ('/proc', '/sys', '/dev', '/run', '/tmp')),
         'EPHEMERAL_OR_DEVICE_MOUNT_REQUIRES_REVIEW')
    current = Path('/')
    for part in p.parts[1:]:
        current /= part
        need(not current.is_symlink(), 'SYMLINK_MOUNT_ANCESTRY')
    need(p.is_dir() or p.is_file(), 'MOUNT_SOURCE_NOT_REGULAR')
    return p


def build_plan(bindings, host, area, program_sha):
    ids = {v['containerId'] for v in bindings.values()}
    need(len(ids) == len(bindings) and ids <= host.keys(), 'BOUND_CONTAINER_MISSING_OR_DUPLICATE')
    need(all(not d['State']['Running'] or i in ids for i, d in host.items()), 'UNBOUND_RUNNING_CONTAINER')
    roots = set()
    roles = {}
    for role, bound in sorted(bindings.items()):
        d = host[bound['containerId']]
        need(d['Image'] == bound['nativeImage'], 'BOUND_IMAGE_CHANGED')
        need(not d['HostConfig'].get('AutoRemove') and not d['State'].get('Paused')
             and not d['State'].get('Restarting') and not (d['Config'].get('Labels') or {}).get('com.docker.swarm.service.id'),
             'UNSUPPORTED_LIFECYCLE')
        need(set(d['HostConfig'].get('Tmpfs') or {}) <= {'/tmp', '/run', '/var/run'},
             'NON_SCRATCH_TMPFS_REQUIRES_RESTORE_REVIEW')
        for m in d['Mounts']:
            if m['Type'] == 'tmpfs' and m['Destination'] in ('/tmp', '/run', '/var/run'):
                continue
            need(m['Type'] in ('bind', 'volume') and (m['Type'] != 'volume' or m.get('Driver') == 'local'),
                 'UNSUPPORTED_MOUNT_DRIVER')
            p = source_path(m['Source'])
            need(not overlap(str(p), str(area)), 'BACKUP_INSIDE_SOURCE')
            roots.add(str(p))
        roles[role] = {'containerId': d['Id'], 'nativeImage': d['Image'], 'fingerprint': fingerprint(d),
                       'originalRestartPolicy': d['HostConfig']['RestartPolicy'], 'wasRunning': d['State']['Running']}
    # Do not silently duplicate or omit nested mounted state.
    roots = sorted(p for p in roots if not any(p != q and p.startswith(q.rstrip('/') + '/') for q in roots))
    for cid, d in host.items():
        if cid not in ids:
            need(not any(overlap(m.get('Source', '/__no_source__'), p) for m in d['Mounts'] for p in roots),
                 'NON_ROSTER_CONTAINER_SHARES_CAPTURE_SOURCE')
    need(0 < len(roots) <= 64, 'PERSISTENT_SOURCE_COUNT_LIMIT')
    return {'schema': 'ouf.storage-cold-backup-plan.v1', 'createdEpoch': int(time.time()),
            'validUntilEpoch': int(time.time()) + 86400, 'programSha256': program_sha,
            'roles': roles, 'sources': roots, 'maximumSeconds': 3600, 'maximumProducedBytes': LIMIT,
            'maximumCommandCalls': 256, 'maximumHostContainers': 192,
            'includesWholeSharedPostgresCluster': True, 'runtimeMutationCommands': [],
            'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
            'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}


def offline(plan, host):
    ids = {r['containerId'] for r in plan['roles'].values()}
    need(all(not d['State']['Running'] for d in host.values()), 'RUNNING_CONTAINER_DURING_OFFLINE_CAPTURE')
    for r in plan['roles'].values():
        need(r['containerId'] in host, 'BOUND_CONTAINER_MISSING')
        d = host[r['containerId']]
        need(fingerprint(d) == r['fingerprint'], 'BOUND_CONFIG_OR_PROCESS_GENERATION_CHANGED')
        need(d['State']['Status'] == 'exited' and d['State']['Pid'] == 0
             and d['State']['ExitCode'] == 0 and not d['State'].get('OOMKilled')
             and not d['State'].get('Error') and not d['State']['Paused']
             and not d['State']['Restarting'], 'CLEAN_STOP_REQUIRED')
        need(d['HostConfig']['RestartPolicy']['Name'] == 'no', 'RESTART_POLICY_MUST_ALREADY_BE_DISABLED')
    for cid, d in host.items():
        if cid not in ids:
            need(not any(overlap(m.get('Source', '/__no_source__'), p) for m in d['Mounts'] for p in plan['sources']),
                 'NON_ROSTER_CONTAINER_SHARES_CAPTURE_SOURCE')


def tree_manifest(root, until):
    """Hash every source byte; preserve symlinks only inside the same captured root."""
    root = source_path(root)
    result = []
    paths = [root]
    if root.is_dir():
        for parent, dirs, files in os.walk(root, followlinks=False):
            paths.extend(Path(parent) / n for n in sorted(dirs + files))
            need(len(paths) <= MAX_FILES and time.monotonic() < until, 'SOURCE_SCAN_BUDGET')
    for p in sorted(paths):
        need(time.monotonic() < until, 'SOURCE_SCAN_TIMEOUT')
        s = p.lstat()
        need(s.st_dev == root.stat().st_dev, 'NESTED_FILESYSTEM_REQUIRES_REVIEW')
        row = {'path': '.' if p == root else str(p.relative_to(root)), 'mode': s.st_mode,
               'uid': s.st_uid, 'gid': s.st_gid, 'size': s.st_size,
               'mtimeNs': s.st_mtime_ns, 'ctimeNs': s.st_ctime_ns, 'inode': s.st_ino,
               'xattrs': {n: base64.b64encode(os.getxattr(p, n, follow_symlinks=False)).decode()
                          for n in sorted(os.listxattr(p, follow_symlinks=False))}}
        if stat.S_ISREG(s.st_mode):
            h = hashlib.sha256()
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                while block := f.read(1 << 20):
                    need(time.monotonic() < until, 'SOURCE_HASH_TIMEOUT')
                    h.update(block)
                need(frame(os.fstat(f.fileno())) == frame(s), 'SOURCE_CHANGED_WHILE_HASHING')
            row['sha256'] = h.hexdigest()
        elif stat.S_ISLNK(s.st_mode):
            target = p.resolve()
            need(target.is_relative_to(root) and target.exists(), 'EXTERNAL_OR_DANGLING_SOURCE_SYMLINK')
            row['link'] = os.readlink(p)
        else:
            need(stat.S_ISDIR(s.st_mode), 'SPECIAL_FILE_IN_SOURCE')
        need(frame(s) == frame(p.lstat()), 'SOURCE_CHANGED_WHILE_SCANNING')
        result.append(row)
    return result


def hash_file(path, until):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while b := f.read(1 << 20):
            need(time.monotonic() < until, 'HASH_TIMEOUT')
            h.update(b)
    return h.hexdigest()


def verify_source_archive(archive, basename, expected, until):
    remaining = {r['path']: r for r in expected}
    with tarfile.open(archive, 'r:') as tf:
        for member in tf:
            need(time.monotonic() < until, 'ARCHIVE_VALIDATION_TIMEOUT')
            path = Path(member.name)
            need(path.parts and path.parts[0] == basename and '..' not in path.parts,
                 'ARCHIVE_MEMBER_OUTSIDE_SOURCE')
            rel = str(Path(*path.parts[1:])) if len(path.parts) > 1 else '.'
            need(rel in remaining, 'ARCHIVE_MEMBER_EXTRA_OR_DUPLICATE')
            row = remaining.pop(rel)
            need(member.uid == row['uid'] and member.gid == row['gid']
                 and member.mode == stat.S_IMODE(row['mode']), 'ARCHIVE_METADATA_MISMATCH')
            if stat.S_ISREG(row['mode']):
                need(member.isfile() or member.islnk(), 'ARCHIVE_FILE_TYPE_MISMATCH')
                f = tf.extractfile(member)
                h = hashlib.sha256()
                size = 0
                while block := f.read(1 << 20):
                    need(time.monotonic() < until, 'ARCHIVE_VALIDATION_TIMEOUT')
                    h.update(block)
                    size += len(block)
                need(size == row['size'] and h.hexdigest() == row['sha256'], 'ARCHIVE_CONTENT_MISMATCH')
            elif stat.S_ISLNK(row['mode']):
                need(member.issym() and member.linkname == row['link'], 'ARCHIVE_SYMLINK_MISMATCH')
            else:
                need(member.isdir(), 'ARCHIVE_DIRECTORY_MISMATCH')
    need(not remaining, 'ARCHIVE_MEMBER_MISSING')


def recipient(raw):
    lines = raw.decode('ascii').strip().splitlines()
    need(len(lines) == 1 and len(lines[0]) < 4096, 'EXACTLY_ONE_PUBLIC_RECIPIENT_REQUIRED')
    line = lines[0]
    need(re.fullmatch(r'age1[0-9a-z]{58}', line) or re.fullmatch(r'ssh-(rsa|ed25519) [A-Za-z0-9+/=]+(?: [^\r\n]+)?', line),
         'SUPPORTED_PUBLIC_RECIPIENT_REQUIRED')
    return line


def capture(plan, plan_sha, root, run, public_recipient, decision_reference):
    need(digest(canonical(plan)) == plan_sha and time.time() <= plan['validUntilEpoch'], 'PLAN_HASH_OR_EXPIRY')
    need(re.fullmatch('[A-Za-z0-9_.:-]{1,128}', decision_reference), 'DECISION_REFERENCE_REQUIRED')
    # Claim precedes any provider/export call; restart cannot adopt this attempt.
    new(root / 'capture-claim.private.json', canonical({'planSha256': plan_sha, 'decisionReference': decision_reference,
        'recipientSha256': digest(public_recipient.encode()), 'attempts': 1, 'authorityAuthenticatedByThisUtility': False}))
    started = str(time.time())
    ids = {r['containerId'] for r in plan['roles'].values()}
    host = run.inventory(ids)
    offline(plan, host)
    payload = root / 'payload'
    payload.mkdir(mode=0o700)
    new(payload / 'plan.private.json', canonical(plan))
    new(payload / 'containers.private.json', canonical({i: host[i] for i in sorted(ids)}))
    networks = sorted({n['NetworkID'] for r in plan['roles'].values()
                       for n in host[r['containerId']]['NetworkSettings']['Networks'].values() if n.get('NetworkID')})
    if networks:
        run.docker('network', 'inspect', *networks, output=payload / 'networks.private.json')
    before = {}
    for i, source in enumerate(plan['sources']):
        before[source] = tree_manifest(source, run.until)
        need(sum(len(v) for v in before.values()) <= MAX_FILES, 'TOTAL_FILE_LIMIT')
        p = Path(source)
        run.run(['/usr/bin/tar', '--create', '--format=pax', '--numeric-owner', '--acls', '--xattrs',
                 '--xattrs-include=*', '--sparse', '--one-file-system', '-C', str(p.parent), '--', p.name],
                output=payload / ('source-%03d.tar' % i), cap=LIMIT, timeout=1800)
        verify_source_archive(payload / ('source-%03d.tar' % i), p.name, before[source], run.until)
    new(payload / 'source-manifests.private.json', canonical(before))
    images = sorted({r['nativeImage'] for r in plan['roles'].values()})
    run.docker('image', 'save', *images, output=payload / 'images.tar', cap=LIMIT, timeout=1800)
    for role, r in sorted(plan['roles'].items()):
        run.docker('export', r['containerId'], output=payload / (role + '.rootfs.tar'), cap=LIMIT, timeout=600)
    after_host = run.inventory(ids)
    offline(plan, after_host)
    need(set(host) == set(after_host), 'HOST_CONTAINER_SET_CHANGED')
    for source in plan['sources']:
        need(before[source] == tree_manifest(source, run.until), 'SOURCE_CHANGED_DURING_CAPTURE')
    # A start/stop between observations must not be mistaken for a continuous fence.
    event_raw = run.docker('events', '--since', str(started), '--until', str(int(time.time()) + 1),
                          '--filter', 'type=container', '--format', '{{json .}}', cap=4 << 20, timeout=15)
    events = [decode(line) for line in event_raw.splitlines()]
    need(all(e.get('Action') == 'export' and (e.get('Actor') or {}).get('ID') in ids for e in events),
         'CONTAINER_EVENT_DURING_CAPTURE_REQUIRES_REVIEW')
    members = {p.name: {'bytes': p.stat().st_size, 'sha256': hash_file(p, run.until)} for p in sorted(payload.iterdir())}
    new(payload / 'manifest.private.json', canonical({'schema': 'ouf.storage-cold-backup-members.v1', 'members': members,
        'applicationConsistencyProven': False, 'restorePerformed': False, 'runtimeAuthorityIssued': False}))
    bundle = root / 'backup.tar.partial'
    run.run(['/usr/bin/tar', '-cf', '-', '-C', str(payload), '.'], output=bundle, cap=LIMIT, timeout=1800)
    encrypted = root / 'backup.tar.age.partial'
    run.run(['/usr/bin/age', '-r', public_recipient, str(bundle)], output=encrypted, cap=LIMIT, timeout=1800)
    cipher_hash = hash_file(encrypted, run.until)
    final = root / 'backup.tar.age'
    need(not final.exists(), 'FINAL_ARCHIVE_ALREADY_EXISTS')
    os.link(encrypted, final)
    encrypted.unlink()
    result = {'schema': 'ouf.storage-cold-backup-result.v1', 'status': 'ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED',
        'archive': str(final), 'archiveBytes': final.stat().st_size, 'archiveSha256': cipher_hash,
        'planSha256': plan_sha, 'recipientSha256': digest(public_recipient.encode()), 'roles': len(plan['roles']),
        'sources': len(plan['sources']), 'members': len(members), 'commandCalls': run.calls,
        'producedBytes': run.total, 'attempts': 1, 'providerMutationCommands': 0,
        'plaintextRetainedPrivately': True, 'originalsPreserved': True, 'automaticReplayAllowed': False,
        'automaticRestartAllowed': False, 'applicationConsistencyProven': False,
        'restorePerformed': False, 'independentBackupVerified': False, 'g3Complete': False, 'acceptanceCreditAdded': 0}
    new(root / 'result.json', canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('prepare')
    c = sub.add_parser('capture')
    c.add_argument('--plan-sha256', required=True)
    c.add_argument('--recipient-file', required=True)
    c.add_argument('--decision-reference', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'ROOT_ISOLATED_PYTHON_REQUIRED')
    program_sha = digest(protected(Path(__file__).absolute()))
    if args.action == 'prepare':
        raw = protected(BASE, private=True)
        need(digest(raw) == BASE_SHA, 'RETAINED_BASE_INPUT_CHANGED')
        base = decode(raw)
        need(set(base['roles']) == ROLES, 'EXACT_RETAINED_ROSTER_REQUIRED')
        bindings = {r: {k: base['roles'][r][k] for k in ('containerId', 'nativeImage')} for r in ROLES}
        bindings['etcd'] = {'containerId': ETCD_ID, 'nativeImage': ETCD_IMAGE}
        # Parent must be the existing protected staging; no arbitrary output override.
        st = AREA.parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
             and not AREA.parent.is_symlink(), 'PROTECTED_STAGING_REQUIRED')
        AREA.mkdir(mode=0o700)
        run = Runner(AREA, seconds=300)
        host = run.inventory({r['containerId'] for r in bindings.values()})
        plan = build_plan(bindings, host, AREA, program_sha)
        new(AREA / 'plan.private.json', canonical(plan))
        new(AREA / 'planned-containers.private.json', canonical({r['containerId']: host[r['containerId']] for r in bindings.values()}))
        result = {'schema': 'ouf.storage-cold-backup-preparation.v1', 'status': 'PLAN_PREPARED_NOT_STOP_AUTHORITY',
            'planSha256': digest(canonical(plan)), 'roles': sorted(plan['roles']), 'sourceCount': len(plan['sources']),
            'includesWholeSharedPostgresCluster': True, 'maximumSeconds': 3600, 'maximumProducedBytes': LIMIT,
            'targetWrites': 0, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0,
            'remaining': ['APPROVED_STOP_CONTAINMENT_AND_WINDOW', 'PUBLIC_ENCRYPTION_RECIPIENT',
                          'CAPTURE', 'OFFHOST_TRANSFER_AND_ISOLATED_RESTORE']}
        new(AREA / 'preparation-result.json', canonical(result))
    else:
        raw = protected(AREA / 'plan.private.json', private=True)
        need(digest(raw) == args.plan_sha256, 'PLAN_HASH_CHANGED')
        plan = decode(raw)
        need(plan['programSha256'] == program_sha, 'PROGRAM_CHANGED_SINCE_PLAN')
        public = recipient(protected(Path(args.recipient_file), limit=4096))
        need(shutil.which('age', path=ENV['PATH']) == '/usr/bin/age', 'AGE_PACKAGE_REQUIRED')
        # Refuse a previous successful OR failed attempt, even if its caller was killed.
        root = AREA / 'capture'
        root.mkdir(mode=0o700)
        run = Runner(root)
        result = capture(plan, args.plan_sha256, root, run, public, args.decision_reference)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except BaseException as e:
        if isinstance(e, SystemExit):
            raise
        print(json.dumps({'status': 'HELD', 'reason': str(e) if isinstance(e, Held) else type(e).__name__,
                          'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
                          'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
