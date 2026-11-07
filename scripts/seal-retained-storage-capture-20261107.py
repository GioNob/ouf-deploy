#!/usr/bin/env python3
"""Verify and encrypt retained OUF test artifacts for historical custody."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import tarfile
import time


OLD = Path('/var/lib/ouf-storage-migration/capture-after-held-stop-20261107-v1')
NEW = OLD.with_name('capture-historical-custody-20261107-v1')
PRODUCER = Path('/var/lib/ouf-storage-cold-backup-v3.py')
AGE = Path('/usr/bin/age')
RECIPIENT = Path('/var/lib/ouf-storage-cipher-preparation-20261106/recipient.pub')
DECISION = 'GIOVANNI-NONPROD-HISTORICAL-CUSTODY-20261107-01'
OLD_DECISION = 'GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01'
EXPIRY = 1794081219
SECONDS = 900
OUTPUT_LIMIT = 8 << 30
EXPECTED_TAR_BYTES = (265646080, 3896882176, 2378470912)
SCHEMA = 'ouf.storage-retained-capture-custody.v1'


class Held(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Held(code)


def load_producer():
    for path in PRODUCER.parents:
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'UNPROTECTED_PRODUCER_ANCESTRY')
    fd = os.open(PRODUCER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 32524,
             'UNPROTECTED_PRODUCER')
        raw = stream.read(32525)
    need(hashlib.sha256(raw).hexdigest() == 'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac',
         'PRODUCER_DIGEST')
    h = {'__name__': 'retained_custody_definitions', '__file__': str(PRODUCER)}
    exec(compile(raw, str(PRODUCER), 'exec'), h)
    return h


def private_dir(stack, name, parent):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    need(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'UNPROTECTED_CAPTURE_DIRECTORY')
    return fd


def file_info(parent, name):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600 and 0 <= info.st_size <= OUTPUT_LIMIT,
         'UNPROTECTED_RETAINED_FILE')
    return info


def open_retained(h, parent, name, info):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=parent)
    stream = os.fdopen(fd, 'rb')
    if h['frame'](os.fstat(fd)) != h['frame'](info):
        stream.close()
        raise Held('RETAINED_FILE_CHANGED')
    return stream


def absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def retained_state(h, stack):
    parent = h['runtime_parent'](OLD)
    stack.callback(os.close, parent)
    scope = private_dir(stack, OLD.name, parent)
    capture = private_dir(stack, 'capture', scope)
    payload = private_dir(stack, 'payload', capture)
    need(absent(scope, 'result.json') and all(absent(capture, name) for name in (
         'result.json', 'backup.tar.partial', 'backup.tar.age.partial', 'backup.tar.age',
         'command-057.stderr.private')), 'RETAINED_CAPTURE_STAGE_CHANGED')
    claim_raw = h['protected'](OLD / 'claim.private.json', private=True, limit=8192)
    inner_raw = h['protected'](OLD / 'capture' / 'capture-claim.private.json', private=True, limit=8192)
    plan_raw = h['protected'](OLD / 'plan.private.json', private=True)
    claim, inner, plan = map(h['decode'], (claim_raw, inner_raw, plan_raw))
    plan_sha = h['digest'](plan_raw)
    need(claim['schema'] == 'ouf.storage-capture-after-held-stop-claim.v1'
         and claim['decisionReference'] == inner['decisionReference'] == OLD_DECISION
         and claim['planSha256'] == inner['planSha256'] == plan_sha
         and claim['attempts'] == inner['attempts'] == 1
         and claim['captureSeconds'] == 3600 and claim['priorCumulativeStopCommandCalls'] == 184
         and claim['legacyValidUntilEpoch'] == plan['validUntilEpoch'] == EXPIRY
         and claim['originalPlanSha256'] == 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
         and claim['retainedJournalDigest'] == '5f3416a62555adf1d6b4dc00370bd72cf33c0844bb7d671aaae05c08f4bc741f'
         and plan['programSha256'] == '583a5e26ab18bfdb09d868fb3d7fabd9acf347f64dbf01b8caf0bf8cbec80184',
         'RETAINED_PLAN_CLAIM_MISMATCH')
    need(time.time() - file_info(scope, 'claim.private.json').st_mtime >= 3600,
         'PRIOR_CAPTURE_WINDOW_STILL_ACTIVE')
    for ordinal in range(1, 57):
        file_info(capture, 'command-%03d.stderr.private' % ordinal)
    need(file_info(capture, 'command-056.stderr.private').st_size == 0
         and file_info(capture, 'command-056.private').st_size > 0, 'RETAINED_TAIL_CHANGED')
    roles = sorted(plan['roles'])
    need(roles == sorted(h['ROLES'] | {'etcd'}) and len(plan['sources']) == 34,
         'RETAINED_ROSTER_CHANGED')
    source_tars = ['source-%03d.tar' % i for i in range(34)]
    rootfs_tars = [role + '.rootfs.tar' for role in roles]
    names = {*source_tars, *rootfs_tars, 'images.tar', 'plan.private.json',
             'containers.private.json', 'networks.private.json', 'source-manifests.private.json'}
    with os.scandir(payload) as entries:
        observed = set()
        for item in entries:
            need(item.name in names, 'UNEXPECTED_RETAINED_MEMBER')
            observed.add(item.name)
        need(observed == names, 'MISSING_RETAINED_MEMBER')
    members = {name: file_info(payload, name) for name in sorted(names)}
    need(all(item.st_size > 0 for item in members.values()) and (
         sum(members[name].st_size for name in source_tars),
         sum(members[name].st_size for name in rootfs_tars), members['images.tar'].st_size
         ) == EXPECTED_TAR_BYTES, 'RETAINED_TAR_SIZES_CHANGED')
    need(h['protected'](OLD / 'capture/payload/plan.private.json', private=True) == plan_raw,
         'RETAINED_PAYLOAD_PLAN_CHANGED')
    manifests = h['decode'](h['protected'](
        OLD / 'capture/payload/source-manifests.private.json', private=True))
    need(set(manifests) == set(plan['sources']) and sum(len(rows) for rows in manifests.values()) <= h['MAX_FILES'],
         'RETAINED_SOURCE_MANIFEST_SET')
    return payload, members, plan, manifests, plan_sha, claim_raw, inner_raw, inner['recipientSha256']


class DigestingReader:
    def __init__(self, stream):
        self.stream = stream
        self.sha = hashlib.sha256()

    def read(self, size):
        block = self.stream.read(size)
        self.sha.update(block)
        return block


def add_member(tar, name, size, stream):
    info = tarfile.TarInfo(name)
    info.size, info.mode = size, 0o600
    tar.addfile(info, stream)


def stream_custody(h, argv, payload, members, output, evidence):
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))

    with output.open('xb') as cipher:
        age = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=cipher, stderr=subprocess.DEVNULL,
                               env=h['ENV'], preexec_fn=limit)
        try:
            tar = tarfile.open(fileobj=age.stdin, mode='w|', bufsize=1 << 20)
            digests = {}
            for name, info in members.items():
                with open_retained(h, payload, name, info) as stream:
                    reader = DigestingReader(stream)
                    add_member(tar, 'payload/' + name, info.st_size, reader)
                    need(h['frame'](info) == h['frame'](os.fstat(stream.fileno())),
                         'RETAINED_FILE_CHANGED')
                digests[name] = {'bytes': info.st_size, 'sha256': reader.sha.hexdigest()}
            for name, raw in evidence.items():
                add_member(tar, 'evidence/' + name, len(raw), io.BytesIO(raw))
            manifest = h['canonical']({'schema': SCHEMA, 'members': digests,
                'evidenceSha256': {name: h['digest'](raw) for name, raw in evidence.items()},
                'captureEventCoverageProven': False, 'liveSourceContinuityProven': False,
                'historicalCustodyOnly': True, 'restorePerformed': False})
            add_member(tar, 'evidence/custody-manifest.private.json', len(manifest), io.BytesIO(manifest))
            tar.close()
            age.stdin.close()
            need(age.wait() == 0, 'AGE_ENCRYPTION_FAILED')
        finally:
            if age.poll() is None:
                age.kill()
            with contextlib.suppress(BrokenPipeError):
                age.stdin.close()
            age.wait(timeout=5)
        cipher.flush()
        os.fsync(cipher.fileno())
    return h['digest'](manifest)


def execute(h, age_argv, recipient_sha, decision, deadline):
    need(decision == DECISION, 'EXACT_HISTORICAL_CUSTODY_DECISION_REQUIRED')
    need(not os.path.lexists(NEW), 'HISTORICAL_CUSTODY_SCOPE_ALREADY_CLAIMED')
    need(time.time() + SECONDS <= EXPIRY, 'ORIGINAL_WINDOW_INSUFFICIENT')
    with contextlib.ExitStack() as stack:
        payload, members, plan, manifests, plan_sha, claim, inner, original_recipient = retained_state(h, stack)
        need(original_recipient == recipient_sha, 'RETAINED_RECIPIENT_CHANGED')
        for i, source in enumerate(plan['sources']):
            name = 'source-%03d.tar' % i
            with open_retained(h, payload, name, members[name]) as stream:
                h['verify_source_archive'](Path('/proc/self/fd') / str(stream.fileno()),
                                           Path(source).name, manifests[source], deadline)
                need(h['frame'](members[name]) == h['frame'](os.fstat(stream.fileno())),
                     'SOURCE_TAR_CHANGED_DURING_VERIFICATION')
        parent = h['runtime_parent'](NEW)
        stack.callback(os.close, parent)
        free = os.fstatvfs(parent)
        need(free.f_bavail * free.f_frsize >= OUTPUT_LIMIT, 'CUSTODY_FREE_SPACE_REQUIRED')
        need(sum(info.st_size for info in members.values()) <= OUTPUT_LIMIT - (64 << 20),
             'CUSTODY_PAYLOAD_LIMIT')
        os.mkdir(NEW.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        claim_meta = {'schema': SCHEMA, 'decisionReference': decision, 'originalPlanSha256': plan_sha,
            'priorStopCommandsCharged': 184, 'priorStopSecondsCharged': 2400,
            'priorCaptureCommandMarkersCharged': 56, 'priorCaptureSecondsCharged': 3600,
            'priorCaptureBytesLimitNotReset': True, 'newCustodySeconds': SECONDS,
            'newCipherOutputLimit': OUTPUT_LIMIT, 'newAgeInvocations': 1,
            'originalExpiryEpoch': EXPIRY, 'historicalCustodyOnly': True,
            'automaticReplayAllowed': False}
        claim_bytes = h['canonical'](claim_meta)
        h['new'](NEW / 'claim.private.json', claim_bytes)
        partial = NEW / 'retained-historical.tar.age.partial'
        final = NEW / 'retained-historical.tar.age'
        manifest_sha = stream_custody(h, age_argv, payload, members, partial, {
            'custody-claim.private.json': claim_bytes, 'original-claim.private.json': claim,
            'original-producer-claim.private.json': inner})
        for name, info in members.items():
            need(h['frame'](file_info(payload, name)) == h['frame'](info), 'RETAINED_FILE_CHANGED')
        partial_info = partial.lstat()
        need(stat.S_ISREG(partial_info.st_mode) and 0 < partial_info.st_size <= OUTPUT_LIMIT,
             'CUSTODY_ARCHIVE_SIZE')
        digest = h['hash_file'](partial, deadline)
        need(h['frame'](partial_info) == h['frame'](partial.lstat()), 'CUSTODY_ARCHIVE_CHANGED')
        need(time.monotonic() < deadline and time.time() <= EXPIRY, 'CUSTODY_TIME_LIMIT')
        os.link(partial, final, follow_symlinks=False)
        partial.unlink()
        result = {'schema': SCHEMA, 'status': 'HISTORICAL_CUSTODY_ARCHIVE_SEALED',
            'archive': str(final), 'archiveBytes': final.stat().st_size, 'archiveSha256': digest,
            'privateManifestSha256': manifest_sha, 'sourceArchivesVerified': 34,
            'retainedPayloadMembersHashed': len(members), 'providerRequests': 0,
            'liveSourceContinuityProven': False, 'captureEventCoverageProven': False,
            'restorePerformed': False, 'acceptanceCreditAdded': 0}
        h['new'](NEW / 'result.json', h['canonical'](result))
        return result


def main():
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
    parser = argparse.ArgumentParser()
    parser.add_argument('--decision-reference', required=True)
    parser.add_argument('--historical-custody-only', action='store_true', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    h = load_producer()
    recipient_raw = h['protected'](RECIPIENT, private=True, limit=4096)
    need(h['digest'](recipient_raw) == '20582d7f592199d5964fc64ece8d035bdf3b93df026c5e222eca615c0f8bb2c0',
         'RECIPIENT_CHANGED')
    need(h['digest'](h['protected'](AGE, limit=64 << 20)) ==
         'eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c', 'AGE_BINARY_CHANGED')
    public = h['recipient'](recipient_raw)

    def timeout(_signal, _frame):
        raise Held('CUSTODY_TIME_LIMIT')

    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, SECONDS)
    try:
        result = execute(h, [str(AGE), '-r', public], h['digest'](public.encode()),
                         args.decision_reference, time.monotonic() + SECONDS)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(h['canonical'](result).decode(), end='')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = str(error) if type(error).__name__ == 'Held' else 'LOCAL_CUSTODY_FAILED'
        print(json.dumps({'schema': SCHEMA, 'status': 'HELD', 'reason': code,
                          'automaticReplayAllowed': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
