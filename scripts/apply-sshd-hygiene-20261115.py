#!/usr/bin/env python3
"""R-007: pinned, offline, one-shot sshd configuration hygiene. Never reloads sshd."""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

BASE_SHA256 = '37d4e06993caa84ffc4ead52d3c035b75ad4e117db6a22d8e6c4c2513ea05d86'
DROPIN_SHA256 = 'e25a1fee9a9a3a432b797b9522181dd6d6df1116261752691579c457a6262901'
SSHD_SHA256 = '379c5c895b2728e249acd62417cc1388245af3da2ed1cba2e407deae40c32f9d'
COMMENTS = (b'# PasswordAuthentication: effective value in sshd_config.d/00-ouf-hardening.conf (ouf task-45)\n'
            b'# PermitRootLogin: effective value in sshd_config.d/00-ouf-hardening.conf (ouf task-45)\n')


@dataclass(frozen=True)
class Settings:
    config: Path = Path('/etc/ssh/sshd_config')
    dropin: Path = Path('/etc/ssh/sshd_config.d/00-ouf-hardening.conf')
    sshd: Path = Path('/usr/sbin/sshd')
    snapshot: Path = Path('/etc/ouf/deploy-snapshots/sshd-hygiene-20261115')
    base_sha256: str = BASE_SHA256
    dropin_sha256: str = DROPIN_SHA256
    sshd_sha256: str = SSHD_SHA256
    include: bytes = b'Include /etc/ssh/sshd_config.d/*.conf\n'


class Denied(Exception):
    pass


class PublicParser(argparse.ArgumentParser):
    def error(self, message):
        raise Denied('INVALID_ARGUMENTS')


def require(condition, code):
    if not condition:
        raise Denied(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def safe_parents(path):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, 'UNTRUSTED_PARENT')


def checked_file(path, digest, mode):
    safe_parents(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, mode),
            'FILE_METADATA_DRIFT')
    data = path.read_bytes()
    require(sha(data) == digest, 'FILE_HASH_DRIFT')
    return data


def target_bytes(base, settings):
    lines = base.splitlines(keepends=True)
    require(len(lines) == 125 and lines[11] == settings.include
            and lines[122:] == [b'\n', b'PasswordAuthentication yes\n', b'PermitRootLogin yes\n'],
            'CONFIG_LAYOUT_DRIFT')
    require(not any(line.split() and line.split()[0].lower() == b'match'
                    for line in lines if not line.lstrip().startswith(b'#')), 'MATCH_NOT_ALLOWED')
    return b''.join(lines[:123]) + COMMENTS


def sshd_call(settings, flag, config):
    try:
        result = subprocess.run([str(settings.sshd), flag, '-f', str(config)],
                                capture_output=True, timeout=30, check=False,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired:
        raise Denied('SSHD_TIMEOUT') from None
    require(result.returncode == 0, 'SSHD_VALIDATION_FAILED')
    return result.stdout


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fsync_directory(path.parent)


def private_directory(path):
    safe_parents(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700),
            'SNAPSHOT_METADATA_DRIFT')


def ensure_parents(path):
    missing = []
    cursor = path
    while not os.path.lexists(cursor):
        missing.append(cursor)
        cursor = cursor.parent
    safe_parents(cursor / 'unused')
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        fsync_directory(directory.parent)


def make_plan(settings, restore=False):
    require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'ROOT_REQUIRED')
    checked_file(settings.dropin, settings.dropin_sha256, 0o644)
    checked_file(settings.sshd, settings.sshd_sha256, 0o755)
    if restore:
        private_directory(settings.snapshot)
        original = checked_file(settings.snapshot / 'original', settings.base_sha256, 0o600)
        cleaned = target_bytes(original, settings)
        before = checked_file(settings.config, sha(cleaned), 0o644)
        after = original
    else:
        before = checked_file(settings.config, settings.base_sha256, 0o644)
        after = target_bytes(before, settings)
    sshd_call(settings, '-t', settings.config)
    effective_before = sshd_call(settings, '-T', settings.config)
    with tempfile.TemporaryDirectory(prefix='ouf-sshd-hygiene-') as directory:
        candidate = Path(directory) / 'sshd_config'
        save(candidate, after)
        sshd_call(settings, '-t', candidate)
        effective_after = sshd_call(settings, '-T', candidate)
    require(effective_before == effective_after, 'EFFECTIVE_CONFIG_CHANGED')
    plan = {'schema': 'ouf.sshd-hygiene.v1', 'operation': 'restore' if restore else 'apply',
            'config': str(settings.config), 'dropin': str(settings.dropin), 'sshd': str(settings.sshd),
            'snapshot': str(settings.snapshot), 'baseSha256': sha(before), 'targetSha256': sha(after),
            'dropinSha256': settings.dropin_sha256, 'sshdSha256': settings.sshd_sha256,
            'effectiveBeforeSha256': sha(effective_before), 'effectiveTargetSha256': sha(effective_after),
            'effectiveEqual': True, 'reloadOrRestart': False,
            'diff': ''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                              fromfile='sshd_config.before', tofile='sshd_config.target'))}
    plan['planSha256'] = sha(encoded(plan))
    return plan, before, after, effective_before


@contextmanager
def apply_lock(settings):
    import fcntl
    safe_parents(settings.config)
    fd = os.open(settings.config.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Denied('OPERATION_BUSY') from None
        yield
    finally:
        os.close(fd)


def atomic_replace(settings, data):
    fd, name = tempfile.mkstemp(prefix='.ouf-sshd-hygiene-', dir=settings.config.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, settings.config)
        fsync_directory(settings.config.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def execute(settings, apply=False, digest=None, restore=False):
    effected = False
    claimed = False
    evidence = None
    try:
        if not apply:
            plan, _, _, _ = make_plan(settings, restore)
            return dict(plan, status='PLANNED', doNotRerunApply=False), 0
        require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'ROOT_REQUIRED')
        with apply_lock(settings):
            plan, before, after, effective = make_plan(settings, restore)
            require(digest == plan['planSha256'], 'PLAN_DIGEST_MISMATCH')
            evidence = settings.snapshot / 'restore' if restore else settings.snapshot
            require(not os.path.lexists(evidence), 'OPERATION_ALREADY_CLAIMED')
            # No retries: all unknown/IO/validation failures require reconciliation.
            # Set before the first mkdir, conservatively covering ambiguous failures.
            effected = True
            ensure_parents(evidence.parent)
            safe_parents(evidence)
            evidence.mkdir(mode=0o700)
            claimed = True
            fsync_directory(evidence.parent)
            private_directory(evidence)
            save(evidence / 'claim.json', encoded(plan) + b'\n')
            save(evidence / 'original', before)
            # Fresh preconditions after the durable snapshot, immediately before rename.
            fresh, _, _, _ = make_plan(settings, restore)
            require(fresh == plan, 'PLAN_CHANGED_BEFORE_RENAME')
            atomic_replace(settings, after)
            checked_file(settings.config, plan['targetSha256'], 0o644)
            sshd_call(settings, '-t', settings.config)
            require(sshd_call(settings, '-T', settings.config) == effective, 'READBACK_EFFECTIVE_CHANGED')
            result = dict(plan, status='RESTORED' if restore else 'APPLIED', doNotRerunApply=True)
            save(evidence / 'result.json', encoded(result) + b'\n')
            return result, 0
    except Exception as error:
        code = str(error) if isinstance(error, Denied) else ('IO_ERROR' if isinstance(error, OSError) else 'UNEXPECTED_ERROR')
        result = {'status': 'BLOCKED', 'code': code,
                  'doNotRerunApply': effected}
        # Existing exclusive claim also blocks replay after process death/restart.
        if apply and os.path.lexists(settings.snapshot / 'restore' if restore else settings.snapshot):
            result['doNotRerunApply'] = True
        if claimed:
            try:
                save(evidence / 'failure.json', encoded(result) + b'\n')
            except Exception:
                pass
        return result, 1


def main():
    os.umask(0o077)
    parser = PublicParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--plan-sha256')
    try:
        args = parser.parse_args()
    except Denied as error:
        print(json.dumps({'status': 'BLOCKED', 'code': str(error), 'doNotRerunApply': False}))
        return 2
    if (args.apply and (not args.plan_sha256 or len(args.plan_sha256) != 64
                       or any(c not in '0123456789abcdef' for c in args.plan_sha256))) or (args.plan and args.plan_sha256):
        print(json.dumps({'status': 'BLOCKED', 'code': 'INVALID_PLAN_DIGEST', 'doNotRerunApply': False}))
        return 2
    result, code = execute(Settings(), args.apply, args.plan_sha256, args.restore)
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
