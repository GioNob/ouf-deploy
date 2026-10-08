"""Read-only replay of input collection; bounded public error labels only."""
import ast
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

SOURCE_HASH = '6485246f0fdcd94e849982b1e082ac987f666cf1ddecf6c58ed8a4a38410c46d'
PARENT = Path('/etc/ouf/deploy-snapshots')
STACK = []
FAILURE_STACK = []


def source():
    rows = []
    for directory in PARENT.glob('semantic-v2-launch-source-*'):
        if len(rows) >= 128:
            raise ValueError('BOUNDED_SOURCE_SEARCH_REQUIRED')
        d = directory.lstat()
        if not stat.S_ISDIR(d.st_mode) or (d.st_uid, d.st_gid, stat.S_IMODE(d.st_mode)) != (0, 0, 0o700):
            continue
        path = directory / 'prepare.py'
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        try:
            a = os.fstat(fd)
            if not stat.S_ISREG(a.st_mode) or a.st_nlink != 1 or (a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode)) != (0, 0, 0o600) or a.st_size > 131072:
                continue
            raw = os.read(fd, 131073); b = os.fstat(fd)
            if len(raw) == a.st_size and hashlib.sha256(raw).hexdigest() == SOURCE_HASH and all(
                    getattr(a, k) == getattr(b, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                rows.append((d.st_mtime_ns, path, raw))
        finally:
            os.close(fd)
    if not rows:
        raise ValueError('SEALED_PREPARER_SOURCE_NOT_FOUND')
    _, path, raw = max(rows, key=lambda r: r[0])
    module = types.ModuleType('_ouf_launch_read_only_diagnosis')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def labels(raw):
    # Public source constants only. Never expose exception text from private
    # file parsing, subprocess stderr, JSON keys, paths or environment values.
    return {v.value for v in ast.walk(ast.parse(raw)) if isinstance(v, ast.Constant)
            and type(v.value) is str and re.fullmatch('[A-Z_]{1,96}', v.value)}


def wrap(module, name, prefix):
    original = getattr(module, name)
    @functools.wraps(original)
    def bounded(*args, **kwargs):
        STACK.append(prefix + '.' + name)
        try:
            return original(*args, **kwargs)
        except Exception:
            if not FAILURE_STACK:
                FAILURE_STACK.extend(STACK)
            raise
        finally:
            STACK.pop()
    setattr(module, name, bounded)


def error_label(error, allowed):
    if type(error).__name__ in ('Denied', 'ValueError') and len(error.args) == 1:
        value = error.args[0]
        if type(value) is str and value in allowed:
            return value
    return 'REDACTED_ERROR'


def main():
    allowed = {'ROOT_REQUIRED', 'SEALED_PREPARER_SOURCE_NOT_FOUND', 'BOUNDED_SOURCE_SEARCH_REQUIRED'}
    report = {'schema': 'ouf.semantic-provider-v2-launch-inputs-diagnosis.v1',
              'readOnly': True, 'configurationWrites': 0, 'containerLifecycleOperations': 0,
              'providerCalls': 0, 'installationAuthorityKeysRead': 0,
              'privateApplicationInputsMayBeRead': True, 'secretValuesPrinted': False,
              'acceptanceGranted': False, 'startAuthorized': False}
    stage = 'LOAD_PREPARER'
    try:
        if os.geteuid() != 0:
            raise ValueError('ROOT_REQUIRED')
        module, raw = source(); allowed |= labels(raw)
        stage = 'LOAD_EXISTING_READER'
        reader = module.load_reader(); allowed |= labels(reader.private(module.READER))
        stage = 'LOAD_EXISTING_RUNTIME_READER'
        ns = reader.namespace(reader.REG / 'register-provider-v2-runtime.py', reader.REG_SOURCE_HASH)
        allowed |= labels(reader.private(reader.REG / 'register-provider-v2-runtime.py'))
        for name in ('private', 'namespace', 'prepare', 'snapshot', 'verify_retained',
                     'resolved_image', 'image', 'verify_container', 'environment', 'archive_identity'):
            wrap(reader, name, 'reader')
        for name in ('read', 'capture', 'docker', 'parse', 'runtimes'):
            wrap(ns, name, 'runtime_reader')
        stage = 'VERIFY_COMMAND_BINDINGS'
        for path, expected in ns.BINDS.values():
            module.require(module.digest(ns.read(Path(path), True)) == expected, 'COMMAND_BINDING_DRIFT')
        stage = 'COLLECT_ONLY'
        module.collect(reader, ns)
        report.update(status='INPUT_COLLECTION_PASS', outputFilesWritten=0)
    except Exception as error:
        report.update(status='BLOCKED', stage=stage, callChain=FAILURE_STACK[-6:],
                      reason=error_label(error, allowed), errorClass=type(error).__name__ if type(error).__name__ in
                      ('Denied', 'ValueError', 'KeyError', 'TypeError', 'FileNotFoundError',
                       'PermissionError', 'OSError', 'TimeoutExpired', 'JSONDecodeError') else 'REDACTED_CLASS')
    print('OUF_PROVIDER_V2_LAUNCH_DIAGNOSIS=' + json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
