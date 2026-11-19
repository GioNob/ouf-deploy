#!/usr/bin/env python3
"""Diagnose only the installed fixed read-only helper; never print its payload."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import traceback

HELPER = Path('/usr/local/sbin/ouf-discovery-preflight')
EXPECTED_HELPER_SHA256 = '65c8caa661005a7bf4bfe7eb1c5f45932a32c3e024095db861882f6c52998618'

def safe_failure(error, trace=None):
    return {'errorClass': type(error).__name__, 'frames': [
        {'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
        for frame in traceback.extract_tb(trace if trace is not None else error.__traceback__)[-12:]]}

def observe_call(call, result):
    """Observe the sealed observer's swallowed failure without changing its result."""
    previous = sys.gettrace()
    def trace(frame, event, arg):
        if event == 'exception' and frame.f_code.co_name == 'observe' and Path(frame.f_code.co_filename).name == 'transition-source.py':
            # Store metadata only, never exception objects, arguments or locals.
            error = arg[1]
            result['observerFailure'] = safe_failure(error, arg[2])
        return trace
    try:
        sys.settrace(trace)
        return call()
    finally:
        sys.settrace(previous)


def inspect():
    if len(sys.argv) != 1 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:
        raise ValueError('ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
    for parent in (HELPER.parent, *HELPER.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('ROOT_HELPER_PARENT_UNSAFE')
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o755 or not 0 < info.st_size <= 131072:
            raise ValueError('ROOT_HELPER_CUSTODY_UNPROVEN')
        raw = os.read(fd, 131073)
        if len(raw) != info.st_size or any(getattr(os.fstat(fd), k) != getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('ROOT_HELPER_CHANGED')
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_HELPER_SHA256:
        raise ValueError('INSTALLED_HELPER_CHANGED')
    result = {'schema': 'ouf.fixed-helper-diagnostic.v2', 'helperSha256': hashlib.sha256(raw).hexdigest(), 'runtimeMutations': 0, 'payloadPrinted': False, 'exceptionMessagePrinted': False}
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(90)
    try:
        module = {'__name__': 'ouf_fixed_read_diagnostic', '__file__': str(HELPER)}
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            exec(compile(raw, str(HELPER), 'exec'), module)
            observe_call(module['collect'], result)
        result['readSucceeded'] = True
    except Exception as error:
        result['readSucceeded'] = False
        result.update(safe_failure(error))
    finally:
        signal.alarm(0)
    return result

if __name__ == '__main__':
    try:
        print(json.dumps(inspect(), sort_keys=True))
    except Exception as error:
        print(json.dumps({'schema': 'ouf.fixed-helper-diagnostic.v2', 'readSucceeded': False, 'errorClass': type(error).__name__, 'payloadPrinted': False, 'exceptionMessagePrinted': False}, sort_keys=True))
        raise SystemExit(2)
