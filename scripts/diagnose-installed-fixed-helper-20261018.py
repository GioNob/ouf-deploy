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
        if len(raw) != info.st_size or os.fstat(fd) != info:
            raise ValueError('ROOT_HELPER_CHANGED')
    finally:
        os.close(fd)
    result = {'schema': 'ouf.fixed-helper-diagnostic.v1', 'helperSha256': hashlib.sha256(raw).hexdigest(), 'runtimeMutations': 0, 'payloadPrinted': False, 'exceptionMessagePrinted': False}
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(90)
    try:
        module = {'__name__': 'ouf_fixed_read_diagnostic', '__file__': str(HELPER)}
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            exec(compile(raw, str(HELPER), 'exec'), module)
            module['collect']()
        result['readSucceeded'] = True
    except Exception as error:
        result['readSucceeded'] = False
        result['errorClass'] = type(error).__name__
        result['frames'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name} for frame in traceback.extract_tb(error.__traceback__)[-12:]]
    finally:
        signal.alarm(0)
    return result

if __name__ == '__main__':
    try:
        print(json.dumps(inspect(), sort_keys=True))
    except Exception as error:
        print(json.dumps({'schema': 'ouf.fixed-helper-diagnostic.v1', 'readSucceeded': False, 'errorClass': type(error).__name__, 'payloadPrinted': False, 'exceptionMessagePrinted': False}, sort_keys=True))
        raise SystemExit(2)
