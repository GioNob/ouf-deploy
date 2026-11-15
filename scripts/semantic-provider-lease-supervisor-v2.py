#!/usr/bin/env python3
"""Pinned bootstrap: verify the complete closure before executing module bytes."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

SELF = "scripts/semantic-provider-lease-supervisor-v2.py"
OPERATION_MODULES = ("authorization", "epochs", "lease_supervisor")
RECOVERY_MODULES = ("activation_core", "bounded_recovery", "recovery_journal", "lease_recovery_budget",
                    "resilient_lease_adapter", "adaptive_supervisor", "nft_seconds_backend", "deadline_backend",
                    "continuous_supervisor", "dns", "readback_margin_compiler")
SOURCES = ({SELF} | {"tools/semantic_provider_operation/" + name + ".py" for name in OPERATION_MODULES}
           | {"tools/semantic_lease_recovery/" + name + ".py" for name in RECOVERY_MODULES})


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def absolute(value):
    return (type(value) is str and value.startswith("/") and ".." not in value.split("/")
            and "//" not in value and "\x00" not in value and str(Path(value).as_posix()) == value)


def ancestors(path):
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "SUPERVISOR_ANCESTOR_CUSTODY_REQUIRED")


def attributes(info):
    return tuple(getattr(info, k) for k in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                           "st_size", "st_mtime_ns", "st_ctime_ns"))


def private(path, expected):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 131072,
                "SUPERVISOR_FILE_CUSTODY_REQUIRED")
        raw = os.read(fd, 131073)
        require(len(raw) == info.st_size and attributes(info) == attributes(os.fstat(fd)),
                "SUPERVISOR_FILE_CHANGED")
        require(hashlib.sha256(raw).hexdigest() == expected, "SUPERVISOR_BINDING_HASH_MISMATCH")
        return raw
    finally:
        os.close(fd)


def private_root(root):
    ancestors(root)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "SUPERVISOR_PRIVATE_DIRECTORY_REQUIRED")


def load_sources(configuration, expected):
    require(absolute(configuration), "ABSOLUTE_PATH_REQUIRED")
    require(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected), "CONFIGURATION_SHA256_REQUIRED")
    raw = private(configuration, expected)
    cfg = json.loads(raw)
    require(type(cfg) is dict and json.dumps(cfg, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                           allow_nan=False).encode("ascii") == raw
            and cfg.get("schema") == "ouf.semantic-provider-lease-supervisor.v1",
            "EXACT_SUPERVISOR_CONFIGURATION_REQUIRED")
    hashes = cfg.get("sourceHashes")
    require(type(hashes) is dict and set(hashes) == SOURCES
            and all(type(h) is str and re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes.values()),
            "EXACT_SUPERVISOR_SOURCE_SET_REQUIRED")
    require(absolute(cfg.get("sourceRoot")), "ABSOLUTE_SOURCE_ROOT_REQUIRED")
    root = Path(cfg["sourceRoot"])
    private_root(root)
    require(Path(__file__).absolute() == root / SELF, "SUPERVISOR_ENTRYPOINT_PATH_DRIFT")
    # Check the running entrypoint first; no application byte executes until ALL pass.
    verified = {relative: private(root / relative, hashes[relative])
                for relative in (SELF, *sorted(SOURCES - {SELF}))}
    require(private(configuration, expected) == raw, "CONFIGURATION_CUSTODY_CHANGED")
    return root, verified


def execute(root, verified):
    for name in OPERATION_MODULES:
        relative = "tools/semantic_provider_operation/" + name + ".py"
        module = types.ModuleType(name)
        module.__file__ = str(root / relative)
        sys.modules[name] = module
        exec(compile(verified[relative], module.__file__, "exec"), module.__dict__)
    return module


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                "ROOT_ISOLATED_NO_BYTECODE_REQUIRED")
        require(len(args) == 4 and args.count("--configuration") == args.count("--configuration-sha256") == 1,
                "EXACT_BOOTSTRAP_ARGUMENTS_REQUIRED")
        values = {}
        for index in (0, 2):
            require(args[index] in {"--configuration", "--configuration-sha256"},
                    "EXACT_BOOTSTRAP_ARGUMENTS_REQUIRED")
            values[args[index]] = args[index + 1]
        root, verified = load_sources(values["--configuration"], values["--configuration-sha256"])
        return execute(root, verified).main(args)
    except Exception as error:
        code = str(error)
        if re.fullmatch(r"[A-Z0-9_]{1,80}", code) is None:
            code = "LOCAL_STATE_UNPROVEN"
        print(code, file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
