#!/usr/bin/env python3
"""Pinned bootstrap: verify the complete package before executing application bytes.

Keep this bootstrap identical in the three entrypoints except SELF and TARGET.
No repository module is imported until every source has passed custody and hash
checks. Package search locations are empty; modules execute from verified bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

SELF = 'scripts/semantic-provider-deployment-broker-v2.py'
TARGET = 'broker_v2'
ENTRYPOINTS = ("scripts/semantic-provider-deployment-broker-v2.py",
              "scripts/semantic-provider-admission-preparer-v2.py",
              "scripts/semantic-provider-preexec-hook-v2.py")
MODULES = ("materialize_southbound_kernel", "materialize_southbound_lease_refresh", "semantic_provider_dns",
           "semantic_provider_lease_nft", "semantic_provider_lease_owner", "materialize_semantic_shared_faces",
           "semantic_provider_lease_coordination", "semantic_provider_preexec", "semantic_provider_preexec_native",
           "semantic_provider_peer_bindings", "semantic_provider_deployment_admission",
           "semantic_provider_deployment_protocol", "semantic_provider_deployment_consumption",
           "semantic_provider_deployment_authentication", "semantic_provider_deployment_producer",
           "semantic_provider_node_observation")
V2_MODULES = ("__init__", "consumption_v2", "evidence_v2", "reauthorization_v2",
              "broker_v2", "driver_v7", "preparer_v2")
SOURCES = ({"tools/" + name + ".py" for name in MODULES} | set(ENTRYPOINTS)
           | {"tools/semantic_provider_admission_v2/" + name + ".py" for name in V2_MODULES}
           | {"tools/semantic_provider_operation/authorization.py", "tools/semantic_provider_operation/epochs.py"})


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw):
    value = json.loads(raw)
    require(type(value) is dict and canonical(value) == raw, "EXACT_BOOTSTRAP_CONFIGURATION_REQUIRED")
    return value


def attributes(info):
    return tuple(getattr(info, k) for k in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                           "st_size", "st_mtime_ns", "st_ctime_ns"))


def private(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "PRIVATE_PATH_REQUIRED")
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "PRIVATE_ANCESTOR_REQUIRED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 131072,
                "PRIVATE_FILE_REQUIRED")
        raw = os.read(fd, 131073)
        require(len(raw) == info.st_size and attributes(info) == attributes(os.fstat(fd)), "PRIVATE_READ_DRIFT")
        return raw
    finally:
        os.close(fd)


def private_root(root):
    require(root.is_absolute() and ".." not in root.parts, "PRIVATE_SOURCE_ROOT_REQUIRED")
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_SOURCE_ROOT_REQUIRED")


def load_sources(configuration):
    raw = private(configuration)
    cfg = decode(raw)
    bound_raw = None
    if SELF == ENTRYPOINTS[1]:
        bound = cfg["configurationBinding"]
        require(type(bound) is dict and set(bound) == {"path", "sha256"}, "EXACT_BOOTSTRAP_BINDING_REQUIRED")
        bound_raw = private(bound["path"])
        require(hashlib.sha256(bound_raw).hexdigest() == bound["sha256"], "BOOTSTRAP_CONFIGURATION_DRIFT")
        cfg = decode(bound_raw)
    require(cfg["schema"] == ("ouf.semantic-preexec-driver.v7" if SELF == ENTRYPOINTS[2]
                              else "ouf.semantic-deployment-broker.v2"), "EXACT_BOOTSTRAP_CONFIGURATION_REQUIRED")
    hashes = cfg["sourceHashes"]
    require(type(hashes) is dict and set(hashes) == SOURCES
            and all(type(h) is str and re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes.values()),
            "EXACT_BROKER_SOURCE_SET_REQUIRED")
    root = Path(cfg["sourceRoot"])
    private_root(root)
    require(Path(__file__).absolute() == root / SELF, "BROKER_ENTRYPOINT_PATH_DRIFT")
    # Check this pinned entrypoint first, then collect the rest before ANY exec.
    verified = {}
    for relative in (SELF, *sorted(SOURCES - {SELF})):
        content = private(root / relative)
        require(hashlib.sha256(content).hexdigest() == hashes[relative], "BROKER_SOURCE_PACKAGE_DRIFT")
        verified[relative] = content
    require(private(configuration) == raw, "BOOTSTRAP_CONFIGURATION_DRIFT")
    if bound_raw is not None:
        require(private(bound["path"]) == bound_raw, "BOOTSTRAP_CONFIGURATION_DRIFT")
    return root, verified


def execute(root, verified):
    def package(name):
        module = types.ModuleType(name)
        module.__package__, module.__path__ = name, []
        sys.modules[name] = module
        if "." in name:
            parent, _, child = name.rpartition(".")
            setattr(sys.modules[parent], child, module)
        return module

    def compiled(name, relative, module=None):
        if module is None:
            module = types.ModuleType(name)
            module.__package__ = name.rpartition(".")[0]
            sys.modules[name] = module
            parent, _, child = name.rpartition(".")
            setattr(sys.modules[parent], child, module)
        module.__file__ = str(root / relative)
        exec(compile(verified[relative], module.__file__, "exec"), module.__dict__)
        return module

    package("tools")
    package("tools.semantic_provider_operation")
    operation = "tools.semantic_provider_operation."
    auth = compiled(operation + "authorization", "tools/semantic_provider_operation/authorization.py")
    # epochs.py's historical top-level import resolves to these verified bytes.
    sys.modules["authorization"] = auth
    compiled(operation + "epochs", "tools/semantic_provider_operation/epochs.py")
    for name in MODULES:
        compiled("tools." + name, "tools/" + name + ".py")
    name = "tools.semantic_provider_admission_v2"
    pkg = package(name)
    compiled(name, "tools/semantic_provider_admission_v2/__init__.py", pkg)
    for child in V2_MODULES[1:]:
        compiled(name + "." + child, "tools/semantic_provider_admission_v2/" + child + ".py")
    return sys.modules[name + "." + TARGET]


def bootstrap(configuration):
    root, verified = load_sources(configuration)
    return execute(root, verified)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                "ROOT_ISOLATED_NO_BYTECODE_REQUIRED")
        require(args.count("--configuration") == 1, "EXACT_BOOTSTRAP_ARGUMENTS_REQUIRED")
        index = args.index("--configuration")
        require(index + 1 < len(args), "EXACT_BOOTSTRAP_ARGUMENTS_REQUIRED")
        return bootstrap(args[index + 1]).main(args)
    except Exception:
        code = {ENTRYPOINTS[0]: "SEMANTIC_DEPLOYMENT_BROKER", ENTRYPOINTS[1]: "SEMANTIC_ADMISSION_PREPARER",
                ENTRYPOINTS[2]: "SEMANTIC_PREEXEC"}[SELF]
        print(code + "=DENIED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
