"""Closed installation contract and custody primitives."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

HEX = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")
PATH = re.compile(r"(?:/[a-zA-Z0-9_.-]+)+")
SCHEMA = "ouf.platform-restart-profile.v1"
GATE_LOOP = ('OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; '
             'while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"')


class Held(Exception):
    """Only stable, non-sensitive reason codes cross the CLI boundary."""


def require(value, reason):
    if not value:
        raise Held(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(value):
    require(isinstance(value, str) and PATH.fullmatch(value)
            and not {".", ".."}.intersection(value.split("/")), "INVALID_PATH")
    return Path(value)


def custody(path, kind=stat.S_ISREG):
    path = Path(path)
    for entry in [*reversed(path.parents), path]:
        info = entry.lstat()
        check = kind if entry == path else stat.S_ISDIR
        require(check(info.st_mode) and info.st_uid == 0, "ROOT_CUSTODY_REQUIRED")
        if check == stat.S_ISSOCK:
            require(not info.st_mode & 0o002, "SOCKET_CUSTODY_REQUIRED")
        else:
            require(not info.st_mode & 0o022, "ROOT_CUSTODY_REQUIRED")
        if check == stat.S_ISREG:
            require(info.st_nlink == 1, "ROOT_CUSTODY_REQUIRED")


def private_dir(path):
    custody(path, stat.S_ISDIR)
    require(not Path(path).stat().st_mode & 0o077, "PRIVATE_DIRECTORY_REQUIRED")


def unique(pairs):
    result = dict(pairs)
    require(len(pairs) == len(result), "DUPLICATE_FIELD")
    return result


def fields(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()), "INVALID_FIELDS")


def integer(value, maximum=86400):
    require(type(value) is int and 1 <= value <= maximum, "INVALID_INTEGER")


def name(value):
    require(isinstance(value, str) and NAME.fullmatch(value), "INVALID_NAME")


def validate_gate(gate, probe, level_timeout):
    fields(gate, "imageId entrypoint command")
    require(isinstance(gate["imageId"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", gate["imageId"]),
            "INVALID_IMAGE_ID")
    entry = gate["entrypoint"]
    require(isinstance(entry, list) and len(entry) == 4 and safe_path(entry[0]).name == "sh"
            and entry[1:] == ["-c", GATE_LOOP, "ouf-gated-application"], "INVALID_GATE_ENTRYPOINT")
    cmd = gate["command"]
    require(isinstance(cmd, list) and cmd and all(isinstance(v, str) and v and "\0" not in v for v in cmd),
            "INVALID_GATE_COMMAND")
    if cmd[0].startswith("/"):
        safe_path(cmd[0])
    else:
        name(cmd[0])
    required = "type address port path timeoutSeconds budgetSeconds acceptStatus"
    fields(probe, required + " jsonStatus" if "jsonStatus" in probe else required)
    codes = probe["acceptStatus"]
    require(type(codes) is list and codes and all(type(code) is int and 100 <= code <= 599 for code in codes)
            and len(codes) == len(set(codes)), "INVALID_HTTP_STATUS_CODES")
    if "jsonStatus" in probe:
        require(isinstance(probe["jsonStatus"], str) and probe["jsonStatus"], "INVALID_JSON_STATUS")
    require(probe["type"] == "actuator", "GATE_REQUIRES_ACTUATOR")
    try:
        loopback = isinstance(probe["address"], str) and ipaddress.IPv4Address(probe["address"]).is_loopback
    except ValueError:
        loopback = False
    require(loopback, "LOOPBACK_REQUIRED")
    safe_path(probe["path"])
    integer(probe["port"], 65535)
    integer(probe["timeoutSeconds"])
    integer(probe["budgetSeconds"])
    require(probe["timeoutSeconds"] <= probe["budgetSeconds"] <= level_timeout, "INVALID_READINESS_BUDGET")


def load_profile(raw, expected):
    require(sha(raw) == expected, "PROFILE_HASH_CHANGED")
    try:
        cfg = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        raise Held("INVALID_JSON") from None
    fields(cfg, "schema levels governedElsewhere docker dockerSocket inventoryTimeoutSeconds stopTimeoutSeconds receipts incidents bootRetryDelaysSeconds")
    require(cfg["schema"] == SCHEMA, "INVALID_SCHEMA")
    fields(cfg["docker"], "path sha256")
    require(isinstance(cfg["docker"]["sha256"], str) and HEX.fullmatch(cfg["docker"]["sha256"]), "INVALID_HASH")
    for value in [cfg["docker"]["path"], cfg["dockerSocket"], cfg["receipts"], cfg["incidents"]]:
        safe_path(value)
    require(cfg["receipts"] != cfg["incidents"], "DISTINCT_DIRECTORIES_REQUIRED")
    integer(cfg["stopTimeoutSeconds"])
    integer(cfg["inventoryTimeoutSeconds"])
    delays = cfg["bootRetryDelaysSeconds"]
    require(type(delays) is list and 1 <= len(delays) <= 5, "INVALID_BACKOFF")
    for delay in delays:
        integer(delay, 3600)
    require(delays == sorted(set(delays)), "INVALID_BACKOFF")
    excluded = cfg["governedElsewhere"]
    require(type(excluded) is list and len(excluded) >= 2, "INVALID_EXCLUSIONS")
    for item in excluded:
        name(item)
    names = set(excluded)
    require(len(names) == len(excluded), "DUPLICATE_NAME")
    levels = cfg["levels"]
    require(type(levels) is list and levels, "EMPTY_LEVELS")
    for level in levels:
        fields(level, "containers timeoutSeconds")
        integer(level["timeoutSeconds"])
        require(type(level["containers"]) is list and level["containers"], "EMPTY_LEVEL")
        for item in level["containers"]:
            gated = isinstance(item, dict) and "gate" in item
            fields(item, "containerName readiness gate" if gated else "containerName readiness")
            target = item["containerName"]
            name(target)
            require(target not in names, "DUPLICATE_OR_EXCLUDED_NAME")
            require(not any(token in target.lower() for token in ("retained", "retired", "before-")),
                    "RETAINED_NAME")
            names.add(target)
            probe = item["readiness"]
            require(type(probe) is dict, "INVALID_PROBE")
            kind = probe.get("type")
            if gated:
                validate_gate(item["gate"], probe, level["timeoutSeconds"])
            elif kind == "tcp":
                fields(probe, "type network port timeoutSeconds")
                name(probe["network"])
                integer(probe["port"], 65535)
                integer(probe["timeoutSeconds"])
            elif kind == "running":
                fields(probe, "type stableSeconds")
                integer(probe["stableSeconds"])
                require(probe["stableSeconds"] < level["timeoutSeconds"], "INVALID_STABILITY_WINDOW")
            else:
                fields(probe, "type")
                require(kind == "healthy", "INVALID_PROBE")
    return cfg
