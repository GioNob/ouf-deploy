"""Per-CID operation epochs (sprint-01 task-37; contract in docs/OUF_SEMANTIC_PROVIDER_B2_DESIGN.md §13.4).

Layout under the runtime registry root:
    <registryRoot>/<cid>/current                     {"epoch": e, "journalSha256": ...}
    <registryRoot>/<cid>/epochs/<e>/adapter.json      journal ouf.semantic-docker-runtime-journal.v2

This module only VALIDATES and READS. The v5.2 runtime (task-39) is the only
writer. Readers use it to prove which epoch is live, on which boot and with
which process generation, and under which operation authorization.
"""
import json
import os
from pathlib import Path
import re
import stat

from authorization import OperationDenied, canonical, decode, require, sha, HEX64

JOURNAL_SCHEMA = "ouf.semantic-docker-runtime-journal.v2"
POINTER_FIELDS = {"epoch", "journalSha256"}
JOURNAL_FIELDS = {"schema", "containerId", "epoch", "bootId", "authorizationSha256", "configurationHash",
                  "state", "runtimeRoot", "bundleHash", "driverHash", "generation", "openedAt", "failure"}
STATES = ("OPENING", "PREPARING", "CREATING", "CREATED", "ADMITTED", "STARTING", "STARTED",
          "DELETING", "DELETED", "FAILED", "ABANDONED")
TERMINAL = frozenset({"DELETED", "FAILED", "ABANDONED"})
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
FAILURE = re.compile(r"[A-Z0-9_]{1,80}")
MAX_EPOCH = 10 ** 9
REQUIRED_UID = 0  # tests override


def file_bytes(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == REQUIRED_UID and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size <= limit, "EPOCH_FILE_CUSTODY_REQUIRED")
        raw = os.read(fd, limit + 1)
        require(len(raw) == info.st_size, "EPOCH_FILE_CHANGED_DURING_READ")
        return raw
    finally:
        os.close(fd)


def directory(path):
    info = os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == REQUIRED_UID and stat.S_IMODE(info.st_mode) == 0o700,
            "EPOCH_DIRECTORY_CUSTODY_REQUIRED")


def validate_journal(raw, cid, epoch):
    value = decode(raw)
    require(set(value) == JOURNAL_FIELDS and value["schema"] == JOURNAL_SCHEMA
            and value["containerId"] == cid and value["epoch"] == epoch, "EXACT_EPOCH_JOURNAL_REQUIRED")
    require(type(value["bootId"]) is str and BOOT_ID.fullmatch(value["bootId"]), "EPOCH_BOOT_ID_REQUIRED")
    require(all(type(value[k]) is str and HEX64.fullmatch(value[k])
                for k in ("authorizationSha256", "configurationHash")), "EPOCH_BINDINGS_REQUIRED")
    require(value["state"] in STATES, "EPOCH_STATE_REQUIRED")
    require(type(value["openedAt"]) is int and value["openedAt"] > 0, "EPOCH_OPENED_AT_REQUIRED")
    for name in ("bundleHash", "driverHash"):
        require(value[name] is None or (type(value[name]) is str and HEX64.fullmatch(value[name])),
                "EPOCH_HASH_FIELD_INVALID")
    require(value["runtimeRoot"] is None or (type(value["runtimeRoot"]) is str
                                             and value["runtimeRoot"].startswith("/")), "EPOCH_RUNTIME_ROOT_INVALID")
    generation = value["generation"]
    require(generation is None or (type(generation) is dict and set(generation) == {"pid", "startTicks"}
                                   and type(generation["pid"]) is int and 1 < generation["pid"] < 2 ** 22
                                   and type(generation["startTicks"]) is int and generation["startTicks"] > 0),
            "EPOCH_GENERATION_INVALID")
    require((value["state"] == "STARTED") <= (generation is not None), "STARTED_EPOCH_GENERATION_REQUIRED")
    require(value["failure"] is None if value["state"] != "FAILED"
            else (type(value["failure"]) is str and FAILURE.fullmatch(value["failure"])), "EPOCH_FAILURE_INVALID")
    return value


def current(registry_root, cid):
    """The live epoch of one CID, or None if it never had one."""
    require(type(cid) is str and HEX64.fullmatch(cid), "EPOCH_CONTAINER_ID_REQUIRED")
    base = Path(registry_root) / cid
    if not os.path.lexists(base / "current"):
        return None
    directory(base)
    pointer = decode(file_bytes(base / "current"))
    require(set(pointer) == POINTER_FIELDS and type(pointer["epoch"]) is int and 1 <= pointer["epoch"] <= MAX_EPOCH
            and type(pointer["journalSha256"]) is str and HEX64.fullmatch(pointer["journalSha256"]),
            "EXACT_EPOCH_POINTER_REQUIRED")
    directory(base / "epochs")
    folder = base / "epochs" / str(pointer["epoch"])
    directory(folder)
    raw = file_bytes(folder / "adapter.json")
    require(sha(raw) == pointer["journalSha256"], "EPOCH_POINTER_JOURNAL_DRIFT")
    later = [name for name in os.listdir(base / "epochs")
             if not re.fullmatch(r"[1-9][0-9]{0,9}", name) or int(name) > pointer["epoch"]]
    require(not later, "EPOCH_BEYOND_POINTER")
    return validate_journal(raw, cid, pointer["epoch"])


def boot_id(path="/proc/sys/kernel/random/boot_id"):
    with open(path, "rb") as stream:
        raw = stream.read(64).strip().decode("ascii")
    require(BOOT_ID.fullmatch(raw) is not None, "BOOT_ID_UNPROVEN")
    return raw


def start_ticks(pid, proc="/proc"):
    """Field 22 of /proc/<pid>/stat (after the parenthesized comm), or None if gone."""
    try:
        with open(f"{proc}/{pid}/stat", "rb") as stream:
            raw = stream.read(4096)
    except FileNotFoundError:
        return None
    fields = raw[raw.rindex(b")") + 2:].split()
    return int(fields[19])


def live(journal, boot, proc="/proc"):
    """True iff the epoch is STARTED on this boot and its exact process generation is alive."""
    return (journal["state"] == "STARTED" and journal["bootId"] == boot
            and start_ticks(journal["generation"]["pid"], proc) == journal["generation"]["startTicks"])
