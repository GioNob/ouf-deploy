"""Local POSIX custody and Docker read-only access for D-052."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import time

from .routes import canonical, decode, require, sha


PRIVATE = (0, 0, 0o600)
DOCKER = "/usr/bin/docker"
DOCKER_SHA = "7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40"
DOCKER_SOCKET = "unix:///var/run/docker.sock"
DOCKER_CONFIG = "/etc/ouf/deploy-snapshots/semantic-provider-routes-d052/docker-config"
CID = re.compile(r"[0-9a-f]{64}")
IDENTITY = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
            "st_mtime_ns", "st_ctime_ns")


def absolute(value):
    value = str(value)
    path = PurePosixPath(value)
    require(value.startswith("/") and not value.startswith("//") and str(path) == value
            and ".." not in path.parts and not any(ord(c) < 32 for c in value),
            "NORMALIZED_ABSOLUTE_PATH_REQUIRED")
    return Path(value)


def identity(entry):
    return tuple(getattr(entry, field) for field in IDENTITY)


def directory(path, *, private=False):
    path = absolute(path)
    for current in (*reversed(path.parents), path):
        entry = current.lstat()
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0 and not entry.st_mode & 0o022,
                "DIRECTORY_CUSTODY_UNPROVEN")
    if private:
        require(entry.st_gid == 0 and stat.S_IMODE(entry.st_mode) == 0o700, "PRIVATE_DIRECTORY_REQUIRED")
    return entry


def read(path, expected=None, *, metadata=PRIVATE, limit=1048576):
    path = absolute(path)
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        entry = os.fstat(fd)
        require(stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1 and 0 <= entry.st_size <= limit
                and (entry.st_uid, entry.st_gid, stat.S_IMODE(entry.st_mode)) == metadata,
                "FILE_CUSTODY_UNPROVEN")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == entry.st_size and identity(entry) == identity(os.fstat(fd))
                == identity(path.lstat()), "FILE_CHANGED_DURING_READ")
        require(expected is None or sha(raw) == expected, "INPUT_SHA256_MISMATCH")
        return raw
    finally:
        os.close(fd)


@contextmanager
def locked(path, *, is_directory=False):
    import fcntl

    if is_directory:
        entry = directory(path, private=True)
    else:
        require(read(path, limit=0) == b"", "LOCK_CUSTODY_UNPROVEN")
        entry = path.lstat()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags | (os.O_DIRECTORY if is_directory else 0))
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Authorization directories can have a different mtime after issuance.
        require(identity(entry)[:6] == identity(os.fstat(fd))[:6] == identity(path.lstat())[:6],
                "LOCK_CUSTODY_UNPROVEN")
        yield
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_once(path, raw, metadata=PRIVATE):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        uid, gid, mode = metadata
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    require(read(path, metadata=metadata) == raw, "WRITE_READBACK_MISMATCH")
    sync_dir(path.parent)


def write_document(path, document):
    write_once(path, canonical(document) + b"\n")


def executable(path, expected):
    path = absolute(path)
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        entry = os.fstat(fd)
        require(stat.S_ISREG(entry.st_mode) and entry.st_uid == 0 and not entry.st_mode & 0o022
                and entry.st_mode & 0o111 and 0 < entry.st_size <= 64000000, "EXECUTABLE_CUSTODY_UNPROVEN")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        require(digest == expected and identity(entry) == identity(os.fstat(fd))
                == identity(path.lstat()), "EXECUTABLE_HASH_MISMATCH")
    finally:
        os.close(fd)


class Docker:
    def command(self, *arguments):
        require(not os.path.lexists(DOCKER_CONFIG), "DOCKER_CONFIG_UNPROVEN")
        executable(DOCKER, DOCKER_SHA)
        process = subprocess.Popen([DOCKER, "--host", DOCKER_SOCKET, "--config", DOCKER_CONFIG, *arguments],
                                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "DOCKER_API_VERSION": "1.44"},
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        limit = 2097152
        raw = bytearray()
        deadline = time.monotonic() + 25
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0 and selector.select(remaining), "DOCKER_READ_TIMEOUT")
                    part = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
                    require(len(raw) <= limit, "DOCKER_READ_UNBOUNDED")
            require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0, "DOCKER_READ_UNPROVEN")
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        executable(DOCKER, DOCKER_SHA)
        return bytes(raw)

    def ids(self):
        rows = self.command("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}").decode("ascii").splitlines()
        require(len(rows) <= 256 and all(CID.fullmatch(cid) for cid in rows) and len(rows) == len(set(rows)),
                "DOCKER_INVENTORY_UNPROVEN")
        return sorted(rows)

    def inspect(self, cid):
        require(CID.fullmatch(cid), "DOCKER_CONTAINER_ID_REQUIRED")
        rows = decode(self.command("container", "inspect", cid))
        require(type(rows) is list and len(rows) == 1 and rows[0]["Id"] == cid, "DOCKER_INSPECT_UNPROVEN")
        return rows[0]


def stopped(frame):
    state = frame["State"]
    require(state["Status"] in {"created", "exited"} and state["Running"] is False
            and state["Paused"] is False and state["Restarting"] is False
            and state.get("Dead", False) is False and type(state["Pid"]) is int and state["Pid"] == 0,
            "PROVIDER_NOT_STOPPED")


def mount_source(value):
    return absolute(value).resolve()


def mount_scan(docker, cids, source):
    ids = docker.ids()
    require(set(cids.values()) <= set(ids), "PROVIDER_CONTAINER_MISSING")
    candidates = {}
    affected = []
    for cid in ids:
        row = docker.inspect(cid)
        state = row["State"]
        require(type(state["Running"]) is bool and type(state["Pid"]) is int
                and state["Status"] in {"created", "exited", "running", "paused", "restarting", "removing", "dead"},
                "DOCKER_STATE_UNPROVEN")
        if cid in cids.values():
            stopped(row)
            candidates[cid] = row
        require(type(row["Mounts"]) is list, "DOCKER_MOUNTS_UNPROVEN")
        for mount in row["Mounts"]:
            require(type(mount["Source"]) is str, "DOCKER_MOUNTS_UNPROVEN")
            if mount["Type"] == "tmpfs" and mount["Source"] in {"", "tmpfs"}:
                continue
            mounted = mount_source(mount["Source"])
            if mounted == source or mounted in source.parents:
                require(state["Running"] is False and state["Pid"] == 0
                        and state["Status"] in {"created", "exited", "dead"}, "ROUTES_MOUNT_IN_USE")
                affected.append({"cid": cid, "source": str(mounted)})
    require(ids == docker.ids(), "DOCKER_INVENTORY_CHANGED")
    return {"inventorySha256": sha(canonical(ids)), "containers": len(ids), "stoppedMounts": affected}, candidates
