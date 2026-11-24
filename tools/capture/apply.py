"""Crash-consistent per-family capture. Only the etcd member stages plaintext."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import threading

from .contract import CHUNK, GIB, MIB, VERSION, canonical, digest_file, profile, read_json, require
from .host import SNAPSHOT, SNAP_DIR
from .plan import file_state, make_plan


def sync_dir(directory):
    if os.name == "posix":
        fd = os.open(directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def publish(path, value):
    tmp = path.with_suffix(".new")
    raw = canonical(value)
    used = sum(r["cipherBytes"] for r in value["archives"].values())
    require(used + len(raw) <= value["maxTotalBytes"], "CAPTURE_TOTAL_CAP")
    require(shutil.disk_usage(path.parent).free >= value["minFreeBytes"] + len(raw), "CAPTURE_FREE_SPACE")
    with tmp.open("wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    tmp.replace(path)
    sync_dir(path.parent)


@contextmanager
def source_file(path):
    # Walk with directory FDs: renaming a parent to a symlink cannot redirect a read.
    if os.name != "posix":
        with path.open("rb") as stream:
            yield stream
        return
    fd = os.open("/", os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, "rb") as stream:
            yield stream
    finally:
        os.close(fd)


def pack_files(plan, sink):
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for filename, row in plan["files"].items():
            path = Path(filename)
            state = row["state"]
            require(file_state(path.lstat()) == state, "SOURCE_CHANGED")
            mode, uid, gid, size, mtime, _ = state
            info = tarfile.TarInfo(path.as_posix().lstrip("/"))
            info.uid, info.gid, info.size = uid, gid, size
            info.mode, info.mtime = stat.S_IMODE(mode), mtime // 10**9
            if stat.S_ISREG(mode):
                with source_file(path) as stream:
                    require(file_state(os.fstat(stream.fileno())) == state, "SOURCE_CHANGED")
                    archive.addfile(info, stream)
                    require(file_state(os.fstat(stream.fileno())) == state, "SOURCE_CHANGED")
            else:
                info.type = tarfile.DIRTYPE if stat.S_ISDIR(mode) else tarfile.SYMTYPE
                info.linkname = row["link"]
                archive.addfile(info)


def container_id(plan, name):
    return next(c["cid"] for c in plan["inventory"]["containers"] if c["name"] == name)


def produce(host, cfg, plan, family, sink, remaining, digest):
    if family == "host-files":
        pack_files(plan, sink)
    elif family == "docker-inventory":
        sink.write(canonical(plan["inventory"]))
    elif family == "postgres":
        pg = cfg["postgres"]
        command = ["exec", container_id(plan, pg["container"])]
        filtered = {}
        for rule in pg["omitTableData"]:
            filtered.setdefault(rule["database"], []).append(
                '--exclude-table-data="' + rule["schema"] + '"."' + rule["table"] + '"')
        exclude = ['--exclude-database="' + name + '"' for name in sorted(filtered)]
        host.stream([*command, "pg_dumpall", "-w", "-U", pg["user"], "-l", pg["database"], *exclude], sink)
        # Keep globals and every database, including schema/constraints of excluded payload tables.
        for name, options in sorted(filtered.items()):
            host.stream([*command, "pg_dump", "-w", "--create", "-U", pg["user"],
                         *sorted(options), "--dbname", name], sink)
        if filtered:
            sink.write(b"\n-- PostgreSQL database cluster dump complete\n")
    elif family == "etcd":
        host.stream(["exec", container_id(plan, cfg["etcd"]["container"]), "sh", "-c", SNAPSHOT,
                     "snapshot", SNAP_DIR + "-" + digest, str(max(1, remaining // 1024))], sink)
    else:
        image = plan["localImages"][int(family.split("-")[1]) - 1]
        host.stream(["image", "save", image], sink)


class MeasuredWriter:
    def __init__(self, pipe, limit):
        self.pipe = pipe
        self.limit = limit
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, chunk):
        require(self.size + len(chunk) <= self.limit, "CAPTURE_TOTAL_CAP")
        self.pipe.write(chunk)
        self.digest.update(chunk)
        self.size += len(chunk)
        return len(chunk)


def encrypt(host, cfg, file, produce_stream, plain_limit, cipher_limit):
    args = [arg for key in cfg["recipients"] for arg in ("-r", key)]
    floor = cfg["minFreeMiB"] * MIB
    errors = []
    with file.open("xb") as out, host.process("age", args, stdin=subprocess.PIPE,
                                              stdout=subprocess.PIPE) as process:
        plain = MeasuredWriter(process.stdin, plain_limit)
        cipher = MeasuredWriter(out, cipher_limit)

        def drain():
            try:
                while chunk := process.stdout.read(CHUNK):
                    require(shutil.disk_usage(file.parent).free >= floor + len(chunk), "CAPTURE_FREE_SPACE")
                    cipher.write(chunk)
            except BaseException as exc:
                errors.append(exc)
                process.kill()
            finally:
                process.stdout.close()

        reader = threading.Thread(target=drain)
        reader.start()
        try:
            produce_stream(plain)
            process.stdin.close()
            reader.join()
            if errors:
                raise errors[0]
            require(process.wait() == 0 and plain.size and cipher.size, "ENCRYPTION_FAILED")
            out.flush()
            os.fsync(out.fileno())
        finally:
            if process.poll() is None:
                process.kill()
            reader.join()
            if errors:
                raise errors[0]
    return dict(plainBytes=plain.size, plainSha256=plain.digest.hexdigest(),
                cipherBytes=cipher.size, cipherSha256=cipher.digest.hexdigest())


def valid_cipher(path, row):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == row["cipherBytes"]
            and digest_file(path) == row["cipherSha256"], "CIPHER_MISMATCH")


def recover_snapshot(host, partial, journal):
    cid = journal.get("etcdPending")
    if cid:
        if host.clean_snapshot(cid, journal["planSha256"]):
            journal["cleanupEvents"].append("ETCD_PLAINTEXT_REMOVED")
        del journal["etcdPending"]
        publish(partial, journal)


def apply(host, cfg, entries, profile_path, commit, expected):
    output = Path(cfg["outputDir"])
    with host.lock(output):
        require(cfg == profile(profile_path, entries), "PROFILE_CHANGED")
        final, partial = output / "manifest.json", output / "manifest.partial.json"
        if partial.exists():
            previous = read_json(partial)
            require(previous["planSha256"] == expected, "CHECKPOINT_CHANGED")
            # Recovery owns only this intent's old CID and digest-qualified tmpfs path.
            # Even a drifted plan must release its plaintext before denying another capture.
            recover_snapshot(host, partial, previous)
        plan, digest = make_plan(host, cfg, entries, profile_path, commit)
        require(not plan["reasons"], next(iter(plan["reasons"]), "CAPTURE_HELD"))
        require(digest == expected, "PLAN_CHANGED")
        work = output / ".capture-work"
        present = final.exists() or partial.exists()
        if present:
            journal = read_json(final if final.exists() else partial)
            require(journal["planSha256"] == digest and journal["families"] == plan["families"]
                    and journal["excluded"] == plan["excluded"], "CHECKPOINT_CHANGED")
        else:
            require(all(p.name == "manifest.partial.new" for p in output.iterdir()), "OUTPUT_NOT_EMPTY")
            journal = dict(schema="ouf.capture-manifest.v1", version=VERSION, commit=commit,
                maxTotalBytes=cfg["maxTotalGiB"] * GIB, minFreeBytes=cfg["minFreeMiB"] * MIB,
                planSha256=digest, registerSha256=plan["registerSha256"], bootId=plan["bootId"],
                utc=datetime.now(timezone.utc).isoformat(), families=plan["families"],
                excluded=plan["excluded"], archives={}, cleanupEvents=[], complete=False)
            publish(partial, journal)
        for name, row in journal["archives"].items():
            require(name in plan["families"], "CHECKPOINT_CHANGED")
            require(all(row[k] == plan["families"][name][k] for k in ("ids", "counts")),
                    "CHECKPOINT_CHANGED")
            valid_cipher(output / (name + ".age"), row)
        if final.exists():
            require(journal["complete"] and journal["archives"].keys() == plan["families"].keys(),
                    "INCOMPLETE_MANIFEST")
            return journal
        work.mkdir(mode=0o700, exist_ok=True)
        require(not work.is_symlink() and work.is_dir(), "INVALID_WORK_DIR")
        etcd_cid = container_id(plan, cfg["etcd"]["container"])
        try:
            for p in work.iterdir():
                require(p.name == "cipher.part" and not p.is_symlink(), "UNKNOWN_WORK_FILE")
                p.unlink()
                journal["cleanupEvents"].append("PARTIAL_CIPHERTEXT_REMOVED")
                publish(partial, journal)
            limit = cfg["maxTotalGiB"] * GIB
            for name, family in plan["families"].items():
                if name in journal["archives"]:
                    continue
                path = output / (name + ".age")
                # A crash between rename and journal commit leaves an uncommitted ciphertext.
                path.unlink(missing_ok=True)
                free = shutil.disk_usage(output).free
                require(free >= cfg["minFreeMiB"] * MIB + family["estimate"], "CAPTURE_FREE_SPACE")
                plain = limit - sum(r["plainBytes"] for r in journal["archives"].values())
                cipher = limit - partial.stat().st_size - sum(r["cipherBytes"] for r in journal["archives"].values())
                staged = work / "cipher.part"
                if name == "etcd":
                    journal["etcdPending"] = etcd_cid
                    publish(partial, journal)
                row = encrypt(host, cfg, staged,
                    lambda stream: produce(host, cfg, plan, name, stream, plain, digest), plain, cipher)
                staged.replace(path)
                sync_dir(output)
                journal["archives"][name] = {**row, "ids": family["ids"], "counts": family["counts"]}
                if name == "etcd":
                    del journal["etcdPending"]
                publish(partial, journal)
            journal["complete"] = True
            publish(partial, journal)
            partial.replace(final)
            sync_dir(output)
            return journal
        finally:
            try:
                recover_snapshot(host, partial, journal)
            finally:
                (work / "cipher.part").unlink(missing_ok=True)
                work.rmdir()
