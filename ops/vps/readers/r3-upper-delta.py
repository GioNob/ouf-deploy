#!/usr/bin/env python3
"""D-046(a)/D-047 reader: inventory of the stopped R3 upper layers, metadata only.

Uso (root, sola lettura):  sudo /usr/bin/python3.13 -I -B r3-upper-delta.py

The upper paths come from the D-042 rootfs result bound by sha256 (the same input
of the volatile restore). Never reads file contents, never follows links, never
writes. Entries below the five APISIX temp directories are summarized.
"""
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath

RESULT = Path("/var/lib/ouf-storage-migration/semantic-provider-b1-rootfs-20261116-mountpoint-0711/result.json")
RESULT_SHA = "49a82a05f7f935e63b76cfacdda742f928c112a1de2a61353436ef1cdac3f2b8"
TEMPS = tuple("usr/local/apisix/" + n for n in
              ("fastcgi_temp", "scgi_temp", "client_body_temp", "proxy_temp", "uwsgi_temp"))
MAX_ENTRIES, MAX_DEPTH, MAX_LISTED = 50000, 64, 400


def emit(**value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def bound(path, expected):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit("BINDING_DRIFT " + str(path))
    return json.loads(raw)


def kind(mode):
    for test, name in ((stat.S_ISDIR, "directory"), (stat.S_ISREG, "file"), (stat.S_ISLNK, "symlink"),
                       (stat.S_ISFIFO, "fifo"), (stat.S_ISSOCK, "socket"), (stat.S_ISCHR, "char"),
                       (stat.S_ISBLK, "block")):
        if test(mode):
            return name
    return "other"


def temp_of(path):
    return next((t for t in TEMPS if path == t or path.startswith(t + "/")), None)


def inventory(role, upper, expected_entries):
    rows, summary, count, listed = [], {}, 0, 0
    device = os.lstat(upper).st_dev
    stack = [("", upper)]
    while stack:
        relative, absolute = stack.pop()
        info = os.lstat(absolute)
        count += 1
        if count > MAX_ENTRIES:
            emit(role=role, step="truncated", entries=count)
            break
        k = kind(info.st_mode)
        row = dict(path=relative, kind=k, mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid,
                   gid=info.st_gid, links=info.st_nlink)
        if k == "file":
            row["size"] = info.st_size
        if k == "symlink":
            row["target"] = os.readlink(absolute)
        try:
            names = sorted(os.listxattr(absolute, follow_symlinks=False))
        except OSError:
            names = ["<unreadable>"]
        if names:
            row["xattrs"] = names
        if info.st_dev != device:
            row["crossDevice"] = True
        temp = temp_of(relative) if relative else None
        if temp and relative != temp and k in ("directory", "file") and not names \
                and (info.st_uid, info.st_gid) != (0, 0) and not info.st_mode & 0o7000:
            s = summary.setdefault(temp, dict(directories=0, files=0, bytes=0, maxDepth=0, owners=[]))
            s["directories" if k == "directory" else "files"] += 1
            s["bytes"] += info.st_size if k == "file" else 0
            s["maxDepth"] = max(s["maxDepth"], len(PurePosixPath(relative).parts) - len(PurePosixPath(temp).parts))
            owner = [info.st_uid, info.st_gid]
            if owner not in s["owners"]:
                s["owners"].append(owner)
        else:
            listed += 1
            if listed <= MAX_LISTED:
                emit(role=role, step="entry", **row)
        if k == "directory" and info.st_dev == device and len(PurePosixPath(relative).parts) < MAX_DEPTH:
            for name in sorted(os.listdir(absolute), reverse=True):
                stack.append((relative + "/" + name if relative else name, os.path.join(absolute, name)))
    emit(role=role, step="summary", entries=count, expectedUpperEntries=expected_entries,
         listed=listed, tempSummary=summary)


def main():
    if len(sys.argv) != 1:
        print("uso: r3-upper-delta.py (nessun argomento)", file=sys.stderr)
        return 2
    result = bound(RESULT, RESULT_SHA)
    for role in ("adapter", "southbound"):
        comparison = bound(result["roles"][role]["comparison"]["path"], result["roles"][role]["comparison"]["sha256"])
        snapshot = comparison["snapshot"]
        upper = snapshot["upper"]
        mounted = any(line.split()[4] in (snapshot["root"], upper)
                      for line in Path("/proc/self/mountinfo").read_text().splitlines())
        emit(role=role, step="snapshot", containerId=comparison.get("containerId"), upper=upper, mounted=mounted,
             expectedUpperSeal=comparison.get("expectedUpperSeal", {}).get("entries"))
        inventory(role, upper, comparison.get("expectedUpperSeal", {}).get("entries"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
