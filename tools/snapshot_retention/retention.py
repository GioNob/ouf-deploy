"""D-070. Run at release completion while the release executor owns the writer lock."""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile


POLICY = Path(__file__).with_name("policy.json")
ROOT = Path("/etc/ouf/deploy-snapshots")
SUFFIX = re.compile(r"-(?:[0-9a-f]{16,}|[a-z0-9_]{8}|v\d+|\d{8})$")


def family(top):
    while match := SUFFIX.search(top):
        if not match.start():
            break
        top = top[:match.start()]
    return top


def container_images():
    def docker(*args):
        return subprocess.check_output(["docker", *args], text=True).splitlines()
    ids = docker("ps", "-aq", "--no-trunc")
    return set(docker("inspect", "--format", "{{.Image}}", *ids)) if ids else set()


def image_in_use(path, images):
    if not images or path.suffix != ".tar":
        return False
    try:
        archive = tarfile.open(path, "r:")
    except tarfile.ReadError:
        # As in the reference census, only plain docker-save archives expose an ID.
        return False
    with archive:
        try:
            member = archive.getmember("manifest.json")
        except KeyError:
            return False
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError("manifest.json")
        manifest = json.load(archive.extractfile(member))
        return any("sha256:" + Path(row["Config"]).name.removesuffix(".json") in images
                   for row in manifest)


def metadata(root, path, st):
    return {"path": path.relative_to(root).as_posix(), "size": st.st_size, "mtimeNs": st.st_mtime_ns,
            "inode": st.st_ino, "device": st.st_dev, "links": st.st_nlink, "ctimeNs": st.st_ctime_ns}


def raise_error(error):
    raise error


def plan(root, policy, images):
    root = root.absolute()
    if root.resolve(strict=True) != root:
        raise ValueError("snapshot root is not a physical directory")
    for key in ("keepPerFamily", "smallBytes", "largeBytes"):
        if type(policy[key]) is not int or policy[key] < 1:
            raise ValueError(key)
    protected = re.compile(policy["protected"])
    if not policy["protected"]:
        raise ValueError("protected")
    groups = defaultdict(list)
    for top in sorted(root.iterdir()):
        if protected.search(top.name) or top.is_symlink() or not top.is_dir() or top.resolve() != top:
            continue
        rows = []
        for directory, dirs, files in os.walk(top, onerror=raise_error):
            physical = (Path(directory) / d for d in dirs)
            dirs[:] = sorted(p.name for p in physical if not p.is_symlink() and p.resolve() == p)
            for name in sorted(files):
                path = Path(directory) / name
                st = path.lstat()
                if stat.S_ISREG(st.st_mode) and (path.suffix in (".jar", ".tar") or st.st_size > policy["largeBytes"]):
                    rows.append(metadata(root, path, st))
        if rows:
            groups[family(top.name)].append((max(row["mtimeNs"] for row in rows), top.name, rows))
    remove = []
    for snapshots in groups.values():
        for _, _, rows in sorted(snapshots)[:-policy["keepPerFamily"]]:
            if any(image_in_use(root / row["path"], images) for row in rows):
                continue
            remove.extend(row for row in rows if row["size"] >= policy["smallBytes"] and row["links"] == 1)
    proposal = {"root": str(root), "policy": policy, "remove": sorted(remove, key=lambda r: r["path"])}
    encoded = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
    return {**proposal, "planSha256": hashlib.sha256(encoded).hexdigest()}


def apply(root, policy, images, digest):
    current = plan(root, policy, images)
    receipt = {"status": "HELD", "planSha256": digest, "removed": []}
    if digest != current["planSha256"]:
        return {**receipt, "reason": "PLAN_CHANGED"}
    root = Path(current["root"])
    try:
        for row in current["remove"]:
            path = root / row["path"]
            if path.resolve(strict=True) != path or metadata(root, path, path.lstat()) != row:
                return {**receipt, "reason": "FILE_CHANGED"}
            path.unlink()
            receipt["removed"].append(row["path"])
    except OSError as error:
        return {**receipt, "reason": str(error)}
    return {**receipt, "status": "APPLIED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, default=POLICY)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("plan")
    commands.add_parser("apply").add_argument("digest")
    args = parser.parse_args()
    try:
        policy = json.loads(args.config.read_text(encoding="utf-8"))
        images = container_images()
        if args.mode == "apply":
            result = apply(args.root, policy, images, args.digest)
        else:
            result = {"status": "PLANNED", **plan(args.root, policy, images)}
    except (OSError, ValueError, TypeError, KeyError, re.error, tarfile.TarError, subprocess.SubprocessError) as error:
        result = {"status": "HELD", "reason": str(error)}
    print(json.dumps(result, sort_keys=True))
    return int(result["status"] == "HELD")


if __name__ == "__main__":
    raise SystemExit(main())
