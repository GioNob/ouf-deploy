#!/usr/bin/env python3
"""Read environment names and the retained southbound image without lifecycle operations."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


ROOT = Path("/etc/ouf/deploy-snapshots/semantic-provider-v2-offline-rootfs-s3BU0nDX/southbound")
ROOTFS = ROOT / "bundle/rootfs"
RECEIPT_SHA256 = "4fb4a4f00f46d795df5beeffb2055162872374d279be6a526f75f3af7d43e6c9"
APISIX_OPENID_CONNECT_BLOB = "b4913a741cd5e05274f0c4e545a528b974acb3b5"
CONTAINERS = {
    "adapter": ("f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67",
                "sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc"),
    "southbound": ("1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916",
                   "sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366"),
}
ENV_TEMPLATE = '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}'
APISIX_HOME = "/usr/local/apisix"
CONFIG_DIR = APISIX_HOME + "/conf"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def docker(*args):
    return subprocess.check_output(("/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args),
                                   text=True, stderr=subprocess.DEVNULL, timeout=25,
                                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}).strip()


def names(result):
    entries = result.split()
    require(len(entries) == len(set(entries))
            and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in entries),
            "ENV_NAME_LIST_INVALID")
    return sorted(entries)


def environment_names():
    roles = {}
    for role, (cid, image) in CONTAINERS.items():
        require(docker("container", "inspect", "--format", "{{.Id}} {{.Image}}", cid) == f"{cid} {image}",
                "HISTORICAL_CONTAINER_IMAGE_CHANGED")
        historical = names(docker("container", "inspect", "--format", ENV_TEMPLATE, cid))
        packaged = names(docker("image", "inspect", "--format", ENV_TEMPLATE, image))
        roles[role] = {"historicalNames": historical, "imageNames": packaged,
                       "containerOnlyNames": sorted(set(historical) - set(packaged)),
                       "imageOnlyNames": sorted(set(packaged) - set(historical))}
    return roles


def directory_access_as_636(rootfs):
    pid = os.fork()
    if pid == 0:
        try:
            os.chroot(rootfs)
            os.chdir("/")
            os.setgroups([])
            os.setgid(636)
            os.setuid(636)
            parent = os.stat(CONFIG_DIR)
            target = CONFIG_DIR + "/apisix.yaml"
            replace_allowed = (not parent.st_mode & stat.S_ISVTX or parent.st_uid == 636
                               or not os.path.lexists(target) or os.lstat(target).st_uid == 636)
            writable = os.access(CONFIG_DIR, os.W_OK | os.X_OK) and replace_allowed
            os._exit(0 if writable else 1)
        except OSError:
            os._exit(2)
    status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    require(status in (0, 1), "UID_636_ACCESS_CHECK_INCOMPLETE")
    return status == 0


def image_review():
    receipt_raw = (ROOT / "expected-rootfs.json").read_bytes()
    require(hashlib.sha256(receipt_raw).hexdigest() == RECEIPT_SHA256, "OFFLINE_IMAGE_RECEIPT_CHANGED")
    receipt = json.loads(receipt_raw)
    manifest = CONTAINERS["southbound"][1]
    require(receipt["manifestDigest"] == manifest, "OFFLINE_IMAGE_MANIFEST_CHANGED")
    modules = ROOTFS / APISIX_HOME.lstrip("/") / "apisix"
    version = re.search(rb'\bVERSION\s*=\s*"([0-9.]+)"', (modules / "core/version.lua").read_bytes())
    require(version is not None, "APISIX_VERSION_UNPROVEN")
    raw = (modules / "plugins/openid-connect.lua").read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    version = version[1].decode("ascii")
    directory = (ROOTFS / CONFIG_DIR.lstrip("/")).stat()
    return {"manifest": manifest, "version": version, "openidConnectSha256": hashlib.sha256(raw).hexdigest(),
            "checkSchemaAllowsBearerJwksWithoutSecret": version == "3.18.0" and blob == APISIX_OPENID_CONNECT_BLOB,
            "configDirectoryOwner": [directory.st_uid, directory.st_gid],
            "configDirectoryMode": oct(stat.S_IMODE(directory.st_mode)),
            "uid636WriteSearchOnRetainedRootfs": directory_access_as_636(ROOTFS),
            "symlinkCreated": False}


def kernel_review():
    release = os.uname().release
    version = re.match(r"(\d+)\.(\d+)", release)
    require(version is not None, "KERNEL_VERSION_UNPROVEN")
    noswap = tuple(map(int, version.groups())) >= (6, 4)
    return {"release": release, "noswapByKernelVersion": noswap,
            "activeSwap": len(Path("/proc/swaps").read_text().splitlines()) > 1}


def main():
    report = {"schema": "ouf.discovery-stopped-image-review.v1", "status": "HELD", "readOnly": True}
    try:
        require(os.geteuid() == 0, "ROOT_READ_REQUIRED")
        report["roles"] = environment_names()
        report["kernel"] = kernel_review()
        report["southboundImage"] = image_review()
        report["status"] = "DISCOVERY_IMAGE_REVIEW_READ"
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        report["reason"] = str(error) if type(error) is ValueError and re.fullmatch(r"[A-Z_]+", str(error)) else type(error).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "DISCOVERY_IMAGE_REVIEW_READ" else 1


if __name__ == "__main__":
    raise SystemExit(main())
