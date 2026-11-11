#!/usr/bin/env python3
"""Read environment names and the retained southbound image without lifecycle operations."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from contextlib import contextmanager


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
UID_CHECK_FAILURES = {
    10: "UID_636_CHROOT_FAILED",
    11: "UID_636_CHDIR_FAILED",
    12: "UID_636_SETGROUPS_FAILED",
    13: "UID_636_SETGID_FAILED",
    14: "UID_636_SETUID_FAILED",
    15: "UID_636_CONFIG_DIRECTORY_STAT_FAILED",
    16: "UID_636_CONFIG_TARGET_STAT_FAILED",
    17: "UID_636_CONFIG_ACCESS_CHECK_FAILED",
}


class ReviewError(ValueError):
    def __init__(self, code, error_number=None):
        super().__init__(code)
        self.code = code
        self.error_number = error_number


@contextmanager
def read_operation(code):
    try:
        yield
    except OSError as error:
        raise ReviewError(code, error.errno) from None
    except subprocess.TimeoutExpired:
        raise ReviewError(code + "_TIMEOUT") from None
    except (subprocess.SubprocessError, UnicodeError):
        raise ReviewError(code) from None


def require(condition, reason):
    if not condition:
        raise ReviewError(reason)


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
        with read_operation(role.upper() + "_CONTAINER_INSPECT_FAILED"):
            require(docker("container", "inspect", "--format", "{{.Id}} {{.Image}}", cid) == f"{cid} {image}",
                    "HISTORICAL_CONTAINER_IMAGE_CHANGED")
        with read_operation(role.upper() + "_CONTAINER_ENV_READ_FAILED"):
            historical = names(docker("container", "inspect", "--format", ENV_TEMPLATE, cid))
        with read_operation(role.upper() + "_IMAGE_ENV_READ_FAILED"):
            packaged = names(docker("image", "inspect", "--format", ENV_TEMPLATE, image))
        roles[role] = {"historicalNames": historical, "imageNames": packaged,
                       "containerOnlyNames": sorted(set(historical) - set(packaged)),
                       "imageOnlyNames": sorted(set(packaged) - set(historical))}
    return roles


def directory_access_as_636(rootfs):
    with read_operation("UID_636_FORK_FAILED"):
        pid = os.fork()
    if pid == 0:
        failure = 10
        try:
            os.chroot(rootfs)
            failure = 11
            os.chdir("/")
            failure = 12
            os.setgroups([])
            failure = 13
            os.setgid(636)
            failure = 14
            os.setuid(636)
            failure = 15
            parent = os.stat(CONFIG_DIR)
            target = CONFIG_DIR + "/apisix.yaml"
            failure = 16
            replace_allowed = True
            if parent.st_mode & stat.S_ISVTX and parent.st_uid != 636:
                try:
                    replace_allowed = os.lstat(target).st_uid == 636
                except FileNotFoundError:
                    pass
            failure = 17
            writable = os.access(CONFIG_DIR, os.W_OK | os.X_OK) and replace_allowed
            os._exit(0 if writable else 1)
        except OSError:
            os._exit(failure)
    with read_operation("UID_636_WAIT_FAILED"):
        _, wait_status = os.waitpid(pid, 0)
    require(os.WIFEXITED(wait_status), "UID_636_CHILD_TERMINATED")
    status = os.WEXITSTATUS(wait_status)
    require(status in (0, 1), UID_CHECK_FAILURES.get(status, "UID_636_UNEXPECTED_EXIT"))
    return status == 0


def image_receipt():
    with read_operation("OFFLINE_IMAGE_RECEIPT_READ_FAILED"):
        receipt_raw = (ROOT / "expected-rootfs.json").read_bytes()
    require(hashlib.sha256(receipt_raw).hexdigest() == RECEIPT_SHA256, "OFFLINE_IMAGE_RECEIPT_CHANGED")
    # The producer writes canonical UTF-8 JSON bytes without a trailer.
    try:
        receipt = json.loads(receipt_raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ReviewError("OFFLINE_IMAGE_RECEIPT_UTF8_INVALID") from None
    except json.JSONDecodeError:
        raise ReviewError("OFFLINE_IMAGE_RECEIPT_JSON_INVALID") from None
    require(isinstance(receipt, dict), "OFFLINE_IMAGE_RECEIPT_OBJECT_REQUIRED")
    require(receipt.get("schema") == "ouf.semantic-offline-image-rootfs.v1"
            and receipt.get("offlineImageRootfsReconstructed") is True, "OFFLINE_IMAGE_RECEIPT_SCHEMA_INVALID")
    require(isinstance(receipt.get("manifestDigest"), str), "OFFLINE_IMAGE_RECEIPT_MANIFEST_MISSING")
    return receipt


def image_review(result=None):
    if result is None:
        result = {}
    receipt = image_receipt()
    manifest = CONTAINERS["southbound"][1]
    require(receipt["manifestDigest"] == manifest, "OFFLINE_IMAGE_MANIFEST_CHANGED")
    result["manifest"] = manifest
    modules = ROOTFS / APISIX_HOME.lstrip("/") / "apisix"
    with read_operation("APISIX_VERSION_READ_FAILED"):
        version = re.search(rb'\bVERSION\s*=\s*"([0-9.]+)"', (modules / "core/version.lua").read_bytes())
    require(version is not None, "APISIX_VERSION_UNPROVEN")
    result["version"] = version[1].decode("ascii")
    with read_operation("APISIX_OPENID_CONNECT_READ_FAILED"):
        raw = (modules / "plugins/openid-connect.lua").read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    result["openidConnectSha256"] = hashlib.sha256(raw).hexdigest()
    result["checkSchemaAllowsBearerJwksWithoutSecret"] = (
        result["version"] == "3.18.0" and blob == APISIX_OPENID_CONNECT_BLOB
    )
    with read_operation("APISIX_CONFIG_DIRECTORY_STAT_FAILED"):
        directory = (ROOTFS / CONFIG_DIR.lstrip("/")).stat()
    require(stat.S_ISDIR(directory.st_mode), "APISIX_CONFIG_DIRECTORY_REQUIRED")
    result["configDirectoryOwner"] = [directory.st_uid, directory.st_gid]
    result["configDirectoryMode"] = oct(stat.S_IMODE(directory.st_mode))
    result["symlinkCreated"] = False
    result["uid636WriteSearchOnRetainedRootfs"] = directory_access_as_636(ROOTFS)
    return result


def kernel_review():
    with read_operation("KERNEL_RELEASE_READ_FAILED"):
        release = os.uname().release
    version = re.match(r"(\d+)\.(\d+)", release)
    require(version is not None, "KERNEL_VERSION_UNPROVEN")
    noswap = tuple(map(int, version.groups())) >= (6, 4)
    with read_operation("KERNEL_SWAP_STATUS_READ_FAILED"):
        active_swap = len(Path("/proc/swaps").read_text().splitlines()) > 1
    return {"release": release, "noswapByKernelVersion": noswap, "activeSwap": active_swap}


def main():
    report = {"schema": "ouf.discovery-stopped-image-review.v1", "status": "HELD", "readOnly": True}
    phase = "ROOT"
    try:
        require(os.geteuid() == 0, "ROOT_READ_REQUIRED")
        phase = "ENVIRONMENT"
        report["roles"] = environment_names()
        phase = "KERNEL"
        report["kernel"] = kernel_review()
        phase = "IMAGE_REVIEW"
        report["southboundImage"] = {}
        image_review(report["southboundImage"])
        report["status"] = "DISCOVERY_IMAGE_REVIEW_READ"
    except ReviewError as error:
        report["reason"] = error.code
        if error.error_number is not None:
            report["errno"] = error.error_number
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        report["reason"] = f"{phase}_UNEXPECTED_{type(error).__name__.upper()}"
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "DISCOVERY_IMAGE_REVIEW_READ" else 1


if __name__ == "__main__":
    raise SystemExit(main())
