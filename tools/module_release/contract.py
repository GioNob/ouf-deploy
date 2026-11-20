"""Private installation profile and public, content-addressed CI identity."""

import hashlib
import ipaddress
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path


class Held(Exception):
    """Only stable reason codes may cross the executor boundary."""


def require(condition, code):
    if not condition:
        raise Held(code)


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def checksum(stream, copy_to=None):
    value = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        value.update(chunk)
        if copy_to is not None:
            copy_to.write(chunk)
    return value.hexdigest()


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


NAME = r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}"
SHA = r"[0-9a-f]{64}"
IMAGE = "sha256:" + SHA
GATE = ('OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; '
        'while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"')
ENTRY = ["/bin/sh", "-c", GATE, "ouf-gated-application"]


def argv(value):
    return isinstance(value, list) and value and all(isinstance(v, str) and v and "\0" not in v for v in value)


def validate(p):
    require(p["schema"] == "ouf.module-release.v1", "PROFILE_VERSION")
    for name in ("module", "container", "retainedName", "failedName"):
        require(matches(NAME, p[name]), "INVALID_NAME")
    require(len({p[k] for k in ("container", "retainedName", "failedName")}) == 3, "NAME_COLLISION")
    require(matches(IMAGE, p["oldImage"]), "PREDECESSOR_IMAGE_REQUIRED")
    for key in ("inbox", "journal", "dockerSocket", "nsenter"):
        require(Path(p[key]).is_absolute() and ".." not in Path(p[key]).parts, "ABSOLUTE_PATH_REQUIRED")
    require(p["networks"] and all(matches(NAME, n) for n in p["networks"]), "NETWORKS_REQUIRED")
    for binding in p["networks"].values():
        ipaddress.IPv4Address(binding["ipv4"])
        require(isinstance(binding["aliases"], list) and all(matches(NAME, a) for a in binding["aliases"]),
                "INVALID_NETWORK_ALIASES")
    require(argv(p["gate"]["command"]), "APPLICATION_COMMAND_REQUIRED")
    ready = p["readiness"]
    require(ready["path"].startswith("/") and not ready["path"].startswith("//")
            and 0 < ready["port"] < 65536 and 0 < ready["attempts"] <= 300
            and ready["acceptStatus"] and all(type(s) is int and 200 <= s < 300 for s in ready["acceptStatus"])
            and ("jsonStatus" not in ready or isinstance(ready["jsonStatus"], str)), "INVALID_READINESS")
    migration = p["migration"]
    require(migration["mode"] in ("none", "spring-flyway", "dedicated")
            and type(migration["rollbackCompatible"]) is bool, "INVALID_MIGRATION")
    require(("command" in migration) == (migration["mode"] == "dedicated")
            and ("command" not in migration or argv(migration["command"])), "INVALID_MIGRATION_COMMAND")
    ci = p["ci"]
    require(matches(NAME + "/" + NAME, ci["repository"]) and matches(NAME, ci["imageName"])
            and matches(r"[0-9a-f]{40}", ci["sourceCommit"]) and matches(r"[0-9a-f]{40}", ci["sourceTree"])
            and all(type(ci[k]) is int and ci[k] > 0 for k in ("runId", "runAttempt", "artifactId"))
            and matches(SHA, ci["zipSha256"]) and matches(IMAGE, ci["imageId"]), "CI_PINS_REQUIRED")


def image_ids(archive, tag, repository, tested):
    """Bind both Docker store identities to the single CI image, without extracting files."""
    metadata = {}
    total = 0
    with tarfile.open(fileobj=archive, mode="r|gz") as tar:
        for member in tar:
            if not member.isfile() or member.size > 1 << 20:
                continue
            if member.name not in ("manifest.json", "index.json") and not matches(
                    r"(blobs/sha256/[a-f0-9]{64}|[a-f0-9]{64}\.json)", member.name):
                continue
            total += member.size
            require(total <= 16 << 20 and member.name not in metadata, "INVALID_IMAGE_METADATA")
            metadata[member.name] = tar.extractfile(member).read()
    entry, = json.loads(metadata["manifest.json"])
    require(entry["RepoTags"] in ([tag], ["docker.io/library/" + tag]), "IMAGE_TAG_CHANGED")
    raw = metadata[entry["Config"]]
    config_hash = hashlib.sha256(raw).hexdigest()
    require(entry["Config"] in ("blobs/sha256/" + config_hash, config_hash + ".json"), "IMAGE_CONFIG_DIGEST_CHANGED")
    labels = json.loads(raw)["config"]["Labels"]
    require(labels["org.opencontainers.image.revision"] == tested and
            labels["org.opencontainers.image.source"] == "https://github.com/" + repository, "IMAGE_LABELS_CHANGED")
    ids = {"sha256:" + config_hash}
    if "index.json" in metadata:
        descriptor, = json.loads(metadata["index.json"])["manifests"]
        ident = descriptor["digest"]
        require(matches(IMAGE, ident), "INVALID_OCI_DESCRIPTOR")
        raw = metadata["blobs/sha256/" + ident[7:]]
        require(len(raw) == descriptor["size"] and hashlib.sha256(raw).hexdigest() == ident[7:]
                and json.loads(raw)["config"]["digest"] in ids, "IMAGE_MANIFEST_DIGEST_CHANGED")
        ids.add(ident)
    return ids


def package(p, target=None, *, transport=False):
    """Hash the exact open ZIP and inner payload. Only copy verified bytes to private custody."""
    ci = p["ci"]
    path = Path(p["inbox"]) / (ci["zipSha256"] + ".zip")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "REGULAR_ARTIFACT_REQUIRED")
        require(checksum(stream) == ci["zipSha256"], "ARTIFACT_DIGEST_CHANGED")
        with zipfile.ZipFile(stream) as z:
            require(sorted(z.namelist()) == ["SHA256SUMS", "image.tar.gz", "manifest.json"]
                    and z.getinfo("manifest.json").file_size <= 65536
                    and z.getinfo("SHA256SUMS").file_size <= 256, "ARTIFACT_LAYOUT")
            manifest = json.loads(z.read("manifest.json"))
            tested = manifest["testedCommit"]
            tag = ci["imageName"] + ":" + tested
            expected = {
                "schema": ci["manifestSchema"], "repository": ci["repository"],
                "reviewedSourceCommit": ci["sourceCommit"], "testedTree": ci["sourceTree"],
                "workflowRunId": str(ci["runId"]), "workflowRunAttempt": str(ci["runAttempt"]),
                "imageRevisionLabel": tested, "imageTag": tag, "archiveName": "image.tar.gz",
                "archiveBytes": z.getinfo("image.tar.gz").file_size,
            }
            require(matches(r"[0-9a-f]{40}", tested) and matches(IMAGE, manifest["imageId"])
                    and all(manifest[k] == v for k, v in expected.items()), "CI_PROVENANCE_CHANGED")
            with z.open("image.tar.gz") as archive:
                archive_hash = checksum(archive, target)
            require(manifest["archiveSha256"] == archive_hash and
                    z.read("SHA256SUMS") == (archive_hash + "  image.tar.gz\n").encode(), "IMAGE_ARCHIVE_DIGEST_CHANGED")
            with z.open("image.tar.gz") as archive:
                ids = image_ids(archive, tag, ci["repository"], tested)
            require(manifest["imageId"] in ids and (transport or ci["imageId"] in ids), "IMAGE_ID_CHANGED")
            require(os.fstat(stream.fileno()).st_ctime_ns == info.st_ctime_ns, "ARTIFACT_CHANGED_DURING_READ")
            return {"archiveSha256": archive_hash, "imageTag": tag, "testedCommit": tested,
                    "publisherImageId": manifest["imageId"], "verifiedImageIds": sorted(ids)}
