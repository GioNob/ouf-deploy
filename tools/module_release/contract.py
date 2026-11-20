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
    executable = p["gate"].get("executable", p["gate"]["command"][0])
    require(isinstance(executable, str) and executable and "\0" not in executable, "INVALID_EXECUTABLE")
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
    labels = p.get("provenanceLabels", {})
    require(isinstance(labels, dict) and all(matches(NAME, key) and field in ("publisherCommit", "sourceCommit")
            and field in ci for key, field in labels.items()), "INVALID_PROVENANCE_LABELS")
    if ci.get("publisherFormat") == "acquisition-mcp":
        require(matches(r"[0-9a-f]{40}", ci["publisherCommit"]) and matches(NAME, ci["tag"])
                and matches(NAME, ci["artifactPrefix"]) and matches(SHA, ci["transportSha256"])
                and matches(r"[a-zA-Z0-9_./-]+", ci["sourceBranch"]), "MCP_PUBLISHER_PINS_REQUIRED")
    else:
        require("publisherFormat" not in ci, "UNKNOWN_PUBLISHER_FORMAT")
    if ci.get("publisherFormat") == "acquisition-mcp" or "database" in migration:
        db = migration["database"]
        require(matches(SHA, db["postgresCid"]) and matches(r"/[a-zA-Z0-9_./-]+", db["socket"])
                and ".." not in db["socket"].split("/") and matches(r"[A-Z_][A-Z_0-9]*", db["urlEnv"])
                and type(db["version"]) is int and db["version"] > 0, "INVALID_DATABASE_PROFILE")
        items = migration["migrations"]
        require(isinstance(items, list) and all(set(item) == {"version", "checksum"}
                and type(item["version"]) is int and item["version"] == i and matches(SHA, item["checksum"])
                for i, item in enumerate(items, db["version"] + 1)), "INVALID_MIGRATION_LIST")
        require(migration["mode"] == ("dedicated" if items else "none")
                and (not items or matches(SHA, migration.get("targetSchemaSha256"))), "MIGRATION_MODE_MISMATCH")
    require(matches(NAME + "/" + NAME, ci["repository"]) and matches(NAME, ci["imageName"])
            and matches(r"[0-9a-f]{40}", ci["sourceCommit"]) and matches(r"[0-9a-f]{40}", ci["sourceTree"])
            and all(type(ci[k]) is int and ci[k] > 0 for k in ("runId", "runAttempt", "artifactId"))
            and matches(SHA, ci["zipSha256"]) and matches(IMAGE, ci["imageId"]), "CI_PINS_REQUIRED")


def image_metadata(archive, verify_blobs):
    metadata, blob_sizes = {}, {}
    total = expanded = 0
    with tarfile.open(fileobj=archive, mode="r|gz") as tar:
        for index, member in enumerate(tar):
            if verify_blobs:
                expanded += member.size
                require(index < 512 and expanded <= 160 << 20 and (member.isfile() or member.isdir())
                        and matches(r"[A-Za-z0-9_./-]+", member.name) and not member.name.startswith("/")
                        and ".." not in member.name.split("/"), "INVALID_IMAGE_MEMBERS")
            if not member.isfile():
                continue
            blob = matches(r"blobs/sha256/[0-9a-f]{64}", member.name)
            checked = verify_blobs and blob
            if checked:
                ident = "sha256:" + member.name.rsplit("/", 1)[1]
                require(ident not in blob_sizes, "INVALID_IMAGE_METADATA")
                blob_sizes[ident] = member.size
            if member.size > 1 << 20:
                if checked:
                    require(checksum(tar.extractfile(member)) == ident[7:], "OCI_BLOB_CHANGED")
                continue
            if not (blob or member.name in ("manifest.json", "index.json") or matches(r"[a-f0-9]{64}\.json", member.name)):
                continue
            total += member.size
            require(total <= 16 << 20 and member.name not in metadata, "INVALID_IMAGE_METADATA")
            raw = tar.extractfile(member).read()
            if checked:
                require(hashlib.sha256(raw).hexdigest() == ident[7:], "OCI_BLOB_CHANGED")
            metadata[member.name] = raw
    return metadata, blob_sizes


def image_ids(archive, tag, repository, tested, *, publisher_config=None):
    """Bind both Docker store identities to the single CI image, without extracting files."""
    metadata, blob_sizes = image_metadata(archive, verify_blobs=publisher_config is not None)
    entry, = json.loads(metadata["manifest.json"])
    require(entry["RepoTags"] in ([tag], ["docker.io/library/" + tag]), "IMAGE_TAG_CHANGED")
    raw = metadata[entry["Config"]]
    config_hash = hashlib.sha256(raw).hexdigest()
    require(entry["Config"] in ("blobs/sha256/" + config_hash, config_hash + ".json"), "IMAGE_CONFIG_DIGEST_CHANGED")
    config = json.loads(raw)["config"]
    labels = config.get("Labels") or {}
    verify_labels(labels, repository, tested, optional=publisher_config is not None)
    if publisher_config is not None:
        require(all(publisher_config.get(k) == v for k, v in config.items() if v), "ARCHIVED_DEFAULTS_CHANGED")
    ids = {"sha256:" + config_hash}
    if "index.json" in metadata:
        descriptor, = json.loads(metadata["index.json"])["manifests"]
        ident = descriptor["digest"]
        require(matches(IMAGE, ident), "INVALID_OCI_DESCRIPTOR")
        raw = metadata["blobs/sha256/" + ident[7:]]
        require(len(raw) == descriptor["size"] and hashlib.sha256(raw).hexdigest() == ident[7:]
                and json.loads(raw)["config"]["digest"] in ids, "IMAGE_MANIFEST_DIGEST_CHANGED")
        if publisher_config is not None:
            manifest = json.loads(raw)
            require(all(blob_sizes.get(d["digest"]) == d["size"] for d in [manifest["config"], *manifest["layers"]])
                    and entry["Layers"] == ["blobs/sha256/" + layer["digest"][7:] for layer in manifest["layers"]]
                    and descriptor.get("annotations", {}).get("io.containerd.image.name")
                    in (None, "docker.io/library/" + tag), "IMAGE_MANIFEST_DIGEST_CHANGED")
        ids.add(ident)
    elif publisher_config is not None:
        raise Held("MCP_OCI_MANIFEST_REQUIRED")
    return ids


def verify_labels(labels, repository, tested, *, optional):
    expected = {"org.opencontainers.image.revision": tested,
                "org.opencontainers.image.source": "https://github.com/" + repository}
    require(all(labels.get(k) == v for k, v in expected.items() if not optional or k in labels),
            "IMAGE_LABELS_CHANGED")


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
            if ci.get("publisherFormat") == "acquisition-mcp":
                from .mcp_artifact import verify
                receipt = verify(z, ci, target, transport)
                require(os.fstat(stream.fileno()).st_ctime_ns == info.st_ctime_ns, "ARTIFACT_CHANGED_DURING_READ")
                return receipt
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
