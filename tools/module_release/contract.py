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


def diagnostic(prefix, exc):
    # Only code locations inside the installed executor may cross this boundary.
    directories = {Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent}
    directories.add(Path(__file__).resolve().parent.parent / "privileged_executor")
    tb = exc.__traceback__
    location = "unknown:0"
    while tb:
        source = Path(tb.tb_frame.f_code.co_filename).resolve()
        if source.parent in directories:
            location = f"{source.name}:{tb.tb_lineno}"
        tb = tb.tb_next
    return f"{prefix}/{type(exc).__name__}@{location}"


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


def valid_semantic_database(db):
    return (isinstance(db, dict) and set(db) == {"postgresCid", "socket", "user", "database", "schema"}
            and matches(r"[a-f0-9]{64}", db["postgresCid"])
            and matches(r"/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+", db["socket"])
            and all(matches(r"[a-z_][a-z0-9_]{0,62}", db[k]) for k in ("user", "database", "schema")))


NAME = r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}"
SHA = r"[0-9a-f]{64}"
IMAGE = "sha256:" + SHA
SEMANTIC_SCHEMA = "ouf.semantic-tested-image.v1"
COMMON_CI_COORDINATES = ("repository", "workflow", "pullRequest", "runId", "runAttempt", "artifactId", "zipSha256",
                         "sourceCommit", "sourceTree", "imageName", "imageId")
CI_COORDINATES = COMMON_CI_COORDINATES + ("manifestSchema",)
MCP_CI_COORDINATES = COMMON_CI_COORDINATES + ("publisherFormat", "artifactPrefix", "sourceBranch", "publisherCommit", "tag")
GATE = ('OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; '
        'while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"')
ENTRY = ["/bin/sh", "-c", GATE, "ouf-gated-application"]
INGESTION_STARTUP_FLAGS = ("--spring.flyway.enabled=false", "--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY")


def argv(value):
    return isinstance(value, list) and value and all(isinstance(v, str) and v and "\0" not in v for v in value)


def candidate_command(command, candidate):
    removed = candidate.get("removeArgs", [])
    return [arg for arg in command if arg not in removed]


def validate(p):
    require(p["schema"] == "ouf.module-release.v1", "PROFILE_VERSION")
    for name in ("module", "container", "retainedName", "failedName"):
        require(matches(NAME, p[name]), "INVALID_NAME")
    require(len({p[k] for k in ("container", "retainedName", "failedName")}) == 3, "NAME_COLLISION")
    require(matches(IMAGE, p["oldImage"]), "PREDECESSOR_IMAGE_REQUIRED")
    if "receiptSigning" in p:
        signer = p["receiptSigning"]
        require(isinstance(signer, dict) and set(signer) == {"publicKey", "privateKey"}
                and isinstance(signer["publicKey"], dict) and set(signer["publicKey"]) == {"path", "sha256"}
                and matches(SHA, signer["publicKey"]["sha256"])
                and all(isinstance(path, str) and Path(path).is_absolute() and ".." not in Path(path).parts
                        for path in (signer["publicKey"]["path"], signer["privateKey"])), "MODULE_RECEIPT_SIGNER_PROFILE")
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
    if "candidate" in p:
        candidate = p["candidate"]
        require(migration["mode"] == "spring-flyway"
                and isinstance(candidate, dict) and candidate and set(candidate) <= {"removeArgs", "enableFlyway"},
                "INVALID_CANDIDATE_PROFILE")
        removed = candidate.get("removeArgs", [])
        command = p["gate"]["command"]
        jar_name(command)
        options = command[command.index("-jar") + 2:]
        require(isinstance(removed, list) and ("removeArgs" not in candidate or removed)
                and all(matches(r"--[a-z][a-z0-9.-]*=[^\x00\r\n]+", arg) and arg in options
                        and removed.count(arg) == command.count(arg) == 1 for arg in removed)
                and candidate.get("enableFlyway", True) is True, "INVALID_CANDIDATE_PROFILE")
    require(migration["mode"] in ("none", "spring-flyway", "dedicated")
            and type(migration["rollbackCompatible"]) is bool, "INVALID_MIGRATION")
    require(("command" in migration) == (migration["mode"] == "dedicated")
            and ("command" not in migration or argv(migration["command"])), "INVALID_MIGRATION_COMMAND")
    ci = p["ci"]
    validate_ci(ci)
    if "flyway" in migration or p["module"] in ("udp", "ingestion"):
        db = migration.get("flyway", {})
        ident = r"[a-z_][a-z0-9_]{0,62}"
        require(migration["mode"] == "spring-flyway" and "database" not in migration
                and matches(SHA, db.get("postgresCid")) and matches(r"/[a-zA-Z0-9_./-]+", db.get("socket"))
                and ".." not in db["socket"].split("/")
                and all(matches(ident, db.get(k)) for k in ("database", "schema"))
                and all(matches(r"[A-Z_][A-Z_0-9]*", db.get(k)) for k in ("urlEnv", "userEnv"))
                and db["urlEnv"] != db["userEnv"], "INVALID_FLYWAY_BINDING")
        require("effectiveDatasource" not in db or db["effectiveDatasource"] == "profile-env",
                "INVALID_FLYWAY_BINDING")
        jar_name(p["gate"]["command"])
    if p["module"] in ("udp", "ingestion"):
        require(matches(NAME, ci.get("artifactPrefix")) and matches(NAME, ci.get("manifestSchema"))
                and "publisherFormat" not in ci and matches(NAME, ci.get("workflow"))
                and type(ci.get("pullRequest")) is int and ci["pullRequest"] > 0, "JAVA_PUBLISHER_PINS_REQUIRED")
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
        if p["module"] == "mcp" and db["version"] + len(items) >= 19:
            require("retentionAdmin019" in migration, "RETENTION_PROFILE_REQUIRED")
    if "retentionAdmin019" in migration:
        spec = migration["retentionAdmin019"]
        require(p["module"] == "mcp" and ci.get("publisherFormat") == "acquisition-mcp"
                and db["version"] + len(items) >= 19
                and isinstance(spec, dict) and spec.keys() - {"adminUrlEnv", "maintenanceUrlEnv"} == {
                    "functionName", "functionSha256", "sqlSha256", "ownerAclSha256",
                    "adminRole", "maintenanceRole", "maintenanceLogin", "adminPassfile", "maintenancePassfile"}
                and all(matches(SHA, spec[k]) for k in ("sqlSha256", "ownerAclSha256", "functionSha256"))
                and spec["functionName"] == "purge_analysis_run_history"
                and all(matches(r"[a-z_][a-z0-9_]{0,62}", spec[k])
                        for k in ("functionName", "adminRole", "maintenanceRole", "maintenanceLogin"))
                and spec["maintenanceLogin"] not in (spec["adminRole"], "ouf_mcp_retention_owner")
                and all(matches(r"[A-Z_][A-Z_0-9]*", spec[key]) and spec[key] != "PGPASSFILE"
                        for key in ("adminUrlEnv", "maintenanceUrlEnv") if key in spec)
                and len({spec["adminRole"], spec["maintenanceRole"], "ouf_mcp_retention_owner"}) == 3
                and all(Path(spec[k]).is_absolute() and ".." not in Path(spec[k]).parts
                        for k in ("adminPassfile", "maintenancePassfile"))
                and spec["adminPassfile"] != spec["maintenancePassfile"], "INVALID_RETENTION_PROFILE")


def jar_name(command):
    require(command.count("-jar") == 1, "FLYWAY_JAR_UNPROVEN")
    tail = command[command.index("-jar") + 1:]
    require(tail and matches(r"/app/[A-Za-z0-9_-][A-Za-z0-9._-]*\.jar", tail[0]), "FLYWAY_JAR_UNPROVEN")
    return tail[0].split("/")[-1]


def validate_ci(ci):
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


def image_ids(archive, tag, repository, tested, *, publisher_config=None, image_defaults=None):
    """Bind both Docker store identities to the single CI image, without extracting files."""
    metadata, blob_sizes = image_metadata(archive, verify_blobs=publisher_config is not None)
    entry, = json.loads(metadata["manifest.json"])
    require(entry["RepoTags"] in ([tag], ["docker.io/library/" + tag]), "IMAGE_TAG_CHANGED")
    raw = metadata[entry["Config"]]
    config_hash = hashlib.sha256(raw).hexdigest()
    require(entry["Config"] in ("blobs/sha256/" + config_hash, config_hash + ".json"), "IMAGE_CONFIG_DIGEST_CHANGED")
    config = json.loads(raw)["config"]
    if image_defaults is not None:
        image_defaults.update(config)
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


def package(p, target=None, *, transport=False, migrations_field=None, image_defaults=None):
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
            if ci["manifestSchema"] == SEMANTIC_SCHEMA:
                require(manifest.get("qualifiedInCiOnly") is True and all(manifest.get(key) is False for key in
                        ("targetApplyAuthorized", "humanBudgetGranted", "releaseAcceptance")), "CI_PROVENANCE_CHANGED")
                entries = manifest.get("flywayMigrations")
                require(isinstance(entries, list) and entries and all(
                    isinstance(row, dict) and set(row) == {"name", "sha256"} and
                    matches(r"V[^/]*\.sql", row["name"]) and matches(SHA, row["sha256"]) for row in entries)
                    and len({row["name"] for row in entries}) == len(entries), "MIGRATION_INVENTORY_REQUIRED")
            with z.open("image.tar.gz") as archive:
                archive_hash = checksum(archive, target)
            require(manifest["archiveSha256"] == archive_hash and
                    z.read("SHA256SUMS") == (archive_hash + "  image.tar.gz\n").encode(), "IMAGE_ARCHIVE_DIGEST_CHANGED")
            with z.open("image.tar.gz") as archive:
                ids = image_ids(archive, tag, ci["repository"], tested, image_defaults=image_defaults)
            require(manifest["imageId"] in ids and (transport or ci["imageId"] in ids), "IMAGE_ID_CHANGED")
            require(os.fstat(stream.fileno()).st_ctime_ns == info.st_ctime_ns, "ARTIFACT_CHANGED_DURING_READ")
            facts = {"archiveSha256": archive_hash, "imageTag": tag, "testedCommit": tested,
                    "publisherImageId": manifest["imageId"], "verifiedImageIds": sorted(ids)}
            if migrations_field is not None:
                require(isinstance(manifest.get(migrations_field), list), "MIGRATION_INVENTORY_REQUIRED")
                facts["migrations"] = manifest[migrations_field]
            return facts
