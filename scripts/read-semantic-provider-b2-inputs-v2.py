#!/usr/bin/env python3
"""Read-only B2 v2 compositor inventory, human-invoked as root with -I -B.

Only explicit public projections leave this process. No commands are run,
bindings are never followed (especially key bindings), and no file is written.
Each section fails independently, with public error codes only. Hashes identify
observations, not authorization, runtime readiness or an expected baseline.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys

SCHEMA = "ouf.semantic-provider-b2-inventory.v2"
LIMIT = 4 * 1024 * 1024
MAX_FILES = 512
MAX_DEPTH = 16
REQUIRED_UID = 0
ROLES = ("adapter", "southbound")
RECEIPT_SHA256 = "8a0ed83e6cbbcd4f46802d610c5382a57605381242896a0145174f7fe2a31d3d"
COUNTERS = {"writes": 0, "containerOperations": 0, "nftWrites": 0,
            "privateKeysRead": 0, "signaturesIssued": 0}
COMMANDS = ("nft", "ip", "nsenter", "unshare", "mount", "umount")


class Held(Exception):
    pass


def require(value, code):
    if not value:
        raise Held(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def absolute(value):
    require(type(value) is str and value.startswith("/") and not value.startswith("//")
            and ".." not in PurePosixPath(value).parts and "\x00" not in value,
            "ABSOLUTE_PATH_REQUIRED")
    return value


def text(value):
    require(type(value) is str, "PUBLIC_STRING_REQUIRED")
    return value


def hash_value(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value), "SHA256_REQUIRED")
    return value


def number(value):
    require(type(value) in (int, float) and 0 <= value < float("inf"), "PUBLIC_NUMBER_REQUIRED")
    return value


def boolean(value):
    require(type(value) is bool, "PUBLIC_BOOLEAN_REQUIRED")
    return value


def obj(value):
    require(type(value) is dict, "OBJECT_REQUIRED")
    return value


def array(value):
    require(type(value) is list, "ARRAY_REQUIRED")
    return value


def project(value, fields):
    """Validate leaves too: an unexpected nested object must never leak."""
    obj(value)
    return {name: check(value[name]) for name, check in fields.items() if name in value}


def custody(info, *, directory=False, private=False):
    require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode),
            "DIRECTORY_REQUIRED" if directory else "REGULAR_FILE_REQUIRED")
    require(info.st_uid == REQUIRED_UID, "ROOT_OWNERSHIP_REQUIRED")
    require(not info.st_mode & 0o022, "NOT_WRITABLE_BY_OTHERS_REQUIRED")
    if private:
        require(not info.st_mode & 0o077, "PRIVATE_CUSTODY_REQUIRED")


@contextmanager
def directory(path, *, private=False, checked=True):
    """Walk with directory FDs: O_NOFOLLOW covers every ancestor as well."""
    parts = PurePosixPath(absolute(str(path))).parts
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
            os.close(fd)
            fd = following
        if checked:
            custody(os.fstat(fd), directory=True, private=private)
        yield fd
    finally:
        os.close(fd)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def read(path, *, private=True):
    path = PurePosixPath(absolute(str(path)))
    # No key targets are followed; also reject key-like filenames in inventories.
    require(not re.search(r"(?:^|[-_.])(key|keys|pem|secret|secrets)(?:[-_.]|$)", path.name,
                          re.IGNORECASE), "KEY_FILE_REFUSED")
    with directory(path.parent, checked=False) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            custody(before, private=private)
            require(before.st_size <= LIMIT, "FILE_TOO_LARGE")
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= LIMIT, "FILE_TOO_LARGE")
                chunks.append(chunk)
            require(identity(before) == identity(os.fstat(fd)) == identity(
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)), "FILE_CHANGED_DURING_READ")
            return b"".join(chunks)
        finally:
            os.close(fd)


def files(root, *, depth=2, suffix=None, complete=False):
    """Bounded traversal; special files and symlinks are rejected, never followed."""
    result = []
    visited = 0

    def walk(path, remaining):
        nonlocal visited
        with directory(path, private=True) as fd:
            names = sorted(os.listdir(fd))
            require(len(names) <= MAX_FILES, "DIRECTORY_TOO_LARGE")
            visited += len(names)
            require(visited <= MAX_FILES, "TOO_MANY_ENTRIES")
            for name in names:
                child = str(PurePosixPath(path) / name)
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode), "SYMLINK_REFUSED")
                if stat.S_ISDIR(info.st_mode):
                    if remaining > 1:
                        walk(child, remaining - 1)
                    else:
                        require(not complete, "TRAVERSAL_DEPTH_LIMIT")
                else:
                    require(stat.S_ISREG(info.st_mode), "REGULAR_FILE_REQUIRED")
                    if suffix is None or name.endswith(suffix):
                        result.append(child)
                        require(len(result) <= MAX_FILES, "TOO_MANY_FILES")
    walk(absolute(str(root)), depth)
    return result


def document(path):
    raw = read(path)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "DUPLICATE_JSON_KEY")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False, "FINITE_JSON_REQUIRED"))
    except (ValueError, UnicodeDecodeError):
        raise Held("JSON_REQUIRED") from None
    obj(value)
    summary = {"path": str(path), "sha256": sha(raw), "schema": None, "keys": sorted(value)}
    summary.update(project(value, {"schema": text}))
    return summary, value


def triple(value):
    return project(value, {name: hash_value for name in
                          ("transactionId", "configurationHash", "leaseStructureHash")})


def binding(value):
    return project(value, {"path": absolute, "sha256": hash_value})


def flows(value):
    return [project(row, {"endpointRef": text, "leaseSeconds": number}) for row in array(value)]


def kernel(value):
    return project(value, {"tableName": text, "providerFlows": flows})


def dns(value):
    obj(value)
    return {"keys": sorted(value), **project(value, {
        "resolvers": lambda rows: [text(row) for row in array(rows)], "resolverPort": number})}


def coordinator_section(context, install):
    rows = []
    for root in (context, install):
        for path in files(root, suffix=".json"):
            row, value = document(path)
            if set(value).intersection(("journalFile", "commonLockFile", "nftPath",
                                        "expectedStructureHash", "binding", "kernel", "dns", "sourceHashes")):
                row.update(project(value, {"journalFile": absolute, "commonLockFile": absolute,
                    "nftPath": absolute, "nftSha256": hash_value, "expectedStructureHash": hash_value,
                    "binding": triple, "readBudgetSeconds": number, "kernel": kernel,
                    "dns": dns, "providerFlows": flows,
                    "sourceHashes": lambda v: {"count": len(obj(v))}}))
                if "binding" in value and "configurationHash" in value["binding"]:
                    row["configurationHashMatches"] = (value["binding"]["configurationHash"] == sha(
                        canonical({k: v for k, v in value.items() if k != "binding"})))
            if value.get("schema") == "ouf.semantic-lease-coordination.v1":
                row.update(project(value, {"state": text, "leaseAuthorized": boolean,
                                          "transactionId": hash_value, "leaseStructureHash": hash_value}))
            if PurePosixPath(path).name == "boot-profile.json":
                row.update(project(value, {"profile": text, "mode": text}))
                row["bindings"] = {}
                # The installed profile uses flat path/hash pairs, not nested bindings.
                for name, hash_name in (("coordinatedConfiguration", "coordinatedConfigurationHash"),
                                        ("bootConfiguration", "bootConfigurationHash"),
                                        ("bootGuardFile", "bootGuardHash")):
                    if name in value:
                        row["bindings"][name] = binding({"path": value[name], "sha256": value[hash_name]})
            rows.append(row)
    observed = {row["path"]: row["sha256"] for row in rows}
    for row in rows:
        for item in row.get("bindings", {}).values():
            if item["path"] in observed:
                item["matchesObservedFile"] = observed[item["path"]] == item["sha256"]
    return {"documents": rows}


def nic(value):
    return project(value, {**{name: text for name in
        ("interface", "bridge", "mac", "ipv4", "workloadRef", "bindingRef")},
        "leaseGuard": lambda v: project(v, {"configurationHash": hash_value, "tableName": text})})


def templates_section(registry):
    result = []
    for path in files(registry):
        if PurePosixPath(path).name != "preparer-template.json":
            continue
        row, value = document(path)
        row.update(project(value, {"kernel": lambda v: project(v, {"tableName": text}),
            "coordinationBinding": triple, "coordinationJournal": absolute, "lockFile": absolute,
            "hostNetworkNamespace": number, "pythonPath": absolute, "pythonHash": hash_value,
            "budgetSeconds": number,
            "commands": lambda v: project(v, dict.fromkeys(COMMANDS, absolute)),
            "commandHashes": lambda v: project(v, dict.fromkeys(COMMANDS, hash_value))}))
        row["candidate"] = project(value["candidate"], {"tableName": text,
            "networkBindings": lambda v: [nic(item) for item in array(v)],
            "transport": lambda v: {"flows": len(array(v)), "digest": sha(canonical(v))}})
        result.append(row)
    require(result, "PREPARER_TEMPLATES_REQUIRED")
    return {"templates": result}


def limits(value):
    return project(value, dict.fromkeys(("maxEntries", "maxBytes", "maxDepth"), number))


def rootfs_section(path):
    row, value = document(path)
    row.update(project(value, {"status": text, "state": text, "limits": limits, "rootfsLimits": limits}))
    row["roles"] = {}
    for role in ROLES:
        row["roles"][role] = project(value["roles"][role], {"containerId": hash_value, "imageId": text,
            "effectiveSeal": lambda v: project(v, {"schema": text, "sha256": hash_value,
                                                   "entries": number, "bytes": number}),
            "limits": limits, "rootfsLimits": limits})
    return row


def recipes_section(root):
    result = {}
    for role in ROLES:
        result[role] = {}
        for name in ("template", "launch", "context", "policy"):
            row, value = document(str(PurePosixPath(root) / role / (name + ".json")))
            if name == "policy":
                row["expectedOciSha256"] = sha(canonical(obj(value["expectedOci"])))
            elif name == "context":
                row.update(project(value, {"containerId": hash_value, "bundleParent": absolute,
                    "networkNamespaceName": lambda v: None if v is None else text(v), "rootfsPath": absolute}))
            result[role][name] = row
    return {"roles": result}


def preparation_section(root):
    result = {}
    for name in ("successors.json", "manifest.json"):
        row, value = document(str(PurePosixPath(root) / name))
        row.update(project(value, {"status": text, "state": text}))
        body = obj(value["manifest"]) if name == "manifest.json" else value
        if name == "manifest.json":
            row["manifest"] = project(body, {"schema": text, "status": text, "state": text})
        successors = obj(body["successors"]) if name == "manifest.json" else body
        containers = array(successors["containers"])
        require(len(containers) == 2, "EXACT_TWO_ROLE_CONTAINERS_REQUIRED")
        # Same writer-order contract as prepare-semantic-provider-b1-rootfs.py:223.
        row["roleOrder"] = list(ROLES)
        row["roles"] = {role: project(item, {"containerId": hash_value, "image": text,
            "transaction": text, "manifestDigest": text, "configDigest": text, "status": text,
            "state": text}) for role, item in zip(ROLES, containers)}
        result[name] = row
    result["rolesMatch"] = result["successors.json"]["roles"] == result["manifest.json"]["roles"]
    return result


def receipt_section(path):
    if path is None:
        return {"provided": False, "expectedSha256": RECEIPT_SHA256}
    row, value = document(path)
    row.update(project(value, {"status": text, "phase": text}))
    return {**row, "provided": True, "expectedSha256": RECEIPT_SHA256,
            "matchesExpected": row["sha256"] == RECEIPT_SHA256}


def sources_section(root):
    rows = {}
    for name in ("tools", "scripts"):
        for path in files(str(PurePosixPath(root) / name), depth=MAX_DEPTH, complete=True):
            require(PurePosixPath(path).suffix in (".py", ".sh"), "SOURCE_FILE_TYPE_UNPROVEN")
            rows[path] = sha(read(path, private=False))
    require(rows, "SOURCE_FILES_REQUIRED")
    return {"files": rows}


def section(report, name, function, *args):
    try:
        report[name] = {"status": "READ", **function(*args)}
    except Held as error:
        report[name] = {"status": "HELD", "error": str(error)}
    except OSError as error:
        report[name] = {"status": "HELD", "error": "OS_ERROR", "errno": error.errno,
                        "exception": type(error).__name__}
    except Exception as error:
        report[name] = {"status": "HELD", "error": "UNEXPECTED", "exception": type(error).__name__}


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])

    def path(value):
        try:
            return absolute(value)
        except Held:
            raise argparse.ArgumentTypeError("absolute path without parent traversal required") from None

    for name in ("coordinator-context", "coordinator-install", "historic-registry", "rootfs-result",
                 "recipes-root", "a2-root", "historic-source"):
        parser.add_argument("--" + name, required=True, type=path)
    parser.add_argument("--generation-receipt", type=path)
    return parser.parse_args(argv)


def collect(args):
    report = {"schema": SCHEMA, "status": "READ", **COUNTERS}
    section(report, "coordinatorSuccessor", coordinator_section, args.coordinator_context, args.coordinator_install)
    section(report, "historicTemplates", templates_section, args.historic_registry)
    section(report, "rootfs", rootfs_section, args.rootfs_result)
    section(report, "recipesV2", recipes_section, args.recipes_root)
    section(report, "preparationA2", preparation_section, args.a2_root)
    section(report, "generationSourcesReceipt", receipt_section, args.generation_receipt)
    section(report, "installedClosures", sources_section, args.historic_source)
    report["sectionErrors"] = sorted(name for name, value in report.items()
                                     if type(value) is dict and "error" in value)
    return report


def main(argv=None):
    args = arguments(argv)
    if (not hasattr(os, "geteuid") or os.geteuid() != REQUIRED_UID
            or not (sys.flags.isolated and sys.dont_write_bytecode)):
        report = {"schema": SCHEMA, "status": "HELD", "reason": "ROOT_ISOLATED_PYTHON_REQUIRED", **COUNTERS}
    else:
        report = collect(args)
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0 if report["status"] == "READ" else 1


if __name__ == "__main__":
    raise SystemExit(main())
