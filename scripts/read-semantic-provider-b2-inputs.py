#!/usr/bin/env python3
"""Read-only B2 inventory (sprint-01 task-35). Human-invoked as root.

Prints only hashes, schemas, key sets, states and whitelisted public fields
(paths, key windows, table names, counts). It never prints file contents,
never opens key-binding targets, writes nothing and runs no container or nft
write operation. Every section is independent: a failure is reported as a
public code in that section and the others are still read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SCHEMA = "ouf.semantic-provider-b2-inventory.v1"
LIMIT = 4 * 1024 * 1024
REQUIRED_UID = 0  # tests override this with their own uid
WRAPPER = re.compile(rb'#!/bin/sh\nexec (/\S+) -I -B (/\S+) --configuration (/\S+) "\$@"\n')
HEX64 = re.compile(r"[0-9a-f]{64}")
PUBLIC_KEY_FIELDS = ("keyRef", "issuerRef", "roles", "notBefore", "expiresAt", "state")


class Held(Exception):
    pass


def require(value, code):
    if not value:
        raise Held(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, *, private=False):
    """Bytes of a root-owned regular file, no symlink, bounded. Content is never printed."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "REGULAR_FILE_REQUIRED")
        require(info.st_uid == REQUIRED_UID, "ROOT_OWNED_FILE_REQUIRED")
        require(not info.st_mode & 0o022, "NOT_WRITABLE_BY_OTHERS_REQUIRED")
        if private:
            require(not info.st_mode & 0o077, "PRIVATE_FILE_REQUIRED")
        require(info.st_size <= LIMIT, "FILE_TOO_LARGE")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            require(total <= LIMIT, "FILE_TOO_LARGE")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def parse(raw):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise Held("JSON_REQUIRED") from None
    require(type(value) is dict, "JSON_OBJECT_REQUIRED")
    return value


def document(path, *, private=False):
    raw = read(path, private=private)
    return raw, parse(raw)


def summary(path, *, private=False):
    raw, value = document(path, private=private)
    return {"path": str(path), "sha256": sha(raw), "schema": value.get("schema"), "keys": sorted(value)}


def binding(value):
    """A {path, sha256} binding, checked against the file it names (never opened if it is a key)."""
    require(type(value) is dict and type(value.get("path")) is str and HEX64.fullmatch(str(value.get("sha256"))),
            "BINDING_SHAPE_UNPROVEN")
    return value["path"], value["sha256"]


def checked(value, *, private=False):
    path, expected = binding(value)
    raw = read(path, private=private)
    return {"path": path, "sha256": expected, "matches": sha(raw) == expected}, raw


def listing(path):
    info = os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == REQUIRED_UID, "ROOT_DIRECTORY_REQUIRED")
    return {"path": str(path), "mode": oct(stat.S_IMODE(info.st_mode)), "entries": sorted(os.listdir(path))}


def public_keys(policy):
    keys = policy.get("keys")
    require(type(keys) is list, "POLICY_KEYS_REQUIRED")
    return [{k: key.get(k) for k in PUBLIC_KEY_FIELDS} for key in keys if type(key) is dict]


def section(report, name, function, *args):
    try:
        report[name] = function(*args)
    except Held as error:
        report[name] = {"error": str(error)}
    except OSError as error:
        report[name] = {"error": "OS_ERROR", "errno": error.errno, "exception": type(error).__name__}
    except Exception as error:  # public type only, never the message
        report[name] = {"error": "UNEXPECTED", "exception": type(error).__name__}


# --- sections -----------------------------------------------------------------

def wrapper_section(wrapper):
    raw = read(wrapper, private=False)
    match = WRAPPER.fullmatch(raw)
    require(match is not None, "WRAPPER_SHAPE_UNPROVEN")
    python, source, configuration = (part.decode("ascii") for part in match.groups())
    return {"path": wrapper, "sha256": sha(raw), "python": python, "source": source, "configuration": configuration}


def v51_section(wrapper):
    configuration = wrapper_section(wrapper)["configuration"]
    raw, config = document(configuration)
    out = {"path": configuration, "sha256": sha(raw), "schema": config.get("schema"), "keys": sorted(config)}
    for name in ("runtimePath", "runtimeSha256", "pythonPath", "pythonSha256", "driverPath", "driverSha256",
                 "admissionPath", "admissionSha256", "registryRoot", "runtimeStateRoot", "armingRoot",
                 "mandateRoot", "armingIssuerRef"):
        out[name] = config.get(name)
    candidates = config.get("candidates")
    require(type(candidates) is dict, "V51_CANDIDATES_REQUIRED")
    out["candidates"] = {cid: entry for cid, entry in sorted(candidates.items())}
    out["arming"] = listing(config["armingRoot"])
    registry = Path(config["registryRoot"])
    out["registry"] = listing(registry)
    out["candidateRegistryEntries"] = {
        cid: (listing(registry / cid) if os.path.lexists(registry / cid) else None) for cid in sorted(candidates)}
    state_root = Path(config["runtimeStateRoot"])
    out["runtimeStateRoot"] = {"path": str(state_root), "exists": os.path.lexists(state_root)}
    return out


def broker_summary(path, expected):
    raw, broker = document(path)
    out = {"path": path, "sha256": sha(raw), "matchesCandidate": sha(raw) == expected,
           "schema": broker.get("schema"), "keys": sorted(broker)}
    for name in ("sourceRoot", "candidateRoot", "runtimeRootParent", "authorities"):
        out[name] = broker.get(name)
    hashes = broker.get("sourceHashes")
    if type(hashes) is dict:
        out["sourceHashes"] = {"count": len(hashes), "sha256": sha(json.dumps(hashes, sort_keys=True).encode())}
    for name in ("intentBinding", "policyBinding", "preparerTemplate"):
        if name in broker:
            out[name] = checked(broker[name])[0]
    policy_raw = checked(broker["policyBinding"])[1]
    policy = parse(policy_raw)
    out["policy"] = {"schema": policy.get("schema"), "keys": public_keys(policy)}
    openssl = broker.get("opensslBinding")
    if type(openssl) is dict:
        out["opensslBinding"] = {k: openssl.get(k) for k in ("path", "sha256", "version")}
    out["signatureDirectory"] = broker.get("signatureDirectory")
    producers = {}
    for role, entry in sorted((broker.get("producers") or {}).items()):
        configuration, raw_configuration = checked(entry["configuration"])
        value = parse(raw_configuration)
        producers[role] = {
            "source": checked(entry["source"])[0], "configuration": configuration,
            "schema": value.get("schema"), "keys": sorted(value), "keyRef": value.get("keyRef"),
            # The key file itself is never opened; only the presence of the binding is reported.
            "signingKeyBindingPresent": "signingKeyBinding" in value}
    out["producers"] = producers
    return out, broker


def driver_summary(candidate_root):
    path = Path(candidate_root) / "driver.json"
    if not os.path.lexists(path):
        return None
    raw, driver = document(path)
    out = {"path": str(path), "sha256": sha(raw), "schema": driver.get("schema"), "keys": sorted(driver)}
    kernel = driver.get("kernel") if type(driver.get("kernel")) is dict else {}
    out["kernelTableName"] = kernel.get("tableName")
    out["leaseStructureHash"] = kernel.get("leaseStructureHash")
    for name in ("coordinationJournal", "preexecJournal", "lockFile"):
        out[name] = driver.get(name)
    for name in ("coordinationJournal", "preexecJournal"):
        journal = driver.get(name)
        if type(journal) is str and os.path.lexists(journal):
            raw_journal, value = document(journal)
            out[name + "State"] = {"sha256": sha(raw_journal), "schema": value.get("schema"),
                                   "state": value.get("state"), "leaseAuthorized": value.get("leaseAuthorized")}
    return out


def historic_section(b1_root):
    """The v4 chain behind the pre-B1 wrapper, kept by the B1 switch claim."""
    prior = read(Path(b1_root) / "switch" / "prior-runtime-wrapper.sh")
    match = WRAPPER.fullmatch(prior)
    require(match is not None, "PRIOR_WRAPPER_SHAPE_UNPROVEN")
    configuration = match.group(3).decode("ascii")
    raw, config = document(configuration)
    out = {"priorWrapperSha256": sha(prior), "configuration": {"path": configuration, "sha256": sha(raw),
           "schema": config.get("schema"), "keys": sorted(config)}, "candidates": {}}
    for cid, entry in sorted((config.get("candidates") or {}).items()):
        item = {"keys": sorted(entry), "intentRef": entry.get("intentRef"), "bundleParents": entry.get("bundleParents")}
        try:
            item["broker"], broker = broker_summary(entry["admissionConfiguration"], entry["admissionConfigurationHash"])
            item["driver"] = driver_summary(broker["candidateRoot"])
            for name in ("broker-state.json", "deployment.json", "admission.json", "preexec.json"):
                path = Path(broker["candidateRoot"]) / name
                if os.path.lexists(path):
                    raw_state, value = document(path)
                    item[name] = {"sha256": sha(raw_state), "schema": value.get("schema"), "state": value.get("state")}
        except Held as error:
            item["error"] = str(error)
        except (OSError, KeyError, TypeError) as error:
            item["error"] = type(error).__name__
        out["candidates"][cid] = item
    return out


def versioned_base_section(root):
    entries = listing(root)["entries"]
    numbers = sorted(int(name[:-5]) for name in entries if re.fullmatch(r"[1-9][0-9]*\.json", name))
    out = {"path": str(root), "generations": numbers,
           "other": [name for name in entries if not re.fullmatch(r"[1-9][0-9]*\.json", name)]}
    if numbers:
        raw, value = document(Path(root) / f"{numbers[-1]}.json")
        out["latest"] = {"number": numbers[-1], "sha256": sha(raw), "schema": value.get("schema"),
                         "installationRef": value.get("installationRef"), "entityRef": value.get("entityRef"),
                         "keys": public_keys(value)}
    return out


def nft_section(nft, tables):
    info = os.stat(nft)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == REQUIRED_UID and not info.st_mode & 0o022,
            "TRUSTED_NFT_REQUIRED")

    def run(*argv):
        result = subprocess.run([nft, "-j", *argv], stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=10, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        require(result.returncode == 0 and len(result.stdout) <= LIMIT, "NFT_READ_FAILED")
        return json.loads(result.stdout)["nftables"]

    listed = [item["table"] for item in run("list", "tables") if "table" in item]
    out = {"tables": sorted(f"{t['family']} {t['name']}" for t in listed), "detail": {}}
    for name in tables:
        for family in ("inet", "bridge"):
            if f"{family} {name}" not in out["tables"]:
                continue
            sets = [item["set"] for item in run("list", "table", family, name) if "set" in item]
            out["detail"][f"{family} {name}"] = [
                {"set": s["name"], "elements": len(s.get("elem", []))} for s in sorted(sets, key=lambda s: s["name"])]
    return out


def ingress_section(a2_root):
    found = []

    def walk(value, where):
        if type(value) is dict:
            for key, item in value.items():
                if key == "proposedIngress" and type(item) is dict:
                    found.append({"file": where, "proposedIngress": item})
                else:
                    walk(item, where)
        elif type(value) is list:
            for item in value:
                walk(item, where)

    for name in listing(a2_root)["entries"]:
        path = Path(a2_root) / name
        if name.endswith(".json") and os.path.isfile(path) and not os.path.islink(path):
            walk(document(path)[1], name)
    return found


def recipes_section(recipes_root):
    out = []
    for name in listing(recipes_root)["entries"]:
        path = Path(recipes_root) / name
        if os.path.isdir(path) and not os.path.islink(path):
            for inner in sorted(os.listdir(path)):
                if inner.endswith(".json"):
                    out.append(summary(path / inner))
        elif name.endswith(".json"):
            out.append(summary(path))
    return out


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("wrapper", "b1-root", "a2-root", "recipes-root", "versioned-base-root", "nft"):
        parser.add_argument("--" + name, required=True)
    return parser.parse_args(argv)


COUNTERS = {"writes": 0, "containerOperations": 0, "nftWrites": 0, "privateKeysRead": 0, "signaturesIssued": 0}


def collect(args):
    report = {"schema": SCHEMA, "status": "READ", **COUNTERS}
    section(report, "wrapper", wrapper_section, args.wrapper)
    section(report, "v51", v51_section, args.wrapper)
    section(report, "historicV4", historic_section, args.b1_root)
    section(report, "versionedBase", versioned_base_section, args.versioned_base_root)
    tables = set()
    for item in (report.get("historicV4", {}).get("candidates") or {}).values():
        name = ((item.get("driver") or {}).get("kernelTableName"))
        if type(name) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            tables.add(name)
    section(report, "nft", nft_section, args.nft, sorted(tables))
    section(report, "a2Ingress", ingress_section, args.a2_root)
    section(report, "recipesV2", recipes_section, args.recipes_root)
    errors = sorted(name for name, value in report.items() if type(value) is dict and "error" in value)
    report["sectionErrors"] = errors
    return report


def main(argv=None):
    args = arguments(argv)
    if os.geteuid() != REQUIRED_UID or not (sys.flags.isolated and sys.dont_write_bytecode):
        report = {"schema": SCHEMA, "status": "HELD", "reason": "ROOT_ISOLATED_PYTHON_REQUIRED", **COUNTERS}
    else:
        report = collect(args)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "READ" else 1


if __name__ == "__main__":
    raise SystemExit(main())
