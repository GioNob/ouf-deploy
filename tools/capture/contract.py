"""The shipped schemas are the runtime contracts. Only their vocabulary is supported."""
import hashlib
import json
from pathlib import Path
import re

from platform_restart.profile import Held, canonical, custody, private_dir, require, sha, unique

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 ** 2
GIB = 1024 ** 3
CHUNK = MIB
VERSION = "1"


def read_json(path):
    with path.open("rb") as stream:
        return json.load(stream, object_pairs_hook=unique)


def validate(value, spec):
    if "const" in spec:
        require(value == spec["const"], "INVALID_CONSTANT")
    if "enum" in spec:
        require(value in spec["enum"], "INVALID_CHOICE")
    kind = spec.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    if kind is None:
        return
    require(type(value) is types[kind], "INVALID_TYPE")
    if kind == "object":
        require(set(spec["required"]) <= value.keys() <= spec["properties"].keys(), "INVALID_FIELDS")
        for key, item in value.items():
            validate(item, spec["properties"][key])
    elif kind == "array":
        require(len(value) >= spec["minItems"], "MISSING_ITEMS")
        require(len(set(map(canonical, value))) == len(value), "DUPLICATE_ITEM")
        for item in value:
            validate(item, spec["items"])
    elif kind == "integer":
        require(value >= spec["minimum"], "INVALID_LIMIT")
    elif kind == "string":
        require(len(value) >= spec.get("minLength", 1), "EMPTY_STRING")
        if "pattern" in spec:
            require(re.fullmatch(spec["pattern"], value), "INVALID_STRING")


def schema(name):
    return read_json(ROOT / "contracts" / (name + "-v1.schema.json"))


def registry():
    document = read_json(ROOT / "tools/privileged_executor/host-register.json")
    validate(document, schema("configuration-register"))
    entries = {e["id"]: e for e in document["entries"]}
    require(len(entries) == len(document["entries"]), "DUPLICATE_ID")
    return entries


def mapping(rows, key):
    result = {r[key]: r["id"] for r in rows}
    require(len(result) == len(rows), "AMBIGUOUS_SELECTOR")
    return result


def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def profile(path, entries):
    custody(path)
    require(path.stat().st_mode & 0o077 == 0, "PRIVATE_PROFILE_REQUIRED")
    cfg = read_json(path)
    validate(cfg, schema("capture-profile"))
    for key in ("postgres", "etcd", "inventory", "images", "paths", "excludePaths",
                "units", "volumes", "databases"):
        rows = cfg["postgres"][key] if key == "databases" else cfg[key]
        for row in rows if isinstance(rows, list) else [rows]:
            require(key in entries.get(row["id"], {}).get("selector", {}).get("bindings", []),
                    "INVALID_REGISTER_BINDING")
    for key in ("paths", "excludePaths"):
        mapping(cfg[key], "path")
    for key, field in (("units", "pattern"), ("volumes", "name"), ("absent", "id")):
        mapping(cfg[key], field)
    dbs = mapping(cfg["postgres"]["databases"], "name")
    require(cfg["postgres"]["database"] in dbs and "capture.iam" in dbs.values(), "IAM_DATABASE_REQUIRED")
    for row in cfg["postgres"]["omitTableData"]:
        require(row["database"] in dbs and row["database"] not in ("postgres", "template0", "template1"),
                "INVALID_FILTER_DATABASE")
    absent = {row["id"] for row in cfg["absent"]}
    require(absent <= entries.keys(), "INVALID_ABSENCE")
    owners = {r["id"] for r in cfg["secretOwners"]}
    required = {k for k, e in entries.items() if e.get("kind") and e["secrets"]}
    require(len(owners) == len(cfg["secretOwners"]) and owners == required, "SECRET_CUSTODY_MISSING")
    output = Path(cfg["outputDir"])
    paths = [r["path"] for key in ("paths", "excludePaths") for r in cfg[key]]
    for value in [str(path), *paths, cfg["dockerSocket"], str(output),
                  *(cfg[k]["path"] for k in ("docker", "age", "nice"))]:
        require(value.startswith("/") and str(Path(value)) == value and ".." not in Path(value).parts
                and not value.startswith("//"), "INVALID_PATH")
    require(all(not (output.is_relative_to(p) or Path(p).is_relative_to(output))
                for p in [path, *paths]), "OUTPUT_OVERLAP")
    require(not set(mapping(cfg["paths"], "path")) & set(mapping(cfg["excludePaths"], "path")),
            "AMBIGUOUS_SELECTOR")
    require("capture.r3-keys" in {r["id"] for r in cfg["excludePaths"]}, "R3_EXCLUSIONS_REQUIRED")
    private_dir(output)
    return cfg
