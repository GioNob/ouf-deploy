"""Additional checks for the proposed generation33 YAML vendor source profile.

This module is deliberately independent of frozen generation31/32 qualifiers.
A successful result verifies this source-profile supplement only; publisher,
image, full module inventory, vulnerability gates and release authority still
belong to the generation qualifier. Raw scanner/SBOM bytes are never rewritten.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

ICEBERG = "github.com/apache/iceberg-go"
YAML = "go.yaml.in/yaml/v3"
LEGACY = "gopkg.in/yaml.v3"
CONFIG = ICEBERG + "/config/config.go"
PINNED = {ICEBERG: "v0.7.0", YAML: "v3.0.5"}
INPUT_H1 = "h1:bTD6Pb4uM4sWcMfIx0/cV1haHMc84r+CvPieUqYzD4I="
INPUT_ZIP_SHA256 = "a042ec87708c376362859041b1741213dc4e05400cad7ad0220ea4361a250d55"
BASE_CONFIG = "30ec8eebf86cd2f5df0c8d6bbf8661c0bf72d10fc8c025d6943c9565ae13a604"
PATCHED_CONFIG_SHA256 = "9983e5e82a9372e9f47db6ccc5a55d9b747fd503caaedb5619e4b37e95c75ab4"
PATCH_SHA256 = "001459c5254303378cb30dafaceec1777cbb143957fa6afb5e2e7eb8cbb46eef"
BASE_COMMIT = "89a9104ec3639d38ab07e4461721cb5270e95571"
LICENSES = {
    ICEBERG + "/LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    ICEBERG + "/NOTICE": "f519dc027959fc106b1b53706b70eb3bd5da2c0bac79336888c58a79d03c8f52",
}
SHA = re.compile(r"[0-9a-f]{64}")


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def inventory(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "REGULAR_VENDOR_ROOT_REQUIRED")
    rows = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "VENDOR_SYMLINK_DENIED")
        if path.is_file():
            name = path.relative_to(root).as_posix()
            require("\n" not in name and "\r" not in name, "AMBIGUOUS_VENDOR_PATH")
            rows[name] = sha(path.read_bytes())
    return rows


def tree_sha(rows):
    return sha("".join(rows[n] + "  " + n + "\n" for n in sorted(rows)).encode())


def source_inventory(root):
    root = Path(root)
    rows = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] in {"vendor", ".git"}:
            continue
        require(not path.is_symlink(), "BASE_SOURCE_SYMLINK_DENIED")
        if path.is_file():
            name = relative.as_posix()
            require("\n" not in name and "\r" not in name, "AMBIGUOUS_SOURCE_PATH")
            rows[name] = sha(path.read_bytes())
    return rows


def validate_profile(p):
    require(p.get("schema") == "ouf.seaweedfs-vendor-yaml-source-profile.v1"
            and p.get("generation") == 33 and p.get("previousGeneration") == 32,
            "EXACT_VENDOR_SOURCE_PROFILE_REQUIRED")
    require(p.get("status") == "BOUND_SOURCE_PROFILE_NOT_ADMITTED"
            and p.get("dependencySourceMode") == "vendor-with-reviewed-source-patches",
            "BOUND_VENDOR_PROFILE_REQUIRED")
    require(p.get("releaseAdmitted") is False and p.get("runtimeAuthorityIssued") is False
            and p.get("allDependenciesMaintained") is False and p.get("targetOperations") == 0,
            "NO_ADMISSION_OR_MAINTENANCE_INFERENCE")
    require(p.get("maintenance") == {"status": "OPEN", "technicalOwner": None,
            "reviewCadence": "EACH_CANDIDATE_AND_WEEKLY_WHILE_PATCH_ACTIVE"},
            "EXPLICIT_OPEN_DOWNSTREAM_OWNERSHIP_REQUIRED")
    require(p.get("build") == {"go": "1.27.3", "os": "linux", "arch": "amd64",
            "cgo": False, "tags": [], "trimpath": True, "moduleMode": "vendor"},
            "EXACT_VENDOR_BUILD_MODE_REQUIRED")
    require(p.get("upstream") == {"module": ICEBERG, "version": "v0.7.0",
            "commit": BASE_COMMIT, "zipSha256": INPUT_ZIP_SHA256,
            "h1InputOnly": INPUT_H1, "checksumDoesNotDescribePatchedSource": True},
            "AUTHENTIC_UPSTREAM_INPUT_REQUIRED")
    require(p.get("maintainedYaml") == {"module": YAML, "version": "v3.0.5",
            "h1": "h1:N6y/pJk8buWs9NY5ERU2HSMfm+IuD/OtfdAnq6kESPw="},
            "EXACT_MAINTAINED_YAML_PIN_REQUIRED")
    patch = p.get("patch", {})
    require(patch.get("file") == CONFIG and patch.get("sha256") == PATCH_SHA256
            and patch.get("originalFileSha256") == BASE_CONFIG
            and patch.get("modifiedFileSha256") == PATCHED_CONFIG_SHA256, "EXACT_SOURCE_PATCH_REQUIRED")
    tree = p.get("vendor", {})
    for key in ("baseTreeSha256", "patchedTreeSha256", "modulesTxtSha256"):
        require(isinstance(tree.get(key), str) and SHA.fullmatch(tree[key]), "VENDOR_TREE_BINDINGS_REQUIRED")
    require(tree["baseTreeSha256"] != tree["patchedTreeSha256"]
            and type(tree.get("fileCount")) is int and tree["fileCount"] > 0,
            "CHANGED_VENDOR_TREE_REQUIRED")
    locks = p.get("rootLockfilesSha256", {})
    require(set(locks) == {"go.mod", "go.sum"} and all(isinstance(v, str) and SHA.fullmatch(v)
            for v in locks.values()), "EXACT_ROOT_LOCK_BINDINGS_REQUIRED")
    for key in ("baseSourceTreeSha256", "materializerSha256", "previousGenerationManifestSha256", "moduleOriginsSha256"):
        require(isinstance(p.get(key), str) and SHA.fullmatch(p[key]), "SOURCE_TOOL_BINDINGS_REQUIRED")
    require(type(p.get("moduleOriginCount")) is int and p["moduleOriginCount"] > 0, "COMPLETE_MODULE_ORIGIN_COUNT_REQUIRED")
    require(isinstance(p.get("previousSourceGitTree"), str)
            and re.fullmatch(r"[0-9a-f]{40}", p["previousSourceGitTree"]), "PARENT_SOURCE_TREE_BINDING_REQUIRED")
    return p


def verify_parent(profile, previous_manifest_bytes):
    previous = json.loads(previous_manifest_bytes)
    require(sha(previous_manifest_bytes) == profile["previousGenerationManifestSha256"]
            and previous.get("generation") == 32
            and previous.get("build", {}).get("patchedSourceTree") == profile["previousSourceGitTree"],
            "FROZEN_GENERATION32_PARENT_REQUIRED")


def verify_sources(profile, root, patch_bytes, materializer_bytes):
    p = validate_profile(profile)
    root = Path(root)
    require(sha(patch_bytes) == p["patch"]["sha256"], "DEPENDENCY_PATCH_CHANGED")
    require(sha(materializer_bytes) == p["materializerSha256"], "MATERIALIZER_CHANGED")
    for name, wanted in p["rootLockfilesSha256"].items():
        path = root / name
        require(path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == wanted,
                "ROOT_LOCK_CHANGED:" + name)
    require(tree_sha(source_inventory(root)) == p["baseSourceTreeSha256"], "BASE_SOURCE_TREE_CHANGED")
    rows = inventory(root / "vendor")
    require(len(rows) == p["vendor"]["fileCount"] and tree_sha(rows) == p["vendor"]["patchedTreeSha256"],
            "PATCHED_VENDOR_TREE_CHANGED")
    reconstructed_base = dict(rows)
    reconstructed_base[CONFIG] = BASE_CONFIG
    require(tree_sha(reconstructed_base) == p["vendor"]["baseTreeSha256"], "ONLY_LOCKED_CONFIG_DELTA_ALLOWED")
    require(rows.get("modules.txt") == p["vendor"]["modulesTxtSha256"], "VENDOR_MODULE_METADATA_CHANGED")
    require(rows.get(CONFIG) == p["patch"]["modifiedFileSha256"], "PATCHED_CONFIG_CHANGED")
    for name, wanted in LICENSES.items():
        require(rows.get(name) == wanted, "UPSTREAM_LICENSE_OR_NOTICE_CHANGED")
    config = (root / "vendor" / CONFIG).read_bytes()
    require(b"// OUF downstream modification (2026-11-03):" in config
            and b'"go.yaml.in/yaml/v3"' in config and b'"gopkg.in/yaml.v3"' not in config,
            "EXPLICIT_YAML_MIGRATION_AND_NOTICE_REQUIRED")
    return {"patchedVendorTreeSha256": tree_sha(rows), "files": len(rows)}


def normalized_package(name):
    return name.removeprefix("vendor/").rsplit("/vendor/", 1)[-1]


def legacy(name):
    name = normalized_package(name)
    return name == LEGACY or name.startswith(LEGACY + "/")


def verify_compiled_closure(packages, build_info):
    require(isinstance(packages, list) and packages and all(isinstance(x, str) for x in packages),
            "COMPILED_PACKAGE_INVENTORY_REQUIRED")
    require(len(packages) == len(set(packages)), "DUPLICATE_COMPILED_PACKAGE")
    require(not any(legacy(x) for x in packages), "COMPILED_LEGACY_YAML_PRESENT")
    require({ICEBERG + "/config", ICEBERG + "/table", YAML} <= set(packages),
            "ICEBERG_FEATURE_AND_MAINTAINED_YAML_REQUIRED")
    require(not any(line.startswith("\t=>\t") for line in build_info.splitlines()),
            "MODULE_REPLACEMENT_UNSUPPORTED")
    rows = [line.split("\t")[2:] for line in build_info.splitlines() if line.startswith("\tdep\t")]
    require(rows and all(len(row) >= 2 for row in rows), "BINARY_MODULE_ROWS_REQUIRED")
    require(not any(legacy(row[0]) for row in rows), "BINARY_LEGACY_YAML_PRESENT")
    require(len({row[0] for row in rows}) == len(rows), "DUPLICATE_BINARY_MODULE_PATH")
    require(all(len(row) == 2 or (len(row) == 3 and row[2] == "") for row in rows),
            "VENDOR_BYTES_MUST_NOT_CLAIM_UPSTREAM_H1")
    for name, version in PINNED.items():
        selected = [row for row in rows if row[0] == name]
        require(len(selected) == 1 and selected[0][1] == version, "CANONICAL_BINARY_MODULE_REQUIRED:" + name)
    return {"legacyYamlCompiled": False, "canonicalIcebergRetained": True}


def verify_module_origins(profile, origin_bytes, build_info, root_go_sum_bytes):
    require(sha(origin_bytes) == profile["moduleOriginsSha256"], "MODULE_ORIGIN_INVENTORY_CHANGED")
    origin = json.loads(origin_bytes)
    require(origin.get("schema") == "ouf.vendor-original-module-origins.v1"
            and origin.get("status") == "ORIGINAL_INPUTS_VERIFIED_NOT_RELEASE_ADMITTED"
            and origin.get("moduleCacheMutated") is False
            and origin.get("rootGoSumSha256") == sha(root_go_sum_bytes)
            and origin.get("buildInfoSha256") == sha(build_info.encode()), "BOUND_ORIGINAL_MODULE_INPUTS_REQUIRED")
    rows = origin.get("modules", [])
    modules = [tuple(line.split("\t")[2:4]) for line in build_info.splitlines() if line.startswith("\tdep\t")]
    require(isinstance(rows, list) and len(rows) == profile["moduleOriginCount"] == origin.get("moduleCount")
            and len(rows) == len(modules) == len(set(modules)), "COMPLETE_BINARY_MODULE_ORIGINS_REQUIRED")
    keys = [(r.get("module"), r.get("version")) for r in rows]
    require(len(keys) == len(set(keys)) and set(keys) == set(modules), "EXACT_BINARY_ORIGIN_IDENTITIES_REQUIRED")
    locks = {}
    for line in root_go_sum_bytes.decode().splitlines():
        parts = line.split()
        require(len(parts) == 3, "VALID_ROOT_GO_SUM_REQUIRED")
        key = tuple(parts[:2])
        require(key not in locks or locks[key] == parts[2], "CONFLICTING_ROOT_GO_SUM")
        locks[key] = parts[2]
    for row in rows:
        name, version = row["module"], row["version"]
        require(row.get("checksumsDescribeOriginalInputsOnly") is True
                and row.get("modifiedInVendor") is (name == ICEBERG), "ORIGINAL_VS_PATCHED_SOURCE_DISTINCTION_REQUIRED")
        for key in ("inputZipSha256", "inputGoModSha256"):
            require(isinstance(row.get(key), str) and SHA.fullmatch(row[key]), "MODULE_INPUT_ARCHIVE_DIGEST_REQUIRED")
        for field, suffix in (("inputZipH1", ""), ("inputGoModH1", "/go.mod")):
            value = row.get(field)
            require(isinstance(value, str) and re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", value)
                    and value == locks.get((name, version + suffix)), "AUTHENTIC_INPUT_H1_LOCK_REQUIRED:" + name)
        if name == ICEBERG:
            require(row["inputZipSha256"] == INPUT_ZIP_SHA256 and row["inputZipH1"] == INPUT_H1,
                    "EXACT_ICEBERG_ORIGIN_REQUIRED")
    return {"moduleOriginsSha256": sha(origin_bytes), "moduleCount": len(rows),
            "archiveChecksumsAreNotPatchedSourceChecksums": True}


def verify_execution(record):
    require(record.get("effectiveGOFLAGS") == "" and record.get("effectiveGOWORK") == "off",
            "EXPLICIT_EFFECTIVE_GO_CONFIGURATION_REQUIRED")
    commands = record.get("rootCommands", [])
    require(isinstance(commands, list) and commands, "ROOT_COMMAND_RECORD_REQUIRED")
    required_roles = {"build", "production-deps", "regression", "race", "excluded-profile"}
    require(required_roles <= {r.get("role") for r in commands}, "ALL_ROOT_VENDOR_COMMAND_ROLES_REQUIRED")
    for row in commands:
        args = row.get("args", [])
        require(isinstance(args, list) and all(isinstance(a, str) for a in args), "COMMAND_ARGUMENTS_REQUIRED")
        require(args.count("-mod=vendor") == 1
                and not any(a.startswith("-mod=") and a != "-mod=vendor" for a in args)
                and not any(a == "-mod" or a.startswith("-overlay") for a in args),
                "ROOT_COMMAND_BYPASSES_VENDOR:" + str(row.get("role")))
        expected_command = {"build": "build", "production-deps": "list", "regression": "test", "race": "test"}
        require(row.get("role") in required_roles and args
                and (args[0] == expected_command[row["role"]] if row["role"] in expected_command
                     else args[0] in {"test", "build"}), "ROOT_COMMAND_ROLE_MISMATCH")
        require(row["role"] != "production-deps" or "-deps" in args, "PRODUCTION_DEPS_COMMAND_REQUIRED")
        require(row["role"] != "race" or "-race" in args, "RACE_COMMAND_REQUIRED")
    return {"rootVendorModeRecorded": True}


def verify_raw_identity(scan_bytes, spdx_bytes):
    scan, spdx = json.loads(scan_bytes), json.loads(spdx_bytes)
    packages = [p for r in scan.get("Results", []) if r.get("Type") == "gobinary" for p in r.get("Packages", [])]
    require(packages, "RAW_GO_BINARY_SCAN_REQUIRED")
    require(not any(legacy(p.get("Name", "")) for p in packages), "RAW_SCAN_LEGACY_YAML_PRESENT")
    require(not any(legacy(p.get("name", "")) for p in spdx.get("packages", [])), "RAW_SPDX_LEGACY_YAML_PRESENT")
    ids = {}
    for name, version in PINNED.items():
        selected = [p for p in packages if p.get("Name") == name]
        wanted = "pkg:golang/" + name + "@" + version
        require(len(selected) == 1 and selected[0].get("Version") == version
                and selected[0].get("Identifier", {}).get("PURL") == wanted,
                "CANONICAL_RAW_SCAN_IDENTITY_REQUIRED:" + name)
        nodes = [p for p in spdx.get("packages", []) if p.get("name") == name]
        require(len(nodes) == 1 and nodes[0].get("versionInfo") == version
                and isinstance(nodes[0].get("SPDXID"), str)
                and any(ref.get("referenceType") == "purl" and ref.get("referenceLocator") == wanted
                        for ref in nodes[0].get("externalRefs", [])), "CANONICAL_RAW_SPDX_IDENTITY_REQUIRED:" + name)
        ids[name] = nodes[0]["SPDXID"]
    return {"rawScanSha256": sha(scan_bytes), "rawSpdxSha256": sha(spdx_bytes), "rawPackageIds": ids}


def source_provenance(profile, binary_sha256, scan_bytes, spdx_bytes, verified_source, verified_closure):
    p = validate_profile(profile)
    require(isinstance(binary_sha256, str) and SHA.fullmatch(binary_sha256), "BINARY_HASH_REQUIRED")
    require(verified_source == {"patchedVendorTreeSha256": p["vendor"]["patchedTreeSha256"],
                               "files": p["vendor"]["fileCount"]}, "VERIFIED_VENDOR_SOURCE_REQUIRED")
    require(verified_closure == {"legacyYamlCompiled": False, "canonicalIcebergRetained": True},
            "VERIFIED_COMPILED_CLOSURE_REQUIRED")
    raw = verify_raw_identity(scan_bytes, spdx_bytes)
    return {
        "schema": "ouf.modified-dependency-source-provenance.v1",
        "status": "SOURCE_PROFILE_SUPPLEMENT_VERIFIED_NOT_RELEASE_ADMITTED",
        "profileSha256": sha(canonical(p)), "binarySha256": binary_sha256,
        **raw, "upstream": p["upstream"], "sourcePatch": p["patch"], "vendor": p["vendor"],
        "relationships": [
            {"from": "patched-iceberg-source", "type": "DESCENDANT_OF", "to": "upstream-iceberg-source"},
            {"from": "locked-yaml-import-patch", "type": "PATCH_FOR", "to": "upstream-iceberg-source"},
            {"from": "locked-yaml-import-patch", "type": "PATCH_APPLIED", "to": "patched-iceberg-source"},
            {"from": "bound-binary-reference", "type": "GENERATED_FROM", "to": "patched-iceberg-source"},
        ],
        "rawArtifactsRewritten": False, "standaloneSpdxDocument": False,
        "maintenance": p["maintenance"], "allDependenciesMaintained": False,
        "releaseAdmitted": False, "runtimeAuthorityIssued": False,
    }


def assess(profile, root, patch_bytes, materializer_bytes, binary_bytes, packages, build_info,
           execution, scan_bytes, spdx_bytes, previous_manifest_bytes, module_origins_bytes):
    validate_profile(profile)
    verify_parent(profile, previous_manifest_bytes)
    source = verify_sources(profile, root, patch_bytes, materializer_bytes)
    closure = verify_compiled_closure(packages, build_info)
    verify_execution(execution)
    origins = verify_module_origins(profile, module_origins_bytes, build_info, (Path(root) / "go.sum").read_bytes())
    result = source_provenance(profile, sha(binary_bytes), scan_bytes, spdx_bytes, source, closure)
    result["originalModuleInputs"] = origins
    return result
