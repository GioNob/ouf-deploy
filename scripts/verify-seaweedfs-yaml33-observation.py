#!/usr/bin/env python3
"""Verify the exact observed YAML33 build pins before fresh image qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "releases/seaweedfs-452-generation33-vendor-build-manifest-20261104.json"
PARENT = "releases/seaweedfs-452-generation32-build-manifest-20261103.json"
PROFILE = "config/seaweedfs-generation33-vendor-source-profile.json"
OBSERVED_ARCHIVE = "evidence/artifacts/seaweedfs-yaml33-source-observation-41776440912.zip"
OBSERVED_RECEIPT = "evidence/seaweedfs-yaml33-source-observation-hosted-20261104.json"
COMMIT = "4bd8c2645766ffbe407ca744c7bd72691a46ef9c"
RUN = 41776440912
INACTIVE_MODULE = "github.com/tyler-smith/go-bip39"
INACTIVE_FOOTER = f"# {INACTIVE_MODULE} => github.com/cosmos/go-bip39 v1.0.0"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load("vendor_image_contract", "tools/storage_security/generation_vendor_contract.py")
guard = load("yaml_source_profile", "tools/storage_security/vendor_yaml_source.py")
require = contract.require
sha = contract.sha


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def observed_archive(path, pin):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == pin["bytes"]
            and path.stat().st_size <= 8 * 1024 * 1024 and file_sha(path) == pin["sha256"],
            "EXACT_OBSERVATION_ARCHIVE_REQUIRED")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = {row.filename for row in entries}
        require(len(entries) == len(names) == pin["members"] <= 512
                and sum(row.file_size for row in entries) <= 64 * 1024 * 1024,
                "UNIQUE_BOUNDED_OBSERVATION_MEMBERS_REQUIRED")
        for row in entries:
            name = PurePosixPath(row.filename)
            require(name.as_posix() == row.filename and not name.is_absolute()
                    and ".." not in name.parts and "\\" not in row.filename
                    and not row.is_dir() and not stat.S_ISLNK(row.external_attr >> 16),
                    "REGULAR_OBSERVATION_MEMBER_REQUIRED")
        members = {row.filename: archive.read(row) for row in entries}
    sums = {}
    for line in members.pop("SHA256SUMS").decode().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        require(match and match[2] not in sums, "UNIQUE_OBSERVATION_CHECKSUM_REQUIRED")
        sums[match[2]] = match[1]
    require(set(sums) == set(members) and all(sha(raw) == sums[name] for name, raw in members.items()),
            "OBSERVATION_CHECKSUM_CLOSURE_REQUIRED")
    return members


def inactive_footer_free(data):
    """Only the exact unselected Go wildcard footer can be omitted for enumeration."""
    lines = data.decode().splitlines(keepends=True)
    require(lines and lines[-1] == INACTIVE_FOOTER + "\n", "PINNED_INACTIVE_FOOTER_REQUIRED")
    body = lines[:-1]
    require(not any("=>" in line or line.strip() == INACTIVE_MODULE
                    or line.startswith((INACTIVE_MODULE + "/", "# " + INACTIVE_MODULE + " ")) for line in body),
            "ACTIVE_OR_UNKNOWN_VENDOR_REPLACEMENT_DENIED")
    return "".join(body).encode()


def execution_record(members):
    commands = json.loads(members["commands.json"])
    by_name = {row["name"]: row for row in commands}
    require(len(by_name) == len(commands), "UNIQUE_OBSERVED_COMMAND_NAMES_REQUIRED")
    choices = {
        "first-build": "build",
        "second-build": "build",
        "production-graph": "production-deps",
        "production-packages": "production-deps",
        "iceberg-worker-tests": "regression",
        "source-profile-tests": "regression",
        "upstream-config-tests": "regression",
        "upstream-config-race": "race",
        **{f"denied-{tag}": "excluded-profile" for tag in
           ("elastic", "rclone", "kafka", "openbao", "vault", "gcs", "google_pub_sub", "googlecloud")},
    }
    rows = []
    for name, role in choices.items():
        row = by_name[name]
        negative = role == "excluded-profile"
        require(row["args"][0] == "go" and row["GOFLAGS"] == "" and row["GOWORK"] == "off"
                and row["CGO_ENABLED"] == ("1" if role == "race" else "0")
                and row["expectedNonzero"] is negative and (row["exitCode"] != 0) is negative
                and sha(members[name + ".stdout"]) == row["stdoutSha256"]
                and sha(members[name + ".stderr"]) == row["stderrSha256"],
                "OBSERVED_COMMAND_AND_RESULT_MISMATCH:" + name)
        rows.append({"role": role, "args": row["args"][1:]})
    checks = {}
    for phase in ("before", "after"):
        name = "module-cache-verify-" + phase
        checks["goModVerify" + phase.title()] = (
            by_name[name]["args"] == ["go", "mod", "verify"] and by_name[name]["exitCode"] == 0
            and members[name + ".stdout"] == b"all modules verified\n"
            and sha(members[name + ".stdout"]) == by_name[name]["stdoutSha256"])
    return {"effectiveGOFLAGS": "", "effectiveGOWORK": "off", "rootCommands": rows,
            **checks, "baselineVendorFilesMatchOriginalArchives": True}


def material_bytes(profile, members, execution):
    return {
        "vendor-source-profile.json": profile,
        "vendor-materializer.json": members["vendor-materializer.json"],
        "baseline-vendor-origins.json": members["baseline-vendor-origins.json"],
        "compiled-module-origins.json": members["compiled-module-origins.json"],
        "vendor-before-files.json": members["vendor-before-files.json"],
        "vendor-after-files.json": members["vendor-after-files.json"],
        "baseline-vendor-file-origins.json": members["baseline-vendor-file-origins.json"],
        "baseline-vendor-module-enumeration.txt": members["baseline-vendor-module-enumeration.txt"],
        "vendor-modules.txt": members["baseline-vendor-modules.txt"],
        "vendor-execution.json": contract.canonical(execution),
    }


def verify(manifest, parent_raw, profile_raw, receipt_raw, archive_path):
    parent = contract.validate_manifest(manifest, parent_raw)
    pin = manifest["observation"]
    require(pin["workflowRun"] == RUN and pin["repositoryCommit"] == COMMIT
            and pin["receiptPath"] == OBSERVED_RECEIPT and pin["archive"]["path"] == OBSERVED_ARCHIVE
            and sha(receipt_raw) == pin["receiptSha256"], "EXACT_OBSERVATION_RECEIPT_REQUIRED")
    receipt = json.loads(receipt_raw)
    require(receipt["workflowRun"] == RUN and receipt["artifact"] == pin["archive"]
            and receipt["imageQualified"] is False and receipt["releaseAdmitted"] is False
            and type(receipt["targetOperations"]) is int and receipt["targetOperations"] == 0,
            "OBSERVATION_MUST_REMAIN_SOURCE_ONLY")
    members = observed_archive(archive_path, pin["archive"])
    observed = json.loads(members["observation.json"])
    require(sha(members["observation.json"]) == pin["reportSha256"] and receipt["observation"] == observed
            and observed["status"] == "OBSERVATION_PASS_NOT_RELEASE_QUALIFIED"
            and observed["repositoryCommit"] == COMMIT and int(observed["runId"]) == RUN
            and observed["binarySha256"] == manifest["build"]["binarySha256"]
            and observed["binaryBytes"] == manifest["build"]["binaryBytes"]
            and observed["reproducibleTwoCleanPaths"] is True and observed["compiledLegacyYaml"] is False
            and observed["fullVendorPublished"] is False and observed["binaryPublished"] is False
            and observed["cacheInputsAndVendorUnchanged"] is True
            and observed["releaseAdmitted"] is False and observed["runtimeAuthorityIssued"] is False
            and type(observed["targetOperations"]) is int and observed["targetOperations"] == 0,
            "EXACT_SUCCESSFUL_SOURCE_OBSERVATION_REQUIRED")
    require(members["base32-manifest.json"] == parent_raw
            and manifest["upstreamCommit"] == parent["upstreamCommit"]
            and observed["rootSourceTree32"] == manifest["rootSourceGitTree"]
            and observed["baseManifestSha256"] == manifest["parentManifestSha256"]
            and observed["sourcePatchCount"] == 32 and observed["dependencyPatchCount"] == 1,
            "OBSERVATION_PARENT_CHANGED")
    profile = guard.validate_profile(json.loads(profile_raw))
    guard.verify_parent(profile, parent_raw)
    execution = execution_record(members)
    contract.verify_execution(execution)
    materials = material_bytes(profile_raw, members, execution)
    contract.verify_material_digests(manifest, materials)
    vendor = manifest["vendor"]
    require(profile["vendor"] == {
        "baseTreeSha256": vendor["beforeTreeSha256"], "patchedTreeSha256": vendor["afterTreeSha256"],
        "modulesTxtSha256": vendor["modulesTxtSha256"], "fileCount": vendor["fileCount"]}
        and profile["rootLockfilesSha256"] == manifest["rootLockfilesSha256"],
        "PROFILE_AND_VENDOR_MANIFEST_CHANGED")
    contract.verify_vendor_inventories(manifest, json.loads(materials["vendor-before-files.json"]),
        json.loads(materials["vendor-after-files.json"]), json.loads(materials["baseline-vendor-file-origins.json"]))
    packages = json.loads(members["production-packages.json"])["packages"]
    graph = ("\n".join(packages) + "\n").encode()
    info = members["first-build-info.stdout"].decode()
    require(info.splitlines()[1:] == members["second-build-info.stdout"].decode().splitlines()[1:]
            and profile["moduleOriginsSha256"] == sha(materials["compiled-module-origins.json"]),
            "TWO_BUILD_INFO_AND_ORIGINS_BINDINGS_REQUIRED")
    contract.verify_compiled(manifest, parent, graph, info)
    origin = contract.verify_origin_coverage(json.loads(materials["baseline-vendor-origins.json"]),
        json.loads(materials["compiled-module-origins.json"]), inactive_footer_free(materials["vendor-modules.txt"]),
        info, materials["baseline-vendor-module-enumeration.txt"], manifest["rootLockfilesSha256"]["go.sum"])
    require(origin["compiledModules"] == profile["moduleOriginCount"] == observed["compiledModuleCount"] == 214
            and origin["allVendorModules"] == observed["baselineVendorModuleCount"] == 341,
            "EXACT_VENDOR_AND_COMPILED_ORIGIN_COUNTS_REQUIRED")
    require(receipt["comparisonWithImage32"] == {
        "moduleCounts": [parent["build"]["binaryModuleRows"], origin["compiledModules"]],
        "packageCounts": [parent["build"]["compiledPackages"], len(packages)],
        "removedModules": [{"name": contract.LEGACY_YAML, "version": "v3.0.1"}],
        "removedPackages": [contract.LEGACY_YAML], "addedModules": [], "addedPackages": [],
    }, "EXACT_OBSERVED_COMPILED_DELTA_REQUIRED")
    return {"schema": "ouf.yaml33-image-build-preflight.v1",
            "status": "OBSERVED_BUILD_PINS_VERIFIED_FRESH_IMAGE_QUALIFICATION_REQUIRED",
            "generation": 33, "workflowRun": RUN, "binarySha256": observed["binarySha256"],
            "compiledPackages": len(packages), **origin, "vendorFilesBound": vendor["fileCount"],
            "originalInputZipsRehashedByThisPreflight": False,
            "imageQualified": False, "releaseAdmitted": False, "runtimeAuthorityIssued": False,
            "targetOperations": 0}


def verify_repo(repo):
    manifest = json.loads((repo / MANIFEST).read_bytes())
    parent_raw = (repo / PARENT).read_bytes()
    contract.validate_manifest(manifest, parent_raw)
    profile_raw = (repo / PROFILE).read_bytes()
    profile = guard.validate_profile(json.loads(profile_raw))
    for row in manifest["orderedSourcePatches"] + manifest["orderedDependencyPatches"]:
        path = repo / row["path"]
        require(path.is_file() and not path.is_symlink() and file_sha(path) == row["sha256"],
                "PATCH_SOURCE_CHANGED:" + row["path"])
    materializer = repo / "scripts/prepare_iceberg_vendor_patch.py"
    require(file_sha(materializer) == profile["materializerSha256"], "EXACT_VENDOR_MATERIALIZER_REQUIRED")
    return verify(manifest, parent_raw, profile_raw,
                  (repo / OBSERVED_RECEIPT).read_bytes(), repo / OBSERVED_ARCHIVE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    repo = parser.parse_args().repo
    result = verify_repo(repo)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
