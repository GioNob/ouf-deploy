"""Generation33 image qualification for a pinned vendor source and raw inventory."""
import argparse
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
GENERATION = 33
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SOURCE_FILES = {
    ".github/workflows/storage-452-generation33-image.yml",
    ".github/workflows/storage-452-yaml33-source-observation.yml",
    "scripts/observe-seaweedfs-yaml33.py",
    "scripts/prepare_iceberg_vendor_patch.py",
    "scripts/collect_vendor_module_origins.py",
    "scripts/verify_iceberg_vendor_source_profile.py",
    "scripts/verify-seaweedfs-yaml33-observation.py",
    "scripts/qualify-seaweedfs-452-generation33-image.py",
    "scripts/readback-seaweedfs-452-generation33-image.py",
    "tools/storage_security/generation_image_v4.py",
    "tools/storage_security/generation_vendor_contract.py",
    "tools/storage_security/vendor_module_origins.py",
    "tools/storage_security/vendor_yaml_source.py",
    "config/seaweedfs-yaml33-observation-inputs.json",
    "tests/test_generation_vendor_contract.py",
    "tests/test_seaweedfs_yaml33_image_preflight.py",
    "tests/test_seaweedfs_yaml33_observation.py",
    "tests/test_prepare_iceberg_vendor_patch.py",
    "tests/test_vendor_module_origins.py",
    "tests/test_vendor_yaml_source_profile.py",
    "tests/test_seaweedfs_452_generation33_image.py",
    "tests/fixtures/compare_iceberg_yaml.go",
}
REGRESSIONS = {
    "main": "regressions.jsonl", "server": "server-focused.jsonl",
    "storage": "storage-focused.jsonl", "race": "race.jsonl",
}
OTHER_TESTS = {
    "root-iam-regressions.jsonl": {"pass_tests": 24, "pass_packages": 2},
    "nested-iam-regressions.jsonl": {"pass_tests": 18, "pass_packages": 1},
    "kafka-compile.jsonl": {"pass_packages": 4, "skip_packages": 2},
    "compat-tests.jsonl": {"pass_tests": 3, "pass_packages": 1},
}
COMBINED_DENIALS = {
    "denied-elastic-rclone.log": ("OUF_STANDARD_PROFILE_DOES_NOT_SUPPORT_ELASTIC_OR_RCLONE",),
    "denied-kafka-openbao-vault.log": ("OUF_STANDARD_PROFILE_DOES_NOT_SUPPORT_KAFKA_NOTIFICATION_OR_REPLICATION",
                                      "OUF_STANDARD_PROFILE_DOES_NOT_SUPPORT_OPENBAO_OR_VAULT"),
    "denied-gcs-kafka-openbao.log": ("OUF_STANDARD_PROFILE_GOOGLE_UNSUPPORTED_USE_SEPARATELY_QUALIFIED_CANDIDATE",),
}
EXTRA_EVIDENCE = {
    "compat-receipt.json", "shell-hosted.jsonl", "kafka-tidy.diff",
    "nested-lockfiles-before.sha256", "post-regression-mod-verify.txt",
    *REGRESSIONS.values(), *OTHER_TESTS, *COMBINED_DENIALS,
}
NESTED_IAM_LOCKS = {
    "test/s3/iam/go.mod": "f52ebe5060c285796722ea36851c0a5f991f67b3a5586b2987c8940f00ea62ff",
    "test/s3/iam/go.sum": "28cdd28aa2d4f88fa9349e2ddf4f4d7ab398e4bf486dae55e9f99627904fe750",
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load("image33_preflight", "scripts/verify-seaweedfs-yaml33-observation.py")
parent = load("image33_regression_baseline", "scripts/qualify-seaweedfs-452-generation32-image.py").engine
contract = preflight.contract
guard = preflight.guard
image = parent.image
require = preflight.require
sha = preflight.sha
manifest = json.loads((ROOT / preflight.MANIFEST).read_bytes())
profile = json.loads((ROOT / preflight.PROFILE).read_bytes())
PROFILE = image.ImageProfile(manifest["build"]["binarySha256"], manifest["upstreamCommit"],
    "ouf-seaweedfs-candidate:4.52-g33-" + manifest["build"]["binarySha256"][:8],
    parent.PROFILE.licence_sha)


def verify_patch_sources():
    return preflight.verify_repo(ROOT)


def source_names():
    return parent.source_names() | SOURCE_FILES | {preflight.MANIFEST, preflight.PROFILE,
        preflight.OBSERVED_RECEIPT, preflight.OBSERVED_ARCHIVE,
        manifest["orderedDependencyPatches"][0]["path"]}


def file_hash(path):
    return preflight.file_sha(path)


def seal_sources(out):
    verify_patch_sources()
    (out / "source-SHA256SUMS").write_text("".join(
        file_hash(ROOT / path) + "  " + path + "\n" for path in sorted(source_names())))


def baseline_observation():
    return preflight.observed_archive(ROOT / preflight.OBSERVED_ARCHIVE, manifest["observation"]["archive"])


def verify_fresh_source(members, producer, run_id):
    observed = json.loads(members["observation.json"])
    require(observed["status"] == "OBSERVATION_PASS_NOT_RELEASE_QUALIFIED"
            and observed["repositoryCommit"] == producer and int(observed["runId"]) == run_id
            and observed["binarySha256"] == PROFILE.binary_sha
            and observed["binaryBytes"] == manifest["build"]["binaryBytes"]
            and observed["rootSourceTree32"] == manifest["rootSourceGitTree"]
            and observed["baseManifestSha256"] == manifest["parentManifestSha256"]
            and observed["sourcePatchCount"] == 32 and observed["dependencyPatchCount"] == 1
            and observed["vendorBeforeTreeSha256"] == manifest["vendor"]["beforeTreeSha256"]
            and observed["vendorAfterTreeSha256"] == manifest["vendor"]["afterTreeSha256"]
            and observed["vendorFileCount"] == manifest["vendor"]["fileCount"]
            and observed["fullVendorPublished"] is False and observed["binaryPublished"] is False
            and observed["reproducibleTwoCleanPaths"] is True and observed["cacheInputsAndVendorUnchanged"] is True
            and observed["compiledLegacyYaml"] is False and observed["allDependenciesMaintained"] is False
            and observed["releaseAdmitted"] is False and observed["runtimeAuthorityIssued"] is False
            and type(observed["targetOperations"]) is int and observed["targetOperations"] == 0,
            "EXACT_FRESH_YAML33_SOURCE_OBSERVATION_REQUIRED")
    require(members["base32-manifest.json"] == (ROOT / preflight.PARENT).read_bytes(),
            "OBSERVED_PARENT_MANIFEST_CHANGED")
    baseline = baseline_observation()
    require(set(members) == set(baseline), "EXACT_FRESH_OBSERVATION_EVIDENCE_SET_REQUIRED")
    for name in ("vendor-materializer.json", "vendor-before-files.json", "vendor-after-files.json",
                 "baseline-vendor-file-origins.json", "baseline-vendor-module-enumeration.txt",
                 "baseline-vendor-modules.txt", "root-module-graph.stdout"):
        require(members[name] == baseline[name], "FROZEN_VENDOR_OR_ROOT_GRAPH_CHANGED:" + name)
    contract.verify_execution(preflight.execution_record(members))
    packages = json.loads(members["production-packages.json"])["packages"]
    graph = ("\n".join(packages) + "\n").encode()
    info = members["first-build-info.stdout"].decode()
    require(info.splitlines()[1:] == members["second-build-info.stdout"].decode().splitlines()[1:]
            == baseline["first-build-info.stdout"].decode().splitlines()[1:],
            "TWO_NEW_VENDOR_BUILD_INFOS_MUST_MATCH_PIN")
    require(info.splitlines()[0].endswith(": go1.27.3"), "EXACT_BUILD_INFO_TOOLCHAIN_REQUIRED")
    contract.verify_compiled(manifest, parent.MANIFEST, graph, info)
    compiled = guard.verify_compiled_closure(packages, info)
    origin_result = contract.verify_origin_coverage(
        json.loads(members["baseline-vendor-origins.json"]), json.loads(members["compiled-module-origins.json"]),
        preflight.inactive_footer_free(members["baseline-vendor-modules.txt"]), info,
        members["baseline-vendor-module-enumeration.txt"], manifest["rootLockfilesSha256"]["go.sum"])
    for name in ("baseline-vendor-origins.json", "compiled-module-origins.json"):
        observed_rows = contract.origin_rows(json.loads(members[name]))
        pinned_rows = contract.origin_rows(json.loads(baseline[name]))
        require(observed_rows.keys() == pinned_rows.keys(), "EXACT_ORIGINAL_MODULE_SET_REQUIRED")
        # The proxy's optional VCS metadata is preserved in both records, but
        # it does not change the four cryptographic identities being compared.
        fields = ("inputZipSha256", "inputGoModSha256", "inputZipH1", "inputGoModH1",
                  "checksumsDescribeOriginalInputsOnly", "modifiedInVendor")
        require(all(all(row[field] == pinned_rows[key][field] for field in fields)
                    for key, row in observed_rows.items()), "ORIGINAL_VENDOR_INPUT_CHANGED:" + name)
    require(origin_result["allVendorModules"] == 341 and origin_result["compiledModules"] == 214,
            "EXACT_FRESH_ORIGIN_COUNTS_REQUIRED")
    return packages, info, compiled, observed


def read_bundle(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 16 * 1024 * 1024,
            "BOUNDED_FRESH_SOURCE_BUNDLE_REQUIRED")
    with zipfile.ZipFile(path) as source:
        entries = source.infolist()
        require(len(entries) == len({entry.filename for entry in entries}) <= 512
                and sum(entry.file_size for entry in entries) <= 96 * 1024 * 1024,
                "UNIQUE_BOUNDED_FRESH_SOURCE_MEMBERS_REQUIRED")
        groups = {"observation": {}, "regression": {}}
        for entry in entries:
            member = PurePosixPath(entry.filename)
            require(member.as_posix() == entry.filename and len(member.parts) == 2
                    and member.parts[0] in groups and member.parts[1] != ".."
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", member.parts[1]) and not entry.is_dir()
                    and not stat.S_ISLNK(entry.external_attr >> 16),
                    "SAFE_REGULAR_FRESH_SOURCE_MEMBER_REQUIRED")
            groups[member.parts[0]][member.parts[1]] = source.read(entry)
    observation = groups["observation"]
    sums = {}
    for line in observation.pop("SHA256SUMS").decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match and match[2] not in sums, "UNIQUE_FRESH_OBSERVATION_CHECKSUM_REQUIRED")
        sums[match[2]] = match[1]
    require(set(sums) == set(observation) and all(sha(raw) == sums[name] for name, raw in observation.items()),
            "FRESH_OBSERVATION_CHECKSUM_CLOSURE_REQUIRED")
    require(set(groups["regression"]) == EXTRA_EVIDENCE, "EXACT_FRESH_REGRESSION_INPUTS_REQUIRED")
    return observation, groups["regression"]


def verify_regressions(members):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, raw in members.items():
            (root / name).write_bytes(raw)
        result = {
            "regressionEvidence": {name: parent.verify_regressions(root / path, name)
                                   for name, path in REGRESSIONS.items()},
            "hostedRegressionEvidence": {"shell": parent.verify_hosted_regressions(root / "shell-hosted.jsonl", "shell")},
            "dbCompatibility": json.loads(members["compat-receipt.json"]),
        }
    parent.verify_qualification_records(result)
    require(members["kafka-tidy.diff"] == b"", "NATIVE_KAFKA_TIDY_DRIFT")
    require(members["post-regression-mod-verify.txt"] == b"all modules verified\n",
            "POST_REGRESSION_ORIGINAL_MODULE_CACHE_CHECK_REQUIRED")
    for name, markers in COMBINED_DENIALS.items():
        require(all(marker.encode() in members[name] for marker in markers), "COMBINED_PROFILE_DENIAL_REQUIRED:" + name)
    lines = [line.split() for line in members["nested-lockfiles-before.sha256"].decode().splitlines()]
    sums = {name: digest for digest, name in lines}
    require(len(lines) == len(sums) == 4
            and sums == parent.PREVIOUS["sourceRevision"]["nestedKafkaLockfilesSha256"] | NESTED_IAM_LOCKS,
            "NESTED_LOCKFILE_EVIDENCE_REQUIRED")
    for name, expected in OTHER_TESTS.items():
        rows = [json.loads(line) for line in members[name].split(b"\n") if line]
        terminal = [row for row in rows if row.get("Action") in ("pass", "skip", "fail")]
        identities = {(row["Package"], row.get("Test")) for row in terminal}
        counts = Counter(row["Action"] + ("_tests" if "Test" in row else "_packages") for row in terminal)
        require(len(identities) == len(terminal) and counts == expected, "EXACT_NESTED_OR_COMPAT_TESTS_REQUIRED:" + name)
    return result


def build_evidence(bundle, producer, run_id):
    require(re.fullmatch(r"[0-9a-f]{40}", producer) and type(run_id) is int and run_id > 0
            and run_id != preflight.RUN, "NEW_GITHUB_PRODUCER_REQUIRED")
    observation, tests = read_bundle(bundle)
    packages, info, compiled, observed = verify_fresh_source(observation, producer, run_id)
    source = {
        "producerCommit": producer, "runId": run_id, "upstreamCommit": PROFILE.source_commit,
        "patchManifestSha256": file_hash(ROOT / preflight.MANIFEST),
        "vendorSourceBundleSha256": file_hash(bundle), "patchedTree": manifest["rootSourceGitTree"],
        "sourcePatchCount": 32, "dependencyPatchCount": 1, "vendor": manifest["vendor"],
        "observedReferenceRunId": preflight.RUN, "freshObservationSha256": sha(observation["observation.json"]),
        "rootLockfilesSha256": manifest["rootLockfilesSha256"],
        **verify_regressions(tests),
    }
    return source, packages, info, compiled, observation["root-module-graph.stdout"]


def stage(work, evidence, regressions, build, producer, run_id):
    verify_patch_sources()
    require(not build.exists(), "NEW_BUILD_OUTPUT_REQUIRED")
    root = work / "first"
    patch = ROOT / manifest["orderedDependencyPatches"][0]["path"]
    materializer = ROOT / "scripts/prepare_iceberg_vendor_patch.py"
    guard.verify_sources(profile, root, patch.read_bytes(), materializer.read_bytes())
    nested_locks = parent.PREVIOUS["sourceRevision"]["nestedKafkaLockfilesSha256"] | NESTED_IAM_LOCKS
    require(all(file_hash(root / name) == digest for name, digest in nested_locks.items()),
            "NESTED_LOCKFILE_DRIFT_AFTER_TESTS")
    binary = work / "weed-first"
    require(binary.stat().st_size == manifest["build"]["binaryBytes"] and file_hash(binary) == PROFILE.binary_sha
            and file_hash(work / "weed-second") == PROFILE.binary_sha, "FRESH_BINARY_PIN_REQUIRED")
    build.mkdir(parents=True)
    bundle = build / "vendor-source-evidence.zip"
    with zipfile.ZipFile(bundle, "x", compression=zipfile.ZIP_DEFLATED) as out:
        for path in sorted(evidence.iterdir()):
            require(path.is_file() and not path.is_symlink(), "REGULAR_OBSERVER_OUTPUT_REQUIRED")
            out.write(path, "observation/" + path.name)
        for name in sorted(EXTRA_EVIDENCE):
            path = regressions / name
            require(path.is_file() and not path.is_symlink(), "REGULAR_REGRESSION_OUTPUT_REQUIRED")
            out.write(path, "regression/" + name)
    source, _, _, _, _ = build_evidence(bundle, producer, run_id)
    (build / "build-source.json").write_bytes(image.canonical(source))
    shutil.copyfile(binary, build / "weed")
    shutil.copyfile(root / "LICENSE", build / "LICENSE")


def package(build, out):
    verify_patch_sources()
    require(not out.exists(), "NEW_CANDIDATE_IMAGE_OUTPUT_REQUIRED")
    identity = json.loads((build / "build-source.json").read_bytes())
    bundle = build / "vendor-source-evidence.zip"
    source, packages, info, _, root_graph = build_evidence(bundle, identity["producerCommit"], identity["runId"])
    require(source == identity, "FRESH_BUILD_SOURCE_RECORD_CHANGED")
    image.write_image((build / "weed").read_bytes(), (build / "LICENSE").read_bytes(), out, profile=PROFILE)
    graph = image.canonical({"packages": packages})
    (out / "original-compiled-packages.json").write_bytes(graph)
    (out / "original-candidate.json").write_bytes(image.canonical({
        "binarySha256": PROFILE.binary_sha, "declaredSource": PROFILE.source_commit,
        "compiledPackagesSha256": sha(graph), "buildInfoSha256": sha(info.encode()),
        "buildProfile": "go1.27.3-linux-amd64-cgo0-no-tags-vendor",
    }))
    (out / "build-info.txt").write_bytes(info.encode())
    (out / "generation-manifest.json").write_bytes((ROOT / preflight.MANIFEST).read_bytes())
    (out / "root-module-graph.txt").write_bytes(root_graph)
    (out / "build-source.json").write_bytes(image.canonical(source))
    shutil.copyfile(bundle, out / bundle.name)


def scan_inventories(scan_bytes, spdx_bytes, info):
    raw_binding = guard.verify_raw_identity(scan_bytes, spdx_bytes)
    scan, spdx = json.loads(scan_bytes), json.loads(spdx_bytes)
    require(scan.get("Trivy", {}).get("Version") == "0.70.0", "PINNED_TRIVY_REQUIRED")
    modules = contract.parse_module_rows(info)
    root_modules = [tuple(line.split("\t")[2:4]) for line in info.splitlines() if line.startswith("\tmod\t")]
    require(len(root_modules) == 1 and root_modules[0][0] == "github.com/seaweedfs/seaweedfs",
            "EXACT_MAIN_MODULE_REQUIRED")
    expected = modules | set(root_modules) | {("stdlib", "v1.27.3")}
    scan_packages = scan["Results"][0]["Packages"]
    require(len(scan_packages) == len(expected) and {(p["Name"], p["Version"]) for p in scan_packages} == expected,
            "COMPLETE_RAW_SCAN_BINARY_INVENTORY_REQUIRED")
    versioned = [(p["name"], p["versionInfo"]) for p in spdx["packages"] if p.get("versionInfo")]
    descriptive = [(p["name"], p.get("primaryPackagePurpose")) for p in spdx["packages"] if not p.get("versionInfo")]
    require(len(versioned) == len(expected) and set(versioned) == expected
            and len(descriptive) == 2 and set(descriptive) == {
                ("usr/local/bin/weed", "APPLICATION"), (scan["ArtifactName"], "CONTAINER")},
            "COMPLETE_RAW_SPDX_BINARY_INVENTORY_REQUIRED")
    findings = scan["Results"][0].get("Vulnerabilities")
    if findings is None:
        findings = []
    require(isinstance(findings, list) and all(isinstance(f, dict) and f.get("Severity") in SEVERITIES
            and f.get("VulnerabilityID") for f in findings), "COMPLETE_SEVERITY_INVENTORY_REQUIRED")
    counts = Counter(f["Severity"] for f in findings)
    held = sorted({f["VulnerabilityID"] for f in findings if f["Severity"] in ("CRITICAL", "HIGH", "UNKNOWN")})
    return {**raw_binding, "scannedBinaryComponents": len(expected), "spdxPackages": len(spdx["packages"]),
            "rawSeverityCounts": {level: counts[level] for level in SEVERITIES},
            "unresolvedHighCriticalUnknown": held, "vulnerabilitySubgate": "HELD_RAW_FINDINGS" if held else "PASS_RAW"}


def assess(out, image_id, producer, run_id):
    source, packages, info, compiled, root_graph = build_evidence(out / "vendor-source-evidence.zip", producer, run_id)
    require((out / "build-source.json").read_bytes() == image.canonical(source)
            and (out / "generation-manifest.json").read_bytes() == (ROOT / preflight.MANIFEST).read_bytes()
            and (out / "root-module-graph.txt").read_bytes() == root_graph
            and (out / "build-info.txt").read_bytes() == info.encode()
            and (out / "original-compiled-packages.json").read_bytes() == image.canonical({"packages": packages}),
            "CANDIDATE_SOURCE_EVIDENCE_BINDING_REQUIRED")
    original = json.loads((out / "original-candidate.json").read_bytes())
    require(original["buildInfoSha256"] == sha(info.encode()) and original["binarySha256"] == PROFILE.binary_sha,
            "CANDIDATE_BUILD_INFO_BINDING_REQUIRED")
    image_record = image.verify_layout(out, profile=PROFILE)
    require(image_id == image_record["configDigest"], "DAEMON_IMAGE_ID_CHANGED")
    evidence = {name: (out / name).read_bytes() for name in parent.lifecycle.INPUTS}
    sdk = parent.lifecycle.assess(evidence)
    scan, spdx = evidence["fresh-image-scan.json"], evidence["image.spdx.json"]
    result = scan_inventories(scan, spdx, info)
    supplement = guard.source_provenance(profile, PROFILE.binary_sha, scan, spdx,
        {"patchedVendorTreeSha256": profile["vendor"]["patchedTreeSha256"], "files": profile["vendor"]["fileCount"]},
        compiled)
    return {**image_record, **result, "generation": GENERATION, "patchedSourceTree": source["patchedTree"],
            "status": "IMAGE_EVIDENCE_PREPARED_NOT_ADMITTED", "producerCommit": producer, "runId": run_id,
            "sdkLifecycle": sdk, "deprecatedS3ManagerPresent": False,
            "buildSourceSha256": file_hash(out / "build-source.json"),
            "freshScanSha256": sha(scan), "sbomSha256": sha(spdx),
            "scanMatchesAllBinaryModules": True, "spdxMatchesAllBinaryModules": True,
            "appliedApplicabilityDispositions": [], "vendorSourceSupplement": supplement,
            "licenceReview": "OPEN", "durableReleaseCustody": "OPEN", "cohortQualification": "OPEN",
            "dependencyMaintenance": {"status": "OPEN", "allDependenciesMaintained": False},
            "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("preflight")
    stage_parser = sub.add_parser("stage")
    for name in ("work", "evidence", "regressions", "build"):
        stage_parser.add_argument(name, type=Path)
    pack = sub.add_parser("package")
    pack.add_argument("build", type=Path)
    pack.add_argument("output", type=Path)
    for operation in ("assess", "seal-sources"):
        sub.add_parser(operation).add_argument("output", type=Path)
    args = parser.parse_args(argv)
    if args.operation == "preflight":
        print(json.dumps(verify_patch_sources(), indent=2))
    elif args.operation == "stage":
        stage(args.work, args.evidence, args.regressions, args.build, os.environ["GITHUB_SHA"],
              int(os.environ["GITHUB_RUN_ID"]))
    elif args.operation == "package":
        package(args.build, args.output)
    elif args.operation == "assess":
        result = assess(args.output, (args.output / "daemon-image-id.txt").read_text().strip(),
                        os.environ["GITHUB_SHA"], int(os.environ["GITHUB_RUN_ID"]))
        (args.output / "assessment.json").write_bytes(image.canonical(result))
    else:
        seal_sources(args.output)
