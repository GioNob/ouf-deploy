#!/usr/bin/env python3
"""Sequential generation31 cold+MIME and identity/TLS labs, never acceptance."""
import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = Path(__file__).resolve()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


binding_api = load_module("generation31_binding", ROOT / "scripts/storage-generation31-lab-binding.py")
require = binding_api.require


def preflight(lock_sha, cohort_sha, root=ROOT, cohort_path=None):
    binding = binding_api.load(root, lock_sha)
    path = Path(cohort_path) if cohort_path is not None else Path(root) / binding_api.COHORT_RECEIPT_PATH
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024,
            "VERIFIED_COHORT_RECEIPT_NOT_AVAILABLE")
    binding_api.validate_cohort_receipt(path.read_bytes(), cohort_sha, binding)
    binding["cohortReceiptSha256"] = cohort_sha
    binding["cohortReceiptPath"] = str(path.resolve())
    return binding


COHORT_MEMBERS = {
    "cohort-receipt.json", "seaweedfs-452-generation31-candidate-lock-20261103.json",
    "modified-raftstore-source.tar.gz", "modified-raftstore-source-manifest.json",
    "licence-rebinding.json", "publisher-verification.json", "producer/SHA256SUMS",
    "producer/provenance.json", "ordered-patches.txt", "module-downloads.jsonl", "SHA256SUMS",
}


def bind_cohort_artifact(archive, output, binding, expected_archive_sha, expected_receipt_sha, root=ROOT):
    """Authenticate the predecessor job's complete small bundle before extraction."""
    require(binding_api.valid_sha(expected_archive_sha) and archive.is_file() and not archive.is_symlink()
            and 0 < archive.stat().st_size <= 32 * 1024 * 1024, "BOUNDED_COHORT_ARCHIVE_REQUIRED")
    require(binding_api.sha(archive.read_bytes()) == expected_archive_sha, "EXACT_COHORT_ARCHIVE_SHA_REQUIRED")
    require(not output.exists() and not output.is_symlink(), "NEW_COHORT_BINDING_DIRECTORY_REQUIRED")
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        require(len(entries) == len(COHORT_MEMBERS) and {e.filename for e in entries} == COHORT_MEMBERS,
                "EXACT_COHORT_BUNDLE_MEMBERS_REQUIRED")
        require(sum(e.file_size for e in entries) <= 64 * 1024 * 1024, "COHORT_EXPANSION_BUDGET")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in entry.filename
                    and not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16),
                    "REGULAR_COHORT_MEMBERS_REQUIRED")
        members = {e.filename: source.read(e) for e in entries}
    sums = {}
    for line in members["SHA256SUMS"].decode().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        require(match is not None, "UNIQUE_COHORT_CHECKSUM_REQUIRED")
        name = match[2][2:] if match[2].startswith("./") else match[2]
        require(name in COHORT_MEMBERS and name not in sums, "UNIQUE_COHORT_CHECKSUM_REQUIRED")
        sums[name] = match[1]
    require(set(sums) == COHORT_MEMBERS - {"SHA256SUMS"}, "COMPLETE_COHORT_CHECKSUM_CLOSURE_REQUIRED")
    require(all(binding_api.sha(members[name]) == digest for name, digest in sums.items()),
            "COHORT_MEMBER_CHECKSUM_MISMATCH")
    lock_bytes = (Path(root) / binding_api.LOCK_PATH).read_bytes()
    require(members["seaweedfs-452-generation31-candidate-lock-20261103.json"] == lock_bytes
            and binding_api.sha(lock_bytes) == binding["lockSha256"], "COHORT_LOCK_COPY_MUST_MATCH_COMMITTED_LOCK")
    receipt = binding_api.validate_cohort_receipt(members["cohort-receipt.json"], expected_receipt_sha, binding)
    require(binding_api.sha(members["licence-rebinding.json"]) == receipt["legalTextRebindingSha256"],
            "COHORT_LEGAL_REBINDING_CHANGED")
    require(binding_api.sha(members["modified-raftstore-source.tar.gz"]) == binding_api.MODIFIED_MPL_ARCHIVE_SHA
            and binding_api.sha(members["modified-raftstore-source-manifest.json"]) == binding_api.MODIFIED_MPL_MANIFEST_SHA,
            "COHORT_MODIFIED_MPL_SOURCE_CHANGED")
    output.mkdir(parents=True)
    for name, raw in members.items():
        dest = output / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(raw)
    return output / "cohort-receipt.json"


def check_archive(archive, binding):
    expected = binding["lock"]["producerArtifact"]
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == expected["bytes"],
            "EXACT_PRODUCER_ARCHIVE_SIZE_REQUIRED")
    with archive.open("rb") as stream:
        import hashlib
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    require(actual == expected["digest"][7:], "EXACT_PRODUCER_ARCHIVE_SHA_REQUIRED")


def prepare_image(archive, work, binding, cold, root=ROOT):
    check_archive(archive, binding)
    reader = load_module("generation31_runtime_readback", Path(root) / "scripts/readback-seaweedfs-452-generation31-image.py").engine
    lock = binding["lock"]
    require(reader.candidate.PROFILE.binary_sha == binding_api.BINARY_SHA
            and reader.candidate.MANIFEST["generation"] == 31,
            "GENERATION31_IMAGE_PROFILE_REQUIRED")
    result = reader.verify(archive, work / "readback", lock["producerArtifact"]["digest"][7:],
                           lock["producerCommit"], lock["qualification"]["runId"])
    require(result["binarySha256"] == binding_api.BINARY_SHA
            and result["ociManifestDigest"] == lock["image"]["manifestDigest"]
            and result["imageConfigDigest"] == lock["image"]["configDigest"],
            "READBACK_IMAGE_AND_LOCK_MUST_MATCH")
    image_root = work / "image"
    image_root.mkdir()
    reader.unpack(archive, image_root)
    record = reader.candidate.image.verify_layout(image_root, profile=reader.candidate.PROFILE)
    require(all(record[k] == lock["image"][k] for k in
                ("manifestDigest", "configDigest", "layerDigest", "dockerArchiveSha256", "upstreamLicenceSha256"))
            and record["binarySha256"] == binding_api.BINARY_SHA, "EXACT_GENERATION31_OCI_REQUIRED")
    require(cold.file_digest(image_root / "runtime.docker.tar") == lock["image"]["dockerArchiveSha256"],
            "EXACT_DOCKER_ARCHIVE_REQUIRED")
    cold.command(["docker", "load", "--input", str(image_root / "runtime.docker.tar")], timeout=120)
    require(cold.command(["docker", "image", "inspect", "--format", "{{.Id}}", cold.IMAGE_ID]) == cold.IMAGE_ID,
            "DAEMON_IMAGE_CHANGED")
    return record


def child_argv(lab, mode, action, binding):
    args = ["sudo", "-n", "nsenter", "-t", lab.pid, "-n", sys.executable, "-I", "-B", "-S",
            str(ENTRYPOINT), "client", mode, action, binding["lockSha256"], binding["cohortReceiptSha256"],
            "--cohort-receipt", binding["cohortReceiptPath"]]
    if mode == "identity":
        args.extend(["--tls", str(lab.data / "config/tls")])
    return args


def configured_harness(mode, binding, root=ROOT):
    require(mode in {"cold", "identity"}, "KNOWN_LAB_REQUIRED")
    source = "run-seaweedfs-452-cold-recovery.py" if mode == "cold" else "run-seaweedfs-452-identity-tls.py"
    module = load_module("generation31_" + mode, Path(root) / "scripts" / source)
    cold = module if mode == "cold" else module.cold
    cold.LOCK_SHA = binding["lockSha256"]
    cold.IMAGE_ID = binding["lock"]["image"]["configDigest"]
    cold.MANIFEST = binding["lock"]["image"]["manifestDigest"]
    cold.BINARY_SHA = binding_api.BINARY_SHA
    cold.prepare_image = lambda archive, work: prepare_image(archive, work, binding, cold, root)
    native_lab = module.Lab

    class Generation30Lab(native_lab):
        def client(self, action):
            timeout = 90 if action == "ready" else (180 if mode == "cold" else 240)
            try:
                output = cold.command(child_argv(self, mode, action, binding), timeout=timeout)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                (self.evidence / (self.prefix + "-" + action + "-stderr.log")).write_text(
                    cold.bounded_diagnostic(error.stderr, "GENERATION31_CLIENT_FAILED_WITHOUT_STDERR"))
                raise RuntimeError("GENERATION31_CLIENT_FAILED:" + mode + ":" + action) from error
            result = json.loads(output)
            if mode == "cold" and action in {"seed", "verify"}:
                binding_api.require_octet_stream_pass(result)
            cold.write_json(self.evidence / (self.prefix + "-" + action + ".json"), result)
            return result

    module.Lab = Generation30Lab
    return module


def run_client(mode, action, binding, tls=None):
    module = configured_harness(mode, binding)
    if mode == "identity":
        require(action in {"ready", "verify"} and tls is not None, "IDENTITY_CLIENT_ARGUMENTS_REQUIRED")
        return module.client(action, tls)
    require(action in {"ready", "seed", "verify"}, "COLD_CLIENT_ACTION_REQUIRED")
    result = module.client(action)
    if action != "ready":
        binding_api.require_octet_stream_pass(result)
    return result


def validate_results(cold_result, identity_result, binding):
    for result in (cold_result, identity_result):
        require(result.get("candidateLockSha256") == binding["lockSha256"]
                and result.get("ociManifestDigest") == binding["lock"]["image"]["manifestDigest"]
                and result.get("binarySha256") == binding_api.BINARY_SHA,
                "RUNTIME_RESULTS_MUST_BIND_GENERATION31")
        require(result.get("releaseAdmitted") is False and result.get("runtimeAuthorityIssued") is False
                and result.get("targetOperations") == result.get("gatesClosed") == result.get("acceptanceTestsPassed") == 0,
                "LAB_CANNOT_GRANT_AUTHORITY")
    require(cold_result.get("status") == "SYNTHETIC_STORAGE_COLD_RESTORE_PASS_NOT_ACCEPTANCE"
            and cold_result.get("originalContainersRemoved") is True
            and cold_result.get("restoreUsesOnlyIndependentRoots") is True, "COLD_RESTORE_NOT_VERIFIED")
    binding_api.require_octet_stream_pass(cold_result)
    require(identity_result.get("status") == "SYNTHETIC_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE"
            and identity_result.get("s3CasesPassed") == 23 and identity_result.get("tlsNegativesPassed") == 2
            and identity_result.get("egressProbesPassed") == 2, "IDENTITY_TLS_EGRESS_NOT_VERIFIED")


def run(archive, work, binding):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "ISOLATED_CI_ONLY")
    check_archive(archive, binding)
    require(not work.exists() and not work.is_symlink(), "NEW_LAB_WORK_DIRECTORY_REQUIRED")
    work.mkdir(parents=True)
    try:
        # Each original run performs strict stop before it can return success.
        cold = configured_harness("cold", binding)
        cold.run(archive, work / "cold")
        identity = configured_harness("identity", binding)
        identity.run(archive, work / "identity")
        cold_result = json.loads((work / "cold/evidence/recovery-result.json").read_bytes())
        identity_result = json.loads((work / "identity/evidence/identity-result.json").read_bytes())
        validate_results(cold_result, identity_result, binding)
        result = {"schema": "ouf.seaweedfs-generation31-runtime-labs.v1", "generation": 31,
                  "status": "SYNTHETIC_COLD_MIME_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE",
                  "candidateLockSha256": binding["lockSha256"], "cohortReceiptSha256": binding["cohortReceiptSha256"],
                  "buildManifestSha256": binding_api.BUILD_MANIFEST_SHA, "binarySha256": binding_api.BINARY_SHA,
                  "ociManifestDigest": binding["lock"]["image"]["manifestDigest"],
                  "octetStreamBeforeAndAfterRestore": "PASS", "identityS3Cases": 23, "tlsNegatives": 2,
                  "egressProbes": 2, "maximumConcurrentContainers": 4, "labsSequential": True,
                  "harnessSourceSha256": binding_api.HARNESS_SOURCES, "targetOperations": 0,
                  "gatesClosed": 0, "acceptanceTestsPassed": 0, "releaseAdmitted": False,
                  "runtimeAuthorityIssued": False}
        (work / "runtime-result.json").write_text(json.dumps(result, indent=2) + "\n")
    except Exception as error:
        (work / "runtime-failure.json").write_text(json.dumps({
            "generation": 31, "status": "GENERATION31_RUNTIME_FAILED_NOT_ACCEPTANCE",
            "failureClass": type(error).__name__, "safeReason": str(error)[:512] if isinstance(error, (ValueError, RuntimeError)) else "COMMAND_OR_IO_FAILED",
            "targetOperations": 0, "releaseAdmitted": False, "runtimeAuthorityIssued": False}, indent=2) + "\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    info = sub.add_parser("lock-info"); info.add_argument("lock_sha256")
    bind = sub.add_parser("bind-cohort")
    bind.add_argument("archive", type=Path); bind.add_argument("output", type=Path)
    bind.add_argument("lock_sha256"); bind.add_argument("cohort_receipt_sha256"); bind.add_argument("cohort_archive_sha256")
    pre = sub.add_parser("preflight")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("archive", type=Path); run_parser.add_argument("work", type=Path)
    child = sub.add_parser("client")
    child.add_argument("mode", choices=("cold", "identity")); child.add_argument("action", choices=("ready", "seed", "verify"))
    child.add_argument("--tls", type=Path)
    for item in (pre, run_parser, child):
        item.add_argument("lock_sha256"); item.add_argument("cohort_receipt_sha256")
        item.add_argument("--cohort-receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.operation in {"lock-info", "bind-cohort"}:
        binding = binding_api.load(ROOT, args.lock_sha256)
        if args.operation == "lock-info":
            print(json.dumps({"artifactId": binding["lock"]["producerArtifact"]["id"],
                              "lockSha256": binding["lockSha256"]}))
        else:
            path = bind_cohort_artifact(args.archive, args.output, binding, args.cohort_archive_sha256,
                                        args.cohort_receipt_sha256)
            print(json.dumps({"cohortReceiptPath": str(path), "status": "EXACT_COHORT_ARTIFACT_BOUND"}))
        return
    binding = preflight(args.lock_sha256, args.cohort_receipt_sha256, cohort_path=args.cohort_receipt)
    if args.operation == "preflight":
        print(json.dumps({"status": "VERIFIED_GENERATION31_COHORT_BOUND", "lockSha256": binding["lockSha256"]}))
    elif args.operation == "client":
        print(json.dumps(run_client(args.mode, args.action, binding, args.tls)))
    else:
        run(args.archive.resolve(), args.work.absolute(), binding)


if __name__ == "__main__":
    main()
