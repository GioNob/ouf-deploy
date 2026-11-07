#!/usr/bin/env python3
"""Verify the exact SeaweedFS 4.52 delivery cohort without admitting it."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "readback", ROOT / "scripts/readback-seaweedfs-452-image.py"
)
readback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readback)
require = readback.require

MAX_ZIP_MEMBERS = 10000
MAX_SMALL_ARCHIVE_EXPANDED = 1024 * 1024 * 1024
EXPECTED_LICENCE_UNKNOWNS = {
    ("github.com/apache/arrow-go/v18", "v18.8.0", "LICENSE.txt",
     "ff2fe52b8dfd2574c6ea7f0c407948c857f62672c2a3a9a17083ee10af8067ef",
     "Copyright"): {"Apache-2.0", "BSD-3-Clause", "Copyright"},
    ("github.com/apache/thrift", "v0.24.0", "LICENSE",
     "89aa7b27868669299bd8a6c53b72ec4beadce42dad6c8336797cc26e1e8df98d",
     "GNU-All-permissive-Copying-License"):
        {"Apache-2.0", "BSD-3-Clause", "GNU-All-permissive-Copying-License"},
    ("github.com/parquet-go/parquet-go", "v0.32.0", "LICENSE",
     "6720c58d56926778b4656eb72c446ef65e8a416e2d2af498c8caaab24a02c8e9",
     "Copyright"): {"Apache-2.0", "Copyright"},
}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def checked_zip(path, expected_sha, required_names, exact_count=None):
    require(path.is_file() and sha256(path) == expected_sha, "EXACT_ARCHIVE_REQUIRED:" + path.name)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        require(len(entries) == len(set(names)) <= MAX_ZIP_MEMBERS, "UNIQUE_BOUNDED_MEMBERS_REQUIRED")
        if exact_count is not None:
            require(len(entries) == exact_count, "EXACT_ARCHIVE_MEMBER_COUNT_REQUIRED")
        require(set(required_names) <= set(names), "REQUIRED_ARCHIVE_MEMBERS_MISSING")
        require(sum(entry.file_size for entry in entries) <= MAX_SMALL_ARCHIVE_EXPANDED,
                "SMALL_ARCHIVE_EXPANDED_BUDGET")
        for entry in entries:
            name = PurePosixPath(entry.filename)
            require(str(name) == entry.filename and not name.is_absolute() and ".." not in name.parts,
                    "SAFE_ARCHIVE_PATH_REQUIRED")
            require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16),
                    "REGULAR_ARCHIVE_MEMBER_REQUIRED")
        return {name: archive.read(name) for name in required_names}


def validate_lock(lock):
    require(lock["schema"] == "ouf.storage-candidate-lock.v1", "CANDIDATE_LOCK_SCHEMA")
    require(lock["status"] == "EVIDENCE_PREPARED_NOT_ADMITTED", "CANDIDATE_NOT_ADMITTED")
    require(lock["orderedPatchCount"] == 15, "EXACT_PATCH_COUNT")
    require(lock["qualification"]["vulnerabilitySubgate"] == "PASS_RAW",
            "RAW_VULNERABILITY_SUBGATE_REQUIRED")
    require(all(value == 0 for value in lock["qualification"]["rawSeverityCounts"].values()),
            "ZERO_RAW_VULNERABILITY_FINDINGS_REQUIRED")
    require(lock["qualification"]["awsSdkV1"] == "ABSENT", "AWS_SDK_V1_ABSENT_REQUIRED")
    require(lock["qualification"]["deprecatedS3Manager"] == "ABSENT",
            "DEPRECATED_S3_MANAGER_ABSENT_REQUIRED")
    require(not lock["releaseAdmitted"] and not lock["runtimeAuthorityIssued"],
            "NO_RELEASE_OR_RUNTIME_AUTHORITY_REQUIRED")
    require(lock["targetOperations"] == 0, "ZERO_TARGET_OPERATIONS_REQUIRED")


def verify(lock_path, candidate_zip, readback_zip, licence_delta_zip,
           historical_licences_zip, output):
    require(not output.exists(), "NEW_COHORT_RECEIPT_REQUIRED")
    lock = json.loads(lock_path.read_bytes())
    validate_lock(lock)

    producer = lock["producerArtifact"]
    producer_sha = producer["digest"].removeprefix("sha256:")
    require(sha256(candidate_zip) == producer_sha, "EXACT_PRODUCER_ARTIFACT_REQUIRED")
    with tempfile.TemporaryDirectory() as directory:
        reproduced_dir = Path(directory) / "readback"
        reproduced = readback.verify(
            candidate_zip,
            reproduced_dir,
            producer_sha,
            lock["producerCommit"],
            lock["qualification"]["runId"],
        )
        require(reproduced["binarySha256"] == lock["buildProfile"]["binarySha256"],
                "LOCK_BINARY_BINDING_REQUIRED")
        require(reproduced["ociManifestDigest"] == lock["image"]["manifestDigest"],
                "LOCK_OCI_BINDING_REQUIRED")
        require(reproduced["imageConfigDigest"] == lock["image"]["configDigest"],
                "LOCK_CONFIG_BINDING_REQUIRED")

        hosted = lock["independentReadback"]
        readback_members = checked_zip(
            readback_zip,
            hosted["digest"].removeprefix("sha256:"),
            ["SHA256SUMS", "assessment.json", "byte-readback.json", "provenance.json",
             "publisher-verification.json", "source-SHA256SUMS"],
            exact_count=6,
        )
        for name in ("SHA256SUMS", "assessment.json", "byte-readback.json",
                     "provenance.json", "source-SHA256SUMS"):
            require(readback_members[name] == (reproduced_dir / name).read_bytes(),
                    "INDEPENDENT_READBACK_MISMATCH:" + name)
        publisher = json.loads(readback_members["publisher-verification.json"])
        require(isinstance(publisher, list) and len(publisher) == 1,
                "EXACT_PUBLISHER_VERIFICATION_REQUIRED")
        verification = publisher[0]["verificationResult"]
        certificate = verification["signature"]["certificate"]
        statement = verification["statement"]
        invocation = statement["predicate"]["runDetails"]["metadata"]["invocationId"]
        require(invocation.endswith(f'/runs/{lock["qualification"]["runId"]}/attempts/1'),
                "PUBLISHER_RUN_BINDING_REQUIRED")
        require(certificate["sourceRepositoryDigest"] == lock["producerCommit"]
                and certificate["githubWorkflowSHA"] == lock["producerCommit"],
                "PUBLISHER_COMMIT_BINDING_REQUIRED")
        require(certificate["runnerEnvironment"] == "github-hosted"
                and certificate["githubWorkflowRepository"] == "GioNob/ouf-deploy",
                "PUBLISHER_IDENTITY_REQUIRED")
        require(statement["subject"] == [{"name": "SHA256SUMS", "digest": {
            "sha256": hashlib.sha256(readback_members["SHA256SUMS"]).hexdigest()
        }}], "PUBLISHER_SUBJECT_BINDING_REQUIRED")

    preflight = lock["licencePreflight"]
    delta_members = checked_zip(
        licence_delta_zip,
        preflight["sha256"],
        ["licence-preflight-receipt.json", "classifier-results.json", "SHA256SUMS"],
        exact_count=preflight["archiveMembers"],
    )
    licence = json.loads(delta_members["licence-preflight-receipt.json"])
    require(licence["binarySha256"] == lock["buildProfile"]["binarySha256"],
            "LICENCE_BINARY_BINDING_REQUIRED")
    require(licence["ociManifestDigest"] == lock["image"]["manifestDigest"],
            "LICENCE_OCI_BINDING_REQUIRED")
    require(licence["thirdPartyModulesVerified"] == preflight["checkedThirdPartyModules"],
            "LICENCE_MODULE_COUNT_REQUIRED")
    require(len(licence["unknownClassifications"]) == preflight["rawUnknownClassifications"],
            "LICENCE_UNKNOWN_COUNT_REQUIRED")
    require(not licence["redistributionAccepted"] and licence["licenceReview"] == "OPEN",
            "LICENCE_REVIEW_MUST_REMAIN_OPEN")
    classifier = json.loads(delta_members["classifier-results.json"])
    detections = {}
    for group in classifier["Results"]:
        for finding in group.get("Licenses", []):
            detections.setdefault(finding["FilePath"], set()).add(finding["Name"])
    unknowns = {
        (row["module"], row["version"], row["path"], row["sha256"], row["classifier"]):
            detections[row["view"]]
        for row in licence["unknownClassifications"]
    }
    require(unknowns == EXPECTED_LICENCE_UNKNOWNS,
            "EXACT_LICENCE_UNKNOWN_CONTEXT_REQUIRED")

    historical = licence["historicalCorpus"]
    checked_zip(
        historical_licences_zip,
        historical["sha256"],
        ["inventory.json", "mpl-source-manifest.json", "SHA256SUMS"],
    )

    result = {
        "schema": "ouf.seaweedfs-452-cohort-readback.v1",
        "status": "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED",
        "candidateLockSha256": sha256(lock_path),
        "binarySha256": reproduced["binarySha256"],
        "ociManifestDigest": reproduced["ociManifestDigest"],
        "producerArtifact": {
            "sha256": producer_sha,
            "bytes": candidate_zip.stat().st_size,
            "retention": producer["retention"],
            "expiresAt": producer["expiresAt"],
            "contentAndChecksumsVerified": True,
        },
        "independentReadback": {
            "sha256": sha256(readback_zip),
            "publisherSignatureVerified": True,
            "assessmentReproduced": True,
        },
        "licenceEvidence": {
            "deltaSha256": sha256(licence_delta_zip),
            "historicalCorpusSha256": sha256(historical_licences_zip),
            "thirdPartyModulesVerified": licence["thirdPartyModulesVerified"],
            "legalTextsFound": licence["thirdPartyLegalTextsFound"],
            "rawUnknownClassifications": len(licence["unknownClassifications"]),
            "unknownClassifierContextVerified": True,
            "review": "OPEN",
            "redistributionAccepted": False,
        },
        "durableImageCustody": "OPEN",
        "cohortContent": "VERIFIED",
        "releaseAdmitted": False,
        "runtimeAuthorityIssued": False,
        "targetOperations": 0,
    }
    output.write_bytes(canonical(result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--readback", type=Path, required=True)
    parser.add_argument("--licence-delta", type=Path, required=True)
    parser.add_argument("--historical-licences", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.lock, args.candidate, args.readback, args.licence_delta,
                            args.historical_licences, args.output), indent=2))
