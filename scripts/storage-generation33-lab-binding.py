#!/usr/bin/env python3
"""Pure fail-closed binding for generation33 synthetic runtime laboratories.

No Docker, network, imports of legacy harnesses, or production lock is created.
The caller must provide the committed lock digest; unknown producer facts are
not accepted as placeholders. Existing generation15 entrypoints stay unchanged.
"""
import hashlib
import json
from pathlib import Path
import re

BUILD_MANIFEST_PATH = "releases/seaweedfs-452-generation33-vendor-build-manifest-20261104.json"
BUILD_MANIFEST_SHA = "6fa4e051e4a5c3f41c262ce4b3d1b0b36c0de27d462c930268ef99a542b40232"
BINARY_SHA = "c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc"
MODIFIED_MPL_ARCHIVE_SHA = "2767531e9510840ba159cdbb9062633dad51d4d2b5984b7d57c1aabcb38d177e"
MODIFIED_MPL_MANIFEST_SHA = "0b65ee710cf88f9bd2b76c0918377f10b71c6225d8937732ae6871e875569d53"
LOCK_PATH = "releases/seaweedfs-452-generation33-candidate-lock-20261104.json"
MONGO_DELTA_PATH = "evidence/seaweedfs-452-generation32-mongodb-v2-legal-delta-20261104.json"
VENDOR_PROFILE_PATH = "config/seaweedfs-generation33-vendor-source-profile.json"
VENDOR_PROFILE_SHA = "2331b929c579e778a76072d279f8aa47e31cc054c0c8165936de8a7d7a6a5464"
HARNESS_SOURCES = {
    "scripts/run-seaweedfs-452-cold-recovery.py": "a4cbc41ec35ff220868c616ce323612d8e89eec42e0cbd9c47332c25f4344089",
    "scripts/run-seaweedfs-452-identity-tls.py": "50f75e99b0f3f012b2651e6856fecfc3f1742d20676c70c36499f30e84e75185",
}
SHA = re.compile(r"[a-f0-9]{64}")


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def valid_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) and value != "0" * 64


def artifact(value, code):
    require(isinstance(value, dict), code)
    require(type(value.get("id")) is int and value["id"] > 0, code + "_ID")
    require(type(value.get("bytes")) is int and 0 < value["bytes"] <= 512 * 1024 * 1024,
            code + "_SIZE")
    digest = value.get("digest", "")
    require(isinstance(digest, str) and digest.startswith("sha256:")
            and valid_sha(digest[7:]), code + "_DIGEST")


def validate(lock_bytes, expected_lock_sha, manifest_bytes):
    """Return a detached binding after exact identity validation, without effects."""
    require(valid_sha(expected_lock_sha) and sha(lock_bytes) == expected_lock_sha,
            "EXACT_COMMITTED_GENERATION33_LOCK_REQUIRED")
    require(sha(manifest_bytes) == BUILD_MANIFEST_SHA, "EXACT_GENERATION33_BUILD_MANIFEST_REQUIRED")
    lock = json.loads(lock_bytes)
    manifest = json.loads(manifest_bytes)
    require(lock.get("schema") == "ouf.storage-candidate-lock.v3"
            and lock.get("generation") == 33 and lock.get("orderedPatchCount") == 33
            and lock.get("sourcePatchCount") == 32 and type(lock.get("dependencyPatchCount")) is int
            and lock.get("dependencyPatchCount") == 1
            and lock.get("status") == "EVIDENCE_PREPARED_NOT_ADMITTED",
            "GENERATION33_LOCK_REQUIRED")
    build = lock.get("buildManifest", {})
    require(build.get("path") == BUILD_MANIFEST_PATH and build.get("sha256") == BUILD_MANIFEST_SHA
            and build.get("rootSourceTree") == manifest["rootSourceGitTree"]
            and build.get("vendorAfterTreeSha256") == manifest["vendor"]["afterTreeSha256"],
            "EXACT_PATCHED_SOURCE_REQUIRED")
    require(lock.get("buildProfile", {}).get("binarySha256") == BINARY_SHA
            and manifest["build"]["binarySha256"] == BINARY_SHA,
            "EXACT_GENERATION33_BINARY_REQUIRED")
    require(lock.get("buildProfile") == manifest["build"], "EXACT_GENERATION33_BUILD_PROFILE_REQUIRED")
    require(lock.get("modifiedMplSource") == {"archiveSha256": MODIFIED_MPL_ARCHIVE_SHA, "manifestSha256": MODIFIED_MPL_MANIFEST_SHA},
            "EXACT_MODIFIED_MPL_SOURCE_LOCK_REQUIRED")
    require(lock.get("dependencyMaintenance") == {"status": "OPEN", "allDependenciesMaintained": False},
            "MAINTENANCE_REVIEW_MUST_REMAIN_OPEN")
    require(lock.get("sourceRevision") == {
                "rootSourceGitTree": manifest["rootSourceGitTree"],
                "rootLockfilesSha256": manifest["rootLockfilesSha256"],
                "vendorAfterTreeSha256": manifest["vendor"]["afterTreeSha256"]}
            and lock.get("compiledDependencyPolicy") == {
                "allTenArchivedCensus29ModulesAbsent": True, "allDependenciesMaintained": False},
            "EXACT_GENERATION33_SOURCE_PROFILE_REQUIRED")
    require(lock.get("vendorSourceProfile") == {"path": VENDOR_PROFILE_PATH, "sha256": VENDOR_PROFILE_SHA},
            "EXACT_GENERATION33_VENDOR_PROFILE_REQUIRED")
    mongo = lock.get("mongoV2LegalDelta", {})
    require(mongo.get("path") == MONGO_DELTA_PATH and valid_sha(mongo.get("sha256")),
            "EXACT_MONGODB_V2_LEGAL_DELTA_REQUIRED")
    producer = lock.get("producerCommit", "")
    require(isinstance(producer, str) and re.fullmatch(r"[a-f0-9]{40}", producer)
            and producer != "0" * 40, "REAL_PRODUCER_COMMIT_REQUIRED")
    qualification = lock.get("qualification", {})
    require(type(qualification.get("runId")) is int and qualification["runId"] > 0
            and qualification.get("allJobsPassed") is True
            and qualification.get("workflow") == ".github/workflows/storage-452-generation33-image.yml"
            and qualification.get("vulnerabilitySubgate") == "PASS_RAW", "QUALIFIED_PRODUCER_REQUIRED")
    severity = qualification.get("rawSeverityCounts", {})
    require(all(type(severity.get(k)) is int and severity[k] >= 0
                for k in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
            and all(severity[k] == 0 for k in ("UNKNOWN", "HIGH", "CRITICAL")),
            "RAW_FINDINGS_MUST_NOT_BE_HIDDEN")
    artifact(lock.get("producerArtifact"), "REAL_PRODUCER_ARTIFACT_REQUIRED")
    artifact(lock.get("independentReadback"), "REAL_READBACK_ARTIFACT_REQUIRED")
    image = lock.get("image", {})
    for key in ("manifestDigest", "configDigest", "layerDigest"):
        value = image.get(key, "")
        require(isinstance(value, str) and value.startswith("sha256:") and valid_sha(value[7:]),
                "EXACT_IMAGE_DIGEST_REQUIRED:" + key)
    for key in ("dockerArchiveSha256", "upstreamLicenceSha256"):
        require(valid_sha(image.get(key)), "EXACT_IMAGE_DIGEST_REQUIRED:" + key)
    require(lock.get("releaseAdmitted") is False and lock.get("runtimeAuthorityIssued") is False
            and type(lock.get("targetOperations")) is int and lock["targetOperations"] == 0,
            "LAB_CANNOT_GRANT_AUTHORITY")
    return {"generation": 33, "lockSha256": expected_lock_sha, "lock": lock,
            "buildManifestSha256": BUILD_MANIFEST_SHA, "binarySha256": BINARY_SHA}


def load(root, expected_lock_sha):
    """Fail before legacy module import, subprocess, artifact unpack, or Docker."""
    root = Path(root)
    lock_path = root / LOCK_PATH
    require(lock_path.is_file() and not lock_path.is_symlink(), "GENERATION33_LOCK_NOT_AVAILABLE")
    binding = validate(lock_path.read_bytes(), expected_lock_sha, (root / BUILD_MANIFEST_PATH).read_bytes())
    profile = root / VENDOR_PROFILE_PATH
    require(profile.is_file() and not profile.is_symlink() and sha(profile.read_bytes()) == VENDOR_PROFILE_SHA,
            "EXACT_GENERATION33_VENDOR_PROFILE_REQUIRED")
    delta = root / MONGO_DELTA_PATH
    require(delta.is_file() and not delta.is_symlink()
            and sha(delta.read_bytes()) == binding["lock"]["mongoV2LegalDelta"]["sha256"],
            "EXACT_MONGODB_V2_LEGAL_DELTA_REQUIRED")
    for path, expected in HARNESS_SOURCES.items():
        source = root / path
        require(source.is_file() and not source.is_symlink() and sha(source.read_bytes()) == expected,
                "PINNED_LAB_HARNESS_CHANGED:" + path)
    return binding


def require_octet_stream_pass(result):
    """Both seed and verify must cross this guard in the new cold adapter."""
    probe = result.get("octetStreamCompatibility", {})
    require(probe.get("status") == "PASS" and probe.get("findings") == []
            and probe.get("requestedContentType") == "application/octet-stream"
            and probe.get("getContentType") == "application/octet-stream"
            and probe.get("headContentType") == "application/octet-stream",
            "GENERATION33_OCTET_STREAM_REGRESSION")
    return result

COHORT_RECEIPT_PATH = "evidence/seaweedfs-452-generation33-cohort-hosted-20261104.json"


def validate_cohort_receipt(raw, expected_sha, binding):
    require(valid_sha(expected_sha) and sha(raw) == expected_sha, "EXACT_VERIFIED_COHORT_RECEIPT_REQUIRED")
    receipt = json.loads(raw)
    lock = binding["lock"]
    require(receipt.get("schema") == "ouf.seaweedfs-generation33-cohort.v1"
            and receipt.get("generation") == 33
            and receipt.get("status") == "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED",
            "VERIFIED_GENERATION33_COHORT_REQUIRED")
    expected = {"candidateLockSha256": binding["lockSha256"], "binarySha256": BINARY_SHA,
                "ociManifestDigest": lock["image"]["manifestDigest"],
                "producerArtifactSha256": lock["producerArtifact"]["digest"][7:],
                "independentReadbackSha256": lock["independentReadback"]["digest"][7:]}
    require(all(receipt.get(k) == v for k, v in expected.items()), "COHORT_AND_RUNTIME_BINDING_MISMATCH")
    require(receipt.get("modifiedMplSourceArchiveSha256") == MODIFIED_MPL_ARCHIVE_SHA
            and receipt.get("modifiedMplSourceManifestSha256") == MODIFIED_MPL_MANIFEST_SHA
            and receipt.get("dependencyMaintenance") == {"status": "OPEN", "allDependenciesMaintained": False},
            "COHORT_MODIFIED_MPL_SOURCE_BINDING_REQUIRED")
    require(receipt.get("readbackReproduced") is True
            and receipt.get("publisherVerificationRecordBound") is True
            and valid_sha(receipt.get("legalTextRebindingSha256")), "COHORT_VERIFICATION_INCOMPLETE")
    require(receipt.get("mongoV2LegalDeltaSha256") == lock["mongoV2LegalDelta"]["sha256"]
            and receipt.get("sourceRevision") == lock["sourceRevision"]
            and receipt.get("compiledDependencyPolicy") == lock["compiledDependencyPolicy"]
            and receipt.get("vendorSourceProfile") == lock["vendorSourceProfile"],
            "COHORT_GENERATION33_PROFILE_OR_MONGODB_DELTA_CHANGED")
    modified = receipt.get("modifiedVendorDependency", {})
    require(modified.get("module") == "github.com/apache/iceberg-go" and modified.get("version") == "v0.7.0"
            and modified.get("sourceProfilePath") == VENDOR_PROFILE_PATH
            and modified.get("sourceProfileSha256") == VENDOR_PROFILE_SHA
            and modified.get("downstreamNoticePresent") is True
            and modified.get("originalChecksumsDescribeModifiedSource") is False
            and modified.get("canonicalScannerIdentityModified") is False
            and modified.get("canonicalSpdxIdentityModified") is False
            and modified.get("licenceReview") == "OPEN" and modified.get("redistributionAccepted") is False,
            "COHORT_MODIFIED_VENDOR_PROVENANCE_REQUIRED")
    require(all(valid_sha(modified.get(k)) for k in
                ("originalZipSha256", "originalConfigSha256", "modifiedConfigSha256", "patchSha256"))
            and modified.get("patchPath") == "patches/iceberg-go/0.7.0-maintained-yaml-vendor.patch"
            and isinstance(modified.get("originalZipH1InputOnly"), str)
            and re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", modified["originalZipH1InputOnly"]),
            "COHORT_ORIGINAL_INPUT_AND_PATCH_IDENTITIES_REQUIRED")
    texts = modified.get("originalLegalTexts", {})
    require(set(texts) == {"LICENSE", "NOTICE"}
            and all(isinstance(v, dict) and valid_sha(v.get("sha256"))
                    and type(v.get("bytes")) is int and v["bytes"] > 0 for v in texts.values()),
            "COHORT_ORIGINAL_VENDOR_LEGAL_TEXTS_REQUIRED")
    require(receipt.get("releaseAdmitted") is False and receipt.get("runtimeAuthorityIssued") is False
            and type(receipt.get("targetOperations")) is int and receipt["targetOperations"] == 0,
            "LAB_CANNOT_GRANT_AUTHORITY")
    return receipt
