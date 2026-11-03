#!/usr/bin/env python3
"""Fail-closed verifier for the current SeaweedFS qualification view.

The replacement plan intentionally retains the 4.51 evidence blocks as history.
This verifier binds the additive 4.52 view to the immutable candidate lock, the
hosted cohort receipt, and the five test-only SDK-v2 migration dossiers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


PLAN_PATH = "releases/minio-seaweedfs-plan-20261102.json"
LOCK_PATH = "releases/seaweedfs-452-candidate-lock-20261103.json"
COHORT_PATH = "evidence/seaweedfs-452-cohort-readback-hosted-20261103.json"
UPSTREAM_COMMIT = "984eac6a790be89e2a11de175a7413e1e3e32dd3"
LOCK_SHA256 = "81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea"
EXPECTED_DOSSIERS = [
    "evidence/seaweedfs-sdk-v1-basic-tests-local-20261103.json",
    "evidence/seaweedfs-sdk-v1-multipart-tool-local-20261103.json",
    "evidence/seaweedfs-sdk-v1-volume-grpc-test-local-20261103.json",
    "evidence/seaweedfs-sdk-v1-s3tables-signer-local-20261103.json",
    "evidence/seaweedfs-sdk-v1-sse-tests-local-20261103.json",
]
HISTORICAL_FIELDS = [
    "candidate",
    "latestLaboratoryQualification",
    "g1ApplicabilityReview",
    "runtimeImageQualification",
    "licenceEvidence",
    "dependencyLifecycleReview",
]
HISTORICAL_CANONICAL_SHA256 = {
    "candidate": "a390757b96fcd7d76af5c1bd5c90859faa67a1ab2e6b8a93d4c111f48c3e4332",
    "latestLaboratoryQualification": "bc7dd0f87eaba4259f0170b4fb3d92d7dfccf315a16a027d423813b464cfddf9",
    "g1ApplicabilityReview": "f50ca355c2a981ac0f14a99dd7a911729563bd3754d153f6d38240822a7a591d",
    "runtimeImageQualification": "127fa1cbe4b04bef17d17890310adc498a7f2ceb0be5ea03e3a36c11bc1237ef",
    "licenceEvidence": "8a5081c0b4872ad66609d3598286bb4fa1042408a7b1bff0aca0c311c6f653b1",
    "dependencyLifecycleReview": "b2dcd6f7b599bb7659f11b02b36a3d5e8137ccd8698f27d8cda10adc84b08674",
}
WP_WEIGHTS = [4, 6, 8, 8, 8, 4, 4, 4]
WP_CREDITS = [50, 85, 60, 15, 35, 0, 0, 0]


def fail(code: str) -> None:
    raise ValueError(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        fail(code)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()
    return sha256(encoded)


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    require(isinstance(value, dict), "JSON_OBJECT_REQUIRED")
    return value, raw


def validate_documents(
    plan: dict[str, Any],
    lock: dict[str, Any],
    lock_bytes: bytes,
    cohort: dict[str, Any],
    dossiers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    require(plan.get("version") == "1.2", "PLAN_VERSION_1_2_REQUIRED")
    require(plan.get("date") == "2026-11-02", "HISTORICAL_PLAN_DATE_REQUIRED")
    require(plan.get("updatedAt") == "2026-11-03", "CURRENT_UPDATE_DATE_REQUIRED")
    require(
        plan.get("status")
        == "PRIVATE_PLAN_CAPTURED_452_TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED_TARGET_PENDING",
        "CURRENT_PLAN_STATUS_REQUIRED",
    )
    require(plan.get("historicalEvidenceFields") == HISTORICAL_FIELDS, "HISTORICAL_FIELDS_REQUIRED")
    for field, expected in HISTORICAL_CANONICAL_SHA256.items():
        require(canonical_sha256(plan.get(field)) == expected, "HISTORICAL_EVIDENCE_CHANGED")

    historical = plan.get("candidate", {})
    require(historical.get("initialVersionToEvaluate") == "4.51", "HISTORICAL_451_REQUIRED")
    require(
        historical.get("sourceCommit") == "153ab668c99731a6d29492bf6c61d0b4fa701101",
        "HISTORICAL_451_COMMIT_REQUIRED",
    )
    require(
        historical.get("patchedBuild", {}).get("acceptedApplicability", {}).get("decisionRef")
        == "urn:ouf:decision:OUF-SW-G1-20261102-01",
        "HISTORICAL_APPLICABILITY_DECISION_REQUIRED",
    )

    current = plan.get("currentQualification", {})
    require(current.get("candidateLock") == LOCK_PATH, "CURRENT_LOCK_PATH_REQUIRED")
    require(current.get("candidateLockSha256") == LOCK_SHA256, "CURRENT_LOCK_DIGEST_REQUIRED")
    require(sha256(lock_bytes) == LOCK_SHA256, "CANDIDATE_LOCK_BYTES_CHANGED")
    require(current.get("version") == "4.52", "CURRENT_VERSION_452_REQUIRED")
    require(current.get("upstreamCommit") == UPSTREAM_COMMIT, "CURRENT_UPSTREAM_COMMIT_REQUIRED")
    require(current.get("qualifiedImagePatchCount") == 15, "QUALIFIED_IMAGE_PATCH_COUNT_REQUIRED")
    require(current.get("repositoryPatchCount") == 20, "REPOSITORY_PATCH_COUNT_REQUIRED")
    require(current.get("qualificationRunId") == 41622752493, "QUALIFICATION_RUN_REQUIRED")
    require(current.get("vulnerabilitySubgate") == "PASS_RAW", "RAW_VULNERABILITY_PASS_REQUIRED")
    require(
        current.get("rawSeverityCounts")
        == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "ZERO_RAW_VULNERABILITY_FINDINGS_REQUIRED",
    )
    require(current.get("historicalApplicabilityApplied") is False, "NO_451_DISPOSITION_TRANSFER_REQUIRED")
    require(current.get("cohortReceipt") == COHORT_PATH, "CURRENT_COHORT_PATH_REQUIRED")
    require(current.get("cohortRunId") == 41627470213, "CURRENT_COHORT_RUN_REQUIRED")
    require(current.get("cohortContent") == "VERIFIED", "CURRENT_COHORT_CONTENT_REQUIRED")
    require(
        current.get("status") == "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED",
        "NOT_ADMITTED_COHORT_STATUS_REQUIRED",
    )
    require(current.get("awsSdkV1InQualifiedBinary") == "ABSENT", "SDK_V1_BINARY_ABSENCE_REQUIRED")
    require(
        current.get("deprecatedS3ManagerInQualifiedBinary") == "ABSENT",
        "DEPRECATED_MANAGER_BINARY_ABSENCE_REQUIRED",
    )
    require(current.get("remainingRepositoryDirectSdkV1Importers") == 21, "DIRECT_IMPORTER_COUNT_REQUIRED")
    require(current.get("remainingIamTestImporters") == 13, "IAM_IMPORTER_COUNT_REQUIRED")
    require(current.get("remainingOtherTestImporters") == 8, "OTHER_IMPORTER_COUNT_REQUIRED")
    require(current.get("testOnlyDossiers") == EXPECTED_DOSSIERS, "EXACT_TEST_DOSSIERS_REQUIRED")

    require(lock.get("version") == "4.52", "LOCK_VERSION_REQUIRED")
    require(lock.get("upstreamCommit") == UPSTREAM_COMMIT, "LOCK_UPSTREAM_REQUIRED")
    require(lock.get("orderedPatchCount") == 15, "LOCK_PATCH_COUNT_REQUIRED")
    require(lock.get("buildProfile", {}).get("binarySha256") == current.get("binarySha256"), "BINARY_BINDING_REQUIRED")
    require(lock.get("image", {}).get("manifestDigest") == current.get("ociManifestDigest"), "OCI_BINDING_REQUIRED")
    require(lock.get("qualification", {}).get("awsSdkV1") == "ABSENT", "LOCK_SDK_V1_ABSENCE_REQUIRED")
    require(lock.get("qualification", {}).get("deprecatedS3Manager") == "ABSENT", "LOCK_MANAGER_ABSENCE_REQUIRED")
    require(lock.get("qualification", {}).get("vulnerabilitySubgate") == "PASS_RAW", "LOCK_RAW_PASS_REQUIRED")
    require(lock.get("releaseAdmitted") is False, "LOCK_NOT_ADMITTED_REQUIRED")
    require(lock.get("runtimeAuthorityIssued") is False, "LOCK_NO_RUNTIME_AUTHORITY_REQUIRED")
    require(lock.get("targetOperations") == 0, "LOCK_ZERO_TARGET_OPERATIONS_REQUIRED")

    require(cohort.get("candidateLockSha256") == LOCK_SHA256, "COHORT_LOCK_BINDING_REQUIRED")
    require(cohort.get("cohortContent") == "VERIFIED", "COHORT_VERIFIED_REQUIRED")
    require(cohort.get("status") == "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED", "COHORT_NOT_ADMITTED_REQUIRED")
    require(cohort.get("binarySha256") == current.get("binarySha256"), "COHORT_BINARY_BINDING_REQUIRED")
    require(cohort.get("ociManifestDigest") == current.get("ociManifestDigest"), "COHORT_OCI_BINDING_REQUIRED")
    require(cohort.get("licenceEvidence", {}).get("rawUnknownClassifications") == 3, "THREE_LICENCE_UNKNOWNS_REQUIRED")
    require(cohort.get("licenceEvidence", {}).get("review") == "OPEN", "LICENCE_REVIEW_OPEN_REQUIRED")
    require(cohort.get("licenceEvidence", {}).get("redistributionAccepted") is False, "NO_REDISTRIBUTION_ACCEPTANCE_REQUIRED")
    require(cohort.get("durableImageCustody") == "OPEN", "DURABLE_CUSTODY_OPEN_REQUIRED")
    require(cohort.get("releaseAdmitted") is False, "COHORT_NOT_RELEASED_REQUIRED")
    require(cohort.get("runtimeAuthorityIssued") is False, "COHORT_NO_RUNTIME_AUTHORITY_REQUIRED")
    require(cohort.get("targetOperations") == 0, "COHORT_ZERO_TARGET_OPERATIONS_REQUIRED")

    expected_after = [25, 24, 23, 22, 21]
    for path, after in zip(EXPECTED_DOSSIERS, expected_after, strict=True):
        dossier = dossiers.get(path, {})
        require(dossier.get("upstreamCommit") == UPSTREAM_COMMIT, "DOSSIER_UPSTREAM_REQUIRED")
        require(dossier.get("directAwsSdkV1ImportersAfter") == after, "DOSSIER_IMPORTER_SEQUENCE_REQUIRED")
        require(dossier.get("workflow", {}).get("status") == "HOSTED_PASS", "HOSTED_PASS_REQUIRED")
        require(dossier.get("releaseAdmitted") is False, "DOSSIER_NOT_ADMITTED_REQUIRED")
        require(dossier.get("runtimeAuthorityIssued") is False, "DOSSIER_NO_RUNTIME_AUTHORITY_REQUIRED")
        require(dossier.get("targetOperations") == 0, "DOSSIER_ZERO_TARGET_OPERATIONS_REQUIRED")

    progress = plan.get("progressEstimate", {})
    weighted = sum(weight * credit / 100 for weight, credit in zip(WP_WEIGHTS, WP_CREDITS, strict=True))
    percent = weighted / sum(WP_WEIGHTS) * 100
    require(progress.get("creditsPercent") == WP_CREDITS, "PROGRESS_CREDITS_REQUIRED")
    require(math.isclose(progress.get("weightedCredits", -1), weighted, abs_tol=1e-12), "WEIGHTED_CREDITS_REQUIRED")
    require(
        math.isclose(progress.get("exactWeightedEstimatePercent", -1), percent, abs_tol=1e-12),
        "EXACT_PROGRESS_FORMULA_REQUIRED",
    )
    require(progress.get("reportedApproximatePercent") == 35, "REPORTED_PROGRESS_REQUIRED")
    require(progress.get("uncertaintyPercentagePoints") == 10, "PROGRESS_UNCERTAINTY_REQUIRED")
    require(progress.get("gatePass") == 0 and progress.get("gateTotal") == 8, "ZERO_OF_EIGHT_GATES_REQUIRED")
    require(
        progress.get("acceptanceTestPass") == 0 and progress.get("acceptanceTestTotal") == 21,
        "ZERO_OF_TWENTY_ONE_AT_REQUIRED",
    )
    require(
        progress.get("realObjectsCopied") == 0 and progress.get("realObjectTotal") == 120,
        "ZERO_OF_ONE_HUNDRED_TWENTY_OBJECTS_REQUIRED",
    )
    require(len(plan.get("workPackages", [])) == 8, "EIGHT_WORK_PACKAGES_REQUIRED")
    require(all(item.get("status") == "OPEN" for item in plan.get("workPackages", [])), "ALL_GATES_OPEN_REQUIRED")
    require(len(plan.get("acceptanceTests", [])) == 21, "TWENTY_ONE_ACCEPTANCE_TESTS_REQUIRED")
    require(all(item.get("status") == "OPEN" for item in plan.get("acceptanceTests", [])), "ALL_ACCEPTANCE_TESTS_OPEN_REQUIRED")

    require(plan.get("invariants", {}).get("consumedScopeCount") == 17, "SCOPE17_REQUIRED")
    require(plan.get("invariants", {}).get("cumulativeEngineGets") == 52, "ENGINE52_REQUIRED")
    require(plan.get("migrationPerformed") is False, "NO_MIGRATION_REQUIRED")
    require(plan.get("runtimeMutationsPerformed") is False, "NO_RUNTIME_MUTATIONS_REQUIRED")
    require(plan.get("targetApplyAuthorizedByThisPlan") is False, "NO_TARGET_APPLY_AUTHORITY_REQUIRED")
    require(plan.get("m2Accepted") is False, "M2_NOT_ACCEPTED_REQUIRED")
    require(current.get("licenceRawUnknownClassifications") == 3, "CURRENT_LICENCE_UNKNOWNS_REQUIRED")
    require(current.get("licenceReview") == "OPEN", "CURRENT_LICENCE_REVIEW_OPEN_REQUIRED")
    require(current.get("redistributionAccepted") is False, "CURRENT_NO_REDISTRIBUTION_ACCEPTANCE_REQUIRED")
    require(current.get("durableImageCustody") == "OPEN", "CURRENT_CUSTODY_OPEN_REQUIRED")
    require(current.get("overallSwG1") == "OPEN", "CURRENT_SW_G1_OPEN_REQUIRED")
    require(current.get("releaseAdmitted") is False, "CURRENT_NOT_ADMITTED_REQUIRED")
    require(current.get("runtimeAuthorityIssued") is False, "CURRENT_NO_RUNTIME_AUTHORITY_REQUIRED")
    require(current.get("targetOperations") == 0, "CURRENT_ZERO_TARGET_OPERATIONS_REQUIRED")
    require(current.get("activeStorageBackend") == "MinIO", "MINIO_MUST_REMAIN_ACTIVE")

    return {
        "schema": "ouf.storage-plan-current-verification.v1",
        "status": "PASS_NOT_ADMITTED",
        "candidateVersion": "4.52",
        "candidateLockSha256": LOCK_SHA256,
        "repositoryPatchCount": 20,
        "qualifiedImagePatchCount": 15,
        "remainingRepositoryDirectSdkV1Importers": 21,
        "progressPercent": percent,
        "gatesPassed": 0,
        "acceptanceTestsPassed": 0,
        "realObjectsCopied": 0,
        "targetOperations": 0,
        "releaseAdmitted": False,
        "runtimeAuthorityIssued": False,
        "activeStorageBackend": "MinIO",
    }


def validate_tree(root: Path) -> dict[str, Any]:
    plan, _ = read_json(root / PLAN_PATH)
    lock, lock_bytes = read_json(root / LOCK_PATH)
    cohort, _ = read_json(root / COHORT_PATH)
    dossiers = {path: read_json(root / path)[0] for path in EXPECTED_DOSSIERS}
    return validate_documents(plan, lock, lock_bytes, cohort, dossiers)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = validate_tree(args.root.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
