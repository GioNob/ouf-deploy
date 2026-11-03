#!/usr/bin/env python3
"""Fail-closed verifier for the current SeaweedFS qualification view.

The replacement plan intentionally retains the 4.51 evidence blocks as history.
This verifier binds the additive 4.52 view to the immutable candidate lock, the
hosted cohort receipt, the six historical test-only dossiers, the 27-patch source closure and the
28-patch standard-profile hosted receipt. Generation29 is current only through its exact image, hosted cohort and fresh
runtime receipts. Historical OCI15/SDK27/profile28 views remain immutable; old
MIME failure is preserved. Engineering credits remain unchanged at17.5/46,
and known dependency lifecycle residuals prevent a universal maintenance claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
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
    "evidence/seaweedfs-sdk-v1-iam-sts-signer-local-20261103.json",
]
SOURCE_CLOSURE_PATH = "evidence/seaweedfs-sdk27-hosted-20261103.json"
SOURCE_CLOSURE_HEAD = "70cd2671b41b0f775889826b2617811451a5e2ba"
PRODUCTION_GRAPH_SHA256 = "cb2536b10d73bc04e587c257a75a622c6b3cf855f1d232f26dba246b43b03f4a"
EXPECTED_SOURCE_PATCHES = {
    "patches/seaweedfs/4.52-bucket-policy-tests-sdk-v2.patch": "d97a3360ff974525d4e080f2fe7ec8344113cd2f9c27453289034d292a5a4e19",
    "patches/seaweedfs/4.52-normal-tests-sdk-v2.patch": "431f6dbcaf751ce447aa14cb3fb1d7386eb47733ea6b972a7d179dee7e715d9b",
    "patches/seaweedfs/4.52-iam-service-account-sdk-v2.patch": "bbbffe7b5a3ff2c5750b6dc974172b3e32de460abc50a6f69a7bc55f27b678b5",
    "patches/seaweedfs/4.52-kafka-test-module-remove-sdk-v1.patch": "11a1ed01867dcba555389ec82e2f65d6b188dc23a97419ed5bfcfbccb2cc27a7",
    "patches/seaweedfs/4.52-root-iam-tests-sdk-v2.patch": "f3fc1c0c20b04c4885efd0ce747fad2d52822116510379e0c337a5ba73d6b883",
    "patches/seaweedfs/4.52-iam-module-sdk-v2.patch": "7d1fb3c4f47ea82be66fe7794793534079cf56f1d0e42ea1a87211ea3abc869a",
}
EXPECTED_HOSTED_WORKFLOWS = {
    "storage-bucket-policy-tests-sdk-v2",
    "storage-normal-tests-sdk-v2",
    "storage-iam-service-account-sdk-v2",
    "storage-kafka-module-cleanup",
    "storage-root-iam-tests-sdk-v2",
    "storage-iam-module-sdk-v2",
}
OPTIONAL_MODULE_LIMITS = {
    "moduleGraphEradicationClaimed": False,
    "excludedBuildTags": ["elastic", "rclone"],
    "qualificationScope": "OUF_STANDARD_WITHOUT_ELASTIC_OR_RCLONE",
    "rootStandardModuleGraphSdkV1": 0,
    "rootStandardModuleGraphDeprecatedS3Manager": 0,
    "remainingNestedKafkaModulesQualified": False,
    "liveIamRoundtripPerformed": False,
}
STANDARD_RECEIPT_PATH = "evidence/seaweedfs-ouf-standard-module-closure-hosted-20261103.json"
STANDARD_HEAD = "24e96bb5e875a4c0b5c17aed2653e0bd14bd05be"
STANDARD_RUN = 41691297148
STANDARD_PATCH_PATH = "patches/seaweedfs/4.52-ouf-standard-optional-closure.patch"
STANDARD_PATCH_SHA256 = "b8387b32bfcb1f8bb7f4cb30d781c5035a6a46b1a82c6a655e318cf794f2bf79"
STANDARD_EVIDENCE_DIR = "evidence/storage-ouf-standard-41691297148"
MIME_DEFECT_PATH = "evidence/seaweedfs-452-cold-recovery-mime-failed-20261103.json"
MIME_DEFECT_RUN = 41691296882
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
WP_CREDITS = [50, 85, 60, 35, 35, 0, 0, 0]
COLD_RECEIPT_PATH = "evidence/seaweedfs-452-cold-recovery-hosted-20261103.json"
COLD_RECEIPT_SHA256 = "2cb1ae3c6ca67f58bac1ac5b48a7c2db934f26ee033098d3cf82571de313fa6c"
COLD_EVIDENCE_DIR = "evidence/seaweedfs-452-cold-recovery-hosted-20261103"
IMAGE29_RECEIPT_PATH = "evidence/seaweedfs-452-generation29-image-hosted-20261103.json"
IMAGE29_RECEIPT_SHA256 = "9b6ff3d19e18d9c20d1577c32744a3a4e4b2ae0a66a5d0940ca713f9a17057c8"
IMAGE29_MANIFEST_PATH = "releases/seaweedfs-452-generation29-build-manifest-20261103.json"
IMAGE29_MANIFEST_SHA256 = "cddbcd4f40c13cb8e86d49d9bf30dc85109aeb3fa50334d92c4690e622d952c9"


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


def validate_source_closure(
    current: dict[str, Any],
    receipt: dict[str, Any],
    receipt_bytes: bytes,
    patch_hashes: dict[str, str],
) -> None:
    require(current.get("sourceClosureReceipt") == SOURCE_CLOSURE_PATH, "SOURCE_CLOSURE_RECEIPT_PATH_REQUIRED")
    require(current.get("sourceClosureReceiptSha256") == sha256(receipt_bytes), "SOURCE_CLOSURE_RECEIPT_HASH_MISMATCH")
    require(current.get("sourceClosureHead") == SOURCE_CLOSURE_HEAD, "SOURCE_CLOSURE_HEAD_REQUIRED")
    require(current.get("sourceClosureStatus") == "HOSTED_PASS", "SOURCE_CLOSURE_HOSTED_PASS_REQUIRED")
    require(current.get("optionalModuleDependencyLimits") == OPTIONAL_MODULE_LIMITS, "OPTIONAL_MODULE_LIMITS_REQUIRED")
    require(receipt.get("schemaVersion") == 1, "SOURCE_RECEIPT_SCHEMA_REQUIRED")
    require(receipt.get("status") == "HOSTED_PASS", "SOURCE_RECEIPT_HOSTED_PASS_REQUIRED")
    require(receipt.get("sourceHead") == SOURCE_CLOSURE_HEAD, "SOURCE_RECEIPT_HEAD_REQUIRED")
    require(receipt.get("upstreamCommit") == UPSTREAM_COMMIT, "SOURCE_RECEIPT_UPSTREAM_REQUIRED")
    require(receipt.get("patchCount") == 27, "SOURCE_RECEIPT_PATCH27_REQUIRED")
    require(receipt.get("candidateLockSha256") == LOCK_SHA256, "SOURCE_RECEIPT_LOCK_REQUIRED")
    require(receipt.get("patchHashes") == EXPECTED_SOURCE_PATCHES, "SOURCE_RECEIPT_PATCH_HASHES_REQUIRED")
    require(patch_hashes == EXPECTED_SOURCE_PATCHES, "SOURCE_PATCH_BYTES_CHANGED")
    require(receipt.get("directSourceImporters") == 0, "SOURCE_RECEIPT_ZERO_IMPORTERS_REQUIRED")
    limits = receipt.get("limits", {})
    require(receipt.get("optionalModuleGraphEradicationClaimed") is False, "SOURCE_RECEIPT_MODULE_LIMIT_REQUIRED")
    require(limits.get("optionalBuildTagsStillOpen") == ["elastic", "rclone"], "SOURCE_RECEIPT_OPTIONAL_TAGS_REQUIRED")
    require(limits.get("remainingNestedKafkaModulesQualified") is False, "SOURCE_RECEIPT_NESTED_KAFKA_LIMIT_REQUIRED")
    require(limits.get("liveIamRoundtripPerformed") is False, "SOURCE_RECEIPT_LIVE_IAM_LIMIT_REQUIRED")
    require(limits.get("releaseAdmitted") is False, "SOURCE_RECEIPT_NOT_ADMITTED_REQUIRED")
    require(limits.get("runtimeAuthorityIssued") is False, "SOURCE_RECEIPT_NO_AUTHORITY_REQUIRED")
    require(limits.get("targetOperations") == 0, "SOURCE_RECEIPT_ZERO_TARGET_REQUIRED")
    require(limits.get("consumedScopeCount") == 17, "SOURCE_RECEIPT_SCOPE17_REQUIRED")
    require(limits.get("cumulativeEngineGets") == 52, "SOURCE_RECEIPT_ENGINE52_REQUIRED")
    binary = receipt.get("qualifiedBinary", {})
    require(binary.get("sha256") == current.get("binarySha256"), "SOURCE_RECEIPT_BINARY_REQUIRED")
    require(binary.get("byteIdentical") is True, "SOURCE_RECEIPT_BINARY_IDENTITY_REQUIRED")
    require(binary.get("productionGraphCount") == 1811, "SOURCE_RECEIPT_PRODUCTION_GRAPH_COUNT_REQUIRED")
    require(binary.get("productionGraphSha256") == PRODUCTION_GRAPH_SHA256, "SOURCE_RECEIPT_PRODUCTION_GRAPH_HASH_REQUIRED")
    workflows = receipt.get("workflows", [])
    require(isinstance(workflows, list) and len(workflows) == 6, "SIX_HOSTED_WORKFLOWS_REQUIRED")
    require(all(isinstance(w, dict) for w in workflows), "HOSTED_WORKFLOW_OBJECT_REQUIRED")
    require({w.get("name") for w in workflows} == EXPECTED_HOSTED_WORKFLOWS, "EXACT_HOSTED_WORKFLOW_SET_REQUIRED")
    run_ids, job_ids, artifact_ids = set(), set(), set()
    for workflow in workflows:
        require(workflow.get("conclusion") == "success", "ALL_HOSTED_RUNS_SUCCESS_REQUIRED")
        require(workflow.get("headSha") == SOURCE_CLOSURE_HEAD, "HOSTED_RUN_SOURCE_HEAD_REQUIRED")
        require(workflow.get("workflowPath") == ".github/workflows/" + workflow["name"] + ".yml", "HOSTED_WORKFLOW_PATH_REQUIRED")
        if workflow["name"] == "storage-kafka-module-cleanup":
            require(workflow.get("directImporters") is None, "KAFKA_GLOBAL_SCAN_NOT_CLAIMED")
        else:
            require(workflow.get("directImporters") == 0, "HOSTED_RUN_ZERO_IMPORTERS_REQUIRED")
        for key, seen in (("runId", run_ids), ("jobId", job_ids)):
            value = workflow.get(key)
            require(type(value) is int and value > 0 and value not in seen, "UNIQUE_HOSTED_RUN_AND_JOB_IDS_REQUIRED")
            seen.add(value)
        artifact = workflow.get("artifact", {})
        artifact_id = artifact.get("id")
        require(type(artifact_id) is int and artifact_id > 0 and artifact_id not in artifact_ids, "UNIQUE_HOSTED_ARTIFACT_IDS_REQUIRED")
        artifact_ids.add(artifact_id)
        require(artifact.get("downloadVerified") is True, "HOSTED_ARTIFACT_DOWNLOAD_VERIFIED_REQUIRED")
        require(isinstance(artifact.get("name"), str) and artifact["name"], "HOSTED_ARTIFACT_NAME_REQUIRED")
        require(bool(re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", "")))), "HOSTED_ARTIFACT_SHA256_REQUIRED")
        require(bool(re.fullmatch(r"[0-9a-f]{64}", str(workflow.get("manifestSha256", "")))), "HOSTED_MANIFEST_SHA256_REQUIRED")
        manifest = workflow.get("fileManifest", [])
        require(isinstance(manifest, list) and len(manifest) > 0, "HOSTED_FILE_MANIFEST_REQUIRED")
        require(workflow.get("manifestEntriesVerified") == len(manifest), "HOSTED_MANIFEST_VERIFICATION_REQUIRED")
        require(all(isinstance(f, dict) and isinstance(f.get("file"), str) for f in manifest), "HOSTED_MANIFEST_FILE_REQUIRED")
        files = {f["file"]: f for f in manifest}
        require(len(files) == len(manifest), "HOSTED_MANIFEST_FILES_UNIQUE_REQUIRED")
        if workflow["name"] != "storage-kafka-module-cleanup":
            empty_scan = files.get("remaining-direct-importers.txt", {})
            require(empty_scan.get("size") == 0 and empty_scan.get("sha256") == sha256(b""), "HOSTED_EMPTY_IMPORTER_SCAN_REQUIRED")
        graphs = workflow.get("dependencyGraphs", [])
        require(isinstance(graphs, list) and len(graphs) > 0, "HOSTED_DEPENDENCY_GRAPHS_REQUIRED")
        for graph in graphs:
            require(isinstance(graph, dict), "HOSTED_DEPENDENCY_GRAPH_OBJECT_REQUIRED")
            require(type(graph.get("packageCount")) is int and graph["packageCount"] > 0, "HOSTED_DEPENDENCY_GRAPH_COUNT_REQUIRED")
            require(graph.get("sdkV1Packages") == 0, "HOSTED_DEPENDENCY_GRAPH_NO_SDKV1_REQUIRED")
            require(graph.get("sha256") == files.get(graph.get("file"), {}).get("sha256") and bool(re.fullmatch(r"[0-9a-f]{64}", str(graph.get("sha256", "")))), "HOSTED_DEPENDENCY_GRAPH_MANIFEST_BINDING_REQUIRED")


def validate_documents(
    plan: dict[str, Any],
    lock: dict[str, Any],
    lock_bytes: bytes,
    cohort: dict[str, Any],
    dossiers: dict[str, dict[str, Any]],
    source_receipt: dict[str, Any],
    source_receipt_bytes: bytes,
    patch_hashes: dict[str, str],
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
    require(current.get("repositoryPatchCount") == 28, "REPOSITORY_PATCH_COUNT_REQUIRED")
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
    require(current.get("remainingRepositoryDirectSdkV1Importers") == 0, "DIRECT_IMPORTER_COUNT_REQUIRED")
    require(current.get("remainingIamTestImporters") == 0, "IAM_IMPORTER_COUNT_REQUIRED")
    require(current.get("remainingOtherTestImporters") == 0, "OTHER_IMPORTER_COUNT_REQUIRED")
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

    expected_after = [25, 24, 23, 22, 21, 20]
    for path, after in zip(EXPECTED_DOSSIERS, expected_after, strict=True):
        dossier = dossiers.get(path, {})
        require(dossier.get("upstreamCommit") == UPSTREAM_COMMIT, "DOSSIER_UPSTREAM_REQUIRED")
        require(dossier.get("directAwsSdkV1ImportersAfter") == after, "DOSSIER_IMPORTER_SEQUENCE_REQUIRED")
        require(dossier.get("workflow", {}).get("status") == "HOSTED_PASS", "HOSTED_PASS_REQUIRED")
        require(dossier.get("releaseAdmitted") is False, "DOSSIER_NOT_ADMITTED_REQUIRED")
        require(dossier.get("runtimeAuthorityIssued") is False, "DOSSIER_NO_RUNTIME_AUTHORITY_REQUIRED")
        require(dossier.get("targetOperations") == 0, "DOSSIER_ZERO_TARGET_OPERATIONS_REQUIRED")

    validate_source_closure(current, source_receipt, source_receipt_bytes, patch_hashes)
    resolved = plan.get("pendingRepositoryQualification", {})
    require(resolved.get("patchCount") == 27 and resolved.get("status") == "COMPLETED_HOSTED_PASS", "PENDING_QUALIFICATION_RESOLVED_REQUIRED")
    require(resolved.get("resolvedBy") == SOURCE_CLOSURE_PATH, "PENDING_QUALIFICATION_RECEIPT_REQUIRED")
    require(resolved.get("currentQualificationRetainedUntilHostedPass") is True, "HOSTED_PROMOTION_CONDITION_PRESERVED_REQUIRED")

    progress = plan.get("progressEstimate", {})
    weighted = sum(weight * credit / 100 for weight, credit in zip(WP_WEIGHTS, WP_CREDITS, strict=True))
    percent = weighted / sum(WP_WEIGHTS) * 100
    require(progress.get("creditsPercent") == WP_CREDITS, "PROGRESS_CREDITS_REQUIRED")
    require(math.isclose(progress.get("weightedCredits", -1), weighted, abs_tol=1e-12), "WEIGHTED_CREDITS_REQUIRED")
    require(
        math.isclose(progress.get("exactWeightedEstimatePercent", -1), percent, abs_tol=1e-12),
        "EXACT_PROGRESS_FORMULA_REQUIRED",
    )
    require(progress.get("reportedApproximatePercent") == 38, "REPORTED_PROGRESS_REQUIRED")
    credit = progress.get("creditChange", {})
    require(credit.get("workPackage") == "SW-WP3" and credit.get("previousCreditPercent") == 15 and credit.get("currentCreditPercent") == 35, "COLD_PROGRESS_CREDIT_CHANGE_REQUIRED")
    require(credit.get("receipt") == COLD_RECEIPT_PATH and credit.get("receiptSha256") == COLD_RECEIPT_SHA256, "COLD_PROGRESS_EVIDENCE_REQUIRED")
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
        "repositoryPatchCount": 28,
        "qualifiedImagePatchCount": 15,
        "sourceClosureReceiptSha256": sha256(source_receipt_bytes),
        "hostedSourceClosureRunCount": 6,
        "optionalModuleGraphEradicationClaimed": False,
        "remainingRepositoryDirectSdkV1Importers": 0,
        "progressPercent": percent,
        "gatesPassed": 0,
        "acceptanceTestsPassed": 0,
        "realObjectsCopied": 0,
        "targetOperations": 0,
        "releaseAdmitted": False,
        "runtimeAuthorityIssued": False,
        "activeStorageBackend": "MinIO",
    }


def validate_archived_workflow(workflow: dict[str, Any], archived: dict[str, bytes]) -> None:
    manifest_bytes = archived.get("SHA256SUMS")
    require(isinstance(manifest_bytes, bytes), "ARCHIVED_MANIFEST_REQUIRED")
    require(sha256(manifest_bytes) == workflow.get("manifestSha256"), "ARCHIVED_MANIFEST_HASH_MISMATCH")
    declared = {}
    for line in manifest_bytes.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](?:\./)?([^/\\]+)", line)
        require(match is not None, "ARCHIVED_MANIFEST_FORMAT_REQUIRED")
        digest, name = match.groups()
        require(name not in (".", "..", "SHA256SUMS") and name not in declared, "ARCHIVED_MANIFEST_MEMBER_INVALID")
        declared[name] = digest
    receipt_members = {entry["file"]: entry for entry in workflow["fileManifest"]}
    require(declared == {name: entry["sha256"] for name, entry in receipt_members.items()}, "ARCHIVED_MANIFEST_RECEIPT_MISMATCH")
    require(set(archived) == set(receipt_members) | {"SHA256SUMS"}, "ARCHIVED_EVIDENCE_MEMBER_SET_REQUIRED")
    for name, entry in receipt_members.items():
        raw = archived[name]
        require(isinstance(raw, bytes) and len(raw) == entry["size"], "ARCHIVED_EVIDENCE_SIZE_MISMATCH")
        require(sha256(raw) == entry["sha256"], "ARCHIVED_EVIDENCE_HASH_MISMATCH")


def validate_archived_tree(root: Path, receipt: dict[str, Any]) -> None:
    for workflow in receipt["workflows"]:
        run_id = workflow["runId"]
        require(type(run_id) is int and run_id > 0, "ARCHIVED_RUN_ID_REQUIRED")
        directory = root / "evidence/sdk27-artifacts" / str(run_id)
        require(directory.is_dir() and not directory.is_symlink() and directory.resolve().is_relative_to(root.resolve()), "ARCHIVED_EVIDENCE_DIRECTORY_REQUIRED")
        archived = {}
        names = ["SHA256SUMS"] + [entry["file"] for entry in workflow["fileManifest"]]
        for name in names:
            require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None and name not in (".", ".."), "ARCHIVED_EVIDENCE_PATH_INVALID")
            path = directory / name
            require(path.is_file() and not path.is_symlink(), "ARCHIVED_EVIDENCE_FILE_REQUIRED")
            archived[name] = path.read_bytes()
        validate_archived_workflow(workflow, archived)


def validate_standard_profile(
    plan: dict[str, Any], receipt: dict[str, Any], receipt_bytes: bytes,
    patch_sha256: str, defect: dict[str, Any], defect_bytes: bytes,
) -> None:
    current = plan["currentQualification"]
    profile = current.get("standardProfileQualification", {})
    require(profile.get("status") == "HOSTED_PASS", "STANDARD_PROFILE_HOSTED_PASS_REQUIRED")
    require(profile.get("profile") == "OUF_STANDARD_WITHOUT_ELASTIC_OR_RCLONE", "STANDARD_PROFILE_SCOPE_REQUIRED")
    require(profile.get("excludedBuildTags") == ["elastic", "rclone"], "STANDARD_EXCLUSIONS_REQUIRED")
    require(profile.get("universalUpstreamModuleClosureClaimed") is False, "NO_UNIVERSAL_MODULE_CLOSURE_REQUIRED")
    require(profile.get("receipt") == STANDARD_RECEIPT_PATH and profile.get("receiptSha256") == sha256(receipt_bytes), "STANDARD_RECEIPT_BINDING_REQUIRED")
    require(profile.get("sourceHead") == STANDARD_HEAD and profile.get("runId") == STANDARD_RUN, "STANDARD_SOURCE_RUN_BINDING_REQUIRED")
    require(profile.get("orderedPatchCount") == 28 and profile.get("qualifiedImagePatchCount") == 15, "STANDARD_PATCH_COUNTS_REQUIRED")
    require(profile.get("patch") == STANDARD_PATCH_PATH and profile.get("patchSha256") == STANDARD_PATCH_SHA256 and patch_sha256 == STANDARD_PATCH_SHA256, "STANDARD_PATCH28_BINDING_REQUIRED")
    for field in ("rootModuleGraphSdkV1", "rootModuleGraphDeprecatedS3Manager"):
        require(profile.get(field) == 0, "STANDARD_MODULE_ZERO_UNMAINTAINED_REQUIRED")
    require(profile.get("qualifiedBinaryByteIdentical") is True, "STANDARD_BINARY_IDENTITY_REQUIRED")
    require(receipt.get("status") == "HOSTED_PASS_ARTIFACT_BYTES_VERIFIED" and receipt.get("jobConclusion") == "success", "STANDARD_HOSTED_SUCCESS_REQUIRED")
    require(receipt.get("headSha") == STANDARD_HEAD and receipt.get("runId") == STANDARD_RUN, "STANDARD_RECEIPT_SOURCE_RUN_REQUIRED")
    require(receipt.get("jobId") == 126110264320, "STANDARD_JOB_REQUIRED")
    steps = receipt.get("steps", [])
    require(len(steps) == 16 and all(step.get("status") == "completed" and step.get("conclusion") == "success" for step in steps), "STANDARD_ALL_STEPS_SUCCESS_REQUIRED")
    verification = receipt.get("verification", {})
    require(verification.get("status") == "ARTIFACT_BYTES_VERIFIED", "STANDARD_BYTES_VERIFIED_REQUIRED")
    for field in ("sdkV1RootModuleGraph", "deprecatedManagerRootModuleGraph", "sdkV1DirectSourceImporters"):
        require(verification.get(field) == 0, "STANDARD_VERIFIED_CLOSURE_REQUIRED")
    patches = verification.get("patches", [])
    require(len(patches) == 28 and patches[-1] == {"path": STANDARD_PATCH_PATH, "sha256": STANDARD_PATCH_SHA256}, "STANDARD_VERIFIED_PATCH28_REQUIRED")
    require(verification.get("negativeBuildTags") == ["elastic", "rclone", "elastic,rclone"], "STANDARD_TAG_DENIALS_REQUIRED")
    require(verification.get("tidyRootAndKafkaFixedPoint") is True, "STANDARD_TIDY_FIXED_POINT_REQUIRED")
    require(verification.get("productionPackages") == 1811 and verification.get("productionGraphSha256") == PRODUCTION_GRAPH_SHA256, "STANDARD_PRODUCTION_GRAPH_REQUIRED")
    require(verification.get("binarySha256") == current["binarySha256"], "STANDARD_PRODUCTION_BINARY_REQUIRED")
    require(receipt.get("artifact", {}).get("githubDigest") == "sha256:" + receipt.get("artifact", {}).get("zipSha256", ""), "STANDARD_ARCHIVE_DIGEST_BINDING_REQUIRED")
    require(receipt.get("attestation", {}).get("subjectSha256") == verification.get("manifestSha256"), "STANDARD_ATTESTED_MANIFEST_BINDING_REQUIRED")
    require(receipt.get("retainedBoundedEvidence", {}).get("directory") == STANDARD_EVIDENCE_DIR, "STANDARD_RETAINED_DIRECTORY_REQUIRED")
    pending = plan.get("pendingStandardProfileQualification", {})
    require(pending.get("status") == "COMPLETED_HOSTED_PASS" and pending.get("resolvedBy") == STANDARD_RECEIPT_PATH, "STANDARD_PENDING_RESOLVED_REQUIRED")
    require(pending.get("currentQualificationRetainedUntilHostedPass") is True, "STANDARD_HOSTED_PROMOTION_CONDITION_REQUIRED")

    defects = current.get("knownCompatibilityDefects", [])
    require(len(defects) == 1, "KNOWN_MIME_DEFECT_REQUIRED")
    recorded = defects[0]
    require(recorded.get("code") == "CONTENT_TYPE_MISMATCH" and recorded.get("status") == "OPEN", "MIME_DEFECT_OPEN_REQUIRED")
    require(recorded.get("receipt") == MIME_DEFECT_PATH and recorded.get("receiptSha256") == sha256(defect_bytes), "MIME_DEFECT_RECEIPT_BINDING_REQUIRED")
    require(recorded.get("runId") == MIME_DEFECT_RUN, "MIME_DEFECT_RUN_REQUIRED")
    require(recorded.get("failingObjectKey") is None and recorded.get("actualResponseContentType") is None, "MIME_UNOBSERVED_VALUES_MUST_REMAIN_UNKNOWN")
    require(recorded.get("s3MetadataCompatibilityQualified") is False, "MIME_COMPATIBILITY_NOT_QUALIFIED_REQUIRED")
    require(defect.get("runId") == MIME_DEFECT_RUN and defect.get("sourceCommit") == STANDARD_HEAD, "MIME_RECEIPT_SOURCE_RUN_REQUIRED")
    require(defect.get("candidateLockSha256") == LOCK_SHA256 and defect.get("binarySha256") == current["binarySha256"] and defect.get("ociManifestDigest") == current["ociManifestDigest"], "MIME_RECEIPT_CANDIDATE_BINDING_REQUIRED")
    observed = defect.get("observed", {})
    require(observed.get("childException") == "RuntimeError: CONTENT_TYPE_MISMATCH" and observed.get("failedOperation") == "GET_CONTENT_TYPE_COMPARISON", "MIME_OBSERVED_FAILURE_REQUIRED")
    require(observed.get("seedComplete") is False and observed.get("backupExecuted") is False and observed.get("restoreExecuted") is False, "MIME_FAILED_RUN_NO_RESTORE_REQUIRED")
    require(defect.get("diagnosis", {}).get("compatibilityResolved") is False and defect.get("g2Closed") is False, "MIME_DEFECT_UNRESOLVED_REQUIRED")
    correction = current.get("pendingCompatibilityCorrection", {})
    require(correction == {"orderedPatchCount": 29, "status": "NOT_QUALIFIED", "requiresNewImageQualification": True, "candidateLockUnchanged": True}, "PRODUCTION_PATCH29_NOT_PROMOTED_REQUIRED")


def validate_standard_evidence(receipt: dict[str, Any], archived: dict[str, bytes]) -> None:
    expected = receipt["retainedBoundedEvidence"]["files"]
    require(set(archived) == set(expected), "STANDARD_EVIDENCE_MEMBER_SET_REQUIRED")
    for name, entry in expected.items():
        require(isinstance(archived[name], bytes) and len(archived[name]) == entry["bytes"] and sha256(archived[name]) == entry["sha256"], "STANDARD_EVIDENCE_BYTES_MISMATCH")
    declared = {}
    for line in archived["BOUNDED_SHA256SUMS"].decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        require(match is not None, "STANDARD_BOUNDED_MANIFEST_FORMAT_REQUIRED")
        digest, name = match.groups()
        require(name not in declared and name not in (".", "..", "BOUNDED_SHA256SUMS"), "STANDARD_BOUNDED_MANIFEST_MEMBER_INVALID")
        declared[name] = digest
    require(declared == {name: entry["sha256"] for name, entry in expected.items() if name != "BOUNDED_SHA256SUMS"}, "STANDARD_BOUNDED_MANIFEST_BINDING_REQUIRED")
    require(sha256(archived["original-artifact-SHA256SUMS"]) == receipt["verification"]["manifestSha256"], "STANDARD_ORIGINAL_MANIFEST_BINDING_REQUIRED")
    require(archived["upstream-source-sha.txt"].decode("ascii").strip() == UPSTREAM_COMMIT, "STANDARD_RAW_UPSTREAM_BINDING_REQUIRED")
    patch_lines = archived["patches-sha256.txt"].decode("utf-8").splitlines()
    expected_patch_lines = [entry["sha256"] + "  ../" + entry["path"] for entry in receipt["verification"]["patches"]]
    require(patch_lines == expected_patch_lines, "STANDARD_RAW_PATCH_SEQUENCE_BINDING_REQUIRED")
    require(sha256(archived["production-deps.txt"]) == PRODUCTION_GRAPH_SHA256, "STANDARD_RAW_PRODUCTION_GRAPH_REQUIRED")
    binary_line = archived["binary-sha256.txt"].decode("utf-8").split()
    require(len(binary_line) == 2 and binary_line[0] == receipt["verification"]["binarySha256"], "STANDARD_RAW_BINARY_BINDING_REQUIRED")
    graph = archived["root-module-graph.txt"].decode("utf-8")
    modules = archived["root-modules.txt"].decode("utf-8")
    require(re.search(r"github\.com/aws/(?:aws-sdk-go@|aws-sdk-go-v2/feature/s3/manager@)", graph) is None, "STANDARD_RAW_GRAPH_UNMAINTAINED_DEPENDENCY")
    require(re.search(r"(?m)^github\.com/aws/(?:aws-sdk-go|aws-sdk-go-v2/feature/s3/manager)\s", modules) is None, "STANDARD_RAW_MODULES_UNMAINTAINED_DEPENDENCY")
    require(archived["tidy.diff"] == b"" and archived["kafka-tidy.diff"] == b"" and archived["remaining-direct-sdk-v1-importers.txt"] == b"", "STANDARD_RAW_FIXED_POINT_AND_SOURCE_CLOSURE_REQUIRED")


def read_standard_evidence(root: Path, receipt: dict[str, Any]) -> dict[str, bytes]:
    directory = root / STANDARD_EVIDENCE_DIR
    require(directory.is_dir() and not directory.is_symlink() and directory.resolve().is_relative_to(root.resolve()), "STANDARD_EVIDENCE_DIRECTORY_REQUIRED")
    archived = {}
    for name in receipt["retainedBoundedEvidence"]["files"]:
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None and name not in (".", ".."), "STANDARD_EVIDENCE_PATH_INVALID")
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "STANDARD_EVIDENCE_FILE_REQUIRED")
        archived[name] = path.read_bytes()
    return archived


def read_cold_evidence(root: Path, receipt: dict[str, Any]) -> dict[str, bytes]:
    preserved = receipt.get("rawEvidencePreservation", {})
    require(preserved.get("repositoryDirectory") == COLD_EVIDENCE_DIR, "COLD_EVIDENCE_DIRECTORY_REQUIRED")
    directory = root / COLD_EVIDENCE_DIR
    require(directory.is_dir() and not directory.is_symlink() and directory.resolve().is_relative_to(root.resolve()), "COLD_EVIDENCE_DIRECTORY_REQUIRED")
    archived = {}
    files = preserved.get("files", [])
    require(isinstance(files, list) and len(files) == 31, "COLD_31_MEMBERS_REQUIRED")
    for item in files:
        name = item.get("path", "")
        require(isinstance(name, str) and name.startswith(COLD_EVIDENCE_DIR + "/"), "COLD_EVIDENCE_PATH_INVALID")
        member = name.removeprefix(COLD_EVIDENCE_DIR + "/")
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", member) is not None and member not in (".", ".."), "COLD_EVIDENCE_PATH_INVALID")
        require(member not in archived, "COLD_EVIDENCE_DUPLICATE")
        path = directory / member
        require(path.is_file() and not path.is_symlink(), "COLD_EVIDENCE_FILE_REQUIRED")
        archived[member] = path.read_bytes()
    return archived


def validate_cold_evidence(
    plan: dict[str, Any], receipt: dict[str, Any], receipt_bytes: bytes,
    archived: dict[str, bytes],
) -> None:
    require(sha256(receipt_bytes) == COLD_RECEIPT_SHA256, "COLD_RECEIPT_BYTES_CHANGED")
    require(json.loads(receipt_bytes) == receipt, "COLD_RECEIPT_OBJECT_BYTES_MISMATCH")
    view = plan.get("historicalRuntimeQualification", {}).get("coldRecovery15", {})
    require(view.get("receipt") == COLD_RECEIPT_PATH and view.get("receiptSha256") == COLD_RECEIPT_SHA256, "COLD_RECEIPT_BINDING_REQUIRED")
    require(view.get("status") == "HOSTED_SYNTHETIC_COLD_RESTORE_PASS_MIME_FAIL_NOT_ACCEPTANCE", "COLD_STATUS_REQUIRED")
    require(view.get("runId") == receipt.get("runId") == 41696541366, "COLD_RUN_REQUIRED")
    require(view.get("sourceCommit") == receipt.get("sourceCommit") == "041992eacd851d277cd049f03b9fe68a393e6df4", "COLD_SOURCE_REQUIRED")
    require(view.get("orderedImagePatchCount") == 15 and view.get("transferredToGeneration29") is False, "COLD_GENERATION15_ONLY_REQUIRED")
    result = receipt["hostedResult"]
    current = plan["currentQualification"]
    for key in ("candidateLockSha256", "binarySha256", "ociManifestDigest"):
        require(view.get(key) == result.get(key) == current.get(key), "COLD_CANDIDATE15_BINDING_REQUIRED")
    require(result.get("status") == "SYNTHETIC_STORAGE_COLD_RESTORE_PASS_NOT_ACCEPTANCE", "COLD_HOSTED_PASS_REQUIRED")
    for key in ("syntheticObjects", "syntheticBytes", "backupFiles"):
        require(view.get(key) == result.get(key), "COLD_MEASUREMENT_BINDING_REQUIRED")
    readback = receipt["independentReadback"]
    require(view.get("backupBytes") == readback.get("backupBytes"), "COLD_MEASUREMENT_BINDING_REQUIRED")
    for key in ("eightDistinctContainerIdentities", "allExitCodesZero"):
        require(view.get(key) is True and readback.get(key) is True, "COLD_INDEPENDENT_RESTORE_REQUIRED")
    require(view.get("octetStreamCompatibility") == result.get("octetStreamCompatibility", {}).get("status") == "FAIL", "COLD_MIME_DEFECT_MUST_REMAIN_FAIL")
    for key in ("g2Closed", "g3Closed", "fullFoundationBackupContractSatisfied", "rpoAcceptance", "rtoAcceptance", "releaseAdmitted", "runtimeAuthorityIssued"):
        require(view.get(key) is False, "COLD_NO_ACCEPTANCE_OR_AUTHORITY_REQUIRED")
    require(view.get("targetOperations") == 0 and view.get("postgresRecovery") == "NOT_TESTED", "COLD_NO_TARGET_OR_POSTGRES_CLAIM_REQUIRED")
    expected = {item["path"].removeprefix(COLD_EVIDENCE_DIR + "/"): item for item in receipt["rawEvidencePreservation"]["files"]}
    require(set(archived) == set(expected), "COLD_EVIDENCE_MEMBER_SET_REQUIRED")
    for name, item in expected.items():
        require(len(archived[name]) == item["bytes"] and sha256(archived[name]) == item["sha256"], "COLD_EVIDENCE_BYTES_MISMATCH")
    manifest = {}
    for line in archived["SHA256SUMS"].decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](?:\./)?([A-Za-z0-9_.-]+)", line)
        require(match is not None, "COLD_MANIFEST_FORMAT_REQUIRED")
        digest, name = match.groups()
        require(name not in manifest and name not in (".", "..", "SHA256SUMS"), "COLD_MANIFEST_MEMBER_INVALID")
        manifest[name] = digest
    require(len(manifest) == 30 and manifest == {name: item["sha256"] for name, item in expected.items() if name != "SHA256SUMS"}, "COLD_MANIFEST_BINDING_REQUIRED")
    require(json.loads(archived["recovery-result.json"]) == result, "COLD_RAW_RESULT_BINDING_REQUIRED")
    require(json.loads(archived["exact-image.json"]) == receipt["exactImage"], "COLD_RAW_IMAGE_BINDING_REQUIRED")


def validate_generation29_image(
    plan: dict[str, Any], receipt: dict[str, Any], receipt_bytes: bytes,
    build_manifest_bytes: bytes,
) -> None:
    require(sha256(receipt_bytes) == IMAGE29_RECEIPT_SHA256 and json.loads(receipt_bytes) == receipt, "IMAGE29_RECEIPT_BYTES_REQUIRED")
    require(sha256(build_manifest_bytes) == IMAGE29_MANIFEST_SHA256, "IMAGE29_BUILD_MANIFEST_BYTES_REQUIRED")
    view = plan.get("generation29Qualification", {})
    require(view.get("status") == "HOSTED_IMAGE_PASS_COHORT_AND_RUNTIME_PENDING", "IMAGE29_PHASE_A_ONLY_REQUIRED")
    require(view.get("receipt") == IMAGE29_RECEIPT_PATH and view.get("receiptSha256") == IMAGE29_RECEIPT_SHA256, "IMAGE29_RECEIPT_BINDING_REQUIRED")
    require(view.get("buildManifest") == IMAGE29_MANIFEST_PATH and view.get("buildManifestSha256") == receipt.get("buildManifestSha256") == IMAGE29_MANIFEST_SHA256, "IMAGE29_BUILD_MANIFEST_BINDING_REQUIRED")
    require(receipt.get("schema") == "ouf.seaweedfs-generation29-hosted-image.v1" and receipt.get("status") == "HOSTED_PASS_BYTES_REVERIFIED_NOT_ADMITTED", "IMAGE29_VERIFIED_RECEIPT_REQUIRED")
    require(view.get("sourceCommit") == receipt.get("producerCommit") == "041992eacd851d277cd049f03b9fe68a393e6df4", "IMAGE29_SOURCE_REQUIRED")
    require(view.get("runId") == receipt.get("runId") == 41696541570, "IMAGE29_RUN_REQUIRED")
    require(view.get("orderedPatchCount") == receipt.get("generation") == 29, "IMAGE29_PATCH29_REQUIRED")
    jobs = receipt.get("jobs", [])
    require(len(jobs) == 4 and {job.get("name") for job in jobs} == {"verify", "qualify-standard-profile", "runtime_candidate", "independent_image_readback"} and all(job.get("conclusion") == "success" for job in jobs), "IMAGE29_FOUR_SUCCESSFUL_JOBS_REQUIRED")
    readback = receipt["byteReadback"]
    for key in ("binarySha256", "ociManifestDigest", "imageConfigDigest", "patchedSourceTree", "vulnerabilitySubgate", "rawSeverityCounts"):
        require(view.get(key) == readback.get(key), "IMAGE29_CONTENT_BINDING_REQUIRED")
    require(view.get("binarySha256") != plan["currentQualification"]["binarySha256"] and view.get("ociManifestDigest") != plan["currentQualification"]["ociManifestDigest"], "IMAGE29_DISTINCT_GENERATION_REQUIRED")
    require(view.get("publisherSignatureVerifiedByHostedReader") is True and receipt.get("publisherSignatureVerifiedByHostedReader") is True, "IMAGE29_HOSTED_SIGNATURE_REQUIRED")
    require(view.get("localCryptographicSignatureVerificationClaimed") is False and receipt.get("localCryptographicSignatureVerificationClaimed") is False, "IMAGE29_NO_LOCAL_CRYPTO_CLAIM_REQUIRED")
    require(view.get("oldRuntimeEvidenceTransferred") is False, "IMAGE29_NO_RUNTIME_PROOF_TRANSFER_REQUIRED")
    for key in ("phaseBHostedCohort", "runtimeLabs29"):
        require(view.get(key) == receipt.get(key) == "PENDING", "IMAGE29_COHORT_AND_RUNTIME_PENDING_REQUIRED")
    for key in ("licenceReview", "durableImageCustody", "overallSwG1"):
        require(view.get(key) == "OPEN", "IMAGE29_OPEN_GATES_REQUIRED")
    for key in ("redistributionAccepted", "releaseAdmitted", "runtimeAuthorityIssued"):
        require(view.get(key) is False, "IMAGE29_NO_ADMISSION_OR_AUTHORITY_REQUIRED")
    require(view.get("targetOperations") == 0 and view.get("activeStorageBackend") == "MinIO", "IMAGE29_NO_TARGET_CHANGE_REQUIRED")


# Historical snapshots are immutable views, never rewritten to use generation29.
HISTORICAL_QUALIFICATION15_SHA = "58c9def4a5b4917a4861821c18ed73178e768e79196021696f4b5e5053be7b4f"
HISTORICAL_PHASE_A29_SHA = "74e5c093e0d9caccd7b4bc3947f435ada3d76da5a20bc575056902d69c27734b"
LOCK29_PATH = "releases/seaweedfs-452-generation29-candidate-lock-20261103.json"
LOCK29_SHA = "ed2a3b045420e91cd0ece7c2a8cbf9ccdedbf1145fc7fb3203b2d080c2bdf7bc"
COHORT29_PATH = "evidence/seaweedfs-452-generation29-cohort-hosted-20261103.json"
COHORT29_SHA = "ba67c94bfb9a473db31f82a7430604597faa0dddaae71c6818e738d57197e599"
RUNTIME29_PATH = "evidence/seaweedfs-generation29-runtime-hosted-20261103.json"
RUNTIME29_SHA = "786e28000b25d6fbb5e7b1b7884527447ab79a04a8f4cc48ff34dee37ffe94be"
COHORT29_DIR = "evidence/seaweedfs-452-generation29-cohort-hosted-20261103"
RUNTIME29_DIR = "evidence/seaweedfs-generation29-runtime-hosted-41701381292"
LIFECYCLE29_INVENTORY = {'inventoryReceipt': 'evidence/seaweedfs-generation29-lifecycle-inventory-20261103.json',
 'inventoryReceiptSha256': '2ba40208c83515c658801b198428daa1d9cbdd03d836c15a02c9d6a33a0370b0',
 'inventoryPath': 'evidence/lifecycle262/compiled-module-inventory.json',
 'inventorySha256': '43a2fbaa8afc194ad9b5f180ec91178201e4f339515ca45daf37cf52b46272c3',
 'scope': 'COMPILED_GENERATION29_ONLY',
 'compiledModules': 262,
 'repositoryMetadataResolvedModules': 250,
 'repositoryMetadataUnknownModules': ['golang.org/x/crypto',
                                      'golang.org/x/exp',
                                      'golang.org/x/image',
                                      'golang.org/x/net',
                                      'golang.org/x/oauth2',
                                      'golang.org/x/sync',
                                      'golang.org/x/sys',
                                      'golang.org/x/term',
                                      'golang.org/x/text',
                                      'golang.org/x/time',
                                      'google.golang.org/protobuf',
                                      'modernc.org/b'],
 'archivedCompiledModules': ['github.com/boltdb/bolt',
                             'github.com/envoyproxy/protoc-gen-validate',
                             'github.com/facebookgo/clock',
                             'github.com/facebookgo/stats',
                             'github.com/google/btree',
                             'github.com/mitchellh/colorstring',
                             'github.com/mitchellh/mapstructure',
                             'github.com/rcrowley/go-metrics',
                             'go.opencensus.io',
                             'gopkg.in/yaml.v3'],
 'additionalPolicyStates': {'cloud.google.com/go/pubsub': 'MODULE_DEPRECATED',
                            'github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp': 'DECLARED_NO_LONGER_MAINTAINED',
                            'github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric': 'DEPRECATED_FUTURE_ARCHIVAL_ANNOUNCED',
                            'github.com/Shopify/sarama': 'LEGACY_MODULE_PATH_MOVED_REPOSITORY',
                            'github.com/arangodb/go-driver': 'MAJOR_DEPRECATED_NO_NEW_FEATURES',
                            'github.com/armon/go-metrics': 'LEGACY_IMPORT_PATH_DEPRECATED',
                            'github.com/golang/protobuf': 'MODULE_DEPRECATED',
                            'github.com/pkg/errors': 'MAINTENANCE_MODE_DECLARED',
                            'github.com/syndtr/goleveldb': 'MAINTENANCE_UNKNOWN_NOT_ARCHIVED',
                            'go.mongodb.org/mongo-driver': 'DEPRECATED_MAJOR_SUPPORT_WINDOW_PASSED',
                            'google.golang.org/api': 'MAINTENANCE_MODE_CRITICAL_SECURITY_FIXES_DECLARED'},
 'repositoryNotArchivedProvesSupport': False,
 'unknownOriginAssumedMaintained': False,
 'allApiDeprecationsImplyModuleEndOfSupport': False,
 'widerMaintenanceAssessment': 'OPEN'}
LIFECYCLE29_INPUTS = {'evidence/lifecycle262/build-info-generation29.txt': {'sha256': '4d0a9eabc3fb020456824361b0bb944c6de92c3250ae5df5e2ae3bf6785e0c11',
                                                       'bytes': 25462},
 'evidence/lifecycle262/compiled-module-inventory.json': {'sha256': '43a2fbaa8afc194ad9b5f180ec91178201e4f339515ca45daf37cf52b46272c3',
                                                          'bytes': 405202},
 'evidence/lifecycle262/flagged-compiled-importers.json': {'sha256': '2bada89f2630f71118833338b6af69519ee79b18e306d6d9288f97a11e025f33',
                                                           'bytes': 44018},
 'evidence/lifecycle262/github-canonical-repositories.json': {'sha256': '9e64e53d4a5ed9461edbbf01b9cf9d8754f10b3bddef4e1aea3fc7df0b437b49',
                                                              'bytes': 32275},
 'evidence/lifecycle262/github-clock-redirect-resolution.json': {'sha256': '9de0b51ed35d4d710274292e0fae2f6ac6e1d6ec2643ff6bf0e90c5fcd0df139',
                                                                 'bytes': 26959},
 'evidence/lifecycle262/github-redirects.json': {'sha256': '90e7a326e98ef3961d8fd7889ee887535b1af499de4047b78e4a9f609d187bd3',
                                                 'bytes': 1866},
 'evidence/lifecycle262/github-repositories-001.json': {'sha256': 'c85cd02d3b02b5e3eb3df79fffc7cd035b27ddc60be30a67b51a43428614f9be',
                                                        'bytes': 189802},
 'evidence/lifecycle262/github-repositories-002.json': {'sha256': 'af33865524f6a9276aecef12bdb444d12f00a80c42ce00156a4b7da1e8ebb623',
                                                        'bytes': 373538},
 'evidence/lifecycle262/github-repositories-003.json': {'sha256': 'bbeea865ce6e662c4894cea4bd8dc21783c97ba184f57d864f6c955407c5a4d8',
                                                        'bytes': 361226},
 'evidence/lifecycle262/github-repositories-004.json': {'sha256': '40c3830eb915b9db66a66f601556237170d479319047d2ed915d5b0f04151c71',
                                                        'bytes': 471160},
 'evidence/lifecycle262/github-repositories-005.json': {'sha256': '72df6e80c975094dd7b13476c049a8e5e59b55692e793f18d700e8a6438b6c78',
                                                        'bytes': 160104},
 'evidence/lifecycle262/non-github-module-origins.json': {'sha256': 'e280b4beabd48ec4df00da87237fc99fdc77e9febcc9dddc14bd2435cf0dddde',
                                                          'bytes': 25117},
 'evidence/lifecycle262/pgv-archive-observation.json': {'sha256': 'b68f6f3bb8e2fd9818c71bac47ffb235b1af33eb38c3bef4651595adfbadf680',
                                                        'bytes': 681},
 'evidence/lifecycle262/pinned-module-deprecation-markers.json': {'sha256': '0185a38b37a049a6c6c058d3a5400b3dfed9ead4f0784add2af5daf12c2cfb3f',
                                                                  'bytes': 9954},
 'evidence/lifecycle262/primary-policy-readback.json': {'sha256': '0df8b633388d573467973b9afcf79b6f94e4c2fef6b23f36273b81ede60a6a1c',
                                                        'bytes': 2075},
 'evidence/lifecycle262/production-import-edges-generation29.txt': {'sha256': 'c78d5499b3b360797c5def44dd52b03d37f416f3f614704146523fed217df28c',
                                                                    'bytes': 477196},
 'evidence/seaweedfs-generation29-lifecycle-inventory-20261103.json': {'sha256': '2ba40208c83515c658801b198428daa1d9cbdd03d836c15a02c9d6a33a0370b0',
                                                                       'bytes': 2466}}
LIFECYCLE29_RESIDUALS = {
    "ShopifySaramaAndRcrowleyMetrics": [
        "github.com/Shopify/sarama@v1.38.1",
        "github.com/rcrowley/go-metrics@v0.0.0-20201227073835-cf1acfcdf475",
    ],
    "Bolt": ["github.com/boltdb/bolt@v1.3.1"],
    "Mapstructure": ["github.com/mitchellh/mapstructure@v1.5.1-0.20220423185008-bf980b35cac4"],
    "ArmonMetrics": ["github.com/armon/go-metrics@v0.4.1"],
}


def historical_plan_view(plan: dict[str, Any]) -> dict[str, Any]:
    require(canonical_sha256(plan.get("historicalQualification15")) == HISTORICAL_QUALIFICATION15_SHA,
            "HISTORICAL_QUALIFICATION15_CHANGED")
    require(canonical_sha256(plan.get("historicalGeneration29PhaseA")) == HISTORICAL_PHASE_A29_SHA,
            "HISTORICAL_PHASE_A29_CHANGED")
    view = dict(plan)
    view["currentQualification"] = plan["historicalQualification15"]
    view["generation29Qualification"] = plan["historicalGeneration29PhaseA"]
    return view


def generation29_current_view(lock: dict[str, Any]) -> dict[str, Any]:
    """Projection of exact generation29 evidence; no historical result is promoted."""
    return {
        "generation": 29, "version": "4.52", "upstreamCommit": UPSTREAM_COMMIT,
        "candidateLock": LOCK29_PATH, "candidateLockSha256": LOCK29_SHA,
        "qualifiedImagePatchCount": 29, "repositoryPatchCount": 29,
        "binarySha256": lock["buildProfile"]["binarySha256"],
        "ociManifestDigest": lock["image"]["manifestDigest"],
        "imageConfigDigest": lock["image"]["configDigest"],
        "status": "TECHNICAL_COHORT_AND_SYNTHETIC_RUNTIME_VERIFIED_NOT_ADMITTED",
        "qualificationRunId": 41696541570,
        "imageReceipt": IMAGE29_RECEIPT_PATH, "imageReceiptSha256": IMAGE29_RECEIPT_SHA256,
        "cohortReceipt": COHORT29_PATH, "cohortReceiptSha256": COHORT29_SHA,
        "cohortRunId": 41701381292, "cohortContent": "VERIFIED",
        "runtimeReceipt": RUNTIME29_PATH, "runtimeReceiptSha256": RUNTIME29_SHA,
        "runtimeRunId": 41701381292, "runtimeJobId": 126147936979,
        "buildProfile": "OUF_STANDARD_WITHOUT_ELASTIC_OR_RCLONE",
        "excludedBuildTags": ["elastic", "rclone"],
        "vulnerabilitySubgate": "PASS_RAW",
        "rawSeverityCounts": {key: 0 for key in ("HIGH", "CRITICAL", "UNKNOWN", "LOW", "MEDIUM")},
        "awsSdkV1InQualifiedBinary": "ABSENT", "deprecatedS3ManagerInQualifiedBinary": "ABSENT",
        "remainingRepositoryDirectSdkV1Importers": 0,
        "historicalApplicabilityApplied": False, "historicalRuntimeProofTransferred": False,
        "historicalSourceClosureReference": "historicalQualification15.sourceClosureReceipt",
        "historicalStandardProfileReference": "historicalQualification15.standardProfileQualification",
        "syntheticRuntime": {
            "coldRestore": "PASS", "objects": 5, "bytes": 8388702,
            "backupFiles": 110, "backupBytes": 8417467,
            "octetStreamGetAndHeadBeforeAndAfterRestore": "PASS",
            "identityS3Cases": 23, "tlsNegatives": 2, "egressProbes": 2,
            "distinctContainers": 12, "maximumConcurrentContainers": 4,
            "postgresRecovery": "NOT_TESTED", "certificateRotation": "NOT_TESTED",
            "s3MetadataCompatibilityGenerallyQualified": False,
            "rpoAcceptance": False, "rtoAcceptance": False,
        },
        "mimeCorrection": {
            "status": "EXACT_GENERATION29_SYNTHETIC_REGRESSION_PASS",
            "historicalGeneration15FailurePreserved": True,
            "historicalLostMetadataRepaired": False, "storageGateG2Closed": False,
        },
        "dependencyLifecycle": {
            "status": "OPEN", "allDependenciesMaintained": False,
            "selectedRemediationFronts": LIFECYCLE29_RESIDUALS,
            "selectedFrontsAreExhaustive": False,
            "widerInventoryAssessment": LIFECYCLE29_INVENTORY,
            "claimScope": "AWS_SDK_V1_AND_DEPRECATED_S3_MANAGER_REMOVED_ONLY",
            "prototypeRemovalsQualified": False,
        },
        "licenceRawUnknownClassifications": 3, "licenceReview": "OPEN",
        "redistributionAccepted": False, "durableImageCustody": "OPEN", "overallSwG1": "OPEN",
        "releaseAdmitted": False, "runtimeAuthorityIssued": False,
        "targetOperations": 0, "activeStorageBackend": "MinIO",
    }


def read_generation29_raw(root: Path, cohort: dict[str, Any], runtime: dict[str, Any]) -> dict[str, bytes]:
    raw: dict[str, bytes] = {}
    groups = [
        (COHORT29_DIR, [{"path": name, **item} for name, item in cohort["retainedRawEvidence"].items()], 14),
        (RUNTIME29_DIR, runtime["rawEvidence"]["files"], 60),
    ]
    for prefix, entries, count in groups:
        require(len(entries) == count, "GENERATION29_RAW_MEMBER_COUNT_REQUIRED")
        for item in entries:
            path = item.get("path", "")
            require(isinstance(path, str) and path.startswith(prefix + "/")
                    and not any(part in ("", ".", "..") for part in path.split("/"))
                    and "\\" not in path and path not in raw, "GENERATION29_RAW_PATH_REQUIRED")
            file = root / path
            require(file.is_file() and not file.is_symlink() and file.stat().st_size <= 32 * 1024 * 1024,
                    "GENERATION29_REGULAR_BOUNDED_RAW_REQUIRED")
            data = file.read_bytes()
            require(len(data) == item["bytes"] and sha256(data) == item["sha256"], "GENERATION29_RAW_BYTES_CHANGED")
            raw[path] = data
    return raw


def validate_current_generation29(
    plan: dict[str, Any], lock: dict[str, Any], lock_bytes: bytes,
    cohort: dict[str, Any], cohort_bytes: bytes, runtime: dict[str, Any], runtime_bytes: bytes,
    raw: dict[str, bytes],
) -> None:
    for value, data, expected, code in (
        (lock, lock_bytes, LOCK29_SHA, "LOCK29_BYTES_REQUIRED"),
        (cohort, cohort_bytes, COHORT29_SHA, "COHORT29_BYTES_REQUIRED"),
        (runtime, runtime_bytes, RUNTIME29_SHA, "RUNTIME29_BYTES_REQUIRED"),
    ):
        require(sha256(data) == expected and json.loads(data) == value, code)
    expected = generation29_current_view(lock)
    current = plan.get("currentQualification", {})
    require(current == expected, "CURRENT_GENERATION29_VIEW_REQUIRED")
    require(plan.get("generation29Qualification") == {
        "status": "HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED",
        "currentQualificationField": "currentQualification", "oldRuntimeEvidenceTransferred": False,
    }, "GENERATION29_PROMOTION_STATUS_REQUIRED")
    require(plan.get("nextGenerationPrototype") == {
        "status": "IN_DEVELOPMENT_NOT_QUALIFIED", "qualifiedGenerationRetained": 29,
        "progressCreditAdded": 0, "runtimeProofTransferred": False,
    }, "NEXT_PROTOTYPE_NOT_QUALIFIED_REQUIRED")
    require(lock["generation"] == lock["orderedPatchCount"] == 29, "LOCK29_GENERATION_REQUIRED")
    require(cohort["status"] == "HOSTED_TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED"
            and runtime["status"] == "HOSTED_SYNTHETIC_GENERATION29_RUNTIME_PASS_NOT_ACCEPTANCE",
            "GENERATION29_HOSTED_RESULTS_REQUIRED")
    for value in (cohort, runtime):
        require(value["runId"] == 41701381292 and value["sourceCommit"] == "7a71218586bcdbc50e1c983a1a12158dc9660de9",
                "GENERATION29_EXACT_RUN_REQUIRED")
        for key in ("candidateLockSha256", "binarySha256", "ociManifestDigest"):
            require(value[key] == current[key], "GENERATION29_COHORT_RUNTIME_IDENTITY_REQUIRED")
        require(value["targetOperations"] == 0 and value["releaseAdmitted"] is False
                and value["runtimeAuthorityIssued"] is False, "GENERATION29_NO_AUTHORITY_REQUIRED")
    require(runtime["allThreeWorkflowJobsPassed"] is True and runtime["runtimeJobId"] == 126147936979,
            "GENERATION29_ALL_HOSTED_JOBS_REQUIRED")
    require(runtime["predecessorCohortArtifact"]["id"] == cohort["artifact"]["id"] == 13264050910
            and runtime["predecessorCohortArtifact"]["archiveSha256"] == cohort["artifact"]["sha256"],
            "GENERATION29_PREDECESSOR_ARTIFACT_REQUIRED")
    # Recheck each retained raw byte, even when callers supply an in-memory map.
    entries = {name: item for name, item in cohort["retainedRawEvidence"].items()}
    entries.update({item["path"]: item for item in runtime["rawEvidence"]["files"]})
    require(set(raw) == set(entries) and len(raw) == 74, "GENERATION29_COMPLETE_RAW_SET_REQUIRED")
    for name, item in entries.items():
        require(len(raw[name]) == item["bytes"] and sha256(raw[name]) == item["sha256"], "GENERATION29_RAW_BYTES_CHANGED")
    cohort_raw = raw[COHORT29_DIR + "/cohort/cohort-receipt.json"]
    require(sha256(cohort_raw) == cohort["cohortReceiptSha256"] == runtime["cohortReceiptSha256"],
            "GENERATION29_EXACT_COHORT_RECEIPT_REQUIRED")
    for path, data in raw.items():
        if path.startswith(COHORT29_DIR + "/cohort/"):
            require(raw[RUNTIME29_DIR + "/cohort/" + path.removeprefix(COHORT29_DIR + "/cohort/")] == data,
                    "GENERATION29_PREDECESSOR_BYTES_REQUIRED")
    result = json.loads(raw[RUNTIME29_DIR + "/runtime-result.json"])
    cold = json.loads(raw[RUNTIME29_DIR + "/cold/recovery-result.json"])
    identity = json.loads(raw[RUNTIME29_DIR + "/identity/identity-result.json"])
    for value in (result, cold, identity):
        for key in ("candidateLockSha256", "binarySha256", "ociManifestDigest"):
            require(value[key] == current[key], "GENERATION29_RAW_IDENTITY_REQUIRED")
        require(value["targetOperations"] == value["gatesClosed"] == value["acceptanceTestsPassed"] == 0
                and value["releaseAdmitted"] is False and value["runtimeAuthorityIssued"] is False,
                "GENERATION29_RAW_NO_ACCEPTANCE_REQUIRED")
    require(result["octetStreamBeforeAndAfterRestore"] == "PASS"
            and cold["octetStreamCompatibility"]["status"] == "PASS"
            and cold["octetStreamCompatibility"]["getContentType"] == cold["octetStreamCompatibility"]["headContentType"] == "application/octet-stream"
            and cold["syntheticObjects"] == 5 and cold["backupFiles"] == 110
            and cold["originalContainersRemoved"] is True and cold["restoreUsesOnlyIndependentRoots"] is True,
            "GENERATION29_COLD_AND_MIME_REQUIRED")
    require(identity["s3CasesPassed"] == 23 and identity["tlsNegativesPassed"] == 2
            and identity["egressProbesPassed"] == 2, "GENERATION29_IDENTITY_TLS_EGRESS_REQUIRED")
    require(cold["postgresRecovery"] == "NOT_TESTED" and cold["rpoAcceptance"] is False
            and cold["rtoAcceptance"] is False and cold["s3MetadataCompatibilityQualified"] is False
            and identity["certificateRotation"] == "NOT_TESTED", "GENERATION29_LIMITS_REQUIRED")


def validate_generation29_sources(root: Path, manifest_bytes: bytes, runtime: dict[str, Any]) -> None:
    require(sha256(manifest_bytes) == IMAGE29_MANIFEST_SHA256, "IMAGE29_BUILD_MANIFEST_BYTES_REQUIRED")
    manifest = json.loads(manifest_bytes)
    require(len(manifest["orderedPatches"]) == 29, "GENERATION29_ALL_PATCHES_REQUIRED")
    for patch in manifest["orderedPatches"]:
        require(sha256((root / patch["path"]).read_bytes()) == patch["sha256"], "GENERATION29_PATCH_SOURCE_CHANGED")
    for path, expected in runtime["sourceHashesVerified"].items():
        require(sha256((root / path).read_bytes()) == expected, "GENERATION29_RUNTIME_SOURCE_CHANGED")
    jobs = runtime["workflowJobsEvidence"]
    raw = (root / jobs["path"]).read_bytes()
    require(len(raw) == jobs["bytes"] and sha256(raw) == jobs["sha256"], "GENERATION29_JOB_EVIDENCE_CHANGED")
    actual = json.loads(raw)["jobs"]
    require(len(actual) == 3 and all(item["conclusion"] == "success" and item["head_sha"] == runtime["sourceCommit"] for item in actual),
            "GENERATION29_ALL_HOSTED_JOBS_REQUIRED")


def validate_lifecycle29_evidence(root: Path, current: dict[str, Any]) -> None:
    for name, item in LIFECYCLE29_INPUTS.items():
        path = root / name
        require(path.is_file() and not path.is_symlink(), "LIFECYCLE29_RAW_REGULAR_FILE_REQUIRED")
        data = path.read_bytes()
        require(len(data) == item["bytes"] and sha256(data) == item["sha256"], "LIFECYCLE29_EVIDENCE_BYTES_CHANGED")
    view = current["dependencyLifecycle"]["widerInventoryAssessment"]
    require(view == LIFECYCLE29_INVENTORY, "LIFECYCLE29_ASSESSMENT_REQUIRED")
    receipt = json.loads((root / view["inventoryReceipt"]).read_bytes())
    inventory = json.loads((root / view["inventoryPath"]).read_bytes())
    require(receipt["binarySha256"] == inventory["binarySha256"] == current["binarySha256"]
            and receipt["producerRun"] == inventory["producerRun"] == current["qualificationRunId"],
            "LIFECYCLE29_BINARY_BINDING_REQUIRED")
    require(inventory["compiledModules"] == len(inventory["modules"]) == 262
            and len(inventory["archivedCompiledModules"]) == 10
            and len(inventory["githubRepositoryMetadataUnknownForModules"]) == 12
            and inventory["githubRepositoryMetadataResolvedForModules"] == 250
            and inventory["allDependenciesMaintainedClaimed"] is False,
            "LIFECYCLE29_COMPLETE_LIMITED_INVENTORY_REQUIRED")
    records = {item["module"]: item for item in inventory["modules"]}
    require(records["go.mongodb.org/mongo-driver"]["additionalLifecyclePolicy"]["status"] == "DEPRECATED_MAJOR_SUPPORT_WINDOW_PASSED"
            and records["github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp"]["additionalLifecyclePolicy"]["status"] == "DECLARED_NO_LONGER_MAINTAINED",
            "LIFECYCLE29_PINNED_POLICY_FINDINGS_REQUIRED")


def validate_tree(root: Path) -> dict[str, Any]:
    original_plan, _ = read_json(root / PLAN_PATH)
    plan = historical_plan_view(original_plan)
    lock, lock_bytes = read_json(root / LOCK_PATH)
    cohort, _ = read_json(root / COHORT_PATH)
    dossiers = {path: read_json(root / path)[0] for path in EXPECTED_DOSSIERS}
    source_receipt, source_receipt_bytes = read_json(root / SOURCE_CLOSURE_PATH)
    patch_hashes = {path: sha256((root / path).read_bytes()) for path in EXPECTED_SOURCE_PATCHES}
    result = validate_documents(plan, lock, lock_bytes, cohort, dossiers, source_receipt, source_receipt_bytes, patch_hashes)
    validate_archived_tree(root, source_receipt)
    standard_receipt, standard_bytes = read_json(root / STANDARD_RECEIPT_PATH)
    defect, defect_bytes = read_json(root / MIME_DEFECT_PATH)
    validate_standard_profile(plan, standard_receipt, standard_bytes, sha256((root / STANDARD_PATCH_PATH).read_bytes()), defect, defect_bytes)
    validate_standard_evidence(standard_receipt, read_standard_evidence(root, standard_receipt))
    result["standardProfileClosure"] = "HOSTED_PASS"
    result["standardProfileReceiptSha256"] = sha256(standard_bytes)
    result["knownCompatibilityDefects"] = ["CONTENT_TYPE_MISMATCH"]
    cold, cold_bytes = read_json(root / COLD_RECEIPT_PATH)
    validate_cold_evidence(plan, cold, cold_bytes, read_cold_evidence(root, cold))
    result["historicalColdRecovery15"] = "HOSTED_PASS_MIME_FAIL_NOT_ACCEPTANCE"
    result["coldProofTransferredToGeneration29"] = False
    image29, image29_bytes = read_json(root / IMAGE29_RECEIPT_PATH)
    validate_generation29_image(plan, image29, image29_bytes, (root / IMAGE29_MANIFEST_PATH).read_bytes())
    result["generation29ImageReceiptSha256"] = IMAGE29_RECEIPT_SHA256
    lock29, lock29_bytes = read_json(root / LOCK29_PATH)
    cohort29, cohort29_bytes = read_json(root / COHORT29_PATH)
    runtime29, runtime29_bytes = read_json(root / RUNTIME29_PATH)
    # Receipt pins are checked before using their file lists.
    require(sha256(cohort29_bytes) == COHORT29_SHA and sha256(runtime29_bytes) == RUNTIME29_SHA,
            "GENERATION29_RECEIPT_PINS_REQUIRED")
    raw29 = read_generation29_raw(root, cohort29, runtime29)
    validate_current_generation29(original_plan, lock29, lock29_bytes, cohort29, cohort29_bytes,
                                  runtime29, runtime29_bytes, raw29)
    validate_generation29_sources(root, (root / IMAGE29_MANIFEST_PATH).read_bytes(), runtime29)
    validate_lifecycle29_evidence(root, original_plan["currentQualification"])
    result.update({"candidateLockSha256": LOCK29_SHA, "repositoryPatchCount": 29,
                   "qualifiedImagePatchCount": 29,
                   "generation29ImageQualification": "HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED",
                   "generation29CohortReceiptSha256": COHORT29_SHA,
                   "generation29RuntimeReceiptSha256": RUNTIME29_SHA,
                   "historicalRepositoryPatchCount": 28, "historicalQualifiedImagePatchCount": 15,
                   "knownCompatibilityDefects": [], "historicalGeneration15MimeDefect": "FAIL_PRESERVED",
                   "generation29MimeRegression": "PASS_SYNTHETIC_ONLY",
                   "dependencyLifecycleStatus": "OPEN", "allDependenciesMaintained": False,
                   "nextPrototypeQualified": False})
    return result


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
