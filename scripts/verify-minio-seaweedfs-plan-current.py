#!/usr/bin/env python3
"""Fail-closed verifier for the current SeaweedFS qualification view.

The replacement plan intentionally retains the 4.51 evidence blocks as history.
This verifier binds the additive 4.52 view to the immutable candidate lock, the
hosted cohort receipt, the six historical test-only dossiers, and the exact 27-patch hosted receipt.
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
    "optionalBuildTagsStillOpen": ["elastic", "rclone"],
    "remainingNestedKafkaModulesQualified": False,
    "liveIamRoundtripPerformed": False,
}
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
    require(current.get("repositoryPatchCount") == 27, "REPOSITORY_PATCH_COUNT_REQUIRED")
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
        "repositoryPatchCount": 27,
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


def validate_tree(root: Path) -> dict[str, Any]:
    plan, _ = read_json(root / PLAN_PATH)
    lock, lock_bytes = read_json(root / LOCK_PATH)
    cohort, _ = read_json(root / COHORT_PATH)
    dossiers = {path: read_json(root / path)[0] for path in EXPECTED_DOSSIERS}
    source_receipt, source_receipt_bytes = read_json(root / SOURCE_CLOSURE_PATH)
    patch_hashes = {path: sha256((root / path).read_bytes()) for path in EXPECTED_SOURCE_PATCHES}
    result = validate_documents(plan, lock, lock_bytes, cohort, dossiers, source_receipt, source_receipt_bytes, patch_hashes)
    validate_archived_tree(root, source_receipt)
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
