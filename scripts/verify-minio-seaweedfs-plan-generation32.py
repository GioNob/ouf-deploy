"""Bind generation 32 to its own hosted evidence, preserving the whole prior plan."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import PurePosixPath
import zipfile

LOCK = "releases/seaweedfs-452-generation32-candidate-lock-20261103.json"
LOCK_SHA = "91a7c874deb5b11f1a18dc483e99f6031644b62abb769a9e11ff1ad29250fb7d"
IMAGE = "evidence/seaweedfs-452-generation32-image-hosted-20261104.json"
IMAGE_SHA = "a956fe5249719bb516b2f2e7f90384f14b0c74b38a894c68f8d153ffe51cc784"
COHORT = "evidence/seaweedfs-452-generation32-cohort-hosted-20261104.json"
RUNTIME = "evidence/seaweedfs-generation32-runtime-hosted-20261104.json"
COHORT_ZIP = "evidence/artifacts/seaweedfs-generation32-cohort-41778371999.zip"
RUNTIME_ZIP = "evidence/artifacts/seaweedfs-generation32-runtime-41778371999.zip"
COHORT_ZIP_SHA = "b235c9e9b53d20d7c4eb58250602a051f9e6d66b5faf4cf55417afa905234772"
RUNTIME_ZIP_SHA = "fb76046dabfd6d58ff0236b72b795d981f57b7aeaba3d179108ee6ecef82ff1b"
INNER_COHORT_SHA = "cf3a01b6426bdb64725b155d252089026a3cf08bc94859da7619ac17a88af19c"
SOURCE_COMMIT = "5dfb1995d1eadd33caeb923594866c1e380d25db"
RUN = 41778371999
JOBS = (126403922831, 126403970928, 126404723521)
BASE_PLAN_CANONICAL_SHA = "8066f1b6af601fc655b62a21bbfeddcbe60d0737f7743790fb69b9424f0fc6f7"
COHORT_SHA = "77238c1add22745a2325674f58b7c65743c6d9eeb5121fe68a3964425d9cfc82"
RUNTIME_SHA = "60ce12401fe635f0a5a213f508878dd77c558c35c6660b6b762f1f853fb3d64f"
PROTOTYPE = {"status": "IN_DEVELOPMENT_NOT_QUALIFIED", "qualifiedGenerationRetained": 32,
             "progressCreditAdded": 0, "runtimeProofTransferred": False}
ALIAS = {"status": "HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED",
         "currentQualificationField": "currentQualification", "oldRuntimeEvidenceTransferred": False}
HISTORICAL_ALIAS = {"status": "HISTORICAL_HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED",
                    "historicalQualificationField": "historicalQualification31",
                    "oldRuntimeEvidenceTransferred": False}
ARCHIVED_REMOVED = [
    "github.com/boltdb/bolt", "github.com/facebookgo/clock", "github.com/facebookgo/stats",
    "github.com/google/btree", "github.com/mitchellh/mapstructure", "github.com/rcrowley/go-metrics",
    "github.com/envoyproxy/protoc-gen-validate", "github.com/mitchellh/colorstring", "go.opencensus.io",
]


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def safe_name(name):
    path = PurePosixPath(name)
    return bool(path.parts) and not path.is_absolute() and "\\" not in name and all(
        part not in (".", "..") for part in path.parts) and path.as_posix() == name


def read_bound(root, path, expected):
    require(safe_name(path), "GEN32_BOUND_PATH_REQUIRED")
    member = root / path
    require(member.is_file() and not member.is_symlink() and member.resolve().is_relative_to(root.resolve()),
            "GEN32_REGULAR_FILE_REQUIRED:" + path)
    require(member.stat().st_size <= 64 * 1024**2, "GEN32_FILE_SIZE_BOUND:" + path)
    data = member.read_bytes()
    require(len(data) <= 64 * 1024**2 and sha(data) == expected, "GEN32_BOUND_BYTES_CHANGED:" + path)
    return data


def restore_generation31_plan(plan):
    require(plan["currentQualification"]["generation"] == 32, "GEN32_CURRENT_GENERATION_REQUIRED")
    require(plan["generation32Qualification"] == ALIAS and plan["generation31Qualification"] == HISTORICAL_ALIAS,
            "GEN32_QUALIFICATION_ALIASES_REQUIRED")
    require(plan["nextGenerationPrototype"] == PROTOTYPE, "GEN33_PROTOTYPE_REMAINS_UNQUALIFIED")
    restored = copy.deepcopy(plan)
    restored["currentQualification"] = restored.pop("historicalQualification31")
    restored["generation31Qualification"] = restored.pop("historicalGeneration31QualificationAlias")
    restored["nextGenerationPrototype"] = restored.pop("historicalNextGenerationPrototypeBefore32")
    del restored["generation32Qualification"]
    require(sha(canonical(restored)) == BASE_PLAN_CANONICAL_SHA, "ALL_PRE32_HISTORY_AND_PROGRESS_IMMUTABLE")
    return restored


def checked_zip(data, count):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == count and all(map(safe_name, names)),
                "GEN32_EXACT_ZIP_MEMBERS_REQUIRED")
        require(sum(member.file_size for member in archive.infolist()) <= 8 * 1024**2,
                "GEN32_ZIP_EXPANSION_BOUND")
        members = {name: archive.read(name) for name in names}
    checks = {}
    for line in members["SHA256SUMS"].decode().splitlines():
        digest, name = line.split("  ", 1)
        name = name.removeprefix("./")
        require(name in members and name not in checks and sha(members[name]) == digest,
                "GEN32_ZIP_CHECKSUM_CHANGED")
        checks[name] = digest
    require(set(checks) == set(members) - {"SHA256SUMS"}, "GEN32_ZIP_CHECKSUM_CLOSURE")
    return members


def bind_qualification(root):
    lock_raw = read_bound(root, LOCK, LOCK_SHA)
    lock = json.loads(lock_raw)
    image = json.loads(read_bound(root, IMAGE, IMAGE_SHA))
    manifest = lock["buildManifest"]
    manifest_json = json.loads(read_bound(root, manifest["path"], manifest["sha256"]))
    require(lock["generation"] == manifest_json["generation"] == 32, "GEN32_MANIFEST_GENERATION_REQUIRED")
    require(lock["orderedPatchCount"] == len(manifest_json["orderedPatches"]) == 32, "GEN32_PATCH_COUNT")
    for patch in manifest_json["orderedPatches"]:
        read_bound(root, patch["path"], patch["sha256"])
    binary = lock["buildProfile"]["binarySha256"]
    oci = lock["image"]["manifestDigest"]
    require(image["candidateLockSha256"] == LOCK_SHA and image["byteReadback"]["binarySha256"] == binary
            and image["byteReadback"]["ociManifestDigest"] == oci
            and image["image"] == lock["image"] and image["run"]["id"] == lock["qualification"]["runId"]
            and image["run"]["head_sha"] == lock["producerCommit"], "GEN32_IMAGE_BINDING")
    require(len(image["jobs"]) == 4 and all(j["conclusion"] == "success" for j in image["jobs"])
            and image["publisherSignatureReverifiedLocally"] is False
            and lock["independentReadback"]["publisherSignatureVerifiedByHostedJob"] is True,
            "GEN32_HOSTED_IMAGE_REQUIRED")
    for key in ("buildEvidenceArtifact", "independentReadback"):
        item = lock[key]
        require(len(read_bound(root, item["path"], item["digest"].removeprefix("sha256:"))) == item["bytes"],
                "GEN32_IMAGE_ARTIFACT_SIZE")
    for key in ("licenceRebinding", "mongoV2LegalDelta"):
        item = lock[key]
        read_bound(root, item["path"], item["sha256"])
    build = lock["qualification"]
    require(build["vulnerabilitySubgate"] == "PASS_RAW" and build["rawSeverityCounts"] ==
            dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), 0), "GEN32_FRESH_SCAN_REQUIRED")
    require(lock["buildProfile"]["binaryModuleRows"] == 215 and lock["buildProfile"]["compiledPackages"] == 1533,
            "GEN32_COMPILED_INVENTORY_REQUIRED")

    cohort_zip = read_bound(root, COHORT_ZIP, COHORT_ZIP_SHA)
    runtime_zip = read_bound(root, RUNTIME_ZIP, RUNTIME_ZIP_SHA)
    require(len(cohort_zip) == 118228 and len(runtime_zip) == 170026, "GEN32_HOSTED_ZIP_BYTES")
    cohort_files, raw = checked_zip(cohort_zip, 11), checked_zip(runtime_zip, 62)
    for name, data in cohort_files.items():
        require(raw["cohort/" + name] == data, "GEN32_COHORT_RUNTIME_BYTE_BINDING:" + name)
    require(cohort_files[PurePosixPath(LOCK).name] == lock_raw, "GEN32_ARCHIVED_LOCK_CHANGED")
    require(sha(cohort_files["cohort-receipt.json"]) == INNER_COHORT_SHA, "GEN32_INNER_COHORT_CHANGED")
    inner = json.loads(cohort_files["cohort-receipt.json"])
    require(inner == image["localCohortReplay"], "GEN32_HOSTED_LOCAL_COHORT_REPLAY_MISMATCH")
    result = json.loads(raw["runtime-result.json"])
    for item in (lock, image, inner, result):
        require(item["releaseAdmitted"] is False and item["runtimeAuthorityIssued"] is False
                and item["targetOperations"] == 0, "GEN32_NO_RUNTIME_AUTHORITY")
    for item in (inner, result):
        require(item["generation"] == 32 and item["candidateLockSha256"] == LOCK_SHA
                and item["binarySha256"] == binary and item["ociManifestDigest"] == oci, "GEN32_RUNTIME_IDENTITY")
    require(inner["status"] == "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED" and
            inner["licenceReview"] == inner["durableImageCustody"] == "OPEN"
            and inner["redistributionAccepted"] is False and inner["readbackReproduced"] is True,
            "GEN32_COHORT_SCOPE")
    require(inner["legalTextRebindingSha256"] == lock["licenceRebinding"]["sha256"] ==
            sha(cohort_files["licence-rebinding.json"]), "GEN32_LEGAL_BINDING")
    require(inner["mongoV2LegalDeltaSha256"] == lock["mongoV2LegalDelta"]["sha256"], "GEN32_MONGO_LEGAL_DELTA")
    for name, field in (("modified-raftstore-source.tar.gz", "archiveSha256"),
                        ("modified-raftstore-source-manifest.json", "manifestSha256")):
        require(sha(cohort_files[name]) == lock["modifiedMplSource"][field], "GEN32_LOCAL_MPL_BYTES")
    legal = json.loads(cohort_files["licence-rebinding.json"])
    modules = [json.loads(line)["Path"] for line in cohort_files["module-downloads.jsonl"].splitlines()]
    require(len(modules) == len(set(modules)) == legal["thirdPartyModules"] == 215 and
            legal["thirdPartyLegalTexts"] == 304 and legal["mplSourceArchivesReverified"] == 7,
            "GEN32_LEGAL_INVENTORY")
    require(not set(modules).intersection(ARCHIVED_REMOVED) and "gopkg.in/yaml.v3" in modules and
            "go.mongodb.org/mongo-driver/v2" in modules, "GEN32_MAINTENANCE_BOUNDARY")

    require(result["status"] == "SYNTHETIC_COLD_MIME_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE" and
            result["cohortReceiptSha256"] == INNER_COHORT_SHA and result["octetStreamBeforeAndAfterRestore"] == "PASS"
            and result["buildManifestSha256"] == manifest["sha256"]
            and result["acceptanceTestsPassed"] == result["gatesClosed"] == 0 and result["labsSequential"] is True
            and result["maximumConcurrentContainers"] == 4, "GEN32_SYNTHETIC_RUNTIME_REQUIRED")
    sources = json.loads(raw["source-sha256.json"])
    require(len(sources) == 16, "GEN32_RUNTIME_SOURCE_COUNT")
    for path, digest in sources.items():
        read_bound(root, path, digest)
    cold = json.loads(raw["cold/recovery-result.json"])
    identity = json.loads(raw["identity/identity-result.json"])
    backup = json.loads(raw["cold/cold-backup-manifest.json"])
    require(cold["syntheticObjects"] == 5 and cold["syntheticBytes"] == 8388702
            and cold["backupFiles"] == len(backup) == 110
            and cold["allBodiesAndHashMetadataEqual"] is True and cold["restoreUsesOnlyIndependentRoots"] is True
            and cold["octetStreamCompatibility"]["status"] == "PASS"
            and cold["postgresRecovery"] == "NOT_TESTED" and cold["rpoAcceptance"] is cold["rtoAcceptance"] is False,
            "GEN32_EXACT_COLD_RUNTIME_REQUIRED")
    require(identity["s3CasesPassed"] == result["identityS3Cases"] == 23 and
            identity["tlsNegativesPassed"] == result["tlsNegatives"] == 2 and
            identity["egressProbesPassed"] == result["egressProbes"] == 2, "GEN32_IDENTITY_COUNTS")
    containers = [row for name, data in raw.items() if name.endswith("containers.json") for row in json.loads(data)]
    stops = [json.loads(data) for name, data in raw.items() if name.endswith("-stopped.json")]
    require(len(containers) == len({item["Id"] for item in containers}) == len(stops) == 12 and
            all(stop["ExitCode"] == 0 and stop["Running"] is False for stop in stops), "GEN32_DISTINCT_CLEAN_CONTAINERS")
    backup_bytes = sum(item["bytes"] for item in backup.values())
    return lock, image, inner, result, sources, legal, backup_bytes


def current_view32(history, lock, legal, backup_bytes):
    current = copy.deepcopy(history["currentQualification"])
    current.update(generation=32, candidateLock=LOCK, candidateLockSha256=LOCK_SHA,
                   qualifiedImagePatchCount=32, repositoryPatchCount=32,
                   binarySha256=lock["buildProfile"]["binarySha256"],
                   ociManifestDigest=lock["image"]["manifestDigest"], imageConfigDigest=lock["image"]["configDigest"],
                   qualificationRunId=lock["qualification"]["runId"], imageReceipt=IMAGE, imageReceiptSha256=IMAGE_SHA,
                   cohortReceipt=COHORT, cohortReceiptSha256=COHORT_SHA, cohortRunId=RUN,
                   runtimeReceipt=RUNTIME, runtimeReceiptSha256=RUNTIME_SHA, runtimeRunId=RUN, runtimeJobId=JOBS[-1],
                   buildProfile="OUF_STANDARD_WITHOUT_ELASTIC_RCLONE_KAFKA_OPENBAO_GOOGLE_ADAPTERS",
                   excludedBuildTags=["elastic", "rclone", "kafka", "openbao", "vault", "gcs", "google_pub_sub", "googlecloud"])
    current["licenceRawUnknownClassifications"] = len(legal["historicalUnknownClassifications"])
    current["licenceRawUnknownClassificationsScope"] = "HISTORICAL_CORPUS_REVIEW_OPEN"
    current["syntheticRuntime"]["backupBytes"] = backup_bytes
    current["mimeCorrection"]["status"] = "EXACT_GENERATION32_SYNTHETIC_REGRESSION_PASS"
    current["dependencyLifecycle"] = {
        "status": "OPEN", "allDependenciesMaintained": False, "compiledModules": 215, "compiledPackages": 1533,
        "historicalGeneration29InventoryReference": "historicalQualification29.dependencyLifecycle.widerInventoryAssessment",
        "archivedModulesRemovedFromGeneration29Binary": ARCHIVED_REMOVED,
        "remainingArchivedCompiledModules": ["gopkg.in/yaml.v3"],
        "unknownOriginAssumedMaintained": False, "widerMaintenanceAssessment": "OPEN",
        "targetFeatureBinding": "OPEN", "nextGeneration33QualificationTransferred": False,
        "moduleGraphEradicationClaimed": False, "mongoDriverMajor": 2,
        "excludedGoogleFeatures": lock["sourceRevision"]["excludedGoogleFeatures"],
    }
    return current


def validate_tree32(root, plan, historical_validator):
    historical = restore_generation31_plan(plan)
    previous = historical_validator(root, historical)
    lock, image, inner, result, sources, legal, backup_bytes = bind_qualification(root)
    cohort = json.loads(read_bound(root, COHORT, COHORT_SHA))
    runtime = json.loads(read_bound(root, RUNTIME, RUNTIME_SHA))
    for receipt in (cohort, runtime):
        require(receipt["runId"] == RUN and receipt["sourceCommit"] == SOURCE_COMMIT
                and receipt["wholeWorkflowConclusion"] == "success"
                and [job["id"] for job in receipt["jobs"]] == list(JOBS)
                and all(job["conclusion"] == "success" for job in receipt["jobs"])
                and receipt["releaseAdmitted"] is False and receipt["runtimeAuthorityIssued"] is False
                and receipt["targetOperations"] == 0 and receipt["cohortReceiptSha256"] == INNER_COHORT_SHA,
                "GEN32_HOSTED_RECEIPT_REQUIRED")
    require(runtime["sourceHashesVerified"] == sources and runtime["backupBytes"] == backup_bytes,
            "GEN32_RUNTIME_RECEIPT_RAW_BINDING")
    require(plan["currentQualification"] == current_view32(historical, lock, legal, backup_bytes),
            "GEN32_EXACT_CURRENT_VIEW_REQUIRED")
    previous.update(currentGeneration=32, historicalGeneration31QualifiedImagePatchCount=31,
                    repositoryPatchCount=32, qualifiedImagePatchCount=32, candidateLockSha256=LOCK_SHA,
                    generation32ImageReceiptSha256=IMAGE_SHA, generation32CohortReceiptSha256=COHORT_SHA,
                    generation32RuntimeReceiptSha256=RUNTIME_SHA, generation32MimeRegression="PASS_SYNTHETIC_ONLY",
                    currentBinaryModules=215, currentCompiledPackages=1533, historicalProofTransferredToGeneration32=False)
    return previous
