"""Bind generation 33 to its own hosted evidence, preserving the whole prior plan."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import PurePosixPath
import zipfile

LOCK = "releases/seaweedfs-452-generation33-candidate-lock-20261104.json"
LOCK_SHA = "c2b30130b078a86ca440351980c3e745d4132e256591ec05fe98a9bdfc9058f8"
IMAGE = "evidence/seaweedfs-generation33-image-hosted-20261104.json"
LOCAL_COHORT_SHA = "3d341eedc7fb7343b66d58b0267c69f8668a5c3751cd8851158d771c962844b8"
IMAGE_SHA = "006ddaad0faf8bc179b8386478b8b24824ec09742d76deb4a5b7c71d456627d0"
COHORT = "evidence/seaweedfs-452-generation33-cohort-hosted-20261104.json"
RUNTIME = "evidence/seaweedfs-generation33-runtime-hosted-20261104.json"
COHORT_ZIP = "evidence/artifacts/seaweedfs-generation33-cohort-41794344274.zip"
RUNTIME_ZIP = "evidence/artifacts/seaweedfs-generation33-runtime-41794344274.zip"
COHORT_ZIP_SHA = "5a8a59be0d0ee6230322e4828cc1edef5ca1e24689dc2ff7f19ede830203430e"
RUNTIME_ZIP_SHA = "86fafad9677c30df2c14535b8279a23a34e3142cc348f5071ee46d0ef0a53b24"
INNER_COHORT_SHA = "5b28de1dd43fca337064d41439d302d53dc7f470640fe3fc0d8d1292b1ec02dc"
SOURCE_COMMIT = "7a00b8bfaf8a2cefdc2aff278be62fd5b7f28791"
RUN = 41794344274
JOBS = (126454780558,126454854350,126455651447)
COHORT_BYTES = 127980
RUNTIME_BYTES = 180386
BASE_PLAN_CANONICAL_SHA = "228760f4c060831aada7b3bcb200a01e9c3681fbdced59ca9ca1ea9c53021326"
COHORT_SHA = "6be72f64172037acf65e9935b07e169d960bd2869399d8d3af3fe8551c4ec344"
RUNTIME_SHA = "00952ebeb5100c8f21a0ce19cddfef13af225ae9cdc727778cff5df658a0216b"
COORDINATED = "evidence/storage-coordinated-generation32-hosted-20261104.json"
COORDINATED_SHA = "96d17a119f8750dd5def60ab4df057763f73cb7e922c78967a0ba3c150878099"
FENCE = "evidence/storage-postgres-publication-fence-hosted-20261104.json"
FENCE_SHA = "3214d5a03ff8837a7ddd14de0036b8ebd810563197482b775f3e73dc59acba6e"
PROTOTYPE = {"status": "IN_DEVELOPMENT_NOT_QUALIFIED", "qualifiedGenerationRetained": 33,
             "progressCreditAdded": 0, "runtimeProofTransferred": False}
ALIAS = {"status": "HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED",
         "currentQualificationField": "currentQualification", "oldRuntimeEvidenceTransferred": False}
HISTORICAL_ALIAS = {"status": "HISTORICAL_HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED",
                    "historicalQualificationField": "historicalQualification32",
                    "oldRuntimeEvidenceTransferred": False}
ARCHIVED_REMOVED = [
    "github.com/boltdb/bolt", "github.com/facebookgo/clock", "github.com/facebookgo/stats",
    "github.com/google/btree", "github.com/mitchellh/mapstructure", "github.com/rcrowley/go-metrics",
    "gopkg.in/yaml.v3", "github.com/envoyproxy/protoc-gen-validate", "github.com/mitchellh/colorstring", "go.opencensus.io",
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
    require(safe_name(path), "GEN33_BOUND_PATH_REQUIRED")
    member = root / path
    require(member.is_file() and not member.is_symlink() and member.resolve().is_relative_to(root.resolve()),
            "GEN33_REGULAR_FILE_REQUIRED:" + path)
    require(member.stat().st_size <= 64 * 1024**2, "GEN33_FILE_SIZE_BOUND:" + path)
    data = member.read_bytes()
    require(len(data) <= 64 * 1024**2 and sha(data) == expected, "GEN33_BOUND_BYTES_CHANGED:" + path)
    return data


def restore_generation32_plan(plan):
    require(plan["currentQualification"]["generation"] == 33, "GEN33_CURRENT_GENERATION_REQUIRED")
    require(plan["generation33Qualification"] == ALIAS and plan["generation32Qualification"] == HISTORICAL_ALIAS,
            "GEN33_QUALIFICATION_ALIASES_REQUIRED")
    require(plan["nextGenerationPrototype"] == PROTOTYPE, "NEXT_PROTOTYPE_REMAINS_UNQUALIFIED")
    require(plan['engineeringRecovery33'] == recovery_view(), 'GEN33_RECOVERY_SCOPE_CANNOT_BE_TRANSFERRED')
    restored = copy.deepcopy(plan)
    restored['progressEstimate'] = restored.pop('historicalProgressEstimateBefore33')
    del restored['engineeringRecovery33']
    restored["currentQualification"] = restored.pop("historicalQualification32")
    restored["generation32Qualification"] = restored.pop("historicalGeneration32QualificationAlias")
    restored["nextGenerationPrototype"] = restored.pop("historicalNextGenerationPrototypeBefore33")
    del restored["generation33Qualification"]
    require(sha(canonical(restored)) == BASE_PLAN_CANONICAL_SHA, "ALL_PRE33_HISTORY_AND_PROGRESS_IMMUTABLE")
    return restored


def checked_zip(data, count):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == count and all(map(safe_name, names)),
                "GEN33_EXACT_ZIP_MEMBERS_REQUIRED")
        require(sum(member.file_size for member in archive.infolist()) <= 8 * 1024**2,
                "GEN33_ZIP_EXPANSION_BOUND")
        members = {name: archive.read(name) for name in names}
    checks = {}
    for line in members["SHA256SUMS"].decode().splitlines():
        digest, name = line.split("  ", 1)
        name = name.removeprefix("./")
        require(name in members and name not in checks and sha(members[name]) == digest,
                "GEN33_ZIP_CHECKSUM_CHANGED")
        checks[name] = digest
    require(set(checks) == set(members) - {"SHA256SUMS"}, "GEN33_ZIP_CHECKSUM_CLOSURE")
    return members


def bind_qualification(root):
    require(all((COHORT_SHA,RUNTIME_SHA,COHORT_ZIP_SHA,RUNTIME_ZIP_SHA,JOBS,COHORT_BYTES,RUNTIME_BYTES)), "ACTUAL_HOSTED_33_EVIDENCE_REQUIRED")
    lock_raw = read_bound(root, LOCK, LOCK_SHA)
    lock = json.loads(lock_raw)
    image = json.loads(read_bound(root, IMAGE, IMAGE_SHA))
    manifest = lock["buildManifest"]
    manifest_json = json.loads(read_bound(root, manifest["path"], manifest["sha256"]))
    require(lock["generation"] == manifest_json["generation"] == 33, "GEN33_MANIFEST_GENERATION_REQUIRED")
    require(lock["orderedPatchCount"] == 33 and lock['sourcePatchCount'] == 32
            and lock['dependencyPatchCount'] == 1 and len(manifest_json['orderedSourcePatches']) == 32
            and len(manifest_json['orderedDependencyPatches']) == 1, 'GEN33_PATCH_COUNT')
    for patch in manifest_json['orderedSourcePatches'] + manifest_json['orderedDependencyPatches']:
        read_bound(root,patch['path'],patch['sha256'])
    binary=lock['buildProfile']['binarySha256'];oci=lock['image']['manifestDigest']
    require(image['byteReadback']['binarySha256'] == binary and image['byteReadback']['ociManifestDigest'] == oci
            and all(image['assessment'][k] == v for k,v in lock['image'].items())
            and image['run']['id'] == lock['qualification']['runId']
            and image['run']['head_sha'] == lock['producerCommit'], 'GEN33_IMAGE_BINDING')
    require(len(image['jobs']) == 4 and all(j['conclusion']=='success' for j in image['jobs'])
            and image['independentReadback']['publisherSignatureReverifiedLocally'] is False
            and image['independentReadback']['publisherSignatureVerifiedByHostedJob'] is True,
            'GEN33_HOSTED_IMAGE_REQUIRED')
    for key in ('sourceArtifact','independentReadback'):
        item=image[key]
        require(len(read_bound(root,item['path'],item['digest'].removeprefix('sha256:'))) == item['bytes'],
                'GEN33_IMAGE_ARTIFACT_SIZE')
    raw_image=image['rawEvidence']
    for name,item in raw_image['originalMemberBytes'].items():
        require(len(read_bound(root,raw_image['directory']+'/'+name,item['sha256'])) == item['bytes'],
                'GEN33_ORIGINAL_IMAGE_MEMBER_CHANGED')
    require(image['vendorBuildInfoH1'] == 'EMPTY_BY_DESIGN_AUTHENTIC_ORIGINAL_MODULE_ZIP_H1_RECORDED_SEPARATELY'
            and image['assessment']['vendorSourceSupplement']['rawArtifactsRewritten'] is False,
            'GEN33_ORIGINAL_INPUT_AND_VENDOR_SOURCE_DISTINCT')
    for key in ("licenceRebinding", "mongoV2LegalDelta", "vendorSourceProfile"):
        item = lock[key]
        read_bound(root, item["path"], item["sha256"])
    build = lock["qualification"]
    require(build["vulnerabilitySubgate"] == "PASS_RAW" and build["rawSeverityCounts"] ==
            dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), 0), "GEN33_FRESH_SCAN_REQUIRED")
    require(lock["buildProfile"]["binaryDependencyModules"] == 214 and lock["buildProfile"]["compiledPackages"] == 1532,
            "GEN33_COMPILED_INVENTORY_REQUIRED")

    cohort_zip = read_bound(root, COHORT_ZIP, COHORT_ZIP_SHA)
    runtime_zip = read_bound(root, RUNTIME_ZIP, RUNTIME_ZIP_SHA)
    require(len(cohort_zip) == COHORT_BYTES and len(runtime_zip) == RUNTIME_BYTES, "GEN33_HOSTED_ZIP_BYTES")
    cohort_files, raw = checked_zip(cohort_zip, 17), checked_zip(runtime_zip, 68)
    for name, data in cohort_files.items():
        require(raw["cohort/" + name] == data, "GEN33_COHORT_RUNTIME_BYTE_BINDING:" + name)
    require(cohort_files[PurePosixPath(LOCK).name] == lock_raw, "GEN33_ARCHIVED_LOCK_CHANGED")
    require(sha(cohort_files["cohort-receipt.json"]) == INNER_COHORT_SHA, "GEN33_INNER_COHORT_CHANGED")
    inner = json.loads(cohort_files["cohort-receipt.json"])
    local=json.loads(read_bound(root, 'evidence/seaweedfs-generation33-cohort-replay-local-20261104.json', LOCAL_COHORT_SHA))
    require(inner == local['cohortReceipt'], 'GEN33_HOSTED_LOCAL_COHORT_REPLAY_MISMATCH')
    result = json.loads(raw["runtime-result.json"])
    for item in (lock, image, inner, result):
        require(item["releaseAdmitted"] is False and item["runtimeAuthorityIssued"] is False
                and item["targetOperations"] == 0, "GEN33_NO_RUNTIME_AUTHORITY")
    for item in (inner, result):
        require(item["generation"] == 33 and item["candidateLockSha256"] == LOCK_SHA
                and item["binarySha256"] == binary and item["ociManifestDigest"] == oci, "GEN33_RUNTIME_IDENTITY")
    require(inner["status"] == "TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED" and
            inner["licenceReview"] == inner["durableImageCustody"] == "OPEN"
            and inner["redistributionAccepted"] is False and inner["readbackReproduced"] is True,
            "GEN33_COHORT_SCOPE")
    require(inner["legalTextRebindingSha256"] == lock["licenceRebinding"]["sha256"] ==
            sha(cohort_files["licence-rebinding.json"]), "GEN33_LEGAL_BINDING")
    require(inner["mongoV2LegalDeltaSha256"] == lock["mongoV2LegalDelta"]["sha256"], "GEN33_MONGO_LEGAL_DELTA")
    for name, field in (("modified-raftstore-source.tar.gz", "archiveSha256"),
                        ("modified-raftstore-source-manifest.json", "manifestSha256")):
        require(sha(cohort_files[name]) == lock["modifiedMplSource"][field], "GEN33_LOCAL_MPL_BYTES")
    legal = json.loads(cohort_files["licence-rebinding.json"])
    require(inner['vendorSourceProfile'] == lock['vendorSourceProfile']
            and legal['modifiedVendorDependency'] == inner['modifiedVendorDependency']
            and legal['vendoredBuildInfoH1Fields'] == 'EMPTY_UNCHANGED'
            and legal['originalInputOriginsReverified'] is True, 'GEN33_VENDOR_ORIGINAL_CHECKSUM_BOUNDARY')
    modified=inner['modifiedVendorDependency']
    require(json.loads(cohort_files['modified-iceberg/manifest.json']) == modified
            and modified['originalChecksumsDescribeModifiedSource'] is False
            and modified['canonicalScannerIdentityModified'] is False
            and modified['canonicalSpdxIdentityModified'] is False
            and modified['downstreamNoticePresent'] is True, 'GEN33_MODIFIED_SOURCE_MANIFEST')
    for name,field in [('config/config.go.original','originalConfigSha256'),
                       ('config/config.go.modified','modifiedConfigSha256'),('downstream.patch','patchSha256')]:
        require(sha(cohort_files['modified-iceberg/'+name]) == modified[field], 'GEN33_MODIFIED_SOURCE_BYTES')
    for name,item in modified['originalLegalTexts'].items():
        require(sha(cohort_files['modified-iceberg/'+name]) == item['sha256']
                and len(cohort_files['modified-iceberg/'+name]) == item['bytes'], 'GEN33_ORIGINAL_NOTICE_BYTES')
    modules = [json.loads(line)['Path'] for line in cohort_files['module-downloads.jsonl'].split(b'\n') if line]
    require(len(modules) == len(set(modules)) == legal["thirdPartyModules"] == 214 and
            legal["thirdPartyLegalTexts"] == 302 and legal["mplSourceArchivesReverified"] == 7,
            "GEN33_LEGAL_INVENTORY")
    require(not set(modules).intersection(ARCHIVED_REMOVED) and "go.yaml.in/yaml/v3" in modules and
            "go.mongodb.org/mongo-driver/v2" in modules, "GEN33_MAINTENANCE_BOUNDARY")

    require(result["status"] == "SYNTHETIC_COLD_MIME_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE" and
            result["cohortReceiptSha256"] == INNER_COHORT_SHA and result["octetStreamBeforeAndAfterRestore"] == "PASS"
            and result["buildManifestSha256"] == manifest["sha256"]
            and result["acceptanceTestsPassed"] == result["gatesClosed"] == 0 and result["labsSequential"] is True
            and result["maximumConcurrentContainers"] == 4, "GEN33_SYNTHETIC_RUNTIME_REQUIRED")
    sources = json.loads(raw["source-sha256.json"])
    require(len(sources) == 18, "GEN33_RUNTIME_SOURCE_COUNT")
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
            "GEN33_EXACT_COLD_RUNTIME_REQUIRED")
    require(identity["s3CasesPassed"] == result["identityS3Cases"] == 23 and
            identity["tlsNegativesPassed"] == result["tlsNegatives"] == 2 and
            identity["egressProbesPassed"] == result["egressProbes"] == 2, "GEN33_IDENTITY_COUNTS")
    containers = [row for name, data in raw.items() if name.endswith("containers.json") for row in json.loads(data)]
    stops = [json.loads(data) for name, data in raw.items() if name.endswith("-stopped.json")]
    require(len(containers) == len({item["Id"] for item in containers}) == len(stops) == 12 and
            all(stop["ExitCode"] == 0 and stop["Running"] is False for stop in stops), "GEN33_DISTINCT_CLEAN_CONTAINERS")
    backup_bytes = sum(item["bytes"] for item in backup.values())
    return lock, image, inner, result, sources, legal, backup_bytes


def current_view33(history, lock, legal, backup_bytes):
    current = copy.deepcopy(history["currentQualification"])
    current.update(generation=33, candidateLock=LOCK, candidateLockSha256=LOCK_SHA,
                   qualifiedImagePatchCount=33, repositoryPatchCount=33,
                   binarySha256=lock["buildProfile"]["binarySha256"],
                   ociManifestDigest=lock["image"]["manifestDigest"], imageConfigDigest=lock["image"]["configDigest"],
                   qualificationRunId=lock["qualification"]["runId"], imageReceipt=IMAGE, imageReceiptSha256=IMAGE_SHA,
                   cohortReceipt=COHORT, cohortReceiptSha256=COHORT_SHA, cohortRunId=RUN,
                   runtimeReceipt=RUNTIME, runtimeReceiptSha256=RUNTIME_SHA, runtimeRunId=RUN, runtimeJobId=JOBS[-1],
                   buildProfile="OUF_STANDARD_VENDOR_WITH_MAINTAINED_YAML_WITHOUT_EXCLUDED_ADAPTERS",
                   excludedBuildTags=["elastic", "rclone", "kafka", "openbao", "vault", "gcs", "google_pub_sub", "googlecloud"])
    current['sourcePatchCount']=32
    current['dependencyPatchCount']=1
    current['vendorSourceProfile']=copy.deepcopy(lock['vendorSourceProfile'])
    current['modifiedVendorDependency']=copy.deepcopy(legal['modifiedVendorDependency'])
    current['vendorBuildInfoH1']='EMPTY_BY_DESIGN_ORIGINAL_ZIP_H1_SEPARATE'
    current["licenceRawUnknownClassifications"] = len(legal["historicalUnknownClassifications"])
    current["licenceRawUnknownClassificationsScope"] = "HISTORICAL_CORPUS_REVIEW_OPEN"
    current["syntheticRuntime"]["backupBytes"] = backup_bytes
    current["mimeCorrection"]["status"] = "EXACT_GENERATION33_SYNTHETIC_REGRESSION_PASS"
    current["dependencyLifecycle"] = {
        "status": "OPEN", "allDependenciesMaintained": False, "compiledModules": 214, "compiledPackages": 1532,
        "historicalGeneration29InventoryReference": "historicalQualification29.dependencyLifecycle.widerInventoryAssessment",
        "archivedModulesRemovedFromGeneration29Binary": ARCHIVED_REMOVED,
        "remainingArchivedCompiledModulesFromCensus29": [],
        "remainingArchivedCompiledModulesOverall": "NOT_YET_COMPLETE",
        "unknownOriginAssumedMaintained": False, "widerMaintenanceAssessment": "OPEN",
        "targetFeatureBinding": "OPEN", "priorRuntimeQualificationTransferred": False,
        "moduleGraphEradicationClaimed": False, "mongoDriverMajor": 2,
        "excludedGoogleFeatures": history["currentQualification"]["dependencyLifecycle"]["excludedGoogleFeatures"],
    }
    return current


def recovery_view():
    return {'coordinatedGeneration32Receipt':COORDINATED,'coordinatedGeneration32ReceiptSha256':COORDINATED_SHA,
            'publicationFenceFixtureReceipt':FENCE,'publicationFenceFixtureReceiptSha256':FENCE_SHA,
            'generation33RuntimeProofTransferred':False,'targetWriterFenceQualified':False,
            'externalS3WritesFenced':False,'simultaneousRecoveryCutQualified':False,'pitrQualified':False,
            'rpoAcceptance':False,'rtoAcceptance':False,'targetOperations':0,'gatesClosed':0,'acceptanceTestsPassed':0}


def progress_view(previous):
    value=copy.deepcopy(previous)
    require(value['creditsPercent'] == [50,85,60,35,35,0,0,0] and value['weightedCredits']==17.5,
            'GEN33_EXACT_PREVIOUS_PROGRESS_REQUIRED')
    value.update(date='2026-11-04',creditsPercent=[50,85,60,45,35,0,0,0],weightedCredits=18.3,
                 exactWeightedEstimatePercent=18.3/46*100,reportedApproximatePercent=40)
    value['creditChange']={'workPackage':'SW-WP3','previousCreditPercent':35,'currentCreditPercent':45,
        'receipts':[{'path':COORDINATED,'sha256':COORDINATED_SHA},{'path':FENCE,'sha256':FENCE_SHA}],
        'reason':'Synthetic PostgreSQL17.11 logical restore reconciled with independently cold-restored exact OCI32 S3 objects, plus separate native PostgreSQL publication-fence fixture with two concurrent clients, restart and ambiguous-effect reconciliation. Engineering work credit only; no proof transfer to OCI33 and no target acceptance.',
        'remaining':['External S3 and deployed writer fencing','Simultaneous PostgreSQL/S3 recovery cut and WAL/PITR',
                     'Crash/reboot and complete source-host loss','TLS/key rotation',
                     'Representative capacity, RPO and RTO acceptance','Full foundation backup contract and durable image custody']}
    return value


def validate_recovery_credit(root,plan,historical):
    require(plan['progressEstimate']==progress_view(historical['progressEstimate']), 'GEN33_EXACT_ENGINEERING_CREDIT_REQUIRED')
    for path,digest,run,inner_field,member,count in [
        (COORDINATED,COORDINATED_SHA,41782068196,'receipt','lab/evidence/receipt.json',98),
        (FENCE,FENCE_SHA,41794344238,'nativeReceipt','lab/receipt.json',104)]:
        receipt=json.loads(read_bound(root,path,digest))
        require(receipt['workflowRunId']==run and receipt['workflowConclusion']=='success'
                and receipt['preserved']['consumedScopes']==17 and receipt['preserved']['cumulativeEngineGets']==52
                and receipt['preserved']['minioActive'] is True,'GEN33_RECOVERY_HOSTED_SCOPE')
        item=receipt['originalArtifact'];raw=read_bound(root,item['path'],item['sha256'])
        require(len(raw)==item['bytes'],'GEN33_RECOVERY_ARCHIVE_SIZE')
        members=checked_zip(raw,count)
        inner=receipt[inner_field]
        require(json.loads(members[member])==inner,'GEN33_RECOVERY_RECEIPT_ORIGINAL_BYTES')
        require(inner['targetOperations']==inner['acceptanceTestsPassed']==inner['gatesClosed']==0
                and inner['releaseAdmitted'] is False and inner['runtimeAuthorityIssued'] is False
                and inner['pitrQualified'] is False and inner['simultaneousRecoveryCutQualified'] is False
                and inner['rpoMeasured'] is False and inner['rtoMeasured'] is False,'GEN33_RECOVERY_NOT_ACCEPTANCE')
        for row in receipt['sourceBindingsVerifiedAgainstExactGitTree']:
            data=read_bound(root,row['path'],row['sha256'])
            require(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==row['gitBlobSha'],
                    'GEN33_RECOVERY_SOURCE_BLOB')
        if path==COORDINATED:
            require(inner['status']=='SYNTHETIC_POSTGRES_AND_COLD_S3_RESTORE_PASS'
                    and inner['lockSha256']=='91a7c874deb5b11f1a18dc483e99f6031644b62abb769a9e11ff1ad29250fb7d'
                    and inner['twoIndependentColdRoots'] is True and inner['s3ObjectsReconciled']==3
                    and inner['s3ObjectBytesRead']==1064 and inner['writerFenceEnforced'] is False
                    and inner['livePostgresRecoveryQualified'] is False,'GEN33_HISTORICAL32_RECOVERY_BOUNDARY')
        else:
            require(inner['status']=='NATIVE_SYNTHETIC_PUBLICATION_FENCE_PASS'
                    and inner['checkCount']==23 and inner['realConcurrentClients']==2
                    and inner['oneRestartPreservedState'] is True and inner['unresolvedIntentsBlockFreeze'] is True
                    and inner['publicationFenceEnforcedInFixture'] is True
                    and inner['externalStorageWritesFenced'] is False and inner['targetWriterFenceQualified'] is False,
                    'GEN33_PUBLICATION_FIXTURE_NOT_S3_FENCE')


def validate_tree33(root, plan, historical_validator):
    historical = restore_generation32_plan(plan)
    previous = historical_validator(root, historical)
    validate_recovery_credit(root,plan,historical)
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
                "GEN33_HOSTED_RECEIPT_REQUIRED")
    require(runtime["sourceHashesVerified"] == sources and runtime["backupBytes"] == backup_bytes,
            "GEN33_RUNTIME_RECEIPT_RAW_BINDING")
    require(plan["currentQualification"] == current_view33(historical, lock, legal, backup_bytes),
            "GEN33_EXACT_CURRENT_VIEW_REQUIRED")
    previous.update(currentGeneration=33, historicalGeneration32QualifiedImagePatchCount=32,
                    repositoryPatchCount=33, qualifiedImagePatchCount=33, candidateLockSha256=LOCK_SHA,
                    generation33ImageReceiptSha256=IMAGE_SHA, generation33CohortReceiptSha256=COHORT_SHA,
                    generation33RuntimeReceiptSha256=RUNTIME_SHA, generation33MimeRegression="PASS_SYNTHETIC_ONLY",
                    progressPercent=plan['progressEstimate']['exactWeightedEstimatePercent'],
                    planningProgressEstimatePercent=plan['progressEstimate']['reportedApproximatePercent'],
                    weightedPlanningCredits=plan['progressEstimate']['weightedCredits'],
                    currentBinaryModules=214, currentCompiledPackages=1532, historicalProofTransferredToGeneration33=False)
    return previous
