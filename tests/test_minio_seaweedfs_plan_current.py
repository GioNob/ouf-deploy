import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "plan_current", ROOT / "scripts/verify-minio-seaweedfs-plan-current.py"
)
plan_current = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan_current)


class CurrentStoragePlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current_plan = plan_current.generation29_view(json.loads((ROOT / plan_current.PLAN_PATH).read_bytes()))
        cls.plan = plan_current.historical_plan_view(cls.current_plan)
        cls.lock_bytes = (ROOT / plan_current.LOCK_PATH).read_bytes()
        cls.lock = json.loads(cls.lock_bytes)
        cls.cohort = json.loads((ROOT / plan_current.COHORT_PATH).read_bytes())
        cls.source_receipt_bytes = (ROOT / plan_current.SOURCE_CLOSURE_PATH).read_bytes()
        cls.source_receipt = json.loads(cls.source_receipt_bytes)
        cls.patch_hashes = {path: plan_current.sha256((ROOT / path).read_bytes()) for path in plan_current.EXPECTED_SOURCE_PATCHES}
        cls.standard_bytes = (ROOT / plan_current.STANDARD_RECEIPT_PATH).read_bytes()
        cls.standard = json.loads(cls.standard_bytes)
        cls.defect_bytes = (ROOT / plan_current.MIME_DEFECT_PATH).read_bytes()
        cls.defect = json.loads(cls.defect_bytes)
        cls.standard_files = plan_current.read_standard_evidence(ROOT, cls.standard)
        cls.cold_bytes = (ROOT / plan_current.COLD_RECEIPT_PATH).read_bytes()
        cls.cold = json.loads(cls.cold_bytes)
        cls.cold_files = plan_current.read_cold_evidence(ROOT, cls.cold)
        cls.image29_bytes = (ROOT / plan_current.IMAGE29_RECEIPT_PATH).read_bytes()
        cls.image29 = json.loads(cls.image29_bytes)
        cls.image29_manifest_bytes = (ROOT / plan_current.IMAGE29_MANIFEST_PATH).read_bytes()
        cls.dossiers = {
            path: json.loads((ROOT / path).read_bytes())
            for path in plan_current.EXPECTED_DOSSIERS
        }

    def validate(self, *, plan=None, lock=None, lock_bytes=None, cohort=None, dossiers=None, receipt=None, receipt_bytes=None, patch_hashes=None):
        selected_plan = copy.deepcopy(self.plan if plan is None else plan)
        selected_receipt = copy.deepcopy(self.source_receipt if receipt is None else receipt)
        selected_bytes = self.source_receipt_bytes if receipt_bytes is None else receipt_bytes
        if receipt is not None and receipt_bytes is None:
            selected_bytes = (json.dumps(selected_receipt, indent=2) + "\n").encode()
            selected_plan["currentQualification"]["sourceClosureReceiptSha256"] = plan_current.sha256(selected_bytes)
        return plan_current.validate_documents(
            selected_plan,
            copy.deepcopy(self.lock if lock is None else lock),
            self.lock_bytes if lock_bytes is None else lock_bytes,
            copy.deepcopy(self.cohort if cohort is None else cohort),
            copy.deepcopy(self.dossiers if dossiers is None else dossiers),
            selected_receipt,
            selected_bytes,
            copy.deepcopy(self.patch_hashes if patch_hashes is None else patch_hashes),
        )

    def test_repository_current_plan_passes(self):
        result = plan_current.validate_tree(ROOT)
        self.assertEqual(result["status"], "PASS_NOT_ADMITTED")
        self.assertEqual(result["remainingRepositoryDirectSdkV1Importers"], 0)
        self.assertEqual(result["repositoryPatchCount"], 33)
        self.assertEqual(result["qualifiedImagePatchCount"], 33)
        self.assertEqual(result["historicalQualifiedImagePatchCount"], 15)
        self.assertEqual(result["generation29MimeRegression"], "PASS_SYNTHETIC_ONLY")
        self.assertEqual(result["hostedSourceClosureRunCount"], 6)
        self.assertFalse(result["optionalModuleGraphEradicationClaimed"])
        self.assertFalse(result["releaseAdmitted"])
        self.assertEqual(result["activeStorageBackend"], "MinIO")

    def test_cold_receipt_and_raw_bytes_are_both_required(self):
        plan_current.validate_cold_evidence(self.plan, self.cold, self.cold_bytes, self.cold_files)
        with self.assertRaisesRegex(ValueError, "COLD_RECEIPT_BYTES_CHANGED"):
            plan_current.validate_cold_evidence(self.plan, self.cold, self.cold_bytes + b"\n", self.cold_files)
        changed = dict(self.cold_files)
        changed["recovery-result.json"] = changed["recovery-result.json"].replace(b"true", b"null", 1)
        with self.assertRaisesRegex(ValueError, "COLD_EVIDENCE_BYTES_MISMATCH"):
            plan_current.validate_cold_evidence(self.plan, self.cold, self.cold_bytes, changed)
        missing = dict(self.cold_files)
        del missing["exact-image.json"]
        with self.assertRaisesRegex(ValueError, "COLD_EVIDENCE_MEMBER_SET_REQUIRED"):
            plan_current.validate_cold_evidence(self.plan, self.cold, self.cold_bytes, missing)

    def test_cold_recovery_cannot_be_transferred_to_new_image(self):
        for field, value, code in (
            ("transferredToGeneration29", True, "COLD_GENERATION15_ONLY_REQUIRED"),
            ("orderedImagePatchCount", 29, "COLD_GENERATION15_ONLY_REQUIRED"),
            ("ociManifestDigest", "sha256:" + "0" * 64, "COLD_CANDIDATE15_BINDING_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["historicalRuntimeQualification"]["coldRecovery15"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                plan_current.validate_cold_evidence(changed, self.cold, self.cold_bytes, self.cold_files)

    def test_cold_restore_success_does_not_close_mime_or_acceptance(self):
        for field, value, code in (
            ("octetStreamCompatibility", "PASS", "COLD_MIME_DEFECT_MUST_REMAIN_FAIL"),
            ("g2Closed", True, "COLD_NO_ACCEPTANCE_OR_AUTHORITY_REQUIRED"),
            ("g3Closed", True, "COLD_NO_ACCEPTANCE_OR_AUTHORITY_REQUIRED"),
            ("rpoAcceptance", True, "COLD_NO_ACCEPTANCE_OR_AUTHORITY_REQUIRED"),
            ("rtoAcceptance", True, "COLD_NO_ACCEPTANCE_OR_AUTHORITY_REQUIRED"),
            ("postgresRecovery", "PASS", "COLD_NO_TARGET_OR_POSTGRES_CLAIM_REQUIRED"),
            ("targetOperations", 1, "COLD_NO_TARGET_OR_POSTGRES_CLAIM_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["historicalRuntimeQualification"]["coldRecovery15"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                plan_current.validate_cold_evidence(changed, self.cold, self.cold_bytes, self.cold_files)

    def test_cold_preserved_paths_reject_traversal_and_duplicates(self):
        for value, code in (
            (plan_current.COLD_EVIDENCE_DIR + "/../outside.json", "COLD_EVIDENCE_PATH_INVALID"),
            (self.cold["rawEvidencePreservation"]["files"][1]["path"], "COLD_EVIDENCE_DUPLICATE"),
        ):
            changed = copy.deepcopy(self.cold)
            changed["rawEvidencePreservation"]["files"][0]["path"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, code):
                plan_current.read_cold_evidence(ROOT, changed)

    def test_progress_credit_is_bound_to_actual_cold_evidence(self):
        changed = copy.deepcopy(self.plan)
        changed["progressEstimate"]["creditChange"]["receiptSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "COLD_PROGRESS_EVIDENCE_REQUIRED"):
            self.validate(plan=changed)

    def test_generation29_requires_exact_readback_and_manifest_bytes(self):
        plan_current.validate_generation29_image(self.plan, self.image29, self.image29_bytes, self.image29_manifest_bytes)
        with self.assertRaisesRegex(ValueError, "IMAGE29_RECEIPT_BYTES_REQUIRED"):
            plan_current.validate_generation29_image(self.plan, self.image29, self.image29_bytes + b"\n", self.image29_manifest_bytes)
        with self.assertRaisesRegex(ValueError, "IMAGE29_BUILD_MANIFEST_BYTES_REQUIRED"):
            plan_current.validate_generation29_image(self.plan, self.image29, self.image29_bytes, self.image29_manifest_bytes + b"\n")

    def test_generation29_does_not_inherit_old_binary_or_runtime_proof(self):
        for field, value, code in (
            ("binarySha256", self.plan["currentQualification"]["binarySha256"], "IMAGE29_CONTENT_BINDING_REQUIRED"),
            ("ociManifestDigest", self.plan["currentQualification"]["ociManifestDigest"], "IMAGE29_CONTENT_BINDING_REQUIRED"),
            ("oldRuntimeEvidenceTransferred", True, "IMAGE29_NO_RUNTIME_PROOF_TRANSFER_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["generation29Qualification"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                plan_current.validate_generation29_image(changed, self.image29, self.image29_bytes, self.image29_manifest_bytes)

    def test_generation29_phase_a_cannot_claim_cohort_runtime_or_admission(self):
        for field, value, code in (
            ("phaseBHostedCohort", "PASS", "IMAGE29_COHORT_AND_RUNTIME_PENDING_REQUIRED"),
            ("runtimeLabs29", "PASS", "IMAGE29_COHORT_AND_RUNTIME_PENDING_REQUIRED"),
            ("licenceReview", "CLOSED", "IMAGE29_OPEN_GATES_REQUIRED"),
            ("durableImageCustody", "ESTABLISHED", "IMAGE29_OPEN_GATES_REQUIRED"),
            ("redistributionAccepted", True, "IMAGE29_NO_ADMISSION_OR_AUTHORITY_REQUIRED"),
            ("releaseAdmitted", True, "IMAGE29_NO_ADMISSION_OR_AUTHORITY_REQUIRED"),
            ("runtimeAuthorityIssued", True, "IMAGE29_NO_ADMISSION_OR_AUTHORITY_REQUIRED"),
            ("targetOperations", 1, "IMAGE29_NO_TARGET_CHANGE_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["generation29Qualification"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                plan_current.validate_generation29_image(changed, self.image29, self.image29_bytes, self.image29_manifest_bytes)

    def test_generation29_signature_scope_is_precise(self):
        changed = copy.deepcopy(self.plan)
        changed["generation29Qualification"]["localCryptographicSignatureVerificationClaimed"] = True
        with self.assertRaisesRegex(ValueError, "IMAGE29_NO_LOCAL_CRYPTO_CLAIM_REQUIRED"):
            plan_current.validate_generation29_image(changed, self.image29, self.image29_bytes, self.image29_manifest_bytes)

    def test_historical_451_and_current_452_are_separate(self):
        self.assertEqual(self.plan["candidate"]["initialVersionToEvaluate"], "4.51")
        self.assertEqual(self.plan["currentQualification"]["version"], "4.52")
        self.assertFalse(self.plan["currentQualification"]["historicalApplicabilityApplied"])
        self.assertEqual(self.plan["historicalEvidenceFields"], plan_current.HISTORICAL_FIELDS)

    def test_historical_evidence_blocks_are_byte_value_stable(self):
        changed = copy.deepcopy(self.plan)
        changed["dependencyLifecycleReview"]["status"] = "CLOSED"
        with self.assertRaisesRegex(ValueError, "HISTORICAL_EVIDENCE_CHANGED"):
            self.validate(plan=changed)

    def test_candidate_lock_is_immutable_and_hash_bound(self):
        self.validate()
        with self.assertRaisesRegex(ValueError, "CANDIDATE_LOCK_BYTES_CHANGED"):
            self.validate(lock_bytes=self.lock_bytes + b"\n")

    def test_admission_authority_and_target_operations_fail_closed(self):
        for key, value, code in (
            ("releaseAdmitted", True, "CURRENT_NOT_ADMITTED_REQUIRED"),
            ("runtimeAuthorityIssued", True, "CURRENT_NO_RUNTIME_AUTHORITY_REQUIRED"),
            ("targetOperations", 1, "CURRENT_ZERO_TARGET_OPERATIONS_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(plan=changed)

    def test_gate_acceptance_and_object_counts_fail_closed(self):
        for key, value, code in (
            ("gatePass", 1, "ZERO_OF_EIGHT_GATES_REQUIRED"),
            ("acceptanceTestPass", 1, "ZERO_OF_TWENTY_ONE_AT_REQUIRED"),
            ("realObjectsCopied", 1, "ZERO_OF_ONE_HUNDRED_TWENTY_OBJECTS_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["progressEstimate"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(plan=changed)

    def test_progress_is_recomputed_from_original_weights(self):
        self.assertAlmostEqual(
            self.plan["progressEstimate"]["exactWeightedEstimatePercent"],
            17.5 / 46 * 100,
        )
        changed = copy.deepcopy(self.plan)
        changed["progressEstimate"]["weightedCredits"] = 16
        with self.assertRaisesRegex(ValueError, "WEIGHTED_CREDITS_REQUIRED"):
            self.validate(plan=changed)

    def test_hosted_test_dossier_sequence_is_exact(self):
        changed = copy.deepcopy(self.dossiers)
        changed[plan_current.EXPECTED_DOSSIERS[-1]]["directAwsSdkV1ImportersAfter"] = 22
        with self.assertRaisesRegex(ValueError, "DOSSIER_IMPORTER_SEQUENCE_REQUIRED"):
            self.validate(dossiers=changed)
        changed = copy.deepcopy(self.dossiers)
        changed[plan_current.EXPECTED_DOSSIERS[-1]]["workflow"]["status"] = "LOCAL_PASS"
        with self.assertRaisesRegex(ValueError, "HOSTED_PASS_REQUIRED"):
            self.validate(dossiers=changed)

    def test_minio_and_consumed_scope_remain_frozen(self):
        changed = copy.deepcopy(self.plan)
        changed["currentQualification"]["activeStorageBackend"] = "SeaweedFS"
        with self.assertRaisesRegex(ValueError, "MINIO_MUST_REMAIN_ACTIVE"):
            self.validate(plan=changed)
        changed = copy.deepcopy(self.plan)
        changed["invariants"]["cumulativeEngineGets"] = 53
        with self.assertRaisesRegex(ValueError, "ENGINE52_REQUIRED"):
            self.validate(plan=changed)

    def test_source_receipt_must_be_hosted_pass_and_six_distinct_successes(self):
        for status in ("LOCAL_PASS", "HOSTED_PENDING", "HOSTED_FAIL"):
            changed = copy.deepcopy(self.source_receipt)
            changed["status"] = status
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_HOSTED_PASS_REQUIRED"):
                self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"].pop()
        with self.assertRaisesRegex(ValueError, "SIX_HOSTED_WORKFLOWS_REQUIRED"):
            self.validate(receipt=changed)
        for conclusion in ("failure", "cancelled", "in_progress", None):
            changed = copy.deepcopy(self.source_receipt)
            changed["workflows"][0]["conclusion"] = conclusion
            with self.subTest(conclusion=conclusion), self.assertRaisesRegex(ValueError, "ALL_HOSTED_RUNS_SUCCESS_REQUIRED"):
                self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["runId"] = changed["workflows"][1]["runId"]
        with self.assertRaisesRegex(ValueError, "UNIQUE_HOSTED_RUN_AND_JOB_IDS_REQUIRED"):
            self.validate(receipt=changed)

    def test_pending_view_resolves_only_through_hosted_receipt(self):
        changed = copy.deepcopy(self.plan)
        changed["pendingRepositoryQualification"]["status"] = "LOCAL_EXACT_PASS_HOSTED_PENDING"
        with self.assertRaisesRegex(ValueError, "PENDING_QUALIFICATION_RESOLVED_REQUIRED"):
            self.validate(plan=changed)
        changed = copy.deepcopy(self.plan)
        changed["pendingRepositoryQualification"]["currentQualificationRetainedUntilHostedPass"] = False
        with self.assertRaisesRegex(ValueError, "HOSTED_PROMOTION_CONDITION_PRESERVED_REQUIRED"):
            self.validate(plan=changed)

    def test_exact_workflow_identity_and_source_are_required(self):
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["name"] = changed["workflows"][1]["name"]
        with self.assertRaisesRegex(ValueError, "EXACT_HOSTED_WORKFLOW_SET_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["headSha"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "HOSTED_RUN_SOURCE_HEAD_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["sourceHead"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_HEAD_REQUIRED"):
            self.validate(receipt=changed)

    def test_zero_source_importers_does_not_allow_incomplete_scan(self):
        changed = copy.deepcopy(self.source_receipt)
        changed["directSourceImporters"] = 1
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_ZERO_IMPORTERS_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        workflow = next(w for w in changed["workflows"] if w["name"] != "storage-kafka-module-cleanup")
        workflow["directImporters"] = 1
        with self.assertRaisesRegex(ValueError, "HOSTED_RUN_ZERO_IMPORTERS_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        workflow = next(w for w in changed["workflows"] if w["name"] != "storage-kafka-module-cleanup")
        next(f for f in workflow["fileManifest"] if f["file"] == "remaining-direct-importers.txt")["size"] = 1
        with self.assertRaisesRegex(ValueError, "HOSTED_EMPTY_IMPORTER_SCAN_REQUIRED"):
            self.validate(receipt=changed)
        for field in ("remainingRepositoryDirectSdkV1Importers", "remainingIamTestImporters", "remainingOtherTestImporters"):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"][field] = 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(plan=changed)

    def test_receipt_hash_lock_and_patch27_are_bound(self):
        with self.assertRaisesRegex(ValueError, "SOURCE_CLOSURE_RECEIPT_HASH_MISMATCH"):
            self.validate(receipt_bytes=self.source_receipt_bytes + b"\n")
        for key, value, code in (
            ("candidateLockSha256", "0" * 64, "SOURCE_RECEIPT_LOCK_REQUIRED"),
            ("patchCount", 26, "SOURCE_RECEIPT_PATCH27_REQUIRED"),
        ):
            changed = copy.deepcopy(self.source_receipt)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["patchHashes"]["patches/seaweedfs/4.52-iam-module-sdk-v2.patch"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_PATCH_HASHES_REQUIRED"):
            self.validate(receipt=changed)
        changed_hashes = copy.deepcopy(self.patch_hashes)
        changed_hashes["patches/seaweedfs/4.52-iam-module-sdk-v2.patch"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SOURCE_PATCH_BYTES_CHANGED"):
            self.validate(patch_hashes=changed_hashes)

    def test_all_artifacts_need_verified_download_and_graph_manifest_binding(self):
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["artifact"]["downloadVerified"] = False
        with self.assertRaisesRegex(ValueError, "HOSTED_ARTIFACT_DOWNLOAD_VERIFIED_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["artifact"]["sha256"] = "unverified"
        with self.assertRaisesRegex(ValueError, "HOSTED_ARTIFACT_SHA256_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["dependencyGraphs"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "HOSTED_DEPENDENCY_GRAPH_MANIFEST_BINDING_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["dependencyGraphs"][0]["sdkV1Packages"] = 1
        with self.assertRaisesRegex(ValueError, "HOSTED_DEPENDENCY_GRAPH_NO_SDKV1_REQUIRED"):
            self.validate(receipt=changed)

    def test_binary_identity_and_optional_module_limits_remain_explicit(self):
        changed = copy.deepcopy(self.source_receipt)
        changed["qualifiedBinary"]["byteIdentical"] = False
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_BINARY_IDENTITY_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["qualifiedBinary"]["productionGraphSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_PRODUCTION_GRAPH_HASH_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["optionalModuleGraphEradicationClaimed"] = True
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_MODULE_LIMIT_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.source_receipt)
        changed["limits"]["optionalBuildTagsStillOpen"] = []
        with self.assertRaisesRegex(ValueError, "SOURCE_RECEIPT_OPTIONAL_TAGS_REQUIRED"):
            self.validate(receipt=changed)
        changed = copy.deepcopy(self.plan)
        changed["currentQualification"]["optionalModuleDependencyLimits"]["moduleGraphEradicationClaimed"] = True
        with self.assertRaisesRegex(ValueError, "OPTIONAL_MODULE_LIMITS_REQUIRED"):
            self.validate(plan=changed)

    def test_source_closure_does_not_promote_recovery_or_target_acceptance(self):
        for key, value, code in (
            ("releaseAdmitted", True, "SOURCE_RECEIPT_NOT_ADMITTED_REQUIRED"),
            ("runtimeAuthorityIssued", True, "SOURCE_RECEIPT_NO_AUTHORITY_REQUIRED"),
            ("targetOperations", 1, "SOURCE_RECEIPT_ZERO_TARGET_REQUIRED"),
            ("liveIamRoundtripPerformed", True, "SOURCE_RECEIPT_LIVE_IAM_LIMIT_REQUIRED"),
            ("remainingNestedKafkaModulesQualified", True, "SOURCE_RECEIPT_NESTED_KAFKA_LIMIT_REQUIRED"),
            ("consumedScopeCount", 18, "SOURCE_RECEIPT_SCOPE17_REQUIRED"),
            ("cumulativeEngineGets", 53, "SOURCE_RECEIPT_ENGINE52_REQUIRED"),
        ):
            changed = copy.deepcopy(self.source_receipt)
            changed["limits"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(receipt=changed)
        changed = copy.deepcopy(self.plan)
        changed["progressEstimate"]["creditsPercent"][3] = 30
        with self.assertRaisesRegex(ValueError, "PROGRESS_CREDITS_REQUIRED"):
            self.validate(plan=changed)

    def test_preserved_raw_evidence_rejects_missing_and_changed_bytes(self):
        workflow = self.source_receipt["workflows"][0]
        directory = ROOT / "evidence/sdk27-artifacts" / str(workflow["runId"])
        archived = {"SHA256SUMS": (directory / "SHA256SUMS").read_bytes()}
        archived.update({entry["file"]: (directory / entry["file"]).read_bytes() for entry in workflow["fileManifest"]})
        plan_current.validate_archived_workflow(workflow, archived)
        member = workflow["fileManifest"][0]["file"]
        missing = dict(archived)
        del missing[member]
        with self.assertRaisesRegex(ValueError, "ARCHIVED_EVIDENCE_MEMBER_SET_REQUIRED"):
            plan_current.validate_archived_workflow(workflow, missing)
        changed = dict(archived)
        original = changed[member]
        changed[member] = bytes([original[0] ^ 1]) + original[1:]
        with self.assertRaisesRegex(ValueError, "ARCHIVED_EVIDENCE_HASH_MISMATCH"):
            plan_current.validate_archived_workflow(workflow, changed)
        changed = dict(archived)
        changed["SHA256SUMS"] += b"\n"
        with self.assertRaisesRegex(ValueError, "ARCHIVED_MANIFEST_HASH_MISMATCH"):
            plan_current.validate_archived_workflow(workflow, changed)

    def test_preserved_raw_evidence_rejects_path_traversal(self):
        changed = copy.deepcopy(self.source_receipt)
        changed["workflows"][0]["fileManifest"][0]["file"] = "../outside.txt"
        with self.assertRaisesRegex(ValueError, "ARCHIVED_EVIDENCE_PATH_INVALID"):
            plan_current.validate_archived_tree(ROOT, changed)

    def validate_standard(self, *, plan=None, receipt=None, receipt_bytes=None, patch_sha=None, defect=None):
        selected_plan = copy.deepcopy(self.plan if plan is None else plan)
        selected_receipt = copy.deepcopy(self.standard if receipt is None else receipt)
        raw = self.standard_bytes if receipt_bytes is None else receipt_bytes
        if receipt is not None and receipt_bytes is None:
            raw = (json.dumps(selected_receipt, indent=2) + "\n").encode()
            selected_plan["currentQualification"]["standardProfileQualification"]["receiptSha256"] = plan_current.sha256(raw)
        selected_defect = copy.deepcopy(self.defect if defect is None else defect)
        defect_raw = self.defect_bytes
        if defect is not None:
            defect_raw = (json.dumps(selected_defect, indent=2) + "\n").encode()
            selected_plan["currentQualification"]["knownCompatibilityDefects"][0]["receiptSha256"] = plan_current.sha256(defect_raw)
        return plan_current.validate_standard_profile(selected_plan, selected_receipt, raw, plan_current.STANDARD_PATCH_SHA256 if patch_sha is None else patch_sha, selected_defect, defect_raw)

    def test_standard_profile_is_scoped_and_excluded_tags_stay_denied(self):
        for field, value, code in (
            ("universalUpstreamModuleClosureClaimed", True, "NO_UNIVERSAL_MODULE_CLOSURE_REQUIRED"),
            ("excludedBuildTags", [], "STANDARD_EXCLUSIONS_REQUIRED"),
            ("rootModuleGraphSdkV1", 1, "STANDARD_MODULE_ZERO_UNMAINTAINED_REQUIRED"),
            ("qualifiedImagePatchCount", 28, "STANDARD_PATCH_COUNTS_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"]["standardProfileQualification"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                self.validate_standard(plan=changed)
        changed = copy.deepcopy(self.standard)
        changed["verification"]["negativeBuildTags"] = []
        with self.assertRaisesRegex(ValueError, "STANDARD_TAG_DENIALS_REQUIRED"):
            self.validate_standard(receipt=changed)

    def test_standard_hosted_receipt_patch_and_source_are_bound(self):
        with self.assertRaisesRegex(ValueError, "STANDARD_RECEIPT_BINDING_REQUIRED"):
            self.validate_standard(receipt_bytes=self.standard_bytes + b"\n")
        with self.assertRaisesRegex(ValueError, "STANDARD_PATCH28_BINDING_REQUIRED"):
            self.validate_standard(patch_sha="0" * 64)
        for field, value, code in (
            ("jobConclusion", "failure", "STANDARD_HOSTED_SUCCESS_REQUIRED"),
            ("headSha", "0" * 40, "STANDARD_RECEIPT_SOURCE_RUN_REQUIRED"),
        ):
            changed = copy.deepcopy(self.standard)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                self.validate_standard(receipt=changed)
        changed = copy.deepcopy(self.standard)
        changed["verification"]["deprecatedManagerRootModuleGraph"] = 1
        with self.assertRaisesRegex(ValueError, "STANDARD_VERIFIED_CLOSURE_REQUIRED"):
            self.validate_standard(receipt=changed)
        changed = copy.deepcopy(self.plan)
        changed["pendingStandardProfileQualification"]["status"] = "LOCAL_PASS_HOSTED_PENDING"
        with self.assertRaisesRegex(ValueError, "STANDARD_PENDING_RESOLVED_REQUIRED"):
            self.validate_standard(plan=changed)

    def test_standard_retained_proof_rejects_missing_bytes_and_path_escape(self):
        plan_current.validate_standard_evidence(self.standard, self.standard_files)
        missing = dict(self.standard_files)
        del missing["root-module-graph.txt"]
        with self.assertRaisesRegex(ValueError, "STANDARD_EVIDENCE_MEMBER_SET_REQUIRED"):
            plan_current.validate_standard_evidence(self.standard, missing)
        changed = dict(self.standard_files)
        changed["root-module-graph.txt"] += b"unexpected-module\n"
        with self.assertRaisesRegex(ValueError, "STANDARD_EVIDENCE_BYTES_MISMATCH"):
            plan_current.validate_standard_evidence(self.standard, changed)
        receipt = copy.deepcopy(self.standard)
        receipt["verification"]["patches"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "STANDARD_RAW_PATCH_SEQUENCE_BINDING_REQUIRED"):
            plan_current.validate_standard_evidence(receipt, self.standard_files)
        receipt = copy.deepcopy(self.standard)
        receipt["retainedBoundedEvidence"]["files"]["../outside"] = receipt["retainedBoundedEvidence"]["files"].pop("root-module-graph.txt")
        with self.assertRaisesRegex(ValueError, "STANDARD_EVIDENCE_PATH_INVALID"):
            plan_current.read_standard_evidence(ROOT, receipt)

    def test_known_mime_failure_remains_open_and_does_not_invent_headers(self):
        for field, value, code in (
            ("status", "RESOLVED", "MIME_DEFECT_OPEN_REQUIRED"),
            ("failingObjectKey", "guessed-key.csv", "MIME_UNOBSERVED_VALUES_MUST_REMAIN_UNKNOWN"),
            ("actualResponseContentType", "text/csv", "MIME_UNOBSERVED_VALUES_MUST_REMAIN_UNKNOWN"),
            ("s3MetadataCompatibilityQualified", True, "MIME_COMPATIBILITY_NOT_QUALIFIED_REQUIRED"),
        ):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"]["knownCompatibilityDefects"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                self.validate_standard(plan=changed)
        changed = copy.deepcopy(self.defect)
        changed["observed"]["restoreExecuted"] = True
        with self.assertRaisesRegex(ValueError, "MIME_FAILED_RUN_NO_RESTORE_REQUIRED"):
            self.validate_standard(defect=changed)
        changed = copy.deepcopy(self.plan)
        changed["currentQualification"]["pendingCompatibilityCorrection"]["status"] = "QUALIFIED"
        with self.assertRaisesRegex(ValueError, "PRODUCTION_PATCH29_NOT_PROMOTED_REQUIRED"):
            self.validate_standard(plan=changed)

class QualifiedGeneration29PlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = plan_current.generation29_view(json.loads((ROOT / plan_current.PLAN_PATH).read_bytes()))
        cls.lock_bytes = (ROOT / plan_current.LOCK29_PATH).read_bytes()
        cls.lock = json.loads(cls.lock_bytes)
        cls.cohort_bytes = (ROOT / plan_current.COHORT29_PATH).read_bytes()
        cls.cohort = json.loads(cls.cohort_bytes)
        cls.runtime_bytes = (ROOT / plan_current.RUNTIME29_PATH).read_bytes()
        cls.runtime = json.loads(cls.runtime_bytes)
        cls.raw = plan_current.read_generation29_raw(ROOT, cls.cohort, cls.runtime)

    def validate(self, **changes):
        arguments = {"plan": copy.deepcopy(self.plan), "lock": copy.deepcopy(self.lock),
                     "lock_bytes": self.lock_bytes, "cohort": copy.deepcopy(self.cohort),
                     "cohort_bytes": self.cohort_bytes, "runtime": copy.deepcopy(self.runtime),
                     "runtime_bytes": self.runtime_bytes, "raw": dict(self.raw)}
        arguments.update(changes)
        plan_current.validate_current_generation29(**arguments)

    def test_actual_generation29_joins_independent_image_cohort_and_runtime(self):
        self.validate()
        current = self.plan["currentQualification"]
        self.assertEqual(current["qualifiedImagePatchCount"], 29)
        self.assertNotEqual(current["binarySha256"], self.plan["historicalQualification15"]["binarySha256"])
        self.assertEqual(len(self.raw), 74)

    def test_exact_receipt_and_lock_bytes_required(self):
        for key, expected in (("lock_bytes", "LOCK29_BYTES_REQUIRED"),
                              ("cohort_bytes", "COHORT29_BYTES_REQUIRED"),
                              ("runtime_bytes", "RUNTIME29_BYTES_REQUIRED")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, expected):
                self.validate(**{key: getattr(self, key) + b"\n"})

    def test_receipt_object_cannot_disagree_with_its_pinned_bytes(self):
        for key, code in (("cohort", "COHORT29_BYTES_REQUIRED"), ("runtime", "RUNTIME29_BYTES_REQUIRED")):
            changed = copy.deepcopy(getattr(self, key)); changed["status"] = "PENDING"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                self.validate(**{key: changed})

    def test_historical_image_cannot_replace_generation29_identity(self):
        for key in ("binarySha256", "ociManifestDigest", "candidateLockSha256"):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"][key] = changed["historicalQualification15"][key]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)

    def test_no_unqualified_patch_or_image_promotion(self):
        for key in ("repositoryPatchCount", "qualifiedImagePatchCount", "generation"):
            changed = copy.deepcopy(self.plan); changed["currentQualification"][key] = 30
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)
        for key, value in (("status", "QUALIFIED"), ("qualifiedGenerationRetained", 30),
                           ("progressCreditAdded", 5), ("runtimeProofTransferred", True)):
            changed = copy.deepcopy(self.plan); changed["nextGenerationPrototype"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "NEXT_PROTOTYPE_NOT_QUALIFIED_REQUIRED"):
                self.validate(plan=changed)

    def test_no_authority_custody_or_backend_promotion(self):
        for key, value in (("releaseAdmitted", True), ("runtimeAuthorityIssued", True),
                           ("targetOperations", 1), ("activeStorageBackend", "SeaweedFS"),
                           ("licenceReview", "CLOSED"), ("redistributionAccepted", True),
                           ("durableImageCustody", "ESTABLISHED"), ("overallSwG1", "CLOSED")):
            changed = copy.deepcopy(self.plan); changed["currentQualification"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)

    def test_known_lifecycle_residuals_cannot_be_silently_closed(self):
        for key, value in (("status", "CLOSED"), ("allDependenciesMaintained", True),
                           ("selectedRemediationFronts", {}), ("prototypeRemovalsQualified", True)):
            changed = copy.deepcopy(self.plan); changed["currentQualification"]["dependencyLifecycle"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)

    def test_mime_regression_does_not_repair_history_or_close_general_acceptance(self):
        for key in ("historicalLostMetadataRepaired", "storageGateG2Closed"):
            changed = copy.deepcopy(self.plan); changed["currentQualification"]["mimeCorrection"][key] = True
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)
        for key, value in (("s3MetadataCompatibilityGenerallyQualified", True),
                           ("postgresRecovery", "PASS"), ("certificateRotation", "PASS"),
                           ("rpoAcceptance", True), ("rtoAcceptance", True)):
            changed = copy.deepcopy(self.plan); changed["currentQualification"]["syntheticRuntime"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)

    def test_historical_snapshots_remain_immutable_and_keep_old_mime_failure(self):
        view = plan_current.historical_plan_view(self.plan)
        self.assertEqual(view["currentQualification"]["qualifiedImagePatchCount"], 15)
        self.assertEqual(view["historicalRuntimeQualification"]["coldRecovery15"]["octetStreamCompatibility"], "FAIL")
        self.assertEqual(view["generation29Qualification"]["runtimeLabs29"], "PENDING")
        for field, key, value, error in (
            ("historicalQualification15", "binarySha256", self.plan["currentQualification"]["binarySha256"], "HISTORICAL_QUALIFICATION15_CHANGED"),
            ("historicalQualification15", "repositoryPatchCount", 29, "HISTORICAL_QUALIFICATION15_CHANGED"),
            ("historicalGeneration29PhaseA", "runtimeLabs29", "PASS", "HISTORICAL_PHASE_A29_CHANGED"),
        ):
            changed = copy.deepcopy(self.plan); changed[field][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, error):
                plan_current.historical_plan_view(changed)

    def test_wider_lifecycle_inventory_unknowns_and_policy_states_stay_open(self):
        current = self.plan["currentQualification"]
        plan_current.validate_lifecycle29_evidence(ROOT, current)
        assessment = current["dependencyLifecycle"]["widerInventoryAssessment"]
        self.assertEqual(len(assessment["archivedCompiledModules"]), 10)
        self.assertEqual(len(assessment["repositoryMetadataUnknownModules"]), 12)
        for key, value in (("repositoryMetadataUnknownModules", []), ("archivedCompiledModules", []),
                           ("unknownOriginAssumedMaintained", True), ("repositoryNotArchivedProvesSupport", True),
                           ("allApiDeprecationsImplyModuleEndOfSupport", True), ("widerMaintenanceAssessment", "CLOSED")):
            changed = copy.deepcopy(self.plan)
            changed["currentQualification"]["dependencyLifecycle"]["widerInventoryAssessment"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
                self.validate(plan=changed)

    def test_lifecycle_evidence_must_match_actual_qualified_binary_and_raw_bytes(self):
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in plan_current.LIFECYCLE29_INPUTS:
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            plan_current.validate_lifecycle29_evidence(root, self.plan["currentQualification"])
            target = root / plan_current.LIFECYCLE29_INVENTORY["inventoryPath"]
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "LIFECYCLE29_EVIDENCE_BYTES_CHANGED"):
                plan_current.validate_lifecycle29_evidence(root, self.plan["currentQualification"])

    def test_legacy_source_receipt_is_not_relabelled_as_new_binary(self):
        changed = copy.deepcopy(self.plan)
        changed["currentQualification"]["sourceClosureReceipt"] = plan_current.SOURCE_CLOSURE_PATH
        changed["currentQualification"]["qualifiedBinaryByteIdentical"] = True
        with self.assertRaisesRegex(ValueError, "CURRENT_GENERATION29_VIEW_REQUIRED"):
            self.validate(plan=changed)

    def test_runtime_raw_bytes_are_required_not_just_success_boolean(self):
        key = plan_current.RUNTIME29_DIR + "/runtime-result.json"
        changed = dict(self.raw); del changed[key]
        with self.assertRaisesRegex(ValueError, "GENERATION29_COMPLETE_RAW_SET_REQUIRED"):
            self.validate(raw=changed)
        changed = dict(self.raw); changed[key] += b"\n"
        with self.assertRaisesRegex(ValueError, "GENERATION29_RAW_BYTES_CHANGED"):
            self.validate(raw=changed)

    def test_raw_file_paths_and_duplicates_are_rejected(self):
        for path in (plan_current.RUNTIME29_DIR + "/../outside", self.runtime["rawEvidence"]["files"][1]["path"]):
            changed = copy.deepcopy(self.runtime)
            if path == self.runtime["rawEvidence"]["files"][1]["path"]:
                changed["rawEvidence"]["files"][0] = copy.deepcopy(changed["rawEvidence"]["files"][1])
            else:
                changed["rawEvidence"]["files"][0]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "GENERATION29_RAW_PATH_REQUIRED"):
                plan_current.read_generation29_raw(ROOT, self.cohort, changed)

    def test_qualified_patch_harness_and_job_evidence_cannot_drift(self):
        import shutil
        import tempfile
        manifest_bytes = (ROOT / plan_current.IMAGE29_MANIFEST_PATH).read_bytes()
        manifest = json.loads(manifest_bytes)
        paths = {item["path"] for item in manifest["orderedPatches"]}
        paths.update(self.runtime["sourceHashesVerified"])
        paths.add(self.runtime["workflowJobsEvidence"]["path"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in paths:
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            plan_current.validate_generation29_sources(root, manifest_bytes, self.runtime)
            for name, code in (
                (manifest["orderedPatches"][-1]["path"], "GENERATION29_PATCH_SOURCE_CHANGED"),
                ("scripts/run-seaweedfs-452-generation29-labs.py", "GENERATION29_RUNTIME_SOURCE_CHANGED"),
                (self.runtime["workflowJobsEvidence"]["path"], "GENERATION29_JOB_EVIDENCE_CHANGED"),
            ):
                target = root / name; previous = target.read_bytes(); target.write_bytes(previous + b"\n")
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, code):
                    plan_current.validate_generation29_sources(root, manifest_bytes, self.runtime)
                target.write_bytes(previous)

    def test_fresh_runtime_does_not_increase_progress_credit(self):
        self.assertEqual(self.plan["progressEstimate"]["weightedCredits"], 17.5)
        self.assertEqual(self.plan["progressEstimate"]["reportedApproximatePercent"], 38)
        self.assertEqual(self.plan["progressEstimate"]["creditChange"]["receipt"], plan_current.COLD_RECEIPT_PATH)
        self.assertFalse(self.plan["currentQualification"]["historicalRuntimeProofTransferred"])




class QualifiedGeneration31PlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = plan_current.generation31_helper()
        cls.plan = plan_current.generation31_view(json.loads((ROOT / plan_current.PLAN_PATH).read_bytes()))

    def test_historical31_and_old29_qualified_history(self):
        result = self.helper.validate_tree31(ROOT, self.plan, plan_current.validate_generation29_tree)
        self.assertEqual(result['currentGeneration'], 31)
        self.assertEqual(result['historicalGeneration29QualifiedImagePatchCount'], 29)
        self.assertEqual(result['currentBinaryModules'], 234)
        self.assertEqual(result['currentCompiledPackages'], 1740)
        self.assertEqual(result['historicalGeneration15MimeDefect'], 'FAIL_PRESERVED')
        self.assertFalse(result['historicalProofTransferredToGeneration31'])
        self.assertEqual(result['acceptanceTestsPassed'], 0)

    def test_entire_pre31_plan_reconstructs_exactly(self):
        restored = self.helper.restore_generation29_plan(self.plan)
        self.assertEqual(self.helper.sha(self.helper.canonical(restored)), self.helper.BASE_PLAN_CANONICAL_SHA)
        self.assertEqual(restored['currentQualification'], self.plan['historicalQualification29'])
        self.assertEqual(restored['historicalQualification15'], self.plan['historicalQualification15'])

    def test_historical_binary_cannot_be_rewritten(self):
        changed = copy.deepcopy(self.plan)
        changed['historicalQualification29']['binarySha256'] = self.helper.BINARY_SHA
        with self.assertRaisesRegex(ValueError, 'ALL_PRE31'):
            self.helper.restore_generation29_plan(changed)

    def test_arbitrary_old_plan_field_cannot_be_changed(self):
        changed = copy.deepcopy(self.plan)
        changed['historicalQualification15']['releaseAdmitted'] = True
        with self.assertRaisesRegex(ValueError, 'ALL_PRE31'):
            self.helper.restore_generation29_plan(changed)

    def test_proto32_cannot_inherit_qualification_or_progress(self):
        for field,value in [('qualifiedGenerationRetained',32),('progressCreditAdded',1),('runtimeProofTransferred',True)]:
            with self.subTest(field=field):
                changed=copy.deepcopy(self.plan);changed['nextGenerationPrototype'][field]=value
                with self.assertRaisesRegex(ValueError,'NEXT_PROTOTYPE'):
                    self.helper.restore_generation29_plan(changed)

    def test_current31_cannot_transfer_old29_binary(self):
        changed=copy.deepcopy(self.plan)
        changed['currentQualification']['binarySha256']=changed['historicalQualification29']['binarySha256']
        with self.assertRaisesRegex(ValueError,'EXACT31_CURRENT_VIEW'):
            self.helper.validate_tree31(ROOT,changed,plan_current.validate_generation29_tree)

    def test_current31_cannot_grant_authority_or_claim_maintenance(self):
        for field,value in [('releaseAdmitted',True),('targetOperations',1),('activeStorageBackend','SeaweedFS')]:
            with self.subTest(field=field):
                changed=copy.deepcopy(self.plan);changed['currentQualification'][field]=value
                with self.assertRaisesRegex(ValueError,'EXACT31_CURRENT_VIEW'):
                    self.helper.validate_tree31(ROOT,changed,plan_current.validate_generation29_tree)
        changed=copy.deepcopy(self.plan);changed['currentQualification']['dependencyLifecycle']['allDependenciesMaintained']=True
        with self.assertRaisesRegex(ValueError,'EXACT31_CURRENT_VIEW'):
            self.helper.validate_tree31(ROOT,changed,plan_current.validate_generation29_tree)

    def test_current_mime_pass_cannot_repair_old_loss_or_close_g2(self):
        for field in ('historicalLostMetadataRepaired','storageGateG2Closed'):
            changed=copy.deepcopy(self.plan);changed['currentQualification']['mimeCorrection'][field]=True
            with self.assertRaisesRegex(ValueError,'EXACT31_CURRENT_VIEW'):
                self.helper.validate_tree31(ROOT,changed,plan_current.validate_generation29_tree)

    def test_changed_or_missing_receipt_and_symlink_are_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);path=root/'receipt.json';path.write_bytes(b'actual')
            digest=self.helper.sha(b'actual')
            self.assertEqual(self.helper.read_bound(root,'receipt.json',digest),b'actual')
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'FILE_BYTES_CHANGED'):
                self.helper.read_bound(root,'receipt.json',digest)
            path.unlink()
            with self.assertRaisesRegex(ValueError,'REGULAR_FILE'):
                self.helper.read_bound(root,'receipt.json',digest)
            (root/'actual.json').write_bytes(b'actual');path.symlink_to(root/'actual.json')
            with self.assertRaisesRegex(ValueError,'REGULAR_FILE'):
                self.helper.read_bound(root,'receipt.json',digest)

    def test_checksum_missing_extra_or_changed_member_rejected(self):
        raw=b'local MPL source archive bytes'
        sums=(self.helper.sha(raw)+'  source.tar.gz\n').encode()
        members={'SHA256SUMS':sums,'source.tar.gz':raw}
        self.helper.checksum_members(members)
        for changed in ({'SHA256SUMS':sums},{**members,'source.tar.gz':raw+b'x'},{**members,'unlisted':b'x'}):
            with self.assertRaises(ValueError):self.helper.checksum_members(changed)

    def test_checksums_reject_duplicate_name(self):
        data=b'x';line=(self.helper.sha(data)+'  file\n').encode()
        with self.assertRaisesRegex(ValueError,'CHECKSUM_MEMBER'):
            self.helper.checksum_members({'SHA256SUMS':line+line,'file':data})

    def test_raw_cohort_runtime_and_local_mpl_are_exact(self):
        lock,image,_,_=self.helper.validate_image31(ROOT)
        cohort,runtime,raw=self.helper.validate_cohort_runtime31(ROOT,lock,image)
        self.assertEqual(len(raw),62)
        self.assertEqual(self.helper.sha(raw['cohort/modified-raftstore-source.tar.gz']),lock['modifiedMplSource']['archiveSha256'])
        self.assertEqual(runtime['coldRecovery']['backupBytes'],8417282)
        self.assertEqual(cohort['checks']['mplSourceArchives'],7)
        self.assertEqual(cohort['checks']['modifiedLocalMplFiles'],6)

class QualifiedGeneration32PlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = plan_current.generation32_helper()
        cls.plan = plan_current.generation32_view(json.loads((ROOT / plan_current.PLAN_PATH).read_bytes()))

    def test_exact_hosted_evidence_and_current_view(self):
        history = self.helper.restore_generation31_plan(self.plan)
        result = self.helper.validate_tree32(ROOT, self.plan, lambda root, old: {})
        self.assertEqual(result["currentGeneration"], 32)
        self.assertEqual(result["currentBinaryModules"], 215)
        self.assertEqual(result["currentCompiledPackages"], 1533)
        self.assertEqual(history["currentQualification"]["generation"], 31)
        self.assertEqual(history["progressEstimate"], self.plan["progressEstimate"])
        self.assertEqual(self.plan["currentQualification"]["syntheticRuntime"]["backupBytes"], 8417555)

    def test_no_transfer_or_admission_in_current_view(self):
        for field, value in (("releaseAdmitted", True), ("targetOperations", 1),
                             ("historicalRuntimeProofTransferred", True)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.plan)
                changed["currentQualification"][field] = value
                with self.assertRaisesRegex(ValueError, "GEN32_EXACT_CURRENT_VIEW"):
                    self.helper.validate_tree32(ROOT, changed, lambda root, old: {})

    def test_history_and_next_prototype_are_immutable(self):
        changed = copy.deepcopy(self.plan)
        changed["historicalQualification31"]["releaseAdmitted"] = True
        with self.assertRaisesRegex(ValueError, "ALL_PRE32_HISTORY"):
            self.helper.restore_generation31_plan(changed)
        changed = copy.deepcopy(self.plan)
        changed["nextGenerationPrototype"]["runtimeProofTransferred"] = True
        with self.assertRaisesRegex(ValueError, "GEN33_PROTOTYPE_REMAINS_UNQUALIFIED"):
            self.helper.restore_generation31_plan(changed)

    def test_missing_or_altered_runtime_archive_is_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runtime = root / self.helper.RUNTIME_ZIP
            runtime.parent.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "GEN32_REGULAR_FILE"):
                self.helper.read_bound(root, self.helper.RUNTIME_ZIP, self.helper.RUNTIME_ZIP_SHA)
            runtime.write_bytes(b"wrong image runtime archive")
            with self.assertRaisesRegex(ValueError, "GEN32_BOUND_BYTES_CHANGED"):
                self.helper.read_bound(root, self.helper.RUNTIME_ZIP, self.helper.RUNTIME_ZIP_SHA)


class QualifiedGeneration33PlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper=plan_current.generation33_helper()
        cls.plan=json.loads((ROOT/plan_current.PLAN_PATH).read_bytes())

    def test_exact_hosted_evidence_and_full32_history(self):
        history=self.helper.restore_generation32_plan(self.plan)
        result=self.helper.validate_tree33(ROOT,self.plan,lambda root,old:{})
        self.assertEqual(result['currentGeneration'],33)
        self.assertEqual(result['currentBinaryModules'],214)
        self.assertEqual(result['currentCompiledPackages'],1532)
        self.assertEqual(history['currentQualification']['generation'],32)
        self.assertEqual(self.helper.sha(self.helper.canonical(history)),self.helper.BASE_PLAN_CANONICAL_SHA)
        self.assertEqual(plan_current.generation31_view(self.plan)['currentQualification']['generation'],31)
        self.assertEqual(plan_current.generation29_view(self.plan)['currentQualification']['generation'],29)

    def test_no_old_binary_runtime_or_target_qualification_transfer(self):
        for field,value in [('binarySha256',self.plan['historicalQualification32']['binarySha256']),
                            ('runtimeRunId',self.plan['historicalQualification32']['runtimeRunId']),
                            ('releaseAdmitted',True),('targetOperations',1),('historicalRuntimeProofTransferred',True)]:
            with self.subTest(field=field):
                changed=copy.deepcopy(self.plan);changed['currentQualification'][field]=value
                with self.assertRaisesRegex(ValueError,'GEN33_EXACT_CURRENT_VIEW'):
                    self.helper.validate_tree33(ROOT,changed,lambda root,old:{})

    def test_all_pre33_history_and_scope_immutable(self):
        for path in [('historicalQualification32','releaseAdmitted'),('historicalQualification31','releaseAdmitted'),
                     ('historicalQualification29','releaseAdmitted')]:
            changed=copy.deepcopy(self.plan);changed[path[0]][path[1]]=True
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'ALL_PRE33_HISTORY'):
                self.helper.restore_generation32_plan(changed)
        changed=copy.deepcopy(self.plan);changed['nextGenerationPrototype']['progressCreditAdded']=1
        with self.assertRaisesRegex(ValueError,'NEXT_PROTOTYPE'):
            self.helper.restore_generation32_plan(changed)

    def test_archived_census_closure_does_not_mean_all_dependencies_maintained(self):
        current=self.plan['currentQualification']['dependencyLifecycle']
        self.assertEqual(len(current['archivedModulesRemovedFromGeneration29Binary']),10)
        self.assertFalse(current['allDependenciesMaintained'])
        self.assertFalse(current['moduleGraphEradicationClaimed'])
        changed=copy.deepcopy(self.plan);changed['currentQualification']['dependencyLifecycle']['allDependenciesMaintained']=True
        with self.assertRaisesRegex(ValueError,'GEN33_EXACT_CURRENT_VIEW'):
            self.helper.validate_tree33(ROOT,changed,lambda root,old:{})

    def test_modified_source_and_raw_scanner_identities_are_separate(self):
        lock,image,inner,_,_,legal,_=self.helper.bind_qualification(ROOT)
        self.assertFalse(image['assessment']['vendorSourceSupplement']['rawArtifactsRewritten'])
        self.assertFalse(inner['modifiedVendorDependency']['originalChecksumsDescribeModifiedSource'])
        self.assertEqual(inner['vendorSourceProfile'],lock['vendorSourceProfile'])
        self.assertEqual(legal['vendoredBuildInfoH1Fields'],'EMPTY_UNCHANGED')

    def test_engineering_credit_keeps_history_and_requires_both_proofs(self):
        old=self.helper.restore_generation32_plan(self.plan)
        self.assertEqual(old['progressEstimate']['weightedCredits'],17.5)
        self.assertEqual(self.plan['progressEstimate']['weightedCredits'],18.3)
        self.assertEqual(self.plan['progressEstimate']['creditsPercent'],[50,85,60,45,35,0,0,0])
        self.assertEqual(self.plan['currentQualification']['syntheticRuntime']['postgresRecovery'],'NOT_TESTED')
        changed=copy.deepcopy(self.plan);changed['progressEstimate']['creditsPercent'][3]=100
        with self.assertRaisesRegex(ValueError,'GEN33_EXACT_ENGINEERING_CREDIT'):
            self.helper.validate_tree33(ROOT,changed,lambda root,old:{})
        changed=copy.deepcopy(self.plan);changed['engineeringRecovery33']['externalS3WritesFenced']=True
        with self.assertRaisesRegex(ValueError,'GEN33_RECOVERY_SCOPE'):
            self.helper.restore_generation32_plan(changed)

    def test_missing_and_wrong_archive_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/self.helper.RUNTIME_ZIP;path.parent.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError,'GEN33_REGULAR_FILE'):
                self.helper.read_bound(root,self.helper.RUNTIME_ZIP,self.helper.RUNTIME_ZIP_SHA)
            path.write_bytes(b'old unrelated runtime')
            with self.assertRaisesRegex(ValueError,'GEN33_BOUND_BYTES_CHANGED'):
                self.helper.read_bound(root,self.helper.RUNTIME_ZIP,self.helper.RUNTIME_ZIP_SHA)


if __name__ == "__main__":
    unittest.main()
