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
        cls.plan = json.loads((ROOT / plan_current.PLAN_PATH).read_bytes())
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
        self.assertEqual(result["repositoryPatchCount"], 28)
        self.assertEqual(result["hostedSourceClosureRunCount"], 6)
        self.assertFalse(result["optionalModuleGraphEradicationClaimed"])
        self.assertFalse(result["releaseAdmitted"])
        self.assertEqual(result["activeStorageBackend"], "MinIO")

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
            15.9 / 46 * 100,
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


if __name__ == "__main__":
    unittest.main()
