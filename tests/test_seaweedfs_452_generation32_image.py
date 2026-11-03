import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


candidate = module("candidate32", "scripts/qualify-seaweedfs-452-generation32-image.py").engine
readback = module("readback32", "scripts/readback-seaweedfs-452-generation32-image.py").engine
image = candidate.image


class GenerationBoundaryTests(unittest.TestCase):
    def test_reviewed_manifest_and_patch_bytes_are_exact(self):
        candidate.validate_manifest(candidate.MANIFEST)
        candidate.verify_patch_sources()
        self.assertEqual(len(candidate.source_names()), 46)
        self.assertEqual(candidate.MANIFEST["orderedPatches"][-1]["path"],
                         "patches/seaweedfs/4.52-maintained-profiles-mongodb-v2-generation32.patch")

    def test_compiled_policy_cannot_be_omitted_or_claim_global_maintenance(self):
        for field, value in (('yamlLifecycleStatus', 'CLOSED'), ('allDependenciesMaintained', True),
                             ('rootModuleGraphLegacyEdgesMayRemain', False), ('excludedModulePaths', [])):
            changed = copy.deepcopy(candidate.MANIFEST)
            changed['compiledDependencyPolicy'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'EXACT_COMPILED_LIFECYCLE'):
                candidate.validate_manifest(changed)

    def test_revision_requires_fresh_qualification(self):
        changed = copy.deepcopy(candidate.MANIFEST)
        changed['sourceRevision']['freshHostedQualificationRequired'] = False
        with self.assertRaisesRegex(ValueError, 'FRESH_PROFILE_REVISION'):
            candidate.validate_manifest(changed)

    def test_hosted_requirement_cannot_be_presented_as_local_pass(self):
        changed = copy.deepcopy(candidate.MANIFEST)
        changed['requiredHostedRegression']['shell']['status'] = 'OBSERVED_LOCAL_PASS'
        with self.assertRaisesRegex(ValueError, 'EXPLICIT_HOSTED_TEST_REQUIREMENTS'):
            candidate.validate_manifest(changed)

    def test_legacy_prefixes_and_maintained_siblings(self):
        for module in candidate.EXCLUDED_MODULES:
            for name in (module, module + '/subpackage', 'vendor/' + module + '/subpackage'):
                with self.subTest(name=name): self.assertTrue(candidate.is_excluded_dependency(name))
        for name in ('go.mongodb.org/mongo-driver/v2', 'go.mongodb.org/mongo-driver/v2/mongo',
                     'github.com/aws/aws-sdk-go-v2/service/s3', 'github.com/go-viper/mapstructure/v2',
                     'go.etcd.io/bbolt', 'go.yaml.in/yaml/v3'):
            with self.subTest(name=name): self.assertFalse(candidate.is_excluded_dependency(name))

    def test_workflow_image_tag_matches_the_packaged_profile(self):
        import contextlib
        workflow = (ROOT / '.github/workflows/storage-452-generation32-image.yml').read_text()
        lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("print('image-tag=")]
        self.assertEqual(len(lines), 1)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(lines[0], '<workflow-image-tag>', 'exec'), {'m': candidate.MANIFEST})
        self.assertEqual(output.getvalue().strip(), 'image-tag=' + candidate.PROFILE.image_tag)

    def test_prior_generation_and_authority_are_rejected(self):
        for field, value in (("generation", 15), ("releaseAdmitted", True),
                             ("runtimeAuthorityIssued", True), ("targetOperations", 1)):
            changed = copy.deepcopy(candidate.MANIFEST)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                candidate.validate_manifest(changed)
        changed = copy.deepcopy(candidate.MANIFEST)
        changed["build"]["binarySha256"] = candidate.PREVIOUS["build"]["binarySha256"]
        with self.assertRaisesRegex(ValueError, "NEW_STANDARD_BUILD_PIN"):
            candidate.validate_manifest(changed)

    def test_patch_duplicates_paths_and_optional_tags_are_rejected(self):
        for mutation in ("duplicate", "path", "tags"):
            changed = copy.deepcopy(candidate.MANIFEST)
            if mutation == "duplicate":
                changed["orderedPatches"][-1] = changed["orderedPatches"][0]
            elif mutation == "path":
                changed["orderedPatches"][0]["path"] = "../escape.patch"
            else:
                changed["build"]["tags"] = ["rclone"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                candidate.validate_manifest(changed)

    def test_generation31_build_facts_cannot_be_relabelled_as_generation32(self):
        for field in ('compiledPackagesSha256', 'binaryModuleInventorySha256', 'patchedSourceTree'):
            changed = copy.deepcopy(candidate.MANIFEST)
            changed['build'][field] = candidate.PREVIOUS['build'][field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'NEW_GENERATION_FACTS'):
                candidate.validate_manifest(changed)

    def test_previous_patch_prefix_cannot_be_changed(self):
        changed = copy.deepcopy(candidate.MANIFEST)
        changed['orderedPatches'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'EXACT_PREVIOUS_PATCH_PREFIX'):
            candidate.validate_manifest(changed)

    def test_clean_scan_cannot_declare_all_dependencies_maintained(self):
        changed = copy.deepcopy(candidate.MANIFEST)
        changed['dependencyMaintenance']['allDependenciesMaintained'] = True
        with self.assertRaisesRegex(ValueError, 'NO_ALL_DEPENDENCIES_MAINTAINED'):
            candidate.validate_manifest(changed)

    def test_missing_observed_regression_facts_are_rejected(self):
        changed = copy.deepcopy(candidate.MANIFEST)
        changed['observedLocalRegression']['testsPassed'] = None
        with self.assertRaisesRegex(ValueError, 'OBSERVED_REGRESSION_COUNTS'):
            candidate.validate_manifest(changed)

    def test_engine_cannot_rebind_in_place(self):
        with self.assertRaisesRegex(ValueError, 'FRESH_GENERATION_ENGINE'):
            candidate.configure(ROOT, 32, candidate.MANIFEST_PATH, (), 'ignored', 'ignored')
        with self.assertRaisesRegex(ValueError, 'FRESH_READBACK_ENGINE'):
            readback.configure(ROOT, candidate)

    def test_frozen_previous_manifest_hash_is_enforced(self):
        fresh = module('fresh_profile_engine', 'tools/storage_security/generation_image_v3.py')
        with self.assertRaisesRegex(ValueError, 'FROZEN_PREVIOUS_MANIFEST'):
            fresh.configure(ROOT, 32, candidate.MANIFEST_PATH, (),
                            'releases/seaweedfs-452-generation31-build-manifest-20261103.json', '0' * 64)

    def test_patch_tamper_denied_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.patch").write_bytes(b"changed")
            manifest = {"orderedPatches": [{"path": "fixture.patch", "sha256": image.sha(b"original")} ]}
            with patch.object(candidate, "ROOT", root), patch.object(candidate, "MANIFEST", manifest):
                with self.assertRaisesRegex(ValueError, "PATCH_SOURCE_CHANGED"):
                    candidate.verify_patch_sources()


class ImageReadbackTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.build = self.root / "build"
        self.build.mkdir()
        self.out = self.root / "image"
        self.binary = b"synthetic generation32 executable"
        licence = b"Apache License synthetic fixture"
        profile = candidate.PROFILE._replace(binary_sha=image.sha(self.binary), licence_sha=image.sha(licence))
        manifest = copy.deepcopy(candidate.MANIFEST)
        manifest["build"]["patchedSourceTree"] = "a" * 40
        graph = [candidate.lifecycle.WEED, candidate.lifecycle.WEED + "/s3api"]
        graph_raw = ("\n".join(graph) + "\n").encode()
        manifest["build"].update(binarySha256=profile.binary_sha, compiledPackages=2,
                                 compiledPackagesSha256=image.sha(graph_raw))
        for target, key, value in ((candidate, "PROFILE", profile), (candidate, "MANIFEST", manifest),
                                   (readback, "candidate", candidate)):
            item = patch.object(target, key, value)
            item.start()
            self.addCleanup(item.stop)
        self.profile = profile
        info = ("fixture: go1.27.3\n"
                "\tmod\tgithub.com/seaweedfs/seaweedfs\tv0.0.0-fixture\t\n"
                "\tdep\tgolang.org/x/net\tv0.62.0\th1:fixture\n"
                "\tdep\tgolang.org/x/crypto\tv0.58.1-0.20261009181718-2f1f834330b2\th1:fixture\n"
                "\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=amd64\n"
                "\tbuild\tGOOS=linux\n\tbuild\tvcs.revision=" + profile.source_commit + "\n\tbuild\tvcs.modified=true\n").encode()
        rows = [line for line in info.decode().splitlines() if line.startswith("\tdep\t")]
        manifest["build"]["binaryModuleRows"] = len(rows)
        manifest["build"]["binaryModuleInventorySha256"] = image.sha(("\n".join(rows) + "\n").encode())
        modules = b"github.com/seaweedfs/seaweedfs\ngolang.org/x/net v0.62.0\n"
        module_graph = b"github.com/seaweedfs/seaweedfs golang.org/x/net@v0.62.0\n"
        for name, data in {"weed": self.binary, "LICENSE": licence, "compiled-deps": graph_raw,
                           "build-info.txt": info, "root-modules.txt": modules,
                           "root-module-graph.txt": module_graph}.items():
            (self.build / name).write_bytes(data)
        source = {"upstreamCommit": profile.source_commit, "patchedTree": "a" * 40,
                  "orderedPatchCount": 32, "rootLockfilesSha256": manifest["build"]["rootLockfilesSha256"],
                  "patchManifestSha256": image.sha((ROOT / candidate.MANIFEST_PATH).read_bytes()),
                  "moduleEvidenceSha256": {"root-modules.txt": image.sha(modules),
                                           "root-module-graph.txt": image.sha(module_graph)}}
        source['nestedKafkaLockfilesSha256'] = copy.deepcopy(candidate.PREVIOUS['sourceRevision']['nestedKafkaLockfilesSha256'])
        source['regressionEvidence'] = {
            name: {'profile': name, 'counts': profile['observedLocalCounts'],
                   'terminalTestsSha256': profile['terminalTestsSha256'],
                   'terminalPackagesSha256': profile['terminalPackagesSha256'],
                   'logSha256': image.sha(b'explicit unit fixture log'),
                   'status': 'OBSERVED_TEST_IDENTITIES_VERIFIED_NOT_ACCEPTANCE', 'targetOperations': 0,
                   'environmentConditionalOutcomes': {test: 'skip' for test in profile['environmentConditionalTests']}}
            for name, profile in manifest['regressionProfiles'].items()}
        # Explicitly synthetic unit fixture: actual local server skips are never
        # promoted; the hosted producer must supply real PASS for both TLS cases.
        server = source['regressionEvidence']['server']
        server['counts'] = copy.deepcopy(server['counts'])
        server['environmentConditionalOutcomes'] = {test: 'pass' for test in candidate.HOSTED_REQUIRED_SERVER_TESTS}
        server['counts']['skip_tests'] -= 2
        server['counts']['pass_tests'] += 2
        source['hostedRegressionEvidence'] = {
            name: {'status': 'HOSTED_REQUIRED_TEST_IDENTITIES_VERIFIED_NOT_ACCEPTANCE',
                   'profile': name, 'testsPassed': len(required['tests']), 'packagesPassed': 1,
                   'testsFailed': 0, 'testsSkipped': 0,
                   'terminalTestsSha256': image.sha(image.canonical(
                       [[required['package'], test, 'pass'] for test in required['tests']])),
                   'logSha256': image.sha(b'explicit synthetic unit fixture only'),
                   'localPassWasObserved': False, 'targetOperations': 0}
            for name, required in manifest['requiredHostedRegression'].items()}
        source['dbCompatibility'] = {
            'schema': 'ouf.raftstore-local-compatibility.v1',
            'status': 'LOCAL_DB_FILE_COMPATIBILITY_VERIFIED_NOT_RUNTIME_ACCEPTANCE',
            'oracleContainsArchivedBoltOutsideCandidateOnly': True,
            'testsPassed': ['TestLocalFileReadByOldV2AndReadOnlyLocalDoesNotChangeBytes',
                            'TestLogStoreMonotonicInterfaceRemainsUnclaimed',
                            'TestOldV2FileReadAndWriteWithLocalThenReopenOldV2'],
            'candidateModuleFilesUnchanged': manifest['build']['rootLockfilesSha256'],
            'candidateRequirementPinsUnchanged': True,
            'oracle': 'github.com/hashicorp/raft-boltdb/v2@v2.4.2',
            'fixtureSha256': image.sha((ROOT / 'tests/fixtures/seaweedfs-raftstore-compat/compat_test.go').read_bytes()),
            'dbFormatMigrationPerformed': False, 'crashOrPowerLossQualified': False,
            'runtimeAuthorityIssued': False, 'targetOperations': 0}
        (self.build / "build-source.json").write_bytes(image.canonical(source))

    def prepare(self, findings=None):
        candidate.package(self.build, self.out)
        record = image.verify_layout(self.out, profile=self.profile)
        config = json.loads((self.out / "blobs/sha256" / record["configDigest"][7:]).read_bytes())
        scan = {"SchemaVersion": 2, "Trivy": {"Version": "0.70.0"}, "ArtifactName": self.profile.image_tag,
                "Metadata": {"ImageID": record["configDigest"], "ImageConfig": config},
                "Results": [{"Target": "usr/local/bin/weed", "Class": "lang-pkgs", "Type": "gobinary",
                             "Packages": [{"Name": "stdlib", "Version": "v1.27.3"},
                                          {"Name": "golang.org/x/net", "Version": "v0.62.0"},
                                          {"Name": "golang.org/x/crypto", "Version": "v0.58.1-0.20261009181718-2f1f834330b2"},
                                          {"Name": "github.com/seaweedfs/seaweedfs", "Version": "v0.0.0-fixture"}],
                             "Vulnerabilities": findings or []}]}
        (self.out / "fresh-image-scan.json").write_bytes(image.canonical(scan))
        (self.out / "image.spdx.json").write_bytes(image.canonical({
            "spdxVersion": "SPDX-2.3", "documentNamespace": "urn:fixture:spdx",
            "packages": [{"name": p["Name"], "versionInfo": p["Version"]} for p in scan["Results"][0]["Packages"]]
                        + [{"name": "usr/local/bin/weed", "primaryPackagePurpose": "APPLICATION"},
                           {"name": self.profile.image_tag, "primaryPackagePurpose": "CONTAINER"}],
        }))
        (self.out / "daemon-image-id.txt").write_text(record["configDigest"] + "\n")
        (self.out / "version-smoke.txt").write_text("synthetic version fixture\n")
        result = candidate.assess(self.out, record["configDigest"], "b" * 40, 1)
        (self.out / "assessment.json").write_bytes(image.canonical(result))
        candidate.seal_sources(self.out)
        return result

    def zip(self):
        names = sorted(p for p in self.out.rglob("*") if p.is_file()
                       and p.name not in {"SHA256SUMS", "provenance.json"})
        (self.out / "SHA256SUMS").write_text("".join(
            image.sha(p.read_bytes()) + "  " + p.relative_to(self.out).as_posix() + "\n" for p in names))
        (self.out / "provenance.json").write_text('{"fixture":"not-a-signature"}\n')
        path = self.root / "image.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for p in self.out.rglob("*"):
                if p.is_file():
                    archive.write(p, p.relative_to(self.out).as_posix())
        return path

    def test_complete_roundtrip_reproduces_new_profile_without_admission(self):
        result = self.prepare()
        self.assertEqual(result["generation"], 32)
        self.assertEqual(result["vulnerabilitySubgate"], "PASS_RAW")
        self.assertFalse(result["releaseAdmitted"])
        path = self.zip()
        receipt = readback.verify(path, self.root / "readback", readback.file_hash(path), "b" * 40, 1)
        self.assertEqual(receipt["checksumMembersVerified"], 20)
        self.assertEqual(receipt["sourceFilesVerified"], 46)
        self.assertFalse(receipt["publisherSignatureVerifiedByThisScript"])
        self.assertEqual(receipt["targetOperations"], 0)

    def test_foreign_image_profile_is_rejected(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "EXACT_OWNER_REVIEWED_BINARY"):
            image.verify_layout(self.out, profile=self.profile._replace(binary_sha="0" * 64))

    def test_wrong_graph_or_binary_fails_packaging(self):
        (self.build / "compiled-deps").write_text("wrong\n")
        with self.assertRaisesRegex(ValueError, "EXACT_STANDARD_PACKAGE_CLOSURE"):
            candidate.package(self.build, self.out)
        self.assertFalse(self.out.exists())

    def test_unmodified_vcs_label_cannot_hide_patched_source(self):
        path = self.build / 'build-info.txt'
        path.write_bytes(path.read_bytes().replace(b'vcs.modified=true', b'vcs.modified=false'))
        with self.assertRaisesRegex(ValueError, 'EXACT_STANDARD_BUILD_SETTINGS'):
            candidate.package(self.build, self.out)
        self.assertFalse(self.out.exists())

    def test_excluded_module_denied_even_with_consistent_inventory_hash(self):
        path = self.build / 'build-info.txt'
        raw = path.read_bytes()
        for module in ('go.opencensus.io', 'github.com/mitchellh/colorstring',
                       'go.mongodb.org/mongo-driver', 'github.com/envoyproxy/protoc-gen-validate'):
            info = raw + ('\tdep\t' + module + '\tv1.0.0\th1:synthetic\n').encode()
            path.write_bytes(info)
            rows = [line for line in info.decode().splitlines() if line.startswith('\tdep\t')]
            candidate.MANIFEST['build']['binaryModuleRows'] = len(rows)
            candidate.MANIFEST['build']['binaryModuleInventorySha256'] = image.sha(('\n'.join(rows)+'\n').encode())
            with self.subTest(module=module), self.assertRaisesRegex(ValueError, 'LEGACY_BINARY_MODULE'):
                candidate.package(self.build, self.out)
            self.assertFalse(self.out.exists())

    def test_hosted_server_tls_skip_cannot_be_promoted(self):
        path = self.build / 'build-source.json'
        source = json.loads(path.read_bytes())
        source['regressionEvidence']['server']['environmentConditionalOutcomes'][candidate.HOSTED_REQUIRED_SERVER_TESTS[0]] = 'skip'
        path.write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, 'HOSTED_SERVER_TLS_TESTS_MUST_PASS'):
            candidate.package(self.build, self.out)

    def test_nested_kafka_locks_cannot_drift_from_exact31_prefix(self):
        path = self.build / 'build-source.json'
        source = json.loads(path.read_bytes())
        source['nestedKafkaLockfilesSha256']['test/kafka/go.mod'] = '0' * 64
        path.write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, 'EXACT_NESTED_KAFKA_LOCKFILES'):
            candidate.package(self.build, self.out)

    def test_missing_hosted_shell_result_is_denied_before_readback(self):
        path = self.build / 'build-source.json'
        source = json.loads(path.read_bytes())
        source.pop('hostedRegressionEvidence')
        path.write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, 'COMPLETE_HOSTED_REQUIREMENTS'):
            candidate.package(self.build, self.out)

    def test_wrong_module_rows_fail_before_packaging(self):
        path = self.build / 'build-info.txt'
        path.write_bytes(path.read_bytes().replace(b'golang.org/x/net\tv0.62.0', b'golang.org/x/net\tv0.61.0'))
        with self.assertRaisesRegex(ValueError, 'EXACT_BINARY_MODULE_INVENTORY'):
            candidate.package(self.build, self.out)
        self.assertFalse(self.out.exists())

    def test_build_source_cannot_inherit_or_forge_qualification(self):
        result = self.prepare()
        path = self.out / 'build-source.json'
        original = json.loads(path.read_bytes())
        for mutation in ('test-hash', 'test-count', 'database-pins', 'database-admission', 'database-status', 'oracle-scope'):
            changed = copy.deepcopy(original)
            if mutation == 'test-hash':
                changed['regressionEvidence']['main']['terminalTestsSha256'] = '0' * 64
            elif mutation == 'test-count':
                changed['regressionEvidence']['main']['counts']['pass_tests'] -= 1
            elif mutation == 'database-pins':
                changed['dbCompatibility']['candidateRequirementPinsUnchanged'] = False
            elif mutation == 'database-admission':
                changed['dbCompatibility']['runtimeAuthorityIssued'] = True
            elif mutation == 'database-status':
                changed['dbCompatibility']['status'] = 'RUNTIME_ACCEPTED'
            else:
                changed['dbCompatibility']['oracleContainsArchivedBoltOutsideCandidateOnly'] = False
            path.write_bytes(image.canonical(changed))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'REGRESSION_EVIDENCE|DB_COMPATIBILITY'):
                candidate.assess(self.out, result['configDigest'], 'b' * 40, 1)

    def test_source_manifest_mismatch_fails_reassessment(self):
        result = self.prepare()
        (self.out / "generation-manifest.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "EXACT_GENERATION_MANIFEST"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_module_evidence_tampering_is_denied(self):
        result = self.prepare()
        (self.out / "root-modules.txt").write_text("changed")
        with self.assertRaisesRegex(ValueError, "MODULE_EVIDENCE_BINDING"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_legacy_module_is_denied_even_with_updated_local_hash(self):
        result = self.prepare()
        path = self.out / "root-modules.txt"
        path.write_text("github.com/aws/aws-sdk-go v1.55.8\n")
        source = json.loads((self.out / "build-source.json").read_bytes())
        source["moduleEvidenceSha256"][path.name] = image.sha(path.read_bytes())
        (self.out / "build-source.json").write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, "EXCLUDED_LEGACY_ROOT_MODULE"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_build_info_hash_is_bound(self):
        result = self.prepare()
        (self.out / "build-info.txt").write_text("changed")
        with self.assertRaisesRegex(ValueError, "BUILD_INFO_BINDING"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_fresh_high_and_unknown_findings_are_held(self):
        result = self.prepare([{"Severity": "HIGH", "VulnerabilityID": "FIXTURE-HIGH"},
                               {"Severity": "UNKNOWN", "VulnerabilityID": "FIXTURE-UNKNOWN"}])
        self.assertEqual(result["vulnerabilitySubgate"], "HELD_RAW_FINDINGS")
        self.assertEqual(result["appliedApplicabilityDispositions"], [])
        self.assertFalse(result["runtimeAuthorityIssued"])

    def test_partial_or_wrong_version_scan_inventory_is_denied(self):
        result = self.prepare()
        path = self.out / "fresh-image-scan.json"
        original = json.loads(path.read_bytes())
        for mutation in ("omission", "version", "duplicate"):
            changed = copy.deepcopy(original)
            packages = changed["Results"][0]["Packages"]
            if mutation == "omission":
                packages.pop()
            elif mutation == "version":
                packages[-1]["Version"] = "v0.0.0-wrong"
                # Also alter SPDX so the independent completeness check is exercised.
                bom = json.loads((self.out / "image.spdx.json").read_bytes())
                bom["packages"].append({"name": packages[-1]["Name"], "versionInfo": "v0.0.0-wrong"})
                (self.out / "image.spdx.json").write_bytes(image.canonical(bom))
            else:
                packages.append(copy.deepcopy(packages[0]))
            path.write_bytes(image.canonical(changed))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "COMPLETE_BINARY_SCAN_INVENTORY"):
                candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_readback_and_cli_reject_high_critical_unknown_without_output(self):
        result = self.prepare()
        scan_path = self.out / "fresh-image-scan.json"
        scan = json.loads(scan_path.read_bytes())
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            scan["Results"][0]["Vulnerabilities"] = [{"Severity": severity, "VulnerabilityID": "FIXTURE-" + severity}]
            scan_path.write_bytes(image.canonical(scan))
            held = candidate.assess(self.out, result["configDigest"], "b" * 40, 1)
            (self.out / "assessment.json").write_bytes(image.canonical(held))
            path = self.zip()
            output = self.root / ("held-" + severity)
            with self.subTest(severity=severity), self.assertRaisesRegex(ValueError, "UNRESOLVED_RAW_VULNERABILITIES"):
                readback.verify(path, output, readback.file_hash(path), "b" * 40, 1)
            with patch.object(readback.sys, "stderr", io.StringIO()) as stderr:
                code = readback.main([str(path), str(output), readback.file_hash(path), "b" * 40, "1"])
            self.assertEqual(code, 2)
            self.assertIn("UNRESOLVED_RAW_VULNERABILITIES", stderr.getvalue())
            self.assertFalse(output.exists())

    def test_other_patched_tree_is_denied(self):
        result = self.prepare()
        path = self.out / "build-source.json"
        source = json.loads(path.read_bytes())
        source["patchedTree"] = "f" * 40
        path.write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, "PATCHED_SOURCE_BINDING"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_spdx_missing_extra_duplicate_version_and_descriptive_nodes_denied(self):
        result = self.prepare()
        path = self.out / "image.spdx.json"
        original = json.loads(path.read_bytes())
        for mutation in ("missing", "extra", "duplicate", "version", "descriptive"):
            bom = copy.deepcopy(original)
            packages = bom["packages"]
            if mutation == "missing":
                packages.pop(0)
            elif mutation == "extra":
                packages.append({"name": "fixture.invalid/extra", "versionInfo": "v1.0.0"})
            elif mutation == "duplicate":
                packages.append(copy.deepcopy(packages[0]))
            elif mutation == "version":
                packages[0]["versionInfo"] = "v0.0.0-wrong"
            else:
                packages[-1]["name"] = "wrong-container"
            path.write_bytes(image.canonical(bom))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "SPDX|SBOM"):
                candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_archive_digest_mismatch_is_denied_before_unpack(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "EXACT_IMAGE_ARTIFACT"):
            readback.verify(self.zip(), self.root / "readback", "0" * 64, "b" * 40, 1)

    def test_archive_member_tamper_and_duplicate_are_denied(self):
        self.prepare()
        original = self.zip()
        with zipfile.ZipFile(original) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        members["build-source.json"] = b"{}"
        bad = self.root / "bad.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        dest = self.root / "unpack"
        dest.mkdir()
        with self.assertRaisesRegex(ValueError, "CHECKSUM_MISMATCH"):
            readback.unpack(bad, dest)
        with warnings.catch_warnings(), zipfile.ZipFile(bad, "a") as archive:
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr("build-source.json", b"duplicate")
        with self.assertRaisesRegex(ValueError, "EXACT_UNIQUE_ARCHIVE"):
            readback.unpack(bad, self.root / "unused")

    def test_checksum_paths_and_traversal_are_rejected(self):
        for path in ("../escape", "/absolute", "a\\b", "a/../b"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "UNSAFE_OR_DUPLICATE"):
                readback.checksum_map(["0" * 64 + "  " + path])


class RegressionIdentityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'regressions.jsonl'
        self.base = [{'Action': 'pass', 'Package': 'fixture/pkg', 'Test': 'TestRequired'},
                     {'Action': 'skip', 'Package': 'fixture/pkg', 'Test': 'TestConditional'},
                     {'Action': 'pass', 'Package': 'fixture/pkg'}]
        profile = {'terminalTestsSha256': image.sha(b'pass\tfixture/pkg\tTestRequired\n'),
                   'terminalPackagesSha256': image.sha(b'pass\tfixture/pkg\n'),
                   'environmentConditionalTests': {'TestConditional': ['TestConditional/child']},
                   'environmentConditionalPackage': 'fixture/pkg'}
        mocked = patch.object(candidate, 'MANIFEST', {'regressionProfiles': {'fixture': profile}})
        mocked.start(); self.addCleanup(mocked.stop)

    def verify(self, rows):
        self.path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return candidate.verify_regressions(self.path, 'fixture')

    def test_observed_environment_skip_stays_skip(self):
        result = self.verify(self.base)
        self.assertEqual(result['counts']['skip_tests'], 1)
        self.assertEqual(result['counts']['pass_tests'], 1)

    def test_supported_environment_must_pass_all_conditional_children(self):
        rows = copy.deepcopy(self.base)
        rows[1]['Action'] = 'pass'
        rows.append({'Action': 'pass', 'Package': 'fixture/pkg', 'Test': 'TestConditional/child'})
        self.assertEqual(self.verify(rows)['counts']['pass_tests'], 3)
        rows.pop()
        with self.assertRaisesRegex(ValueError, 'CONDITIONAL_CHILDREN'):
            self.verify(rows)

    def test_conditional_parent_and_children_cannot_move_to_another_package(self):
        changed = copy.deepcopy(self.base); changed[1]['Package'] = 'fixture/wrong'
        with self.assertRaisesRegex(ValueError, 'CONDITIONAL_TEST_PACKAGE_CHANGED'):
            self.verify(changed)
        changed = copy.deepcopy(self.base); changed[1]['Action'] = 'pass'
        changed.append({'Action': 'pass', 'Package': 'fixture/wrong', 'Test': 'TestConditional/child'})
        with self.assertRaisesRegex(ValueError, 'CONDITIONAL_TEST_PACKAGE_CHANGED'):
            self.verify(changed)

    def test_failure_duplicate_and_missing_terminal_are_denied(self):
        failed = copy.deepcopy(self.base); failed[0]['Action'] = 'fail'
        for rows in (failed, self.base + [self.base[0]]):
            with self.assertRaisesRegex(ValueError, 'COMPLETE_UNIQUE'):
                self.verify(rows)
        with self.assertRaisesRegex(ValueError, 'EXACT_OBSERVED'):
            self.verify(self.base[1:])

    def test_other_test_cannot_be_substituted_for_required_test(self):
        changed = copy.deepcopy(self.base); changed[0]['Test'] = 'TestWrong'
        with self.assertRaisesRegex(ValueError, 'EXACT_OBSERVED'):
            self.verify(changed)

    def test_extra_conditional_child_or_other_skip_is_denied(self):
        changed = copy.deepcopy(self.base); changed[0]['Action'] = 'skip'
        with self.assertRaisesRegex(ValueError, 'EXACT_OBSERVED'):
            self.verify(changed)
        changed = copy.deepcopy(self.base)
        changed.append({'Action': 'pass', 'Package': 'fixture/pkg', 'Test': 'TestConditional/unexpected'})
        with self.assertRaisesRegex(ValueError, 'CONDITIONAL_CHILDREN'):
            self.verify(changed)


if __name__ == "__main__":
    unittest.main()
