"""Contract tests use explicitly synthetic generation records, not releases."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("guard", HERE.parent / "tools/storage_security/vendor_yaml_source.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class VendorSourceProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "synthetic-source"
        self.root.mkdir()
        fixture = Path(os.environ["OUF_YAML_PATCHED_VENDOR_FIXTURE"])
        shutil.copytree(fixture, self.root / "vendor")
        (self.root / "go.mod").write_text("module example.invalid/synthetic-contract\ngo 1.27.3\n")
        (self.root / "go.sum").write_text(
            "github.com/apache/iceberg-go v0.7.0 " + g.INPUT_H1 + "\n"
            "github.com/apache/iceberg-go v0.7.0/go.mod h1:oGz5MX3/m3GDc6acsrwbdHChj28jZH8MVDWqUrW6WQQ=\n"
            "go.yaml.in/yaml/v3 v3.0.5 h1:N6y/pJk8buWs9NY5ERU2HSMfm+IuD/OtfdAnq6kESPw=\n"
            "go.yaml.in/yaml/v3 v3.0.5/go.mod h1:HVTZu1O7/Vkt2N+BFy8Zza+lnLsABggaTM2ZpNIGuKg=\n")
        (self.root / "main.go").write_text("package main\nfunc main(){}\n")
        self.patch = Path(os.environ["OUF_YAML_NOTICE_PATCH"]).read_bytes()
        self.materializer = (HERE.parent / "scripts/prepare_iceberg_vendor_patch.py").read_bytes()
        rows = g.inventory(self.root / "vendor")
        before = dict(rows)
        before[g.CONFIG] = g.BASE_CONFIG
        self.parent = g.canonical({"generation": 32, "build": {"patchedSourceTree": "a" * 40},
                                   "fixture": "SYNTHETIC_CONTRACT_RECORD_NOT_A_RELEASE"})
        self.profile = {
            "schema": "ouf.seaweedfs-vendor-yaml-source-profile.v1", "generation": 33,
            "previousGeneration": 32, "status": "BOUND_SOURCE_PROFILE_NOT_ADMITTED",
            "dependencySourceMode": "vendor-with-reviewed-source-patches", "releaseAdmitted": False,
            "runtimeAuthorityIssued": False, "allDependenciesMaintained": False, "targetOperations": 0,
            "maintenance": {"status": "OPEN", "technicalOwner": None, "reviewCadence": "EACH_CANDIDATE_AND_WEEKLY_WHILE_PATCH_ACTIVE"},
            "build": {"go": "1.27.3", "os": "linux", "arch": "amd64", "cgo": False, "tags": [], "trimpath": True, "moduleMode": "vendor"},
            "upstream": {"module": g.ICEBERG, "version": "v0.7.0", "commit": g.BASE_COMMIT,
                         "zipSha256": g.INPUT_ZIP_SHA256, "h1InputOnly": g.INPUT_H1, "checksumDoesNotDescribePatchedSource": True},
            "maintainedYaml": {"module": g.YAML, "version": "v3.0.5", "h1": "h1:N6y/pJk8buWs9NY5ERU2HSMfm+IuD/OtfdAnq6kESPw="},
            "patch": {"file": g.CONFIG, "sha256": g.PATCH_SHA256, "originalFileSha256": g.BASE_CONFIG, "modifiedFileSha256": g.PATCHED_CONFIG_SHA256},
            "vendor": {"baseTreeSha256": g.tree_sha(before), "patchedTreeSha256": g.tree_sha(rows), "modulesTxtSha256": rows["modules.txt"], "fileCount": len(rows)},
            "rootLockfilesSha256": {n: g.sha((self.root / n).read_bytes()) for n in ["go.mod", "go.sum"]},
            "baseSourceTreeSha256": g.tree_sha(g.source_inventory(self.root)), "materializerSha256": g.sha(self.materializer),
            "previousGenerationManifestSha256": g.sha(self.parent), "previousSourceGitTree": "a" * 40,
        }
        self.packages = [g.ICEBERG + "/config", g.ICEBERG + "/table", g.YAML]
        self.info = "fixture: go1.27.3\n\tdep\tgithub.com/apache/iceberg-go\tv0.7.0\t\n\tdep\tgo.yaml.in/yaml/v3\tv3.0.5\t\n"
        self.execution = {"effectiveGOFLAGS": "", "effectiveGOWORK": "off", "rootCommands": [
            {"role": "build", "args": ["build", "-mod=vendor", "./weed"]},
            {"role": "production-deps", "args": ["list", "-deps", "-mod=vendor", "./weed"]},
            {"role": "regression", "args": ["test", "-mod=vendor", "./weed/s3api"]},
            {"role": "race", "args": ["test", "-race", "-mod=vendor", "./weed/server"]},
            {"role": "excluded-profile", "args": ["build", "-mod=vendor", "-tags=kafka", "./weed"]},
        ]}
        self.scan = {"Results": [{"Type": "gobinary", "Packages": [
            {"Name": n, "Version": v, "Identifier": {"PURL": "pkg:golang/" + n + "@" + v}}
            for n, v in g.PINNED.items()]}]}
        self.spdx = {"packages": [{"name": n, "versionInfo": v, "SPDXID": "SPDXRef-" + str(i),
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/" + n + "@" + v}]}
            for i, (n, v) in enumerate(g.PINNED.items())]}

        locks = {tuple(line.split()[:2]): line.split()[2] for line in (self.root / "go.sum").read_text().splitlines()}
        # Synthetic origin records exercise the supplement's bindings. Actual
        # input ZIP content/h1 recomputation is tested separately by the collector.
        self.origins = {"schema": "ouf.vendor-original-module-origins.v1",
            "status": "ORIGINAL_INPUTS_VERIFIED_NOT_RELEASE_ADMITTED", "moduleCacheMutated": False,
            "rootGoSumSha256": g.sha((self.root / "go.sum").read_bytes()), "buildInfoSha256": g.sha(self.info.encode()),
            "moduleCount": 2, "modules": [{"module": n, "version": v,
                "inputZipH1": locks[(n, v)], "inputGoModH1": locks[(n, v + "/go.mod")],
                "inputZipSha256": g.INPUT_ZIP_SHA256 if n == g.ICEBERG else "b" * 64,
                "inputGoModSha256": "c" * 64, "sourceOrigin": None,
                "modifiedInVendor": n == g.ICEBERG, "checksumsDescribeOriginalInputsOnly": True}
                for n, v in g.PINNED.items()]}
        self.profile["moduleOriginsSha256"] = g.sha(g.canonical(self.origins))
        self.profile["moduleOriginCount"] = 2


    def assess(self):
        return g.assess(self.profile, self.root, self.patch, self.materializer,
                        b"SYNTHETIC_BINARY_BYTES_NOT_A_RELEASE", self.packages, self.info,
                        self.execution, g.canonical(self.scan), g.canonical(self.spdx), self.parent, g.canonical(self.origins))

    def test_valid_supplement_keeps_raw_records_and_ownership_open(self):
        before = copy.deepcopy((self.scan, self.spdx))
        result = self.assess()
        self.assertEqual(before, (self.scan, self.spdx))
        self.assertFalse(result["rawArtifactsRewritten"])
        self.assertFalse(result["releaseAdmitted"])
        self.assertFalse(result["allDependenciesMaintained"])
        self.assertIsNone(result["maintenance"]["technicalOwner"])
        self.assertEqual(result["rawSpdxSha256"], g.sha(g.canonical(self.spdx)))

    def test_cli_writes_separate_supplement_and_rejects_raw_output(self):
        evidence = Path(self.tmp.name) / "synthetic-evidence"
        evidence.mkdir()
        records = {"profile": g.canonical(self.profile), "previous-manifest": self.parent,
                   "binary": b"SYNTHETIC_BINARY_BYTES_NOT_A_RELEASE",
                   "packages": g.canonical({"packages": self.packages}),
                   "build-info": self.info.encode(), "execution": g.canonical(self.execution),
                   "module-origins": g.canonical(self.origins), "patch": self.patch,
                   "materializer": self.materializer, "scan": g.canonical(self.scan), "spdx": g.canonical(self.spdx)}
        command = [sys.executable, str(HERE.parent / "scripts/verify_iceberg_vendor_source_profile.py"),
                   "--root", str(self.root)]
        for key, value in records.items():
            path = evidence / key
            path.write_bytes(value)
            command.extend(["--" + key, str(path)])
        output = evidence / "supplement.json"
        result = subprocess.run(command + ["--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(output.read_bytes())["releaseAdmitted"])
        rejected = subprocess.run(command + ["--output", str(evidence / "scan")], capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("SEPARATE_PROVENANCE_OUTPUT_REQUIRED", rejected.stderr)
        for key in ("scan", "spdx"):
            self.assertEqual((evidence / key).read_bytes(), records[key])

    def test_unbound_draft_cannot_qualify(self):
        self.profile["status"] = "DRAFT_WAITING_FOR_GENERATION32_FREEZE"
        with self.assertRaisesRegex(ValueError, "BOUND_VENDOR_PROFILE_REQUIRED"): self.assess()

    def test_different_generation_parent_rejected(self):
        self.parent = g.canonical({"generation": 31, "build": {"patchedSourceTree": "a" * 40}})
        with self.assertRaisesRegex(ValueError, "FROZEN_GENERATION32_PARENT_REQUIRED"): self.assess()

    def test_no_invented_ownership_or_maintenance(self):
        self.profile["maintenance"]["technicalOwner"] = "unverified assignment"
        with self.assertRaisesRegex(ValueError, "EXPLICIT_OPEN_DOWNSTREAM_OWNERSHIP_REQUIRED"): self.assess()

    def test_source_mode_cannot_bypass_vendor(self):
        self.profile["build"]["moduleMode"] = "readonly"
        with self.assertRaisesRegex(ValueError, "EXACT_VENDOR_BUILD_MODE_REQUIRED"): self.assess()

    def test_changed_root_source_rejected(self):
        (self.root / "main.go").write_text("changed source\n")
        with self.assertRaisesRegex(ValueError, "BASE_SOURCE_TREE_CHANGED"): self.assess()

    def test_changed_patch_artifact_rejected(self):
        self.patch += b"\n"
        with self.assertRaisesRegex(ValueError, "DEPENDENCY_PATCH_CHANGED"): self.assess()

    def test_extra_vendor_edit_cannot_be_hidden_by_new_patched_hash(self):
        path = self.root / "vendor/go.yaml.in/yaml/v3/yaml.go"
        path.write_bytes(path.read_bytes() + b"\n")
        self.profile["vendor"]["patchedTreeSha256"] = g.tree_sha(g.inventory(self.root / "vendor"))
        with self.assertRaisesRegex(ValueError, "ONLY_LOCKED_CONFIG_DELTA_ALLOWED"): self.assess()

    def test_compiled_legacy_package_and_vendored_alias_rejected(self):
        for name in [g.LEGACY, "vendor/" + g.LEGACY, "example.invalid/root/vendor/" + g.LEGACY + "/internal"]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "COMPILED_LEGACY_YAML_PRESENT"):
                    g.verify_compiled_closure(self.packages + [name], self.info)

    def test_binary_legacy_module_rejected(self):
        self.info += "\tdep\tgopkg.in/yaml.v3\tv3.0.1\t\n"
        with self.assertRaisesRegex(ValueError, "BINARY_LEGACY_YAML_PRESENT"): self.assess()

    def test_iceberg_feature_cannot_be_removed_to_pass(self):
        self.packages.remove(g.ICEBERG + "/table")
        with self.assertRaisesRegex(ValueError, "ICEBERG_FEATURE_AND_MAINTAINED_YAML_REQUIRED"): self.assess()

    def test_upstream_h1_cannot_be_claimed_for_vendor_bytes(self):
        self.info = self.info.replace("v0.7.0\t\n", "v0.7.0\t" + g.INPUT_H1 + "\n")
        with self.assertRaisesRegex(ValueError, "VENDOR_BYTES_MUST_NOT_CLAIM_UPSTREAM_H1"): self.assess()

    def test_other_vendor_module_cannot_claim_upstream_h1(self):
        self.info += "\tdep\texample.invalid/third-module\tv1.0.0\th1:" + "A" * 43 + "=\n"
        with self.assertRaisesRegex(ValueError, "VENDOR_BYTES_MUST_NOT_CLAIM_UPSTREAM_H1"): self.assess()

    def test_duplicate_module_path_at_different_version_rejected(self):
        self.info += "\tdep\tgo.yaml.in/yaml/v3\tv3.0.4\t\n"
        with self.assertRaisesRegex(ValueError, "DUPLICATE_BINARY_MODULE_PATH"): self.assess()

    def test_replacement_module_rejected(self):
        self.info += "\t=>\texample.invalid/fork\tv0.7.0-ouf.1\t\n"
        with self.assertRaisesRegex(ValueError, "MODULE_REPLACEMENT_UNSUPPORTED"): self.assess()

    def test_one_root_command_cannot_bypass_vendor(self):
        self.execution["rootCommands"][2]["args"][1] = "-mod=readonly"
        with self.assertRaisesRegex(ValueError, "ROOT_COMMAND_BYPASSES_VENDOR"): self.assess()

    def test_missing_regression_or_effective_workspace_rejected(self):
        self.execution["rootCommands"].pop(2)
        with self.assertRaisesRegex(ValueError, "ALL_ROOT_VENDOR_COMMAND_ROLES_REQUIRED"): self.assess()
        self.execution["effectiveGOWORK"] = "auto"
        with self.assertRaisesRegex(ValueError, "EXPLICIT_EFFECTIVE_GO_CONFIGURATION_REQUIRED"): self.assess()

    def test_scanner_upstream_name_and_purl_cannot_be_replaced(self):
        self.scan["Results"][0]["Packages"][0]["Name"] = "example.invalid/fork"
        with self.assertRaisesRegex(ValueError, "CANONICAL_RAW_SCAN_IDENTITY_REQUIRED"): self.assess()

    def test_legacy_raw_scan_or_spdx_rejected(self):
        self.scan["Results"][0]["Packages"].append({"Name": g.LEGACY, "Version": "v3.0.1"})
        with self.assertRaisesRegex(ValueError, "RAW_SCAN_LEGACY_YAML_PRESENT"): self.assess()
        self.scan["Results"][0]["Packages"].pop()
        self.spdx["packages"].append({"name": g.LEGACY, "versionInfo": "v3.0.1"})
        with self.assertRaisesRegex(ValueError, "RAW_SPDX_LEGACY_YAML_PRESENT"): self.assess()

    def test_duplicate_or_wrong_canonical_spdx_node_rejected(self):
        self.spdx["packages"].append(copy.deepcopy(self.spdx["packages"][0]))
        with self.assertRaisesRegex(ValueError, "CANONICAL_RAW_SPDX_IDENTITY_REQUIRED"): self.assess()
        self.spdx["packages"].pop()
        self.spdx["packages"][0]["externalRefs"][0]["referenceLocator"] = "pkg:golang/example.invalid/fork@v0.7.0"
        with self.assertRaisesRegex(ValueError, "CANONICAL_RAW_SPDX_IDENTITY_REQUIRED"): self.assess()

    def test_missing_original_module_input_rejected(self):
        self.origins["modules"].pop()
        self.origins["moduleCount"] = self.profile["moduleOriginCount"] = 1
        self.profile["moduleOriginsSha256"] = g.sha(g.canonical(self.origins))
        with self.assertRaisesRegex(ValueError, "COMPLETE_BINARY_MODULE_ORIGINS_REQUIRED"): self.assess()

    def test_original_input_hash_cannot_be_relabelled_as_patched_hash(self):
        self.origins["modules"][0]["checksumsDescribeOriginalInputsOnly"] = False
        self.profile["moduleOriginsSha256"] = g.sha(g.canonical(self.origins))
        with self.assertRaisesRegex(ValueError, "ORIGINAL_VS_PATCHED_SOURCE_DISTINCTION_REQUIRED"): self.assess()

    def test_original_h1_must_match_the_frozen_root_lock(self):
        self.origins["modules"][0]["inputZipH1"] = "h1:" + "A" * 43 + "="
        self.profile["moduleOriginsSha256"] = g.sha(g.canonical(self.origins))
        with self.assertRaisesRegex(ValueError, "AUTHENTIC_INPUT_H1_LOCK_REQUIRED"): self.assess()

    def test_upstream_archive_byte_identity_cannot_drift(self):
        self.origins["modules"][0]["inputZipSha256"] = "0" * 64
        self.profile["moduleOriginsSha256"] = g.sha(g.canonical(self.origins))
        with self.assertRaisesRegex(ValueError, "EXACT_ICEBERG_ORIGIN_REQUIRED"): self.assess()



if __name__ == "__main__":
    unittest.main(verbosity=2)
