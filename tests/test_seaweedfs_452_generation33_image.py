"""Boundaries for fresh A33 build evidence and unmodified raw package identities."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
script = ROOT / "scripts/qualify-seaweedfs-452-generation33-image.py"
spec = importlib.util.spec_from_file_location("candidate33", script)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
image = candidate.engine


class QualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.members = image.baseline_observation()

    def test_observed_source_evidence_satisfies_build_identity_contract(self):
        packages, info, closure, observed = image.verify_fresh_source(self.members,
            image.preflight.COMMIT, image.preflight.RUN)
        self.assertEqual(len(packages), 1532)
        self.assertEqual(len(image.contract.parse_module_rows(info)), 214)
        self.assertEqual(observed["binarySha256"], image.PROFILE.binary_sha)
        self.assertFalse(closure["legacyYamlCompiled"])

    def test_observer_archive_cannot_be_relabelled_as_fresh_qualification(self):
        for commit, run in ((image.preflight.COMMIT, image.preflight.RUN + 1), ("1" * 40, image.preflight.RUN)):
            with self.subTest(commit=commit, run=run), self.assertRaisesRegex(ValueError, "EXACT_FRESH_YAML33"):
                image.verify_fresh_source(self.members, commit, run)
        with self.assertRaisesRegex(ValueError, "NEW_GITHUB_PRODUCER"):
            image.build_evidence(Path("not-read.zip"), image.preflight.COMMIT, image.preflight.RUN)

    def test_vendored_origins_cannot_hide_modified_archive_identity(self):
        changed = dict(self.members)
        origins = json.loads(changed["baseline-vendor-origins.json"])
        target = next(row for row in origins["modules"] if row["module"] == "gopkg.in/yaml.v3")
        target["inputZipSha256"] = "1" * 64
        changed["baseline-vendor-origins.json"] = json.dumps(origins).encode()
        with self.assertRaisesRegex(ValueError, "ORIGINAL_VENDOR_INPUT_CHANGED"):
            image.verify_fresh_source(changed, image.preflight.COMMIT, image.preflight.RUN)

    def scan_fixture(self):
        info = self.members["first-build-info.stdout"].decode()
        modules = image.contract.parse_module_rows(info)
        main = next(tuple(line.split("\t")[2:4]) for line in info.splitlines() if line.startswith("\tmod\t"))
        modules |= {main, ("stdlib", "v1.27.3")}
        packages = [{"Name": name, "Version": version,
                     "Identifier": {"PURL": f"pkg:golang/{name}@{version}"}} for name, version in sorted(modules)]
        nodes = [{"name": pkg["Name"], "versionInfo": pkg["Version"], "SPDXID": "SPDXRef-" + str(i),
                  "externalRefs": [{"referenceType": "purl", "referenceLocator": pkg["Identifier"]["PURL"]}]}
                 for i, pkg in enumerate(packages)]
        nodes.extend([{"name": "usr/local/bin/weed", "primaryPackagePurpose": "APPLICATION"},
                      {"name": "fixture:33", "primaryPackagePurpose": "CONTAINER"}])
        return ({"Trivy": {"Version": "0.70.0"}, "ArtifactName": "fixture:33",
                 "Results": [{"Type": "gobinary", "Packages": packages}]},
                {"packages": nodes}, info)

    def test_scan_and_spdx_are_complete_and_expose_unresolved_findings(self):
        scan, spdx, info = self.scan_fixture()
        scan["Results"][0]["Vulnerabilities"] = [{"Severity": "HIGH", "VulnerabilityID": "CVE-test-only"}]
        raw_scan, raw_spdx = (json.dumps(item).encode() for item in (scan, spdx))
        actual = image.scan_inventories(raw_scan, raw_spdx, info)
        self.assertEqual(actual["scannedBinaryComponents"], 216)
        self.assertEqual(actual["spdxPackages"], 218)
        self.assertEqual(actual["vulnerabilitySubgate"], "HELD_RAW_FINDINGS")
        self.assertEqual(actual["rawScanSha256"], image.sha(raw_scan))
        self.assertEqual(actual["rawSpdxSha256"], image.sha(raw_spdx))

    def test_unmodified_canonical_purls_required_and_legacy_yaml_denied(self):
        scan, spdx, info = self.scan_fixture()
        mutated = copy.deepcopy(scan)
        row = next(p for p in mutated["Results"][0]["Packages"] if p["Name"] == "github.com/apache/iceberg-go")
        row["Identifier"]["PURL"] = "pkg:golang/local-fork@v0.7.0"
        with self.assertRaisesRegex(ValueError, "CANONICAL_RAW_SCAN_IDENTITY"):
            image.scan_inventories(json.dumps(mutated).encode(), json.dumps(spdx).encode(), info)
        spdx["packages"].append({"name": "gopkg.in/yaml.v3", "versionInfo": "v3.0.1"})
        with self.assertRaisesRegex(ValueError, "RAW_SPDX_LEGACY_YAML_PRESENT"):
            image.scan_inventories(json.dumps(scan).encode(), json.dumps(spdx).encode(), info)

    def test_fresh_bundle_rejects_traversal_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("observation/../escape", b"unsafe")
            with self.assertRaisesRegex(ValueError, "SAFE_REGULAR_FRESH_SOURCE_MEMBER"):
                image.read_bundle(archive)


if __name__ == "__main__":
    unittest.main()
