"""Exercise the real observed artifact and prevent source pins from being relabelled."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "scripts/verify-seaweedfs-yaml33-observation.py"
spec = importlib.util.spec_from_file_location("image_preflight", path)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class ImagePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / preflight.MANIFEST).read_bytes())
        cls.parent = (ROOT / preflight.PARENT).read_bytes()
        cls.profile = (ROOT / preflight.PROFILE).read_bytes()
        cls.receipt = (ROOT / preflight.OBSERVED_RECEIPT).read_bytes()
        cls.archive = ROOT / preflight.OBSERVED_ARCHIVE

    def test_real_artifact_binds_image_inputs_without_claiming_image_qualification(self):
        result = preflight.verify_repo(ROOT)
        self.assertEqual(result["compiledPackages"], 1532)
        self.assertEqual(result["compiledModules"], 214)
        self.assertEqual(result["allVendorModules"], 341)
        self.assertEqual(result["vendorFilesBound"], 13918)
        self.assertFalse(result["imageQualified"])
        self.assertFalse(result["originalInputZipsRehashedByThisPreflight"])

    def test_generation32_binary_cannot_be_used_as_the_yaml33_build(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["build"]["binarySha256"] = json.loads(self.parent)["build"]["binarySha256"]
        with self.assertRaisesRegex(ValueError, "ACTUAL_NEW_VENDOR_BUILD_FACTS"):
            preflight.verify(manifest, self.parent, self.profile, self.receipt, self.archive)

    def test_vendor_inventory_cannot_substitute_its_own_digest(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["materialsSha256"]["vendor-before-files.json"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "VENDOR_MATERIAL_CHANGED"):
            preflight.verify(manifest, self.parent, self.profile, self.receipt, self.archive)

    def test_changed_aggregate_or_archive_bytes_fail_before_evidence_use(self):
        with self.assertRaisesRegex(ValueError, "EXACT_OBSERVATION_RECEIPT"):
            preflight.verify(self.manifest, self.parent, self.profile, self.receipt + b" ", self.archive)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "altered.zip"
            path.write_bytes(self.archive.read_bytes()[:-1] + b"X")
            with self.assertRaisesRegex(ValueError, "EXACT_OBSERVATION_ARCHIVE"):
                preflight.verify(self.manifest, self.parent, self.profile, self.receipt, path)

    def test_only_the_observed_inactive_footer_can_be_projected_out(self):
        body = b"# example.org/project v1.0.0\n## explicit\nexample.org/project\n"
        footer = (preflight.INACTIVE_FOOTER + "\n").encode()
        self.assertEqual(preflight.inactive_footer_free(body + footer), body)
        for mutated in (body + b"# example.org/a => example.org/b v1.0.0\n", body + footer + footer,
                        body + preflight.INACTIVE_MODULE.encode() + b"/pkg\n" + footer,
                        body + b"# " + preflight.INACTIVE_MODULE.encode() + b" v1.0.1\n" + footer):
            with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                preflight.inactive_footer_free(mutated)


if __name__ == "__main__":
    unittest.main()
