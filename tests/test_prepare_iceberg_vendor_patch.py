import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("materializer", HERE.parent / "scripts/prepare_iceberg_vendor_patch.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class VendorPatchGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vendor = Path(self.tmp.name) / "vendor"
        shutil.copytree(os.environ["OUF_YAML_BASE_VENDOR_FIXTURE"], self.vendor)
        self.zip = Path(os.environ["OUF_ICEBERG_INPUT_ZIP"])
        self.before = m.inventory(self.vendor)
        self.base = m.tree_digest(self.before)
        after = dict(self.before)
        after[m.CONFIG] = m.digest(m.patched_bytes((self.vendor / m.CONFIG).read_bytes()))
        self.after = m.tree_digest(after)

    def run_guard(self, base=None, after=None, archive=None):
        return m.prepare(self.vendor, archive or self.zip, base or self.base, after or self.after)

    def test_exact_patch_preserves_licenses_and_changes_only_config(self):
        result = self.run_guard()
        changed = [p for p, sha in m.inventory(self.vendor).items() if self.before[p] != sha]
        self.assertEqual([m.CONFIG], changed)
        self.assertTrue(result["upstreamChecksumDoesNotDescribePatchedBytes"])
        self.assertIn(m.NOTICE.encode(), (self.vendor / m.CONFIG).read_bytes())

    def test_arbitrary_sibling_change_rejected_before_config_write(self):
        p = self.vendor / "modules.txt"
        p.write_bytes(p.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "BASE_VENDOR_TREE_CHANGED"):
            self.run_guard()
        self.assertEqual(self.before[m.CONFIG], m.digest((self.vendor / m.CONFIG).read_bytes()))

    def test_base_config_pin_independently_enforced(self):
        p = self.vendor / m.CONFIG
        p.write_bytes(p.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "BASE_CONFIG_CHANGED"):
            self.run_guard(base=m.tree_digest(m.inventory(self.vendor)))

    def test_license_pin_independently_enforced(self):
        (self.vendor / m.MODULE / "NOTICE").write_text("changed")
        with self.assertRaisesRegex(ValueError, "UPSTREAM_LICENSE_OR_NOTICE_CHANGED"):
            self.run_guard(base=m.tree_digest(m.inventory(self.vendor)))

    def test_module_version_drift_rejected(self):
        p = self.vendor / "modules.txt"
        p.write_text(p.read_text().replace("# go.yaml.in/yaml/v3 v3.0.5", "# go.yaml.in/yaml/v3 v3.0.4"))
        with self.assertRaisesRegex(ValueError, "EXACT_MODULE_METADATA_REQUIRED"):
            self.run_guard(base=m.tree_digest(m.inventory(self.vendor)))

    def test_wrong_result_digest_rejected_before_write(self):
        with self.assertRaisesRegex(ValueError, "EXPECTED_PATCHED_TREE_MISMATCH"):
            self.run_guard(after="0" * 64)
        self.assertEqual(self.before, m.inventory(self.vendor))

    def test_changed_archive_rejected_before_write(self):
        archive = Path(self.tmp.name) / "changed.zip"
        archive.write_bytes(self.zip.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "UPSTREAM_MODULE_ZIP_CHANGED"):
            self.run_guard(archive=archive)
        self.assertEqual(self.before, m.inventory(self.vendor))

    def test_vendor_symlink_rejected(self):
        (self.vendor / "unexpected-link").symlink_to(self.zip)
        with self.assertRaisesRegex(ValueError, "VENDOR_SYMLINK_DENIED"):
            self.run_guard()
        self.assertEqual(self.before[m.CONFIG], m.digest((self.vendor / m.CONFIG).read_bytes()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
