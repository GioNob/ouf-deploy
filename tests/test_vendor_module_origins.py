"""Verify genuine cached input bytes; every mutation uses a temporary copy."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("origins", HERE.parent / "tools/storage_security/vendor_module_origins.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ModuleOriginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cache = Path(os.environ["OUF_MODULE_CACHE"])
        self.go_sum = Path(os.environ["OUF_ROOT_GO_SUM"]).read_text()
        locks = {tuple(row.split()[:2]): row.split()[2] for row in self.go_sum.splitlines()}
        self.identities = [("github.com/apache/iceberg-go", "v0.7.0"), ("go.yaml.in/yaml/v3", "v3.0.5")]
        self.info = "fixture: go1.27.3\n" + "".join("\tdep\t" + n + "\t" + v + "\t\n" for n, v in self.identities)
        self.records = []
        for name, version in self.identities:
            prefix = cache / "cache/download" / name / "@v" / version
            info = json.loads(prefix.with_suffix(prefix.suffix + ".info").read_text())
            self.records.append({"Path": name, "Version": version,
                "Zip": str(prefix) + ".zip", "GoMod": str(prefix) + ".mod", "Info": str(prefix) + ".info",
                "Sum": locks[(name, version)], "GoModSum": locks[(name, version + "/go.mod")],
                "Origin": info.get("Origin")})

    def collect(self):
        return m.collect(self.info, self.go_sum, self.records)

    def test_real_zip_and_gomod_h1_recomputed_for_every_module(self):
        result = self.collect()
        self.assertEqual(2, result["moduleCount"])
        self.assertEqual(self.identities, [(r["module"], r["version"]) for r in result["modules"]])
        self.assertTrue(result["modules"][0]["modifiedInVendor"])
        self.assertFalse(result["modules"][1]["modifiedInVendor"])
        self.assertFalse(result["moduleCacheMutated"])
        self.assertEqual(m.ICEBERG_ZIP_SHA256, result["modules"][0]["inputZipSha256"])

    def test_missing_module_input_rejected(self):
        self.records.pop()
        with self.assertRaisesRegex(ValueError, "EXACT_ORIGINAL_MODULE_DOWNLOAD_REQUIRED"): self.collect()

    def test_duplicate_module_input_rejected(self):
        self.records.append(copy.deepcopy(self.records[0]))
        with self.assertRaisesRegex(ValueError, "EXACT_ORIGINAL_MODULE_DOWNLOAD_REQUIRED"): self.collect()

    def test_forged_h1_not_in_root_lock_rejected(self):
        self.records[0]["Sum"] = "h1:" + "A" * 43 + "="
        with self.assertRaisesRegex(ValueError, "INPUT_SUM_NOT_IN_LOCK"): self.collect()

    def test_other_module_archive_cannot_substitute_upstream(self):
        self.records[0]["Zip"] = self.records[1]["Zip"]
        with self.assertRaisesRegex(ValueError, "EXACT_MODULE_ZIP_PREFIX_REQUIRED"): self.collect()

    def test_archive_reencoding_with_same_content_h1_changes_pinned_bytes(self):
        original = Path(self.records[0]["Zip"])
        changed = Path(self.tmp.name) / "padded.zip"
        changed.write_bytes(original.read_bytes() + b"different zip encoding")
        self.assertEqual(self.records[0]["Sum"], m.zip_h1(changed, *self.identities[0]))
        self.records[0]["Zip"] = str(changed)
        with self.assertRaisesRegex(ValueError, "EXACT_ICEBERG_INPUT_ZIP_REQUIRED"): self.collect()

    def test_changed_gomod_content_rejected(self):
        changed = Path(self.tmp.name) / "changed.mod"
        changed.write_bytes(Path(self.records[0]["GoMod"]).read_bytes() + b"\n// modified\n")
        self.records[0]["GoMod"] = str(changed)
        with self.assertRaisesRegex(ValueError, "MODULE_GOMOD_H1_MISMATCH"): self.collect()

    def test_download_record_stream_and_array_are_equivalent(self):
        stream = b"\n".join(json.dumps(r).encode() for r in self.records)
        self.assertEqual(self.records, m.parse_records(stream))
        self.assertEqual(self.records, m.parse_records(json.dumps(self.records).encode()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
