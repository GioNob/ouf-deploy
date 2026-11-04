"""Bounded observer tests; no full vendor, build, network or cache mutations."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("observe", HERE.parent / "scripts/observe-seaweedfs-yaml33.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def vendor_fixture(self):
        root = self.root / "vendor"
        root.mkdir()
        name, version = "example.invalid/component", "v1.2.3"
        path = root / name / "source.go"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"package component\n")
        (root / "modules.txt").write_text("# " + name + " " + version + "\n## explicit\n" + name + "\n")
        archive = self.root / "module.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(name + "@" + version + "/source.go", path.read_bytes())
        return root, [(name, version)], [{"Path": name, "Version": version, "Zip": str(archive)}]

    def test_corrected_parent_pin_and_canonical_helper_are_bound(self):
        inputs = json.loads((HERE.parent / "config/seaweedfs-yaml33-observation-inputs.json").read_bytes())
        self.assertEqual(inputs["baseManifestSha256"], "5289372fe7577936376497adba277fb329bb2a625652eacad47c854735937144")
        self.assertEqual(inputs["rootSourceTree32"], "80632ef3a54debb04531c1913860d2f94d2b418d")
        helper = "scripts/replay-seaweedfs-source-tree.py"
        self.assertEqual(inputs["inputFilesSha256"][helper], m.sha(HERE.parent / helper))
        for name, expected in inputs["inputFilesSha256"].items():
            self.assertEqual(expected, m.sha(HERE.parent / name), name)

    def test_all_baseline_files_bind_to_original_zip(self):
        root, rows, records = self.vendor_fixture()
        result = m.verify_vendor_files(root, rows, records)
        self.assertEqual(result["filesAuthenticatedAgainstOriginalZip"], 1)
        self.assertEqual(result["vendorTreeSha256"], m.guard.tree_sha(m.guard.inventory(root)))

    def test_authentic_archive_alongside_modified_vendor_is_rejected(self):
        root, rows, records = self.vendor_fixture()
        (root / rows[0][0] / "source.go").write_bytes(b"changed source\n")
        with self.assertRaisesRegex(ValueError, "VENDOR_FILE_DIFFERS_FROM_ORIGINAL_ZIP"):
            m.verify_vendor_files(root, rows, records)

    def test_added_source_missing_from_original_archive_is_rejected(self):
        root, rows, records = self.vendor_fixture()
        (root / rows[0][0] / "extra.go").write_text("package component\n")
        with self.assertRaisesRegex(ValueError, "VENDOR_FILE_NOT_IN_ORIGINAL_ZIP"):
            m.verify_vendor_files(root, rows, records)

    def test_unowned_vendor_file_is_rejected(self):
        root, rows, records = self.vendor_fixture()
        (root / "unowned").write_text("extra\n")
        with self.assertRaisesRegex(ValueError, "VENDOR_FILE_WITHOUT_MODULE"):
            m.verify_vendor_files(root, rows, records)

    def test_vendor_headers_cannot_hide_replacement_or_duplicate_identity(self):
        for text in ["# example.invalid/a v1.0.0 => example.invalid/b v1.0.0\n", "# example.invalid/a v1.0.0\n# example.invalid/a v1.1.0\n"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                m.vendor_modules(text)

    def test_module_header_enumeration_does_not_pretend_binary_build_info(self):
        text = m.module_info([("example.invalid/a", "v1.0.0")])
        self.assertIn("NOT binary build-info", text)
        self.assertEqual(m.vendor_modules("# example.invalid/a v1.0.0\n## explicit\nexample.invalid/a\n"), [("example.invalid/a", "v1.0.0")])

    def test_only_pinned_unused_replacement_footer_is_allowed(self):
        header = "# example.invalid/a v1.0.0\n## explicit\nexample.invalid/a\n"
        module = "github.com/tyler-smith/go-bip39"
        footer = f"# {module} => github.com/cosmos/go-bip39 v1.0.0\n"
        self.assertEqual(m.vendor_modules(header + footer), [("example.invalid/a", "v1.0.0")])
        for invalid in [
            footer + header,
            header + footer * 2,
            header + footer.replace("v1.0.0", "v1.0.1"),
            header + footer.replace(module, "example.invalid/b"),
            header + footer.replace(module, module + " v1.0.0"),
            header + f"# {module} v1.0.0\n" + footer,
            header + f"{module}/package\n" + footer,
        ]:
            with self.subTest(text=invalid), self.assertRaises(ValueError):
                m.vendor_modules(invalid)

    def test_failed_command_retains_stderr_and_exit_code(self):
        obs = m.Observer(self.root / "repo", self.root / "upstream", self.root / "work", self.root / "evidence", 20)
        with self.assertRaisesRegex(ValueError, "COMMAND_UNEXPECTED_EXIT"):
            obs.run("failure", [sys.executable, "-c", "import sys; print('diagnostic',file=sys.stderr); sys.exit(7)"])
        self.assertEqual(obs.commands[0]["exitCode"], 7)
        self.assertIn("diagnostic", (obs.evidence / "failure.stderr").read_text())
        m.finalize(obs.evidence, {"status": "OBSERVATION_FAIL_NOT_RELEASE_QUALIFIED", "releaseAdmitted": False})
        self.assertIn("failure.stderr", (obs.evidence / "SHA256SUMS").read_text())

    def test_timeout_kills_process_group_and_preserves_diagnostics(self):
        obs = m.Observer(self.root / "repo", self.root / "upstream", self.root / "work", self.root / "evidence", 20)
        with self.assertRaisesRegex(ValueError, "COMMAND_TIMEOUT"):
            obs.run("timeout", [sys.executable, "-c", "import time; print('started',flush=True); time.sleep(5)"], timeout=0.1)
        self.assertTrue(obs.commands[0]["timedOut"])
        self.assertEqual(obs.commands[0]["exitCode"], 124)
        self.assertIn("started", (obs.evidence / "timeout.stdout").read_text())

    def test_existing_work_or_source_nested_work_is_rejected(self):
        work = self.root / "exists"
        work.mkdir()
        with self.assertRaisesRegex(ValueError, "FRESH_OBSERVATION_WORK_REQUIRED"):
            m.Observer(self.root / "repo", self.root / "upstream", work, self.root / "evidence")
        with self.assertRaisesRegex(ValueError, "ISOLATED_OBSERVATION_WORK_REQUIRED"):
            m.Observer(self.root / "repo", self.root / "upstream", self.root / "repo/work", self.root / "evidence")

    def test_finalizer_hashes_failed_observation_without_binary_or_vendor(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "failure.log").write_text("failure\n")
        m.finalize(evidence, {"status": "OBSERVATION_FAIL_NOT_RELEASE_QUALIFIED", "releaseAdmitted": False})
        self.assertEqual(set(p.name for p in evidence.iterdir()), {"failure.log", "observation.json", "SHA256SUMS"})
        self.assertFalse(json.loads((evidence / "observation.json").read_bytes())["releaseAdmitted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
