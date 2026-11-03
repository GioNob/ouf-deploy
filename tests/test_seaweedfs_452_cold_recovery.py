import datetime
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cold_recovery", ROOT / "scripts/run-seaweedfs-452-cold-recovery.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class ColdRecoveryTests(unittest.TestCase):
    def test_copy_requires_independent_empty_root_and_verifies_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "payload").write_bytes(b"\x00fixture\xff")
            expected = lab.cold_copy(source, root / "backup")
            self.assertEqual(expected["payload"]["sha256"], lab.digest(b"\x00fixture\xff"))
            with self.assertRaisesRegex(RuntimeError, "EMPTY_NEW"):
                lab.cold_copy(source, root / "backup")
            with self.assertRaisesRegex(RuntimeError, "INDEPENDENT"):
                lab.cold_copy(source, source / "nested")
            (root / "backup/payload").write_bytes(b"changed")
            self.assertNotEqual(lab.inventory(root / "backup"), expected)

    def test_symlink_is_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "outside").write_bytes(b"outside")
            (root / "source/link").symlink_to(root / "outside")
            with self.assertRaisesRegex(RuntimeError, "SYMLINK"):
                lab.cold_copy(root / "source", root / "backup")
            self.assertFalse((root / "backup").exists())

    def test_file_and_total_budgets_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_bytes(b"1234")
            (root / "two").write_bytes(b"5678")
            with patch.object(lab, "MAX_FILE", 3):
                with self.assertRaisesRegex(RuntimeError, "FILE_BUDGET"):
                    lab.inventory(root)
            with patch.object(lab, "MAX_TOTAL", 7):
                with self.assertRaisesRegex(RuntimeError, "BACKUP_BUDGET"):
                    lab.inventory(root)

    def test_signer_binds_payload_metadata_and_exact_loopback(self):
        now = datetime.datetime(2026, 11, 3, tzinfo=datetime.timezone.utc)
        params = {"extra": {"x-amz-meta-ouf-content-hash": "test"}, "now": now}
        first = lab.signed_headers("PUT", "/bucket/key", body=b"one", **params)
        second = lab.signed_headers("PUT", "/bucket/key", body=b"two", **params)
        self.assertEqual(first["host"], "127.0.0.1:18333")
        self.assertIn("20261103/us-east-1/s3/aws4_request", first["authorization"])
        self.assertIn("x-amz-meta-ouf-content-hash", first["authorization"])
        self.assertNotEqual(first["authorization"], second["authorization"])

    def test_run_refuses_non_ci_before_any_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "new"
            with patch.dict(lab.os.environ, {"GITHUB_ACTIONS": "false"}):
                with self.assertRaisesRegex(RuntimeError, "ISOLATED_CI_ONLY"):
                    lab.run(Path("missing.zip"), destination)
            self.assertFalse(destination.exists())

    def test_readiness_does_not_retry_authorization_or_unknown_failure(self):
        with patch.object(lab, "request", side_effect=RuntimeError("HTTP_403_GET")) as request:
            with self.assertRaisesRegex(RuntimeError, "PERMANENT_READINESS"):
                lab.client("ready")
            self.assertEqual(request.call_count, 1)
        with patch.object(lab, "request", side_effect=OSError("unknown")) as request:
            with self.assertRaisesRegex(RuntimeError, "UNCLASSIFIED_READINESS"):
                lab.client("ready")
            self.assertEqual(request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
