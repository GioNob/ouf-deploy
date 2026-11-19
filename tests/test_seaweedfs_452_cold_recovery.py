import datetime
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cold_recovery", ROOT / "scripts/run-seaweedfs-452-cold-recovery.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class ColdRecoveryTests(unittest.TestCase):
    def test_seed_verify_separates_recovery_from_real_mime_failure_without_replay(self):
        objects, calls = {}, []

        def transport(method, key=None, body=b"", query=None, extra=None,
                      expected=(200,), timeout=30, bucket=lab.BUCKET):
            calls.append((method, bucket, key))
            if method == "PUT":
                if key:
                    headers = {**(extra or {}), "content-length": str(len(body))}
                    if bucket == lab.COMPAT_BUCKET:
                        headers["content-type"] = "text/plain; charset=utf-8"
                    objects[bucket, key] = (body, headers)
                return b"", {}
            if method == "DELETE":
                del objects[bucket, key]
                return b"", {}
            if key == "":
                keys = sorted(k for b, k in objects if b == bucket)
                start = int((query or {}).get("continuation-token", "0"))
                page, more = keys[start:start + 2], start + 2 < len(keys)
                xml = '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                xml += ''.join('<Contents><Key>' + escape(k) + '</Key></Contents>' for k in page)
                xml += '<IsTruncated>' + str(more).lower() + '</IsTruncated>'
                if more:
                    xml += '<NextContinuationToken>' + str(start + 2) + '</NextContinuationToken>'
                return (xml + '</ListBucketResult>').encode(), {}
            if (bucket, key) not in objects:
                self.assertEqual(expected, (404,))
                return b"", {}
            data, headers = objects[bucket, key]
            return (b"" if method == "HEAD" else data), dict(headers)

        with patch.object(lab, "request", side_effect=transport):
            before = lab.client("seed")
            mutation_end = len(calls)
            after = lab.client("verify")
        self.assertEqual(before["objects"], after["objects"])
        self.assertEqual(before["octetStreamCompatibility"], after["octetStreamCompatibility"])
        self.assertEqual(len(before["objects"]), 4)
        self.assertEqual(before["listPages"], 2)
        probe = before["octetStreamCompatibility"]
        self.assertEqual(probe["status"], "FAIL")
        self.assertFalse(probe["g2Closed"])
        self.assertEqual({f["method"] for f in probe["findings"]}, {"GET", "HEAD"})
        self.assertTrue(all(f["expected"] == "application/octet-stream" for f in probe["findings"]))
        self.assertTrue(all(f["observed"] == "text/plain; charset=utf-8" for f in probe["findings"]))
        self.assertTrue(all(method in {"GET", "HEAD"} for method, _, _ in calls[mutation_end:]))
        self.assertEqual(sum(m == "PUT" and b == lab.COMPAT_BUCKET and bool(k)
                             for m, b, k in calls), 1)

    def test_recovery_mime_mismatch_keeps_exact_key_method_and_observed_header(self):
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                with self.assertRaisesRegex(RuntimeError, "CONTENT_TYPE_MISMATCH") as error:
                    lab.check_content_type("fixture.txt", method, {"content-type": "text/plain"}, lab.RECOVERY_MIME)
                details = lab.json.loads(str(error.exception).split(":", 1)[1])
                self.assertEqual(details, {"key": "fixture.txt", "method": method,
                                          "expected": lab.RECOVERY_MIME, "observed": "text/plain"})

    def test_compatibility_pass_requires_both_methods_and_preserves_no_gate_claim(self):
        body = b"public octet-stream MIME compatibility fixture\n"
        headers = {"content-type": "application/octet-stream", "content-length": str(len(body)),
                   "x-amz-meta-ouf-content-hash": lab.digest(body)}
        with patch.object(lab, "request", side_effect=[(body, headers), (b"", headers)]) as request:
            result = lab.probe_octet_stream("verify")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["g2Closed"])
        self.assertEqual([c.args[0] for c in request.call_args_list], ["GET", "HEAD"])

    def test_compatibility_probe_does_not_tolerate_body_corruption_as_mime_limitation(self):
        with patch.object(lab, "request", side_effect=[(b"corrupt", {}), (b"", {})]):
            with self.assertRaisesRegex(RuntimeError, "COMPAT_PROBE_BODY_MISMATCH"):
                lab.probe_octet_stream("verify")

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

    def test_ring_readiness_requires_latest_exact_applied_membership(self):
        self.assertFalse(lab.ready_lock_ring("the cluster has 0 filers"))
        valid = "LockRing: applying master ring update v123: [127.0.0.1:18888]"
        self.assertTrue(lab.ready_lock_ring(valid))
        self.assertFalse(lab.ready_lock_ring(valid + "\nLockRing: applying master ring update v124: []"))
        self.assertFalse(lab.ready_lock_ring("LockRing: applying master ring update v123: [other:18888]"))
        self.assertFalse(lab.ready_lock_ring("LockRing: received ring update v123: [127.0.0.1:18888]"))

    def test_http_readiness_requests_waits_and_child_share_finite_budget(self):
        # Enter the last fraction of the budget before a transient failure.
        # Neither the request nor the following sleep may use its normal cap.
        with patch.object(lab.time, "monotonic", side_effect=[0, 89.75, 89.75, 89.85, 90]), \
                patch.object(lab, "request", side_effect=TimeoutError()) as request, \
                patch.object(lab.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "BOUNDED_READINESS_EXHAUSTED"):
                lab.client("ready")
            request.assert_called_once_with("GET", timeout=0.25)
            self.assertEqual(sleep.call_count, 1)
            self.assertAlmostEqual(sleep.call_args.args[0], 0.15)
        # A late successful response cannot be reported as ready.
        with patch.object(lab.time, "monotonic", side_effect=[0, 89.75, 89.75, 90]), \
                patch.object(lab, "request", return_value=(b"", {})):
            with self.assertRaisesRegex(RuntimeError, "HTTP_READINESS_BUDGET"):
                lab.client("ready")
        # HTTP socket timeouts apply to individual I/O calls; cap the entire
        # readiness subprocess as well, including a slow response body.
        with tempfile.TemporaryDirectory() as directory:
            instance = lab.Lab("lab", Path(directory), Path(directory))
            instance.pid = "123"
            with patch.object(lab, "command", return_value='{"readinessAttempts": 1}') as command:
                instance.client("ready")
                self.assertEqual(command.call_args.kwargs["timeout"], 90)

    def test_client_failure_keeps_bounded_child_diagnostic_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = lab.Lab("lab", Path(directory), Path(directory))
            instance.pid = "123"
            error = lab.subprocess.CalledProcessError(1, ["fixture"], stderr="TimeoutError: timed out")
            with patch.object(lab, "command", side_effect=error) as command:
                with self.assertRaisesRegex(RuntimeError, "CLIENT_ACTION_FAILED:seed"):
                    instance.client("seed")
                self.assertEqual(command.call_count, 1)
            self.assertEqual((Path(directory) / "lab-client-seed-stderr.log").read_text(),
                             "TimeoutError: timed out")

    def test_child_timeout_preserves_bytes_and_text_without_retry(self):
        for stderr in (b"partial timeout \xff", "partial timeout à", None):
            with self.subTest(stderr=stderr), tempfile.TemporaryDirectory() as directory:
                instance = lab.Lab("lab", Path(directory), Path(directory))
                instance.pid = "123"
                error = lab.subprocess.TimeoutExpired(["fixture"], 180, stderr=stderr)
                with patch.object(lab, "command", side_effect=error) as command:
                    with self.assertRaisesRegex(RuntimeError, "CLIENT_ACTION_TIMED_OUT:seed"):
                        instance.client("seed")
                    self.assertEqual(command.call_count, 1)
                diagnostic = (Path(directory) / "lab-client-seed-stderr.log").read_text()
                self.assertTrue(diagnostic.startswith("partial timeout") if stderr
                                else diagnostic == "CHILD_TIMEOUT_NO_STDERR")
        self.assertLessEqual(len(lab.bounded_diagnostic("à" * 40000, "").encode()), 32768)

    def test_readiness_subprocess_timeout_cannot_exceed_remaining_budget(self):
        with patch.object(lab.time, "monotonic", return_value=99.75):
            self.assertEqual(lab.remaining_timeout(100), 0.25)
        with patch.object(lab.time, "monotonic", return_value=80):
            self.assertEqual(lab.remaining_timeout(100), 5)
        with patch.object(lab.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "LOCK_RING_READINESS_BUDGET"):
                lab.remaining_timeout(100)


if __name__ == "__main__":
    unittest.main()
