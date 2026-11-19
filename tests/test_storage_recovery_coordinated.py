import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.storage_recovery import coordinated as reconciliation
from tools.storage_recovery import manifest as recovery
from tools.storage_recovery.profile import canonical_json


class CoordinatedReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((ROOT / "profiles/seaweedfs-452-lab/profile.json").read_bytes())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.generation = "generation-0001"
        self.fence = {"schema": "ouf.storage-fixture-writer-fence.v1", "generation": self.generation,
                      "acceptingWrites": False, "activeWriters": 0,
                      "pendingAcknowledgements": 0, "syntheticOnly": True}
        self.fence_bytes = canonical_json(self.fence)
        artifacts = []
        for kind in self.profile["backupPolicy"]["requiredArtifactKinds"]:
            (self.source / kind).write_bytes(("synthetic " + kind).encode())
            artifacts.append(recovery.record_artifact(self.source, kind,
                logical_id=kind.replace("_", "-"), kind=kind, generation=self.generation))
        self.manifest = recovery.build_manifest(self.profile, artifacts, backup_id="lab-backup-0001",
            created_at="2026-11-03T19:00:00Z", writer_fence={"status": "CONFIRMED",
                "generation": self.generation, "evidenceSha256": hashlib.sha256(self.fence_bytes).hexdigest()})
        self.bodies = {"empty": b"", "città/%.bin": bytes(range(256)) * 1024,
                       "record": b"acknowledged bytes\x00\xff"}
        self.catalog = {"schema": "ouf.storage-fixture-catalog-snapshot.v1",
            "sqlSchema": "ouf_recovery_fixture", "generation": self.generation,
            "sourcePostgresDumpSha256": next(a["sha256"] for a in artifacts if a["kind"] == "postgres_dump"),
            "complete": True, "rowCount": len(self.bodies), "rows": [
                {"bucket": reconciliation.BUCKET, "key": key, "generation": self.generation,
                 "contentSha256": hashlib.sha256(body).hexdigest(), "contentBytes": len(body), "ackState": "ACKED"}
                for key, body in sorted(self.bodies.items())]}
        self.listing = [(reconciliation.BUCKET, key) for key in sorted(self.bodies)]
        self.streams = []

    def reader(self, bucket, key):
        stream = io.BytesIO(self.bodies[key])
        self.streams.append(stream)
        expected = next(row for row in self.catalog["rows"] if row["key"] == key)
        return reconciliation.ObjectReadback(stream, self.generation,
            expected["contentSha256"], expected["contentBytes"])

    def run_reconciliation(self, **overrides):
        args = dict(fence_evidence=self.fence_bytes, catalog_snapshot=canonical_json(self.catalog),
                    listed_objects=self.listing, listing_complete=True, read_object=self.reader)
        args.update(overrides)
        return reconciliation.reconcile(self.profile, self.manifest, **args)

    def codes(self, report):
        self.assertFalse(report["fixtureReconciled"])
        self.assertFalse(report["runtimeHealthyClaimed"])
        return {row["code"] for row in report["findings"]}

    def test_actual_stream_bytes_reconcile_and_close_without_runtime_acceptance(self):
        result = self.run_reconciliation()
        self.assertTrue(result["fixtureReconciled"])
        self.assertTrue(result["allExpectedReadbacksCompleted"])
        self.assertEqual(result["bodyBytesRead"], sum(map(len, self.bodies.values())))
        self.assertTrue(all(stream.closed for stream in self.streams))
        for name in ("runtimeHealthyClaimed", "livePostgresRecoveryQualified", "backupBytesVerifiedByThisFunction",
                     "pitrQualified", "rpoMeasured", "rtoMeasured", "releaseAdmitted", "runtimeAuthorityIssued"):
            self.assertFalse(result[name])

    def test_missing_and_unreferenced_objects_block_reconciliation(self):
        listing = self.listing[:-1] + [(reconciliation.BUCKET, "unexpected")]
        result = self.run_reconciliation(listed_objects=listing)
        self.assertEqual(self.codes(result), {"MISSING_OBJECT", "UNREFERENCED_OBJECT"})
        self.assertFalse(result["allExpectedReadbacksCompleted"])

    def test_corrupted_body_with_unchanged_hash_metadata_is_detected(self):
        original = self.bodies["record"]
        self.bodies["record"] = b"X" + original[1:]
        self.assertEqual(self.codes(self.run_reconciliation()), {"BODY_SHA256_MISMATCH"})

    def test_truncated_and_overlong_streams_fail_closed_and_are_closed(self):
        for body in (b"short", b"Z" * 1000000):
            with self.subTest(bytes=len(body)):
                self.bodies["record"] = body
                report = self.run_reconciliation()
                self.assertIn("BODY_LENGTH_MISMATCH", self.codes(report))
                row = next(row for row in report["readbacks"] if row["key"] == "record")
                expected = next(row["contentBytes"] for row in self.catalog["rows"] if row["key"] == "record")
                self.assertLessEqual(row["bytesRead"], expected + 1)
                self.assertTrue(all(stream.closed for stream in self.streams))

    def test_mixed_generations_and_dump_bindings_rejected_before_get(self):
        for mutation, code in ((lambda c: c.update(generation="generation-0002"), "CATALOG_GENERATION"),
                               (lambda c: c["rows"][0].update(generation="generation-0002"), "ROW_GENERATION"),
                               (lambda c: c.update(sourcePostgresDumpSha256="0"*64), "POSTGRES_DUMP_BINDING")):
            catalog = copy.deepcopy(self.catalog)
            mutation(catalog)
            reader = Mock()
            with self.assertRaisesRegex(reconciliation.ReconciliationError, code):
                self.run_reconciliation(catalog_snapshot=canonical_json(catalog), read_object=reader)
            reader.assert_not_called()

    def test_object_generation_mismatch_does_not_become_healthy(self):
        def other_generation(bucket, key):
            value = self.reader(bucket, key)
            value.generation = "generation-0002"
            return value
        self.assertEqual(self.codes(self.run_reconciliation(read_object=other_generation)),
                         {"OBJECT_GENERATION_MISMATCH"})

    def test_stale_writer_and_closed_fence_reject_admission(self):
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "STALE_WRITER"):
            reconciliation.admit_fixture_write("generation-0001", "generation-0002", True)
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "WRITER_FENCE_CLOSED"):
            reconciliation.admit_fixture_write(self.generation, self.generation, False)
        reconciliation.admit_fixture_write(self.generation, self.generation, True)

    def test_pending_ack_and_active_writer_prevent_reads(self):
        for field, value, code in (("pendingAcknowledgements", 1, "PENDING_ACK"),
                                   ("activeWriters", 1, "QUIESCENT"),
                                   ("acceptingWrites", True, "QUIESCENT")):
            fence = dict(self.fence, **{field: value})
            raw = canonical_json(fence)
            self.manifest["writerFence"]["evidenceSha256"] = hashlib.sha256(raw).hexdigest()
            reader = Mock()
            with self.assertRaisesRegex(reconciliation.ReconciliationError, code):
                self.run_reconciliation(fence_evidence=raw, read_object=reader)
            reader.assert_not_called()
        self.manifest["writerFence"]["evidenceSha256"] = hashlib.sha256(self.fence_bytes).hexdigest()
        self.catalog["rows"][0]["ackState"] = "PENDING"
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "PENDING_ACK"):
            self.run_reconciliation()

    def test_incomplete_or_duplicate_snapshot_cannot_yield_success(self):
        for changes in ({"listing_complete": False}, {"listed_objects": self.listing + self.listing[:1]}):
            with self.assertRaises(reconciliation.ReconciliationError):
                self.run_reconciliation(**changes)
        catalog = dict(self.catalog, complete=False)
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "COMPLETE_SNAPSHOTS"):
            self.run_reconciliation(catalog_snapshot=canonical_json(catalog))
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "FENCE_EVIDENCE_HASH"):
            self.run_reconciliation(fence_evidence=self.fence_bytes + b" ")

    def test_stream_read_failure_produces_blocked_report_and_closes_stream(self):
        class Failed(io.BytesIO):
            def read(self, size=-1):
                raise OSError("fixture transport interrupted")
        stream = Failed()
        reader = lambda bucket, key: reconciliation.ObjectReadback(stream, self.generation, "0"*64, 0)
        report = self.run_reconciliation(read_object=reader)
        self.assertIn("OBJECT_READBACK_FAILED", self.codes(report))
        self.assertFalse(report["allExpectedReadbacksCompleted"])
        self.assertFalse(report["bodyByteCountComplete"])
        self.assertTrue(stream.closed)

    def test_object_count_and_byte_budgets_bound_inputs_before_network(self):
        reader = Mock()
        with patch.object(reconciliation, "MAX_OBJECTS", 2):
            with self.assertRaisesRegex(reconciliation.ReconciliationError, "ROW_COUNT_BUDGET"):
                self.run_reconciliation(read_object=reader)
        with patch.object(reconciliation, "MAX_TOTAL_BYTES", 2):
            with self.assertRaisesRegex(reconciliation.ReconciliationError, "TOTAL_OBJECT_BYTES"):
                self.run_reconciliation(read_object=reader)
        reader.assert_not_called()


    def test_unbounded_listing_iterator_is_stopped_before_get(self):
        def more_keys():
            for number in range(1000000):
                yield (reconciliation.BUCKET, "key-" + str(number))
        reader = Mock()
        with patch.object(reconciliation, "MAX_OBJECTS", 3):
            with self.assertRaisesRegex(reconciliation.ReconciliationError, "LIST_OBJECT_COUNT_BUDGET"):
                self.run_reconciliation(listed_objects=more_keys(), read_object=reader)
        reader.assert_not_called()

    def test_metadata_cannot_override_measured_length_or_bytes(self):
        def false_metadata(bucket, key):
            response = self.reader(bucket, key)
            response.metadata_sha256 = "0" * 64
            response.content_length = True
            return response
        result = self.run_reconciliation(read_object=false_metadata)
        self.assertEqual(self.codes(result), {"HASH_METADATA_MISMATCH", "DECLARED_LENGTH_MISMATCH"})
        self.assertTrue(result["bodyByteCountComplete"])
        self.assertTrue(all(row["completeBodySha256"] for row in result["readbacks"]))


if __name__ == "__main__":
    unittest.main()
