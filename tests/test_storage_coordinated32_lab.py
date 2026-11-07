"""Exercise the real reconciliation adapter with bounded S3 response fixtures."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("coordinated32", ROOT / "scripts/run-storage-coordinated32-lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
from tools.storage_recovery.postgres_fixture import decode_snapshot


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CoordinatedFixtureTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.proof = Path(folder.name)
        self.destination = self.proof / "postgres/destination"
        self.destination.mkdir(parents=True)
        archive = b"PGDMPtest-only"
        (self.proof / "postgres/catalog.dump").write_bytes(archive)
        raw = {
            "schema": "ouf.postgres-fixture-raw-snapshot.v1",
            "generationRows": [{"generation": lab.GENERATION, "accepting_writes": False,
                                "active_writers": 0, "pending_acknowledgements": 0}],
            "objectRows": [{"bucket": lab.coordinated.BUCKET, "object_key": "record",
                            "generation": lab.GENERATION, "content_sha256": sha(b"good"),
                            "content_bytes": 4, "ack_state": "ACKED"}],
        }
        snapshot = decode_snapshot(json.dumps(raw).encode(), expected_generation=lab.GENERATION,
                                   source_dump_sha256=sha(archive))
        for key in ("catalogSnapshot", "fenceEvidence"):
            (self.destination / ("snapshot-00-" + key + ".json")).write_bytes(snapshot[key])
        self.inventory = {role + "/file": {"bytes": 1, "sha256": sha(b"x")}
                          for role in ("config", "master", "filer", "volume")}
        lab.bind_joint_manifest(self.proof, self.inventory)

    def request(self, *, payload=b"good", generation=lab.GENERATION, truncated=False):
        def send(method, key, **kwargs):
            self.assertEqual(method, "GET")
            self.assertEqual(kwargs["bucket"], lab.coordinated.BUCKET)
            if key == "":
                trunc = "true" if truncated else "false"
                return (f'<ListBucketResult xmlns="{lab.S3_NS["s"]}">'
                        f"<IsTruncated>{trunc}</IsTruncated><Contents><Key>record</Key></Contents>"
                        "</ListBucketResult>").encode(), {}
            self.assertEqual(key, "record")
            return payload, {lab.GENERATION_HEADER: generation, lab.HASH_HEADER: sha(b"good"),
                             "content-length": "4"}
        return send

    def test_complete_listing_and_real_get_frame_reconcile(self):
        report = lab.reconcile_restored(self.request(), self.proof)
        self.assertTrue(report["fixtureReconciled"])
        self.assertEqual(report["bodyBytesRead"], 4)

    def test_equal_length_corruption_and_stale_metadata_are_not_accepted(self):
        report = lab.reconcile_restored(self.request(payload=b"evil", generation="stale"), self.proof)
        self.assertFalse(report["fixtureReconciled"])
        self.assertEqual({f["code"] for f in report["findings"]},
                         {"BODY_SHA256_MISMATCH", "OBJECT_GENERATION_MISMATCH"})

    def test_truncated_list_is_not_reconciled(self):
        with self.assertRaisesRegex(RuntimeError, "COMPLETE_SINGLE_PAGE"):
            lab.reconcile_restored(self.request(truncated=True), self.proof)

    def test_actual_dump_digest_is_required_and_missing_backup_role_rejected(self):
        (self.proof / "postgres/catalog.dump").write_bytes(b"PGDMPchanged")
        lab.bind_joint_manifest(self.proof, self.inventory)
        with self.assertRaisesRegex(lab.coordinated.ReconciliationError, "EXACT_SINGLE_POSTGRES_DUMP_BINDING"):
            lab.reconcile_restored(self.request(), self.proof)
        del self.inventory["master/file"]
        with self.assertRaisesRegex(RuntimeError, "COLD_BACKUP_ROLE_INDEX_REQUIRED:master"):
            lab.bind_joint_manifest(self.proof, self.inventory)

    def test_single_seed_writes_generation_and_content_digest(self):
        puts = []
        def send(*args, **kwargs):
            puts.append((args, kwargs))
        fixture = {key: base64.b64encode(key.encode()).decode() for key in ("a", "b", "c")}
        self.assertEqual(lab.seed(send, sha, fixture), {"seededObjects": 3, "mutatingRequestRetries": 0})
        self.assertEqual(puts[0], (("PUT", ""), {"bucket": lab.coordinated.BUCKET}))
        self.assertEqual(len(puts), 4)
        for (method, key, body), kwargs in puts[1:]:
            self.assertEqual(method, "PUT")
            self.assertEqual(body, key.encode())
            self.assertEqual(kwargs["bucket"], lab.coordinated.BUCKET)
            self.assertEqual(kwargs["extra"][lab.GENERATION_HEADER], lab.GENERATION)
            self.assertEqual(kwargs["extra"][lab.HASH_HEADER], sha(body))


if __name__ == "__main__":
    unittest.main()
