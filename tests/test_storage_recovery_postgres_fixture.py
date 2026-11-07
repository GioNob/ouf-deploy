import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.storage_recovery import postgres_fixture as adapter
from tools.storage_recovery.coordinated import ReconciliationError
from tools.storage_recovery import coordinated, manifest
from tools.storage_recovery.profile import canonical_json


class PostgresFixtureAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = {"schema": "ouf.postgres-fixture-raw-snapshot.v1",
            "generationRows": [{"generation": "generation-0001", "accepting_writes": False,
                                "active_writers": 0, "pending_acknowledgements": 0}],
            "objectRows": [{"bucket": "ouf-recovery-fixture", "object_key": "città/%.bin",
                "generation": "generation-0001", "content_sha256": hashlib.sha256(b"body").hexdigest(),
                "content_bytes": 4, "ack_state": "ACKED"}]}
        self.references = {"expected_generation": "generation-0001", "source_dump_sha256": "a" * 64}

    def peer(self, code):
        path = self.root / "fixture-peer"
        path.write_text("#!" + sys.executable + "\n" + code)
        path.chmod(0o700)
        return path

    def run_peer(self, code, **kw):
        return adapter.read_fixture_snapshot(psql=self.peer(code), socket_directory=self.root,
                                             **self.references, **kw)

    def decode(self, value=None):
        return adapter.decode_snapshot(json.dumps(self.raw if value is None else value).encode(),
                                       **self.references)

    def test_real_subprocess_exports_compatible_complete_inputs_without_health_claim(self):
        report = self.run_peer("import sys\nsys.stdout.write(" + repr(json.dumps(self.raw)) + ")\n")
        catalog = json.loads(report["catalogSnapshot"])
        fence = json.loads(report["fenceEvidence"])
        self.assertEqual(catalog["rowCount"], 1)
        self.assertEqual(catalog["rows"][0]["key"], "città/%.bin")
        self.assertEqual(fence["activeWriters"], 0)
        self.assertTrue(catalog["complete"])
        for key in ("dumpRestoreOriginVerified", "writerFenceEnforcedByAdapter",
                    "runtimeHealthyClaimed", "pitrQualified", "releaseAdmitted", "runtimeAuthorityIssued"):
            self.assertFalse(report["receipt"][key])

    def test_psql_command_is_fixed_readonly_and_environment_is_not_inherited(self):
        captured = self.root / "captured.json"
        code = ("import json,os,sys\n" +
                "open(" + repr(str(captured)) + ", 'w').write(json.dumps({'argv':sys.argv[1:], 'env':dict(os.environ)}))\n" +
                "sys.stdout.write(" + repr(json.dumps(self.raw)) + ")\n")
        with patch.dict(os.environ, {"PGHOST": "remote.invalid", "PGOPTIONS": "-c role=admin",
                                    "PGPASSWORD": "fixture-secret", "PGSERVICE": "foreign"}):
            self.run_peer(code)
        got = json.loads(captured.read_bytes())
        for flag in ("--no-psqlrc", "--no-password", "--set=ON_ERROR_STOP=1",
                     "--dbname=ouf_recovery_fixture", "--username=ouf_recovery_fixture"):
            self.assertIn(flag, got["argv"])
        sql = next(arg.removeprefix("--command=") for arg in got["argv"] if arg.startswith("--command="))
        self.assertEqual(sql, adapter.SNAPSHOT_SQL)
        self.assertIn("REPEATABLE READ READ ONLY", sql)
        self.assertIn("LIMIT 4097", sql)
        self.assertEqual(sql.count("COMMIT;"), 1)
        for name in ("PGHOST", "PGOPTIONS", "PGPASSWORD", "PGSERVICE"):
            self.assertNotIn(name, got["env"])

    def test_timeout_kills_process_and_does_not_retry(self):
        marker = self.root / "attempts"
        code = "import time\nopen(" + repr(str(marker)) + ", 'a').write('attempt\\n')\ntime.sleep(10)\n"
        started = time.monotonic()
        with self.assertRaisesRegex(ReconciliationError, "PROCESS_TIMEOUT"):
            self.run_peer(code, timeout=0.15)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(marker.read_text(), "attempt\n")

    def test_descendant_retaining_pipes_cannot_hold_adapter_open(self):
        code = "import os,time\nif os.fork() == 0:\n time.sleep(10)\nelse:\n os._exit(0)\n"
        started = time.monotonic()
        with self.assertRaisesRegex(ReconciliationError, "PROCESS_TIMEOUT"):
            self.run_peer(code, timeout=0.15)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_streaming_stdout_limit_stops_producer_without_unbounded_buffer(self):
        code = "import os\nwhile True: os.write(1, b'x'*65536)\n"
        with self.assertRaisesRegex(ReconciliationError, "STDOUT_BUDGET"):
            self.run_peer(code)

    def test_streaming_stderr_limit_stops_producer_and_redacts_payload(self):
        code = "import os\nwhile True: os.write(2, b'fixture-secret'*8192)\n"
        with self.assertRaisesRegex(ReconciliationError, "STDERR_BUDGET") as ctx:
            self.run_peer(code)
        self.assertNotIn("fixture-secret", str(ctx.exception))

    def test_nonzero_exit_with_valid_json_never_yields_snapshot(self):
        code = "import sys\nsys.stdout.write(" + repr(json.dumps(self.raw)) + ")\nsys.exit(3)\n"
        with self.assertRaisesRegex(ReconciliationError, "PROCESS_FAILED"):
            self.run_peer(code)

    def test_stderr_warning_blocks_otherwise_valid_snapshot(self):
        code = "import sys\nsys.stdout.write(" + repr(json.dumps(self.raw)) + ")\nsys.stderr.write('fixture-warning')\n"
        with self.assertRaisesRegex(ReconciliationError, "DIAGNOSTIC_OUTPUT"):
            self.run_peer(code)

    def test_password_file_is_private_empty_regular_and_removed_after_success(self):
        captured = self.root / "password-path.json"
        code = ("import os,stat,sys,json\n"
                "p=os.environ['PGPASSFILE']; s=os.stat(p)\n"
                "open(" + repr(str(captured)) + ",'w').write(json.dumps(p))\n"
                "if not stat.S_ISREG(s.st_mode):\n"
                " sys.stderr.write('WARNING: password file is not a plain file\\n')\n"
                "else:\n"
                " assert stat.S_IMODE(s.st_mode)==0o600\n"
                " assert stat.S_IMODE(os.stat(os.path.dirname(p)).st_mode)==0o700\n"
                " assert open(p,'rb').read()==b''\n"
                "sys.stdout.write(" + repr(json.dumps(self.raw)) + ")\n")
        self.run_peer(code)
        password = Path(json.loads(captured.read_text()))
        self.assertFalse(password.exists())
        self.assertFalse(password.parent.exists())

    def test_password_file_is_removed_on_warning_exit_and_timeout(self):
        for mode, tail, error in (("warning", "sys.stderr.write('warning')", "DIAGNOSTIC_OUTPUT"),
                                 ("exit", "sys.exit(3)", "PROCESS_FAILED"),
                                 ("timeout", "time.sleep(10)", "PROCESS_TIMEOUT")):
            with self.subTest(mode=mode):
                captured = self.root / (mode + "-password-path.json")
                code = ("import os,json,sys,time\nopen(" + repr(str(captured)) +
                        ",'w').write(json.dumps(os.environ['PGPASSFILE']))\n"
                        "sys.stdout.write(" + repr(json.dumps(self.raw)) + ")\n" + tail + "\n")
                with self.assertRaisesRegex(ReconciliationError, error):
                    self.run_peer(code, timeout=0.15)
                password = Path(json.loads(captured.read_text()))
                self.assertFalse(password.exists())
                self.assertFalse(password.parent.exists())

    def test_password_file_is_removed_if_process_cannot_start(self):
        with patch.object(adapter.subprocess, "Popen", side_effect=OSError("fixture failure")) as popen:
            with self.assertRaisesRegex(ReconciliationError, "PROCESS_START_FAILED"):
                self.run_peer("pass\n")
        password = Path(popen.call_args.kwargs["env"]["PGPASSFILE"])
        self.assertFalse(password.exists())
        self.assertFalse(password.parent.exists())

    def test_duplicate_json_fields_trailing_frames_and_invalid_json_rejected(self):
        valid = json.dumps(self.raw).encode()
        for raw in (b'{"schema":1,"schema":2}', valid + valid, b"not json", b"", b"[]"):
            with self.subTest(raw=raw[:30]), self.assertRaises(ReconciliationError):
                adapter.decode_snapshot(raw, **self.references)

    def test_ambiguous_or_nonquiescent_fence_rejected(self):
        for field, value, code in (("accepting_writes", True, "FENCE_NOT_CLOSED"),
                                  ("active_writers", 1, "ACTIVE_WRITERS"),
                                  ("active_writers", False, "ACTIVE_WRITERS"),
                                  ("pending_acknowledgements", 1, "PENDING_ACK"),
                                  ("generation", "generation-0000", "STALE_WRITER")):
            raw = copy.deepcopy(self.raw)
            raw["generationRows"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ReconciliationError, code):
                self.decode(raw)
        for rows in ([], self.raw["generationRows"] * 2):
            raw = copy.deepcopy(self.raw)
            raw["generationRows"] = rows
            with self.assertRaisesRegex(ReconciliationError, "SINGLE_GENERATION"):
                self.decode(raw)

    def test_oversized_or_inconsistent_catalog_rejected(self):
        for rows in ([], self.raw["objectRows"] * 4097, self.raw["objectRows"] * 2):
            raw = copy.deepcopy(self.raw)
            raw["objectRows"] = rows
            with self.assertRaises(ReconciliationError):
                self.decode(raw)
        for field, value in (("ack_state", "PENDING"), ("generation", "old"),
                             ("bucket", "target-data"), ("content_bytes", True),
                             ("content_bytes", 16777217), ("content_sha256", "bad"),
                             ("object_key", "x" * 1025)):
            raw = copy.deepcopy(self.raw)
            raw["objectRows"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ReconciliationError):
                self.decode(raw)

    def test_bad_reference_or_socket_rejected_before_process(self):
        with patch.object(adapter.subprocess, "Popen") as popen:
            for socket in (Path("relative"), Path("/missing")):
                with self.assertRaises(ReconciliationError):
                    adapter.read_fixture_snapshot(psql=Path(sys.executable), socket_directory=socket,
                                                  **self.references)
            bad = dict(self.references, source_dump_sha256="not-a-hash")
            with self.assertRaises(ReconciliationError):
                adapter.read_fixture_snapshot(psql=Path(sys.executable), socket_directory=self.root, **bad)
            popen.assert_not_called()

    def test_export_feeds_body_reconciler_and_corruption_remains_visible(self):
        profile = json.loads((ROOT / "profiles/seaweedfs-452-lab/profile.json").read_bytes())
        artifacts = []
        for kind in profile["backupPolicy"]["requiredArtifactKinds"]:
            (self.root / kind).write_bytes(("fixture " + kind).encode())
            artifacts.append(manifest.record_artifact(self.root, kind,
                logical_id=kind.replace("_", "-"), kind=kind, generation="generation-0001"))
        self.references["source_dump_sha256"] = next(a["sha256"] for a in artifacts if a["kind"] == "postgres_dump")
        exported = self.decode()
        backup = manifest.build_manifest(profile, artifacts, backup_id="lab-backup-0001",
            created_at="2026-11-03T19:00:00Z", writer_fence={"status": "CONFIRMED",
                "generation": "generation-0001", "evidenceSha256": hashlib.sha256(exported["fenceEvidence"]).hexdigest()})
        row = self.raw["objectRows"][0]
        def reconcile(body):
            return coordinated.reconcile(profile, backup, fence_evidence=exported["fenceEvidence"],
                catalog_snapshot=exported["catalogSnapshot"], listing_complete=True,
                listed_objects=[(row["bucket"], row["object_key"])],
                read_object=lambda *_: coordinated.ObjectReadback(io.BytesIO(body),
                    "generation-0001", row["content_sha256"], 4))
        self.assertTrue(reconcile(b"body")["fixtureReconciled"])
        bad = reconcile(b"evil")
        self.assertFalse(bad["fixtureReconciled"])
        self.assertEqual([item["code"] for item in bad["findings"]], ["BODY_SHA256_MISMATCH"])


if __name__ == "__main__":
    unittest.main()
