"""Offline harness checks. These never count as PostgreSQL runtime tests."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("native_fixture_lab", HERE / "run_storage_postgres_fixture_native.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class NativeLabContractTests(unittest.TestCase):
    def test_child_environment_does_not_inherit_pg_credentials_or_connection(self):
        with patch.dict(os.environ, {"PGHOST": "target.invalid", "PGPASSWORD": "must-not-leak",
                                     "PGOPTIONS": "-c default_transaction_read_only=off"}):
            result = lab.run([sys.executable, "-I", "-S", "-c",
                "import os; print('|'.join(sorted(k for k in os.environ if k.startswith('PG'))))"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b"PGCONNECT_TIMEOUT|PGPASSFILE|PGSERVICEFILE")
        self.assertNotIn(b"must-not-leak", result.stdout + result.stderr)

    def test_command_timeout_is_finite(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            lab.run([sys.executable, "-I", "-S", "-c", "import time; time.sleep(20)"], timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_overbudget_output_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "LAB_COMMAND_OUTPUT_BUDGET"):
            lab.run([sys.executable, "-I", "-S", "-c", "import sys; sys.stdout.write('x' * 1048577)"])

    def test_exit_status_and_diagnostics_preserved(self):
        result = lab.run([sys.executable, "-I", "-S", "-c",
            "import sys; print('fixture'); print('failure',file=sys.stderr); sys.exit(3)"])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, b"fixture\n", b"failure\n"))

    def test_harness_rejects_root_without_creating_database_or_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "must-not-exist"
            harness = lab.NativeLab(Path(temp), output)
            with patch.object(lab.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "UNPRIVILEGED_LAB_USER_REQUIRED"):
                    harness.start()
            self.assertFalse(output.exists())

    def test_local_fixed_database_argv_and_claim_boundaries(self):
        harness = lab.NativeLab(Path("/fixture/bin"), Path("/fixture/evidence"))
        harness.socket = Path("/fixture/private/socket")
        argv = harness.argv("SELECT 1", user=lab.ROLE)
        self.assertIn("--host=/fixture/private/socket", argv)
        self.assertIn("--dbname=ouf_recovery_fixture", argv)
        self.assertIn("--username=ouf_recovery_fixture", argv)
        self.assertIn("--no-psqlrc", argv)
        self.assertIn("--no-password", argv)
        self.assertEqual(lab.CLAIMS["targetOperations"], 0)
        self.assertTrue(all(value is False for key, value in lab.CLAIMS.items() if key != "targetOperations"))
        self.assertEqual(lab.VERSION, "17.11")
        self.assertEqual(lab.SOURCE_SHA256, "dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979")

    def test_success_requires_all_seven_native_cases_and_no_skips(self):
        result = unittest.TestResult()
        self.assertFalse(lab.successful(result, True, None))
        result.testsRun = 7
        self.assertTrue(lab.successful(result, True, None))
        result.skipped.append((self, "not a live result"))
        self.assertFalse(lab.successful(result, True, None))
        result.skipped.clear()
        self.assertFalse(lab.successful(result, False, None))
        self.assertFalse(lab.successful(result, True, "cleanup failed"))
        self.assertFalse(lab.successful(None, True, None))

    def test_fast_stop_timeout_attempts_forced_cleanup_and_remains_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            harness = lab.NativeLab(Path(temp), Path(temp))
            harness.data = Path(temp) / "data"
            harness.temp, harness.started = Mock(), True
            forced = subprocess.CompletedProcess([], 0, b"stopped", b"")
            with patch.object(lab, "run", side_effect=[subprocess.TimeoutExpired("pg_ctl", 25), forced]) as run:
                with self.assertRaisesRegex(RuntimeError, "POSTGRES_CLEAN_STOP_FAILED"):
                    harness.stop()
            self.assertEqual(run.call_count, 2)
            self.assertIn("immediate", run.call_args_list[1].args[0])
            self.assertEqual(run.call_args_list[1].kwargs["timeout"], 10)
            harness.temp.cleanup.assert_called_once()
            self.assertFalse(harness.started)
            self.assertTrue((Path(temp) / "cleanup-error.txt").is_file())

    def test_failed_forced_cleanup_does_not_claim_server_stopped(self):
        with tempfile.TemporaryDirectory() as temp:
            harness = lab.NativeLab(Path(temp), Path(temp))
            harness.data = Path(temp) / "data"
            harness.temp, harness.started = Mock(), True
            with patch.object(lab, "run", side_effect=subprocess.TimeoutExpired("pg_ctl", 25)) as run:
                with self.assertRaisesRegex(RuntimeError, "FORCED_CLEANUP"):
                    harness.stop()
            self.assertEqual(run.call_count, 2)
            self.assertTrue(harness.started)
            harness.temp.cleanup.assert_not_called()

    def test_actual_native_manifest_bridge_hashes_good_and_corrupt_file_bodies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = lab.NativeLab(root, root)
            harness.profile = json.loads((lab.ROOT / "profiles/seaweedfs-452-lab/profile.json").read_bytes())
            harness.artifacts = []
            for kind in harness.profile["backupPolicy"]["requiredArtifactKinds"]:
                (root / kind).write_bytes(("synthetic bridge " + kind).encode())
                harness.artifacts.append(lab.manifest.record_artifact(root, kind,
                    logical_id=kind.replace("_", "-"), kind=kind, generation=lab.GENERATION))
            dump_sha = next(a["sha256"] for a in harness.artifacts if a["kind"] == "postgres_dump")
            body = b"native runner bridge fixture\x00\xff"
            harness.bodies = {"bridge": body}
            harness.paths = {"bridge": root / "bridge-body"}
            harness.paths["bridge"].write_bytes(body)
            raw = {"schema": "ouf.postgres-fixture-raw-snapshot.v1",
                "generationRows": [{"generation": lab.GENERATION, "accepting_writes": False,
                                    "active_writers": 0, "pending_acknowledgements": 0}],
                "objectRows": [{"bucket": lab.coordinated.BUCKET, "object_key": "bridge",
                                "generation": lab.GENERATION, "content_bytes": len(body),
                                "content_sha256": hashlib.sha256(body).hexdigest(), "ack_state": "ACKED"}]}
            snapshot = lab.postgres_fixture.decode_snapshot(json.dumps(raw).encode(),
                expected_generation=lab.GENERATION, source_dump_sha256=dump_sha)
            good = harness.reconcile(snapshot)
            self.assertTrue(good["fixtureReconciled"])
            self.assertEqual(good["bodyBytesRead"], len(body))
            self.assertFalse(good["runtimeHealthyClaimed"])
            harness.paths["bridge"].write_bytes(b"X" + body[1:])
            corrupt = harness.reconcile(snapshot)
            self.assertFalse(corrupt["fixtureReconciled"])
            self.assertEqual({f["code"] for f in corrupt["findings"]}, {"BODY_SHA256_MISMATCH"})


if __name__ == "__main__":
    unittest.main()
