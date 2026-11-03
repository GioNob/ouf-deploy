"""Disposable native PostgreSQL fixture laboratory. Never a recovery admission.

Run explicitly with --pg-bin and --output. Requires an unprivileged OS user.
The published adapter and SQL schema are exercised unchanged. Object bodies are
local fixture files; no SeaweedFS process, actual dump/restore or writer fence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.storage_recovery import coordinated, manifest, postgres_fixture
from tools.storage_recovery.profile import canonical_json

VERSION = "17.11"
SOURCE_SHA256 = "dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979"
GENERATION = "postgres-native-fixture-0001"
NEXT_GENERATION = "postgres-native-fixture-0002"
ROLE = "ouf_recovery_fixture"
PORT = 55439
EXPECTED_NATIVE_TESTS = 7
CLAIMS = {name: False for name in (
    "dumpRestoreOriginVerified", "writerFenceEnforcedByAdapter", "livePostgresRecoveryQualified",
    "seaweedfsExercised", "pitrQualified", "rpoMeasured", "rtoMeasured",
    "runtimeHealthyClaimed", "releaseAdmitted", "runtimeAuthorityIssued")}
CLAIMS["targetOperations"] = 0


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def clean_environment():
    return {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PGCONNECT_TIMEOUT": "5",
            "PGPASSFILE": "/dev/null", "PGSERVICEFILE": "/dev/null"}


def successful(result, stopped, failure):
    return (result is not None and result.testsRun == EXPECTED_NATIVE_TESTS
            and not result.skipped and result.wasSuccessful() and stopped and failure is None)


def run(argv, *, timeout=20):
    """Lab administrative command; private files retain diagnostics, not pipes."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout,
                                   stderr=stderr, env=clean_environment(), start_new_session=True)
        try:
            returncode = process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=2)
        stdout.seek(0)
        stderr.seek(0)
        out, err = stdout.read(1048577), stderr.read(1048577)
        if len(out) > 1048576 or len(err) > 1048576:
            raise RuntimeError("LAB_COMMAND_OUTPUT_BUDGET")
        return subprocess.CompletedProcess(argv, returncode, out, err)


class NativeLab:
    def __init__(self, pg_bin, output):
        self.pg_bin, self.output = pg_bin.resolve(), output.resolve()
        self.temp = None
        self.started = False
        self.counter = 0
        self.snapshots = []

    def binary(self, name):
        return self.pg_bin / name

    def argv(self, sql, *, user="fixture_admin", application="ouf-native-lab"):
        return [str(self.binary("psql")), "--no-psqlrc", "--no-password", "--quiet",
                "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
                "--set=VERBOSITY=verbose", "--host=" + str(self.socket),
                "--port=" + str(PORT), "--username=" + user, "--dbname=" + ROLE,
                "--command=SET application_name = '" + application + "'; " + sql]

    def sql(self, sql, *, user="fixture_admin", expect=0):
        result = run(self.argv(sql, user=user))
        self.counter += 1
        stem = self.output / ("sql-%03d" % self.counter)
        stem.with_suffix(".sql").write_text(sql)
        stem.with_suffix(".stdout").write_bytes(result.stdout)
        stem.with_suffix(".stderr").write_bytes(result.stderr)
        if result.returncode != expect:
            raise AssertionError("LAB_SQL_EXIT: %s != %s (%s)" % (result.returncode, expect, stem.name))
        return result

    def start(self):
        if os.geteuid() == 0:
            raise RuntimeError("UNPRIVILEGED_LAB_USER_REQUIRED")
        self.output.mkdir(parents=True, exist_ok=False)
        self.temp = tempfile.TemporaryDirectory(prefix="oufpg-")
        self.root = Path(self.temp.name)
        self.socket = self.root / "socket"
        self.socket.mkdir(mode=0o700)
        self.data = self.root / "data"
        versions = {}
        for name in ("postgres", "initdb", "pg_ctl", "psql"):
            binary = self.binary(name)
            result = run([str(binary), "--version"])
            version = result.stdout.decode().strip()
            if result.returncode or not version.endswith(" " + VERSION):
                raise RuntimeError("EXACT_POSTGRES_VERSION_REQUIRED: " + name)
            versions[name] = {"version": version, "sha256": digest(binary)}
        (self.output / "binary-identities.json").write_bytes(canonical_json(versions))
        result = run([str(self.binary("initdb")), "--pgdata=" + str(self.data),
                      "--username=fixture_admin", "--auth-local=trust", "--auth-host=reject",
                      "--encoding=UTF8", "--locale=C"], timeout=30)
        (self.output / "initdb.stdout").write_bytes(result.stdout)
        (self.output / "initdb.stderr").write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError("INITDB_FAILED")
        # No network listener. Socket and data have owner-only filesystem access.
        with (self.data / "postgresql.conf").open("a") as config:
            config.write("\nlisten_addresses = ''\nport = %d\nunix_socket_directories = '%s'\n"
                         "unix_socket_permissions = 0700\nmax_connections = 10\n"
                         "shared_buffers = '16MB'\nfsync = on\n" % (PORT, self.socket))
        self.started = True  # Also clean up a server that starts after pg_ctl times out.
        result = run([str(self.binary("pg_ctl")), "-D", str(self.data), "-l",
                      str(self.output / "postgres.log"), "-w", "-t", "20", "start"], timeout=25)
        if result.returncode:
            raise RuntimeError("POSTGRES_START_FAILED")
        # Bootstrap database through postgres; later SQL uses only the fixture DB.
        argv = self.argv("CREATE DATABASE " + ROLE)
        argv[argv.index("--dbname=" + ROLE)] = "--dbname=postgres"
        argv[-1] = "--command=CREATE DATABASE " + ROLE
        result = run(argv)
        if result.returncode:
            raise RuntimeError("FIXTURE_DATABASE_CREATE_FAILED")
        self.sql((ROOT / "tests/fixtures/storage-recovery/catalog.sql").read_text())
        self.sql("CREATE ROLE " + ROLE + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; "
                 "REVOKE ALL ON DATABASE " + ROLE + " FROM PUBLIC; "
                 "GRANT CONNECT ON DATABASE " + ROLE + " TO " + ROLE + "; "
                 "REVOKE CREATE ON SCHEMA public FROM PUBLIC; "
                 "GRANT USAGE ON SCHEMA ouf_recovery_fixture TO " + ROLE + "; "
                 "GRANT SELECT ON ALL TABLES IN SCHEMA ouf_recovery_fixture TO " + ROLE)
        self.profile = json.loads((ROOT / "profiles/seaweedfs-452-lab/profile.json").read_bytes())
        self.artifact_root = self.root / "artifacts"
        self.artifact_root.mkdir()
        self.bodies = {"empty": b"", "binary": bytes(range(256)) * 4,
                       "città/record": b"acknowledged native PostgreSQL fixture\x00\xff"}
        self.body_root = self.root / "bodies"
        self.body_root.mkdir()
        self.paths = {}
        for number, (key, body) in enumerate(self.bodies.items()):
            path = self.body_root / str(number)
            path.write_bytes(body)
            self.paths[key] = path
        self.artifacts = []
        for kind in self.profile["backupPolicy"]["requiredArtifactKinds"]:
            # Explicit synthetic references, not database dump or storage backup.
            (self.artifact_root / kind).write_bytes(("synthetic reference " + kind).encode())
            self.artifacts.append(manifest.record_artifact(self.artifact_root, kind,
                logical_id=kind.replace("_", "-"), kind=kind, generation=GENERATION))
        self.dump_reference = next(a["sha256"] for a in self.artifacts if a["kind"] == "postgres_dump")

    def reset(self):
        statements = ["BEGIN", "TRUNCATE ouf_recovery_fixture.objects, ouf_recovery_fixture.generation",
                      "INSERT INTO ouf_recovery_fixture.generation VALUES(true,'%s',false,0,0)" % GENERATION]
        for key, body in self.bodies.items():
            statements.append("INSERT INTO ouf_recovery_fixture.objects VALUES('%s','%s','%s','%s',%d,'ACKED')" %
                              (coordinated.BUCKET, key, GENERATION, hashlib.sha256(body).hexdigest(), len(body)))
            self.paths[key].write_bytes(body)
        self.sql(";".join(statements + ["COMMIT"]))

    def snapshot(self, generation=GENERATION):
        result = postgres_fixture.read_fixture_snapshot(psql=self.binary("psql"),
            socket_directory=self.socket, port=PORT, expected_generation=generation,
            source_dump_sha256=self.dump_reference)
        number = len(self.snapshots)
        for field in ("fenceEvidence", "catalogSnapshot"):
            (self.output / ("snapshot-%02d-%s.json" % (number, field))).write_bytes(result[field])
        self.snapshots.append(result["receipt"])
        return result

    def reconcile(self, snapshot):
        fence_sha = hashlib.sha256(snapshot["fenceEvidence"]).hexdigest()
        backup = manifest.build_manifest(self.profile, self.artifacts, backup_id="native-fixture-0001",
            created_at="2026-11-03T00:00:00Z", writer_fence={"status": "CONFIRMED",
            "generation": GENERATION, "evidenceSha256": fence_sha})
        def reader(bucket, key):
            body = self.bodies[key]
            return coordinated.ObjectReadback(self.paths[key].open("rb"), GENERATION,
                                              hashlib.sha256(body).hexdigest(), len(body))
        return coordinated.reconcile(self.profile, backup, fence_evidence=snapshot["fenceEvidence"],
            catalog_snapshot=snapshot["catalogSnapshot"],
            listed_objects=[(coordinated.BUCKET, key) for key in self.bodies],
            listing_complete=True, read_object=reader)

    def stop(self):
        failure = None
        if self.started:
            try:
                result = run([str(self.binary("pg_ctl")), "-D", str(self.data), "-m", "fast",
                              "-w", "-t", "20", "stop"], timeout=25)
                (self.output / "stop.stdout").write_bytes(result.stdout)
                (self.output / "stop.stderr").write_bytes(result.stderr)
                if result.returncode:
                    raise RuntimeError("FAST_STOP_EXIT_" + str(result.returncode))
                self.started = False
            except Exception as error:
                failure = type(error).__name__ + ": " + str(error)
                try:
                    forced = run([str(self.binary("pg_ctl")), "-D", str(self.data), "-m", "immediate",
                                  "-w", "-t", "5", "stop"], timeout=10)
                    (self.output / "forced-stop.stdout").write_bytes(forced.stdout)
                    (self.output / "forced-stop.stderr").write_bytes(forced.stderr)
                    if forced.returncode:
                        raise RuntimeError("FORCED_STOP_EXIT_" + str(forced.returncode))
                    self.started = False
                except Exception as forced_error:
                    failure += "; FORCED_CLEANUP: " + type(forced_error).__name__ + ": " + str(forced_error)
                finally:
                    (self.output / "cleanup-error.txt").write_text(failure + "\n")
        if self.temp and not self.started:
            self.temp.cleanup()
        if failure:
            # Even successful forced cleanup cannot promote failed normal stop.
            raise RuntimeError("POSTGRES_CLEAN_STOP_FAILED: " + failure)


class NativeTests(unittest.TestCase):
    lab = None

    def setUp(self):
        self.lab.reset()

    def test_real_snapshot_and_file_body_hash_reconcile(self):
        report = self.lab.reconcile(self.lab.snapshot())
        (self.lab.output / "reconciliation.json").write_bytes(canonical_json(report))
        self.assertTrue(report["fixtureReconciled"])
        self.assertEqual(report["bodyBytesRead"], sum(map(len, self.lab.bodies.values())))
        self.assertFalse(report["livePostgresRecoveryQualified"])

    def test_corrupt_body_is_detected_despite_valid_database_metadata(self):
        snapshot = self.lab.snapshot()
        original = self.lab.bodies["binary"]
        self.lab.paths["binary"].write_bytes(b"X" + original[1:])
        report = self.lab.reconcile(snapshot)
        (self.lab.output / "corruption-reconciliation.json").write_bytes(canonical_json(report))
        self.assertFalse(report["fixtureReconciled"])
        self.assertEqual({r["code"] for r in report["findings"]}, {"BODY_SHA256_MISMATCH"})

    def test_select_only_role_cannot_mutate_and_owner_read_only_is_enforced(self):
        sql = "UPDATE ouf_recovery_fixture.generation SET accepting_writes=true"
        result = self.lab.sql(sql, user=ROLE, expect=1)
        self.assertIn(b"42501", result.stderr)  # permission_denied, no mutable grants
        result = self.lab.sql("BEGIN READ ONLY; " + sql, expect=1)
        self.assertIn(b"25006", result.stderr)  # even owner cannot update read-only transaction
        self.assertEqual(self.lab.sql("SHOW listen_addresses").stdout.strip(), b"")
        self.lab.snapshot()

    def test_pending_ack_blocks_snapshot(self):
        self.lab.sql("UPDATE ouf_recovery_fixture.objects SET ack_state='PENDING' WHERE object_key='binary'")
        with self.assertRaisesRegex(coordinated.ReconciliationError, "PENDING_ACK_RECONCILIATION_REQUIRED"):
            self.lab.snapshot()

    def test_pending_counter_blocks_snapshot(self):
        self.lab.sql("UPDATE ouf_recovery_fixture.generation SET pending_acknowledgements=1")
        with self.assertRaisesRegex(coordinated.ReconciliationError, "PENDING_ACK_RECONCILIATION_REQUIRED"):
            self.lab.snapshot()

    def test_mixed_generations_block_snapshot(self):
        self.lab.sql("UPDATE ouf_recovery_fixture.objects SET generation='other-generation' WHERE object_key='binary'")
        with self.assertRaisesRegex(coordinated.ReconciliationError, "ROW_GENERATION_MISMATCH"):
            self.lab.snapshot()

    def test_uncommitted_changes_are_invisible_and_atomic_commit_is_coherent(self):
        updates = ("UPDATE ouf_recovery_fixture.generation SET generation='%s'; "
                   "UPDATE ouf_recovery_fixture.objects SET generation='%s'; " % (NEXT_GENERATION, NEXT_GENERATION))
        out_path, err_path = self.lab.output / "writer.stdout", self.lab.output / "writer.stderr"
        with out_path.open("wb") as stdout, err_path.open("wb") as stderr:
            writer = subprocess.Popen(self.lab.argv("BEGIN; " + updates + "SELECT pg_sleep(25); ROLLBACK",
                application="ouf-uncommitted-writer"), stdout=stdout, stderr=stderr,
                stdin=subprocess.DEVNULL, env=clean_environment(), start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while True:
                    status = self.lab.sql("SELECT count(*) FROM pg_stat_activity WHERE "
                        "application_name='ouf-uncommitted-writer' AND wait_event='PgSleep'").stdout.strip()
                    if status == b"1":
                        break
                    self.assertLess(time.monotonic(), deadline, "writer did not reach uncommitted barrier")
                    self.assertIsNone(writer.poll(), "writer exited before barrier")
                    time.sleep(0.05)
                observed = self.lab.snapshot()
                self.assertEqual(observed["receipt"]["generation"], GENERATION)
                self.assertEqual(self.lab.sql("SELECT count(*) FROM pg_stat_activity WHERE "
                    "application_name='ouf-uncommitted-writer' AND wait_event='PgSleep'").stdout.strip(), b"1")
                self.lab.sql("SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE "
                             "application_name='ouf-uncommitted-writer'")
                self.assertEqual(writer.wait(timeout=5), 1)
            finally:
                try:
                    os.killpg(writer.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                writer.wait(timeout=2)
        self.assertIn(b"57014", err_path.read_bytes())
        self.lab.sql("BEGIN; " + updates + "COMMIT")
        committed = self.lab.snapshot(NEXT_GENERATION)
        catalog = json.loads(committed["catalogSnapshot"])
        self.assertTrue(all(row["generation"] == NEXT_GENERATION for row in catalog["rows"]))
        with self.assertRaisesRegex(coordinated.ReconciliationError, "STALE_WRITER_GENERATION"):
            self.lab.snapshot(GENERATION)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    lab = NativeLab(args.pg_bin, args.output)
    NativeTests.lab = lab
    result, failure, stopped = None, None, False
    try:
        lab.start()
        with (lab.output / "tests.log").open("w") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(
                unittest.defaultTestLoader.loadTestsFromTestCase(NativeTests))
    except Exception as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        try:
            lab.stop()
            stopped = True
        except Exception as error:
            failure = "CLEANUP: " + type(error).__name__ + ": " + str(error)
        if lab.temp is not None and lab.output.is_dir():
            success = successful(result, stopped, failure)
            receipt = dict(CLAIMS, schema="ouf.postgres-native-fixture-lab.v1",
                status="REAL_POSTGRES_FIXTURE_PASS_NOT_RECOVERY" if success else "BLOCKED",
                postgresVersion=VERSION, expectedSourceTarballSha256=SOURCE_SHA256,
                sourceArchiveVerifiedByHarness=False,
                testsRun=result.testsRun if result else 0,
                expectedTests=EXPECTED_NATIVE_TESTS, skipped=len(result.skipped) if result else 0,
                failures=len(result.failures) if result else 0,
                errors=len(result.errors) if result else 0, cleanupSucceeded=stopped,
                failure=failure, snapshots=lab.snapshots)
            (lab.output / "receipt.json").write_bytes(canonical_json(receipt))
            print(json.dumps(receipt, indent=2))
    return 0 if successful(result, stopped, failure) else 1


if __name__ == "__main__":
    raise SystemExit(main())
