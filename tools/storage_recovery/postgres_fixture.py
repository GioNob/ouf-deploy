"""Read-only PostgreSQL fixture snapshot adapter; never runtime admission.

This executes psql against an explicitly supplied local Unix socket only. The
caller must qualify the server, establish the writer fence, and prove restore
origin separately. Reading a fence row does not enforce a fence on any writer.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time

from .coordinated import (BUCKET, MAX_OBJECTS, MAX_OBJECT_BYTES, MAX_TOTAL_BYTES,
                          MAX_SNAPSHOT_BYTES, ReconciliationError, _identity,
                          _integer, _json, _keys, _sha, require)
from .profile import canonical_json

MAX_STDERR = 65536
MAX_STDOUT = MAX_SNAPSHOT_BYTES + 16384


@contextmanager
def empty_password_environment():
    """Private empty regular passfile; no inherited libpq credentials/options.

    libpq warns for /dev/null because it is not a regular file. A private empty
    file prevents both that warning and fallback to the user's default .pgpass.
    The file and its owner-only directory live exactly as long as the process
    attempt, including its bounded termination and pipe cleanup.
    """
    with tempfile.TemporaryDirectory(prefix="ouf-empty-pgpass-") as directory:
        os.chmod(directory, 0o700)
        passfile = str(Path(directory) / "pgpass")
        descriptor = os.open(passfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        yield {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PGCONNECT_TIMEOUT": "5",
               "PGPASSFILE": passfile, "PGSERVICEFILE": "/dev/null"}

# Fixed SQL, never caller-interpolated. The sentinel row distinguishes oversized
# relations from complete snapshots. Both tables are read within one snapshot.
SNAPSHOT_SQL = """BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL idle_in_transaction_session_timeout = '12s';
SET LOCAL search_path = pg_catalog;
SELECT json_build_object(
  'schema', 'ouf.postgres-fixture-raw-snapshot.v1',
  'generationRows', (SELECT COALESCE(json_agg(g), '[]'::json) FROM
    (SELECT generation, accepting_writes, active_writers,
            pending_acknowledgements FROM ouf_recovery_fixture.generation
     ORDER BY generation LIMIT 2) g),
  'objectRows', (SELECT COALESCE(json_agg(o), '[]'::json) FROM
    (SELECT bucket, object_key, generation, content_sha256, content_bytes,
            ack_state FROM ouf_recovery_fixture.objects
     ORDER BY bucket COLLATE "C", object_key COLLATE "C" LIMIT 4097) o)
);
COMMIT;
"""


def _terminate(process):
    # psql is a session/group leader. Kill the entire group, including a peer
    # child retaining a pipe after the direct process exits. No shell is used.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def _run_bounded(argv: list[str], *, timeout: float) -> bytes:
    """One process attempt, bounded memory/time, no raw stderr in exceptions."""
    require(type(timeout) in (int, float) and 0 < timeout <= 30,
            "PROCESS_TIMEOUT_BUDGET")
    with empty_password_environment() as environment:
        environment["PGAPPNAME"] = "ouf-recovery-fixture-readback"
        return _run_bounded_in_environment(argv, timeout=timeout, environment=environment)


def _run_bounded_in_environment(argv: list[str], *, timeout: float, environment: dict) -> bytes:
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            start_new_session=True, close_fds=True)
    except OSError as error:
        raise ReconciliationError("POSTGRES_FIXTURE_PROCESS_START_FAILED") from error
    output = bytearray()
    stderr_count = 0
    selector = selectors.DefaultSelector()
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "POSTGRES_FIXTURE_PROCESS_TIMEOUT")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    require(len(output) + len(chunk) <= MAX_STDOUT,
                            "POSTGRES_FIXTURE_STDOUT_BUDGET")
                    output.extend(chunk)
                else:
                    stderr_count += len(chunk)
                    require(stderr_count <= MAX_STDERR, "POSTGRES_FIXTURE_STDERR_BUDGET")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "POSTGRES_FIXTURE_PROCESS_TIMEOUT")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise ReconciliationError("POSTGRES_FIXTURE_PROCESS_TIMEOUT") from error
        require(return_code == 0, "POSTGRES_FIXTURE_PROCESS_FAILED")
        # psql warnings are not a successful clean snapshot in this narrow lab.
        require(stderr_count == 0, "POSTGRES_FIXTURE_DIAGNOSTIC_OUTPUT")
        return bytes(output)
    finally:
        _terminate(process)
        selector.close()
        process.stdout.close()
        process.stderr.close()


def decode_snapshot(raw: bytes, *, expected_generation: str,
                    source_dump_sha256: str) -> dict:
    """Validate an observed snapshot, not the origin of a restore or fence."""
    require(isinstance(expected_generation, str) and 0 < len(expected_generation) <= 128,
            "EXPECTED_GENERATION_REQUIRED")
    require(_sha(source_dump_sha256), "SOURCE_DUMP_REFERENCE_REQUIRED")
    observed = _json(raw, MAX_STDOUT)
    _keys(observed, {"schema", "generationRows", "objectRows"}, "POSTGRES_SNAPSHOT_FIELDS")
    require(observed["schema"] == "ouf.postgres-fixture-raw-snapshot.v1",
            "POSTGRES_SNAPSHOT_SCHEMA")
    generations = observed["generationRows"]
    require(isinstance(generations, list) and len(generations) == 1,
            "SINGLE_GENERATION_REQUIRED")
    generation = generations[0]
    _keys(generation, {"generation", "accepting_writes", "active_writers",
                        "pending_acknowledgements"}, "POSTGRES_GENERATION_FIELDS")
    require(generation["generation"] == expected_generation, "STALE_WRITER_GENERATION")
    require(generation["accepting_writes"] is False, "WRITER_FENCE_NOT_CLOSED")
    _integer(generation["active_writers"], 0, 0, "ACTIVE_WRITERS_REMAIN")
    _integer(generation["pending_acknowledgements"], 0, 0, "PENDING_ACK_RECONCILIATION_REQUIRED")
    rows = observed["objectRows"]
    require(isinstance(rows, list) and 1 <= len(rows) <= MAX_OBJECTS,
            "POSTGRES_CATALOG_ROW_BUDGET")
    translated, identities, total = [], set(), 0
    for row in rows:
        _keys(row, {"bucket", "object_key", "generation", "content_sha256",
                    "content_bytes", "ack_state"}, "POSTGRES_OBJECT_FIELDS")
        identity = _identity(row["bucket"], row["object_key"])
        require(identity not in identities, "DUPLICATE_CATALOG_OBJECT")
        identities.add(identity)
        require(row["generation"] == expected_generation, "ROW_GENERATION_MISMATCH")
        require(row["ack_state"] == "ACKED", "PENDING_ACK_RECONCILIATION_REQUIRED")
        require(_sha(row["content_sha256"]), "CATALOG_HASH_REQUIRED")
        _integer(row["content_bytes"], 0, MAX_OBJECT_BYTES, "OBJECT_SIZE_BUDGET")
        total += row["content_bytes"]
        require(total <= MAX_TOTAL_BYTES, "TOTAL_OBJECT_BYTES_BUDGET")
        translated.append({"bucket": BUCKET, "key": row["object_key"],
            "generation": expected_generation, "contentSha256": row["content_sha256"],
            "contentBytes": row["content_bytes"], "ackState": "ACKED"})
    fence = {"schema": "ouf.storage-fixture-writer-fence.v1",
        "generation": expected_generation, "acceptingWrites": False,
        "activeWriters": 0, "pendingAcknowledgements": 0, "syntheticOnly": True}
    catalog = {"schema": "ouf.storage-fixture-catalog-snapshot.v1",
        "sqlSchema": "ouf_recovery_fixture", "generation": expected_generation,
        "sourcePostgresDumpSha256": source_dump_sha256,
        "complete": True, "rowCount": len(translated),
        "rows": sorted(translated, key=lambda row: (row["bucket"], row["key"]))}
    fence_bytes, catalog_bytes = canonical_json(fence), canonical_json(catalog)
    require(len(catalog_bytes) <= MAX_SNAPSHOT_BYTES, "CATALOG_SNAPSHOT_BYTE_BUDGET")
    return {"fenceEvidence": fence_bytes, "catalogSnapshot": catalog_bytes,
        "receipt": {"schema": "ouf.postgres-fixture-snapshot-readback.v1",
            "status": "FIXTURE_SNAPSHOT_OBSERVED_NOT_RESTORE_OR_FENCE_PROOF",
            "rawSnapshotSha256": hashlib.sha256(raw).hexdigest(),
            "sqlSha256": hashlib.sha256(SNAPSHOT_SQL.encode()).hexdigest(),
            "fenceEvidenceSha256": hashlib.sha256(fence_bytes).hexdigest(),
            "catalogSnapshotSha256": hashlib.sha256(catalog_bytes).hexdigest(),
            "generation": expected_generation, "objectCount": len(translated),
            "expectedObjectBytes": total, "sourceDumpReference": source_dump_sha256,
            "dumpRestoreOriginVerified": False, "writerFenceEnforcedByAdapter": False,
            "runtimeHealthyClaimed": False, "pitrQualified": False,
            "releaseAdmitted": False, "runtimeAuthorityIssued": False,
            "targetOperations": 0}}


def read_fixture_snapshot(*, psql: Path, socket_directory: Path,
                          expected_generation: str, source_dump_sha256: str,
                          port: int = 5432, timeout: float = 15) -> dict:
    """Read the fixed fixture DB/schema through an authorized local lab socket.

    socket_directory and executable are supplied by the isolated lab owner;
    filesystem checks are not a server identity or immutable-image attestation.
    No TCP target, credentials, arbitrary SQL, DB name, or shell is accepted.
    """
    require(isinstance(psql, Path) and psql.is_absolute() and psql.is_file()
            and os.access(psql, os.X_OK), "PSQL_EXECUTABLE_REQUIRED")
    require(isinstance(socket_directory, Path) and socket_directory.is_absolute()
            and socket_directory.is_dir() and "," not in str(socket_directory)
            and "\x00" not in str(socket_directory), "SINGLE_LOCAL_SOCKET_DIRECTORY_REQUIRED")
    _integer(port, 1, 65535, "POSTGRES_PORT_REQUIRED")
    # Validate caller references before starting a process.
    require(_sha(source_dump_sha256), "SOURCE_DUMP_REFERENCE_REQUIRED")
    require(isinstance(expected_generation, str) and 0 < len(expected_generation) <= 128,
            "EXPECTED_GENERATION_REQUIRED")
    argv = [str(psql), "--no-psqlrc", "--no-password", "--quiet", "--tuples-only",
            "--no-align", "--set=ON_ERROR_STOP=1", "--host=" + str(socket_directory),
            "--port=" + str(port), "--username=ouf_recovery_fixture",
            "--dbname=ouf_recovery_fixture", "--command=" + SNAPSHOT_SQL]
    raw = _run_bounded(argv, timeout=timeout)
    return decode_snapshot(raw, expected_generation=expected_generation,
                           source_dump_sha256=source_dump_sha256)
