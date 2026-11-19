"""Bounded reconciliation of synthetic catalog rows and streamed object bodies.

No SQL, network, writer fencing, backup or restore is executed here. Adapters
must supply complete snapshots and apply independent I/O timeouts. Positive
results concern these inputs only, never runtime health or PET acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, BinaryIO, Callable, Iterable

from .manifest import validate_manifest
from .profile import canonical_json

MAX_OBJECTS = 4096
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_FENCE_BYTES = 16384
CHUNK_BYTES = 65536
BUCKET = "ouf-recovery-fixture"


class ReconciliationError(ValueError):
    """A prerequisite is invalid; no reconciliation or healthy claim is allowed."""


def require(value: Any, code: str) -> None:
    if not value:
        raise ReconciliationError(code)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def _json(raw: bytes, maximum: int) -> dict:
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum, "INPUT_BYTE_BUDGET")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ReconciliationError("INVALID_JSON_INPUT") from error
    require(isinstance(value, dict), "OBJECT_INPUT_REQUIRED")
    return value


def _keys(value: Any, expected: set[str], code: str) -> None:
    require(isinstance(value, dict) and set(value) == expected, code)


def _integer(value: Any, minimum: int, maximum: int, code: str) -> None:
    require(type(value) is int and minimum <= value <= maximum, code)


def _sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _identity(bucket: Any, key: Any) -> tuple[str, str]:
    require(bucket == BUCKET and isinstance(key, str) and key
            and "\x00" not in key, "FIXTURE_OBJECT_IDENTITY_REQUIRED")
    try:
        size = len(key.encode("utf-8"))
    except UnicodeError as error:
        raise ReconciliationError("INVALID_KEY_ENCODING") from error
    require(size <= 1024, "OBJECT_KEY_BUDGET")
    return bucket, key


def admit_fixture_write(expected_generation: str, observed_generation: str,
                        accepting_writes: bool) -> None:
    """Pure fixture guard; an adapter must make admission atomic at its owner."""
    require(isinstance(expected_generation, str) and expected_generation
            and expected_generation == observed_generation, "STALE_WRITER_GENERATION")
    require(accepting_writes is True, "WRITER_FENCE_CLOSED")


@dataclass
class ObjectReadback:
    body: BinaryIO
    generation: str
    metadata_sha256: str | None
    content_length: int | None


def _read_body(stream: BinaryIO, expected_size: int) -> tuple[int, str, bool]:
    """Read at most expected size + one overflow sentinel, then always close."""
    count, checksum = 0, hashlib.sha256()
    try:
        while count <= expected_size:
            requested = min(CHUNK_BYTES, expected_size + 1 - count)
            block = stream.read(requested)
            require(isinstance(block, bytes) and len(block) <= requested, "BOUNDED_BYTES_STREAM_REQUIRED")
            if not block:
                return count, checksum.hexdigest(), True
            count += len(block)
            checksum.update(block)
        return count, checksum.hexdigest(), False
    finally:
        stream.close()


def reconcile(
    profile: dict,
    manifest: dict,
    *,
    fence_evidence: bytes,
    catalog_snapshot: bytes,
    listed_objects: Iterable[tuple[str, str]],
    listing_complete: bool,
    read_object: Callable[[str, str], ObjectReadback],
) -> dict:
    """Compare one complete, fenced fixture generation; errors cannot yield PASS.

    read_object must provide the actual GET body stream and response metadata,
    not expected bytes reconstructed from the SQL row. This function owns close.
    """
    validate_manifest(profile, manifest)
    generation = manifest["writerFence"]["generation"]
    fence = _json(fence_evidence, MAX_FENCE_BYTES)
    require(hashlib.sha256(fence_evidence).hexdigest() == manifest["writerFence"]["evidenceSha256"],
            "FENCE_EVIDENCE_HASH_MISMATCH")
    _keys(fence, {"schema", "generation", "acceptingWrites", "activeWriters",
                  "pendingAcknowledgements", "syntheticOnly"}, "FENCE_EVIDENCE_FIELDS")
    require(fence["schema"] == "ouf.storage-fixture-writer-fence.v1"
            and fence["generation"] == generation and fence["syntheticOnly"] is True,
            "FENCE_GENERATION_OR_SCOPE_MISMATCH")
    require(fence["acceptingWrites"] is False and type(fence["activeWriters"]) is int
            and fence["activeWriters"] == 0, "QUIESCENT_WRITER_FENCE_REQUIRED")
    require(type(fence["pendingAcknowledgements"]) is int
            and fence["pendingAcknowledgements"] == 0, "PENDING_ACK_RECONCILIATION_REQUIRED")
    catalog = _json(catalog_snapshot, MAX_SNAPSHOT_BYTES)
    _keys(catalog, {"schema", "sqlSchema", "generation", "sourcePostgresDumpSha256",
                    "complete", "rowCount", "rows"},
          "CATALOG_SNAPSHOT_FIELDS")
    require(catalog["schema"] == "ouf.storage-fixture-catalog-snapshot.v1"
            and catalog["sqlSchema"] == "ouf_recovery_fixture", "FIXTURE_CATALOG_ONLY")
    require(catalog["generation"] == generation, "CATALOG_GENERATION_MISMATCH")
    dumps = [row["sha256"] for row in manifest["artifacts"] if row["kind"] == "postgres_dump"]
    require(len(dumps) == 1 and catalog["sourcePostgresDumpSha256"] == dumps[0],
            "EXACT_SINGLE_POSTGRES_DUMP_BINDING_REQUIRED")
    require(catalog["complete"] is True and listing_complete is True, "COMPLETE_SNAPSHOTS_REQUIRED")
    _integer(catalog["rowCount"], 1, MAX_OBJECTS, "ROW_COUNT_BUDGET")
    require(isinstance(catalog["rows"], list) and len(catalog["rows"]) == catalog["rowCount"],
            "COMPLETE_ROW_SET_REQUIRED")
    expected, expected_bytes = {}, 0
    for row in catalog["rows"]:
        _keys(row, {"bucket", "key", "generation", "contentSha256", "contentBytes", "ackState"},
              "CATALOG_ROW_FIELDS")
        identity = _identity(row["bucket"], row["key"])
        require(identity not in expected, "DUPLICATE_CATALOG_OBJECT")
        require(row["generation"] == generation, "ROW_GENERATION_MISMATCH")
        require(row["ackState"] == "ACKED", "PENDING_ACK_RECONCILIATION_REQUIRED")
        require(_sha(row["contentSha256"]), "CATALOG_HASH_REQUIRED")
        _integer(row["contentBytes"], 0, MAX_OBJECT_BYTES, "OBJECT_SIZE_BUDGET")
        expected_bytes += row["contentBytes"]
        require(expected_bytes <= MAX_TOTAL_BYTES, "TOTAL_OBJECT_BYTES_BUDGET")
        expected[identity] = row
    observed = set()
    for index, identity in enumerate(listed_objects):
        require(index < MAX_OBJECTS, "LIST_OBJECT_COUNT_BUDGET")
        require(isinstance(identity, tuple) and len(identity) == 2, "LIST_OBJECT_FIELDS")
        identity = _identity(*identity)
        require(identity not in observed, "DUPLICATE_LIST_OBJECT")
        observed.add(identity)
    findings = []
    def finding(code, identity):
        findings.append({"code": code, "bucket": identity[0], "key": identity[1]})
    for identity in sorted(expected.keys() - observed):
        finding("MISSING_OBJECT", identity)
    for identity in sorted(observed - expected.keys()):
        finding("UNREFERENCED_OBJECT", identity)
    readbacks, actual_bytes = [], 0
    for identity in sorted(expected.keys() & observed):
        row = expected[identity]
        try:
            response = read_object(*identity)
            require(isinstance(response, ObjectReadback), "READBACK_FRAME_REQUIRED")
            count, checksum, ended = _read_body(response.body, row["contentBytes"])
        except Exception:
            finding("OBJECT_READBACK_FAILED", identity)
            continue
        actual_bytes += count
        if response.generation != generation:
            finding("OBJECT_GENERATION_MISMATCH", identity)
        if response.metadata_sha256 != row["contentSha256"]:
            finding("HASH_METADATA_MISMATCH", identity)
        if type(response.content_length) is not int or response.content_length != row["contentBytes"]:
            finding("DECLARED_LENGTH_MISMATCH", identity)
        if count != row["contentBytes"] or not ended:
            finding("BODY_LENGTH_MISMATCH", identity)
        if checksum != row["contentSha256"]:
            finding("BODY_SHA256_MISMATCH", identity)
        readbacks.append({"bucket": identity[0], "key": identity[1], "bytesRead": count,
                          "readBytesSha256": checksum,
                          "completeBodySha256": checksum if ended else None, "reachedEof": ended})
    complete = len(readbacks) == len(expected) and all(row["reachedEof"] for row in readbacks)
    passed = complete and not findings
    return {
        "schema": "ouf.storage-fixture-reconciliation.v1",
        "status": "SYNTHETIC_FIXTURE_RECONCILED_NOT_ACCEPTANCE" if passed else "SYNTHETIC_RECONCILIATION_BLOCKED",
        "fixtureReconciled": passed, "allExpectedReadbacksCompleted": complete,
        "generation": generation, "backupId": manifest["backupId"],
        "profileSha256": manifest["profileSha256"], "fenceEvidenceSha256": manifest["writerFence"]["evidenceSha256"],
        "catalogSnapshotSha256": hashlib.sha256(catalog_snapshot).hexdigest(),
        "listedObjectSetSha256": hashlib.sha256(canonical_json(sorted(observed))).hexdigest(),
        "expectedObjects": len(expected), "listedObjects": len(observed),
        "expectedBytes": expected_bytes, "bodyBytesRead": actual_bytes,
        "bodyByteCountComplete": not any(f["code"] == "OBJECT_READBACK_FAILED" for f in findings),
        "readbacks": readbacks, "findings": findings,
        "runtimeHealthyClaimed": False, "livePostgresRecoveryQualified": False,
        "backupBytesVerifiedByThisFunction": False,
        "pitrQualified": False, "rpoMeasured": False, "rtoMeasured": False,
        "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0,
    }
