"""Hash-bound backup manifests and read-only restore verification for the lab.

This module never stops a writer, creates a backup, or restores a service.  It
records already-fenced synthetic fixture files, plans a distinct restore path,
and verifies bytes that a caller has placed there.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable

from .profile import (
    LAB_DATA_ROOT,
    REQUIRED_ARTIFACT_KINDS,
    RESTORE_ROOT,
    ProfileError,
    profile_sha256,
    validate_profile,
)


MANIFEST_SCHEMA = "ouf.storage-recovery-manifest.v1"
MANIFEST_STATUS = "SYNTHETIC_BACKUP_MANIFEST_NOT_ACCEPTANCE"
PLAN_SCHEMA = "ouf.storage-recovery-plan.v1"
PLAN_STATUS = "PLANNED_NOT_EXECUTED"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


class ManifestError(ValueError):
    """Manifest or restore plan failed a fail-closed validation rule."""


def _exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ManifestError(code)
    return value


def _relative(raw: Any, code: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\\" in raw:
        raise ManifestError(code)
    path = PurePosixPath(raw)
    if path == PurePosixPath(".") or ".." in path.parts or any(part in ("", ".") for part in path.parts):
        raise ManifestError(code)
    return path


def _utc_timestamp(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.endswith("Z"):
        raise ManifestError("UTC_TIMESTAMP_REQUIRED")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise ManifestError("UTC_TIMESTAMP_REQUIRED") from error
    if parsed.utcoffset().total_seconds() != 0:
        raise ManifestError("UTC_TIMESTAMP_REQUIRED")
    return raw


def _authority() -> dict[str, Any]:
    return {
        "syntheticOnly": True,
        "releaseAdmitted": False,
        "runtimeAuthorityIssued": False,
        "targetOperations": 0,
        "acceptanceClaimed": False,
    }


def _validate_authority(value: Any) -> None:
    if value != _authority():
        raise ManifestError("SYNTHETIC_ZERO_AUTHORITY_REQUIRED")


def _candidate_binding(profile: dict[str, Any]) -> dict[str, Any]:
    candidate = profile["candidate"]
    return {
        "lockSha256": candidate["lockSha256"],
        "version": candidate["version"],
        "upstreamCommit": candidate["upstreamCommit"],
        "binarySha256": candidate["binarySha256"],
        "ociManifestDigest": candidate["ociManifestDigest"],
    }


def _regular_file(path: Path, code: str) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ManifestError(code)
    return info


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_symlink_components(root: Path, relative: PurePosixPath, code: str) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ManifestError(code)


def record_artifact(
    source_root: Path,
    relative_path: str,
    *,
    logical_id: str,
    kind: str,
    generation: str,
) -> dict[str, Any]:
    """Hash one existing synthetic fixture file without following symlinks."""
    if not ID.fullmatch(logical_id):
        raise ManifestError("ARTIFACT_LOGICAL_ID_INVALID")
    if kind not in REQUIRED_ARTIFACT_KINDS:
        raise ManifestError("ARTIFACT_KIND_INVALID")
    if not ID.fullmatch(generation):
        raise ManifestError("ARTIFACT_GENERATION_INVALID")
    rel = _relative(relative_path, "ARTIFACT_RELATIVE_PATH_INVALID")
    if stat.S_ISLNK(source_root.lstat().st_mode):
        raise ManifestError("ARTIFACT_SOURCE_ROOT_SYMLINK_FORBIDDEN")
    root = source_root.resolve(strict=True)
    source = root.joinpath(*rel.parts)
    _reject_symlink_components(root, rel, "ARTIFACT_SYMLINK_FORBIDDEN")
    info = _regular_file(source, "ARTIFACT_MUST_BE_REGULAR_FILE")
    if info.st_size <= 0:
        raise ManifestError("EMPTY_ARTIFACT_FORBIDDEN")
    return {
        "logicalId": logical_id,
        "kind": kind,
        "relativePath": rel.as_posix(),
        "bytes": info.st_size,
        "sha256": _sha256_file(source),
        "generation": generation,
        "sourcePathClass": "SYNTHETIC_LAB",
    }


def build_manifest(
    profile: dict[str, Any],
    artifacts: Iterable[dict[str, Any]],
    *,
    backup_id: str,
    created_at: str,
    writer_fence: dict[str, Any],
) -> dict[str, Any]:
    validate_profile(profile)
    if not ID.fullmatch(backup_id) or not backup_id.startswith("lab-"):
        raise ManifestError("LAB_BACKUP_ID_REQUIRED")
    _utc_timestamp(created_at)
    fence = _exact_keys(writer_fence, {"status", "generation", "evidenceSha256"}, "WRITER_FENCE_FIELDS_INVALID")
    if (
        fence["status"] != "CONFIRMED"
        or not isinstance(fence["generation"], str)
        or not ID.fullmatch(fence["generation"])
        or not isinstance(fence["evidenceSha256"], str)
        or not HEX64.fullmatch(fence["evidenceSha256"])
    ):
        raise ManifestError("CONFIRMED_WRITER_FENCE_REQUIRED")
    rows = sorted(
        (dict(row) for row in artifacts),
        key=lambda row: (row.get("kind", ""), row.get("logicalId", "")),
    )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "status": MANIFEST_STATUS,
        "candidate": _candidate_binding(profile),
        "profileSha256": profile_sha256(profile),
        "backupId": backup_id,
        "createdAt": created_at,
        "writerFence": fence,
        "artifacts": rows,
        "totals": {"artifacts": len(rows), "bytes": sum(row.get("bytes", 0) for row in rows)},
        "authority": _authority(),
    }
    validate_manifest(profile, manifest)
    return manifest


def validate_manifest(profile: dict[str, Any], manifest: Any) -> dict[str, Any]:
    validate_profile(profile)
    root = _exact_keys(
        manifest,
        {
            "schema",
            "status",
            "candidate",
            "profileSha256",
            "backupId",
            "createdAt",
            "writerFence",
            "artifacts",
            "totals",
            "authority",
        },
        "MANIFEST_FIELDS_INVALID",
    )
    if root["schema"] != MANIFEST_SCHEMA or root["status"] != MANIFEST_STATUS:
        raise ManifestError("MANIFEST_IDENTITY_INVALID")
    if root["candidate"] != _candidate_binding(profile) or root["profileSha256"] != profile_sha256(profile):
        raise ManifestError("MANIFEST_CANDIDATE_OR_PROFILE_MISMATCH")
    if not isinstance(root["backupId"], str) or not ID.fullmatch(root["backupId"]) or not root["backupId"].startswith("lab-"):
        raise ManifestError("LAB_BACKUP_ID_REQUIRED")
    _utc_timestamp(root["createdAt"])
    _validate_authority(root["authority"])
    fence = _exact_keys(root["writerFence"], {"status", "generation", "evidenceSha256"}, "WRITER_FENCE_FIELDS_INVALID")
    if (
        fence["status"] != "CONFIRMED"
        or not isinstance(fence["generation"], str)
        or not ID.fullmatch(fence["generation"])
        or not isinstance(fence["evidenceSha256"], str)
        or not HEX64.fullmatch(fence["evidenceSha256"])
    ):
        raise ManifestError("CONFIRMED_WRITER_FENCE_REQUIRED")

    rows = root["artifacts"]
    if not isinstance(rows, list) or not rows:
        raise ManifestError("ARTIFACTS_REQUIRED")
    logical_ids: set[str] = set()
    paths: set[PurePosixPath] = set()
    kinds: list[str] = []
    order: list[tuple[str, str]] = []
    total = 0
    maximum_artifact = profile["backupPolicy"]["maximumArtifactBytes"]
    for row in rows:
        artifact = _exact_keys(
            row,
            {"logicalId", "kind", "relativePath", "bytes", "sha256", "generation", "sourcePathClass"},
            "ARTIFACT_FIELDS_INVALID",
        )
        if not isinstance(artifact["logicalId"], str) or not ID.fullmatch(artifact["logicalId"]):
            raise ManifestError("ARTIFACT_LOGICAL_ID_INVALID")
        if artifact["logicalId"] in logical_ids:
            raise ManifestError("DUPLICATE_ARTIFACT_LOGICAL_ID")
        logical_ids.add(artifact["logicalId"])
        if artifact["kind"] not in REQUIRED_ARTIFACT_KINDS:
            raise ManifestError("ARTIFACT_KIND_INVALID")
        kinds.append(artifact["kind"])
        order.append((artifact["kind"], artifact["logicalId"]))
        path = _relative(artifact["relativePath"], "ARTIFACT_RELATIVE_PATH_INVALID")
        if path in paths:
            raise ManifestError("DUPLICATE_ARTIFACT_RELATIVE_PATH")
        paths.add(path)
        if (
            not isinstance(artifact["bytes"], int)
            or isinstance(artifact["bytes"], bool)
            or not 1 <= artifact["bytes"] <= maximum_artifact
        ):
            raise ManifestError("ARTIFACT_SIZE_INVALID")
        if not isinstance(artifact["sha256"], str) or not HEX64.fullmatch(artifact["sha256"]):
            raise ManifestError("ARTIFACT_SHA256_INVALID")
        if artifact["generation"] != fence["generation"]:
            raise ManifestError("ARTIFACT_FENCE_GENERATION_MISMATCH")
        if artifact["sourcePathClass"] != "SYNTHETIC_LAB":
            raise ManifestError("SYNTHETIC_ARTIFACTS_ONLY")
        total += artifact["bytes"]
    if order != sorted(order) or set(kinds) != set(REQUIRED_ARTIFACT_KINDS):
        raise ManifestError("EXACT_SORTED_BACKUP_COMPONENT_SET_REQUIRED")
    if total > profile["backupPolicy"]["maximumTotalBytes"]:
        raise ManifestError("BACKUP_TOTAL_SIZE_EXCEEDED")
    if root["totals"] != {"artifacts": len(rows), "bytes": total}:
        raise ManifestError("MANIFEST_TOTALS_MISMATCH")
    return root


def plan_restore(profile: dict[str, Any], manifest: dict[str, Any], restore_root: str) -> dict[str, Any]:
    validate_manifest(profile, manifest)
    root = PurePosixPath(restore_root)
    if not root.is_absolute() or ".." in root.parts:
        raise ManifestError("ABSOLUTE_RESTORE_ROOT_REQUIRED")
    try:
        root.relative_to(RESTORE_ROOT)
    except ValueError as error:
        raise ManifestError("SYNTHETIC_RESTORE_ROOT_REQUIRED") from error
    if root == RESTORE_ROOT:
        raise ManifestError("DEDICATED_RESTORE_ROOT_REQUIRED")
    for role in profile["roles"]:
        source = PurePosixPath(role["persistentPath"])
        if root == source or root in source.parents or source in root.parents:
            raise ManifestError("RESTORE_MUST_BE_INDEPENDENT_OF_ORIGINALS")
    mappings = [
        {
            "logicalId": row["logicalId"],
            "relativePath": row["relativePath"],
            "destination": str(root.joinpath(*PurePosixPath(row["relativePath"]).parts)),
            "expectedBytes": row["bytes"],
            "expectedSha256": row["sha256"],
        }
        for row in manifest["artifacts"]
    ]
    return {
        "schema": PLAN_SCHEMA,
        "status": PLAN_STATUS,
        "backupId": manifest["backupId"],
        "profileSha256": manifest["profileSha256"],
        "restoreRoot": str(root),
        "originalsMustRemainInaccessible": True,
        "environmentMustStartEmpty": True,
        "mappings": mappings,
        "authority": _authority(),
    }


def verify_restore(
    profile: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    restored_root: Path,
) -> dict[str, Any]:
    validate_manifest(profile, manifest)
    expected_plan = plan_restore(profile, manifest, plan.get("restoreRoot", ""))
    if plan != expected_plan:
        raise ManifestError("RESTORE_PLAN_MISMATCH")
    if stat.S_ISLNK(restored_root.lstat().st_mode):
        raise ManifestError("RESTORE_VERIFICATION_ROOT_SYMLINK_FORBIDDEN")
    root = restored_root.resolve(strict=True)
    verified = 0
    verified_bytes = 0
    for row in manifest["artifacts"]:
        rel = _relative(row["relativePath"], "ARTIFACT_RELATIVE_PATH_INVALID")
        target = root.joinpath(*rel.parts)
        _reject_symlink_components(root, rel, "RESTORE_SYMLINK_FORBIDDEN")
        info = _regular_file(target, "RESTORED_ARTIFACT_MUST_BE_REGULAR_FILE")
        digest = _sha256_file(target)
        if info.st_size != row["bytes"] or digest != row["sha256"]:
            raise ManifestError("RESTORED_ARTIFACT_MISMATCH")
        verified += 1
        verified_bytes += info.st_size
    return {
        "schema": "ouf.storage-recovery-verification.v1",
        "status": "VERIFIED_SYNTHETIC_CONTENT_ONLY_NOT_ACCEPTANCE",
        "backupId": manifest["backupId"],
        "verifiedArtifacts": verified,
        "verifiedBytes": verified_bytes,
        "rpoMeasured": False,
        "rtoMeasured": False,
        "postgresCoordinatedRecoveryQualified": False,
        "targetE2E": False,
        "authority": _authority(),
    }
