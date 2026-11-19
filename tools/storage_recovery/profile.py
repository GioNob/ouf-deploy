#!/usr/bin/env python3
"""Validate the bounded SeaweedFS 4.52 recovery-lab profile.

The validator is intentionally strict.  It accepts only the exact candidate
identity and a loopback, synthetic-only profile.  It does not start services,
copy data, confer runtime authority, or qualify an OUF target.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "ouf.storage-recovery-profile.v1"
STATUS = "SYNTHETIC_LAB_PROFILE_NOT_ADMITTED"
LOCK_PATH = "releases/seaweedfs-452-candidate-lock-20261103.json"
LOCK_SHA256 = "81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea"
VERSION = "4.52"
UPSTREAM_COMMIT = "984eac6a790be89e2a11de175a7413e1e3e32dd3"
PATCH_COUNT = 15
BINARY_SHA256 = "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033"
OCI_DIGEST = "sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4"
ROLE_NAMES = ("filer", "master", "s3", "volume")
REQUIRED_ARTIFACT_KINDS = (
    "config_snapshot",
    "filer_metadata",
    "master_metadata",
    "postgres_dump",
    "volume_data",
)
LAB_DATA_ROOT = PurePosixPath("/var/lib/ouf-lab/seaweedfs-452")
RESTORE_ROOT = PurePosixPath("/var/lib/ouf-lab/restore")


class ProfileError(ValueError):
    """The profile is incomplete, unbounded, or outside the synthetic lab."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def profile_sha256(profile: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(profile)).hexdigest()


def _exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProfileError(code)
    return value


def _under(path: PurePosixPath, root: PurePosixPath) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _absolute_lab_path(raw: Any, code: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise ProfileError(code)
    path = PurePosixPath(raw)
    if ".." in path.parts or not _under(path, LAB_DATA_ROOT) or path == LAB_DATA_ROOT:
        raise ProfileError(code)
    return path


def validate_profile(profile: Any) -> dict[str, Any]:
    root = _exact_keys(
        profile,
        {"schema", "status", "candidate", "authority", "isolation", "roles", "backupPolicy"},
        "PROFILE_FIELDS_INVALID",
    )
    if root["schema"] != SCHEMA or root["status"] != STATUS:
        raise ProfileError("PROFILE_IDENTITY_INVALID")

    candidate = _exact_keys(
        root["candidate"],
        {
            "lockPath",
            "lockSha256",
            "product",
            "version",
            "upstreamCommit",
            "orderedPatchCount",
            "binarySha256",
            "ociManifestDigest",
        },
        "CANDIDATE_FIELDS_INVALID",
    )
    expected_candidate = {
        "lockPath": LOCK_PATH,
        "lockSha256": LOCK_SHA256,
        "product": "SeaweedFS",
        "version": VERSION,
        "upstreamCommit": UPSTREAM_COMMIT,
        "orderedPatchCount": PATCH_COUNT,
        "binarySha256": BINARY_SHA256,
        "ociManifestDigest": OCI_DIGEST,
    }
    if candidate != expected_candidate:
        raise ProfileError("EXACT_CANDIDATE_REQUIRED")

    authority = _exact_keys(
        root["authority"],
        {
            "syntheticOnly",
            "releaseAdmitted",
            "runtimeAuthorityIssued",
            "targetOperations",
            "acceptanceClaimed",
        },
        "AUTHORITY_FIELDS_INVALID",
    )
    if authority != {
        "syntheticOnly": True,
        "releaseAdmitted": False,
        "runtimeAuthorityIssued": False,
        "targetOperations": 0,
        "acceptanceClaimed": False,
    }:
        raise ProfileError("SYNTHETIC_ZERO_AUTHORITY_REQUIRED")

    isolation = _exact_keys(
        root["isolation"],
        {"network", "allowedCidrs", "externalEgress", "targetEndpointsAllowed"},
        "ISOLATION_FIELDS_INVALID",
    )
    if (
        isolation["network"] != "seaweedfs-452-synthetic-lab"
        or isolation["allowedCidrs"] != ["127.0.0.0/8", "::1/128"]
        or isolation["externalEgress"] is not False
        or isolation["targetEndpointsAllowed"] is not False
    ):
        raise ProfileError("DEFAULT_DENY_LAB_ISOLATION_REQUIRED")
    for cidr in isolation["allowedCidrs"]:
        if not ipaddress.ip_network(cidr).is_loopback:
            raise ProfileError("LOOPBACK_CIDRS_ONLY")

    roles = root["roles"]
    if not isinstance(roles, list) or [row.get("name") for row in roles if isinstance(row, dict)] != list(ROLE_NAMES):
        raise ProfileError("EXACT_SEPARATED_ROLES_REQUIRED")
    persistent_paths: set[PurePosixPath] = set()
    for role in roles:
        row = _exact_keys(
            role,
            {
                "name",
                "kind",
                "imageDigest",
                "listenHosts",
                "persistentPath",
                "readOnlyRootFilesystem",
                "runAsUid",
                "syntheticOnly",
            },
            "ROLE_FIELDS_INVALID",
        )
        if row["kind"] != row["name"] or row["imageDigest"] != OCI_DIGEST:
            raise ProfileError("ROLE_CANDIDATE_BINDING_INVALID")
        if row["listenHosts"] != ["127.0.0.1"]:
            raise ProfileError("ROLE_LOOPBACK_BIND_REQUIRED")
        if row["readOnlyRootFilesystem"] is not True or row["syntheticOnly"] is not True:
            raise ProfileError("ROLE_HARDENING_INVALID")
        if not isinstance(row["runAsUid"], int) or isinstance(row["runAsUid"], bool) or row["runAsUid"] <= 0:
            raise ProfileError("ROLE_NONROOT_UID_REQUIRED")
        path = _absolute_lab_path(row["persistentPath"], "ROLE_PERSISTENCE_PATH_INVALID")
        if path in persistent_paths:
            raise ProfileError("ROLE_PERSISTENCE_PATHS_MUST_BE_DISTINCT")
        persistent_paths.add(path)

    policy = _exact_keys(
        root["backupPolicy"],
        {
            "requiredArtifactKinds",
            "maximumArtifactBytes",
            "maximumTotalBytes",
            "writerFenceRequired",
            "independentRestoreRootRequired",
            "originalsInaccessibleRequired",
            "allowSymlinks",
        },
        "BACKUP_POLICY_FIELDS_INVALID",
    )
    if policy["requiredArtifactKinds"] != list(REQUIRED_ARTIFACT_KINDS):
        raise ProfileError("EXACT_BACKUP_COMPONENT_SET_REQUIRED")
    if (
        not isinstance(policy["maximumArtifactBytes"], int)
        or isinstance(policy["maximumArtifactBytes"], bool)
        or not 1 <= policy["maximumArtifactBytes"] <= 2 * 1024**3
        or not isinstance(policy["maximumTotalBytes"], int)
        or isinstance(policy["maximumTotalBytes"], bool)
        or policy["maximumArtifactBytes"] > policy["maximumTotalBytes"]
        or policy["maximumTotalBytes"] > 8 * 1024**3
    ):
        raise ProfileError("BOUNDED_BACKUP_SIZE_REQUIRED")
    expected_flags = {
        "writerFenceRequired": True,
        "independentRestoreRootRequired": True,
        "originalsInaccessibleRequired": True,
        "allowSymlinks": False,
    }
    if any(policy[name] is not value for name, value in expected_flags.items()):
        raise ProfileError("FAIL_CLOSED_BACKUP_POLICY_REQUIRED")
    return root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    validate_profile(profile)
    print(json.dumps({
        "status": "VALID_SYNTHETIC_PROFILE_NOT_ACCEPTANCE",
        "profileSha256": profile_sha256(profile),
        "releaseAdmitted": False,
        "runtimeAuthorityIssued": False,
        "targetOperations": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
