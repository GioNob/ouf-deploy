"""Pure B1 payload validation/building and task-14 detached verification.

No signing, private-key access, artifact reads or publication. Artifact paths
describe POSIX deployment inputs, independently of the verifier's host OS.
"""

import copy
import hashlib
import json
from pathlib import PurePosixPath
import re

from tools.semantic_b1b2_authority import authority as A


SCHEMA = "ouf.semantic-provider-b1-artifact-acceptance.v1"
SEAL_SCHEMA = "ouf.semantic-rootfs-seal.v1"
MAX_PAYLOAD_BYTES = 131072  # Task-14's signed-payload bound.
ROLES = ("adapter", "southbound")
RECIPE_PARTS = ("template", "launch", "context", "policy")
A_FILES = ("manifest", "result", "semanticPeer", "successors")
FIELDS = {"schema", "installationRef", "entityRef", "generation", "profile",
          "preparationA", "creation", "roles", "softwareClosure", "trustPolicy",
          "startAuthorized", "leaseAuthorized", "issuedAt"}
EXPECTED_FIELDS = {"installationRef", "entityRef", "issuerRef", "profileSha256",
                   "preparationA", "roles", "trustPolicy", "minimumGeneration"}


class AcceptanceDenied(RuntimeError):
    """Stable public code; messages never contain input values."""


def require(ok, code):
    if not ok:
        raise AcceptanceDenied(code)


def exact(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)


def path(value, *, absolute, code):
    require(type(value) is str and bool(value) and "\\" not in value
            and not any(ord(char) < 32 or ord(char) == 127 for char in value), code)
    parsed = PurePosixPath(value)
    require(parsed.is_absolute() == absolute and str(parsed) == value
            and ".." not in parsed.parts and value not in ("/", ".")
            and not value.startswith("//") and (absolute or ":" not in value), code)


def binding(value):
    exact(value, {"path", "sha256"}, "ACCEPTANCE_BINDING_FIELDS_REQUIRED")
    path(value["path"], absolute=True, code="ACCEPTANCE_ABSOLUTE_PATH_REQUIRED")
    require(A.hashed(value["sha256"]), "ACCEPTANCE_SHA256_REQUIRED")


def integer(value, minimum, code):
    require(type(value) is int and value >= minimum, code)


def validate_acceptance(value):
    """Validate a closed manifest without opening/following any artifact path.

    Returns an independent copy. The builder requires the schema field too.
    Generation monotonicity is enforced by the caller's persisted minimum.
    """
    exact(value, FIELDS, "ACCEPTANCE_FIELDS_REQUIRED")
    require(value["schema"] == SCHEMA, "ACCEPTANCE_SCHEMA_REQUIRED")
    for field in ("installationRef", "entityRef"):
        require(A.identity(value[field]), "ACCEPTANCE_IDENTITY_REQUIRED")
    integer(value["generation"], 1, "ACCEPTANCE_GENERATION_REQUIRED")
    binding(value["profile"])
    prep = value["preparationA"]
    exact(prep, {"root", "planSha256", "files"}, "ACCEPTANCE_PREPARATION_FIELDS_REQUIRED")
    path(prep["root"], absolute=True, code="ACCEPTANCE_ABSOLUTE_PATH_REQUIRED")
    require(A.hashed(prep["planSha256"]), "ACCEPTANCE_SHA256_REQUIRED")
    exact(prep["files"], A_FILES, "ACCEPTANCE_PREPARATION_FILES_REQUIRED")
    for item in prep["files"].values():
        binding(item)
    creation = value["creation"]
    exact(creation, {"transactionRef", "evidence", "declaredGaps"}, "ACCEPTANCE_CREATION_FIELDS_REQUIRED")
    require(A.identity(creation["transactionRef"]), "ACCEPTANCE_TRANSACTION_REQUIRED")
    require(creation["evidence"] == "PREPARATION_A_ONLY", "ACCEPTANCE_CREATION_EVIDENCE_REQUIRED")
    gaps = creation["declaredGaps"]
    require(type(gaps) is list and all(type(code) is str
            and re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*", code) for code in gaps),
            "ACCEPTANCE_GAP_CODES_REQUIRED")
    require(len(gaps) == len(set(gaps)), "ACCEPTANCE_GAP_CODES_REQUIRED")
    exact(value["roles"], ROLES, "ACCEPTANCE_ROLES_REQUIRED")
    for role in ROLES:
        row = value["roles"][role]
        exact(row, {"containerId", "imageId", "recipe", "rootfs"}, "ACCEPTANCE_ROLE_FIELDS_REQUIRED")
        require(A.hashed(row["containerId"]), "ACCEPTANCE_CID_REQUIRED")
        require(type(row["imageId"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", row["imageId"]),
                "ACCEPTANCE_IMAGE_ID_REQUIRED")
        exact(row["recipe"], RECIPE_PARTS, "ACCEPTANCE_RECIPE_FIELDS_REQUIRED")
        for item in row["recipe"].values():
            binding(item)
        rootfs = row["rootfs"]
        exact(rootfs, {"offlineImageReceipt", "offlineDockerReceipt", "comparison", "effectiveSeal"},
              "ACCEPTANCE_ROOTFS_FIELDS_REQUIRED")
        for field in ("offlineImageReceipt", "offlineDockerReceipt", "comparison"):
            binding(rootfs[field])
        seal = rootfs["effectiveSeal"]
        exact(seal, {"schema", "sha256", "entries", "bytes"}, "ACCEPTANCE_SEAL_FIELDS_REQUIRED")
        require(seal["schema"] == SEAL_SCHEMA, "ACCEPTANCE_SEAL_SCHEMA_REQUIRED")
        require(A.hashed(seal["sha256"]), "ACCEPTANCE_SHA256_REQUIRED")
        integer(seal["entries"], 1, "ACCEPTANCE_SEAL_ENTRIES_REQUIRED")
        integer(seal["bytes"], 0, "ACCEPTANCE_SEAL_BYTES_REQUIRED")
    adapter, southbound = (value["roles"][role] for role in ROLES)
    require(adapter["containerId"] != southbound["containerId"], "ACCEPTANCE_DISTINCT_CIDS_REQUIRED")
    recipes = [{(item["path"], item["sha256"]) for item in row["recipe"].values()}
               for row in (adapter, southbound)]
    require(recipes[0] != recipes[1], "ACCEPTANCE_DISTINCT_RECIPES_REQUIRED")
    closure = value["softwareClosure"]
    exact(closure, {"sourceCommit", "files"}, "ACCEPTANCE_CLOSURE_FIELDS_REQUIRED")
    require(type(closure["sourceCommit"]) is str and re.fullmatch(r"[0-9a-f]{40}", closure["sourceCommit"]),
            "ACCEPTANCE_SOURCE_COMMIT_REQUIRED")
    require(type(closure["files"]) is dict and 1 <= len(closure["files"]) <= 256,
            "ACCEPTANCE_CLOSURE_FILES_REQUIRED")
    for name, digest in closure["files"].items():
        path(name, absolute=False, code="ACCEPTANCE_RELATIVE_PATH_REQUIRED")
        require(A.hashed(digest), "ACCEPTANCE_SHA256_REQUIRED")
    binding(value["trustPolicy"])
    require(value["startAuthorized"] is False, "ACCEPTANCE_START_FORBIDDEN")
    require(value["leaseAuthorized"] is False, "ACCEPTANCE_LEASE_FORBIDDEN")
    integer(value["issuedAt"], 0, "ACCEPTANCE_ISSUED_AT_REQUIRED")
    return copy.deepcopy(value)


def build_acceptance(**fields):
    """Sorted compact ASCII JSON plus exactly one LF; hash/sign those bytes.

    No timestamps, generations or filesystem values are inferred or filled in.
    """
    value = validate_acceptance(fields)
    raw = A.canonical(value) + b"\n"
    require(len(raw) <= MAX_PAYLOAD_BYTES, "ACCEPTANCE_PAYLOAD_BOUND_REQUIRED")
    return raw


def decode_manifest(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PAYLOAD_BYTES, "ACCEPTANCE_PAYLOAD_BOUND_REQUIRED")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "ACCEPTANCE_DUPLICATE_KEY")
            result[key] = value
        return result

    def no_constant(_):
        raise ValueError()

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise AcceptanceDenied("ACCEPTANCE_JSON_REQUIRED") from None
    return validate_acceptance(value)


def validate_expected(expected):
    exact(expected, EXPECTED_FIELDS, "ACCEPTANCE_EXPECTED_FIELDS_REQUIRED")
    for field in ("installationRef", "entityRef", "issuerRef"):
        require(A.identity(expected[field]), "ACCEPTANCE_EXPECTED_IDENTITY_REQUIRED")
    require(A.hashed(expected["profileSha256"]), "ACCEPTANCE_EXPECTED_SHA256_REQUIRED")
    prep = expected["preparationA"]
    exact(prep, {"planSha256", "files"}, "ACCEPTANCE_EXPECTED_PREPARATION_REQUIRED")
    exact(prep["files"], A_FILES, "ACCEPTANCE_EXPECTED_PREPARATION_FILES_REQUIRED")
    require(A.hashed(prep["planSha256"]) and all(A.hashed(item) for item in prep["files"].values()),
            "ACCEPTANCE_EXPECTED_SHA256_REQUIRED")
    exact(expected["roles"], ROLES, "ACCEPTANCE_EXPECTED_ROLES_REQUIRED")
    for row in expected["roles"].values():
        exact(row, {"containerId", "imageId"}, "ACCEPTANCE_EXPECTED_ROLE_FIELDS_REQUIRED")
        require(A.hashed(row["containerId"]), "ACCEPTANCE_EXPECTED_CID_REQUIRED")
        require(type(row["imageId"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", row["imageId"]),
                "ACCEPTANCE_EXPECTED_IMAGE_ID_REQUIRED")
    binding(expected["trustPolicy"])
    integer(expected["minimumGeneration"], 1, "ACCEPTANCE_EXPECTED_GENERATION_REQUIRED")
    return copy.deepcopy(expected)


def verify_acceptance(manifest_raw, signature_raw, *, expected, authenticator):
    """Verify exact raw payload bytes, current ACTIVE mandate and caller pins.

    Task-14 AuthorityDenied codes propagate unchanged. Only the authenticator
    reads public policy/OpenSSL inputs; this module never opens artifact paths.
    The caller supplies independent expectations, never derived from this payload.
    """
    manifest = decode_manifest(manifest_raw)
    pins = validate_expected(expected)
    require(isinstance(authenticator, A.B1B2Authenticator), "ACCEPTANCE_AUTHENTICATOR_REQUIRED")
    require(manifest["trustPolicy"] == pins["trustPolicy"] == authenticator.policy_binding,
            "ACCEPTANCE_TRUST_POLICY_MISMATCH")
    verified = authenticator.verify_b1b2_detached(manifest_raw, signature_raw, "ARTIFACT_ACCEPTANCE",
                                                pins["issuerRef"], manifest["installationRef"], manifest["entityRef"])
    require(verified is True, "ACCEPTANCE_SIGNATURE_UNPROVEN")
    for field, code in (("installationRef", "ACCEPTANCE_INSTALLATION_MISMATCH"),
                        ("entityRef", "ACCEPTANCE_ENTITY_MISMATCH")):
        require(manifest[field] == pins[field], code)
    require(manifest["profile"]["sha256"] == pins["profileSha256"], "ACCEPTANCE_PROFILE_MISMATCH")
    require(manifest["preparationA"]["planSha256"] == pins["preparationA"]["planSha256"],
            "ACCEPTANCE_A_PLAN_MISMATCH")
    for field, label in (("manifest", "MANIFEST"), ("result", "RESULT"),
                         ("semanticPeer", "SEMANTIC_PEER"), ("successors", "SUCCESSORS")):
        require(manifest["preparationA"]["files"][field]["sha256"] == pins["preparationA"]["files"][field],
                "ACCEPTANCE_A_" + label + "_MISMATCH")
    for role in ROLES:
        require(manifest["roles"][role]["containerId"] == pins["roles"][role]["containerId"],
                "ACCEPTANCE_CID_MISMATCH")
        require(manifest["roles"][role]["imageId"] == pins["roles"][role]["imageId"],
                "ACCEPTANCE_IMAGE_MISMATCH")
    require(manifest["generation"] >= pins["minimumGeneration"], "ACCEPTANCE_GENERATION_MISMATCH")
    return {"payloadSha256": hashlib.sha256(manifest_raw).hexdigest(), "manifest": manifest}
