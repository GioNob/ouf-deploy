"""Durable provider operation authorization (sprint-01 task-37, D-033, D-034).

One human-issued document authorizes the provider to run, and restart, while the
signing key's mandate was ACTIVE at the signed `issuedAt` and the key was never
revoked (D-029 durable rule). Signed with the installer key, role RUNTIME_ARMING
of the existing B1/B2 anchor, under a SEPARATE signing domain (D-034 D6a): an
operation signature can never be confused with an arming or acceptance one.

Chain (D-034 D7): `<n>.json` + `<n>.signature.json`, n = 1..N contiguous; entry k>1
must supersede sha256(payload k-1). The head (N) is the only effective one; a head
with decision STOP means "do not run". Stray names, gaps, forks or custody
errors are denials, never a shorter chain.

`mandates` is the B1/B2 mandate module the caller compiled from verified bytes
(`tools/semantic_authority_mandates/mandates.py`); it is never imported by path.
Read-only: no writes, no keys, no subprocess except the pinned OpenSSL verify.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "ouf.semantic-provider-operation-authorization.v1"
SIGNATURE_SCHEMA = "ouf.semantic-provider-operation-signature.v1"
DOMAIN = b"OUF-SEMANTIC-PROVIDER-OPERATION\x00V1\x00"
ROLE = "RUNTIME_ARMING"
ROLES = ("adapter", "southbound")
DECISIONS = ("OPERATE", "STOP")
FIELDS = {"schema", "installationRef", "entityRef", "issuerRef", "sequence", "supersedes", "issuedAt",
          "decision", "runtimeConfigurationSha256", "acceptanceSha256", "roles", "lease"}
ROLE_FIELDS = {"containerId", "imageManifestDigest", "framePolicySha256", "admissionConfigurationSha256",
               "rootfsSealSha256", "transportSha256", "tableName"}
LEASE_FIELDS = {"ownerConfigurationSha256", "leaseStructureHash", "dnsProfileSha256"}
HEADER_FIELDS = {"schema", "algorithm", "keyRef", "role", "issuerRef", "installationRef", "entityRef", "payloadHash"}
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TABLE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
NAME = re.compile(r"([1-9][0-9]{0,5})[.](json|signature[.]json)")
MAX_CHAIN = 256
LIMIT = 65536


class OperationDenied(RuntimeError):
    """Public code only; never paths or contents."""


def require(value, code):
    if not value:
        raise OperationDenied(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "BOUNDED_OPERATION_DOCUMENT_REQUIRED")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "DUPLICATE_OPERATION_FIELD")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(OperationDenied("NON_FINITE_NUMBER")))
    except (ValueError, UnicodeDecodeError):
        raise OperationDenied("OPERATION_JSON_REQUIRED") from None
    require(type(value) is dict and canonical(value) == raw, "CANONICAL_OPERATION_JSON_REQUIRED")
    return value


def identity(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None


def integer(value, minimum=0):
    return type(value) is int and minimum <= value < 2 ** 53


def validate(raw):
    """Closed schema of one authorization payload (exact canonical bytes)."""
    value = decode(raw)
    require(set(value) == FIELDS and value["schema"] == SCHEMA, "EXACT_OPERATION_AUTHORIZATION_REQUIRED")
    require(all(identity(value[k]) for k in ("installationRef", "entityRef", "issuerRef")),
            "OPERATION_SCOPE_REQUIRED")
    require(integer(value["sequence"], 1) and integer(value["issuedAt"], 1), "OPERATION_SEQUENCE_AND_TIME_REQUIRED")
    require((value["sequence"] == 1 and value["supersedes"] is None)
            or (value["sequence"] > 1 and type(value["supersedes"]) is str and HEX64.fullmatch(value["supersedes"])),
            "OPERATION_SUPERSEDES_REQUIRED")
    require(value["decision"] in DECISIONS, "OPERATION_DECISION_REQUIRED")
    require(all(type(value[k]) is str and HEX64.fullmatch(value[k])
                for k in ("runtimeConfigurationSha256", "acceptanceSha256")), "OPERATION_BINDINGS_REQUIRED")
    roles = value["roles"]
    require(type(roles) is dict and tuple(sorted(roles)) == ROLES, "EXACT_OPERATION_ROLES_REQUIRED")
    for entry in roles.values():
        require(type(entry) is dict and set(entry) == ROLE_FIELDS
                and type(entry["containerId"]) is str and HEX64.fullmatch(entry["containerId"])
                and type(entry["imageManifestDigest"]) is str and DIGEST.fullmatch(entry["imageManifestDigest"])
                and all(type(entry[k]) is str and HEX64.fullmatch(entry[k]) for k in
                        ("framePolicySha256", "admissionConfigurationSha256", "rootfsSealSha256", "transportSha256"))
                and type(entry["tableName"]) is str and TABLE.fullmatch(entry["tableName"]),
                "EXACT_OPERATION_ROLE_REQUIRED")
    require(len({e["containerId"] for e in roles.values()}) == 2
            and len({e["tableName"] for e in roles.values()}) == 2, "DISTINCT_OPERATION_ROLES_REQUIRED")
    lease = value["lease"]
    require(type(lease) is dict and set(lease) == LEASE_FIELDS
            and all(type(lease[k]) is str and HEX64.fullmatch(lease[k]) for k in LEASE_FIELDS),
            "EXACT_OPERATION_LEASE_REQUIRED")
    return value


def signing_bytes(raw, header):
    """Frame signed by the installer key. Separate domain from mandates.DOMAIN."""
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "BOUNDED_OPERATION_DOCUMENT_REQUIRED")
    require(type(header) is dict and set(header) == HEADER_FIELDS and header["schema"] == SIGNATURE_SCHEMA
            and header["algorithm"] == "Ed25519" and header["role"] == ROLE
            and all(identity(header[k]) for k in ("keyRef", "issuerRef", "installationRef", "entityRef"))
            and header["payloadHash"] == sha(raw), "EXACT_OPERATION_SIGNING_FRAME_REQUIRED")
    encoded = canonical(header)
    return DOMAIN + len(encoded).to_bytes(4, "big") + encoded + len(raw).to_bytes(4, "big") + raw


def private_file(path):
    """Root-owned (or REQUIRED_UID in tests) regular 0600 file, nlink 1, no symlink, bounded."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == REQUIRED_UID and info.st_gid == REQUIRED_UID
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= LIMIT,
                "OPERATION_FILE_CUSTODY_REQUIRED")
        raw = os.read(fd, LIMIT + 1)
        require(len(raw) == info.st_size and os.fstat(fd).st_mtime_ns == info.st_mtime_ns,
                "OPERATION_FILE_CHANGED_DURING_READ")
        return raw
    finally:
        os.close(fd)


REQUIRED_UID = 0  # tests override


def inventory(root):
    """Contiguous 1..N with both files per entry; anything else is a denial."""
    info = os.lstat(root)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == REQUIRED_UID and stat.S_IMODE(info.st_mode) == 0o700,
            "OPERATION_DIRECTORY_CUSTODY_REQUIRED")
    names = os.listdir(root)
    require(len(names) <= 2 * MAX_CHAIN, "OPERATION_CHAIN_UNBOUNDED")
    numbers = {}
    for name in names:
        match = NAME.fullmatch(name)
        require(match is not None, "FOREIGN_OPERATION_ENTRY")
        numbers.setdefault(int(match.group(1)), set()).add(match.group(2))
    require(sorted(numbers) == list(range(1, len(numbers) + 1))
            and all(kinds == {"json", "signature.json"} for kinds in numbers.values()),
            "CONTIGUOUS_OPERATION_CHAIN_REQUIRED")
    return len(numbers)


def verify_entry(mandates, ledger, authenticator, raw, signature_raw, expected):
    """One link: closed payload, separate-domain signature, durable mandate at issuedAt."""
    value = validate(raw)
    require((value["installationRef"], value["entityRef"], value["issuerRef"]) == expected,
            "OPERATION_SCOPE_DRIFT")
    record = decode(signature_raw)
    require(set(record) == HEADER_FIELDS | {"signature"} and record["schema"] == SIGNATURE_SCHEMA
            and record["algorithm"] == "Ed25519" and record["role"] == ROLE and identity(record["keyRef"])
            and (record["installationRef"], record["entityRef"], record["issuerRef"]) == expected
            and record["payloadHash"] == sha(raw)
            and type(record["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}", record["signature"]),
            "EXACT_OPERATION_SIGNATURE_REQUIRED")
    try:
        mandate = ledger.at(record["keyRef"], value["issuedAt"])
        revoked = ledger.ever_revoked(record["keyRef"])
    except mandates.MandateDenied:
        raise OperationDenied("OPERATION_KEY_UNKNOWN") from None
    require(mandate["issuerRef"] == expected[2] and ROLE in mandate["roles"] and mandate["state"] == "ACTIVE"
            and mandate["notBefore"] <= value["issuedAt"] < mandate["expiresAt"],
            "OPERATION_MANDATE_AT_ISSUANCE_REQUIRED")
    require(not revoked, "OPERATION_KEY_REVOKED")
    header = {k: v for k, v in record.items() if k != "signature"}
    try:
        authenticator.verify(signing_bytes(raw, header), bytes.fromhex(mandate["publicKey"]),
                             bytes.fromhex(record["signature"]))
    except mandates.MandateDenied:
        raise OperationDenied("OPERATION_SIGNATURE_INVALID") from None
    return value


def head(mandates, anchor_binding, ledger_root, openssl_binding, authorization_root, installation, entity, issuer,
         clock, budget=None):
    """Verify the whole chain and return the effective head.

    Result: {"sequence", "sha256", "decision", "authorization"}. Verification is
    durable: it does not depend on `now` being inside the mandate window, only on
    issuedAt <= now and the ledger history. The ledger must not change while
    the chain is verified.
    """
    expected = (installation, entity, issuer)
    require(all(identity(v) for v in expected), "OPERATION_SCOPE_REQUIRED")
    now = clock()
    try:
        ledger = mandates.MandateLedger(anchor_binding, ledger_root, installation, entity, clock, budget)
        ledger.refresh(now)
        require(ledger.view()["anchor"]["schema"] == mandates.B1B2_ANCHOR_SCHEMA, "EXACT_B1B2_ANCHOR_REQUIRED")
        snapshot = ledger.snapshot()
        authenticator = mandates.MandateAuthenticator(anchor_binding, ledger_root, openssl_binding, clock, budget)
    except mandates.MandateDenied:
        raise OperationDenied("OPERATION_LEDGER_UNPROVEN") from None
    root = Path(authorization_root)
    count = inventory(root)
    require(count >= 1, "OPERATION_AUTHORIZATION_ABSENT")
    previous = None
    for number in range(1, count + 1):
        raw = private_file(root / f"{number}.json")
        signature_raw = private_file(root / f"{number}.signature.json")
        value = verify_entry(mandates, ledger, authenticator, raw, signature_raw, expected)
        require(value["sequence"] == number and value["supersedes"] == previous, "OPERATION_CHAIN_BROKEN")
        require(value["issuedAt"] <= now, "OPERATION_ISSUED_IN_FUTURE")
        if number > 1:
            require(value["issuedAt"] >= last_issued, "OPERATION_CHAIN_TIME_REGRESSED")
        previous, last_issued, head_value, head_raw = sha(raw), value["issuedAt"], value, raw
    require(inventory(root) == count, "OPERATION_CHAIN_CHANGED_DURING_VERIFICATION")
    try:
        ledger.refresh(clock())
        require(ledger.snapshot() == snapshot, "OPERATION_LEDGER_CHANGED_DURING_VERIFICATION")
    except mandates.MandateDenied:
        raise OperationDenied("OPERATION_LEDGER_UNPROVEN") from None
    return {"sequence": count, "sha256": sha(head_raw), "decision": head_value["decision"],
            "authorization": head_value}
