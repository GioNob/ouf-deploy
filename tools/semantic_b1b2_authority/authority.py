"""Bounded public Ed25519 verification for B1/B2 only.

The native verification primitives mirror deployment_authentication, without
importing its cohort package or extending its closed deployment role set.
No signing, private-key reads, network access or implicit authority provisioning.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time


POLICY_SCHEMA = "ouf.semantic-provider-b1b2-trust-policy.v1"
SIGNATURE_SCHEMA = "ouf.semantic-provider-b1b2-detached-signature.v1"
B1B2_ROLES = frozenset({"ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"})
BASE_ROLES = frozenset({"DEPLOYMENT_INTENT", "CREATION_ATTESTATION", "FINAL_DEPLOYMENT_APPROVAL"})
DOMAIN = b"OUF-SEMANTIC-PROVIDER-B1B2-EVIDENCE\x00V1\x00"
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
KEY_FIELDS = {"keyRef", "issuerRef", "roles", "publicKey", "notBefore", "expiresAt", "state"}
HEADER_FIELDS = {"schema", "algorithm", "keyRef", "role", "issuerRef", "installationRef", "entityRef", "payloadHash"}


class AuthorityDenied(RuntimeError):
    """Public reason code; never includes input contents or key material."""


def require(value, reason):
    if not value:
        raise AuthorityDenied(reason)


def identity(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None


def hashed(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw, limit=65536):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "BOUNDED_AUTHENTICATION_RECORD_REQUIRED")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "DUPLICATE_AUTHENTICATION_KEY")
            result[key] = value
        return result

    try:
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AuthorityDenied("INVALID_AUTHENTICATION_JSON") from None
    require(type(result) is dict, "EXACT_AUTHENTICATION_OBJECT_REQUIRED")
    return result


def absolute(value):
    require(type(value) is str, "EXPLICIT_AUTHENTICATION_PATH_REQUIRED")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value,
            "EXPLICIT_AUTHENTICATION_PATH_REQUIRED")
    return path


def binding(value):
    """Validate a public binding without following or opening its path."""
    require(type(value) is dict and set(value) == {"path", "sha256"} and hashed(value["sha256"]),
            "EXPLICIT_AUTHENTICATION_BINDING_REQUIRED")
    absolute(value["path"])
    return copy.deepcopy(value)


def key_mandates(keys, roles, maximum):
    require(type(keys) is list and 1 <= len(keys) <= maximum, "EXACT_LOCAL_TRUST_POLICY_REQUIRED")
    seen = set()
    for key in keys:
        require(type(key) is dict and set(key) == KEY_FIELDS and identity(key["keyRef"])
                and identity(key["issuerRef"]) and key["keyRef"] not in seen
                and type(key["roles"]) is list and 1 <= len(key["roles"]) <= len(roles)
                and all(type(role) is str and role in roles for role in key["roles"])
                and len(set(key["roles"])) == len(key["roles"])
                and hashed(key["publicKey"])
                and type(key["notBefore"]) is int and type(key["expiresAt"]) is int
                and 0 <= key["notBefore"] < key["expiresAt"]
                and key["state"] in ("ACTIVE", "REVOKED"), "EXACT_LOCAL_KEY_MANDATE_REQUIRED")
        seen.add(key["keyRef"])


def policy(raw, installation, entity, now=None):
    """Validate syntax and scope; the verifier enforces the selected key's time."""
    value = decode(raw)
    require(set(value) == {"schema", "installationRef", "entityRef", "basePolicy", "authorityProfile", "keys"}
            and value["schema"] == POLICY_SCHEMA and identity(installation) and identity(entity)
            and (value["installationRef"], value["entityRef"]) == (installation, entity),
            "EXACT_B1B2_TRUST_POLICY_REQUIRED")
    binding(value["basePolicy"])
    binding(value["authorityProfile"])
    key_mandates(value["keys"], B1B2_ROLES, 8)
    return value


def base_policy(raw, installation, entity):
    """Read-only validation of the existing schema; its role set is unchanged."""
    value = decode(raw)
    require(set(value) == {"schema", "installationRef", "entityRef", "keys"}
            and value["schema"] == "ouf.semantic-deployment-trust-policy.v1"
            and identity(installation) and identity(entity)
            and (value["installationRef"], value["entityRef"]) == (installation, entity),
            "EXACT_BASE_TRUST_POLICY_REQUIRED")
    key_mandates(value["keys"], BASE_ROLES, 32)
    return value


def signing_bytes(raw, header):
    require(type(raw) is bytes and 0 < len(raw) <= 131072, "BOUNDED_SIGNED_PAYLOAD_REQUIRED")
    require(type(header) is dict and set(header) == HEADER_FIELDS, "EXACT_SIGNATURE_HEADER_REQUIRED")
    require(header["schema"] == SIGNATURE_SCHEMA and header["algorithm"] == "Ed25519"
            and type(header["role"]) is str and header["role"] in B1B2_ROLES
            and all(identity(header[key]) for key in ("keyRef", "issuerRef", "installationRef", "entityRef"))
            and header["payloadHash"] == hashlib.sha256(raw).hexdigest(), "EXACT_SIGNING_FRAME_SCOPE_REQUIRED")
    encoded = canonical(header)
    return DOMAIN + len(encoded).to_bytes(4, "big") + encoded + len(raw).to_bytes(4, "big") + raw


def attributes(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                                               "st_size", "st_mtime_ns", "st_ctime_ns"))


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "TRUSTED_AUTHENTICATION_ANCESTOR_REQUIRED")
    return info


def ancestors(path):
    absolute(str(path))
    for parent in path.parents:
        directory(parent)


def public_bytes(path, limit=65536):
    """Root 0600 custody for public policy, not a private-key reader."""
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= limit, "PRIVATE_AUTHENTICATION_INPUT_REQUIRED")
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and attributes(before) == attributes(os.fstat(fd))
                == attributes(path.lstat()), "AUTHENTICATION_INPUT_DRIFT")
        return raw
    finally:
        os.close(fd)


class VerificationBudget:
    """One monotonic deadline for the complete native verification operation."""

    def __init__(self, seconds, deadline=None, monotonic=time.monotonic):
        require(type(seconds) is int and 1 <= seconds <= 18, "BOUNDED_AUTHENTICATION_BUDGET_REQUIRED")
        self.monotonic = monotonic
        now = monotonic()
        require(deadline is None or type(deadline) in (int, float) and now < deadline <= now + seconds,
                "EXACT_AUTHENTICATION_DEADLINE_REQUIRED")
        self.deadline = now + seconds if deadline is None else deadline

    def remaining(self, maximum=2):
        left = self.deadline - self.monotonic()
        require(left > 0, "AUTHENTICATION_DEADLINE_MISSED")
        return min(maximum, left)

    def check(self):
        self.remaining()


class B1B2Authenticator:
    def __init__(self, policy_binding, openssl_binding, clock=time.time, budget=None):
        self.policy_binding = binding(policy_binding)
        require(type(openssl_binding) is dict and set(openssl_binding) == {"path", "sha256", "version"}
                and type(openssl_binding["version"]) is str
                and re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+[a-z]?", openssl_binding["version"]),
                "EXACT_OPENSSL_VERSION_BINDING_REQUIRED")
        self.openssl_binding = {**binding({key: openssl_binding[key] for key in ("path", "sha256")}),
                                "version": openssl_binding["version"]}
        ancestors(Path(self.policy_binding["path"]))
        ancestors(Path(self.openssl_binding["path"]))
        self.clock = clock
        self.budget = budget if budget is not None else VerificationBudget(18)
        require(callable(getattr(self.budget, "check", None)) and callable(getattr(self.budget, "remaining", None)),
                "EXPLICIT_AUTHENTICATION_BUDGET_REQUIRED")

    def check_budget(self):
        self.budget.check()

    def timeout(self):
        return self.budget.remaining()

    def read_policy(self):
        self.check_budget()
        raw = public_bytes(Path(self.policy_binding["path"]))
        require(hashlib.sha256(raw).hexdigest() == self.policy_binding["sha256"],
                "LOCAL_TRUST_POLICY_REVOKED_OR_CHANGED")
        self.check_budget()
        return raw

    def executable(self):
        self.check_budget()
        path = Path(self.openssl_binding["path"])
        ancestors(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                    and before.st_mode & 0o111 and before.st_size <= 64000000,
                    "TRUSTED_AUTHENTICATION_EXECUTABLE_REQUIRED")
            hasher, total = hashlib.sha256(), 0
            while True:
                self.check_budget()
                raw = os.read(fd, 65536)
                if not raw:
                    break
                total += len(raw)
                require(total <= 64000000, "AUTHENTICATION_EXECUTABLE_UNBOUNDED")
                hasher.update(raw)
            require(hasher.hexdigest() == self.openssl_binding["sha256"]
                    and attributes(before) == attributes(os.fstat(fd)) == attributes(path.lstat()),
                    "AUTHENTICATION_EXECUTABLE_DRIFT")
        finally:
            os.close(fd)
        return str(path)

    def verify(self, payload, public_key, signature):
        executable = self.executable()
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run([executable, "version"], stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=subprocess.DEVNULL, timeout=self.timeout(),
                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
            except (OSError, subprocess.TimeoutExpired):
                raise AuthorityDenied("DETACHED_VERIFICATION_UNPROVEN") from None
            output.seek(0)
            raw = output.read(257)
        version = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", raw)
        require(result.returncode == 0 and len(raw) <= 256 and version is not None
                and version.group(1).decode("ascii") == self.openssl_binding["version"],
                "DETACHED_OPENSSL_VERSION_UNPROVEN")
        with tempfile.TemporaryDirectory(prefix="ouf-b1b2-verification-") as temp:
            paths = []
            for name, data in zip(("public.der", "signature.bin", "frame.bin"),
                                  (DER_PREFIX + public_key, signature, payload)):
                path = Path(temp) / name
                path.write_bytes(data)
                path.chmod(0o600)
                paths.append(str(path))
            try:
                result = subprocess.run([executable, "pkeyutl", "-verify", "-pubin", "-rawin", "-keyform", "DER",
                                         "-inkey", paths[0], "-sigfile", paths[1], "-in", paths[2]],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        timeout=self.timeout(),
                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
            except (OSError, subprocess.TimeoutExpired):
                raise AuthorityDenied("DETACHED_VERIFICATION_UNPROVEN") from None
        self.executable()
        self.check_budget()
        require(result.returncode == 0, "DETACHED_SIGNATURE_INVALID")

    def verify_b1b2_detached(self, raw, signature_raw, role, issuer, installation, entity):
        require(type(raw) is bytes and 0 < len(raw) <= 131072 and type(role) is str and role in B1B2_ROLES
                and all(identity(value) for value in (issuer, installation, entity)), "EXACT_AUTHENTICATION_SCOPE_REQUIRED")
        self.check_budget()
        now = self.clock()
        policy_raw = self.read_policy()
        configured = policy(policy_raw, installation, entity, now)
        record = decode(signature_raw, 4096)
        require(set(record) == HEADER_FIELDS | {"signature"} and record["schema"] == SIGNATURE_SCHEMA
                and record["algorithm"] == "Ed25519" and identity(record["keyRef"])
                and (record["role"], record["issuerRef"], record["installationRef"], record["entityRef"], record["payloadHash"])
                == (role, issuer, installation, entity, hashlib.sha256(raw).hexdigest())
                and type(record["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}", record["signature"]),
                "EXACT_DETACHED_SIGNATURE_REQUIRED")
        keys = [key for key in configured["keys"] if key["keyRef"] == record["keyRef"] and key["issuerRef"] == issuer
                and role in key["roles"] and key["state"] == "ACTIVE" and key["notBefore"] <= now < key["expiresAt"]]
        require(len(keys) == 1, "ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED")
        header = {key: value for key, value in record.items() if key != "signature"}
        self.verify(signing_bytes(raw, header), bytes.fromhex(keys[0]["publicKey"]), bytes.fromhex(record["signature"]))
        finished = self.clock()
        require(finished >= now and keys[0]["notBefore"] <= finished < keys[0]["expiresAt"],
                "LOCAL_MANDATE_EXPIRED_OR_CLOCK_REGRESSED")
        require(self.read_policy() == policy_raw, "AUTHENTICATION_REVOKED_DURING_VERIFICATION")
        self.check_budget()
        return True


def verify_b1b2_detached(raw, signature_raw, role, issuer, installation, entity, *, policy_binding,
                         openssl_binding, clock=time.time, budget=None):
    return B1B2Authenticator(policy_binding, openssl_binding, clock, budget).verify_b1b2_detached(
        raw, signature_raw, role, issuer, installation, entity)
