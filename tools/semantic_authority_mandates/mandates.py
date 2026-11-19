"""Stable trust anchors plus an append-only ledger of mandate generations (D-028).

Self-contained: standard library only, no import of semantic_b1b2_authority.
The anchor (an already published trust policy) carries keys, roles, issuers and
states; the ledger carries only time windows and revocations. Generation 0 is
the anchor itself. Public Ed25519 verification only: no signing and no
private-key reads. Every rejection is MandateDenied(<PUBLIC_CODE>).
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time


LEDGER_SCHEMA = "ouf.semantic-authority-mandate.v1"
B1B2_ANCHOR_SCHEMA = "ouf.semantic-provider-b1b2-trust-policy.v1"
BASE_ANCHOR_SCHEMA = "ouf.semantic-deployment-trust-policy.v1"
SIGNATURE_SCHEMA = "ouf.semantic-provider-b1b2-detached-signature.v1"
B1B2_ROLES = frozenset({"ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"})
BASE_ROLES = frozenset({"DEPLOYMENT_INTENT", "CREATION_ATTESTATION", "FINAL_DEPLOYMENT_APPROVAL"})
DOMAIN = b"OUF-SEMANTIC-PROVIDER-B1B2-EVIDENCE\x00V1\x00"
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
KEY_FIELDS = {"keyRef", "issuerRef", "roles", "publicKey", "notBefore", "expiresAt", "state"}
HEADER_FIELDS = {"schema", "algorithm", "keyRef", "role", "issuerRef", "installationRef", "entityRef", "payloadHash"}
GENERATION_FIELDS = {"schema", "generation", "anchor", "installationRef", "entityRef", "previousSha256",
                     "issuedAt", "issuerRef", "preconditions", "mandates"}
PRECONDITION_FLAGS = ("keyNotRevoked", "custodyIntact", "noOpenSecurityIncident")
MANDATE_FIELDS = {"keyRef", "notBefore", "expiresAt", "state"}
MAX_MANDATE_SECONDS = 7776000  # 90 days
MAX_GENERATIONS = 512
MAX_MANDATES = 32
GENERATION_LIMIT = 65536
GENERATION_NAME = re.compile(r"([1-9][0-9]{0,8})[.]json")
TEMPORARY_NAME = re.compile(r"[.]tmp-[1-9][0-9]{0,8}-[0-9a-f]{32}")
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}


class MandateDenied(RuntimeError):
    """Public reason code; never includes input contents or key material."""


def require(value, reason):
    if not value:
        raise MandateDenied(reason)


def identity(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None


def hashed(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def integer(value):
    return type(value) is int


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw, limit=65536):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "BOUNDED_MANDATE_RECORD_REQUIRED")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "DUPLICATE_MANDATE_KEY")
            result[key] = value
        return result

    try:
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise MandateDenied("INVALID_MANDATE_JSON") from None
    require(type(result) is dict, "EXACT_MANDATE_OBJECT_REQUIRED")
    return result


def absolute(value):
    require(type(value) is str, "EXPLICIT_MANDATE_PATH_REQUIRED")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value, "EXPLICIT_MANDATE_PATH_REQUIRED")
    return path


def binding(value):
    """Validate a public binding without following or opening its path."""
    require(type(value) is dict and set(value) == {"path", "sha256"} and hashed(value["sha256"]),
            "EXPLICIT_MANDATE_BINDING_REQUIRED")
    absolute(value["path"])
    return copy.deepcopy(value)


def attributes(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                                               "st_size", "st_mtime_ns", "st_ctime_ns"))


def directory(path):
    try:
        info = path.lstat()
    except OSError:
        raise MandateDenied("TRUSTED_MANDATE_ANCESTOR_REQUIRED") from None
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "TRUSTED_MANDATE_ANCESTOR_REQUIRED")
    return info


def ancestors(path):
    absolute(str(path))
    for parent in path.parents:
        directory(parent)


def private_bytes(path, limit=65536):
    """Root 0600 custody for public records; never a private-key reader."""
    ancestors(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise MandateDenied("PRIVATE_MANDATE_INPUT_REQUIRED") from None
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= limit, "PRIVATE_MANDATE_INPUT_REQUIRED")
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and attributes(before) == attributes(os.fstat(fd))
                == attributes(path.lstat()), "MANDATE_INPUT_DRIFT")
        return raw
    except OSError:
        raise MandateDenied("PRIVATE_MANDATE_INPUT_REQUIRED") from None
    finally:
        os.close(fd)


def ledger_directory(path):
    """Root:root 0700, not a symlink, with trusted ancestors."""
    ancestors(path)
    try:
        info = path.lstat()
    except OSError:
        raise MandateDenied("PRIVATE_MANDATE_LEDGER_REQUIRED") from None
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_MANDATE_LEDGER_REQUIRED")
    return info


# --- Anchors: syntax identical to the published trust policies -------------

def key_mandates(keys, roles, maximum):
    require(type(keys) is list and 1 <= len(keys) <= maximum, "EXACT_ANCHOR_TRUST_POLICY_REQUIRED")
    seen = set()
    for key in keys:
        require(type(key) is dict and set(key) == KEY_FIELDS and identity(key["keyRef"])
                and identity(key["issuerRef"]) and key["keyRef"] not in seen
                and type(key["roles"]) is list and 1 <= len(key["roles"]) <= len(roles)
                and all(type(role) is str and role in roles for role in key["roles"])
                and len(set(key["roles"])) == len(key["roles"])
                and hashed(key["publicKey"])
                and integer(key["notBefore"]) and integer(key["expiresAt"])
                and 0 <= key["notBefore"] < key["expiresAt"]
                and key["state"] in ("ACTIVE", "REVOKED"), "EXACT_ANCHOR_KEY_MANDATE_REQUIRED")
        seen.add(key["keyRef"])


def b1b2_anchor(raw, installation, entity):
    value = decode(raw)
    require(set(value) == {"schema", "installationRef", "entityRef", "basePolicy", "authorityProfile", "keys"}
            and value["schema"] == B1B2_ANCHOR_SCHEMA and identity(installation) and identity(entity)
            and (value["installationRef"], value["entityRef"]) == (installation, entity),
            "EXACT_B1B2_ANCHOR_REQUIRED")
    binding(value["basePolicy"])
    binding(value["authorityProfile"])
    key_mandates(value["keys"], B1B2_ROLES, 8)
    return value


def base_anchor(raw, installation, entity):
    value = decode(raw)
    require(set(value) == {"schema", "installationRef", "entityRef", "keys"}
            and value["schema"] == BASE_ANCHOR_SCHEMA and identity(installation) and identity(entity)
            and (value["installationRef"], value["entityRef"]) == (installation, entity),
            "EXACT_BASE_ANCHOR_REQUIRED")
    key_mandates(value["keys"], BASE_ROLES, 32)
    return value


def anchor(raw, installation, entity):
    """Recognise the anchor kind by schema, then validate it exactly."""
    schema = decode(raw).get("schema")
    if schema == B1B2_ANCHOR_SCHEMA:
        return b1b2_anchor(raw, installation, entity)
    require(schema == BASE_ANCHOR_SCHEMA, "KNOWN_MANDATE_ANCHOR_REQUIRED")
    return base_anchor(raw, installation, entity)


# --- Budget -----------------------------------------------------------------

class VerificationBudget:
    """One monotonic deadline for the complete native verification operation."""

    def __init__(self, seconds, deadline=None, monotonic=time.monotonic):
        require(type(seconds) is int and 1 <= seconds <= 18, "BOUNDED_MANDATE_BUDGET_REQUIRED")
        self.monotonic = monotonic
        now = monotonic()
        require(deadline is None or type(deadline) in (int, float) and now < deadline <= now + seconds,
                "EXACT_MANDATE_DEADLINE_REQUIRED")
        self.deadline = now + seconds if deadline is None else deadline

    def remaining(self, maximum=2):
        left = self.deadline - self.monotonic()
        require(left > 0, "MANDATE_DEADLINE_MISSED")
        return min(maximum, left)

    def check(self):
        self.remaining()


def checked_budget(budget):
    budget = budget if budget is not None else VerificationBudget(18)
    require(callable(getattr(budget, "check", None)) and callable(getattr(budget, "remaining", None)),
            "EXPLICIT_MANDATE_BUDGET_REQUIRED")
    return budget


def instant(value):
    require(type(value) in (int, float) and value == value and 0 <= value < 2 ** 62, "TRUSTED_MANDATE_CLOCK_REQUIRED")
    return value


# --- Ledger -----------------------------------------------------------------

def generation_record(raw, number, anchor_binding, anchored, previous):
    """Per-generation syntax; cross-generation invariants live in Chain."""
    value = decode(raw, GENERATION_LIMIT)
    require(canonical(value) == raw, "CANONICAL_MANDATE_GENERATION_REQUIRED")
    require(set(value) == GENERATION_FIELDS and value["schema"] == LEDGER_SCHEMA
            and integer(value["generation"]) and value["generation"] == number,
            "EXACT_MANDATE_GENERATION_REQUIRED")
    require(value["anchor"] == anchor_binding, "MANDATE_ANCHOR_MISMATCH")
    require((value["installationRef"], value["entityRef"]) == (anchored["installationRef"], anchored["entityRef"]),
            "MANDATE_SCOPE_MISMATCH")
    require(value["previousSha256"] == previous, "MANDATE_CHAIN_BROKEN")
    require(integer(value["issuedAt"]) and value["issuedAt"] >= 0 and identity(value["issuerRef"]),
            "EXACT_MANDATE_GENERATION_REQUIRED")
    checks = value["preconditions"]
    require(type(checks) is dict and set(checks) == {*PRECONDITION_FLAGS, "evidenceSha256"}
            and all(type(checks[flag]) is bool for flag in PRECONDITION_FLAGS)
            and hashed(checks["evidenceSha256"]), "EXACT_MANDATE_PRECONDITIONS_REQUIRED")
    entries = value["mandates"]
    require(type(entries) is list and 1 <= len(entries) <= MAX_MANDATES, "EXACT_MANDATE_LIST_REQUIRED")
    keys = {key["keyRef"] for key in anchored["keys"]}
    seen = set()
    for entry in entries:
        require(type(entry) is dict and set(entry) == MANDATE_FIELDS and identity(entry["keyRef"])
                and integer(entry["notBefore"]) and integer(entry["expiresAt"])
                and entry["state"] in ("ACTIVE", "REVOKED"), "EXACT_MANDATE_ENTRY_REQUIRED")
        require(entry["keyRef"] in keys, "MANDATE_KEY_NOT_IN_ANCHOR")
        require(entry["keyRef"] not in seen, "DUPLICATE_MANDATE_KEY_REF")
        seen.add(entry["keyRef"])
        require(0 <= entry["notBefore"] < entry["expiresAt"]
                and entry["expiresAt"] - entry["notBefore"] <= MAX_MANDATE_SECONDS, "MANDATE_WINDOW_UNBOUNDED")
        if entry["state"] == "ACTIVE":
            require(all(checks[flag] is True for flag in PRECONDITION_FLAGS), "MANDATE_PRECONDITIONS_UNMET")
    return value


class Chain:
    """Cross-generation invariants, starting from generation 0 (the anchor)."""

    def __init__(self, anchored):
        self.anchored = anchored
        self.state = {key["keyRef"]: {"notBefore": key["notBefore"], "state": key["state"]}
                      for key in anchored["keys"]}
        self.issued = None

    def add(self, value, now):
        require(value["issuedAt"] <= now, "MANDATE_ISSUED_IN_FUTURE")
        require(self.issued is None or value["issuedAt"] >= self.issued, "MANDATE_ISSUED_AT_REGRESSED")
        for entry in value["mandates"]:
            last = self.state[entry["keyRef"]]
            require(entry["notBefore"] >= last["notBefore"], "MANDATE_NOT_BEFORE_REGRESSED")
            require(last["state"] != "REVOKED" or entry["state"] == "REVOKED", "MANDATE_REVOCATION_REVERSED")
            self.state[entry["keyRef"]] = {"notBefore": entry["notBefore"], "state": entry["state"]}
        self.issued = value["issuedAt"]


class MandateLedger:
    """Read-only view of one anchor and its ledger. Queries use the last refresh."""

    def __init__(self, anchor_binding, ledger_root, installation, entity, clock=time.time, budget=None):
        self.anchor_binding = binding(anchor_binding)
        self.root = absolute(ledger_root)
        require(identity(installation) and identity(entity), "EXACT_MANDATE_SCOPE_REQUIRED")
        require(callable(clock), "TRUSTED_MANDATE_CLOCK_REQUIRED")
        self.installation, self.entity = installation, entity
        self.clock = clock
        self.budget = checked_budget(budget)
        self.loaded = None

    def read_anchor(self):
        self.budget.check()
        raw = private_bytes(Path(self.anchor_binding["path"]))
        require(hashlib.sha256(raw).hexdigest() == self.anchor_binding["sha256"], "MANDATE_ANCHOR_REVOKED_OR_CHANGED")
        return raw, anchor(raw, self.installation, self.entity)

    def inventory(self):
        """Exact contiguous names 1..M; any other entry, temporary or gap fails closed."""
        before = ledger_directory(self.root)
        try:
            names = os.listdir(self.root)
        except OSError:
            raise MandateDenied("PRIVATE_MANDATE_LEDGER_REQUIRED") from None
        require(len(names) <= MAX_GENERATIONS, "MANDATE_LEDGER_UNBOUNDED")
        numbers = []
        for name in names:
            match = GENERATION_NAME.fullmatch(name)
            if match is None:
                require(TEMPORARY_NAME.fullmatch(name) is None, "MANDATE_TEMPORARY_ENTRY_PRESENT")
                raise MandateDenied("UNKNOWN_MANDATE_ENTRY")
            numbers.append(int(match[1]))
        require(sorted(numbers) == list(range(1, len(numbers) + 1)), "MANDATE_GENERATION_GAP")
        require(attributes(before) == attributes(ledger_directory(self.root)), "MANDATE_LEDGER_DRIFT")
        return len(numbers)

    def read_generations(self, now):
        anchor_raw, anchored = self.read_anchor()
        count = self.inventory()
        chain, records, raws, previous = Chain(anchored), [], [], None
        for number in range(1, count + 1):
            self.budget.check()
            raw = private_bytes(self.root / (str(number) + ".json"), GENERATION_LIMIT)
            value = generation_record(raw, number, self.anchor_binding, anchored, previous)
            chain.add(value, now)
            records.append(value)
            raws.append(raw)
            previous = hashlib.sha256(raw).hexdigest()
        require(self.inventory() == count, "MANDATE_LEDGER_DRIFT")
        return anchor_raw, anchored, records, raws

    def refresh(self, now=None):
        now = instant(self.clock() if now is None else now)
        anchor_raw, anchored, records, raws = self.read_generations(now)
        self.loaded = {"anchorRaw": anchor_raw, "anchor": anchored, "records": records, "raws": raws,
                       "keys": {key["keyRef"]: key for key in anchored["keys"]}}
        return self

    def view(self):
        if self.loaded is None:
            self.refresh()
        return self.loaded

    def key(self, key_ref):
        keys = self.view()["keys"]
        require(type(key_ref) is str and key_ref in keys, "UNKNOWN_MANDATE_KEY")
        return keys[key_ref]

    def effective(self, key_ref, records):
        """Highest generation naming the key, else generation 0; anchor revocation always wins."""
        key = self.key(key_ref)
        result = {"keyRef": key_ref, "issuerRef": key["issuerRef"], "roles": list(key["roles"]),
                  "publicKey": key["publicKey"], "notBefore": key["notBefore"], "expiresAt": key["expiresAt"],
                  "state": key["state"], "generation": 0}
        for record in reversed(records):
            entries = [entry for entry in record["mandates"] if entry["keyRef"] == key_ref]
            if entries:
                result.update(notBefore=entries[0]["notBefore"], expiresAt=entries[0]["expiresAt"],
                              state=entries[0]["state"], generation=record["generation"])
                break
        if key["state"] == "REVOKED":
            result["state"] = "REVOKED"
        return result

    def current(self, key_ref, role, now=None):
        now = instant(self.clock() if now is None else now)
        mandate = self.effective(key_ref, self.view()["records"])
        require(type(role) is str and role in mandate["roles"] and mandate["state"] == "ACTIVE"
                and mandate["notBefore"] <= now < mandate["expiresAt"], "ACTIVE_MANDATE_REQUIRED")
        return mandate

    def at(self, key_ref, t):
        t = instant(t)
        records = [record for record in self.view()["records"] if record["issuedAt"] <= t]
        return self.effective(key_ref, records)

    def ever_revoked(self, key_ref):
        view = self.view()
        return self.key(key_ref)["state"] == "REVOKED" or any(
            entry["keyRef"] == key_ref and entry["state"] == "REVOKED"
            for record in view["records"] for entry in record["mandates"])

    def snapshot(self):
        view = self.view()
        return {"anchorSha256": hashlib.sha256(view["anchorRaw"]).hexdigest(), "generations": len(view["raws"]),
                "headSha256": hashlib.sha256(view["raws"][-1]).hexdigest() if view["raws"] else None}


# --- Detached B1/B2 verification under the current mandate -----------------

def signing_bytes(raw, header):
    require(type(raw) is bytes and 0 < len(raw) <= 131072, "BOUNDED_SIGNED_PAYLOAD_REQUIRED")
    require(type(header) is dict and set(header) == HEADER_FIELDS, "EXACT_SIGNATURE_HEADER_REQUIRED")
    require(header["schema"] == SIGNATURE_SCHEMA and header["algorithm"] == "Ed25519"
            and type(header["role"]) is str and header["role"] in B1B2_ROLES
            and all(identity(header[key]) for key in ("keyRef", "issuerRef", "installationRef", "entityRef"))
            and header["payloadHash"] == hashlib.sha256(raw).hexdigest(), "EXACT_SIGNING_FRAME_SCOPE_REQUIRED")
    encoded = canonical(header)
    return DOMAIN + len(encoded).to_bytes(4, "big") + encoded + len(raw).to_bytes(4, "big") + raw


class MandateAuthenticator:
    def __init__(self, anchor_binding, ledger_root, openssl_binding, clock=time.time, budget=None):
        self.anchor_binding = binding(anchor_binding)
        self.ledger_root = str(absolute(ledger_root))
        require(type(openssl_binding) is dict and set(openssl_binding) == {"path", "sha256", "version"}
                and type(openssl_binding["version"]) is str
                and re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+[a-z]?", openssl_binding["version"]),
                "EXACT_OPENSSL_VERSION_BINDING_REQUIRED")
        self.openssl_binding = {**binding({key: openssl_binding[key] for key in ("path", "sha256")}),
                                "version": openssl_binding["version"]}
        ancestors(Path(self.anchor_binding["path"]))
        ancestors(Path(self.openssl_binding["path"]))
        require(callable(clock), "TRUSTED_MANDATE_CLOCK_REQUIRED")
        self.clock = clock
        self.budget = checked_budget(budget)

    def timeout(self):
        return self.budget.remaining()

    def executable(self):
        self.budget.check()
        path = Path(self.openssl_binding["path"])
        ancestors(path)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise MandateDenied("TRUSTED_MANDATE_EXECUTABLE_REQUIRED") from None
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                    and before.st_mode & 0o111 and before.st_size <= 64000000,
                    "TRUSTED_MANDATE_EXECUTABLE_REQUIRED")
            hasher, total = hashlib.sha256(), 0
            while True:
                self.budget.check()
                raw = os.read(fd, 65536)
                if not raw:
                    break
                total += len(raw)
                require(total <= 64000000, "MANDATE_EXECUTABLE_UNBOUNDED")
                hasher.update(raw)
            require(hasher.hexdigest() == self.openssl_binding["sha256"]
                    and attributes(before) == attributes(os.fstat(fd)) == attributes(path.lstat()),
                    "MANDATE_EXECUTABLE_DRIFT")
        except OSError:
            raise MandateDenied("TRUSTED_MANDATE_EXECUTABLE_REQUIRED") from None
        finally:
            os.close(fd)
        return str(path)

    def verify(self, payload, public_key, signature):
        executable = self.executable()
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run([executable, "version"], stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=subprocess.DEVNULL, timeout=self.timeout(), env=ENV)
            except (OSError, subprocess.TimeoutExpired):
                raise MandateDenied("DETACHED_VERIFICATION_UNPROVEN") from None
            output.seek(0)
            raw = output.read(257)
        version = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", raw)
        require(result.returncode == 0 and len(raw) <= 256 and version is not None
                and version.group(1).decode("ascii") == self.openssl_binding["version"],
                "DETACHED_OPENSSL_VERSION_UNPROVEN")
        with tempfile.TemporaryDirectory(prefix="ouf-mandate-verification-") as temp:
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
                                        timeout=self.timeout(), env=ENV)
            except (OSError, subprocess.TimeoutExpired):
                raise MandateDenied("DETACHED_VERIFICATION_UNPROVEN") from None
        self.executable()
        self.budget.check()
        require(result.returncode == 0, "DETACHED_SIGNATURE_INVALID")

    def verify_b1b2_detached(self, raw, signature_raw, role, issuer, installation, entity):
        require(type(raw) is bytes and 0 < len(raw) <= 131072 and type(role) is str and role in B1B2_ROLES
                and all(identity(value) for value in (issuer, installation, entity)), "EXACT_AUTHENTICATION_SCOPE_REQUIRED")
        self.budget.check()
        now = instant(self.clock())
        ledger = MandateLedger(self.anchor_binding, self.ledger_root, installation, entity, self.clock, self.budget)
        ledger.refresh(now)
        require(ledger.view()["anchor"]["schema"] == B1B2_ANCHOR_SCHEMA, "EXACT_B1B2_ANCHOR_REQUIRED")
        snapshot = ledger.snapshot()
        record = decode(signature_raw, 4096)
        require(set(record) == HEADER_FIELDS | {"signature"} and record["schema"] == SIGNATURE_SCHEMA
                and record["algorithm"] == "Ed25519" and identity(record["keyRef"])
                and (record["role"], record["issuerRef"], record["installationRef"], record["entityRef"], record["payloadHash"])
                == (role, issuer, installation, entity, hashlib.sha256(raw).hexdigest())
                and type(record["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}", record["signature"]),
                "EXACT_DETACHED_SIGNATURE_REQUIRED")
        require(record["keyRef"] in ledger.view()["keys"], "ACTIVE_MANDATE_REQUIRED")
        mandate = ledger.current(record["keyRef"], role, now)
        require(mandate["issuerRef"] == issuer, "ACTIVE_MANDATE_REQUIRED")
        header = {key: value for key, value in record.items() if key != "signature"}
        self.verify(signing_bytes(raw, header), bytes.fromhex(mandate["publicKey"]), bytes.fromhex(record["signature"]))
        finished = instant(self.clock())
        require(finished >= now, "MANDATE_CLOCK_REGRESSED")
        ledger.refresh(finished)
        require(ledger.snapshot() == snapshot, "MANDATE_LEDGER_CHANGED_DURING_VERIFICATION")
        require(ledger.current(record["keyRef"], role, finished) == mandate, "ACTIVE_MANDATE_REQUIRED")
        self.budget.check()
        return True


# --- Exclusive append of generation M+1 (task-28 primitive) ---------------

def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_generation(ledger_root, anchor_binding, installation, entity, mandates, preconditions, issuer_ref,
                     evidence_sha256, clock=time.time):
    """Validate the whole ledger, then publish M+1 exclusively; never overwrite."""
    ledger = MandateLedger(anchor_binding, ledger_root, installation, entity, clock)
    now = instant(clock())
    ledger.refresh(now)
    view = ledger.view()
    require(type(preconditions) is dict and set(preconditions) == set(PRECONDITION_FLAGS)
            and all(type(preconditions[flag]) is bool for flag in PRECONDITION_FLAGS),
            "EXACT_MANDATE_PRECONDITIONS_REQUIRED")
    require(hashed(evidence_sha256), "EXACT_MANDATE_PRECONDITIONS_REQUIRED")
    require(identity(issuer_ref), "EXACT_MANDATE_GENERATION_REQUIRED")
    number = len(view["raws"]) + 1
    require(number <= MAX_GENERATIONS, "MANDATE_LEDGER_UNBOUNDED")
    value = {"schema": LEDGER_SCHEMA, "generation": number, "anchor": ledger.anchor_binding,
             "installationRef": view["anchor"]["installationRef"], "entityRef": view["anchor"]["entityRef"],
             "previousSha256": hashlib.sha256(view["raws"][-1]).hexdigest() if view["raws"] else None,
             "issuedAt": int(now), "issuerRef": issuer_ref,
             "preconditions": {**{flag: preconditions[flag] for flag in PRECONDITION_FLAGS},
                               "evidenceSha256": evidence_sha256},
             "mandates": copy.deepcopy(mandates)}
    try:
        raw = canonical(value)
    except (TypeError, ValueError):
        raise MandateDenied("EXACT_MANDATE_ENTRY_REQUIRED") from None
    require(len(raw) <= GENERATION_LIMIT, "BOUNDED_MANDATE_RECORD_REQUIRED")
    record = generation_record(raw, number, ledger.anchor_binding, view["anchor"], value["previousSha256"])
    chain = Chain(view["anchor"])
    for previous in view["records"]:
        chain.add(previous, now)
    chain.add(record, now)
    root = ledger.root
    final = root / (str(number) + ".json")
    temporary = root / (".tmp-" + str(number) + "-" + secrets.token_hex(16))
    ledger_directory(root)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise MandateDenied("MANDATE_TEMPORARY_UNAVAILABLE") from None
    try:
        try:
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            require(info.st_uid == info.st_gid == 0 and info.st_nlink == 1, "PRIVATE_MANDATE_TEMPORARY_REQUIRED")
            written = 0
            while written < len(raw):
                written += os.write(fd, raw[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, final, follow_symlinks=False)
        except FileExistsError:
            raise MandateDenied("MANDATE_GENERATION_EXISTS") from None
        except OSError:
            raise MandateDenied("MANDATE_GENERATION_PUBLICATION_FAILED") from None
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        except OSError:
            raise MandateDenied("MANDATE_TEMPORARY_REMOVAL_FAILED") from None
    fsync_directory(root)
    require(private_bytes(final, GENERATION_LIMIT) == raw, "MANDATE_GENERATION_READBACK_MISMATCH")
    ledger.refresh(instant(clock()))
    require(ledger.snapshot()["generations"] == number
            and ledger.snapshot()["headSha256"] == hashlib.sha256(raw).hexdigest(),
            "MANDATE_GENERATION_READBACK_MISMATCH")
    return {"generation": number, "sha256": hashlib.sha256(raw).hexdigest()}
