"""Acceptance v5.1 (task-29a): ledger-based signing authority and verification.

The installer key's ARTIFACT_ACCEPTANCE mandate is read from the B1/B2 anchor
plus the mandate ledger (D-028), so issuance keeps working after the anchor's
generation-0 window. mandates.py is compiled from verified bytes, never
imported by path. The existing B1 issuer, signer and verifier stay unchanged.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import time
import types

from tools.semantic_b1b2_authority import authority as A
from tools.semantic_b1_acceptance import acceptance as B

require = A.require
ROLE = "ARTIFACT_ACCEPTANCE"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}


def load_mandates(raw, expected_sha256, path):
    """Compile exactly the checked mandates.py bytes into a private module."""
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == expected_sha256, "MANDATES_MODULE_DRIFT")
    module = types.ModuleType("ouf_bound_authority_mandates_acceptance_v51")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def mandate_at(M, ledger, key_ref, issuer, at):
    """The installer mandate in force at `at` (D-029 semantics), ACTIVE for the role."""
    try:
        mandate = ledger.at(key_ref, at)
        revoked = ledger.ever_revoked(key_ref)
    except M.MandateDenied as error:
        raise A.AuthorityDenied(str(error)) from None
    require(not revoked and mandate["state"] == "ACTIVE" and ROLE in mandate["roles"]
            and mandate["issuerRef"] == issuer and mandate["notBefore"] <= at < mandate["expiresAt"],
            "EXACT_ACCEPTANCE_MANDATE_REQUIRED")
    return mandate


def current_mandate(M, ledger, key_ref, issuer, now):
    try:
        ledger.refresh(now)
        mandate = ledger.current(key_ref, ROLE, now)
    except M.MandateDenied as error:
        raise A.AuthorityDenied(str(error)) from None
    require(mandate["issuerRef"] == issuer, "EXACT_ACCEPTANCE_MANDATE_REQUIRED")
    return mandate


class LedgerSigner:
    """Sign one acceptance with the existing installer key; one key read, verified at once."""

    def __init__(self, M, key_binding, key_ref, ledger, authenticator, scope, progress, clock=time.time):
        self.M, self.key, self.key_ref = M, A.binding(key_binding), key_ref
        self.ledger, self.authenticator, self.clock = ledger, authenticator, clock
        require(set(scope) == {"issuerRef", "installationRef", "entityRef"} and all(A.identity(v) for v in scope.values()),
                "EXPLICIT_SIGNING_SCOPE_REQUIRED")
        self.scope, self.progress = dict(scope), progress

    def key_hash(self):
        raw = A.public_bytes(Path(self.key["path"]), 4096)
        self.progress["privateKeysRead"] = 1
        return hashlib.sha256(raw).hexdigest()

    def native(self, argv, limit):
        executable = self.authenticator.executable()
        try:
            result = subprocess.run([executable, *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=self.authenticator.timeout(), env=ENV)
        except (OSError, subprocess.TimeoutExpired):
            raise A.AuthorityDenied("EXISTING_KEY_SIGNING_UNPROVEN") from None
        require(result.returncode == 0 and len(result.stdout) <= limit, "EXISTING_KEY_SIGNING_UNPROVEN")
        self.authenticator.executable()
        return result.stdout

    def sign(self, raw):
        started = self.clock()
        mandate = current_mandate(self.M, self.ledger, self.key_ref, self.scope["issuerRef"], started)
        snapshot = self.ledger.snapshot()
        version = self.native(["version"], 256)
        match = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", version)
        require(match is not None and match[1].decode() == self.authenticator.openssl_binding["version"],
                "DETACHED_OPENSSL_VERSION_UNPROVEN")
        self.progress["phase"] = "READ_INSTALLER_KEY"
        require(self.key_hash() == self.key["sha256"], "EXISTING_SIGNING_KEY_DRIFT")
        public = self.native(["pkey", "-in", self.key["path"], "-pubout", "-outform", "DER"], 44)
        require(public == A.DER_PREFIX + bytes.fromhex(mandate["publicKey"]), "SIGNING_KEY_PUBLIC_MANDATE_DRIFT")
        header = {"schema": self.M.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": self.key_ref, "role": ROLE,
                  **self.scope, "payloadHash": hashlib.sha256(raw).hexdigest()}
        frame = self.M.signing_bytes(raw, header)
        with tempfile.TemporaryDirectory(prefix="ouf-acceptance-v51-signing-") as directory:
            path = Path(directory) / "frame.bin"
            path.write_bytes(frame)
            path.chmod(0o600)
            self.progress.update(phase="SIGNING", signingAttempted=True, signaturesIssued=None)
            signature = self.native(["pkeyutl", "-sign", "-rawin", "-inkey", self.key["path"], "-in", str(path)], 64)
            self.progress.update(phase="SIGNATURE_RETURNED", signaturesIssued=1)
        require(len(signature) == 64, "EXACT_ED25519_SIGNATURE_REQUIRED")
        require(self.key_hash() == self.key["sha256"], "SIGNING_KEY_CHANGED_DURING_ISSUANCE")
        envelope = self.M.canonical({**header, "signature": signature.hex()}) + b"\n"
        self.progress["phase"] = "VERIFY_SIGNATURE"
        try:
            verified = self.authenticator.verify_b1b2_detached(raw, envelope, ROLE, self.scope["issuerRef"],
                                                               self.scope["installationRef"], self.scope["entityRef"])
        except self.M.MandateDenied as error:
            raise A.AuthorityDenied(str(error)) from None
        require(verified is True, "ISSUED_SIGNATURE_VERIFICATION_REQUIRED")
        finished = self.clock()
        require(finished >= started and current_mandate(self.M, self.ledger, self.key_ref, self.scope["issuerRef"],
                                                        finished) == mandate
                and self.ledger.snapshot() == snapshot, "SIGNING_MANDATE_CHANGED_OR_EXPIRED")
        return envelope


def verify_acceptance(M, manifest_raw, signature_raw, *, expected, authenticator):
    """B.verify_acceptance semantics with the ledger-backed MandateAuthenticator."""
    manifest = B.decode_manifest(manifest_raw)
    pins = B.validate_expected(expected)
    require(isinstance(authenticator, M.MandateAuthenticator), "ACCEPTANCE_AUTHENTICATOR_REQUIRED")
    require(manifest["trustPolicy"] == pins["trustPolicy"] == authenticator.anchor_binding,
            "ACCEPTANCE_TRUST_POLICY_MISMATCH")
    try:
        verified = authenticator.verify_b1b2_detached(manifest_raw, signature_raw, ROLE, pins["issuerRef"],
                                                      manifest["installationRef"], manifest["entityRef"])
    except M.MandateDenied as error:
        raise A.AuthorityDenied(str(error)) from None
    require(verified is True, "ACCEPTANCE_SIGNATURE_UNPROVEN")
    for field, code in (("installationRef", "ACCEPTANCE_INSTALLATION_MISMATCH"),
                        ("entityRef", "ACCEPTANCE_ENTITY_MISMATCH")):
        require(manifest[field] == pins[field], code)
    require(manifest["profile"]["sha256"] == pins["profileSha256"], "ACCEPTANCE_PROFILE_MISMATCH")
    require(manifest["preparationA"]["planSha256"] == pins["preparationA"]["planSha256"], "ACCEPTANCE_A_PLAN_MISMATCH")
    for field, label in (("manifest", "MANIFEST"), ("result", "RESULT"),
                         ("semanticPeer", "SEMANTIC_PEER"), ("successors", "SUCCESSORS")):
        require(manifest["preparationA"]["files"][field]["sha256"] == pins["preparationA"]["files"][field],
                "ACCEPTANCE_A_" + label + "_MISMATCH")
    for role in B.ROLES:
        require(manifest["creation"]["roles"][role]["transactionRef"] == pins["transactions"][role],
                "ACCEPTANCE_TRANSACTION_MISMATCH")
        require(manifest["roles"][role]["containerId"] == pins["roles"][role]["containerId"], "ACCEPTANCE_CID_MISMATCH")
        require(manifest["roles"][role]["imageId"] == pins["roles"][role]["imageId"], "ACCEPTANCE_IMAGE_MISMATCH")
    require(manifest["creation"]["recreation"] == pins["recreation"], "ACCEPTANCE_RECREATION_MISMATCH")
    require(manifest["generation"] >= pins["minimumGeneration"], "ACCEPTANCE_GENERATION_MISMATCH")
    return {"payloadSha256": hashlib.sha256(manifest_raw).hexdigest(), "manifest": manifest}
