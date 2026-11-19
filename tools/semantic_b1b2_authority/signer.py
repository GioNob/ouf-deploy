"""Issue one B1/B2 acceptance using an existing installer Ed25519 key.

The caller owns authorization/publication. No provisioning or private-key copy.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from . import authority as A


class ExistingB1B2Ed25519Signer:
    def __init__(self, key_binding, mandate, verifier, scope, progress):
        self.key = A.binding(key_binding)  # Syntax only, including in constructor.
        self.mandate, self.verifier = mandate.copy(), verifier
        A.require(set(scope) == {"issuerRef", "installationRef", "entityRef"}
                  and all(A.identity(v) for v in scope.values()), "EXPLICIT_SIGNING_SCOPE_REQUIRED")
        self.scope, self.progress = scope.copy(), progress

    def key_hash(self):
        raw = A.public_bytes(Path(self.key["path"]), 4096)
        self.progress["privateKeysRead"] = 1
        return hashlib.sha256(raw).hexdigest()

    def native(self, argv, limit):
        executable = self.verifier.executable()
        try:
            result = subprocess.run([executable, *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=self.verifier.timeout(),
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
        except (OSError, subprocess.TimeoutExpired):
            raise A.AuthorityDenied("EXISTING_KEY_SIGNING_UNPROVEN") from None
        raw = result.stdout
        A.require(result.returncode == 0 and len(raw) <= limit, "EXISTING_KEY_SIGNING_UNPROVEN")
        self.verifier.executable()
        return raw

    def sign(self, raw):
        started = self.verifier.clock()
        policy_raw = self.verifier.read_policy()
        configured = A.policy(policy_raw, self.scope["installationRef"], self.scope["entityRef"])
        A.require(self.mandate in configured["keys"] and self.mandate["state"] == "ACTIVE"
                  and "ARTIFACT_ACCEPTANCE" in self.mandate["roles"]
                  and self.mandate["issuerRef"] == self.scope["issuerRef"]
                  and self.mandate["notBefore"] <= started < self.mandate["expiresAt"],
                  "EXPLICIT_SIGNING_ROLE_MANDATE_REQUIRED")
        # Validate the version before any key access, with the same pinned binary.
        version = self.native(["version"], 256)
        match = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", version)
        A.require(match is not None and match[1].decode() == self.verifier.openssl_binding["version"],
                  "DETACHED_OPENSSL_VERSION_UNPROVEN")
        self.progress["phase"] = "READ_INSTALLER_KEY"
        A.require(self.key_hash() == self.key["sha256"], "EXISTING_SIGNING_KEY_DRIFT")
        public = self.native(["pkey", "-in", self.key["path"], "-pubout", "-outform", "DER"], 44)
        A.require(public == A.DER_PREFIX + bytes.fromhex(self.mandate["publicKey"]),
                  "SIGNING_KEY_PUBLIC_MANDATE_DRIFT")
        header = {"schema": A.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": self.mandate["keyRef"],
                  "role": "ARTIFACT_ACCEPTANCE", **self.scope, "payloadHash": hashlib.sha256(raw).hexdigest()}
        frame = A.signing_bytes(raw, header)
        with tempfile.TemporaryDirectory(prefix="ouf-b1b2-signing-") as directory:
            path = Path(directory) / "frame.bin"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(frame)
            finally:
                os.close(fd)
            self.progress.update(phase="SIGNING", signingAttempted=True, signaturesIssued=None)
            signature = self.native(["pkeyutl", "-sign", "-rawin", "-inkey", self.key["path"],
                                     "-in", str(path)], 64)
            self.progress.update(phase="SIGNATURE_RETURNED", signaturesIssued=1)
        A.require(len(signature) == 64, "EXACT_ED25519_SIGNATURE_REQUIRED")
        A.require(self.key_hash() == self.key["sha256"], "SIGNING_KEY_CHANGED_DURING_ISSUANCE")
        envelope = A.canonical({**header, "signature": signature.hex()}) + b"\n"
        self.progress["phase"] = "VERIFY_SIGNATURE"
        A.require(self.verifier.verify_b1b2_detached(raw, envelope, "ARTIFACT_ACCEPTANCE",
                  self.scope["issuerRef"], self.scope["installationRef"], self.scope["entityRef"]) is True,
                  "ISSUED_SIGNATURE_VERIFICATION_REQUIRED")
        finished = self.verifier.clock()
        A.require(finished >= started and self.mandate["notBefore"] <= finished < self.mandate["expiresAt"]
                  and self.verifier.read_policy() == policy_raw, "SIGNING_MANDATE_CHANGED_OR_EXPIRED")
        return envelope
