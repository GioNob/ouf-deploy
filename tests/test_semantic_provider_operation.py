"""Task-37: durable operation authorization and epoch reader. Native (root, CI sudo).

Ephemeral Ed25519 keys, real OpenSSL and the real mandate ledger. Fixtures under /run.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "tools/semantic_provider_operation"
NATIVE = os.environ.get("OUF_PROVIDER_OPERATION_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_PROVIDER_OPERATION_NATIVE requires Linux root:root; refusing to skip")
DAY = 86400
OK = {"keyNotRevoked": True, "custodyIntact": True, "noOpenSecurityIncident": True}
CID_A, CID_S = "a" * 64, "b" * 64
BOOT = "6dc087ac-1111-4222-8333-444455556666"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(NATIVE, "set OUF_PROVIDER_OPERATION_NATIVE=1 under native Linux root")
class Fixture(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(PACKAGE))
        self.addCleanup(sys.path.remove, str(PACKAGE))
        self.m = load(ROOT / "tools/semantic_authority_mandates/mandates.py", "mandates_fixture")
        self.a = load(PACKAGE / "authorization.py", "authorization")
        sys.modules["authorization"] = self.a
        self.addCleanup(sys.modules.pop, "authorization", None)
        self.e = load(PACKAGE / "epochs.py", "epochs_fixture")
        self.addCleanup(os.umask, os.umask(0o077))
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-operation-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.openssl = Path("/usr/bin/openssl").resolve(strict=True)
        self.ssl = {"path": str(self.openssl), "sha256": sha(self.openssl.read_bytes()),
                    "version": self.native("version").decode().split()[1]}
        self.keys, self.public = {}, {}
        for name in ("key-a", "key-b"):
            path = self.root / ("EPHEMERAL-" + name + ".pem")
            self.native("genpkey", "-algorithm", "Ed25519", "-out", str(path))
            path.chmod(0o600)
            self.keys[name] = path
            self.public[name] = self.native("pkey", "-in", str(path), "-pubout", "-outform", "DER")[12:].hex()
        anchor = {"schema": self.m.B1B2_ANCHOR_SCHEMA, "installationRef": "inst", "entityRef": "ent",
                  "basePolicy": {"path": str(self.root / "unopened-base.json"), "sha256": "c" * 64},
                  "authorityProfile": {"path": str(self.root / "unopened-profile.json"), "sha256": "d" * 64},
                  "keys": [self.key("key-a", ["RUNTIME_ARMING", "ARTIFACT_ACCEPTANCE"]),
                           self.key("key-b", ["ARTIFACT_ACCEPTANCE"])]}
        path = self.root / "anchor.json"
        self.write(path, self.m.canonical(anchor))
        self.anchor = {"path": str(path), "sha256": sha(path.read_bytes())}
        self.ledger_root = self.root / "ledger"
        self.ledger_root.mkdir(mode=0o700)
        self.chain = self.root / "operation"
        self.chain.mkdir(mode=0o700)
        self.now = 1500

    def key(self, name, roles):
        return {"keyRef": name, "issuerRef": "installer", "roles": roles, "publicKey": self.public[name],
                "notBefore": 1000, "expiresAt": 2000, "state": "ACTIVE"}

    def native(self, *args):
        return subprocess.run([str(self.openssl), *args], check=True, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout

    def write(self, path, raw, mode=0o600):
        Path(path).write_bytes(raw)
        os.chmod(path, mode)

    def clock(self):
        return self.now

    def payload(self, sequence=1, supersedes=None, issued=1400, decision="OPERATE", **changes):
        role = lambda cid, table: {"containerId": cid, "imageManifestDigest": "sha256:" + "1" * 64,
                                   "framePolicySha256": "2" * 64, "admissionConfigurationSha256": "3" * 64,
                                   "rootfsSealSha256": "4" * 64, "transportSha256": "5" * 64, "tableName": table}
        value = {"schema": self.a.SCHEMA, "installationRef": "inst", "entityRef": "ent", "issuerRef": "installer",
                 "sequence": sequence, "supersedes": supersedes, "issuedAt": issued, "decision": decision,
                 "runtimeConfigurationSha256": "6" * 64, "acceptanceSha256": "7" * 64,
                 "roles": {"adapter": role(CID_A, "ouf_b2_adapter"), "southbound": role(CID_S, "ouf_b2_south")},
                 "lease": {"ownerConfigurationSha256": "8" * 64, "leaseStructureHash": "9" * 64,
                           "dnsProfileSha256": "0" * 64}}
        value.update(changes)
        return self.a.canonical(value)

    def signature(self, raw, key="key-a", domain=None, **header_changes):
        header = {"schema": self.a.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": key, "role": "RUNTIME_ARMING",
                  "issuerRef": "installer", "installationRef": "inst", "entityRef": "ent", "payloadHash": sha(raw)}
        header.update(header_changes)
        frame = self.a.signing_bytes(raw, {**header, "role": "RUNTIME_ARMING"})
        if domain is not None:
            frame = domain + frame[len(self.a.DOMAIN):]
        frame_path = self.root / "frame.bin"
        self.write(frame_path, frame)
        signed = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys[key]), "-in", str(frame_path))
        return self.a.canonical({**header, "signature": signed.hex()})

    def put(self, number, raw, signature=None):
        self.write(self.chain / f"{number}.json", raw)
        self.write(self.chain / f"{number}.signature.json", signature or self.signature(raw))
        return raw

    def head(self):
        return self.a.head(self.m, self.anchor, str(self.ledger_root), self.ssl, str(self.chain),
                           "inst", "ent", "installer", self.clock)

    def denied(self, code, function=None, *args):
        with self.assertRaises(self.a.OperationDenied) as caught:
            (function or self.head)(*args)
        self.assertEqual(str(caught.exception), code)

    def append(self, mandates):
        return self.m.write_generation(str(self.ledger_root), self.anchor, "inst", "ent", mandates, OK,
                                       "renewal-job", "9" * 64, self.clock)


class AuthorizationTests(Fixture):
    def test_single_and_chain_head(self):
        first = self.put(1, self.payload())
        result = self.head()
        self.assertEqual((result["sequence"], result["decision"], result["sha256"]), (1, "OPERATE", sha(first)))
        self.put(2, self.payload(2, sha(first), 1450, "STOP"))
        self.assertEqual((self.head()["sequence"], self.head()["decision"]), (2, "STOP"))

    def test_durable_after_mandate_expiry_and_renewal_gap(self):
        self.put(1, self.payload(issued=1400))
        self.now = 5000  # anchor window ended at 2000, no renewal: still valid (D-029)
        self.assertEqual(self.head()["decision"], "OPERATE")

    def test_issued_outside_mandate_or_in_future(self):
        self.put(1, self.payload(issued=2500))
        self.now = 3000
        self.denied("OPERATION_MANDATE_AT_ISSUANCE_REQUIRED")
        self.put(1, self.payload(issued=1600))
        self.now = 1500
        self.denied("OPERATION_ISSUED_IN_FUTURE")

    def test_revocation_stops_operation(self):
        self.put(1, self.payload(issued=1400))
        self.append([{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900 + 60 * DAY, "state": "REVOKED"}])
        self.now = 1600
        self.denied("OPERATION_KEY_REVOKED")

    def test_renewed_mandate_covers_later_issuance(self):
        self.append([{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900 + 60 * DAY, "state": "ACTIVE"}])
        self.now = 3000
        self.put(1, self.payload(issued=2500))
        self.assertEqual(self.head()["sequence"], 1)

    def test_wrong_domain_role_key_and_tampering(self):
        raw = self.payload()
        self.put(1, raw, self.signature(raw, domain=self.m.DOMAIN))
        self.denied("OPERATION_SIGNATURE_INVALID")
        self.put(1, raw, self.signature(raw, key="key-b"))
        self.denied("OPERATION_MANDATE_AT_ISSUANCE_REQUIRED")
        self.put(1, raw, self.signature(self.payload(issued=1401)))
        self.denied("EXACT_OPERATION_SIGNATURE_REQUIRED")
        signature = json.loads(self.signature(raw))
        signature["signature"] = ("0" if signature["signature"][0] != "0" else "1") + signature["signature"][1:]
        self.put(1, raw, self.a.canonical(signature))
        self.denied("OPERATION_SIGNATURE_INVALID")

    def test_chain_rules(self):
        first = self.put(1, self.payload())
        self.put(2, self.payload(2, "f" * 64, 1450))
        self.denied("OPERATION_CHAIN_BROKEN")
        self.put(2, self.payload(2, sha(first), 1300))
        self.denied("OPERATION_CHAIN_TIME_REGRESSED")
        (self.chain / "2.signature.json").unlink()
        self.denied("CONTIGUOUS_OPERATION_CHAIN_REQUIRED")
        (self.chain / "2.json").unlink()
        self.write(self.chain / "notes.txt", b"x")
        self.denied("FOREIGN_OPERATION_ENTRY")
        (self.chain / "notes.txt").unlink()
        self.put(3, self.payload(3, sha(first), 1450))
        self.denied("CONTIGUOUS_OPERATION_CHAIN_REQUIRED")

    def test_schema_custody_and_canonical(self):
        self.denied("OPERATION_AUTHORIZATION_ABSENT")
        raw = self.put(1, self.payload())
        os.chmod(self.chain / "1.json", 0o644)
        self.denied("OPERATION_FILE_CUSTODY_REQUIRED")
        self.put(1, raw.replace(b",", b", ", 1))
        self.denied("CANONICAL_OPERATION_JSON_REQUIRED")
        self.put(1, self.payload(extra=True))
        self.denied("EXACT_OPERATION_AUTHORIZATION_REQUIRED")
        bad = json.loads(self.payload())
        bad["roles"]["southbound"]["containerId"] = CID_A
        self.put(1, self.a.canonical(bad))
        self.denied("DISTINCT_OPERATION_ROLES_REQUIRED")
        self.put(1, self.payload(installationRef="other"))
        self.denied("OPERATION_SCOPE_DRIFT")
        os.chmod(self.chain, 0o755)
        self.denied("OPERATION_DIRECTORY_CUSTODY_REQUIRED")


class EpochTests(Fixture):
    def journal(self, cid=CID_A, epoch=1, state="STARTED", **changes):
        value = {"schema": self.e.JOURNAL_SCHEMA, "containerId": cid, "epoch": epoch, "bootId": BOOT,
                 "authorizationSha256": "1" * 64, "configurationHash": "2" * 64, "state": state,
                 "runtimeRoot": "/run/docker/runtime-runc/moby", "bundleHash": "3" * 64, "driverHash": "4" * 64,
                 "generation": {"pid": os.getpid(), "startTicks": self.e.start_ticks(os.getpid())},
                 "openedAt": 1500, "failure": None}
        value.update(changes)
        return self.a.canonical(value)

    def publish(self, raw, cid=CID_A, epoch=1):
        base = self.root / "registry" / cid
        (base / "epochs" / str(epoch)).mkdir(parents=True, mode=0o700, exist_ok=True)
        for path in (self.root / "registry", base, base / "epochs", base / "epochs" / str(epoch)):
            os.chmod(path, 0o700)
        self.write(base / "epochs" / str(epoch) / "adapter.json", raw)
        self.write(base / "current", self.a.canonical({"epoch": epoch, "journalSha256": sha(raw)}))

    def test_current_and_live(self):
        self.assertIsNone(self.e.current(self.root / "registry", CID_A))
        self.publish(self.journal())
        value = self.e.current(self.root / "registry", CID_A)
        self.assertTrue(self.e.live(value, BOOT))
        self.assertFalse(self.e.live(value, "6dc087ac-1111-4222-8333-000000000000"))
        dead = json.loads(self.journal())
        dead["generation"]["startTicks"] += 1
        self.assertFalse(self.e.live(dead, BOOT))

    def test_drift_and_shape(self):
        self.publish(self.journal())
        self.write(self.root / "registry" / CID_A / "epochs/1/adapter.json", self.journal(openedAt=1501))
        self.denied("EPOCH_POINTER_JOURNAL_DRIFT", self.e.current, self.root / "registry", CID_A)
        self.publish(self.journal(generation=None))
        self.denied("STARTED_EPOCH_GENERATION_REQUIRED", self.e.current, self.root / "registry", CID_A)
        self.publish(self.journal(state="FAILED"))
        self.denied("EPOCH_FAILURE_INVALID", self.e.current, self.root / "registry", CID_A)
        self.publish(self.journal(state="FAILED", failure="RUNTIME_CREATE_DENIED"))
        self.assertEqual(self.e.current(self.root / "registry", CID_A)["state"], "FAILED")
        (self.root / "registry" / CID_A / "epochs/2").mkdir(mode=0o700)
        self.denied("EPOCH_BEYOND_POINTER", self.e.current, self.root / "registry", CID_A)

    def test_boot_id_shape(self):
        self.assertRegex(self.e.boot_id(), self.e.BOOT_ID.pattern)


if __name__ == "__main__":
    unittest.main()
