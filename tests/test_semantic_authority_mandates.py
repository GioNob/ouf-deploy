"""Mandate ledger (D-028): native custody, ephemeral Ed25519 keys, local OpenSSL.

Fixtures live under /run, are created per test and removed afterwards. No
network, no daemon, no real authority material.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/semantic_authority_mandates/mandates.py"
NATIVE = os.environ.get("OUF_MANDATES_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_MANDATES_NATIVE requires Linux root:root; refusing to skip")
DAY = 86400
EVIDENCE = "9" * 64
OK = {"keyNotRevoked": True, "custodyIntact": True, "noOpenSecurityIncident": True}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load():
    spec = importlib.util.spec_from_file_location("mandates_fixture", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(NATIVE, "set OUF_MANDATES_NATIVE=1 under native Linux root")
class Fixture(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.addCleanup(os.umask, os.umask(0o077))
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-mandates-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.openssl = Path("/usr/bin/openssl").resolve(strict=True)
        self.ssl = {"path": str(self.openssl), "sha256": sha(self.openssl.read_bytes()),
                    "version": self.native("version").decode().split()[1]}
        self.keys, self.public = {}, {}
        for name in ("key-a", "key-b", "key-r"):
            path = self.root / ("EPHEMERAL-" + name + ".pem")
            self.native("genpkey", "-algorithm", "Ed25519", "-out", str(path))
            path.chmod(0o600)
            self.keys[name] = path
            self.public[name] = self.native("pkey", "-in", str(path), "-pubout", "-outform", "DER")[12:].hex()
        self.anchor_value = {
            "schema": self.m.B1B2_ANCHOR_SCHEMA, "installationRef": "test-installation", "entityRef": "test-entity",
            "basePolicy": {"path": str(self.root / "unopened-base.json"), "sha256": "c" * 64},
            "authorityProfile": {"path": str(self.root / "unopened-profile.json"), "sha256": "d" * 64},
            "keys": [
                self.key("key-a", ["RUNTIME_ARMING", "ARTIFACT_ACCEPTANCE"]),
                self.key("key-b", ["ARTIFACT_ACCEPTANCE"]),
                self.key("key-r", ["RUNTIME_ARMING"], state="REVOKED")]}
        self.anchor_path = self.root / "anchor.json"
        self.write(self.anchor_path, self.m.canonical(self.anchor_value))
        self.anchor = self.pin(self.anchor_path)
        self.ledger_root = self.root / "ledger"
        self.ledger_root.mkdir(mode=0o700)
        self.now = 1500

    # --- helpers ----------------------------------------------------------

    def key(self, name, roles, state="ACTIVE", issuer="test-issuer"):
        return {"keyRef": name, "issuerRef": issuer, "roles": roles, "publicKey": self.public[name],
                "notBefore": 1000, "expiresAt": 2000, "state": state}

    def native(self, *args):
        return subprocess.run([str(self.openssl), *args], check=True, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)

    def pin(self, path):
        return {"path": str(path), "sha256": sha(path.read_bytes())}

    def clock(self):
        return self.now

    def ledger(self, anchor=None, installation="test-installation", entity="test-entity"):
        return self.m.MandateLedger(anchor or self.anchor, str(self.ledger_root), installation, entity, self.clock)

    def mandate(self, key="key-a", nb=1900, days=60, state="ACTIVE"):
        return {"keyRef": key, "notBefore": nb, "expiresAt": nb + days * DAY, "state": state}

    def append(self, mandates, preconditions=OK, issuer="renewal-job"):
        return self.m.write_generation(str(self.ledger_root), self.anchor, "test-installation", "test-entity",
                                       mandates, preconditions, issuer, EVIDENCE, self.clock)

    def generation(self, number, mandates, issued=None, preconditions=OK, **changes):
        """Hand-built record (for invalid cases), chained to the existing file N-1."""
        previous = None if number == 1 else sha((self.ledger_root / (str(number - 1) + ".json")).read_bytes())
        value = {"schema": self.m.LEDGER_SCHEMA, "generation": number, "anchor": self.anchor,
                 "installationRef": "test-installation", "entityRef": "test-entity", "previousSha256": previous,
                 "issuedAt": self.now if issued is None else issued, "issuerRef": "renewal-job",
                 "preconditions": {**preconditions, "evidenceSha256": EVIDENCE}, "mandates": mandates}
        value.update(changes)
        return value

    def put(self, number, value):
        raw = value if isinstance(value, bytes) else self.m.canonical(value)
        self.write(self.ledger_root / (str(number) + ".json"), raw)
        return raw

    def denied(self, code, function, *args, **kwargs):
        with self.assertRaises(self.m.MandateDenied) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), code)
        self.assertRegex(str(caught.exception), r"\A[A-Z0-9_]{1,80}\Z")

    def refused(self, code):
        self.denied(code, self.ledger().refresh)

    def sign(self, raw, key="key-a", role="RUNTIME_ARMING", issuer="test-issuer", wrong_domain=False):
        header = {"schema": self.m.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": key, "role": role,
                  "issuerRef": issuer, "installationRef": "test-installation", "entityRef": "test-entity",
                  "payloadHash": sha(raw)}
        frame = self.m.signing_bytes(raw, header)
        if wrong_domain:
            frame = b"OUF-DEPLOYMENT-EVIDENCE\0V1\0" + frame[len(self.m.DOMAIN):]
        frame_path = self.root / "frame.bin"
        self.write(frame_path, frame)
        signature = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys[key]), "-in", str(frame_path))
        return self.m.canonical({**header, "signature": signature.hex()})

    def authenticator(self, anchor=None):
        return self.m.MandateAuthenticator(anchor or self.anchor, str(self.ledger_root), self.ssl, self.clock)

    def verify(self, raw, signature, role="RUNTIME_ARMING", issuer="test-issuer", authenticator=None):
        return (authenticator or self.authenticator()).verify_b1b2_detached(
            raw, signature, role, issuer, "test-installation", "test-entity")


class LedgerTests(Fixture):
    def test_empty_ledger_is_generation_zero(self):
        ledger = self.ledger().refresh()
        current = ledger.current("key-a", "RUNTIME_ARMING")
        self.assertEqual((current["generation"], current["notBefore"], current["expiresAt"]), (0, 1000, 2000))
        self.assertEqual(ledger.snapshot(), {"anchorSha256": self.anchor["sha256"], "generations": 0,
                                             "headSha256": None})
        self.assertFalse(ledger.ever_revoked("key-a"))

    def test_valid_generations_one_to_m_and_latest_wins(self):
        results = []
        for step in range(3):
            self.now = 1500 + step * 10
            results.append(self.append([self.mandate(nb=1900 + step)]))
        self.assertEqual([r["generation"] for r in results], [1, 2, 3])
        for number, result in enumerate(results, 1):
            self.assertEqual(result["sha256"], sha((self.ledger_root / (str(number) + ".json")).read_bytes()))
        self.now = 1950
        ledger = self.ledger().refresh()
        current = ledger.current("key-a", "RUNTIME_ARMING")
        self.assertEqual((current["generation"], current["notBefore"]), (3, 1902))
        self.assertEqual(ledger.snapshot()["generations"], 3)
        self.assertEqual(ledger.snapshot()["headSha256"], results[-1]["sha256"])
        # A key not named by any generation keeps its generation-0 window.
        self.assertEqual(ledger.at("key-b", 1950)["generation"], 0)
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-b", "ARTIFACT_ACCEPTANCE")
        record = json.loads((self.ledger_root / "2.json").read_bytes())
        self.assertEqual(record["previousSha256"], results[0]["sha256"])
        self.assertEqual(record["preconditions"], {**OK, "evidenceSha256": EVIDENCE})

    def test_gap_foreign_temporary_and_bad_names(self):
        self.put(1, self.generation(1, [self.mandate()]))
        self.put(3, self.generation(1, [self.mandate()], generation=3))
        self.refused("MANDATE_GENERATION_GAP")
        (self.ledger_root / "3.json").unlink()
        (self.ledger_root / "1.json").rename(self.ledger_root / "2.json")
        self.refused("MANDATE_GENERATION_GAP")
        (self.ledger_root / "2.json").rename(self.ledger_root / "1.json")
        for name in ("01.json", "1.json.bak", "notes", "0.json", ".hidden"):
            self.write(self.ledger_root / name, b"{}")
            with self.subTest(name=name):
                self.refused("UNKNOWN_MANDATE_ENTRY")
            (self.ledger_root / name).unlink()
        (self.ledger_root / "sub").mkdir(mode=0o700)
        self.refused("UNKNOWN_MANDATE_ENTRY")
        (self.ledger_root / "sub").rmdir()
        self.write(self.ledger_root / (".tmp-2-" + "ab" * 16), b"{}")
        self.refused("MANDATE_TEMPORARY_ENTRY_PRESENT")

    def test_custody_symlink_mode_owner_and_links(self):
        raw = self.put(1, self.generation(1, [self.mandate()]))
        path, saved = self.ledger_root / "1.json", self.root / "saved.json"
        for defect in ("mode", "uid", "gid", "hardlink", "symlink", "directory"):
            if defect == "mode":
                path.chmod(0o640)
            elif defect in ("uid", "gid"):
                os.chown(path, int(defect == "uid"), int(defect == "gid"))
            elif defect == "hardlink":
                os.link(path, saved)
            elif defect == "symlink":
                path.rename(saved)
                path.symlink_to(saved)
            else:
                path.unlink()
                path.mkdir(mode=0o700)
            try:
                with self.subTest(defect=defect):
                    self.refused("PRIVATE_MANDATE_INPUT_REQUIRED")
            finally:
                if defect == "hardlink":
                    saved.unlink()
                if defect == "symlink":
                    path.unlink()
                    saved.rename(path)
                if defect == "directory":
                    path.rmdir()
                    self.write(path, raw)
                os.chown(path, 0, 0)
                path.chmod(0o600)
        self.ledger().refresh()
        for mode in (0o750, 0o755, 0o701):
            self.ledger_root.chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.refused("PRIVATE_MANDATE_LEDGER_REQUIRED")
        self.ledger_root.chmod(0o700)
        os.chown(self.ledger_root, 1, 0)
        self.refused("PRIVATE_MANDATE_LEDGER_REQUIRED")
        os.chown(self.ledger_root, 0, 0)
        moved = self.root / "real-ledger"
        self.ledger_root.rename(moved)
        self.ledger_root.symlink_to(moved)
        self.refused("PRIVATE_MANDATE_LEDGER_REQUIRED")
        self.ledger_root.unlink()
        moved.rename(self.ledger_root)
        self.root.chmod(0o777)
        self.refused("TRUSTED_MANDATE_ANCESTOR_REQUIRED")
        self.root.chmod(0o700)
        self.anchor_path.chmod(0o644)
        self.refused("PRIVATE_MANDATE_INPUT_REQUIRED")

    def test_non_canonical_and_duplicate_json(self):
        value = self.generation(1, [self.mandate()])
        for raw, code in ((json.dumps(value, sort_keys=True, indent=1).encode(), "CANONICAL_MANDATE_GENERATION_REQUIRED"),
                          (self.m.canonical(value) + b"\n", "CANONICAL_MANDATE_GENERATION_REQUIRED"),
                          (json.dumps(value, separators=(",", ":")).encode(), "CANONICAL_MANDATE_GENERATION_REQUIRED"),
                          (b'{"schema":"a","schema":"a"}', "DUPLICATE_MANDATE_KEY"),
                          (b"[1]", "EXACT_MANDATE_OBJECT_REQUIRED"),
                          (b'{"a":NaN}', "INVALID_MANDATE_JSON")):
            self.put(1, raw)
            with self.subTest(raw=raw[:40]):
                self.refused(code)

    def test_exact_fields_schema_and_types(self):
        good = self.generation(1, [self.mandate()])
        cases = [({"schema": "ouf.semantic-authority-mandate.v2"}, "EXACT_MANDATE_GENERATION_REQUIRED"),
                 ({"generation": 2}, "EXACT_MANDATE_GENERATION_REQUIRED"),
                 ({"generation": True}, "EXACT_MANDATE_GENERATION_REQUIRED"),
                 ({"extra": 1}, "EXACT_MANDATE_GENERATION_REQUIRED"),
                 ({"issuedAt": 1.5}, "EXACT_MANDATE_GENERATION_REQUIRED"),
                 ({"issuerRef": "bad/issuer"}, "EXACT_MANDATE_GENERATION_REQUIRED"),
                 ({"preconditions": {**OK}}, "EXACT_MANDATE_PRECONDITIONS_REQUIRED"),
                 ({"preconditions": {**OK, "custodyIntact": 1, "evidenceSha256": EVIDENCE}},
                  "EXACT_MANDATE_PRECONDITIONS_REQUIRED"),
                 ({"mandates": []}, "EXACT_MANDATE_LIST_REQUIRED"),
                 ({"mandates": [self.mandate(nb=1900 + i) | {"keyRef": "key-a"} for i in range(33)]},
                  "EXACT_MANDATE_LIST_REQUIRED"),
                 ({"mandates": [self.mandate() | {"state": "SUSPENDED"}]}, "EXACT_MANDATE_ENTRY_REQUIRED"),
                 ({"mandates": [self.mandate() | {"roles": ["RUNTIME_ARMING"]}]}, "EXACT_MANDATE_ENTRY_REQUIRED"),
                 ({"mandates": [self.mandate() | {"publicKey": "0" * 64}]}, "EXACT_MANDATE_ENTRY_REQUIRED"),
                 ({"mandates": [self.mandate() | {"notBefore": True}]}, "EXACT_MANDATE_ENTRY_REQUIRED")]
        for change, code in cases:
            self.put(1, good | change)
            with self.subTest(change=list(change)):
                self.refused(code)
        for missing in good:
            value = copy.deepcopy(good)
            del value[missing]
            self.put(1, value)
            with self.subTest(missing=missing), self.assertRaises(self.m.MandateDenied):
                self.ledger().refresh()

    def test_anchor_scope_and_chain(self):
        self.put(1, self.generation(1, [self.mandate()], anchor={**self.anchor, "sha256": "0" * 64}))
        self.refused("MANDATE_ANCHOR_MISMATCH")
        self.put(1, self.generation(1, [self.mandate()], anchor={**self.anchor, "path": str(self.root / "x.json")}))
        self.refused("MANDATE_ANCHOR_MISMATCH")
        self.put(1, self.generation(1, [self.mandate()], installationRef="other-installation"))
        self.refused("MANDATE_SCOPE_MISMATCH")
        self.put(1, self.generation(1, [self.mandate()], entityRef="other-entity"))
        self.refused("MANDATE_SCOPE_MISMATCH")
        self.put(1, self.generation(1, [self.mandate()], previousSha256="0" * 64))
        self.refused("MANDATE_CHAIN_BROKEN")
        self.put(1, self.generation(1, [self.mandate()]))
        self.put(2, self.generation(2, [self.mandate(nb=1901)], previousSha256="0" * 64))
        self.refused("MANDATE_CHAIN_BROKEN")
        self.put(2, self.generation(2, [self.mandate(nb=1901)], previousSha256=None))
        self.refused("MANDATE_CHAIN_BROKEN")
        self.put(2, self.generation(2, [self.mandate(nb=1901)]))
        self.ledger().refresh()
        # Rewriting generation 1 breaks the chain from generation 2.
        self.put(1, self.generation(1, [self.mandate(nb=1899)]))
        self.refused("MANDATE_CHAIN_BROKEN")
        # The caller's scope and anchor binding are authoritative.
        self.denied("EXACT_B1B2_ANCHOR_REQUIRED", self.ledger(installation="other-installation").refresh)
        self.denied("MANDATE_ANCHOR_REVOKED_OR_CHANGED", self.ledger(anchor={**self.anchor, "sha256": "0" * 64}).refresh)

    def test_window_not_before_and_issued_at(self):
        self.append([self.mandate(nb=1900, days=90)])
        self.put(2, self.generation(2, [{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900 + 90 * DAY + 1,
                                         "state": "ACTIVE"}]))
        self.refused("MANDATE_WINDOW_UNBOUNDED")
        self.put(2, self.generation(2, [{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900, "state": "ACTIVE"}]))
        self.refused("MANDATE_WINDOW_UNBOUNDED")
        self.put(2, self.generation(2, [self.mandate(nb=1899)]))
        self.refused("MANDATE_NOT_BEFORE_REGRESSED")
        (self.ledger_root / "2.json").unlink()
        (self.ledger_root / "1.json").unlink()
        self.put(1, self.generation(1, [self.mandate(nb=999)]))
        self.refused("MANDATE_NOT_BEFORE_REGRESSED")  # below generation 0
        self.put(1, self.generation(1, [self.mandate()], issued=self.now + 1))
        self.refused("MANDATE_ISSUED_IN_FUTURE")
        self.put(1, self.generation(1, [self.mandate()], issued=1400))
        self.put(2, self.generation(2, [self.mandate(nb=1901)], issued=1399))
        self.refused("MANDATE_ISSUED_AT_REGRESSED")
        self.put(2, self.generation(2, [self.mandate(nb=1901)], issued=1400))
        self.ledger().refresh()

    def test_active_requires_all_preconditions_and_anchor_keys(self):
        for flag in OK:
            self.put(1, self.generation(1, [self.mandate()], preconditions={**OK, flag: False}))
            with self.subTest(flag=flag):
                self.refused("MANDATE_PRECONDITIONS_UNMET")
            (self.ledger_root / "1.json").unlink()
            with self.subTest(flag=flag, writer=True):
                self.denied("MANDATE_PRECONDITIONS_UNMET", self.append, [self.mandate()], {**OK, flag: False})
            self.assertEqual(list(self.ledger_root.iterdir()), [])
        # Revocations need no preconditions.
        self.append([self.mandate("key-b", state="REVOKED")], {**OK, "custodyIntact": False})
        (self.ledger_root / "1.json").unlink()
        self.put(1, self.generation(1, [self.mandate("key-z")]))
        self.refused("MANDATE_KEY_NOT_IN_ANCHOR")
        self.put(1, self.generation(1, [self.mandate(), self.mandate(nb=1901)]))
        self.refused("DUPLICATE_MANDATE_KEY_REF")

    def test_revocation_anchor_ledger_and_reversal(self):
        ledger = self.ledger().refresh()
        self.assertTrue(ledger.ever_revoked("key-r"))
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-r", "RUNTIME_ARMING")
        self.put(1, self.generation(1, [self.mandate("key-r")]))
        self.refused("MANDATE_REVOCATION_REVERSED")
        (self.ledger_root / "1.json").unlink()
        self.append([self.mandate("key-a", state="REVOKED")])
        ledger = self.ledger().refresh()
        self.assertTrue(ledger.ever_revoked("key-a"))
        self.assertFalse(ledger.ever_revoked("key-b"))
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-a", "RUNTIME_ARMING")
        self.denied("MANDATE_REVOCATION_REVERSED", self.append, [self.mandate("key-a", nb=1901)])
        self.put(2, self.generation(2, [self.mandate("key-a", nb=1901)]))
        self.refused("MANDATE_REVOCATION_REVERSED")
        (self.ledger_root / "2.json").unlink()
        # Not naming the key later does not reinstate it; naming it REVOKED again is fine.
        self.append([self.mandate("key-b", nb=1901)])
        self.append([self.mandate("key-a", nb=1902, state="REVOKED")])
        ledger = self.ledger().refresh()
        self.assertEqual(ledger.current("key-b", "ARTIFACT_ACCEPTANCE", 1950)["generation"], 2)
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-a", "RUNTIME_ARMING", 1950)

    def test_historical_at(self):
        self.now = 1500
        self.append([self.mandate(nb=1900, days=60)])
        self.now = 1600
        self.append([self.mandate(nb=1950, days=90)])
        self.now = 1700
        self.append([self.mandate(state="REVOKED", nb=1960)])
        ledger = self.ledger().refresh()
        self.assertEqual((ledger.at("key-a", 0)["generation"], ledger.at("key-a", 0)["expiresAt"]), (0, 2000))
        self.assertEqual(ledger.at("key-a", 1499)["generation"], 0)
        self.assertEqual(ledger.at("key-a", 1500)["generation"], 1)
        self.assertEqual(ledger.at("key-a", 1650)["expiresAt"], 1950 + 90 * DAY)
        self.assertEqual(ledger.at("key-a", 1650)["state"], "ACTIVE")
        self.assertEqual(ledger.at("key-a", 1700)["state"], "REVOKED")
        self.assertEqual(ledger.at("key-r", 1650)["state"], "REVOKED")  # anchor revocation always wins
        self.denied("UNKNOWN_MANDATE_KEY", ledger.at, "key-z", 1650)
        self.denied("TRUSTED_MANDATE_CLOCK_REQUIRED", ledger.at, "key-a", -1)

    def test_role_must_be_granted_by_anchor(self):
        ledger = self.ledger().refresh()
        self.assertEqual(ledger.current("key-b", "ARTIFACT_ACCEPTANCE")["generation"], 0)
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-b", "RUNTIME_ARMING")
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-a", "DEPLOYMENT_INTENT")
        self.denied("UNKNOWN_MANDATE_KEY", ledger.current, "key-z", "RUNTIME_ARMING")

    def test_time_window_boundaries(self):
        ledger = self.ledger().refresh(1000)
        self.assertEqual(ledger.current("key-a", "RUNTIME_ARMING", 1000)["generation"], 0)
        self.assertEqual(ledger.current("key-a", "RUNTIME_ARMING", 1999)["generation"], 0)
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-a", "RUNTIME_ARMING", 999)
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-a", "RUNTIME_ARMING", 2000)

    def test_base_anchor(self):
        value = {"schema": self.m.BASE_ANCHOR_SCHEMA, "installationRef": "test-installation",
                 "entityRef": "test-entity",
                 "keys": [self.key("key-a", ["CREATION_ATTESTATION"]),
                          self.key("key-b", ["DEPLOYMENT_INTENT", "FINAL_DEPLOYMENT_APPROVAL"])]}
        path = self.root / "base.json"
        self.write(path, self.m.canonical(value))
        base = self.pin(path)
        ledger = self.ledger(anchor=base).refresh()
        self.assertEqual(ledger.current("key-a", "CREATION_ATTESTATION")["generation"], 0)
        self.denied("ACTIVE_MANDATE_REQUIRED", ledger.current, "key-a", "RUNTIME_ARMING")
        raw = b"payload"
        self.denied("EXACT_B1B2_ANCHOR_REQUIRED", self.verify, raw, self.sign(raw), authenticator=self.authenticator(base))
        value["keys"][0]["roles"] = ["RUNTIME_ARMING"]
        self.write(path, self.m.canonical(value))
        self.denied("EXACT_ANCHOR_KEY_MANDATE_REQUIRED", self.ledger(anchor=self.pin(path)).refresh)
        self.write(path, self.m.canonical(value | {"schema": "ouf.unknown-policy.v1"}))
        self.denied("KNOWN_MANDATE_ANCHOR_REQUIRED", self.ledger(anchor=self.pin(path)).refresh)

    def test_write_generation_concurrency_readback_and_no_overwrite(self):
        first = self.append([self.mandate()])
        competitor = self.m.canonical(self.generation(2, [self.mandate(nb=1901)]))
        real_link = os.link

        def racing(source, target, **kwargs):
            # Another writer publishes M+1 between validation and link.
            self.write(Path(target), competitor)
            return real_link(source, target, **kwargs)

        with patch.object(self.m.os, "link", side_effect=racing):
            self.denied("MANDATE_GENERATION_EXISTS", self.append, [self.mandate(nb=1902)])
        self.assertEqual((self.ledger_root / "2.json").read_bytes(), competitor)
        self.assertEqual(sorted(p.name for p in self.ledger_root.iterdir()), ["1.json", "2.json"])
        self.assertEqual(self.ledger().refresh().snapshot()["headSha256"], sha(competitor))
        self.assertEqual(first["sha256"], sha((self.ledger_root / "1.json").read_bytes()))
        # Readback: the published bytes are exactly the canonical record, root 0600, single link.
        third = self.append([self.mandate(nb=1903)])
        path = self.ledger_root / "3.json"
        info = path.stat()
        self.assertEqual((third["generation"], third["sha256"]), (3, sha(path.read_bytes())))
        self.assertEqual((info.st_mode & 0o777, info.st_uid, info.st_gid, info.st_nlink), (0o600, 0, 0, 1))
        self.assertEqual(path.read_bytes(), self.m.canonical(json.loads(path.read_bytes())))

    def test_write_generation_rejects_invalid_and_writes_nothing(self):
        self.append([self.mandate()])
        before = sorted(p.name for p in self.ledger_root.iterdir())
        for mandates, code in (([self.mandate(days=91)], "MANDATE_WINDOW_UNBOUNDED"),
                               ([self.mandate(nb=1899)], "MANDATE_NOT_BEFORE_REGRESSED"),
                               ([self.mandate("key-z")], "MANDATE_KEY_NOT_IN_ANCHOR"),
                               ([self.mandate("key-r")], "MANDATE_REVOCATION_REVERSED"),
                               ([], "EXACT_MANDATE_LIST_REQUIRED"),
                               ([self.mandate() | {"x": 1}], "EXACT_MANDATE_ENTRY_REQUIRED"),
                               ([{"keyRef": "key-a", "notBefore": 1.5, "expiresAt": 3, "state": "ACTIVE"}],
                                "EXACT_MANDATE_ENTRY_REQUIRED")):
            with self.subTest(code=code):
                self.denied(code, self.append, mandates)
            self.assertEqual(sorted(p.name for p in self.ledger_root.iterdir()), before)
        self.denied("EXACT_MANDATE_PRECONDITIONS_REQUIRED", self.append, [self.mandate(nb=1901)], {**OK, "extra": True})
        self.denied("EXACT_MANDATE_GENERATION_REQUIRED", self.append, [self.mandate(nb=1901)], OK, "bad issuer")
        self.denied("EXACT_MANDATE_PRECONDITIONS_REQUIRED", self.m.write_generation, str(self.ledger_root), self.anchor,
                    "test-installation", "test-entity", [self.mandate(nb=1901)], OK, "renewal-job", "x", self.clock)
        # A temporary left by a failed writer blocks readers and writers (fail closed).
        self.write(self.ledger_root / (".tmp-2-" + "0" * 32), b"partial")
        self.denied("MANDATE_TEMPORARY_ENTRY_PRESENT", self.append, [self.mandate(nb=1901)])

    def test_write_generation_removes_temporary_on_failure(self):
        with patch.object(self.m.os, "link", side_effect=OSError("simulated")):
            self.denied("MANDATE_GENERATION_PUBLICATION_FAILED", self.append, [self.mandate()])
        self.assertEqual(list(self.ledger_root.iterdir()), [])
        self.ledger().refresh()


class AuthenticatorTests(Fixture):
    def test_valid_invalid_domain_and_scope(self):
        raw = b"arming payload"
        self.assertIs(self.verify(raw, self.sign(raw)), True)
        signature = json.loads(self.sign(raw))
        signature["signature"] = ("0" if signature["signature"][0] != "0" else "1") + signature["signature"][1:]
        self.denied("DETACHED_SIGNATURE_INVALID", self.verify, raw, self.m.canonical(signature))
        self.denied("DETACHED_SIGNATURE_INVALID", self.verify, raw, self.sign(raw, wrong_domain=True))
        self.denied("EXACT_DETACHED_SIGNATURE_REQUIRED", self.verify, raw + b"x", self.sign(raw))
        self.denied("EXACT_DETACHED_SIGNATURE_REQUIRED", self.verify, raw, self.sign(raw, role="ARTIFACT_ACCEPTANCE"))
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, self.sign(raw, issuer="other-issuer"), issuer="other-issuer")
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, self.sign(raw, key="key-b"))
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, self.sign(raw, key="key-r"))
        envelope = json.loads(self.sign(raw))
        envelope["schema"] = "ouf.semantic-deployment-detached-signature.v1"
        self.denied("EXACT_DETACHED_SIGNATURE_REQUIRED", self.verify, raw, self.m.canonical(envelope))

    def test_expired_then_renewed(self):
        raw = b"arming payload"
        signature = self.sign(raw)
        self.now = 2500
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, signature)
        self.append([self.mandate(nb=2400, days=90)])
        self.assertIs(self.verify(raw, signature), True)
        self.now = 2400 + 90 * DAY
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, signature)
        self.now = 2500
        self.append([self.mandate(state="REVOKED", nb=2400)])
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, signature)

    def test_ledger_changed_during_verification(self):
        raw = b"arming payload"
        signature = self.sign(raw)
        authenticator = self.authenticator()
        original = authenticator.verify

        def concurrent(*args):
            original(*args)
            self.append([self.mandate()])

        with patch.object(authenticator, "verify", side_effect=concurrent):
            self.denied("MANDATE_LEDGER_CHANGED_DURING_VERIFICATION", self.verify, raw, signature,
                        authenticator=authenticator)

    def test_mandate_expiring_during_verification_and_clock_regression(self):
        raw = b"arming payload"
        signature = self.sign(raw)
        times = iter([1999, 2000])
        authenticator = self.m.MandateAuthenticator(self.anchor, str(self.ledger_root), self.ssl, lambda: next(times))
        self.denied("ACTIVE_MANDATE_REQUIRED", self.verify, raw, signature, authenticator=authenticator)
        times = iter([1600, 1599])
        authenticator = self.m.MandateAuthenticator(self.anchor, str(self.ledger_root), self.ssl, lambda: next(times))
        self.denied("MANDATE_CLOCK_REGRESSED", self.verify, raw, signature, authenticator=authenticator)

    def test_openssl_binding_and_no_private_key_reads(self):
        raw = b"arming payload"
        signature = self.sign(raw)
        self.denied("MANDATE_EXECUTABLE_DRIFT", self.verify, raw, signature,
                    authenticator=self.m.MandateAuthenticator(self.anchor, str(self.ledger_root),
                                                              {**self.ssl, "sha256": "0" * 64}, self.clock))
        self.denied("DETACHED_OPENSSL_VERSION_UNPROVEN", self.verify, raw, signature,
                    authenticator=self.m.MandateAuthenticator(self.anchor, str(self.ledger_root),
                                                              {**self.ssl, "version": "0.0.1"}, self.clock))
        opened = []
        keys = {str(path) for path in self.keys.values()}

        def path_like(value):
            return isinstance(value, (str, bytes, os.PathLike))

        active = [True]
        self.addCleanup(active.__setitem__, 0, False)

        def audit(event, args):
            # Audit hooks are process-wide and permanent: inert after this test, never raising.
            if not active[0]:
                return
            if event == "open" and path_like(args[0]) and os.fsdecode(args[0]) in keys:
                opened.append(event)
            if event == "subprocess.Popen" and isinstance(args[1], (list, tuple)) and any(
                    path_like(item) and os.fsdecode(item) in keys for item in args[1]):
                opened.append(event)

        sys.addaudithook(audit)
        self.assertIs(self.verify(raw, signature), True)
        self.append([self.mandate()])
        self.assertEqual(opened, [])

    def test_errors_are_public_codes_only(self):
        secret = "SECRET-INPUT-CONTENT"
        self.put(1, json.dumps({"schema": secret}).encode())
        with self.assertRaises(self.m.MandateDenied) as caught:
            self.ledger().refresh()
        self.assertNotIn(secret, str(caught.exception))
        self.assertRegex(str(caught.exception), r"\A[A-Z0-9_]{1,80}\Z")


if __name__ == "__main__":
    unittest.main()
