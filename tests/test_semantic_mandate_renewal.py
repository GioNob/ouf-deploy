"""Mandate renewal job (task-28): native custody under /run, simulated clock.

Ephemeral anchors, profile, receipt and ledgers per test. No network, no
systemd (the runner is stubbed), no private keys (key paths never exist).
"""

import copy
import hashlib
import importlib.util
import json
import subprocess
import os
from pathlib import Path
import secrets
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RENEWAL = ROOT / "tools/semantic_mandate_renewal/renewal.py"
MANDATES = ROOT / "tools/semantic_authority_mandates/mandates.py"
NATIVE = os.environ.get("OUF_MANDATE_RENEWAL_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_MANDATE_RENEWAL_NATIVE requires Linux root:root; refusing to skip")
DAY = 86400
START = 1000
END = START + 60 * DAY


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Crash(BaseException):
    """Simulated process death: nothing in the job may catch it."""


@unittest.skipUnless(NATIVE, "set OUF_MANDATE_RENEWAL_NATIVE=1 under native Linux root")
class Fixture(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o077))
        self.temp = tempfile.TemporaryDirectory(prefix="ouf-renewal-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.code = self.root / "code"
        self.code.mkdir(mode=0o700)
        self.renewal_path, self.mandates_path = self.code / "renewal.py", self.code / "mandates.py"
        self.write(self.renewal_path, RENEWAL.read_bytes())
        self.write(self.mandates_path, MANDATES.read_bytes())
        self.r = load(self.renewal_path, "renewal_fixture")
        self.m = load(self.mandates_path, "mandates_fixture")
        self.installer, self.attestor = secrets.token_hex(32), secrets.token_hex(32)
        self.private_paths = [str(self.root / "keys/installer.pem"), str(self.root / "keys/attestor.pem")]
        self.base = {"schema": self.m.BASE_ANCHOR_SCHEMA, "installationRef": "test-installation",
                     "entityRef": "test-entity", "keys": [
                         self.key("inst-key", ["DEPLOYMENT_INTENT", "FINAL_DEPLOYMENT_APPROVAL"], self.installer),
                         self.key("att-key", ["CREATION_ATTESTATION"], self.attestor),
                         self.key("other-key", ["DEPLOYMENT_INTENT"], secrets.token_hex(32))]}
        self.receipt_path = self.root / "custody-receipt.json"
        self.write(self.receipt_path, b'{"custody":"receipt"}')
        self.base_path, self.profile_path, self.b1b2_path = (self.root / "base.json", self.root / "profile.json",
                                                             self.root / "b1b2.json")
        self.publish_anchors()
        self.state = self.root / "state"
        self.ledgers = self.root / "ledgers"
        for path in (self.state, self.ledgers, self.ledgers / "b1b2", self.ledgers / "base",
                     self.ledgers / "base-versioned"):
            path.mkdir(mode=0o700)
        self.config_path = self.root / "configuration.json"
        self.config = self.make_config()
        self.save_config()
        self.now = END - 31 * DAY

    # --- helpers --------------------------------------------------------

    def key(self, ref, roles, public, issuer="test-issuer", state="ACTIVE"):
        return {"keyRef": ref, "issuerRef": issuer, "roles": roles, "publicKey": public,
                "notBefore": START, "expiresAt": END, "state": state}

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw if isinstance(raw, bytes) else canonical(raw))
        path.chmod(mode)

    def pin(self, path):
        return {"path": str(path), "sha256": sha(path.read_bytes())}

    def publish_anchors(self):
        self.write(self.base_path, self.base)
        self.profile = {"schema": self.r.PROFILE_SCHEMA, "sourceCommit": "a" * 40, "sourceRoot": str(self.root),
                        "sourceHashes": {"x.py": "b" * 64},
                        "authorities": {"installationRef": "test-installation", "entityRef": "test-entity",
                                        "intentIssuerRef": "test-issuer", "approvalIssuerRef": "test-issuer",
                                        "attestorRef": "test-issuer"},
                        "keyRefs": {"installer": "inst-key", "attestor": "att-key"},
                        "keyBindings": {"installer": {"path": self.private_paths[0], "sha256": "c" * 64},
                                        "attestor": {"path": self.private_paths[1], "sha256": "d" * 64}},
                        "policyBinding": self.pin(self.base_path), "custodyReceiptBinding": self.pin(self.receipt_path)}
        self.write(self.profile_path, self.profile)
        self.b1b2 = {"schema": self.m.B1B2_ANCHOR_SCHEMA, "installationRef": "test-installation",
                     "entityRef": "test-entity", "basePolicy": self.pin(self.base_path),
                     "authorityProfile": self.pin(self.profile_path),
                     "keys": [self.key("b1b2-key", ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"], self.installer)]}
        self.write(self.b1b2_path, self.b1b2)

    def make_config(self):
        return {"schema": self.r.CONFIG_SCHEMA, "renewalSource": self.pin(self.renewal_path),
                "mandatesModule": self.pin(self.mandates_path), "installationRef": "test-installation",
                "entityRef": "test-entity", "issuerRef": "renewal-job", "authorityProfile": self.pin(self.profile_path),
                "b1b2": {"anchor": self.pin(self.b1b2_path), "ledgerRoot": str(self.ledgers / "b1b2"),
                         "keyRefs": ["b1b2-key"]},
                "base": {"anchor": self.pin(self.base_path), "ledgerRoot": str(self.ledgers / "base"),
                         "versionedRoot": str(self.ledgers / "base-versioned"), "keyRefs": ["att-key", "inst-key"]},
                "stateRoot": str(self.state), "windowSeconds": 7776000, "renewBeforeSeconds": 2592000}

    def save_config(self, value=None):
        self.write(self.config_path, self.config if value is None else value)

    def clock(self):
        return self.now

    def job(self, digest=None):
        return self.r.Job(str(self.config_path), digest or sha(self.config_path.read_bytes()), self.clock)

    def run(self, dry_run=False):
        return self.job().run(dry_run)

    def status(self):
        return json.loads((self.state / "status.json").read_bytes())

    def names(self, path):
        return sorted(p.name for p in path.iterdir())

    def incident(self):
        path = self.state / "incidents/open.json"
        return json.loads(path.read_bytes()) if path.exists() else None

    def blocked(self, code):
        outcome, reason, _ = self.run()
        self.assertEqual((outcome, reason), ("BLOCKED", code))
        self.assertEqual(self.status()["reasonCode"], code)
        return reason

    def no_generations(self):
        self.assertEqual(self.names(self.ledgers / "b1b2"), [])
        self.assertEqual(self.names(self.ledgers / "base"), [])
        self.assertEqual(self.names(self.ledgers / "base-versioned"), [])


class RenewalTests(Fixture):
    def test_noop_beyond_t30(self):
        self.assertEqual(self.run(), ("NOOP", None, False))
        self.no_generations()
        status = self.status()
        self.assertEqual(status["ledgers"]["b1b2"], {"generation": 0, "headSha256": None, "earliestExpiresAt": END})
        self.assertIsNone(status["versionedBase"])
        self.assertFalse(status["openIncident"])
        self.assertIsNone(self.incident())

    def test_renewed_at_t30_then_idempotent(self):
        self.now = END - 30 * DAY
        self.assertEqual(self.run()[0], "RENEWED")
        for name, refs in (("b1b2", ["b1b2-key"]), ("base", ["att-key", "inst-key"])):
            record = json.loads((self.ledgers / name / "1.json").read_bytes())
            self.assertEqual(record["previousSha256"], None)
            self.assertEqual(record["issuedAt"], self.now)
            self.assertEqual(sorted(m["keyRef"] for m in record["mandates"]), refs)
            for mandate in record["mandates"]:
                self.assertEqual((mandate["notBefore"], mandate["expiresAt"], mandate["state"]),
                                 (self.now, self.now + 90 * DAY, "ACTIVE"))
            self.assertTrue(all(record["preconditions"][flag] for flag in
                                ("keyNotRevoked", "custodyIntact", "noOpenSecurityIncident")))
            evidence = self.state / "evidence" / (record["preconditions"]["evidenceSha256"] + ".json")
            self.assertTrue(evidence.exists())
        versioned = (self.ledgers / "base-versioned/1.json").read_bytes()
        value = json.loads(versioned)
        windows = {k["keyRef"]: (k["notBefore"], k["expiresAt"]) for k in value["keys"]}
        self.assertEqual(windows["inst-key"], (self.now, self.now + 90 * DAY))
        self.assertEqual(windows["att-key"], (self.now, self.now + 90 * DAY))
        self.assertEqual(windows["other-key"], (START, END))  # not configured: untouched
        self.m.base_anchor(versioned, "test-installation", "test-entity")
        self.assertEqual(versioned, self.m.canonical(value))
        status = self.status()
        self.assertEqual(status["versionedBase"], {"generation": 1, "sha256": sha(versioned)})
        self.assertEqual(status["ledgers"]["base"]["earliestExpiresAt"], self.now + 90 * DAY)
        self.assertEqual(self.run()[0], "NOOP")
        self.assertEqual(self.names(self.ledgers / "base"), ["1.json"])

    def test_inside_t30_and_chain_across_renewals(self):
        self.now = END - 10 * DAY
        self.assertEqual(self.run()[0], "RENEWED")
        first = self.now
        self.now = first + 61 * DAY  # 29 days before the renewed expiry
        self.assertEqual(self.run()[0], "RENEWED")
        second = json.loads((self.ledgers / "base/2.json").read_bytes())
        self.assertEqual(second["previousSha256"], sha((self.ledgers / "base/1.json").read_bytes()))
        self.assertEqual(self.names(self.ledgers / "base-versioned"), ["1.json", "2.json"])
        older = json.loads((self.ledgers / "base-versioned/1.json").read_bytes())
        self.assertEqual({k["keyRef"]: k["expiresAt"] for k in older["keys"]}["inst-key"], first + 90 * DAY)

    def test_dry_run_writes_only_status(self):
        self.now = END - 30 * DAY
        self.assertEqual(self.run(dry_run=True), ("NOOP", None, True))
        self.no_generations()
        self.assertEqual(self.names(self.state), ["status.json"])
        self.now = END
        self.assertEqual(self.run(dry_run=True)[:2], ("BLOCKED", "MANDATE_EXPIRED_WITHOUT_RENEWAL"))
        self.assertIsNone(self.incident())

    def test_expired_is_blocked_without_writes(self):
        self.now = END
        self.blocked("MANDATE_EXPIRED_WITHOUT_RENEWAL")
        self.no_generations()
        self.assertEqual(self.incident()["reasonCode"], "MANDATE_EXPIRED_WITHOUT_RENEWAL")
        self.assertTrue(self.status()["openIncident"])

    def test_revoked_in_anchor_or_ledger(self):
        self.now = END - 30 * DAY
        self.base["keys"][1]["state"] = "REVOKED"
        self.publish_anchors()
        self.config = self.make_config()
        self.save_config()
        self.blocked("PRECONDITION_KEY_NOT_REVOKED_UNMET")
        self.no_generations()
        (self.state / "incidents/open.json").unlink()
        self.base["keys"][1]["state"] = "ACTIVE"
        self.publish_anchors()
        self.config = self.make_config()
        self.save_config()
        self.m.write_generation(str(self.ledgers / "b1b2"), self.config["b1b2"]["anchor"], "test-installation",
                                "test-entity", [{"keyRef": "b1b2-key", "notBefore": START, "expiresAt": END,
                                                 "state": "REVOKED"}],
                                {"keyNotRevoked": False, "custodyIntact": True, "noOpenSecurityIncident": True},
                                "operator", "9" * 64, self.clock)
        self.blocked("PRECONDITION_KEY_NOT_REVOKED_UNMET")
        self.assertEqual(self.names(self.ledgers / "base"), [])

    def test_custody_preconditions(self):
        self.now = END - 30 * DAY
        original = self.receipt_path.read_bytes()
        self.write(self.receipt_path, b'{"custody":"changed"}')
        self.blocked("PRECONDITION_CUSTODY_INTACT_UNMET")
        self.no_generations()
        (self.state / "incidents/open.json").unlink()
        self.write(self.receipt_path, original)
        self.receipt_path.chmod(0o666)
        self.blocked("PRECONDITION_CUSTODY_INTACT_UNMET")
        (self.state / "incidents/open.json").unlink()
        self.receipt_path.chmod(0o600)
        self.write(self.profile_path, self.profile | {"sourceRoot": "/changed"})
        self.blocked("PRECONDITION_CUSTODY_INTACT_UNMET")
        self.no_generations()

    def test_open_incident_blocks_and_keeps_first_code(self):
        self.now = END - 30 * DAY
        (self.state / "incidents").mkdir(mode=0o700)
        self.write(self.state / "incidents/open.json",
                   {"reasonCode": "FIRST_CAUSE", "firstSeenAt": 5, "evidenceSha256": None})
        self.blocked("FIRST_CAUSE")
        self.no_generations()
        self.assertEqual(self.incident(), {"reasonCode": "FIRST_CAUSE", "firstSeenAt": 5, "evidenceSha256": None})
        self.assertTrue(self.status()["openIncident"])
        # Ledger information is still reported, for the near-expiry rule of the collector.
        self.assertEqual(self.status()["ledgers"]["base"]["earliestExpiresAt"], END)

    def test_incident_exclusive_first_code_persists(self):
        self.now = END
        self.blocked("MANDATE_EXPIRED_WITHOUT_RENEWAL")
        self.write(self.ledgers / "b1b2" / "stray", b"x")
        self.blocked("MANDATE_EXPIRED_WITHOUT_RENEWAL")
        self.assertEqual(self.incident()["reasonCode"], "MANDATE_EXPIRED_WITHOUT_RENEWAL")
        self.assertEqual(self.names(self.state / "incidents"), ["open.json"])

    def test_temporary_entries_block_and_open_incident(self):
        self.now = END - 30 * DAY
        temporary = self.ledgers / "base" / (".tmp-1-" + "0" * 32)
        self.write(temporary, b"partial")
        self.blocked("MANDATE_TEMPORARY_ENTRY_PRESENT")
        self.assertEqual(self.names(self.ledgers / "b1b2"), [])
        self.assertEqual(self.incident()["reasonCode"], "MANDATE_TEMPORARY_ENTRY_PRESENT")
        temporary.unlink()
        (self.state / "incidents/open.json").unlink()
        versioned = self.ledgers / "base-versioned" / (".tmp-1-" + "1" * 32)
        self.write(versioned, b"partial")
        self.blocked("VERSIONED_BASE_TEMPORARY_ENTRY_PRESENT")
        self.assertEqual(self.names(self.ledgers / "base"), [])

    def test_incoherent_anchors_profile_or_key_refs(self):
        self.now = END - 30 * DAY
        cases = [lambda c: c["base"].update(keyRefs=["inst-key", "other-key"]),
                 lambda c: c["b1b2"].update(keyRefs=["missing-key"]),
                 lambda c: c.update(authorityProfile={**c["authorityProfile"], "sha256": "0" * 64})]
        for change in cases:
            value = copy.deepcopy(self.config)
            change(value)
            self.save_config(value)
            with self.subTest(change=change):
                outcome, reason, _ = self.run()
                self.assertEqual(outcome, "BLOCKED")
                self.assertIn(reason, ("AUTHORITY_COHERENCE_UNPROVEN", "PRECONDITION_CUSTODY_INTACT_UNMET"))
            self.no_generations()
            incident = self.state / "incidents/open.json"
            if incident.exists():
                incident.unlink()
        self.save_config()
        self.b1b2["keys"][0]["publicKey"] = secrets.token_hex(32)
        self.write(self.b1b2_path, self.b1b2)
        self.config["b1b2"]["anchor"] = self.pin(self.b1b2_path)
        self.save_config()
        self.blocked("AUTHORITY_COHERENCE_UNPROVEN")

    def test_crash_between_ledger_and_versioned_base_then_repair_and_drift(self):
        self.now = END - 30 * DAY
        with patch.object(self.r, "publish_linked", side_effect=Crash()):
            with self.assertRaises(Crash):
                self.run()
        self.assertEqual(self.names(self.ledgers / "base"), ["1.json"])
        self.assertEqual(self.names(self.ledgers / "base-versioned"), [])
        self.assertIsNone(self.incident())
        self.assertEqual(self.run()[0], "NOOP")
        self.assertEqual(self.names(self.ledgers / "base-versioned"), ["1.json"])
        self.write(self.ledgers / "base-versioned/1.json", b'{"tampered":true}')
        self.blocked("VERSIONED_BASE_DRIFT")
        (self.state / "incidents/open.json").unlink()
        (self.ledgers / "base-versioned/1.json").unlink()
        self.write(self.ledgers / "base-versioned/2.json", b"{}")
        self.blocked("VERSIONED_BASE_DRIFT")

    def test_b1b2_failure_leaves_base_ledger_intact(self):
        self.now = END - 30 * DAY
        job = self.job()
        calls = []

        def failing(root, *args, **kwargs):
            calls.append(root)
            raise job.mandates.MandateDenied("MANDATE_GENERATION_PUBLICATION_FAILED")

        with patch.object(job.mandates, "write_generation", side_effect=failing):
            outcome, reason, _ = job.run()
        self.assertEqual((outcome, reason), ("BLOCKED", "MANDATE_GENERATION_PUBLICATION_FAILED"))
        self.assertEqual(calls, [str(self.ledgers / "b1b2")])
        self.no_generations()

    def test_configuration_rejections(self):
        with self.assertRaises(self.r.Blocked) as caught:
            self.job("0" * 64)
        self.assertEqual(str(caught.exception), "RENEWAL_CONFIGURATION_DRIFT")
        for change in ({"extra": 1}, {"windowSeconds": 7776001}, {"renewBeforeSeconds": 2592001},
                       {"stateRoot": "relative"}, {"issuerRef": "bad issuer"}, {"schema": "other"}):
            self.save_config(self.config | change)
            with self.subTest(change=change), self.assertRaises(self.r.Blocked) as caught:
                self.job()
            self.assertEqual(str(caught.exception), "EXACT_RENEWAL_CONFIGURATION_REQUIRED")
        for key in self.config:
            value = dict(self.config)
            del value[key]
            self.save_config(value)
            with self.subTest(missing=key), self.assertRaises(self.r.Blocked):
                self.job()
        self.save_config(self.config | {"renewalSource": {**self.config["renewalSource"], "sha256": "0" * 64}})
        with self.assertRaises(self.r.Blocked) as caught:
            self.job()
        self.assertEqual(str(caught.exception), "RENEWAL_SOURCE_DRIFT")
        self.save_config(self.config | {"mandatesModule": {**self.config["mandatesModule"], "sha256": "0" * 64}})
        with self.assertRaises(self.r.Blocked) as caught:
            self.job()
        self.assertEqual(str(caught.exception), "MANDATES_MODULE_DRIFT")
        self.save_config()
        self.config_path.chmod(0o644)
        with self.assertRaises(self.r.Blocked):
            self.job()
        self.config_path.chmod(0o600)
        self.state.chmod(0o755)
        with self.assertRaises(self.r.Blocked) as caught:
            self.job()
        self.assertEqual(str(caught.exception), "PRIVATE_RENEWAL_STATE_ROOT_REQUIRED")

    def test_status_schema_custody_and_no_paths(self):
        self.now = END - 30 * DAY
        self.run()
        path = self.state / "status.json"
        info = path.stat()
        self.assertEqual((info.st_mode & 0o777, info.st_uid, info.st_gid, info.st_nlink), (0o600, 0, 0, 1))
        raw = path.read_bytes()
        value = json.loads(raw)
        self.assertEqual(set(value), {"schema", "checkedAt", "outcome", "reasonCode", "ledgers", "versionedBase",
                                      "openIncident"})
        self.assertEqual(raw, canonical(value))
        self.assertNotIn(b"/", raw)
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertEqual(sorted(p.name for p in self.state.iterdir() if p.name.startswith(".")), [])

    def test_concurrent_run_refused(self):
        import fcntl
        fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with self.assertRaises(self.r.Blocked) as caught:
            self.run()
        self.assertEqual(str(caught.exception), "RENEWAL_ALREADY_RUNNING")

    def test_no_private_key_path_access(self):
        self.now = END - 30 * DAY
        touched = []
        active = [True]
        self.addCleanup(active.__setitem__, 0, False)

        def audit(event, args):
            if not active[0] or not args:
                return
            first = args[0]
            if isinstance(first, (str, bytes, os.PathLike)) and os.fsdecode(first) in self.private_paths:
                touched.append(event)

        sys.addaudithook(audit)
        self.assertEqual(self.run()[0], "RENEWED")
        self.assertEqual(touched, [])


class GovernedOperationTests(Fixture):
    def layout(self):
        base = self.root / "install"
        base.mkdir(mode=0o700, exist_ok=True)
        (base / "etc").mkdir(mode=0o700, exist_ok=True)
        (base / "lib").mkdir(mode=0o700, exist_ok=True)
        (base / "systemd").mkdir(mode=0o700, exist_ok=True)
        return {"codeRoot": str(base / "etc/renewal"), "ledgerParent": str(base / "lib/mandates"),
                "stateRoot": str(base / "lib/renewal-state"), "unitDirectory": str(base / "systemd"),
                "python": sys.executable}

    def source_dir(self):
        source = self.root / "delivery"
        for relative, raw in (("tools/semantic_mandate_renewal/renewal.py", RENEWAL.read_bytes()),
                              ("tools/semantic_authority_mandates/mandates.py", MANDATES.read_bytes())):
            path = source / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.write(path, raw)
        return source

    def install_args(self, apply=False, plan_sha256=None):
        return SimpleNamespace(source_dir=str(self.source_dir()), b1b2_anchor=str(self.b1b2_path),
                               b1b2_anchor_sha256=sha(self.b1b2_path.read_bytes()), base_anchor=str(self.base_path),
                               base_anchor_sha256=sha(self.base_path.read_bytes()),
                               authority_profile=str(self.profile_path),
                               authority_profile_sha256=sha(self.profile_path.read_bytes()),
                               installation_ref="test-installation", entity_ref="test-entity",
                               plan=not apply, apply=apply, plan_sha256=plan_sha256)

    def test_install_plan_apply_and_refuse_reinstall(self):
        layout = self.layout()
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"MANDATE_RENEWAL=NOOP REASON=NONE")

        own = RENEWAL.read_bytes()
        plan, files, _, cfg = self.r.install_plan(self.install_args(), layout, own)
        plan_sha = sha(self.r.canonical(plan))
        self.assertEqual(cfg["b1b2"]["keyRefs"], ["b1b2-key"])
        self.assertEqual(cfg["base"]["keyRefs"], ["att-key", "inst-key"])
        with self.assertRaises(self.r.Blocked) as caught:
            self.r.install(self.install_args(True, "0" * 64), layout, runner, own)
        self.assertEqual(str(caught.exception), "INSTALL_PLAN_CHANGED")
        self.assertFalse(os.path.lexists(layout["codeRoot"]))
        self.assertEqual(self.r.install(self.install_args(True, plan_sha), layout, runner, own), 0)
        self.assertEqual([c[0] for c in calls], ["systemctl", sys.executable, "systemctl"])
        self.assertIn("--dry-run", calls[1])
        self.assertEqual(calls[2], ["systemctl", "enable", "--now", "ouf-authority-mandate-renewal.timer"])
        configuration = Path(layout["codeRoot"]) / "configuration.json"
        self.assertEqual(sha(configuration.read_bytes()), plan["configurationSha256"])
        service = (Path(layout["unitDirectory"]) / "ouf-authority-mandate-renewal.service").read_text()
        self.assertIn("--configuration-sha256 " + plan["configurationSha256"], service)
        for path in (layout["ledgerParent"] + "/b1b2", layout["ledgerParent"] + "/base",
                     layout["ledgerParent"] + "/base-versioned", layout["stateRoot"]):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)
        with self.assertRaises(self.r.Blocked) as caught:
            self.r.install_plan(self.install_args(), layout, own)
        self.assertEqual(str(caught.exception), "INSTALL_TARGET_EXISTS")

    def test_install_refuses_incoherent_inputs_and_source_drift(self):
        layout = self.layout()
        args = self.install_args()
        args.base_anchor_sha256 = "0" * 64
        with self.assertRaises(self.r.Blocked):
            self.r.install_plan(args, layout, RENEWAL.read_bytes())
        with self.assertRaises(self.r.Blocked) as caught:
            self.r.install_plan(self.install_args(), layout, b"other source")
        self.assertEqual(str(caught.exception), "RENEWAL_SOURCE_DRIFT")
        self.assertFalse(os.path.lexists(layout["codeRoot"]))

    def test_incident_close_plan_apply(self):
        self.now = END - 30 * DAY
        temporary = self.ledgers / "base" / (".tmp-1-" + "a" * 32)
        self.write(temporary, b"partial")
        self.blocked("MANDATE_TEMPORARY_ENTRY_PRESENT")
        args = SimpleNamespace(configuration=str(self.config_path),
                               configuration_sha256=sha(self.config_path.read_bytes()),
                               plan=True, apply=False, plan_sha256=None)
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        source = str(self.renewal_path)
        self.assertEqual(self.r.incident_close(args, runner, source), 0)
        incident_sha = sha((self.state / "incidents/open.json").read_bytes())
        plan = {"schema": self.r.CLOSE_PLAN_SCHEMA, "incident": self.incident(), "incidentSha256": incident_sha,
                "temporaries": [{"path": str(temporary), "size": 7, "sha256": sha(b"partial")}]}
        args.apply, args.plan_sha256 = True, "0" * 64
        with self.assertRaises(self.r.Blocked):
            self.r.incident_close(args, runner, source)
        self.assertTrue(temporary.exists())
        args.plan_sha256 = sha(self.r.canonical(plan))
        self.assertEqual(self.r.incident_close(args, runner, source), 0)
        self.assertFalse(temporary.exists())
        self.assertIsNone(self.incident())
        self.assertEqual(len(list((self.state / "incidents/closed").iterdir())), 1)
        self.assertEqual(calls, [["systemctl", "start", "ouf-authority-mandate-renewal.service"]])
        self.assertEqual(self.run()[0], "RENEWED")
        args.apply = False
        with self.assertRaises(self.r.Blocked) as caught:
            self.r.incident_close(args, runner, source)
        self.assertEqual(str(caught.exception), "NOTHING_TO_CLOSE")


class ContractTests(Fixture):
    def test_reviewed_units_equal_installer_output(self):
        digest = "e" * 64
        for name, raw in self.r.unit_files(self.r.LAYOUT, digest).items():
            reviewed = (ROOT / "ops/systemd" / name).read_bytes().replace(b"@CONFIGURATION_SHA256@", digest.encode())
            self.assertEqual(raw, reviewed, name)

    def test_incident_close_runbook_extracts_the_unit_configuration_hash(self):
        digest = "f" * 64
        unit = self.root / "unit.service"
        self.write(unit, self.r.unit_files(self.r.LAYOUT, digest)[self.r.SERVICE])
        script = (ROOT / "ops/vps/mandate-renewal-incident-close.sh").read_text()
        expression = script.split("sed -n '", 1)[1].split("'", 1)[0]
        result = subprocess.run(["sed", "-n", expression, str(unit)], stdout=subprocess.PIPE, check=True, timeout=5)
        self.assertEqual(result.stdout.decode().strip(), digest)

    def test_install_runbook_pins_and_inputs(self):
        script = (ROOT / "ops/vps/mandate-renewal-install.sh").read_text()
        for value in ("6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95",
                      "21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42",
                      "7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18",
                      "--installation-ref ouf-lab-netcup-01", "--entity-ref ouf-lab",
                      "tools/semantic_mandate_renewal/renewal.py", "tools/semantic_authority_mandates/mandates.py"):
            self.assertIn(value, script)
        pins = dict(line.split("=", 1) for line in script.splitlines() if line[:2] in ("C=", "R=", "M="))
        self.assertRegex(pins["C"], r"\A[0-9a-f]{40}\Z")
        for key in ("R", "M"):
            self.assertRegex(pins[key], r"\A[0-9a-f]{64}\Z")
        if set(pins["C"]) != {"0"}:
            # Second pin state: the pinned commit carries exactly these bytes.
            for key, path in (("R", RENEWAL), ("M", MANDATES)):
                self.assertEqual(pins[key], sha(path.read_bytes()), key)
        result = subprocess.run(["bash", str(ROOT / "ops/vps/mandate-renewal-install.sh"), "apply", "x\r"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"ricevuti 1 caratteri", result.stderr)


if __name__ == "__main__":
    unittest.main()
