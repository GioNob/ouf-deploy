"""Signed terminal receipts on the governed MCP fixture with per-test Ed25519 keys."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch

from test_module_release import OLD, NEW
import test_module_release_java as java_tests
import test_module_release_mcp as mcp_tests
import mandate
import store
import module_operation
import module_receipt
from module_release import operation, return_operation
from module_release.contract import Held


OPENSSL = shutil.which("openssl")


def verify_like_platform_reader(public, receipt, signature):
    """Same argv as tools/platform_restart/identity.py verify_signature."""
    return subprocess.run([OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                           "-inkey", str(public), "-in", str(receipt), "-sigfile", str(signature)],
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=10, env={"OPENSSL_CONF": os.devnull}).returncode == 0


@unittest.skipUnless(OPENSSL, "openssl with Ed25519 required")
class SignedReturn(mcp_tests.Release):
    def setUp(self):
        super().setUp()
        self.private, self.public = self.root / "fixture-key", self.root / "fixture-public.der"
        self.keypair(self.private, self.public)
        self.p["receiptSigning"] = {"privateKey": str(self.private),
                                    "publicKey": {"path": str(self.public),
                                                  "sha256": hashlib.sha256(self.public.read_bytes()).hexdigest()}}
        self.enterContext(patch.object(module_receipt, "OPENSSL", OPENSSL))
        self.enterContext(patch.object(module_receipt, "trusted", side_effect=lambda path, **_: Path(path)))
        self.enterContext(patch.object(store, "trusted", side_effect=lambda path, **_: Path(path)))

    def keypair(self, private, public):
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([OPENSSL, "pkey", "-in", str(private), "-pubout", "-outform", "DER", "-out", str(public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def signed(self, stamp, name):
        root = self.root / stamp
        receipt, signature = root / (name + ".json"), root / (name + ".ed25519")
        self.assertTrue(signature.is_file(), name)
        self.assertEqual(signature.stat().st_size, 64)
        self.assertTrue(verify_like_platform_reader(self.public, receipt, signature))
        return receipt.read_bytes()

    def ready(self):
        stamp = self.planned()["digest"]
        self.assertEqual(self.call("apply", stamp)["status"], "READY")
        self.signed(stamp, "receipt")
        return stamp

    def test_return_from_ready_is_signed(self):
        stamp = self.ready()
        self.assertEqual(self.call("rollback", stamp, run="2")["status"], "ROLLED_BACK")
        receipt = json.loads(self.signed(stamp, "return-receipt"))
        self.assertEqual((receipt["status"], receipt["restoredCid"]), ("ROLLED_BACK", OLD))
        self.assertFalse((self.root / "mcp.lock").exists())
        self.assertEqual(self.rt.inspect(self.p["container"])["Id"], OLD)

    def test_reviewed_return_before_ready_is_signed(self):
        run = subprocess.run
        with java_tests.fixture("udp") as (profile, runtime, _, _):
            binding = profile["receiptSigning"] = self.p["receiptSigning"]
            stamp = java_tests.operation.plan(profile, runtime)["planSha256"]
            self.assertEqual(java_tests.operation.apply(profile, stamp, runtime)["status"], "GATED")
            # The Java fixture handles PostgreSQL subprocesses. Use real OpenSSL for the receipt.
            sql = subprocess.run
            def dispatch(argv, **kwargs):
                return (run if argv[0] == OPENSSL else sql)(argv, **kwargs)
            with patch.object(subprocess, "run", side_effect=dispatch):
                returned = java_tests.return_operation.run(profile, stamp, runtime, recover=True,
                                                            seal=module_receipt.sealer(binding))
                self.assertEqual(returned["status"], "ROLLED_BACK")
                root = Path(profile["journal"]) / stamp
                self.assertTrue(verify_like_platform_reader(self.public, root / "return-receipt.json",
                                                            root / "return-receipt.ed25519"))
                self.assertFalse((root / "receipt.json").exists())
                self.assertNotIn("signal:2", runtime.events)

    def test_lost_process_before_return_signature_completes_without_rewrite(self):
        stamp = self.ready()
        with patch.object(module_receipt, "sealer", return_value=Mock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        root = self.root / stamp
        published = (root / "return-receipt.json").read_bytes()
        self.assertFalse((root / "return-receipt.ed25519").exists())
        self.assertTrue((self.root / "mcp.lock").is_dir())
        events = list(self.rt.events)
        self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
        self.assertEqual(self.signed(stamp, "return-receipt"), published)
        self.assertEqual(store.read(self.root / "2/rollback.result"), json.loads(published))
        self.assertFalse((self.root / "mcp.lock").exists())
        # Completion only reads the restored predecessor: no stop, start or signal.
        self.assertFalse([e for e in self.rt.events[len(events):]
                          if e.split(":")[0] in ("stop", "start", "signal", "create")])

    def test_lost_process_after_return_signature_completes(self):
        stamp = self.ready()
        with patch.object(return_operation, "unlock_module", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        signature = (self.root / stamp / "return-receipt.ed25519").read_bytes()
        self.assertTrue((self.root / "mcp.lock").is_dir())
        with patch.object(module_receipt, "save_bytes") as publish:
            self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
            publish.assert_not_called()
        self.assertEqual((self.root / stamp / "return-receipt.ed25519").read_bytes(), signature)
        self.assertEqual(store.read(self.root / "2/rollback.result"), store.read(self.root / "3/rollback.result"))
        self.assertFalse((self.root / "mcp.lock").exists())

    def test_crash_during_unlock_leaves_owner_only_at_retired_path(self):
        stamp = self.ready()
        active = self.root / "mcp.lock"
        unlink = Path.unlink

        def lose_process(path, **kwargs):
            if path.name == "owner.json":
                self.assertFalse(active.exists())
                self.assertEqual(store.read(path), {"planSha256": stamp})
                raise KeyboardInterrupt
            return unlink(path, **kwargs)

        with patch.object(Path, "unlink", lose_process), self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        published = self.signed(stamp, "return-receipt")
        before = len(self.rt.events)
        with patch.object(module_receipt, "signing_key", side_effect=AssertionError("unexpected signing")):
            self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
        for run in ("2", "3"):
            self.assertEqual(store.read(self.root / run / "rollback.result"), json.loads(published))
        self.assertEqual(self.rt.events[before:], ["probe:1"])

    def test_unknown_active_lock_cannot_reconcile_return(self):
        stamp = self.ready()
        with patch.object(return_operation, "unlock_module", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        lock = self.root / "mcp.lock"
        (lock / "owner.json").unlink()
        with self.assertRaisesRegex(mandate.Held, "OPERATION_IN_PROGRESS_OR_INTERRUPTED"):
            self.call("rollback", stamp, run="3")
        self.assertTrue(lock.is_dir())
        self.assertFalse((self.root / "2/rollback.result").exists())

    def test_sign_timeout_reconciles_held_and_retry_reviews(self):
        stamp = self.ready()
        openssl = subprocess.run

        def timeout(argv, **kwargs):
            if "-sign" in argv:
                raise subprocess.TimeoutExpired(argv, 10)
            return openssl(argv, **kwargs)

        with patch.object(module_receipt.subprocess, "run", side_effect=timeout), self.assertRaises(mandate.Held):
            self.call("rollback", stamp, run="2")
        root = self.root / stamp
        held = self.root / "2/rollback.held"
        evidence = held.read_bytes()
        published = (root / "return-receipt.json").read_bytes()
        self.assertFalse((root / "return-receipt.ed25519").exists())
        self.assertFalse((self.root / "2/rollback.result").exists())
        before = len(self.rt.events)
        self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
        self.assertEqual(self.signed(stamp, "return-receipt"), published)
        for run in ("2", "3"):
            self.assertEqual(store.read(self.root / run / "rollback.result"), json.loads(published))
        self.assertEqual(held.read_bytes(), evidence)
        self.assertEqual(self.rt.events[before:], ["probe:1"])

    def test_lost_process_after_unlock_reconciles_original_and_retry(self):
        stamp = self.ready()
        save = module_operation.save

        def cut_before_result(path, value, **kwargs):
            if path.name == "rollback.result" and path.parent.name == self.req["run"]:
                self.assertFalse((self.root / "mcp.lock").exists())
                raise KeyboardInterrupt
            save(path, value, **kwargs)

        with patch.object(module_operation, "save", side_effect=cut_before_result), self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        root = self.root / stamp
        published = self.signed(stamp, "return-receipt")
        self.assertFalse((self.root / "2/rollback.result").exists())
        before = len(self.rt.events)
        with patch.object(return_operation, "run", side_effect=AssertionError("return replay")), \
                patch.object(module_receipt, "signing_key", side_effect=AssertionError("signing on retry")):
            # Lose the recovery process too, after it closes run 2 but before it closes run 3.
            with patch.object(module_operation, "save", side_effect=cut_before_result), \
                    self.assertRaises(KeyboardInterrupt):
                self.call("rollback", stamp, run="3")
            self.assertEqual(self.call("rollback", stamp, run="4")["status"], "ROLLED_BACK")
        for run in ("2", "3", "4"):
            self.assertEqual(store.read(self.root / run / "rollback.result"), json.loads(published))
        self.assertEqual((root / "return-receipt.json").read_bytes(), published)
        self.assertEqual(self.rt.events[before:], ["probe:1", "probe:1"])

    def test_interrupted_replay_cannot_reopen_a_closed_return(self):
        stamp = self.ready()
        self.call("rollback", stamp, run="2")
        save = module_operation.save
        def interrupt_result(path, value, **kwargs):
            if path.name == "rollback.result":
                raise KeyboardInterrupt
            save(path, value, **kwargs)
        with patch.object(module_operation, "save", side_effect=interrupt_result), self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="3")
        self.assertTrue(store.read(self.root / "3/rollback.review")["returnAlreadyConsumed"])
        self.assertEqual(self.call("rollback", stamp, run="4")["status"], "ROLLED_BACK")
        self.assertEqual(store.read(self.root / "4/rollback.result"), store.read(self.root / "2/rollback.result"))
        self.assertFalse((self.root / "3/rollback.result").exists())

    def test_unresolved_create_refuses_signature_and_retains_lock(self):
        stamp = self.ready()
        with patch.object(module_receipt, "sealer", return_value=Mock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        root = self.root / stamp
        (root / "created.json").unlink()
        (root / "return-intent.json").write_text(json.dumps({"cid": None, "planSha256": stamp}))
        self.assertTrue((root / "create-intent.json").is_file())
        with self.assertRaisesRegex(mandate.Held, "CREATE_OWNERSHIP_UNCONFIRMED"):
            self.call("rollback", stamp, run="3")
        self.assertEqual(store.read(self.root / "mcp.lock/owner.json"), {"planSha256": stamp})
        self.assertFalse((root / "return-receipt.ed25519").exists())
        self.assertFalse((self.root / "3/rollback.result").exists())

    def test_completion_refuses_a_predecessor_that_no_longer_serves(self):
        stamp = self.ready()
        with patch.object(module_receipt, "sealer", return_value=Mock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        self.rt.docs[OLD]["State"]["Running"] = False
        with self.assertRaisesRegex(mandate.Held, "RETURN_READINESS_CHANGED"):
            self.call("rollback", stamp, run="3")
        self.assertFalse((self.root / stamp / "return-receipt.ed25519").exists())
        self.assertTrue((self.root / "mcp.lock").is_dir())

    def test_foreign_failed_name_after_return_without_successor_blocks_signature(self):
        with java_tests.fixture("udp") as (profile, rt, _, _):
            profile["receiptSigning"] = self.p["receiptSigning"]
            stamp = java_tests.operation.plan(profile, rt)["planSha256"]
            with patch.object(rt, "stop", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                java_tests.operation.apply(profile, stamp, rt)
            root = Path(profile["journal"]) / stamp
            with self.assertRaises(KeyboardInterrupt):
                java_tests.return_operation.run(profile, stamp, rt, recover=True, seal=Mock(side_effect=KeyboardInterrupt))
            self.assertEqual(store.read(root / "return-intent.json"), {"cid": None, "planSha256": stamp})
            rt.docs[NEW] = {"Id": NEW, "Name": "/" + profile["failedName"]}
            seal = Mock()
            with self.assertRaisesRegex(java_tests.Held, "CUSTODY_NAME_OCCUPIED"):
                java_tests.return_operation.run(profile, stamp, rt, recover=True, seal=seal)
            seal.assert_not_called()
            self.assertFalse((root / "return-receipt.ed25519").exists())
            self.assertEqual(store.read(root.parent / "udp.lock/owner.json"), {"planSha256": stamp})

    def test_completion_refuses_database_and_generation_drift(self):
        stamp = self.ready()
        with patch.object(module_receipt, "sealer", return_value=Mock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        self.db["schema"].append("change")
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            self.call("rollback", stamp, run="3")
        self.db["schema"].pop()
        self.rt.docs[OLD]["RestartCount"] += 1
        with self.assertRaisesRegex(mandate.Held, "TERMINAL_GENERATION_CHANGED"):
            self.call("rollback", stamp, run="4")
        self.assertFalse((self.root / stamp / "return-receipt.ed25519").exists())
        self.assertTrue((self.root / "mcp.lock").is_dir())

    def lose_signature_at_unlock(self, owner, signature):
        unlock = owner.unlock_module

        def lose(lock):
            unlock(lock)
            signature.unlink()

        return patch.object(owner, "unlock_module", side_effect=lose)

    def test_missing_ready_signature_after_unlock_leaves_phase_open(self):
        stamp = self.planned()["digest"]
        with self.lose_signature_at_unlock(operation, self.root / stamp / "receipt.ed25519"), \
                self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_SIGNATURE_REQUIRED"):
            self.call("apply", stamp)
        self.assertFalse((self.root / "1/apply.result").exists())
        self.assertFalse((self.root / "module-mcp.ready").exists())

    def test_missing_compensation_signature_after_unlock_leaves_phase_open(self):
        stamp = self.planned()["digest"]
        self.rt.fault = "handler"
        with self.lose_signature_at_unlock(operation, self.root / stamp / "receipt.ed25519"), \
                self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_SIGNATURE_REQUIRED"):
            self.call("apply", stamp)
        self.assertFalse((self.root / "1/apply.result").exists())
        self.assertEqual(operation.read(self.root / stamp, "receipt.json")["rollback"], "ROLLED_BACK")

    def test_missing_return_signature_after_unlock_leaves_phase_open(self):
        stamp = self.ready()
        with self.lose_signature_at_unlock(return_operation, self.root / stamp / "return-receipt.ed25519"), \
                self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_SIGNATURE_REQUIRED"):
            self.call("rollback", stamp, run="2")
        self.assertFalse((self.root / "2/rollback.result").exists())

    def test_historical_unsigned_return_is_preserved(self):
        stamp = self.ready()
        self.call("rollback", stamp, run="2")
        root = self.root / stamp
        published = (root / "return-receipt.json").read_bytes()
        (root / "return-receipt.ed25519").unlink()
        self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
        self.assertFalse((root / "return-receipt.ed25519").exists())
        self.assertEqual((root / "return-receipt.json").read_bytes(), published)

    def test_closed_replay_verifies_an_existing_signature_without_effects(self):
        stamp = self.ready()
        self.call("rollback", stamp, run="2")
        recorded = (self.root / "2/rollback.result").read_bytes()
        (self.root / stamp / "return-receipt.ed25519").write_bytes(bytes(64))
        before = list(self.rt.events)
        with self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_SIGNATURE_INVALID"):
            self.call("rollback", stamp, run="3")
        self.assertTrue(store.read(self.root / "3/rollback.review")["returnAlreadyConsumed"])
        self.assertFalse((self.root / "3/rollback.result").exists())
        self.assertEqual((self.root / "2/rollback.result").read_bytes(), recorded)
        self.assertEqual(self.rt.events, before)

    def test_signed_migration_requires_lock_of_approved_plan(self):
        self.dedicated()
        stamp = self.planned()["digest"]
        stage = self.call("apply", stamp)
        owner = self.root / "mcp.lock" / "owner.json"
        other = {"planSha256": "0" * 64}
        owner.write_text(json.dumps(other))
        with self.assertRaisesRegex(mandate.Held, "LOCK_OWNER_UNPROVEN"):
            self.call("migrate", stage["digest"])
        self.assertEqual(json.loads(owner.read_bytes()), other)
        self.assertNotIn("migrate", self.rt.events)
        self.assertFalse((self.root / stamp / "receipt.json").exists())

    def test_automatic_compensation_receipt_is_signed(self):
        self.dedicated()
        self.rt.migrate = Mock(side_effect=Held("MIGRATION_FAILED"))
        stamp = self.planned()["digest"]
        stage = self.call("apply", stamp)
        with self.assertRaisesRegex(mandate.Held, "MIGRATION_FAILED"):
            self.call("migrate", stage["digest"])
        receipt = json.loads(self.signed(stamp, "receipt"))
        self.assertEqual((receipt["status"], receipt["rollback"]), ("HELD", "ROLLED_BACK"))
        self.assertFalse((self.root / stamp / "return-receipt.json").exists())
        self.assertFalse((self.root / "mcp.lock").exists())

    def test_migrate_sign_failure_keeps_lock_and_only_publishes_held(self):
        self.dedicated()
        stamp = self.planned()["digest"]
        stage = self.call("apply", stamp)
        openssl = subprocess.run

        def fail_sign(argv, **kwargs):
            if "-sign" in argv:
                return subprocess.CompletedProcess(argv, 1, stdout=b"")
            return openssl(argv, **kwargs)

        with patch.object(module_receipt.subprocess, "run", side_effect=fail_sign), \
                self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_SIGN_FAILED"):
            self.call("migrate", stage["digest"])
        self.assertEqual(store.read(self.root / stamp / "receipt.json")["status"], "READY")
        self.assertEqual(store.read(self.root / "mcp.lock/owner.json"), {"planSha256": stamp})
        self.assertEqual(store.read(self.root / "1/migrate.held")["reason"], "MODULE_RECEIPT_SIGN_FAILED")
        self.assertFalse((self.root / "1/migrate.result").exists())
        self.assertFalse((self.root / stamp / "receipt.ed25519").exists())

    def test_lost_process_before_compensation_signature_is_completed_by_recovery(self):
        stamp = self.planned()["digest"]
        self.rt.fault = "handler"  # The candidate never proves its gate: automatic compensation.
        with patch.object(module_receipt, "sealer", return_value=Mock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):
            self.call("apply", stamp)
        root = self.root / stamp
        published = (root / "receipt.json").read_bytes()
        self.assertEqual(json.loads(published)["rollback"], "ROLLED_BACK")
        self.assertFalse((root / "receipt.ed25519").exists())
        self.assertTrue((self.root / "mcp.lock").is_dir())
        self.rt.fault = None
        with self.assertRaisesRegex(mandate.Held, "rollback=ROLLED_BACK"):
            self.recover()
        self.assertEqual(self.signed(stamp, "receipt"), published)
        self.assertFalse((self.root / "mcp.lock").exists())

    def test_compensation_recovery_refuses_foreign_failed_name_before_signing(self):
        stamp = self.planned()["digest"]
        with patch.object(self.rt, "stop", side_effect=Held("STOP_FAILED")), \
                patch.object(module_receipt, "sealer", return_value=Mock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):
            self.call("apply", stamp)
        directory = self.root / stamp
        published = (directory / "receipt.json").read_bytes()
        receipt = json.loads(published)
        self.assertEqual(receipt["rollback"], "ROLLED_BACK")
        self.assertNotIn("successorCid", receipt)
        request = dict(self.req, run="2", phase="plan")
        approved = self.call("plan", mandate.intent(request), approved=False, run="2")
        foreign = "f" * 64
        self.rt.docs[foreign] = dict(self.rt.inspect(OLD), Id=foreign, Name="/" + self.p["failedName"])
        with self.assertRaisesRegex(mandate.Held, "FAILED_NAME_OCCUPIED"):
            self.call("apply", approved["digest"], run="2")
        with self.assertRaisesRegex(mandate.Held, "FAILED_NAME_OCCUPIED"):
            self.recover("3")
        for run in ("2", "3"):
            held = store.read(self.root / run / "apply.held")
            self.assertEqual((held["reason"], held["residual"]["failedName"]["cid"]), ("FAILED_NAME_OCCUPIED", foreign))
            self.assertFalse((self.root / run / "apply.result").exists())
        self.assertEqual(store.read(self.root / "mcp.lock/owner.json"), {"planSha256": stamp})
        self.assertFalse((directory / "receipt.ed25519").exists())
        self.assertEqual((directory / "receipt.json").read_bytes(), published)

    def test_wrong_private_key_refuses_before_return(self):
        stamp = self.ready()
        other, other_public = self.root / "other-key", self.root / "other-public.der"
        self.keypair(other, other_public)
        self.p["receiptSigning"]["privateKey"] = str(other)
        with self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_KEY_MISMATCH"):
            self.call("rollback", stamp, run="2")
        self.assertEqual(self.rt.inspect(self.p["container"])["Id"], NEW)
        self.assertFalse((self.root / stamp / "return-receipt.json").exists())

    def test_tampered_return_signature_is_refused(self):
        stamp = self.ready()
        with patch.object(return_operation, "unlock_module", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        signature = self.root / stamp / "return-receipt.ed25519"
        for run, damaged in (("3", bytes(64)), ("4", b"short")):
            with self.subTest(run=run):
                signature.write_bytes(damaged)
                with self.assertRaisesRegex(mandate.Held, "MODULE_RECEIPT_SIGNATURE_INVALID"):
                    self.call("rollback", stamp, run=run)
                self.assertEqual(signature.read_bytes(), damaged)
                self.assertTrue((self.root / "mcp.lock").is_dir())
                self.assertEqual(store.read(self.root / run / "rollback.held")["reason"],
                                 "MODULE_RECEIPT_SIGNATURE_INVALID")
                self.assertFalse((self.root / run / "rollback.result").exists())
                self.assertFalse((self.root / "2/rollback.result").exists())
                self.assertFalse(verify_like_platform_reader(self.public, self.root / stamp / "return-receipt.json",
                                                            signature))


# Run only the signed-receipt cases here; the inherited MCP cases run in test_module_release_mcp.
for _name in [n for n in dir(mcp_tests.Release) if n.startswith("test_")]:
    if _name not in SignedReturn.__dict__:
        setattr(SignedReturn, _name, None)


if __name__ == "__main__":
    unittest.main()
