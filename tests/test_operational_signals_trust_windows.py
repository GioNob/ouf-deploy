"""Real published-policy fixture/validator; native custody is never relaxed in production."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.operational_signals import trust_windows as T
from tools import operational_signals as S
from test_semantic_b1b2_authority import policy, grant


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = policy()
        self.policy["keys"].append({**grant(), "keyRef": "second-key", "expiresAt": 2000})
        self.path = self.root / "policy.json"
        self.path.write_bytes(T.M.canonical(self.policy))
        self.inventory = {"schema": T.INVENTORY, "windows": [{"ref": "b1b2", "policyPath": str(self.path),
            "policySha256": hashlib.sha256(self.path.read_bytes()).hexdigest(), "liveConsumers": ["southbound", "adapter"]}]}
        self.inventory_path = self.root / "inventory.json"
        self.args = SimpleNamespace(inventory=str(self.inventory_path), inventory_sha256="", status_path=str(self.root / "status.json"))
        mock = patch.object(T.M, "private_bytes", side_effect=lambda path: path.read_bytes())
        mock.start(); self.addCleanup(mock.stop)
        self.publish()

    def publish(self):
        self.inventory_path.write_bytes(T.M.canonical(self.inventory))
        self.args.inventory_sha256 = hashlib.sha256(self.inventory_path.read_bytes()).hexdigest()

    def test_real_fixture_anchor_validator_earliest_expiry_and_no_consumers(self):
        for consumers in (["southbound", "adapter"], []):
            self.inventory["windows"][0]["liveConsumers"] = consumers
            self.publish()
            result = T.observe(self.args)
            self.assertEqual(set(result), {"schema", "checkedAt", "windows"})
            self.assertIs(type(result["checkedAt"]), int)
            self.assertEqual(result["schema"], T.SCHEMA)
            self.assertEqual(result["windows"], [{"ref": "b1b2", "policySha256": self.inventory["windows"][0]["policySha256"],
                "expiresAt": 2000, "liveConsumers": sorted(consumers)}])

    def test_base_anchor_expired_and_revoked_windows_remain_visible(self):
        value = {k: copy.deepcopy(v) for k, v in self.policy.items() if k not in {"basePolicy", "authorityProfile"}}
        value["schema"] = T.M.BASE_ANCHOR_SCHEMA
        for row in value["keys"]: row["roles"] = ["DEPLOYMENT_INTENT"]
        value["keys"][1].update(expiresAt=200, state="REVOKED")
        self.assertEqual(T.expiration(T.M.canonical(value)), 200)

    def test_hash_or_unreadable_input_leaves_status_untouched_and_public_failure(self):
        for failure in ("policy-hash", "inventory-hash", "unreadable"):
            self.publish()
            if failure == "policy-hash":
                self.inventory["windows"][0]["policySha256"] = "0"*64; self.publish()
            if failure == "inventory-hash": self.args.inventory_sha256 = "0"*64
            if failure == "unreadable": self.path.unlink()
            with patch.object(T, "arguments", return_value=self.args), patch.object(T, "atomic_status") as write, \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(T.main([]), 1)
            write.assert_not_called()
            self.assertFalse(Path(self.args.status_path).exists())
            self.assertRegex(output.getvalue(), r"\A[A-Z0-9_]{1,80}\n\Z")
            self.path.write_bytes(T.M.canonical(self.policy))
            self.inventory["windows"][0]["policySha256"] = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_strict_limits_duplicates_and_policy_validator(self):
        original = copy.deepcopy(self.inventory)
        for change in (lambda w: w.update(ref="INVALID"), lambda w: w.update(liveConsumers=["a"]*17),
                       lambda w: w.update(liveConsumers=["a", "a"]), lambda w: w.update(extra=True)):
            self.inventory = copy.deepcopy(original)
            change(self.inventory["windows"][0]); self.publish()
            with self.assertRaisesRegex(S.SignalError, "INVENTORY_INVALID"): T.observe(self.args)
        self.inventory = {"schema": T.INVENTORY, "windows": original["windows"]*17}; self.publish()
        with self.assertRaisesRegex(S.SignalError, "INVENTORY_INVALID"): T.observe(self.args)
        value = copy.deepcopy(self.policy); value["keys"][0]["expiresAt"] = True
        with self.assertRaises(T.M.MandateDenied): T.expiration(T.M.canonical(value))
        value = copy.deepcopy(self.policy); value["notAfter"] = 500
        with self.assertRaises(T.M.MandateDenied): T.expiration(T.M.canonical(value))

    def test_failed_refresh_keeps_existing_snapshot(self):
        path = Path(self.args.status_path); path.write_bytes(b"retained snapshot")
        self.args.inventory_sha256 = "0"*64
        with patch.object(T, "arguments", return_value=self.args), redirect_stdout(io.StringIO()):
            self.assertEqual(T.main([]), 1)
        self.assertEqual(path.read_bytes(), b"retained snapshot")

    def test_inventory_bounds_and_empty_list(self):
        self.inventory["windows"] = []; self.publish()
        self.assertEqual(T.observe(self.args)["windows"], [])
        with self.assertRaises(T.M.MandateDenied):
            T.M.decode(b'{"schema":"x","schema":"y"}')

    def test_success_and_destination_cannot_overwrite_policy(self):
        with patch.object(T, "arguments", return_value=self.args), patch.object(T, "atomic_status") as write, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(T.main([]), 0)
        self.assertEqual(write.call_args.args[1]["windows"][0]["expiresAt"], 2000)
        self.args.status_path = str(self.path)
        with patch.object(T, "arguments", return_value=self.args), patch.object(T, "atomic_status") as write, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(T.main([]), 1)
        write.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and getattr(os, "geteuid", lambda: -1)() == 0,
                     "real root custody requires Linux root")
class NativeCustodyTests(unittest.TestCase):
    def test_real_custody_symlink_hash_and_atomic_0600(self):
        with tempfile.TemporaryDirectory(prefix="ouf-trust-window-", dir="/var/lib") as folder:
            root = Path(folder)
            path = root / "policy.json"; path.write_bytes(T.M.canonical(policy())); path.chmod(0o600)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(T.expiration(T.pinned(str(path), digest)), 2100000000)
            link = root / "link.json"; link.symlink_to(path)
            with self.assertRaises(T.M.MandateDenied): T.pinned(str(link), digest)
            path.chmod(0o644)
            with self.assertRaises(T.M.MandateDenied): T.pinned(str(path), digest)
            status = root / "status.json"
            S.atomic_status(status, {"schema": T.SCHEMA, "checkedAt": 1, "windows": []})
            info = status.stat()
            self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (0, 0, 0o600))


if __name__ == "__main__":
    unittest.main()
