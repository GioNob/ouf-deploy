import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles/seaweedfs-452-lab/profile.json"
SPEC = importlib.util.spec_from_file_location(
    "storage_recovery_profile", ROOT / "tools/storage_recovery/profile.py"
)
profile_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile_module)


class StorageRecoveryProfileTest(unittest.TestCase):
    def profile(self):
        return json.loads(PROFILE.read_text(encoding="utf-8"))

    def test_exact_synthetic_profile_passes_without_authority(self):
        value = self.profile()
        self.assertIs(profile_module.validate_profile(value), value)
        self.assertEqual(len(profile_module.profile_sha256(value)), 64)
        self.assertFalse(value["authority"]["releaseAdmitted"])
        self.assertFalse(value["authority"]["runtimeAuthorityIssued"])
        self.assertEqual(value["authority"]["targetOperations"], 0)

    def test_candidate_identity_is_exact(self):
        changes = {
            "version": "4.51",
            "orderedPatchCount": 20,
            "binarySha256": "0" * 64,
            "lockSha256": "0" * 64,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                profile = self.profile()
                profile["candidate"][field] = value
                with self.assertRaisesRegex(profile_module.ProfileError, "EXACT_CANDIDATE_REQUIRED"):
                    profile_module.validate_profile(profile)

    def test_authority_or_acceptance_claim_is_rejected(self):
        for field, value in (
            ("releaseAdmitted", True),
            ("runtimeAuthorityIssued", True),
            ("targetOperations", 1),
            ("acceptanceClaimed", True),
            ("syntheticOnly", False),
        ):
            with self.subTest(field=field):
                profile = self.profile()
                profile["authority"][field] = value
                with self.assertRaisesRegex(profile_module.ProfileError, "SYNTHETIC_ZERO_AUTHORITY_REQUIRED"):
                    profile_module.validate_profile(profile)

    def test_non_loopback_or_egress_is_rejected(self):
        profiles = []
        non_loopback = self.profile()
        non_loopback["roles"][0]["listenHosts"] = ["0.0.0.0"]
        profiles.append(non_loopback)
        egress = self.profile()
        egress["isolation"]["externalEgress"] = True
        profiles.append(egress)
        target = self.profile()
        target["isolation"]["targetEndpointsAllowed"] = True
        profiles.append(target)
        for value in profiles:
            with self.assertRaises(profile_module.ProfileError):
                profile_module.validate_profile(value)

    def test_role_set_paths_and_hardening_are_fail_closed(self):
        duplicate = self.profile()
        duplicate["roles"][1]["persistentPath"] = duplicate["roles"][0]["persistentPath"]
        with self.assertRaisesRegex(profile_module.ProfileError, "DISTINCT"):
            profile_module.validate_profile(duplicate)

        missing = self.profile()
        missing["roles"].pop()
        with self.assertRaisesRegex(profile_module.ProfileError, "EXACT_SEPARATED_ROLES_REQUIRED"):
            profile_module.validate_profile(missing)

        root = self.profile()
        root["roles"][0]["runAsUid"] = 0
        with self.assertRaisesRegex(profile_module.ProfileError, "NONROOT"):
            profile_module.validate_profile(root)

        writable = self.profile()
        writable["roles"][0]["readOnlyRootFilesystem"] = False
        with self.assertRaisesRegex(profile_module.ProfileError, "HARDENING"):
            profile_module.validate_profile(writable)

    def test_unknown_fields_and_relaxed_backup_policy_are_rejected(self):
        extra = self.profile()
        extra["targetEndpoint"] = "https://example.invalid"
        with self.assertRaisesRegex(profile_module.ProfileError, "PROFILE_FIELDS_INVALID"):
            profile_module.validate_profile(extra)

        symlinks = self.profile()
        symlinks["backupPolicy"]["allowSymlinks"] = True
        with self.assertRaisesRegex(profile_module.ProfileError, "FAIL_CLOSED"):
            profile_module.validate_profile(symlinks)

        unbounded = self.profile()
        unbounded["backupPolicy"]["maximumTotalBytes"] = 9 * 1024**3
        with self.assertRaisesRegex(profile_module.ProfileError, "BOUNDED"):
            profile_module.validate_profile(unbounded)


if __name__ == "__main__":
    unittest.main()
