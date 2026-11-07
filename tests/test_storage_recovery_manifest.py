import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.storage_recovery import manifest as recovery


PROFILE = ROOT / "profiles/seaweedfs-452-lab/profile.json"


class StorageRecoveryManifestTest(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "source"
        self.source.mkdir()
        self.files = {
            "config_snapshot": "config/profile.json",
            "filer_metadata": "filer/metadata.db",
            "master_metadata": "master/state.bin",
            "postgres_dump": "postgres/fixture.sql",
            "volume_data": "volume/0001.dat",
        }
        for number, (kind, relative) in enumerate(self.files.items(), start=1):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((kind + "\n").encode() * number)

    def artifacts(self, generation="generation-0001"):
        return [
            recovery.record_artifact(
                self.source,
                relative,
                logical_id=f"artifact-{kind.replace('_', '-')}",
                kind=kind,
                generation=generation,
            )
            for kind, relative in self.files.items()
        ]

    def manifest(self, artifacts=None):
        return recovery.build_manifest(
            self.profile,
            self.artifacts() if artifacts is None else artifacts,
            backup_id="lab-backup-0001",
            created_at="2026-11-03T16:00:00Z",
            writer_fence={
                "status": "CONFIRMED",
                "generation": "generation-0001",
                "evidenceSha256": hashlib.sha256(b"synthetic writer fence").hexdigest(),
            },
        )

    def test_manifest_binds_all_required_components_and_zero_authority(self):
        manifest = self.manifest()
        self.assertIs(recovery.validate_manifest(self.profile, manifest), manifest)
        self.assertEqual(manifest["totals"]["artifacts"], 5)
        self.assertEqual(
            [row["kind"] for row in manifest["artifacts"]],
            self.profile["backupPolicy"]["requiredArtifactKinds"],
        )
        self.assertFalse(manifest["authority"]["releaseAdmitted"])
        self.assertEqual(manifest["authority"]["targetOperations"], 0)

    def test_record_rejects_traversal_symlink_and_empty_file(self):
        with self.assertRaisesRegex(recovery.ManifestError, "RELATIVE_PATH"):
            recovery.record_artifact(
                self.source,
                "../escape",
                logical_id="artifact-escape",
                kind="config_snapshot",
                generation="generation-0001",
            )

        target = self.source / "config/profile.json"
        link = self.source / "link"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink unavailable: {error}")
        with self.assertRaisesRegex(recovery.ManifestError, "SYMLINK_FORBIDDEN"):
            recovery.record_artifact(
                self.source,
                "link",
                logical_id="artifact-link",
                kind="config_snapshot",
                generation="generation-0001",
            )
        empty = self.source / "empty"
        empty.touch()
        with self.assertRaisesRegex(recovery.ManifestError, "EMPTY"):
            recovery.record_artifact(
                self.source,
                "empty",
                logical_id="artifact-empty",
                kind="config_snapshot",
                generation="generation-0001",
            )

    def test_manifest_rejects_missing_component_duplicates_and_generation_drift(self):
        with self.assertRaisesRegex(recovery.ManifestError, "EXACT_SORTED_BACKUP_COMPONENT"):
            self.manifest(self.artifacts()[:-1])

        duplicate = self.artifacts()
        duplicate[1]["logicalId"] = duplicate[0]["logicalId"]
        with self.assertRaisesRegex(recovery.ManifestError, "DUPLICATE_ARTIFACT_LOGICAL_ID"):
            self.manifest(duplicate)

        drift = self.artifacts()
        drift[0]["generation"] = "generation-0002"
        with self.assertRaisesRegex(recovery.ManifestError, "GENERATION_MISMATCH"):
            self.manifest(drift)

    def test_manifest_tamper_and_authority_escalation_are_rejected(self):
        manifest = self.manifest()
        changed_total = copy.deepcopy(manifest)
        changed_total["totals"]["bytes"] += 1
        with self.assertRaisesRegex(recovery.ManifestError, "TOTALS_MISMATCH"):
            recovery.validate_manifest(self.profile, changed_total)

        admitted = copy.deepcopy(manifest)
        admitted["authority"]["releaseAdmitted"] = True
        with self.assertRaisesRegex(recovery.ManifestError, "ZERO_AUTHORITY"):
            recovery.validate_manifest(self.profile, admitted)

        changed_profile = copy.deepcopy(self.profile)
        changed_profile["backupPolicy"]["maximumArtifactBytes"] -= 1
        with self.assertRaisesRegex(recovery.ManifestError, "PROFILE_MISMATCH"):
            recovery.validate_manifest(changed_profile, manifest)

    def test_restore_plan_is_independent_and_not_executed(self):
        manifest = self.manifest()
        plan = recovery.plan_restore(
            self.profile, manifest, "/var/lib/ouf-lab/restore/lab-backup-0001"
        )
        self.assertEqual(plan["status"], "PLANNED_NOT_EXECUTED")
        self.assertTrue(plan["environmentMustStartEmpty"])
        self.assertTrue(plan["originalsMustRemainInaccessible"])
        self.assertEqual(plan["authority"]["targetOperations"], 0)

        for forbidden in (
            "/var/lib/ouf-lab/restore",
            "/var/lib/ouf-lab/seaweedfs-452/filer",
            "/tmp/restore",
            "relative/restore",
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(recovery.ManifestError):
                    recovery.plan_restore(self.profile, manifest, forbidden)

    def test_read_only_verification_detects_tamper_and_makes_no_rpo_rto_claim(self):
        manifest = self.manifest()
        runtime_root = Path(self.temporary.name) / "restored"
        runtime_root.mkdir()
        for relative in self.files.values():
            destination = runtime_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.source / relative, destination)

        plan = recovery.plan_restore(
            self.profile, manifest, "/var/lib/ouf-lab/restore/lab-backup-0001"
        )
        result = recovery.verify_restore(self.profile, manifest, plan, runtime_root)
        self.assertEqual(result["verifiedArtifacts"], 5)
        self.assertFalse(result["rpoMeasured"])
        self.assertFalse(result["rtoMeasured"])
        self.assertFalse(result["postgresCoordinatedRecoveryQualified"])
        self.assertFalse(result["targetE2E"])

        (runtime_root / self.files["volume_data"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(recovery.ManifestError, "RESTORED_ARTIFACT_MISMATCH"):
            recovery.verify_restore(self.profile, manifest, plan, runtime_root)


if __name__ == "__main__":
    unittest.main()
