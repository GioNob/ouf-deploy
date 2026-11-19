"""Contract of ops/vps/r3-{issue,install,restore}.sh: one delivery, LF blobs, full closure."""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNBOOKS = [ROOT / "ops/vps" / n for n in ("r3-issue.sh", "r3-install.sh", "r3-restore.sh",
                                         "r3-issue-v2.sh", "r3-upgrade-v2.sh", "r3-issue-v3.sh",
                                         "r3-upgrade-v3.sh", "r3-issue-v4.sh",
                                         "r3-upgrade-v4.sh", "r3-issue-v5.sh",
                                         "r3-upgrade-v5.sh", "r3-issue-v6.sh",
                                         "r3-upgrade-v6.sh", "r3-issue-v7.sh",
                                         "r3-upgrade-v7.sh", "r3-issue-v8.sh",
                                         "r3-upgrade-v8.sh", "r3-issue-v9.sh",
                                         "r3-upgrade-v9.sh", "r3-operate.sh")]
FETCH = re.compile(r"^  fetch (\S+) ([0-9a-f]{64})$", re.M)
PIN = re.compile(r"^C=([0-9a-f]{40})$", re.M)
# These host-side tools evolve with v16. Legacy runbooks fetch their pinned blobs.
VERSIONED_TOOLS = {"tools/semantic_provider_r3/" + name for name in
                   ("compose.py", "install_common.py", "operate.py")}
# Import closure of the issuer/installer/restore entrypoints (traced with the real interpreter,
# task-41c review) plus the 29b switch boundary reused unchanged by install_common.native_switch.
CLOSURE = {
    "scripts/issue-semantic-provider-operation-authorization.py",
    "scripts/install-semantic-provider-r3.py", "scripts/restore-semantic-provider-r3.py",
    "ops/vps/r3-settings.json",
    "tools/semantic_acceptance_v51/__init__.py", "tools/semantic_acceptance_v51/issuance.py",
    "tools/semantic_b1_acceptance/__init__.py", "tools/semantic_b1_acceptance/acceptance.py",
    "tools/semantic_b1b2_authority/__init__.py", "tools/semantic_b1b2_authority/authority.py",
    "tools/semantic_frame_compiler/compile_creation_frame_policy.py",
    "tools/semantic_provider_admission_v2/__init__.py", "tools/semantic_provider_admission_v2/broker_v2.py",
    "tools/semantic_provider_admission_v2/consumption_v2.py", "tools/semantic_provider_admission_v2/driver_v7.py",
    "tools/semantic_provider_admission_v2/evidence_v2.py", "tools/semantic_provider_admission_v2/preparer_v2.py",
    "tools/semantic_provider_admission_v2/reauthorization_v2.py",
    "tools/semantic_provider_operation/__init__.py", "tools/semantic_provider_operation/authorization.py",
    "tools/semantic_provider_r3/__init__.py", "tools/semantic_provider_r3/compose.py",
    "tools/semantic_provider_r3/install_common.py",
    "tools/semantic_provider_r3/operate.py", "scripts/operate-semantic-provider-r3.py",
    # D-047 (task-59): volatile restore before start, plus the unchanged rootfs v3 modules it imports.
    "tools/semantic_provider_r3/volatile_restore.py",
    "scripts/prepare-semantic-provider-b1-rootfs-v3.py", "scripts/prepare-semantic-provider-b1-rootfs.py",
    "tools/semantic_image_rootfs/prepare_provider_image_rootfs.py",
    "tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py",
    "tools/semantic_stopped_rootfs/rootfs_difference_report.py",
    "tools/semantic_stopped_rootfs/rootfs_image_equivalence.py",
    # D-050 (task-65): governed lease-kernel migration, delivered for r3-lease-kernel.sh.
    "scripts/migrate-semantic-lease-kernel.py",
    # D-051 (task-67): v13 identity-provider overlay (imported by compose) and its read-only reader.
    "tools/semantic_provider_r3/identity_overlay_v13.py", "tools/semantic_provider_r3/read_identity_provider_v13.py",
    # D-053.3: v16 driver-denial overlay, imported by compose and by install_common (operate/probe).
    "tools/semantic_provider_r3/driver_denial_overlay_v16.py",
    # R-030 (task-74): v17 driver budget overlay and its pinned installation input.
    "tools/semantic_provider_r3/driver_budget_v17.py", "ops/vps/r3-driver-budget.json",
    # R-022 (task-76/77/78): v18 lease renewal and observability overlays and their pinned input.
    "tools/semantic_provider_r3/lease_renewal_v18.py", "tools/semantic_provider_r3/lease_renewal_overlay_v18.py",
    "tools/semantic_provider_r3/lease_observability_overlay_v18.py", "ops/vps/r3-lease-renewal.json",
    # R-031 (task-81): supersession gate imported by the issuer.
    "tools/semantic_provider_operation/supersede_gate.py",
    # R-031 (task-82): v19 runtime overlay (kill/delete passthrough on proven-absent terminal epochs).
    "tools/semantic_provider_r3/runtime_absent_overlay_v19.py",
    # R-022 (task-90): v20 DNS UDP retransmission overlay.
    "tools/semantic_provider_r3/dns_retransmit_overlay_v20.py",
    # R-022 (task-97): v21 renewal timing observability overlay.
    "tools/semantic_provider_r3/lease_timing_overlay_v21.py",
    # R-022 (task-104): v22 renewal band, composed budgets, parallel DNS and its input.
    "tools/semantic_provider_r3/renewal_overlay_v22.py", "tools/semantic_provider_r3/dns_parallel_overlay_v22.py",
    "ops/vps/r3-lease-renewal-v22.json",
    # R-022 (task-105): v23 DNS cache rollover overlay.
    "tools/semantic_provider_r3/cache_rollover_overlay_v23.py",
    # R-022 (task-109): v24 supervised cache wait overlay.
    "tools/semantic_provider_r3/cache_watch_overlay_v24.py",
    *("tools/semantic_lease_kernel_migration/" + n for n in (
        "__init__.py", "boot_dispatcher.py", "boot_runner_v2.py", "cli.py", "migration.py", "native.py")),
    "tools/semantic_provider_r3/upgrade.py", "scripts/upgrade-semantic-provider-r3.py",
    "tools/semantic_runtime_v51_install/__init__.py", "tools/semantic_runtime_v51_install/common.py",
    "tools/semantic_transaction_profiles/guarded_runtime_switch.py",
    "tools/semantic_transaction_profiles/authenticate_provider_transaction.py",
    "tools/semantic_transaction_profiles/assemble_provider_profiles.py",
    "tools/semantic_transaction_profiles/publish_provider_transaction.py",
    *("tools/semantic_cohort_admission/cohort-draft/tools/" + n + ".py" for n in (
        "semantic_provider_deployment_authentication", "semantic_provider_deployment_protocol",
        "semantic_provider_preexec", "semantic_provider_deployment_admission", "materialize_semantic_shared_faces",
        "materialize_southbound_kernel", "semantic_provider_preexec_native", "semantic_provider_peer_bindings",
        "semantic_provider_lease_coordination", "semantic_provider_lease_nft")),
}


def blob(rev, path):
    return subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{path}"], capture_output=True, check=True).stdout


class R3Runbooks(unittest.TestCase):
    def setUp(self):
        self.texts = [p.read_text(encoding="utf-8") for p in RUNBOOKS]
        self.deliveries = [FETCH.findall(t) for t in self.texts]

    def test_same_delivery_in_all_three(self):
        self.assertTrue(self.deliveries[0])
        for other in self.deliveries[1:]:
            self.assertEqual(self.deliveries[0], other)

    def test_delivery_is_exact_closure(self):
        sys.path.insert(0, str(ROOT))
        try:
            from tools.semantic_provider_r3 import compose as C
        finally:
            sys.path.remove(str(ROOT))
        paths = {p for p, _ in self.deliveries[0]}
        # One delivery serves v1-5 (observer v1) and v6 (observer v2).
        self.assertEqual(paths, CLOSURE | set(C.SOURCE_INPUTS) | set(C.SOURCE_INPUTS_V6) | set(C.SOURCE_INPUTS_V11)
                         | set(C.SOURCE_INPUTS_V12) | set(C.SOURCE_INPUTS_V13)
                         | set(C.SOURCE_INPUTS_V15) | set(C.SOURCE_INPUTS_V16)
                         | set(C.SOURCE_INPUTS_V17) | set(C.SOURCE_INPUTS_V18) | set(C.SOURCE_INPUTS_V19) | set(C.SOURCE_INPUTS_V20) | set(C.SOURCE_INPUTS_V21) | set(C.SOURCE_INPUTS_V22) | set(C.SOURCE_INPUTS_V23) | set(C.SOURCE_INPUTS_V24))

    def test_sealed_hashes_are_lf_blobs_at_head(self):
        for path, digest in self.deliveries[0]:
            if path in VERSIONED_TOOLS:
                continue
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(blob("HEAD", path)).hexdigest(), digest)

    def test_pinned_commit_serves_the_same_blobs(self):
        pins = {PIN.search(t).group(1) for t in self.texts}
        self.assertEqual(len(pins), 1)
        commit = pins.pop()
        if commit == "0" * 40:
            self.skipTest("runbooks not pinned yet")
        for path, digest in self.deliveries[0]:
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(blob(commit, path)).hexdigest(), digest)

    def test_no_container_start_or_restart_policy(self):
        for text in self.texts:
            for word in ("docker start", "docker update", "docker run", "--restart"):
                self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
