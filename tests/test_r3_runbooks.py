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
                                         "r3-upgrade-v7.sh", "r3-operate.sh")]
FETCH = re.compile(r"^  fetch (\S+) ([0-9a-f]{64})$", re.M)
PIN = re.compile(r"^C=([0-9a-f]{40})$", re.M)
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
        self.assertEqual(paths, CLOSURE | set(C.SOURCE_INPUTS) | set(C.SOURCE_INPUTS_V6))

    def test_hashes_are_lf_blobs_at_head(self):
        for path, digest in self.deliveries[0]:
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
