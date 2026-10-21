"""Actual root-owned POSIX input boundaries; no OCI/target acceptance claim."""
import hashlib,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from projected_frame_observation import ProjectedFrameObservation
from tools.semantic_provider_deployment_authentication import VerificationBudget,PreexecDenied

class Custody(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.task=self.root/'tasks';self.task.mkdir(mode=0o700);self.bundle=self.task/('a'*64);self.bundle.mkdir(mode=0o700)
        self.oci=self.bundle/'config.json';self.oci.write_bytes(b'{}');self.oci.chmod(0o644)
        self.owner=self.root/'owner.py';self.owner.write_bytes((ROOT/'tools/semantic_frame_compiler/frame-observer.py').read_bytes());self.owner.chmod(0o600)
        self.policy=self.root/'policy.json';self.policy.write_bytes(b'{}');self.policy.chmod(0o600)
        self.cfg={k:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for k,p in [('source',self.owner),('configuration',self.policy)]};self.cfg['bundleParents']=[str(self.task)]
    def observer(self):return ProjectedFrameObservation(self.cfg,VerificationBudget(18))
    def test_generated_readonly_bundle_and_private_policy_custody_are_distinct(self):
        self.assertEqual(self.observer().bundle(self.oci),b'{}');self.observer().pinned()
        self.policy.chmod(0o644)
        with self.assertRaises(PreexecDenied):self.observer().pinned()
    def test_other_parent_symlink_and_writable_bundle_denied(self):
        other=self.root/'config.json';other.write_bytes(b'{}');other.chmod(0o644)
        with self.assertRaises(ValueError):self.observer().bundle(other)
        self.oci.chmod(0o666)
        with self.assertRaises(ValueError):self.observer().bundle(self.oci)
        self.oci.unlink();self.oci.symlink_to(other)
        with self.assertRaises(OSError):self.observer().bundle(self.oci)
    def test_embedded_owner_source_drift_never_executes_wrapper(self):
        raw=self.owner.read_bytes();self.observer().owner(raw)
        damaged=raw.replace(b'Typed complete OCI document review',b'Altered complete OCI document review',1)
        with self.assertRaises(ValueError):self.observer().owner(damaged)

if __name__=='__main__':unittest.main()
