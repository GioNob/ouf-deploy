"""Canonical parent and concrete-owner boundaries, no target initialization."""
import sys,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_current_admission  # Complete established source import roots.
from tools.semantic_registry_recovery_execution import core as c,factory as f,native as n

class FactoryBoundaries(unittest.TestCase):
    def test_same_logical_operation_cannot_move_to_a_second_evidence_parent(self):
        logical='a'*64
        original={'directoryPlan':{'root':'/fixture/ente-a/evidence/old-action/registry'}}
        selected=f.canonical_root('/fixture/ente-a/evidence/history/inputs.json',logical)
        self.assertEqual(selected,Path('/fixture/ente-a/evidence/semantic-registry-recovery-'+logical))
        f.require_historical_parent(original,selected)
        for copied in ('/fixture/ente-b/evidence/history/inputs.json','/fixture/other-history/inputs.json'):
            with self.subTest(path=copied),self.assertRaisesRegex(c.RecoveryDenied,'RETAINED_INSTALLATION_EVIDENCE_PARENT'):
                f.require_historical_parent(original,f.canonical_root(copied,logical))

    def test_relative_or_traversing_retained_location_is_refused(self):
        for path in ('relative/inputs.json','/fixture/../other/inputs.json'):
            with self.assertRaises(c.RecoveryDenied):f.canonical_root(path,'a'*64)

    def test_callbacks_and_passed_booleans_are_not_native_owners(self):
        fake=SimpleNamespace(guard=lambda:True,verify=lambda:True,lifecycle=None)
        for objects in ((fake,fake,fake,fake),(True,True,True,True),(lambda:True,)*4):
            with self.assertRaisesRegex(c.RecoveryDenied,'ACTUAL_RECOVERY_NATIVE_OWNERS'):n.NativePorts(*objects)

if __name__=='__main__':unittest.main()
