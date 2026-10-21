"""Persistent cutover ambiguity, version fencing and database boundaries."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

m = module('transition', 'tools/semantic_application_cutover/transition_journal.py')
j = module('journal', 'tools/semantic_lease_recovery/recovery_journal.py')
H = 'a' * 64
CONTEXT = m.Transition.initial(H, 'b'*64, 'c'*64, 'd'*64)['contextHash']


class TransitionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        Path(self.directory.name).chmod(0o700)
        self.store = j.Journal(self.directory.name)
        self.store.initialize(m.Transition.initial(H, 'b'*64, 'c'*64, 'd'*64))
        self.transition = m.Transition(self.store, CONTEXT)

    def apply(self, phase):
        row = self.transition.read()
        row = self.transition.begin(phase, H, H, row['version'])
        return self.transition.reconcile(phase, H, 'APPLIED', H, row['version'])

    def test_effect_stays_ambiguous_across_new_instance_and_authority(self):
        with self.transition.invocation():
            row = self.transition.begin(m.PHASES[0], H, H, 0)
        another = m.Transition(j.Journal(self.directory.name), CONTEXT)
        with another.invocation():
            with self.assertRaisesRegex(ValueError, 'RECONCILIATION'):
                another.begin(m.PHASES[0], 'e'*64, 'f'*64, row['version'])
            unknown = another.reconcile(m.PHASES[0], H, 'UNKNOWN', H, row['version'])
            self.assertEqual(unknown['state'], 'IN_FLIGHT')
            with self.assertRaisesRegex(ValueError, 'RECONCILIATION'):
                another.begin(m.PHASES[1], H, H, unknown['version'])

    def test_no_effect_is_consumed_and_new_hash_does_not_replay(self):
        with self.transition.invocation():
            row = self.transition.begin(m.PHASES[0], H, H, 0)
            row = self.transition.reconcile(m.PHASES[0], H, 'NO_EFFECT', H, row['version'])
            self.assertEqual(row['state'], 'NO_EFFECT_REQUIRES_NEW_DECISION')
            with self.assertRaisesRegex(ValueError, 'RECONCILIATION'):
                self.transition.begin(m.PHASES[0], 'e'*64, 'f'*64, row['version'])

    def test_database_boundary_persists_before_possible_effect(self):
        with self.transition.invocation():
            for phase in m.PHASES[:m.PHASES.index('ADMIT_MIGRATION')]: self.apply(phase)
            row = self.transition.begin('ADMIT_MIGRATION', H, H, self.transition.read()['version'])
            self.assertTrue(row['databaseMayHaveChanged'])
            self.assertFalse(row['preMigrationRestoreAllowed'])
        self.assertTrue(m.Transition(j.Journal(self.directory.name), CONTEXT).read()['databaseMayHaveChanged'])

    def test_write_boundary_and_completion_do_not_grant_acceptance(self):
        with self.transition.invocation():
            for phase in m.PHASES: self.apply(phase)
        row = self.transition.read()
        self.assertEqual(row['state'], 'COMPLETED')
        self.assertTrue(row['applicationWritesMayHaveOccurred'])
        self.assertFalse(row['releaseAcceptance'])
        self.assertEqual(row['predecessorHistoryHash'], 'c'*64)
        self.assertEqual(row['predecessorIncidentRef'], 'd'*64)

    def test_phase_skip_wrong_intent_and_stale_versions_denied(self):
        with self.transition.invocation():
            with self.assertRaisesRegex(ValueError, 'PHASE_ORDER'):
                self.transition.begin(m.PHASES[1], H, H, 0)
            row = self.transition.begin(m.PHASES[0], H, H, 0)
            with self.assertRaisesRegex(ValueError, 'INTENT_REQUIRED'):
                self.transition.reconcile(m.PHASES[0], 'e'*64, 'APPLIED', H, row['version'])
            with self.assertRaisesRegex(ValueError, 'VERSION_CONFLICT'):
                self.transition.reconcile(m.PHASES[0], H, 'APPLIED', H, 0)

    def test_exclusive_invocation_and_context_are_required(self):
        with self.assertRaisesRegex(ValueError, 'EXCLUSIVE_INVOCATION'):
            self.transition.begin(m.PHASES[0], H, H, 0)
        with self.transition.invocation():
            with self.assertRaises(BlockingIOError):
                with m.Transition(j.Journal(self.directory.name), CONTEXT).invocation(): pass
        with self.assertRaisesRegex(ValueError, 'CONTEXT_DRIFT'):
            m.Transition(self.store, 'e'*64).read()

    def test_tampered_migration_boundary_and_replay_flags_are_denied(self):
        with self.transition.invocation():
            for phase in m.PHASES[:m.PHASES.index('ADMIT_MIGRATION')+1]: self.apply(phase)
        previous = self.store.read(); changed = dict(previous); changed['databaseMayHaveChanged'] = False
        self.store.compare_and_save(previous, changed)
        with self.assertRaisesRegex(ValueError, 'MIGRATION_BOUNDARY_LOST'): self.transition.read()
        changed['preMigrationRestoreAllowed'] = True
        self.store.compare_and_save(self.store.read(), changed)
        with self.assertRaisesRegex(ValueError, 'POLICY_DRIFT'): self.transition.read()


if __name__ == '__main__': unittest.main()
