"""An incomplete creation can wait, but can never satisfy admission."""
import copy
import importlib.util
from pathlib import Path
import unittest

here = Path(__file__).resolve().parent
module_path = here.parent / 'semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py'
if not module_path.exists():
    module_path = here / 'cohort-draft/tools/semantic_provider_peer_bindings.py'
spec = importlib.util.spec_from_file_location('peer_creation_window', module_path)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class CreationWindow(unittest.TestCase):
    def setUp(self):
        self.peer = {'containerId': 'a'*64, 'applicationHash': 'b'*64}
        self.row = {'id': 'a'*64, 'status': 'stopped', 'pid': 0}
        self.journal = {'schema': 'ouf.semantic-docker-runtime-journal.v1',
            'containerId': 'a'*64, 'configurationHash': 'c'*64, 'state': 'CREATING',
            'runtimeRoot': '/run/test-runtime', 'bundleHash': 'b'*64, 'driverHash': None}
    def pending(self, row=None, journal=None):
        return p.creation_pending(self.row if row is None else row,
            self.journal if journal is None else journal, self.peer, '/run/test-runtime')
    def test_exact_partial_creation_can_only_wait(self):
        self.assertTrue(self.pending())
    def test_completed_failed_and_other_states_do_not_wait(self):
        for state in ('STAGED', 'CREATED', 'STARTED', 'FAILED', 'DENIED'):
            with self.subTest(state=state):
                journal = dict(self.journal, state=state)
                self.assertFalse(self.pending(journal=journal))
    def test_foreign_or_changed_journal_does_not_wait(self):
        for key, value in [('containerId','d'*64), ('bundleHash','d'*64),
            ('runtimeRoot','/run/foreign'), ('driverHash','d'*64),
            ('configurationHash','bad'), ('schema','foreign')]:
            with self.subTest(key=key):
                self.assertFalse(self.pending(journal=dict(self.journal, **{key:value})))
        self.assertFalse(self.pending(journal=dict(self.journal, extra=True)))
    def test_live_boolean_or_foreign_pid_is_not_partial_creation(self):
        for key, value in [('id','d'*64), ('status','running'), ('status','created'),
            ('pid',123), ('pid',False), ('pid','0')]:
            with self.subTest(key=key, value=value):
                self.assertFalse(self.pending(row=dict(self.row, **{key:value})))

if __name__ == '__main__': unittest.main()
