"""Real issued-role readback and explicit non-authenticating entry boundaries."""
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_authority as fixture
from tools.ingestion_rollout_execution import entry as e,authority as a,contract as c

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real role issuance and private custody required')
class NativeEntry(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.NativeIssuer();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.action=self.fixture.issue();self.review=self.fixture.review
        self.decision_hash=c.digest(self.fixture.decision)
        self.mandate_hash=hashlib.sha256((self.fixture.context/'human.json').read_bytes()).hexdigest()
    def load(self):
        with patch.object(a,'verify_closure'):
            return e.load_action(self.review,self.fixture.decision,self.fixture.human,self.decision_hash,self.mandate_hash)
    def test_read_existing_issued_artifacts_never_reissues_or_resets(self):
        before={p.name:p.read_bytes()for p in self.fixture.context.iterdir()if p.is_file()}
        with patch.object(a,'issue_action')as issue:
            loaded=self.load();issue.assert_not_called()
        self.assertEqual(loaded.authority_hash,self.action.authority_hash)
        self.assertTrue(loaded.guard(c.AUTHORITY_KEY,c.scope(self.fixture.native_review)))
        self.assertEqual(before,{p.name:p.read_bytes()for p in self.fixture.context.iterdir()if p.is_file()})
    def test_missing_independent_approval_or_changed_mandate_blocks(self):
        self.mandate_hash='0'*64
        with self.assertRaises(c.Denied):self.load()
        self.mandate_hash=None
        with self.assertRaises(c.Denied):self.load()
    def test_disk_import_or_implicit_mode_cannot_dispatch_or_initialize(self):
        for mode in('step','reconcile','initialize','auto'):
            with patch.object(e,'NativePorts')as ports:
                with self.assertRaises(c.Denied):e.execute(mode,self.review,self.fixture.fixture.packet,
                    self.fixture.human,self.action,self.review['sourceClosure']['declaration'])
                ports.assert_not_called()
    def test_completed_owner_authority_or_extra_scope_is_not_a_rollout_envelope(self):
        import json
        raw=json.loads(self.action.raw);raw['chatbotFileAuthorization']={'allowed':True}
        with self.assertRaises(c.Denied):e.validate_raw(self.review,c.encoded(raw))
        raw.pop(c.AUTHORITY_KEY)
        with self.assertRaises(c.Denied):e.validate_raw(self.review,c.encoded(raw))

if __name__=='__main__':unittest.main()
