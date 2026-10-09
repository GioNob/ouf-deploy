"""Review/recovery rejection and sealed consumer wiring; CI is not authority."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import execute_post_signature_recovery as recovery

class PostSignatureRecoveryTests(unittest.TestCase):
    def facts(self):
        denial={'stage':'VERIFY_RUNTIME_SWITCH','reason':'GUARDED_RUNTIME_SWITCH_UNPROVEN',
            'switchOutcome':'UNCHANGED','renameAttempted':False,'wrapperReplaced':False}
        roles={r:{'status':'ROLE_RECORDS_ISSUED','signaturesIssued':4,'startPerformed':False}
            for r in ('adapter','southbound')}
        return denial,{n:False for n in recovery.CLAIMS},roles,81

    def test_pending_human_scope_blocks_before_file_access(self):
        with patch('os.open',side_effect=AssertionError('file access before approval')):
            with self.assertRaisesRegex(ValueError,'EXPLICIT_POST_SIGNATURE_RECOVERY_APPROVAL_REQUIRED'):
                recovery.main('anything','/nonexistent')

    def test_exact_retained_eight_signature_failure_accepted_for_review(self):
        recovery.validate_retained_failure(*self.facts())

    def test_any_switch_or_cohort_claim_forbids_recovery(self):
        for name in recovery.CLAIMS:
            args=list(self.facts());args[1][name]=True
            with self.assertRaisesRegex(ValueError,'NO_SWITCH_OR_COHORT_CLAIM_REQUIRED'):
                recovery.validate_retained_failure(*args)

    def test_unknown_or_changed_switch_outcome_forbids_recovery(self):
        for field,value in (('renameAttempted',None),('wrapperReplaced',True),('switchOutcome','CHANGED')):
            args=list(self.facts());args[0][field]=value
            with self.assertRaisesRegex(ValueError,'EXACT_PRE_SWITCH_FAILURE_REQUIRED'):
                recovery.validate_retained_failure(*args)

    def test_incomplete_issuance_or_publication_forbids_recovery(self):
        for value in (None,True,3):
            args=list(self.facts());args[2]['adapter']['signaturesIssued']=value
            with self.assertRaisesRegex(ValueError,'EXACT_EIGHT_RETAINED_SIGNATURES_REQUIRED'):
                recovery.validate_retained_failure(*args)
        args=list(self.facts());args[3]=80
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_PUBLICATION_REQUIRED'):
            recovery.validate_retained_failure(*args)

    def test_embedded_repair_matches_repository_and_updates_imported_consumer(self):
        profiles=Path(__file__).resolve().parent.parent/'semantic_transaction_profiles'
        sys.path.insert(0,str(profiles))
        import test_authenticated_transaction  # sets sealed dependency paths
        import authenticated_runtime_switch as factory
        import guarded_runtime_switch as guard
        import docker_cohort_activation as cohort
        original=factory.make_locked_switch_verifier
        for name,item in recovery.UTILITIES.items():
            self.assertEqual(hashlib.sha256((profiles/(name+'.py')).read_bytes()).hexdigest(),item['sha256'])
        saved=[(m,m.__dict__.copy()) for m in (factory,guard,cohort)]
        try:
            recovery.install_repairs(lambda b:hashlib.sha256(b).hexdigest())
            self.assertIsNot(factory.make_locked_switch_verifier,original)
            self.assertIs(cohort.make_locked_switch_verifier,factory.make_locked_switch_verifier)
        finally:
            for module,values in saved:module.__dict__.clear();module.__dict__.update(values)

if __name__=='__main__':unittest.main()
