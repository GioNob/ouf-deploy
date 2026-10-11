import copy
import importlib.util
from pathlib import Path
import unittest

s = importlib.util.spec_from_file_location('preflight', Path(__file__).resolve().parents[1] / 'scripts/read-new-finite-recovery-preflight.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

class Tests(unittest.TestCase):
    def fixture(self):
        auth = {'schema': 'ouf.provider-finite-lease-recovery-authorization.v1', 'ownerConfigurationHash': m.OWNER_HASH,
                'serviceUnit': m.UNIT, 'programHashes': copy.deepcopy(m.PROGRAMS), 'automaticRestart': False,
                'enableAtBoot': False, 'containerLifecycleAuthorized': False, 'approvalRef': 'FIXTURE_ONLY'}
        claim = {'directory': str(m.ROOT), 'approvalRef': 'FIXTURE_ONLY', 'startAuthorized': False}
        receipt = {'status': 'TWO_FLOW_LEASE_ACTIVE_AND_RENEWED', 'doNotRerunApply': True,
                   'ownerConfigurationHash': m.OWNER_HASH, 'serviceUnit': m.UNIT}
        denial = {'status': 'LEASE_WORKER_FAILED', 'refreshCount': 250, 'doNotRerunApply': True}
        return auth, claim, receipt, denial
    def test_own_consumed_context_is_observation_only(self):
        values = self.fixture(); before = copy.deepcopy(values)
        self.assertIsNone(m.validate_artifacts(*values)); self.assertEqual(values, before)
    def test_start_restart_boot_or_lifecycle_authority_drift_denied(self):
        for key in ('automaticRestart', 'enableAtBoot', 'containerLifecycleAuthorized'):
            values = self.fixture(); values[0][key] = True
            with self.assertRaises(ValueError): m.validate_artifacts(*values)
        values = self.fixture(); values[1]['startAuthorized'] = True
        with self.assertRaises(ValueError): m.validate_artifacts(*values)
    def test_foreign_claim_service_or_program_cannot_be_adopted(self):
        for index, key, value in ((1, 'directory', '/etc/foreign'), (1, 'approvalRef', 'foreign'), (0, 'serviceUnit', 'foreign')):
            values = self.fixture(); values[index][key] = value
            with self.assertRaises(ValueError): m.validate_artifacts(*values)
        values = self.fixture(); values[0]['programHashes']['reader.py'] = 'foreign'
        with self.assertRaises(ValueError): m.validate_artifacts(*values)
    def test_success_receipt_never_overrides_current_failure_or_consumption(self):
        for key, value in (('status', 'LEASE_ACTIVE'), ('refreshCount', True), ('refreshCount', 249), ('doNotRerunApply', False)):
            values = self.fixture(); values[3][key] = value
            with self.assertRaises(ValueError): m.validate_artifacts(*values)

if __name__ == '__main__': unittest.main()
