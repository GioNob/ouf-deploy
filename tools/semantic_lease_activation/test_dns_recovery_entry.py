import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import activate_dns_recovery as target


class RecoveryBoundary(unittest.TestCase):
    def test_pending_decision_cannot_apply_or_touch_claim(self):
        with patch.object(target.os.path, 'lexists', side_effect=AssertionError('claim accessed')):
            with self.assertRaisesRegex(ValueError, 'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED'):
                target.apply(target.APPROVAL_REF)

    def test_r8_decision_cannot_authorize_new_recovery(self):
        with self.assertRaisesRegex(ValueError, 'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED'):
            target.approval_live(target.OLD_APPROVAL)

    def test_new_claim_and_unit_are_distinct(self):
        self.assertNotEqual(target.CLAIM, target.PRIOR_CLAIM)
        self.assertNotEqual(target.UNIT, target.OLD_UNIT)

    def report(self):
        return {'roles': {role: {**expected, 'running': True, 'status': 'running',
                    'restartCount': 0, 'exitCode': 0, 'errorPresent': False,
                    'matchesSuccessfulR8Journal': True} for role, expected in target.EXPECTED.items()},
                'networkLease': {'journalFileHash': target.JOURNAL_HASH, 'journalState': 'QUIESCED',
                    'leaseAuthorized': False, 'providerSetsEmpty': True, 'journalAndMembershipConsistent': True,
                    'pollSeconds': 15, 'sourceMatchesByRole': {'adapter': [0], 'southbound': [1]},
                    'flowCount': 2, 'flows': [{**row, 'leaseSeconds': 30} for row in target.FLOW_HASHES]},
                'leaseServiceUnitNames': [target.OLD_UNIT]}

    def test_generational_and_owner_drift_denied(self):
        baseline = self.report()
        target.validate_report(baseline)
        for mutate in (
                lambda r: r['roles']['adapter'].update(pid=1),
                lambda r: r['networkLease'].update(leaseAuthorized=True),
                lambda r: r['networkLease']['flows'][1].update(sourceHash='0'*64),
                lambda r: r.update(leaseServiceUnitNames=[target.UNIT])):
            report = copy.deepcopy(baseline)
            mutate(report)
            with self.assertRaises(ValueError):
                target.validate_report(report)

    def test_known_delivery_component_tamper_denied(self):
        here = Path(__file__).parent
        target.component_bytes(here/'dns_recovery_dns.py', target.DNS_HASH)
        with self.assertRaisesRegex(ValueError, 'EXACT_DELIVERY_COMPONENT_HASH_REQUIRED'):
            target.component_bytes(here/'dns_recovery_dns.py', target.OLD_DNS_HASH)

    def test_plan_has_no_operational_code_or_lock_execution(self):
        import ast
        source = ast.parse(Path(target.__file__).read_text())
        plan = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'plan')
        calls = {ast.unparse(n.func) for n in ast.walk(plan) if isinstance(n, ast.Call)}
        self.assertFalse(calls & {'runtime', 'apply', 'CORE.create', 'core.load_installed', 'coord.hold_lock'})


if __name__ == '__main__':
    unittest.main()
