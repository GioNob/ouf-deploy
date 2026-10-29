import copy
import hashlib
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import activate_dns_recovery as target


class RecoveryBoundary(unittest.TestCase):
    def test_pending_decision_cannot_apply_or_touch_claim(self):
        with patch.object(target, 'APPROVAL_REF', 'PENDING_NEW_DECISION'), \
             patch.object(target.os.path, 'lexists', side_effect=AssertionError('claim accessed')):
            with self.assertRaisesRegex(ValueError, 'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED'):
                target.apply(target.APPROVAL_REF)

    def test_new_decision_is_only_valid_inside_exact_startup_window(self):
        with patch.object(target, 'APPROVAL_REF', 'EXACT_NEW_DECISION'), \
             patch.object(target, 'ISSUED_AT', 100), \
             patch.object(target, 'EXECUTION_EXPIRES_AT', 7300):
            for now in (100, 7299):
                target.approval_live('EXACT_NEW_DECISION', clock=lambda: now)
            for now in (99, 7300):
                with self.assertRaisesRegex(ValueError, 'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED'):
                    target.approval_live('EXACT_NEW_DECISION', clock=lambda: now)
            with self.assertRaisesRegex(ValueError, 'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED'):
                target.approval_live(target.OLD_APPROVAL, clock=lambda: 101)

    def test_consumed_new_claim_is_never_replayed(self):
        with patch.object(target, 'approval_live'), patch.object(target.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(ValueError, 'LEASE_ACTIVATION_ALREADY_CLAIMED_DO_NOT_REPLAY'):
                target.apply('EXACT_NEW_DECISION')

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

    def test_actual_prior_validation_uses_scoped_service_probe(self):
        claim = {'schema': 'ouf.provider-r8-lease-activation-claim.v1', 'approvalRef': target.OLD_APPROVAL,
                 'directory': str(target.PRIOR_ROOT), 'startAuthorized': False}
        authorization = {'approvalRef': target.OLD_APPROVAL, 'serviceUnit': target.OLD_UNIT,
                         'programHashes': {'activate.py': 'a'*64}}
        cycle = {'status': 'LEASE_ACTIVE', 'refreshCount': 2, 'workerPid': 1856196, 'flowAddressCounts': [1, 1]}
        denial = {'status': 'LEASE_WORKER_FAILED', 'refreshCount': 49, 'exceptionChain': [
            {'reason': r} for r in ('REFRESH_FAILED_GATE_BLOCKED', 'REFRESH_FAILED_SETS_REVOKED',
                                  'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE')]}
        data = {str(target.PRIOR_CLAIM): json.dumps(claim).encode(),
                str(target.PRIOR_ROOT/'authorization.json'): json.dumps(authorization).encode(),
                str(target.PRIOR_ROOT/'cycle-2.json'): json.dumps(cycle).encode(),
                str(target.PRIOR_ROOT/'worker-denial.json'): json.dumps(denial).encode(),
                str(target.PRIOR_ROOT/'activate.py'): b'fixture'}
        custody = []
        def private(path, expected=None, executable=False):
            custody.append((str(path), expected, executable))
            return b'native executable fixture' if executable else data[str(path)]
        reader = SimpleNamespace(private=private, parse=json.loads,
            native_read=lambda *a: self.fail('network-only reader called for systemctl'))
        cfg = {'commandBindings': {'systemctl': {'path': '/usr/bin/systemctl', 'sha256': 'b'*64}}}
        props = {'LoadState': 'loaded', 'ActiveState': 'failed', 'SubState': 'failed', 'MainPID': '0',
                 'Restart': 'no', 'NRestarts': '0', 'InvocationID': 'df9a930eafbb4b56abc662319ba9888e',
                 'ExecStart': str(target.PRIOR_ROOT/'activate.py')}
        raw = ('\n'.join(k+'='+v for k, v in props.items())+'\n').encode()
        with patch.object(target, 'configuration', return_value=(cfg, {})), \
             patch.object(target, 'command', side_effect=[raw, (target.OLD_UNIT+' loaded failed failed\n').encode()]) as commands:
            self.assertEqual(target.validate_prior(reader), data[str(target.PRIOR_CLAIM)])
        self.assertEqual(commands.call_count, 2)
        self.assertEqual(sum(row == ('/usr/bin/systemctl', 'b'*64, True) for row in custody), 4)

    def test_service_probe_cannot_mutate_or_query_other_units(self):
        reader = SimpleNamespace(private=lambda *a, **k: self.fail('custody should not be reached'))
        binding = {'path': '/usr/bin/systemctl', 'sha256': 'b'*64}
        for args in (['restart', target.OLD_UNIT], ['reset-failed', target.OLD_UNIT],
                     ['show', target.UNIT], ['list-units']):
            with self.assertRaisesRegex(ValueError, 'EXACT_READ_ONLY_SERVICE_PROBE_REQUIRED'):
                target.service_read(reader, binding, args)


if __name__ == '__main__':
    unittest.main()
