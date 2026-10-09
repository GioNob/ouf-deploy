"""Authority and publication boundaries; no target execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import activate_r8_lease as target
import activation_core as core


class TargetBoundaries(unittest.TestCase):
    def test_declared_compiler_delta_reproduces_old_pair_failure_and_keeps_fail_closed(self):
        source = HERE.parents[0]/'semantic_cohort_admission/cohort-draft'
        sys.path.insert(0, str(source))
        from tools.materialize_southbound_lease_refresh import compile_refresh as old
        spec = importlib.util.spec_from_file_location('reviewed_lease_compiler', HERE/'materialize_southbound_lease_refresh.py')
        fixed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixed)
        cfg = {'tableName': 'pair', 'guardedInterfaces': ['pairbr'], 'existingInterfaces': [], 'staticFlows': [],
               'providerFlows': [{'endpointRef': 'p' + str(i), 'endpoint': 'https://provider.example/' + str(i),
                 'source': '10.77.0.' + str(i + 2), 'addresses': [], 'leaseSeconds': 30,
                 'resolutionEvidenceRef': 'ci', 'allowedPrivateAddresses': []} for i in range(2)]}
        values = [{**{k: f[k] for k in ('endpointRef', 'endpoint', 'resolutionEvidenceRef')},
                   'addresses': ['1.1.1.1' if i == 0 else '8.8.8.8'], 'observedMonotonic': 10,
                   'expiresMonotonic': 39, 'historicalEvidenceOnly': False}
                  for i, f in enumerate(cfg['providerFlows'])]
        self.assertTrue(old(cfg, values, 11, apply_budget_seconds=1)['denyOnly'])
        result = fixed.compile_refresh(cfg, values, 11, apply_budget_seconds=1)
        self.assertFalse(result['denyOnly'])
        self.assertEqual(result['nftTransaction'].count('add element'), 4)
        self.assertEqual(result['nftTransaction'].count('timeout 27s'), 4)
        values[1]['addresses'] = ['127.0.0.1']
        result = fixed.compile_refresh(cfg, values, 11, apply_budget_seconds=1)
        self.assertTrue(result['denyOnly'])
        self.assertNotIn('add element', result['nftTransaction'])
        self.assertEqual(result['nftTransaction'].count('flush set'), 4)
        self.assertEqual(core.digest((source/'tools/materialize_southbound_lease_refresh.py').read_bytes()), target.OLD_COMPILER_HASH)
        self.assertEqual(core.digest((HERE/'materialize_southbound_lease_refresh.py').read_bytes()), target.COMPILER_HASH)

    def test_pending_review_cannot_apply_and_window_is_bounded(self):
        with patch.multiple(target, APPROVAL_REF='PENDING_EXPLICIT_R8_TWO_FLOW_LEASE_APPROVAL', ISSUED_AT=0, EXECUTION_EXPIRES_AT=0):
            with self.assertRaisesRegex(ValueError, 'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED'):
                target.approval_live(target.APPROVAL_REF, clock=lambda: 100)
        with patch.multiple(target, APPROVAL_REF='EXPLICIT_HUMAN_REVIEW', ISSUED_AT=100, EXECUTION_EXPIRES_AT=200):
            for now in (99, 200):
                with self.assertRaises(ValueError):
                    target.approval_live('EXPLICIT_HUMAN_REVIEW', clock=lambda: now)
            target.approval_live('EXPLICIT_HUMAN_REVIEW', clock=lambda: 199)
            with self.assertRaises(ValueError):
                target.approval_live('CI_PASS', clock=lambda: 150)

    def test_real_operator_projection_and_concrete_drift(self):
        report = json.loads((HERE.parents[1]/'evidence/provider-r8-post-start-target-20261009.json').read_bytes())['receipt']
        target.validate_report(report)
        changes = [lambda r: r['roles']['adapter'].update(pid=1),
                   lambda r: r['networkLease']['flows'][0].update(leaseSeconds=300),
                   lambda r: r['networkLease'].update(journalState='LEASE_READY'),
                   lambda r: r['leaseServiceUnitNames'].append('ouf-other-lease.service')]
        for change in changes:
            changed = copy.deepcopy(report)
            change(changed)
            with self.assertRaises(ValueError):
                target.validate_report(changed)

    def test_service_does_not_rearm_or_enable(self):
        args = core.service_command(Path('/etc/ouf/deploy-snapshots/reviewed'), 'a' * 64,
                                    unit=target.UNIT)
        self.assertIn('--property=Restart=no', args)
        self.assertIn('--property=BindsTo=docker.service', args)
        self.assertIn('--property=After=docker.service', args)
        self.assertNotIn('--collect', args)
        self.assertNotIn('enable', args)
        self.assertNotIn('docker', args)
        self.assertEqual(args[-3:], ['--supervise', '/etc/ouf/deploy-snapshots/reviewed/authorization.json', 'a' * 64])

    def test_failure_retains_inner_reason_without_private_error_text(self):
        try:
            try:
                raise RuntimeError('DNS_PROVIDER_FAMILY_MISSING')
            except RuntimeError:
                raise ValueError('secret-sensitive private configuration') from None
        except Exception as error:
            value = core.diagnosis(error)
        self.assertEqual(value['exceptionChain'][1]['reason'], 'DNS_PROVIDER_FAMILY_MISSING')
        self.assertNotIn('secret-sensitive', json.dumps(value))

    def test_exclusive_claim_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'claim.json'
            core.create(path, {'approval': 'first'})
            with self.assertRaises(FileExistsError):
                core.create(path, {'approval': 'second'})
            self.assertEqual(json.loads(path.read_bytes()), {'approval': 'first'})


if __name__ == '__main__':
    unittest.main()
