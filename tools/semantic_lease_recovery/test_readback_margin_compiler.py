import copy
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

class Tests(unittest.TestCase):
    def setUp(self):
        kernel = types.ModuleType('tools.materialize_southbound_kernel')
        kernel.materialize = lambda cfg, **kw: {'tableName': cfg['tableName']}
        def fields(value, expected):
            if set(value) != set(expected): raise ValueError('shape')
        kernel.fields = fields
        with patch.dict(sys.modules, {'tools.materialize_southbound_kernel': kernel}):
            s = importlib.util.spec_from_file_location('margin', Path(__file__).with_name('readback_margin_compiler.py'))
            self.m = importlib.util.module_from_spec(s); s.loader.exec_module(self.m)
        self.cfg = {'tableName': 'fixture', 'providerFlows': [
            {'endpointRef': str(i), 'endpoint': 'https://fixture.invalid', 'resolutionEvidenceRef': 'fixture',
             'allowedPrivateAddresses': [], 'leaseSeconds': 30} for i in range(2)]}
    def observations(self, remaining):
        return [{'endpointRef': f['endpointRef'], 'endpoint': f['endpoint'], 'resolutionEvidenceRef': 'fixture',
                 'addresses': ['1.1.1.1'], 'observedMonotonic': 99., 'expiresMonotonic': 100. + value,
                 'historicalEvidenceOnly': False} for f, value in zip(self.cfg['providerFlows'], remaining)]
    def test_subsecond_zero_and_one_second_plan_deny_entire_batch(self):
        for remaining in (1., 1.9, 2., 2.999):
            p = self.m.compile_refresh(self.cfg, self.observations([20., remaining]), 100., apply_budget_seconds=1)
            self.assertTrue(p['denyOnly']); self.assertNotIn('add element', p['nftTransaction'])
            self.assertEqual(p['nftTransaction'].count('flush set'), 4)
    def test_two_seconds_is_not_extended_and_all_flows_are_revalidated(self):
        before = copy.deepcopy(self.cfg)
        p = self.m.compile_refresh(self.cfg, self.observations([20., 3.1]), 100., apply_budget_seconds=1)
        self.assertFalse(p['denyOnly']); self.assertEqual(p['nftTransaction'].count('timeout 2s'), 2)
        self.assertEqual(self.cfg, before); self.assertFalse(p['resolutionProvenanceProven']); self.assertFalse(p['installed'])
    def test_historical_or_binding_drift_never_admitted(self):
        for key, value in [('historicalEvidenceOnly', True), ('endpointRef', 'foreign')]:
            observations = self.observations([20., 20.]); observations[1][key] = value
            p = self.m.compile_refresh(self.cfg, observations, 100., apply_budget_seconds=1)
            self.assertTrue(p['denyOnly']); self.assertNotIn('add element', p['nftTransaction'])
    def test_elapsed_and_apply_budget_are_always_subtracted(self):
        observations = self.observations([10., 10.])
        p = self.m.compile_refresh(self.cfg, observations, 102.25, apply_budget_seconds=5)
        self.assertFalse(p['denyOnly']); self.assertEqual(p['nftTransaction'].count('timeout 2s'), 4)
        p = self.m.compile_refresh(self.cfg, observations, 103., apply_budget_seconds=6)
        self.assertTrue(p['denyOnly'])

if __name__ == '__main__': unittest.main()
