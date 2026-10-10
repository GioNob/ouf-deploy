import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class Tests(unittest.TestCase):
    def backend(self, ttl):
        stub = types.ModuleType('tools.materialize_southbound_kernel')
        stub.materialize = lambda *a, **kw: None
        with patch.dict(sys.modules, {'tools.materialize_southbound_kernel': stub}):
            spec = importlib.util.spec_from_file_location('seconds_candidate', Path(__file__).with_name('nft_seconds_backend.py'))
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        cfg = {'providerFlows': [{'source': '10.77.0.2', 'leaseSeconds': 30}]}
        backend = module.NftBackend(['/usr/sbin/nft'], {**cfg, 'tableName': 'fixture'}, 'a'*64, 1)
        backend.tables = lambda: {f: {'nftables': [{'set': {'family': f, 'table': 'fixture', 'name': 'provider_0',
            'flags': ['timeout'], 'type': 'ipv4_addr', 'elem': [{'elem': {'val': '1.1.1.1', 'expires': ttl}}]}}]}
            for f in ('inet', 'bridge')}
        return backend, cfg
    def test_seconds_not_milliseconds(self):
        backend, cfg = self.backend(4)
        self.assertEqual(backend.read_sets(cfg), {('inet', 0): {'1.1.1.1': 4}, ('bridge', 0): {'1.1.1.1': 4}})
    def test_no_magnitude_based_unit_guess_or_zero_extension(self):
        for ttl in (0, -1, True, 4000, '4s', 4.5, None):
            backend, cfg = self.backend(ttl)
            with self.assertRaisesRegex(RuntimeError, 'NFT_SET_TTL_UNPROVEN'): backend.read_sets(cfg)
    def test_duplicate_address_refused(self):
        backend, cfg = self.backend(4); tables = backend.tables()
        table = tables['inet']['nftables'][0]['set']; table['elem'] *= 2
        backend.tables = lambda: tables
        with self.assertRaisesRegex(RuntimeError, 'NFT_SET_TTL_UNPROVEN'): backend.read_sets(cfg)
    def test_family_and_structure_guards_remain_strict(self):
        backend, cfg = self.backend(4); tables = backend.tables()
        tables['inet']['nftables'][0]['set']['type'] = 'ipv6_addr'; backend.tables = lambda: tables
        with self.assertRaisesRegex(RuntimeError, 'NFT_SET_FAMILY_UNPROVEN'): backend.read_sets(cfg)


if __name__ == '__main__': unittest.main()
