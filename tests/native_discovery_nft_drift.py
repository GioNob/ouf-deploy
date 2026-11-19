"""Real nft renderings and recreated handles; fixture writes stay in an isolated netns."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('previous_native_fixture', Path(__file__).with_name('native_discovery_quiesce.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location('drift', ROOT / 'scripts/read-discovery-nft-drift-20261109.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class NativeRead(unittest.TestCase):
    setUp = fixture.NativeQuiescence.setUp
    tearDown = fixture.NativeQuiescence.tearDown

    def read_samples(self):
        io = m.ReadOnlyNft(self.transport.binding, 'ouf_quiesce_test', self.transport.binary, self.tmp.name, json.loads)
        samples = {name: io.tables(mode) for name, mode in (('default', 'default'), ('numeric', 'numeric'), ('defaultAgain', 'default'), ('numericAgain', 'numeric'))}
        self.assertEqual(8, io.calls)
        return samples

    def test_both_cli_renderings_read_existing_guard_without_writes(self):
        before = self.coordinator.owner.backend.tables(); journal = self.journal.read()
        samples = self.read_samples(); core = self.core.semantic_provider_lease_nft
        result = m.compare(core.structure_hash, core.structure, self.before_hash, before, samples)
        self.assertTrue(result['stableAcrossReads']); self.assertTrue(result['defaultMatchesExpected'])
        self.assertEqual(journal, self.journal.read()); self.assertEqual(0, self.transport.writes)
        self.assertEqual(self.before_hash, core.structure_hash(self.coordinator.owner.backend.tables()))

    def test_actual_recreation_changes_owner_seal_but_not_boot_footprint(self):
        before = self.coordinator.owner.backend.tables()
        for family in ('inet', 'bridge'): subprocess.run([self.nft, 'delete', 'table', family, 'ouf_quiesce_test'], check=True)
        rules = self.core.materialize_southbound_kernel.materialize(fixture.fixture.kernel(), empty_provider_sets=True)['nftRules']
        subprocess.run([self.nft, '-f', '-'], input=rules.encode(), check=True)
        samples = self.read_samples(); core = self.core.semantic_provider_lease_nft
        result = m.compare(core.structure_hash, core.structure, self.before_hash, before, samples)
        self.assertFalse(result['defaultMatchesExpected']); self.assertFalse(result['numericMatchesExpected'])
        self.assertEqual(m.boot_structure(before), m.boot_structure(samples['default']))
        self.assertIn('handle', result['heldToCurrentNumericDifferences'])
        self.assertEqual(0, self.transport.writes); self.assertEqual('BLOCKED', self.journal.read()['state'])


if __name__ == '__main__': unittest.main(verbosity=2)
