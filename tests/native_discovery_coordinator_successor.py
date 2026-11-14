"""Real nft generation change, new private package and original isolated guard CLI."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stage_fixture', Path(__file__).with_name('test_discovery_coordinator_successor.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
spec = importlib.util.spec_from_file_location('native_fixture', Path(__file__).with_name('native_discovery_quiesce.py'))
n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)
m, q, d = f.m, f.q, f.d


class NativeSuccessor(unittest.TestCase):
    setUp = n.NativeQuiescence.setUp
    tearDown = n.NativeQuiescence.tearDown

    def stage(self):
        root = Path(self.tmp.name); old = root / 'old'; old.mkdir(mode=0o700)
        before = self.coordinator.owner.backend.tables(); footprint = m.digest(d.boot_structure(before))
        owner, boot, profile = f.inputs(old, self.before_hash, footprint, self.nft, self.transport.binding['sha256'])
        Path(owner['commonLockFile']).write_bytes(b''); Path(owner['commonLockFile']).chmod(0o600)
        old_journal = {'schema': 'ouf.semantic-lease-coordination.v1', **owner['binding'], 'state': 'BLOCKED',
                       'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [['1.1.1.1'], []]}
        Path(owner['journalFile']).write_bytes(m.encoded(old_journal)); Path(owner['journalFile']).chmod(0o600)
        for family in ('inet', 'bridge'): subprocess.run([self.nft, 'delete', 'table', family, 'ouf_quiesce_test'], check=True)
        rules = self.core.materialize_southbound_kernel.materialize(f.f.kernel(), empty_provider_sets=True)['nftRules']
        subprocess.run([self.nft, '-f', '-'], input=rules.encode(), check=True)
        now = self.coordinator.owner.backend.tables(); current = self.core.semantic_provider_lease_nft.structure_hash(now)
        self.assertNotEqual(self.before_hash, current)
        m.qualify_tables(self.core, d, owner, boot, now, current, footprint)
        stage = root / 'new'; stage.mkdir(mode=0o700)
        files = m.build_successor(stage, owner, boot, profile, current, 'd' * 64)
        p = q.load_helper('reconcile-discovery-placeholder-20261109.py'); m.write_successor(p, stage, files, f.sources())
        result, reads = m.verify_staged_owner(q, self.core, files['coordinated-configuration.json'], types.SimpleNamespace(binary=self.transport.binary), root)
        self.assertEqual('QUIESCED', result['state']); self.assertGreater(reads, 0)
        self.assertEqual(m.encoded(old_journal), Path(owner['journalFile']).read_bytes())
        return stage, files, owner, boot, current, footprint

    def cli(self, stage, files):
        return subprocess.run([sys.executable, '-I', '-B', str(stage / 'source/scripts/run_semantic_coordinated_lease_owner.py'),
                               '--mode', 'guard', '--configuration', str(stage / 'coordinated-configuration.json'),
                               '--configuration-sha256', m.digest(files['coordinated-configuration.json'])], capture_output=True, timeout=10)

    def test_new_package_passes_original_guard_without_modifying_old_owner(self):
        stage, files, owner, _, current, _ = self.stage(); before = Path(owner['journalFile']).read_bytes()
        result = self.cli(stage, files); self.assertEqual(0, result.returncode, result.stdout.decode())
        self.assertIn(b'PASS QUIESCED=true START_AUTHORIZED=false', result.stdout)
        self.assertEqual(before, Path(owner['journalFile']).read_bytes())
        self.assertEqual(current, self.core.semantic_provider_lease_nft.structure_hash(self.coordinator.owner.backend.tables()))
        self.assertFalse(json.loads((stage / 'coordination-journal.json').read_bytes())['leaseAuthorized'])

    def test_foreign_rule_still_denied_by_boot_comparison_and_exact_new_guard(self):
        stage, files, owner, boot, current, footprint = self.stage()
        subprocess.run([self.nft, 'add', 'chain', 'inet', 'ouf_quiesce_test', 'foreign'], check=True)
        with self.assertRaisesRegex(RuntimeError, 'REVIEWED_BOOT_FOOTPRINT_CHANGED'):
            m.qualify_tables(self.core, d, owner, boot, self.coordinator.owner.backend.tables(), current, footprint)
        result = self.cli(stage, files); self.assertEqual(1, result.returncode)
        self.assertEqual(files['coordination-journal.json'], json.loads((stage / 'coordination-journal.json').read_bytes()))


if __name__ == '__main__': unittest.main(verbosity=2)
