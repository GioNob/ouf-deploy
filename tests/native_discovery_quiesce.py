"""Real nft and coordinator journal, in a disposable network+mount namespace."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('test_discovery_quiesce.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
m = fixture.m


class NativeQuiescence(unittest.TestCase):
    def setUp(self):
        self.assertEqual(0, os.geteuid()); self.core = m.load_core()
        self.tmp = tempfile.TemporaryDirectory(prefix='ouf-quiesce-native-', dir='/run')
        self.nft = str(Path(shutil.which('nft')).resolve())
        rules = self.core.materialize_southbound_kernel.materialize(fixture.kernel(), empty_provider_sets=True)['nftRules']
        subprocess.run([self.nft, '-f', '-'], input=rules.encode(), check=True)
        values = {f: json.loads(subprocess.check_output([self.nft, '-j', 'list', 'table', f, 'ouf_quiesce_test'])) for f in ('inet', 'bridge')}
        self.driver = fixture.driver(self.core, self.tmp.name, values)
        self.before_hash = self.driver['coordinationBinding']['leaseStructureHash']
        lifecycle_spec = importlib.util.spec_from_file_location('lifecycle', ROOT / 'scripts/read-discovery-lifecycle-20261109.py')
        lifecycle = importlib.util.module_from_spec(lifecycle_spec); lifecycle_spec.loader.exec_module(lifecycle)
        native = lifecycle.Native(Path(self.tmp.name))
        binding = {'path': self.nft, 'sha256': m.sha(Path(self.nft).read_bytes())}
        self.transport = m.FlushOnlyNft(binding, 'ouf_quiesce_test', 2, native.binary, self.tmp.name)
        self.coordinator, self.journal, self.transitions = m.services(self.core, self.driver, self.transport)

    def tearDown(self):
        for family in ('inet', 'bridge'): subprocess.run([self.nft, 'delete', 'table', family, 'ouf_quiesce_test'], check=True)
        self.tmp.cleanup()

    def test_real_blocked_empty_guard_quiesces_with_structure_preserved(self):
        m.check_empty_blocked(self.coordinator)
        with patch.object(self.core.semantic_provider_dns, 'observe', side_effect=AssertionError('DNS must remain unused')):
            self.transport.armed = True; self.coordinator.quiesce(); after = self.coordinator.guard()
        self.assertEqual('QUIESCED', after['state']); self.assertEqual(1, self.transport.writes)
        self.assertEqual(['QUIESCING', 'QUIESCED'], self.transitions)
        self.assertEqual(self.before_hash, self.core.semantic_provider_lease_nft.structure_hash(self.coordinator.owner.backend.tables()))
        self.assertEqual([[], []], self.coordinator.sets())
        self.assertFalse(self.journal.read()['leaseAuthorized']); self.assertFalse(self.journal.read()['startAuthorized'])

    def test_real_structure_change_is_preserved_before_any_write(self):
        subprocess.run([self.nft, 'add', 'chain', 'inet', 'ouf_quiesce_test', 'foreign'], check=True)
        with self.assertRaisesRegex(RuntimeError, 'NFT_INSTALLATION_STRUCTURE_DRIFT'): m.check_empty_blocked(self.coordinator)
        self.assertEqual('BLOCKED', self.journal.read()['state']); self.assertEqual(0, self.transport.writes)
        self.assertEqual([], self.transitions)


if __name__ == '__main__': unittest.main(verbosity=2)
