import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('drift', ROOT / 'scripts/read-discovery-nft-drift-20261109.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
core = m.load_quiesce().load_core().semantic_provider_lease_nft


def tables():
    return {family: {'nftables': [
        {'metainfo': {'version': 'fixture', 'json_schema_version': 1}},
        {'table': {'family': family, 'name': 'ouf_test', 'handle': 1}},
        {'chain': {'family': family, 'table': 'ouf_test', 'name': 'guard', 'handle': 2, 'policy': 'drop'}},
        {'set': {'family': family, 'table': 'ouf_test', 'name': 'provider_0', 'handle': 3, 'flags': ['timeout'], 'type': 'ipv4_addr'}},
        {'rule': {'family': family, 'table': 'ouf_test', 'chain': 'guard', 'handle': 4, 'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}}
    ]} for family in ('inet', 'bridge')}


def samples(value): return {name: copy.deepcopy(value) for name in ('default', 'numeric', 'defaultAgain', 'numericAgain')}


def compare(expected, before, observed):
    return m.compare(core.structure_hash, core.structure, expected, before, observed)


class DriftComparisons(unittest.TestCase):
    def test_native_identity_drift_remains_exact_mismatch(self):
        before = tables(); after = copy.deepcopy(before)
        for doc in after.values():
            for row in doc['nftables']:
                for value in row.values():
                    if 'handle' in value: value['handle'] += 10
        c = compare(core.structure_hash(before), before, samples(after))
        self.assertFalse(c['defaultMatchesExpected']); self.assertFalse(c['numericMatchesExpected'])
        self.assertEqual(m.boot_structure(before), m.boot_structure(after))
        self.assertEqual({'handle': 8}, c['heldToCurrentNumericDifferences'])
        self.assertEqual('BOOT_FOOTPRINT_MATCHES_EXACT_DRIVER_HASH_DIFFERS', m.classification(c,
            {'status': 'BOUND_BOOT_BASELINE_READ', 'allOwnerBindingsMatchDriver': True, 'anyCurrentFootprintMatches': True}))

    def test_rule_content_order_and_policy_survive_diagnostic_projection(self):
        before = tables()
        for change in ('verdict', 'order', 'policy'):
            after = copy.deepcopy(before)
            if change == 'verdict': after['inet']['nftables'][-1]['rule']['expr'][-1] = {'accept': None}
            elif change == 'order': after['inet']['nftables'][-1]['rule']['expr'].reverse()
            else: after['inet']['nftables'][2]['chain']['policy'] = 'accept'
            self.assertNotEqual(m.boot_structure(before), m.boot_structure(after))

    def test_counter_changes_do_not_fabricate_rule_drift(self):
        before = tables(); after = copy.deepcopy(before)
        after['inet']['nftables'][-1]['rule']['expr'][0]['counter'] = {'packets': 15, 'bytes': 700}
        self.assertEqual(core.structure_hash(before), core.structure_hash(after))
        self.assertEqual(m.boot_structure(before), m.boot_structure(after))

    def test_numeric_match_never_changes_expected_hash(self):
        before = tables(); observed = samples(before)
        for name in ('default', 'defaultAgain'): observed[name]['inet']['nftables'][2]['chain']['prio'] = 'filter'
        c = compare(core.structure_hash(before), before, observed)
        self.assertEqual(core.structure_hash(before), c['expectedDriverStructureSha256'])
        self.assertFalse(c['defaultMatchesExpected']); self.assertTrue(c['numericMatchesExpected'])
        self.assertEqual('EXPECTED_HASH_MATCHES_NUMERIC_RENDERING_ONLY', m.classification(c, {}))

    def test_unstable_read_and_changed_installed_owner_are_distinct(self):
        before = tables(); observed = samples(before)
        observed['defaultAgain']['inet']['nftables'][-1]['rule']['expr'][-1] = {'accept': None}
        self.assertEqual('NFT_STRUCTURE_CHANGED_DURING_READ', m.classification(compare('0' * 64, before, observed), {}))
        c = compare('0' * 64, before, samples(before))
        self.assertEqual('INSTALLED_BOOT_OWNER_AND_RETAINED_DRIVER_DIFFER', m.classification(c,
            {'status': 'BOUND_BOOT_BASELINE_READ', 'allOwnerBindingsMatchDriver': False, 'anyCurrentFootprintMatches': True}))

    def test_missing_foreign_table_and_unknown_mode_are_refused(self):
        t = tables(); t['inet']['nftables'][1]['table']['name'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'NFT_OBJECT_SCOPE_UNPROVEN'): m.validate_tables(t, 'ouf_test')
        io = m.ReadOnlyNft({'path': '/usr/sbin/nft', 'sha256': 'a' * 64}, 'ouf_test', lambda *_: self.fail('unexpected binary call'), None, json.loads)
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_NFT_READ_MODE_REQUIRED'): io.tables('flush')
        io.calls = 8
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_NFT_READ_MODE_REQUIRED'): io.tables('numeric')

    def test_boot_baseline_checks_bound_bytes_and_driver_identity(self):
        root = Path('/etc/ouf/deploy-snapshots/fixture')
        owner = {'schema': 'ouf.semantic-coordinated-owner-runtime.v1', 'kernel': {'tableName': 'ouf_test'}, 'nftPath': '/usr/sbin/nft',
                 'commonLockFile': str(root / 'lock'), 'journalFile': str(root / 'coordination-journal.json'),
                 'binding': {'leaseStructureHash': 'a' * 64}, 'expectedStructureHash': 'a' * 64}
        boot = {'schema': 'ouf.semantic-runtime-boot-guard.v1', 'kernel': owner['kernel'], 'lockFile': owner['commonLockFile'],
                'nftPath': owner['nftPath'], 'expectedFootprint': 'b' * 64}
        profile = {'schema': 'ouf.semantic-coordinated-boot-profile.v1', 'coordinatedConfiguration': str(root / 'coordinated-configuration.json'),
                   'coordinatedConfigurationHash': m.sha(m.encoded(owner)), 'bootConfiguration': str(root / 'boot.json'), 'bootConfigurationHash': m.sha(m.encoded(boot))}
        receipt = {'schema': 'ouf.semantic-provider-network-guard-installation.v1', 'state': 'INSTALLED', 'directory': str(root),
                   'configurationHash': m.sha(m.encoded(owner)), 'bootProfileHash': m.sha(m.encoded(profile))}
        pointer = {'schema': 'ouf.semantic-coordinated-boot-pointer.v1', 'receiptFile': str(root / 'installation-receipt.json'), 'receiptHash': m.sha(m.encoded(receipt))}
        files = {m.POINTER: pointer, root / 'installation-receipt.json': receipt, root / 'coordinated-configuration.json': owner,
                 root / 'boot-profile.json': profile, root / 'boot.json': boot}
        driver = {'kernel': owner['kernel'], 'lockFile': owner['commonLockFile'], 'coordinationJournal': owner['journalFile'],
                  'commands': {'nft': owner['nftPath']}, 'coordinationBinding': owner['binding']}
        read = lambda path: m.encoded(files[path])
        self.assertTrue(m.boot_baseline(read, json.loads, Path, driver)['allOwnerBindingsMatchDriver'])
        files[root / 'boot.json'] = {**boot, 'expectedFootprint': 'c' * 64}
        with self.assertRaisesRegex(RuntimeError, 'BOOT_CONFIGURATION_HASH_CHANGED'): m.boot_baseline(read, json.loads, Path, driver)

    def test_source_hash_rejection_precedes_dependency_execution(self):
        with patch.object(m, 'QUIESCE_SHA', '0' * 64), self.assertRaisesRegex(RuntimeError, 'PINNED_HELPER_CHANGED'): m.load_quiesce()


if __name__ == '__main__': unittest.main()
