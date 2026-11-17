"""Portable checks of the D-050 feasibility witness and unchanged hash contract."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualify_semantic_lease_restore_seal as Q


def tables():
    return {family: {'nftables': [
        {'metainfo': {'version': 'fixture'}},
        {'table': {'family': family, 'name': 'ouf_task65_seal', 'handle': number}},
        {'set': {'family': family, 'table': 'ouf_task65_seal', 'name': 'provider_0',
                 'handle': 1, 'type': 'ipv4_addr', 'flags': ['timeout']}},
        {'chain': {'family': family, 'table': 'ouf_task65_seal', 'name': 'flow', 'handle': 2}},
        {'rule': {'family': family, 'table': 'ouf_task65_seal', 'chain': 'flow', 'handle': 3,
                  'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}}
    ]} for number, family in enumerate(('inet', 'bridge'), 1)}


class RestoreSealContract(unittest.TestCase):
    def test_exact_historical_structure_is_accepted(self):
        before = tables()
        Q.require_seal(Q.H.structure_hash(before), copy.deepcopy(before))

    def test_each_table_handle_participates_in_the_historical_seal(self):
        before = tables()
        for family in ('inet', 'bridge'):
            with self.subTest(family=family):
                after = copy.deepcopy(before)
                after[family]['nftables'][1]['table']['handle'] += 100
                self.assertEqual(Q.digest(Q.stable(before)), Q.digest(Q.stable(after)))
                with self.assertRaisesRegex(Q.SealUnproven, '^LEASE_KERNEL_RESTORE_SEAL_UNPROVEN$'):
                    Q.require_seal(Q.H.structure_hash(before), after)

    def test_all_other_object_handles_participate(self):
        before = tables()
        for family in ('inet', 'bridge'):
            for index, kind in ((2, 'set'), (3, 'chain'), (4, 'rule')):
                with self.subTest(family=family, kind=kind):
                    after = copy.deepcopy(before)
                    after[family]['nftables'][index][kind]['handle'] += 1
                    with self.assertRaises(Q.SealUnproven):
                        Q.require_seal(Q.H.structure_hash(before), after)

    def test_counter_changes_do_not_change_historical_structure(self):
        before = tables()
        after = copy.deepcopy(before)
        after['inet']['nftables'][4]['rule']['expr'][0]['counter'].update(packets=10, bytes=200)
        Q.require_seal(Q.H.structure_hash(before), after)

    def test_one_batch_contains_both_deletes_and_empty_compilation(self):
        for version in (1, 2):
            config = Q.kernel(version)
            raw = Q.replacement(config)
            expected = ''.join(f'delete table {family} {config["tableName"]}\n'
                               for family in ('inet', 'bridge'))
            self.assertEqual(raw, expected + Q.m.materialize(config, empty_provider_sets=True)['nftRules'])
            self.assertNotIn('elements =', raw)

    def test_invalid_scope_is_denied_before_emitting_batch(self):
        config = Q.kernel()
        config['tableName'] = 'foreign; flush ruleset'
        with self.assertRaises(ValueError):
            Q.replacement(config)


if __name__ == '__main__':
    unittest.main(verbosity=2)
