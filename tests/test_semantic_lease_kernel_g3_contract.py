"""PET A3, task 63h. All addresses, receipts and boot IDs are synthetic."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_lease_kernel_migration import g3_contract as g
from tools.semantic_lease_kernel_migration import g3_install_profile as install


HEAD, OWNER = 'a' * 64, 'b' * 64
BOOT = '00000000-0000-4000-8000-000000000001'
NEXT = '00000000-0000-4000-8000-000000000002'
IP = '192.0.2.10'


def listing(offset=0, version='1.0.9'):
    result = {}
    for family in ('inet', 'bridge'):
        scope = {'family': family, 'table': 'sample'}
        chain = {**scope, 'chain': 'guard'}
        result[family] = {'nftables': [
            {'metainfo': {'version': version, 'release_name': 'fixture', 'json_schema_version': 1}},
            {'table': {'family': family, 'name': 'sample', 'handle': 1 + offset}},
            {'set': {**scope, 'name': 'provider_0', 'type': 'ipv4_addr',
                     'flags': ['timeout'], 'handle': 1 + offset}},
            {'chain': {**scope, 'name': 'guard', 'hook': 'forward', 'type': 'filter',
                       'prio': 0, 'policy': 'drop', 'handle': 2 + offset}},
            {'rule': {**chain, 'handle': 3 + offset, 'expr': [
                {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}},
                           'right': {'set': ['new', 'established']}}},
                {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]}},
            {'rule': {**chain, 'handle': 4 + offset, 'expr': [{'drop': None}]}}]}
    return result


def active(tables, ttl=10):
    for doc in tables.values():
        doc['nftables'][2]['set']['elem'] = [
            {'elem': {'val': IP, 'expires': ttl, 'timeout': 20}}]
    return tables


class Contract(unittest.TestCase):
    def setUp(self):
        self.profile = {'version': '1.0.9', 'jsonSchemaVersion': 1}
        self.empty = listing()
        self.seal = g.local_seal(HEAD, OWNER, 3, BOOT, self.empty, self.profile)
        self.policy = dict(head=HEAD, owner=OWNER, generation=3, bootId=BOOT,
                           nftProfile=self.profile, footprint=g.policy_footprint(self.empty, self.profile))
        self.members = {'provider_0': {'validUntil': {IP: 110}, 'maxSeconds': 20}}

    def tick(self, tables, now=100):
        g.verify_tick(self.policy, self.seal, tables, self.members, now)

    def denied(self, code, fn, *args):
        with self.assertRaises(ValueError) as failure:
            fn(*args)
        self.assertEqual(failure.exception.args, (code,))

    def test_a3_01_compiler_policy_and_live_handles(self):
        # Wire vectors pin both versioned projections for future readers.
        self.assertEqual(self.policy['footprint'],
                         '0029ec217cc2c7fd490a074104f9fdaf89fc27fdc82019e56d2a9b5d3c9a40e9')
        self.assertEqual(self.seal['structureHash'],
                         '0e37b6c59fc800df97e2ceecafbad5f3debb958f3370b807d6b7156f404c5bb8')
        compiled = listing()
        for table in compiled.values():
            for row in table['nftables'][1:]:
                del next(iter(row.values()))['handle']
        self.assertEqual(g.policy_footprint(compiled, self.profile), self.policy['footprint'])
        self.assertEqual(g.policy_footprint(listing(10), self.profile), self.policy['footprint'])
        other = g.local_seal(HEAD, OWNER, 3, BOOT, listing(10), self.profile)
        self.assertNotEqual(other['handles'], self.seal['handles'])
        self.assertNotEqual(other['structureHash'], self.seal['structureHash'])
        self.denied(g.NFT_FORMAT, g.local_seal, HEAD, OWNER, 3, BOOT, compiled, self.profile)

    def test_a3_02_same_boot_replacement_before_renewal(self):
        for index in range(1, 6):
            tables = active(listing())
            next(iter(tables['bridge']['nftables'][index].values()))['handle'] += 90
            with self.subTest(index=index):
                self.denied(g.SEAL_DRIFT, self.tick, tables)

    def test_a3_03_binding_and_receipt(self):
        self.assertIsNone(g.verify_boot(self.seal, BOOT, HEAD, OWNER, self.empty, self.profile))
        for boot, head, owner in ((NEXT, HEAD, OWNER), (BOOT, OWNER, OWNER),
                                  (BOOT, HEAD, HEAD), ('', HEAD, OWNER)):
            self.denied(g.BINDING, g.verify_boot, self.seal, boot, head, owner, self.empty, self.profile)
        self.policy['bootId'] = NEXT
        self.denied(g.BINDING, self.tick, active(listing()))
        for key, value in (('structureHash', OWNER), ('handles', {}), ('schema', ''), ('extra', 1)):
            self.denied(g.SEAL_DRIFT, g.verify_boot, {**self.seal, key: value},
                        BOOT, HEAD, OWNER, self.empty, self.profile)

    def test_a3_04_rule_order_and_independent_signed_policy(self):
        altered = listing()
        rows = altered['inet']['nftables']
        rows[-2:] = reversed(rows[-2:])
        self.assertNotEqual(g.policy_footprint(altered, self.profile), self.policy['footprint'])
        self.seal = g.local_seal(HEAD, OWNER, 3, BOOT, altered, self.profile)
        self.denied(g.POLICY_DRIFT, self.tick, active(altered))

    def test_a3_05_renewal_counters_metadata_and_purity(self):
        tables = active(listing())
        doc = tables['inet']['nftables']
        doc[0]['metainfo'].pop('release_name')
        doc[4]['rule']['expr'][1]['counter'] = {'packets': 3, 'bytes': 400}
        before = copy.deepcopy((tables, self.members, self.policy, self.seal))
        self.tick(tables)
        self.assertEqual(before, (tables, self.members, self.policy, self.seal))
        self.tick(active(tables, 4), now=106)
        self.members['provider_0']['validUntil'][IP] = 130
        self.tick(active(tables, 20), now=110)
        self.denied(g.SETS_NOT_EMPTY, g.policy_footprint, tables, self.profile)
        self.denied(g.SETS_NOT_EMPTY, g.local_seal, HEAD, OWNER, 3, BOOT, tables, self.profile)
        self.denied(g.SETS_NOT_EMPTY, g.verify_boot, self.seal, BOOT, HEAD, OWNER, tables, self.profile)

    def test_a3_06_members_exact_in_both_families(self):
        for mode in ('foreign', 'missing', 'duplicate', 'wrong-family', 'extra-policy'):
            tables = active(listing())
            elements = tables['bridge']['nftables'][2]['set']['elem']
            if mode == 'foreign':
                elements[0]['elem']['val'] = '192.0.2.11'
            elif mode == 'missing':
                elements.clear()
            elif mode == 'duplicate':
                elements *= 2
            elif mode == 'wrong-family':
                elements[0]['elem']['val'] = '2001:db8::10'
            else:
                self.members['provider_1'] = self.members['provider_0']
            with self.subTest(mode=mode):
                self.denied(g.MEMBERS, self.tick, tables)

    def test_a3_06_ipv6_and_empty_authorized_set(self):
        tables = listing()
        for doc in tables.values():
            doc['nftables'][2]['set']['type'] = 'ipv6_addr'
        self.seal = g.local_seal(HEAD, OWNER, 3, BOOT, tables, self.profile)
        self.policy['footprint'] = g.policy_footprint(tables, self.profile)
        self.members['provider_0']['validUntil'] = {}
        self.tick(tables)
        self.members['provider_0']['validUntil']['2001:db8::1'] = 105
        for doc in tables.values():
            doc['nftables'][2]['set']['elem'] = [{'elem': {'val': '2001:db8::1', 'expires': 5}}]
        self.tick(tables)

    def test_a3_07_ttl_bounds_type_unit_and_deadline(self):
        for remaining, timeout, now in ((0, 20, 100), (11, 20, 100), (10, 21, 100),
                                        (10, 9, 100), (10000, 20, 100), (True, 20, 100),
                                        (1, '20', 100), (1, 20, 110), (10, 20, -1)):
            tables = active(listing(), remaining)
            tables['inet']['nftables'][2]['set']['elem'][0]['elem']['timeout'] = timeout
            with self.subTest(remaining=remaining, timeout=timeout, now=now):
                self.denied(g.TTL, self.tick, tables, now)

    def test_a3_08_closed_nft_format(self):
        for field, value in (('version', '1.0.10'), ('json_schema_version', 2),
                             ('json_schema_version', True)):
            tables = listing()
            tables['inet']['nftables'][0]['metainfo'][field] = value
            self.denied(g.NFT_VERSION_DENIED, self.tick, tables)
        for index, row in ((0, {}), (1, {'map': {}}), (2, {'element': {}}),
                           (3, {'chain': {'family': 'inet'}}),
                           (4, {'rule': {}, 'metainfo': {}})):
            tables = listing()
            tables['inet']['nftables'][index] = row
            self.denied(g.NFT_FORMAT, self.tick, tables)
        self.denied(g.NFT_FORMAT, self.tick, {'inet': self.empty['inet']})
        tables = active(listing())
        tables['inet']['nftables'][2]['set']['elem'][0]['elem']['extra'] = True
        self.denied(g.NFT_FORMAT, self.tick, tables)

    def test_a3_09_keep_match_data_and_chain_policy(self):
        for mutate in ('inline-set', 'priority', 'policy', 'expression-order'):
            tables = active(listing())
            rows = tables['inet']['nftables']
            if mutate == 'inline-set':
                rows[4]['rule']['expr'][0]['match']['right']['set'].pop()
            elif mutate == 'priority':
                rows[3]['chain']['prio'] += 1
            elif mutate == 'policy':
                rows[3]['chain']['policy'] = 'accept'
            else:
                rows[4]['rule']['expr'].reverse()
            self.denied(g.POLICY_DRIFT, self.tick, tables)

    def test_signed_installation_profile(self):
        path = Path(__file__).with_name('fixtures') / 'lease-kernel-g3-nft-1.1.3-synthetic.json'
        observed = json.loads(path.read_text(encoding='utf-8'))
        profile = {'version': '1.1.3', 'jsonSchemaVersion': 1}
        compiled = listing(version='1.1.3')
        policy = {**self.policy, 'nftProfile': profile, 'footprint': g.policy_footprint(compiled, profile)}
        seal = g.local_seal(HEAD, OWNER, 3, BOOT, compiled, profile)
        g.verify_boot(seal, BOOT, HEAD, OWNER, compiled, profile)
        g.verify_tick(policy, seal, observed, self.members, 100)
        self.denied(g.NFT_VERSION_DENIED, self.tick, observed)
        observed['bridge']['nftables'][0]['metainfo']['version'] = '1.0.9'
        self.denied(g.NFT_VERSION_DENIED, g.verify_tick, policy, seal, observed, self.members, 100)

    def test_missing_or_invalid_signed_profile(self):
        del self.policy['nftProfile']
        self.denied(g.NFT_VERSION_DENIED, self.tick, active(listing()))
        for profile in (None, {}, {'version': '1.0.9'}, {**self.profile, 'version': ''},
                        {**self.profile, 'jsonSchemaVersion': True}, {**self.profile, 'extra': 0}):
            with self.subTest(profile=profile):
                self.policy['nftProfile'] = profile
                self.denied(g.NFT_VERSION_DENIED, self.tick, active(listing()))

    def test_installation_candidate_uses_pinned_binary(self):
        meta = {'metainfo': {'version': '1.1.3', 'json_schema_version': 1}}
        with patch.object(install.boot, 'command', return_value=json.dumps({'nftables': [meta]})) as read:
            self.assertEqual(install.read_nft_profile('/fixture/nft', HEAD),
                             {'version': '1.1.3', 'jsonSchemaVersion': 1})
            read.assert_called_once_with({'path': '/fixture/nft', 'sha256': HEAD}, ['-j', 'list', 'tables'])
            read.side_effect = ValueError('EXECUTABLE_HASH_CHANGED')
            self.denied('EXECUTABLE_HASH_CHANGED', install.read_nft_profile, '/fixture/nft', HEAD)

    def test_a3_10_journal_states_and_invalid_evidence(self):
        journal = dict(schema=g.JOURNAL, head=HEAD, owner=OWNER, generation=3,
                       bootId=BOOT, state='LEASE_READY', leaseAuthorized=True, startAuthorized=False)
        for state, lease in (('LEASE_READY', True), ('LEASE_UPDATING', True), ('QUIESCING', False),
                             ('QUIESCED', False), ('BLOCKED', False)):
            candidate = {**journal, 'state': state, 'leaseAuthorized': lease}
            quiet = state in ('QUIESCED', 'BLOCKED')
            self.assertEqual(g.classify_journal(candidate, NEXT),
                             g.QUIESCENT if quiet else g.RESIDUE_PREVIOUS_BOOT)
            self.assertEqual(g.classify_journal(candidate, BOOT), g.QUIESCENT if quiet else g.DENY)
            self.assertEqual(g.classify_journal({**candidate, 'leaseAuthorized': not lease}, NEXT), g.DENY)
        for field, value in (('bootId', None), ('bootId', 'bad'), ('bootId', '0' * 32),
                             ('generation', 2), ('head', ''), ('owner', None), ('state', 'UNKNOWN'),
                             ('schema', 'v2'), ('leaseAuthorized', 1), ('startAuthorized', True)):
            self.assertEqual(g.classify_journal({**journal, field: value}, NEXT), g.DENY)
        for field in journal:
            self.assertEqual(g.classify_journal({k: v for k, v in journal.items() if k != field}, NEXT),
                             g.DENY)
        self.assertEqual(g.classify_journal(None, NEXT), g.DENY)
        self.assertEqual(g.classify_journal(journal, 'bad'), g.DENY)
