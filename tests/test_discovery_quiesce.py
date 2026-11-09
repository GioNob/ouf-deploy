import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('quiesce', ROOT / 'scripts/quiesce-discovery-coordinator-20261109.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def kernel():
    return {'tableName': 'ouf_quiesce_test', 'guardedInterfaces': ['oufquiesce0'], 'existingInterfaces': [], 'staticFlows': [],
            'providerFlows': [{'endpointRef': 'provider' + str(i), 'endpoint': 'https://example.invalid/' + str(i),
                               'source': '10.77.0.' + str(i + 2), 'addresses': [], 'leaseSeconds': 60,
                               'resolutionEvidenceRef': 'fixture' + str(i), 'allowedPrivateAddresses': []} for i in range(2)]}


def dns():
    return {'resolvers': ['1.1.1.1'], 'resolverPort': 53, 'timeoutSeconds': 1, 'maxLeaseSeconds': 60, 'applyBudgetSeconds': 5}


def tables():
    return {f: {'nftables': [{'set': {'family': f, 'table': 'ouf_quiesce_test', 'name': 'provider_' + str(i),
                                    'flags': ['timeout'], 'type': 'ipv4_addr', 'elem': []}} for i in range(2)]} for f in ('inet', 'bridge')}


def driver(core, directory, values):
    binding = {'transactionId': '1' * 64, 'configurationHash': m.sha(m.encoded(kernel())),
               'leaseStructureHash': core.semantic_provider_lease_nft.structure_hash(values)}
    value = {'schema': 'ouf.semantic-lease-coordination.v1', **binding, 'state': 'BLOCKED',
             'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[], []]}
    path = Path(directory) / 'coordinator.json'; path.write_bytes(m.encoded(value)); path.chmod(0o600)
    return {'kernel': kernel(), 'dns': dns(), 'coordinationBinding': binding, 'coordinationJournal': str(path)}


class CoordinatorContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.core = m.load_core(); self.values = tables()
        self.driver = driver(self.core, self.tmp.name, self.values)
        self.transport = m.FlushOnlyNft({'path': '/usr/sbin/nft', 'sha256': '2' * 64}, 'ouf_quiesce_test', 2, lambda p, s: p, self.tmp.name)
        self.ancestor = patch.object(self.core.semantic_provider_lease_coordination, '_ancestors')
        self.ancestor.start()
        self.coordinator, self.journal, self.transitions = m.services(self.core, self.driver, self.transport)
        self.fail_flush = False
        def run(args, raw=None, timeout=None):
            if args == ['-f', '-']:
                self.assertTrue(self.transport.armed); self.assertEqual(self.transport.batch, raw)
                self.transport.writes += 1
                if self.fail_flush: raise RuntimeError('SIMULATED_NFT_FAILURE')
                return ''
            return json.dumps(self.values[args[-2]])
        self.coordinator.owner.backend.run = run

    def tearDown(self):
        self.ancestor.stop(); self.tmp.cleanup()

    def test_existing_core_quiesces_without_grant_or_dns(self):
        before = m.check_empty_blocked(self.coordinator)
        with patch.object(self.core.semantic_provider_dns, 'observe', side_effect=AssertionError('DNS called')):
            self.transport.armed = True; result = self.coordinator.quiesce(); guard = self.coordinator.guard()
        after = self.journal.read()
        self.assertEqual('QUIESCED', result['state']); self.assertEqual('QUIESCED', guard['state'])
        self.assertEqual(['QUIESCING', 'QUIESCED'], self.transitions)
        self.assertFalse(after['leaseAuthorized']); self.assertFalse(after['startAuthorized'])
        self.assertEqual({k: v for k, v in before.items() if k != 'state'}, {k: v for k, v in after.items() if k != 'state'})
        self.assertEqual(1, self.transport.writes)

    def test_unowned_structure_stops_before_journal_or_nft_write(self):
        before = self.journal.read(); self.values['inet']['nftables'].append({'chain': {'name': 'foreign'}})
        with self.assertRaisesRegex(RuntimeError, 'NFT_INSTALLATION_STRUCTURE_DRIFT'):
            m.check_empty_blocked(self.coordinator)
        self.assertEqual(before, self.journal.read()); self.assertEqual(0, self.transport.writes)

    def test_nonempty_lease_stops_before_intent(self):
        for f in self.values:
            self.values[f]['nftables'][0]['set']['elem'] = [{'elem': {'val': '1.1.1.1', 'expires': 20000}}]
        with self.assertRaisesRegex(RuntimeError, 'CURRENT_EMPTY_OWNED_SETS_REQUIRED'):
            m.check_empty_blocked(self.coordinator)
        self.assertEqual('BLOCKED', self.journal.read()['state']); self.assertEqual([], self.transitions)

    def test_flush_failure_leaves_incomplete_non_authorizing_state(self):
        m.check_empty_blocked(self.coordinator); self.fail_flush = True; self.transport.armed = True
        with self.assertRaisesRegex(RuntimeError, 'SIMULATED_NFT_FAILURE'): self.coordinator.quiesce()
        self.assertEqual('QUIESCING', self.journal.read()['state'])
        self.assertEqual(['QUIESCING'], self.transitions); self.assertEqual(1, self.transport.writes)
        self.assertFalse(self.journal.read()['leaseAuthorized']); self.assertFalse(self.journal.read()['startAuthorized'])

    def test_no_journal_transition_before_intent(self):
        with self.assertRaisesRegex(RuntimeError, 'QUIESCENCE_ONLY_JOURNAL_TRANSITION_REQUIRED'): self.coordinator.quiesce()
        self.assertEqual('BLOCKED', self.journal.read()['state']); self.assertEqual(0, self.transport.writes)


class TransportBoundary(unittest.TestCase):
    def test_closed_write_command_and_batch(self):
        io = m.FlushOnlyNft({'path': '/usr/sbin/nft', 'sha256': '2' * 64}, 'ouf_quiesce_test', 2, lambda *_: self.fail('binary reached'), None)
        cases = [(['-f', '-'], io.batch), (['flush', 'ruleset'], None), (['-j', 'list', 'table', 'inet', 'foreign'], None)]
        for args, raw in cases:
            with self.subTest(args=args), self.assertRaises(RuntimeError): io.run(args, raw)
        io.armed = True
        for raw in ('flush ruleset\n', io.batch + 'add element inet ouf_quiesce_test provider_0 { 1.1.1.1 }\n'):
            with self.subTest(raw=raw), self.assertRaisesRegex(RuntimeError, 'ONE_EXACT_FLUSH_BATCH_REQUIRED'): io.run(['-f', '-'], raw)
        io.writes = 1
        with self.assertRaisesRegex(RuntimeError, 'ONE_EXACT_FLUSH_BATCH_REQUIRED'): io.run(['-f', '-'], io.batch)

    def test_core_hash_failure_precedes_core_execution(self):
        bad = dict(m.CORE); bad['semantic_provider_lease_coordination'] = '0' * 64
        with patch.object(m, 'CORE', bad), self.assertRaisesRegex(RuntimeError, 'PINNED_COORDINATOR_SOURCE_CHANGED'): m.load_core()


if __name__ == '__main__': unittest.main()
