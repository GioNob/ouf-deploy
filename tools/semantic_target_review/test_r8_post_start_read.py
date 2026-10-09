"""Exercise the entire read-only collector with retained JSON and native adapters.

The fixture is implementation evidence only, never installation authority.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('r8_post_read', HERE/'read_r8_post_start.py')
read = importlib.util.module_from_spec(spec)
spec.loader.exec_module(read)


class PostStartRead(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd(), prefix='r8-post-read-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.context, self.output, self.guard = [self.base/name for name in ('context', 'output', 'guard')]
        self.units = {name: self.base/name for name in ('guard.service', 'docker-drop-in.conf')}
        self.calls = []
        self.sources = {}
        self.patches = []
        for name, value in [('CONTEXT', self.context), ('OUTPUT', self.output), ('GUARD', self.guard), ('UNIT_PATHS', self.units)]:
            p = patch.object(read, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.commands = {}
        for name in ('docker', 'nft', 'systemctl'):
            p = self.base/name
            p.write_bytes(b'fixture executable, never invoked')
            p.chmod(0o755)
            self.commands[name] = {'path': str(p), 'sha256': read.sha(p.read_bytes())}
        self.tables = {family: {'nftables': [
            {'table': {'family': family, 'name': 'ouf_sem_provider', 'handle': 7}},
            *[{'set': {'family': family, 'table': 'ouf_sem_provider', 'name': 'provider_' + str(i),
                       'type': 'ipv4_addr', 'flags': ['timeout'], 'handle': 10 + i}} for i in range(2)]]}
                       for family in ('inet', 'bridge')}
        flows = [{'source': '172.21.0.' + str(i + 2), 'endpoint': 'https://provider.example/' + str(i),
                  'endpointRef': 'provider-' + str(i), 'leaseSeconds': 60, 'allowedPrivateAddresses': []} for i in range(2)]
        self.owner = {'kernel': {'providerFlows': flows, 'tableName': 'ouf_sem_provider'},
                      'expectedStructureHash': read.sha(read.encoded(read.structure(self.tables))),
                      'binding': {'transactionId': '1' * 64, 'configurationHash': '2' * 64,
                                  'leaseStructureHash': read.sha(read.encoded(read.structure(self.tables)))},
                      'journalFile': str(self.guard/'coordination-journal.json'),
                      'commonLockFile': str(self.guard/'common.lock'), 'sourceHashes': {}, 'pollSeconds': 15,
                      'nftPath': self.commands['nft']['path'], 'nftSha256': self.commands['nft']['sha256']}
        self.journal = {'schema': 'ouf.semantic-lease-coordination.v1', **self.owner['binding'],
                        'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False,
                        'leaseAddresses': [[], []]}
        self.put(Path(self.owner['commonLockFile']), {})
        self.put(Path(self.owner['journalFile']), self.journal)
        # Real source bytes are retained and hash-bound but never imported/run.
        for name in ('materialize_southbound_kernel.py', 'semantic_provider_lease_nft.py', 'semantic_provider_lease_coordination.py'):
            source = HERE.parent/'semantic_cohort_admission/cohort-draft/tools'/name
            target = self.guard/'source/tools'/name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)
            self.owner['sourceHashes']['tools/' + name] = read.sha(target.read_bytes())
        owner_hash = self.put(self.guard/'coordinated-configuration.json', self.owner)
        p = patch.object(read, 'OWNER_HASH', owner_hash)
        p.start()
        self.addCleanup(p.stop)
        boot = {'kernel': self.owner['kernel'], 'lockFile': self.owner['commonLockFile']}
        boot_hash = self.put(self.guard/'boot-configuration.json', boot)
        profile = {'coordinatedConfigurationHash': owner_hash, 'bootConfigurationHash': boot_hash, 'sourceHashes': {}}
        profile_hash = self.put(self.guard/'boot-profile.json', profile)
        artifacts = {name: self.put(path, {'unit': name}) for name, path in self.units.items()}
        receipt = {'configurationHash': owner_hash, 'bootConfigurationHash': boot_hash, 'bootProfileHash': profile_hash,
                   'artifactHashes': artifacts, 'guardCommand': 'known bound boot command'}
        receipt_hash = self.put(self.guard/'installation-receipt.json', receipt)
        pointer = {'receiptFile': str(self.guard/'installation-receipt.json'), 'receiptHash': receipt_hash,
                   'observerFile': str(self.guard/'transition-source.py')}
        pointer_path = self.base/'pointer.json'
        pointer_hash = self.put(pointer_path, pointer)
        cfg = {'outputRoot': str(self.output), 'commandBindings': self.commands,
               'guardPointerBinding': {'path': str(pointer_path), 'sha256': pointer_hash}}
        cfg_hash = self.put(self.context/'execution-configuration.json', cfg)
        self.put(self.context/'human-approval-binding.json', {'approvalRef': read.APPROVAL, 'configurationHash': cfg_hash})
        historical = {'status': 'TWO_CANDIDATE_RUNTIME_STARTED', 'candidates': {}}
        self.docker = {}
        for i, (role, (cid, image)) in enumerate(read.TARGETS.items()):
            self.put(self.context/'role-authority'/role/'role-issuance-receipt.json',
                     {'schema': 'ouf.semantic-provider-role-authority-issuance.v1', 'role': role,
                      'status': 'ROLE_RECORDS_ISSUED', 'signaturesIssued': 4})
            h = self.put(self.output/'registry'/cid/'adapter.json', {'containerId': cid, 'state': 'STARTED'})
            historical['candidates'][cid] = {'adapterJournalHash': h}
            self.docker[cid] = {'id': cid, 'image': image, 'runtime': 'ouf-semantic-admitted-v2',
                'state': {'Status': 'running', 'Running': True, 'Pid': 1826000 + i, 'StartedAt': '2026-10-09T19:10:21Z',
                          'ExitCode': 0, 'Error': 'PRIVATE_ERROR_CONTENT'}, 'restartCount': 0,
                'networks': {'private-network': {'IPAddress': flows[i]['source'], 'GlobalIPv6Address': '',
                                                'SecretNotToPrint': 'PRIVATE_NETWORK_CONTENT'}}}
        self.put(self.output/'cohort-activation-receipt.json', historical)
        (self.output/'activation-docker-cli').mkdir(mode=0o700)

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = read.encoded(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        return read.sha(raw)

    def native(self, argv, **kwargs):
        self.calls.append(argv)
        name = Path(argv[0]).name
        if name == 'docker':
            self.assertEqual(argv[1:4], ['--config', str(self.output/'activation-docker-cli'), 'inspect'])
            value = self.docker[argv[-1]]
        elif name == 'nft':
            self.assertEqual(argv[1:4], ['-j', 'list', 'table'])
            value = self.tables[argv[-2]]
        elif name == 'systemctl':
            self.assertIn(argv[1], ('show', 'list-unit-files'))
            raw = b'known bound boot command' if argv[1] == 'show' else b'ouf-semantic-boot-guard.service enabled enabled\n'
            return types.SimpleNamespace(returncode=0, stdout=raw)
        else:
            self.fail('Unexpected native command')
        return types.SimpleNamespace(returncode=0, stdout=read.encoded(value))

    def collect(self):
        with patch.object(read.subprocess, 'run', self.native):
            return read.collect()

    def test_complete_started_cohort_and_quiesced_lease_without_private_output_or_writes(self):
        before = {str(p): p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        report = self.collect()
        self.assertEqual(report['networkLease']['journalState'], 'QUIESCED')
        self.assertTrue(report['networkLease']['providerSetsEmpty'])
        self.assertTrue(report['networkLease']['journalAndMembershipConsistent'])
        self.assertEqual([r['historicalRoleSignaturesIssued'] for r in report['roles'].values()], [4, 4])
        self.assertTrue(all(r['matchesSuccessfulR8Journal'] and r['running'] for r in report['roles'].values()))
        raw = json.dumps(report)
        self.assertNotIn('PRIVATE_', raw)
        self.assertNotIn('172.21.', raw)
        self.assertNotIn('provider.example', raw)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.base.rglob('*') if p.is_file()})

    def test_active_membership_is_observed_without_refresh(self):
        for family in ('inet', 'bridge'):
            self.tables[family]['nftables'][1]['set']['elem'] = [{'elem': {'val': '1.1.1.1', 'expires': 18000}}]
        self.journal.update(state='LEASE_READY', leaseAuthorized=True, leaseAddresses=[['1.1.1.1'], []])
        self.put(Path(self.owner['journalFile']), self.journal)
        report = self.collect()['networkLease']
        self.assertTrue(report['journalAndMembershipConsistent'])
        self.assertFalse(report['providerSetsEmpty'])
        self.assertEqual(report['flows'][0]['minRemainingTtlSeconds'], 18)

    def test_handle_drift_and_mutation_commands_are_denied(self):
        self.tables['inet']['nftables'][0]['table']['handle'] += 1
        with self.assertRaisesRegex(read.ReadDenied, 'NFT_STRUCTURE_DRIFT'):
            self.collect()
        for name, args in [('nft', ['-f', '-']), ('docker', ['start', next(iter(self.docker))]),
                           ('systemctl', ['restart', 'docker.service'])]:
            with self.assertRaisesRegex(read.ReadDenied, 'READ_ONLY_COMMAND_SCOPE_REQUIRED'):
                read.run(self.commands, name, args)

    def test_finite_ttl_and_family_mismatch(self):
        self.tables['inet']['nftables'][1]['set']['elem'] = [{'elem': {'val': '1.1.1.1', 'expires': 61000}}]
        with self.assertRaisesRegex(read.ReadDenied, 'LEASE_ADDRESS_OR_TTL_UNPROVEN'):
            self.collect()
        self.tables['inet']['nftables'][1]['set']['elem'][0]['elem']['expires'] = 10000
        with self.assertRaisesRegex(read.ReadDenied, 'LEASE_FAMILY_MEMBERSHIP_DRIFT'):
            self.collect()

    def test_private_source_drift_stops_before_nft_read(self):
        source = self.guard/'source/tools/semantic_provider_lease_coordination.py'
        source.write_bytes(source.read_bytes() + b'\n')
        with self.assertRaisesRegex(read.ReadDenied, 'EXACT_FILE_HASH_DRIFT'):
            self.collect()
        self.assertFalse(any(Path(argv[0]).name == 'nft' for argv in self.calls))


if __name__ == '__main__':
    unittest.main()
