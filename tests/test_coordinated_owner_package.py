import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / 'stage-coordinated-provider-owner.py'
if not SCRIPT.exists():
    ROOT = ROOT.parent
    SCRIPT = ROOT / 'scripts/stage-coordinated-provider-owner.py'
SOURCE = ROOT / 'gateway-source'
if not SOURCE.exists():
    SOURCE = ROOT / 'coordinated-work'
spec = importlib.util.spec_from_file_location('stage', SCRIPT)
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)


def kernel():
    return {'tableName': 'ouf_stage_fixture', 'guardedInterfaces': ['isolated0'], 'existingInterfaces': [],
        'staticFlows': [{'purpose': 'DNS', 'source': '10.77.0.2', 'destination': '46.38.252.230',
                         'protocol': proto, 'port': 53} for proto in ('tcp', 'udp')],
        'providerFlows': [{'endpointRef': 'fixture', 'endpoint': 'https://provider.fixture.invalid/sparql',
            'source': '10.77.0.2', 'addresses': [], 'leaseSeconds': 30,
            'resolutionEvidenceRef': 'fixture-fresh', 'allowedPrivateAddresses': []}]}


class BoundaryTest(unittest.TestCase):
    def test_exact_reviewed_source_closure(self):
        for name, expected in stage.SOURCE_HASHES.items():
            self.assertEqual(stage.digest((SOURCE / name).read_bytes()), expected, name)

    def test_dns_requires_source_specific_udp_and_tcp(self):
        cfg = kernel(); profile = stage.dns_profile(cfg)
        self.assertEqual(profile['resolvers'], ['46.38.252.230'])
        self.assertEqual(profile['maxLeaseSeconds'], 30)
        for mutate in ('tcp_missing', 'other_source', 'port', 'cached_addresses'):
            cfg = kernel()
            if mutate == 'tcp_missing': cfg['staticFlows'].pop(0)
            if mutate == 'other_source': cfg['staticFlows'][0]['source'] = '10.77.0.3'
            if mutate == 'port': cfg['staticFlows'][0]['port'] = 5353
            if mutate == 'cached_addresses': cfg['providerFlows'][0]['addresses'] = ['8.8.8.8']
            with self.assertRaises(ValueError): stage.dns_profile(cfg)

    def test_native_drift_denies(self):
        report = {'schema': 'ouf.discovery.privileged-preflight.v2', 'releaseApplied': False,
            'runtimeReadiness': {**stage.EXPECTED, 'runtimeCustodyVerified': True, 'stableAcrossReads': True,
                'candidatesNeverStarted': True, 'providerSetsEmpty': True, 'candidateCount': 2,
                'runtimeState': 'RUNTIME_EMPTY', 'guardProfile': 'EMPTY_ONLY', 'startAuthorized': False}}
        stage.validate_native(report)
        for key in ('configurationHash', 'journalHash', 'leaseStructureHash', 'providerSetsEmpty', 'startAuthorized'):
            changed = copy.deepcopy(report); changed['runtimeReadiness'][key] = 'wrong'
            with self.assertRaises(ValueError): stage.validate_native(changed)

    def test_exclusive_write_preserves_existing_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'existing'; path.write_bytes(b'existing')
            with self.assertRaises(FileExistsError): stage.write_new(path, b'new')
            self.assertEqual(path.read_bytes(), b'existing')
            link = Path(tmp) / 'link'; link.symlink_to(path)
            with self.assertRaises(FileExistsError): stage.write_new(link, b'new')
            self.assertEqual(path.read_bytes(), b'existing')


@unittest.skipUnless(os.environ.get('OUF_COORDINATED_STAGE_NATIVE_TEST') == '1', 'isolated root/nft opt-in')
class NativeTest(unittest.TestCase):
    def test_actual_staged_cli_guard_original_rules_and_journal_unchanged(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, os.stat('/proc/1/ns/net').st_ino)
        sys.path.insert(0, str(SOURCE))
        from tools.materialize_southbound_kernel import materialize
        from tools.semantic_provider_lease_nft import structure_hash
        def run(*argv, raw=None):
            return subprocess.run(argv, input=raw, text=True, capture_output=True, timeout=30, check=True).stdout
        cfg = kernel(); installed = False
        try:
            run('nft', '-f', '-', raw=materialize(cfg, empty_provider_sets=True)['nftRules']); installed = True
            def tables():
                return {f: json.loads(run('nft', '-j', 'list', 'table', f, cfg['tableName'])) for f in ('inet', 'bridge')}
            original_tables = tables()
            with tempfile.TemporaryDirectory(prefix='ouf-stage-fixture-', dir='/etc') as tmp:
                root = Path(tmp); root.chmod(0o700)
                snapshots = root / 'snapshots'; snapshots.mkdir(mode=0o700)
                lock = root / 'common.lock'; lock.touch(mode=0o600)
                old_journal = root / 'existing-journal.json'; old_journal.write_bytes(b'{"state":"RUNTIME_EMPTY"}'); old_journal.chmod(0o600)
                original = {'kernel': cfg, 'lockFile': str(lock), 'nftPath': shutil.which('nft')}
                configuration = root / 'runtime.json'; configuration.write_bytes(stage.encoded(original)); configuration.chmod(0o600)
                expected = {'configurationHash': stage.digest(configuration.read_bytes()),
                            'journalHash': stage.digest(old_journal.read_bytes()), 'leaseStructureHash': structure_hash(original_tables)}
                report = {'schema': 'ouf.discovery.privileged-preflight.v2', 'releaseApplied': False,
                    'runtimeReadiness': {**expected, 'runtimeCustodyVerified': True, 'stableAcrossReads': True,
                        'candidatesNeverStarted': True, 'providerSetsEmpty': True, 'candidateCount': 2,
                        'runtimeState': 'RUNTIME_EMPTY', 'guardProfile': 'EMPTY_ONLY', 'startAuthorized': False}}
                lock_inode = lock.stat().st_ino
                with patch.object(stage, 'SNAPSHOTS', snapshots), patch.object(stage, 'EXISTING_CONFIGURATION', configuration), \
                     patch.object(stage, 'EXPECTED', expected), patch.object(stage, 'current_native', return_value=report):
                    result = stage.stage(SOURCE)
                self.assertEqual(result['status'], 'PRIVATE_PACKAGE_STAGED')
                prepared = Path(result['snapshotDirectory'])
                self.assertEqual(prepared.stat().st_mode & 0o777, 0o700)
                journal = json.loads((prepared / 'coordination-journal.json').read_text())
                self.assertEqual(journal['state'], 'QUIESCED')
                self.assertFalse(journal['leaseAuthorized']); self.assertFalse(journal['startAuthorized'])
                self.assertEqual(lock.stat().st_ino, lock_inode)
                self.assertEqual(old_journal.read_bytes(), b'{"state":"RUNTIME_EMPTY"}')
                self.assertEqual(configuration.read_bytes(), stage.encoded(original))
                self.assertEqual(tables(), original_tables)
                for path in prepared.rglob('*'):
                    if path.is_file():
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                        self.assertEqual(path.stat().st_uid, 0)
                        self.assertFalse(path.is_symlink())
                # A foreign source is rejected before any new snapshot/operation.
                with tempfile.TemporaryDirectory() as foreign:
                    foreign_root = Path(foreign)
                    for name in stage.SOURCE_HASHES:
                        p = foreign_root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'foreign')
                    with patch.object(stage, 'SNAPSHOTS', snapshots), patch.object(stage, 'current_native') as observe:
                        with self.assertRaises(ValueError): stage.stage(foreign_root)
                        observe.assert_not_called()
                    self.assertEqual(len(list(snapshots.iterdir())), 1)
                print('COORDINATED_PACKAGE_NATIVE=PASS REAL_NFT_STAGED_CLI_GUARD=true'
                      ' ORIGINAL_RULES_JOURNAL_LOCK_PRESERVED=true ROOT_PRIVATE_FILES=true'
                      ' FOREIGN_SOURCE_DENIED=true LEASE_AUTHORIZED=false START_AUTHORIZED=false')
        finally:
            if installed:
                run('nft', '-f', '-', raw='delete table inet ' + cfg['tableName'] + '\ndelete table bridge ' + cfg['tableName'] + '\n')


if __name__ == '__main__': unittest.main()
