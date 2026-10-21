"""Actual root file transaction and nft readback; systemd/custody adapters simulated.

No target acceptance or real reboot is inferred from this isolated fixture.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
if not (ROOT/'install-coordinated-boot-guard.py').exists(): ROOT = ROOT.parent/'scripts'
SOURCE = ROOT.parent/'gateway-source' if ROOT.name == 'scripts' else ROOT/'coordinated-work'
spec = importlib.util.spec_from_file_location('installation', ROOT/'install-coordinated-boot-guard.py')
install = importlib.util.module_from_spec(spec); spec.loader.exec_module(install)
guard_spec = importlib.util.spec_from_file_location('guard', SOURCE/'scripts/restore_semantic_runtime_boot_guard.py')
guard = importlib.util.module_from_spec(guard_spec); guard_spec.loader.exec_module(guard)


@unittest.skipUnless(os.environ.get('OUF_COORDINATED_INSTALL_NATIVE_TEST') == '1', 'isolated fixture only')
class NativeInstallationTest(unittest.TestCase):
    def exercise(self, fail_reload=False):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, os.stat('/proc/1/ns/net').st_ino)
        sys.path.insert(0, str(SOURCE))
        from tools.materialize_southbound_kernel import materialize
        from tools.semantic_provider_lease_nft import structure_hash
        cfg = {'tableName': 'install_fixture', 'guardedInterfaces': ['isolated0'], 'existingInterfaces': [],
            'staticFlows': [], 'providerFlows': [{'endpointRef': 'fixture', 'endpoint': 'https://provider.fixture.invalid/sparql',
                'source': '10.77.0.2', 'addresses': [], 'leaseSeconds': 30,
                'resolutionEvidenceRef': 'fixture-only', 'allowedPrivateAddresses': []}]}
        def command(args, raw=None):
            return subprocess.run(args, input=raw, text=True, capture_output=True, timeout=15, check=True).stdout
        command(['nft', '-f', '-'], materialize(cfg, empty_provider_sets=True)['nftRules'])
        try:
            original_tables = {f: json.loads(command(['nft', '-j', 'list', 'table', f, cfg['tableName']])) for f in ('inet', 'bridge')}
            lease_hash = structure_hash(original_tables)
            with tempfile.TemporaryDirectory(prefix='ouf-install-native-', dir='/root') as tmp:
                root = Path(tmp); root.chmod(0o700)
                snapshots = root/'snapshots'; snapshots.mkdir(mode=0o700)
                package = root/'package'; package.mkdir(mode=0o700)
                (package/'source').mkdir(mode=0o700)
                for name, expected in install.OWNER_HASHES.items():
                    target = package/'source'/name; target.parent.mkdir(mode=0o700, exist_ok=True)
                    install.write_new(target, (SOURCE/name).read_bytes())
                stage = root/'original/prepared'; stage.mkdir(parents=True, mode=0o700)
                (root/'original').chmod(0o700)
                lock = root/'common.lock'; install.write_new(lock, b'')
                old_journal_path = root/'old-journal.json'; install.write_new(old_journal_path, b'{"state":"RUNTIME_EMPTY"}')
                old_config = {'kernel': cfg, 'nftPath': shutil.which('nft'), 'lockFile': str(lock),
                    'journalFile': str(old_journal_path), 'expectedFootprint': guard.footprint(original_tables)}
                install.write_new(stage/'runtime-configuration.json', install.encoded(old_config))
                expected = {'configurationHash': install.digest(install.encoded(old_config)),
                    'journalHash': install.digest(old_journal_path.read_bytes()), 'leaseStructureHash': lease_hash}
                owner = {'schema': 'ouf.semantic-coordinated-owner-runtime.v1', 'kernel': cfg,
                    'dns': {'resolvers': ['127.0.0.1'], 'resolverPort': 53, 'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1},
                    'expectedStructureHash': lease_hash, 'nftPath': shutil.which('nft'),
                    'nftSha256': install.digest(Path(shutil.which('nft')).read_bytes()), 'readBudgetSeconds': 2,
                    'pollSeconds': 5, 'commonLockFile': str(lock), 'journalFile': str(package/'coordination-journal.json'),
                    'sourceHashes': install.OWNER_HASHES,
                    'binding': {'transactionId': 'a'*64, 'configurationHash': 'b'*64, 'leaseStructureHash': lease_hash}}
                install.write_new(package/'coordinated-configuration.json', install.encoded(owner))
                old_coord = {'schema': 'ouf.semantic-lease-coordination.v1', **owner['binding'], 'state': 'QUIESCED',
                             'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[]]}
                install.write_new(package/'coordination-journal.json', install.encoded(old_coord))
                inputs = root/'inputs'; inputs.mkdir(mode=0o700)
                for name in install.BOOT_HASHES:
                    path = inputs/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    install.write_new(path, (SOURCE/name).read_bytes())
                install.write_new(inputs/'privileged-discovery-preflight-v3.py', (ROOT/'privileged-discovery-preflight-v3.py').read_bytes())
                helper = root/'helper'; install.write_new(helper, (ROOT/'privileged-discovery-preflight-v2.py').read_bytes(), 0o755)
                backup = root/'backup'; pointer = root/'active.json'
                unit_paths = {'guard.service': root/'guard.service', 'docker-drop-in.conf': root/'docker.conf'}
                previous = {'guard.service': b'[Service]\nType=oneshot\nExecStart=/previous\nRemainAfterExit=yes\n',
                            'docker-drop-in.conf': b'[Unit]\nAfter=guard.service\n[Service]\nExecStartPre=/previous\n'}
                for name, path in unit_paths.items(): install.write_new(path, previous[name])
                receipt = {'configurationHash': expected['configurationHash'], 'sourceCommit': 'c'*40,
                    'sourceHashes': {'restore_semantic_runtime_boot_guard.py': install.digest((SOURCE/'scripts/restore_semantic_runtime_boot_guard.py').read_bytes())},
                    'executables': {'systemctl_path': '/fixture/systemctl'}}
                reloads = []; proof = []; original_run = guard.run
                def guarded_run(args, raw=None):
                    if args == ['/fixture/systemctl', 'daemon-reload']:
                        reloads.append(True)
                        if fail_reload and len(reloads) == 1: raise ValueError('fixture reload failure')
                        return ''
                    return original_run(args, raw)
                class InstallationAdapter:
                    def stage(self, args):
                        return (guard, receipt, previous, old_config, {}, {}, {}, 'guard.service',
                                unit_paths['guard.service'], unit_paths['docker-drop-in.conf'], {})
                    def independent(self, *args):
                        self_test.assertEqual(guard.tables(old_config), original_tables)
                        self_test.assertEqual(install.digest(old_journal_path.read_bytes()), expected['journalHash'])
                    def loaded(self, g, r, artifacts, original, gu, unit, drop):
                        for name, path in unit_paths.items(): self_test.assertEqual(path.read_bytes(), artifacts[name])
                        proof.append('loaded adapter readback')
                adapter = InstallationAdapter(); self_test = self
                legacy = SimpleNamespace(selected_runtime_readiness=lambda: {**expected, 'runtimeCustodyVerified': True})
                def original(received): return None, adapter, adapter.stage(None)
                original_module = install.module
                def loaded(path, raw):
                    if path == helper:
                        if install.digest(raw) == install.HELPER_V2_HASH: return legacy
                        def collect():
                            value = install.parsed(pointer.read_bytes())
                            installed = install.parsed(Path(value['receiptFile']).read_bytes())
                            return {'runtimeReadiness': install.observe(installed, legacy)}
                        return SimpleNamespace(collect=collect)
                    return original_module(path, raw)
                with patch.multiple(install, SNAPSHOTS=snapshots, STAGE=stage, PACKAGE=package, HELPER=helper,
                    BACKUP=backup, POINTER=pointer, UNIT_PATHS=unit_paths,
                    UNIT_HASHES={name: install.digest(raw) for name, raw in previous.items()}, EXPECTED=expected,
                    PACKAGE_CONFIG_HASH=install.digest(install.encoded(owner)), PACKAGE_JOURNAL_HASH=install.digest(install.encoded(old_coord))), \
                    patch.object(install, 'original', side_effect=original), patch.object(install, 'module', side_effect=loaded), \
                    patch.object(guard, 'run', side_effect=guarded_run):
                    if fail_reload:
                        with self.assertRaisesRegex(RuntimeError, 'rolled back'): install.install(inputs, (ROOT/'install-coordinated-boot-guard.py').read_bytes())
                        self.assertFalse(pointer.exists())
                        for name, path in unit_paths.items(): self.assertEqual(path.read_bytes(), previous[name])
                        self.assertEqual(install.digest(helper.read_bytes()), install.HELPER_V2_HASH)
                    else:
                        result = install.install(inputs, (ROOT/'install-coordinated-boot-guard.py').read_bytes())
                        self.assertEqual(result['status'], 'INSTALLED_AND_READBACK_VERIFIED')
                        self.assertTrue(result['runtimeReadiness']['stableAcrossReads'])
                        self.assertFalse(result['startAuthorized']); self.assertFalse(result['leaseAuthorized'])
                        self.assertEqual(pointer.stat().st_nlink, 1)
                        self.assertEqual(install.digest(helper.read_bytes()), install.HELPER_V3_HASH)
                        with self.assertRaisesRegex(ValueError, 'no replay'): install.install(inputs, b'ignored')
                self.assertTrue(proof)
                self.assertEqual(old_journal_path.read_bytes(), b'{"state":"RUNTIME_EMPTY"}')
                self.assertEqual((package/'coordination-journal.json').read_bytes(), install.encoded(old_coord))
                self.assertEqual(guard.tables(old_config), original_tables)
                print('COORDINATED_INSTALL_NATIVE=PASS ACTUAL_ROOT_FILE_PUBLICATION=true REAL_NFT_READ_ONLY=true'
                      ' READ_ONLY_CLI=true SYSTEMD_AND_CUSTODY_ADAPTERS_SIMULATED=true'
                      ' RELOAD_FAILURE_ROLLBACK='+str(fail_reload).lower()+' NO_CONTAINER_OR_PROVIDER_OPERATIONS=true')
        finally:
            command(['nft', '-f', '-'], 'delete table inet install_fixture\ndelete table bridge install_fixture\n')

    def test_installation_and_bounded_readback(self): self.exercise()
    def test_reload_failure_restores_all_previous_files(self): self.exercise(True)


if __name__ == '__main__': unittest.main()
