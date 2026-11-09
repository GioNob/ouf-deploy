import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('successor', ROOT / 'scripts/stage-discovery-coordinator-successor-20261109.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
d = m.load_drift(); q = d.load_quiesce(); core = q.load_core()
spec = importlib.util.spec_from_file_location('old_fixture', Path(__file__).with_name('test_discovery_quiesce.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
SOURCE = ROOT / 'owner-source' if (ROOT / 'owner-source').is_dir() else ROOT / 'gateway-source'


def sources():
    expected = {'tools/' + name + '.py': value for name, value in q.CORE.items()}; expected.update(m.EXTRA_SOURCE)
    return {name: (SOURCE / name).read_bytes() for name in expected}


def inputs(root, structure, footprint, nft='/usr/sbin/nft', nft_sha='a' * 64):
    expected = {name: m.sha(raw) for name, raw in sources().items()}
    boot_names = {'scripts/run_semantic_coordinated_boot_guard.py', 'tools/semantic_provider_boot_coordination.py'}
    owner = {'schema': 'ouf.semantic-coordinated-owner-runtime.v1', 'kernel': f.kernel(), 'dns': f.dns(),
             'expectedStructureHash': structure, 'nftPath': nft, 'nftSha256': nft_sha, 'readBudgetSeconds': 5, 'pollSeconds': 15,
             'commonLockFile': str(root / 'common.lock'), 'journalFile': str(root / 'coordination-journal.json'),
             'sourceHashes': {k: v for k, v in expected.items() if k not in boot_names}}
    owner['binding'] = {'transactionId': '1' * 64, 'configurationHash': m.digest(owner), 'leaseStructureHash': structure}
    boot = {'schema': 'ouf.semantic-runtime-boot-guard.v1', 'nftPath': nft, 'kernel': f.kernel(),
            'compilerFile': str(root / 'compiler.py'), 'compilerHash': 'b' * 64, 'expectedFootprint': footprint,
            'journalFile': str(root / 'boot-journal.json'), 'transactionId': '1' * 64, 'lockFile': owner['commonLockFile']}
    profile = {'schema': 'ouf.semantic-coordinated-boot-profile.v1', 'sourceHashes': {k: v for k, v in expected.items() if k in boot_names},
               'coordinatedConfiguration': str(root / 'coordinated-configuration.json'), 'coordinatedConfigurationHash': m.digest(owner),
               'bootConfiguration': str(root / 'boot-configuration.json'), 'bootConfigurationHash': m.digest(boot),
               'bootGuardFile': str(root / 'restorer.py'), 'bootGuardHash': 'c' * 64}
    return owner, boot, profile


class SuccessorContracts(unittest.TestCase):
    def test_new_context_changes_only_binding_and_journal_locations(self):
        owner, boot, profile = inputs(Path('/old'), 'a' * 64, 'b' * 64)
        before = copy.deepcopy((owner, boot, profile))
        files = m.build_successor(Path('/new'), owner, boot, profile, 'c' * 64, 'd' * 64)
        self.assertEqual(before, (owner, boot, profile)); fresh = files['coordinated-configuration.json']
        for key in owner:
            if key not in ('binding', 'journalFile', 'expectedStructureHash'): self.assertEqual(owner[key], fresh[key])
        self.assertEqual('c' * 64, fresh['binding']['leaseStructureHash'])
        self.assertEqual(m.digest({k: v for k, v in fresh.items() if k != 'binding'}), fresh['binding']['configurationHash'])
        self.assertEqual(m.digest(fresh), files['boot-profile.json']['coordinatedConfigurationHash'])
        self.assertEqual(m.digest(files['boot-configuration.json']), files['boot-profile.json']['bootConfigurationHash'])
        self.assertEqual('QUIESCED', files['coordination-journal.json']['state'])
        self.assertFalse(files['coordination-journal.json']['leaseAuthorized']); self.assertFalse(files['coordination-journal.json']['startAuthorized'])
        self.assertEqual([[], []], files['coordination-journal.json']['leaseAddresses'])

    def test_old_directory_transaction_or_unknown_profile_field_refused(self):
        owner, boot, profile = inputs(Path('/old'), 'a' * 64, 'b' * 64)
        with self.assertRaisesRegex(RuntimeError, 'SEPARATE_SUCCESSOR_DIRECTORY_REQUIRED'): m.build_successor(Path('/old'), owner, boot, profile, 'c' * 64, 'd' * 64)
        with self.assertRaisesRegex(RuntimeError, 'NEW_EXPLICIT_BINDING_REQUIRED'): m.build_successor(Path('/new'), owner, boot, profile, 'c' * 64, '1' * 64)
        with self.assertRaisesRegex(RuntimeError, 'EXACT_SOURCE_PROFILE_SHAPES_REQUIRED'): m.build_successor(Path('/new'), {**owner, 'unreviewed': True}, boot, profile, 'c' * 64, 'd' * 64)

    def test_closed_source_bytes_are_required(self):
        owner, boot, profile = inputs(Path('/old'), 'a' * 64, 'b' * 64); raw = sources()
        read = lambda path: raw[str(path.relative_to('/old/source'))]
        self.assertEqual(10, len(m.source_closure(q, owner, profile, read, Path('/old'))))
        raw['scripts/run_semantic_coordinated_lease_owner.py'] += b'\n'
        with self.assertRaisesRegex(RuntimeError, 'SOURCE_CLOSURE_BYTES_CHANGED'): m.source_closure(q, owner, profile, read, Path('/old'))

    def test_extra_source_cannot_extend_root_execution_closure(self):
        owner, boot, profile = inputs(Path('/old'), 'a' * 64, 'b' * 64)
        owner['sourceHashes']['tools/foreign.py'] = 'e' * 64
        with self.assertRaisesRegex(RuntimeError, 'EXACT_ORIGINAL_TEN_SOURCE_CLOSURE_REQUIRED'):
            m.source_closure(q, owner, profile, lambda _: self.fail('read foreign source'), Path('/old'))

    def test_writes_refuse_existing_files_and_preserve_original(self):
        p = q.load_helper('reconcile-discovery-placeholder-20261109.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); owner, boot, profile = inputs(Path('/old'), 'a' * 64, 'b' * 64)
            files = m.build_successor(root, owner, boot, profile, 'c' * 64, 'd' * 64)
            (root / 'coordination-journal.json').write_bytes(b'foreign')
            with self.assertRaises(FileExistsError): m.write_successor(p, root, files, {})
            self.assertEqual(b'foreign', (root / 'coordination-journal.json').read_bytes())

    def test_helper_pin_checked_before_execution(self):
        with patch.object(m, 'DRIFT_SHA', '0' * 64), self.assertRaisesRegex(RuntimeError, 'PINNED_DRIFT_HELPER_CHANGED'): m.load_drift()


if __name__ == '__main__': unittest.main()
