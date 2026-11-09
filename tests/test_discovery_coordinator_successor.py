import copy
import importlib.util
import io
import json
import contextlib
from pathlib import Path
import tempfile
import types
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
    def receipt(self):
        return json.loads((ROOT / 'evidence/discovery-nft-drift-operator-20261109.json').read_bytes())

    def test_complete_operator_receipt_passes_original_producer_bytes(self):
        receipt = self.receipt()
        self.assertIs(False, receipt['installedBoot']['retainedPreflightFootprintMatches'])
        raw = d.encoded(receipt)
        self.assertEqual('fcea4316cd6daa153c454c6ddab59feedf61ff57ffc5f921eac6eb4e6ac8eeb3', m.sha(raw))
        m.verify_reviewed_receipt(raw)

    def test_omitted_operator_field_reproduces_bad_pin_and_is_rejected(self):
        receipt = self.receipt(); del receipt['installedBoot']['retainedPreflightFootprintMatches']
        raw = d.encoded(receipt)
        self.assertEqual('ac43eb0ab617bb0039cfc431bf427ca88ec5e81f513a540da54ef21bc430fde2', m.sha(raw))
        with self.assertRaisesRegex(RuntimeError, 'EXACT_DRIFT_RECEIPT_REQUIRED'): m.verify_reviewed_receipt(raw)

    def test_changed_field_or_bytes_still_rejected(self):
        receipt = self.receipt(); exact = d.encoded(receipt)
        receipt['installedBoot']['retainedPreflightFootprintMatches'] = True
        for raw in (d.encoded(receipt), exact.rstrip(b'\n'), exact + b'\n'):
            with self.subTest(sha=m.sha(raw)), self.assertRaisesRegex(RuntimeError, 'EXACT_DRIFT_RECEIPT_REQUIRED'):
                m.verify_reviewed_receipt(raw)

    def run_receipt_preflight(self, raw):
        # Run main's actual first gate; no Docker, nft or filesystem mutations.
        p = q.load_helper('reconcile-discovery-placeholder-20261109.py')
        l = q.load_helper('read-discovery-lifecycle-20261109.py')
        fake_q = types.SimpleNamespace(load_helper=lambda name: p if name.startswith('reconcile-') else l,
                                       load_core=lambda: core, CLAIM=q.CLAIM, RECEIPT=q.RECEIPT)
        fake_d = types.SimpleNamespace(load_quiesce=lambda: fake_q)
        output = io.StringIO()
        with patch.object(m, 'load_drift', return_value=fake_d), patch.object(m.os, 'geteuid', return_value=0), \
             patch.object(m.os, 'umask'), patch.object(m.os.path, 'lexists', return_value=False), \
             patch.object(m.signal, 'signal'), patch.object(m.signal, 'alarm'), \
             patch.object(p, 'read_private', side_effect=[raw, RuntimeError('FOLLOWING_PREFLIGHT_REACHED')]) as read, \
             patch.object(p, 'save') as save, patch.object(m.os, 'mkdir') as mkdir, \
             contextlib.redirect_stdout(output):
            self.assertEqual(1, m.main())
            save.assert_not_called(); mkdir.assert_not_called()
        return json.loads(output.getvalue()), read.call_count

    def test_main_accepts_complete_receipt_then_reaches_next_read_without_intent(self):
        report, reads = self.run_receipt_preflight(d.encoded(self.receipt()))
        self.assertEqual('FOLLOWING_PREFLIGHT_REACHED', report['reason']); self.assertEqual(2, reads)
        self.assertEqual(m.RECEIPT_SHA, report['reviewedReceiptSha256'])
        self.assertFalse(report['operationIntentPresent']); self.assertFalse(report['stagedContextCreated'])

    def test_main_rejects_incomplete_receipt_before_following_read_or_writes(self):
        receipt = self.receipt(); del receipt['installedBoot']['retainedPreflightFootprintMatches']
        report, reads = self.run_receipt_preflight(d.encoded(receipt))
        self.assertEqual('EXACT_DRIFT_RECEIPT_REQUIRED', report['reason']); self.assertEqual(1, reads)
        self.assertFalse(report['operationIntentPresent']); self.assertFalse(report['stagedContextCreated'])

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
