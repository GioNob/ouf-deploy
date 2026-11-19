"""Real installed material/signatures; process, release and prefix leaves modeled.

Checks the concrete phase router without claiming a complete native controller,
target admission or the database/OCI semantics of synthetic prefix payloads.
"""
import copy, hashlib, sys, unittest
from pathlib import Path
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_paused_operational_worker as fixtures
from tools.m2_discovery_installation_profile import operational_checkpoints as m


class OperationalCheckpoints(unittest.TestCase):
    def prepared(self, phase='START_REPLACEMENT', paused=True, kind='GATE_WAITING'):
        case = fixtures.PausedWorker(); previous, w, auth, observed, calls, row = case.prepared(phase=phase)
        self.addCleanup(case.doCleanups); app = previous.app
        app.raw_hash = hashlib.sha256(app.raw).hexdigest(); app.request_hash = w.request_hash
        app.request = copy.deepcopy(w.node.request)
        app.intent_hashes = copy.deepcopy(m.decode(app.raw)['phaseIntentHashes'])
        app.intents = {'START_REPLACEMENT': {'modeledReleaseIntent': True}}
        for effect in row['effects']:
            effect['intentHash'] = app.intent_hashes[effect['phase']]
            if effect['state'] == 'APPLIED':
                try: value = app.store._read(effect['phase'])
                except FileNotFoundError:
                    value = {'modeledPrefixPayload': effect['phase']}; app.store.publish(effect['phase'], value)
                effect['nativeEvidenceHash'] = m.digest(value)
        row['transitionAuthorityEvidenceHash'] = app.raw_hash
        w.transition.read.return_value = copy.deepcopy(row)
        release = object.__new__(m.GatedReleaseAdapter)
        release.engine = w.node.engine; release.transition = app.transition; release.store = app.store
        release.request_hash = app.request_hash  # actual GatedReleaseAdapter has no request attribute
        release.intent = copy.deepcopy(app.intents['START_REPLACEMENT'])
        release.intent_hash = app.intent_hashes['START_REPLACEMENT']
        actual = {'State': {'Paused': paused, 'Restarting': False, 'Status': 'paused' if paused else 'running'}}
        process = {'processKind': kind, 'modeledGeneration': 'same'}
        release.current = Mock(side_effect=lambda _: (copy.deepcopy(row), copy.deepcopy(actual), copy.deepcopy(process)))
        release.engine.runtime_binding = Mock(return_value={'modeledRuntimeBinding': 'same'})
        app.executor = object.__new__(m.DiscoveryExecutor)
        app.executor.discovery_parent = app.discovery_parent
        app.executor.adapters = {'START_REPLACEMENT': release}
        app.executor.additional_authority_fields = Mock()  # this router's parent section validation is modeled
        p = patch.object(m, 'VerifyingRegistryBinding'); running = p.start().return_value.observe
        running.return_value = {'modeledRunningJavaGeneration': 'same'}; self.addCleanup(p.stop)
        return m.NativeOperationalCheckpoints(app), w, auth, observed, calls, row, actual, process, running

    def test_every_late_executor_and_adapter_point_uses_same_signed_normal_handoff(self):
        for phase, points in m.POINTS.items():
            reader, w, auth, _, calls, row, actual, _, _ = self.prepared(phase)
            auth.now += 86; before = list(calls)
            for point in sorted(points):
                paused = point != 'BEFORE_PREAPPLICATION_SIGUSR1'
                actual['State'].update(Paused=paused, Status='paused' if paused else 'running')
                with self.subTest(phase=phase, point=point), \
                     patch.object(w.provider, 'current', side_effect=AssertionError('NO_INITIAL_PROVIDER_REENTRY')), \
                     patch.object(w.signer, 'sign', side_effect=AssertionError('NO_SIGNING')):
                    reader.guard(phase, point, row); reader.generation(phase, point)
                result = reader.observe(phase, 'BEFORE_NATIVE_RECONCILIATION', row) if point == sorted(points)[0] else result
                self.assertEqual(result['currentHistoryHash'], m.digest(row))
                self.assertTrue(result['currentSignedOperationalInstallationVerified'])
                self.assertTrue(result['currentWorkerAndPositiveOwnedLeasesObserved'])
                for key in ('initialProviderMandateExtended', 'newGenerationAuthorized', 'completeCutoverCheckpointProven',
                    'fullCohortProven', 'nativeMutationDispatched', 'producerReleaseDispatched', 'runtimeAuthorityIssued',
                    'targetApplyAuthorized', 'budgetReset', 'releaseAcceptance'):
                    self.assertIs(result[key], False)
                self.assertEqual(calls, before); self.assertEqual(w.transition.read(), row)
            self.doCleanups()

    def test_reconciliation_observes_all_three_release_states_without_dispatch(self):
        reader, _, _, _, calls, row, actual, process, _ = self.prepared(); before = list(calls)
        for paused, kind in ((True, 'GATE_WAITING'), (False, 'GATE_WAITING'), (False, 'APPLICATION_RUNNING')):
            actual['State'].update(Paused=paused, Status='paused' if paused else 'running'); process['processKind'] = kind
            for point in ('BEFORE_NATIVE_RECONCILIATION', 'AFTER_NATIVE_RECONCILIATION'):
                reader.guard('START_REPLACEMENT', point, row); reader.generation('START_REPLACEMENT', point)
            self.assertEqual(calls, before)

    def test_unpause_and_signal_require_their_exact_process_state(self):
        reader, _, _, _, _, row, actual, process, _ = self.prepared()
        for point, paused, kind in (('BEFORE_UNPAUSE', False, 'GATE_WAITING'),
            ('BEFORE_NATIVE_EFFECT', False, 'APPLICATION_RUNNING'),
            ('BEFORE_PREAPPLICATION_SIGUSR1', True, 'GATE_WAITING'),
            ('BEFORE_PREAPPLICATION_SIGUSR1', False, 'APPLICATION_RUNNING')):
            actual['State'].update(Paused=paused, Status='paused' if paused else 'running'); process['processKind'] = kind
            with self.subTest(point=point, paused=paused, kind=kind), self.assertRaises(ValueError):
                reader.generation('START_REPLACEMENT', point)

    def test_unsupported_early_publication_or_release_cursor_is_never_a_positive_checkpoint(self):
        reader, w, _, _, _, row, _, _, _ = self.prepared()
        for phase, point in (('FENCED_BACKUP', 'BEFORE_NATIVE_EFFECT'),
            ('RELEASE_PRODUCERS', 'BEFORE_DISCOVERY_CAPABILITY_PUBLICATION'),
            ('START_REPLACEMENT', 'PARTIAL_CHECKPOINT_READ_ONLY'), ('VERIFY_APPLICATION', 'BEFORE_UNPAUSE')):
            with self.subTest(phase=phase, point=point), self.assertRaises(ValueError): reader.observe(phase, point, row)
        reader.release.current.assert_not_called(); w.node.verify_retained.assert_not_called()

    def test_foreign_history_unsigned_intent_and_replaced_owner_deny_before_native_read(self):
        reader, w, _, _, _, row, _, _, _ = self.prepared(); original = copy.deepcopy(row)
        for change in ('authority', 'prefix', 'owner', 'phase', 'history'):
            row.clear(); row.update(copy.deepcopy(original)); reader.app.executor.adapters['START_REPLACEMENT'] = reader.release
            reader.app.intent_hashes = copy.deepcopy(m.decode(reader.app.raw)['phaseIntentHashes'])
            if change == 'authority': row['transitionAuthorityEvidenceHash'] = 'f'*64
            elif change == 'prefix': row['effects'][0]['state'] = 'IN_FLIGHT'
            elif change == 'owner': reader.app.executor.adapters['START_REPLACEMENT'] = object()
            elif change == 'phase': reader.app.intent_hashes['START_REPLACEMENT'] = 'f'*64
            else: row['version'] += 1
            with self.subTest(change=change), self.assertRaises(ValueError): reader.observe('START_REPLACEMENT', 'BEFORE_UNPAUSE', row)
            reader.release.current.assert_not_called()

    def test_tampered_completed_prefix_payload_is_not_repaired(self):
        reader, w, _, _, _, row, _, _, _ = self.prepared()
        path = w.store.path('STOP_REVOKE_OLD_LEASE'); path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'JOURNAL_BINDING_DRIFT'):
            reader.observe('START_REPLACEMENT', 'BEFORE_UNPAUSE', row)
        self.assertEqual(path.read_bytes(), b'{}'); reader.release.current.assert_not_called()

    def test_revocation_and_expired_parent_stop_without_initial_window_renewal(self):
        reader, w, auth, _, _, row, _, _, _ = self.prepared(); auth.now += 121
        with self.assertRaises(ValueError): reader.observe('START_REPLACEMENT', 'BEFORE_UNPAUSE', row)
        auth.now -= 35
        root = Path(w.template['installationRoot']); raw = (root/'installed.json').read_bytes()
        (root/'receipt-signatures'/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')).unlink()
        with self.assertRaises((OSError, ValueError)): reader.observe('START_REPLACEMENT', 'BEFORE_UNPAUSE', row)

    def test_lost_lease_or_changed_generation_is_not_retried(self):
        reader, _, _, observed, calls, row, _, process, _ = self.prepared(); before = list(calls)
        observed['bothOwnedLeaseFamiliesPositive'] = False
        with self.assertRaises(ValueError): reader.observe('START_REPLACEMENT', 'BEFORE_UNPAUSE', row)
        observed['bothOwnedLeaseFamiliesPositive'] = True
        original = reader.release.current.side_effect
        def drift(intent):
            result = original(intent); process['modeledGeneration'] = 'changed'; return result
        reader.release.current.side_effect = drift
        with self.assertRaises(ValueError): reader.observe('START_REPLACEMENT', 'BEFORE_UNPAUSE', row)
        self.assertEqual(calls, before)


if __name__ == '__main__': unittest.main()
