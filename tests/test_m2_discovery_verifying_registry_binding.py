"""Real evidence store and existing readers; Engine and process leaves modeled.

The negative control executes the actual completed-only reader. It cannot read
an IN_FLIGHT verification cursor. The new reader succeeds without that receipt.
"""
import copy, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_selected_runtime  # retained module path setup
from gated_process_observation import RunningWorkloadBinding
from gated_creation_plan import ENTRY
from tools.m2_discovery_installation_profile import verifying_registry_binding as m


class VerifyingBinding(unittest.TestCase):
    def prepared(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); root.chmod(0o700); store = m.NativeEvidenceStore(root)
        request = {'Entrypoint': ENTRY, 'User': '10001:10001', 'Cmd': ['java', '-jar', '/app/application.jar']}
        actual = {'Id': 'a'*64, 'Image': 'sha256:'+'b'*64, 'Config': {}, 'HostConfig': {}, 'Mounts': [],
            'NetworkSettings': {}, 'RestartCount': 0, 'State': {'Pid': 12345, 'StartedAt': 'fixture',
                'Running': True, 'Paused': False, 'Restarting': False, 'Status': 'running'}}
        process = {'generation': {'pid': 12345, 'startTicks': 99, 'namespaceInode': 1},
            'processKind': 'APPLICATION_RUNNING'}
        engine = object.__new__(m.Engine); engine.inspect = Mock(side_effect=lambda _: copy.deepcopy(actual))
        engine.matching_configuration = Mock(side_effect=lambda t, r, a: a)
        transition = object.__new__(m.Transition); transition.context = 'c'*64
        effects = [{'phase': phase, 'state': 'APPLIED', 'intentHash': m.digest({'phase': phase})}
            for phase in m.PHASES[:12]]; effects[-1]['state'] = 'IN_FLIGHT'
        release = effects[10]
        evidence = {'schema': 'ouf.semantic-gated-application-release.v1', 'transitionContextHash': transition.context,
            'intentHash': release['intentHash'], 'runtimeBinding': m.Engine.runtime_binding(actual),
            'generation': copy.deepcopy(process['generation']), 'processKind': 'APPLICATION_RUNNING'}
        store.publish('START_REPLACEMENT', evidence); release['nativeEvidenceHash'] = m.digest(evidence)
        row = {'state': 'IN_FLIGHT', 'nextPhase': 11, 'creationRequestHash': m.digest(request), 'effects': effects}
        transition.read = Mock(side_effect=lambda: copy.deepcopy(row))
        reader = m.VerifyingRegistryBinding(engine, transition, request, store)
        reader.process.observe = Mock(side_effect=lambda _: copy.deepcopy(process))
        return reader, actual, process, row, store, evidence

    def test_completed_only_reader_cannot_run_inside_verification_new_reader_uses_only_release(self):
        reader, _, _, row, store, _ = self.prepared()
        completed = RunningWorkloadBinding(reader.engine, reader.transition, reader.request, store)
        with self.assertRaises(StopIteration): completed.observe()
        with patch.object(store, 'read', wraps=store.read) as read:
            result = reader.observe()
        self.assertEqual({call.args[0] for call in read.call_args_list}, {'START_REPLACEMENT'})
        self.assertEqual(result['process']['processKind'], 'APPLICATION_RUNNING')
        self.assertEqual(row['effects'][-1]['state'], 'IN_FLIGHT'); self.assertFalse(store.path('VERIFY_APPLICATION').exists())

    def test_already_published_verification_payload_is_not_required_or_consumed(self):
        reader, _, _, _, store, _ = self.prepared()
        store.publish('VERIFY_APPLICATION', {'modeledReadiness': 'owner-not-reconciled-yet'})
        reader.observe()
        self.assertEqual(store._read('VERIFY_APPLICATION'), {'modeledReadiness': 'owner-not-reconciled-yet'})

    def test_wrong_cursor_or_incomplete_prefix_denies_before_engine_read(self):
        reader, _, _, row, _, _ = self.prepared(); original = copy.deepcopy(row)
        for change in ('ready', 'complete', 'bool', 'missing', 'prior'):
            row.clear(); row.update(copy.deepcopy(original))
            if change == 'ready': row['state'] = 'READY'
            elif change == 'complete': row['effects'][-1]['state'] = 'APPLIED'
            elif change == 'bool': row['nextPhase'] = True
            elif change == 'missing': row['effects'].pop(7)
            else: row['effects'][8]['state'] = 'IN_FLIGHT'
            with self.subTest(change=change), self.assertRaises(ValueError): reader.observe()
        reader.engine.inspect.assert_not_called()

    def test_release_hash_or_source_context_drift_denies_without_repair(self):
        reader, _, _, row, store, evidence = self.prepared(); path = store.path('START_REPLACEMENT')
        path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'JOURNAL_BINDING_DRIFT'): reader.observe()
        self.assertEqual(path.read_bytes(), b'{}'); reader.engine.inspect.assert_not_called()

    def test_release_from_other_context_cannot_establish_running_generation(self):
        reader, _, _, _, _, _ = self.prepared(); reader.transition.context = 'f'*64
        with self.assertRaisesRegex(ValueError, 'EXACT_COMPLETED_APPLICATION_RELEASE'): reader.observe()
        reader.engine.inspect.assert_not_called()

    def test_restarted_paused_or_wrong_native_generation_denies(self):
        reader, actual, process, _, _, _ = self.prepared(); original = copy.deepcopy(actual)
        for change in ('restart', 'paused', 'restarting', 'pid', 'kind', 'generation'):
            actual.clear(); actual.update(copy.deepcopy(original)); process['processKind'] = 'APPLICATION_RUNNING'
            process['generation']['startTicks'] = 99
            if change == 'restart': actual['RestartCount'] = 1
            elif change == 'paused': actual['State']['Paused'] = True
            elif change == 'restarting': actual['State']['Restarting'] = True
            elif change == 'pid': actual['State']['Pid'] += 1
            elif change == 'kind': process['processKind'] = 'GATE_WAITING'
            else: process['generation']['startTicks'] += 1
            with self.subTest(change=change), self.assertRaises(ValueError): reader.observe()

    def test_history_change_between_reads_cannot_be_returned_as_same_generation(self):
        reader, _, process, row, _, _ = self.prepared()
        def change(pid):
            result = copy.deepcopy(process); row['operatorChange'] = True; return result
        reader.process.observe.side_effect = change
        with self.assertRaisesRegex(ValueError, 'CHANGED_DURING_NATIVE'): reader.observe()


if __name__ == '__main__': unittest.main()
