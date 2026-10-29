"""Real durable Runner/Store and actual controller threads; native/IAM simulated.

This proves scheduling, bounded observation and no redispatch, not real Docker,
issuer admission or JVM readiness. The separate native fixture owns those tests.
"""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from tools.semantic_registry_recovery_execution import core as c, postboot_controller as controller


class SimulatedPorts(c.Ports):
    def __init__(self, store, generation):
        self.store, self.generation = store, generation
        self.calls, self.observations = [], []
        self.unknown = {}
        self.missing_ack, self.crash, self.denied = False, False, False
        self.in_step = False

    def guard(self, plan, row, stage):
        c.require(not self.denied, 'SIMULATED_AUTHORITY_REVOKED')

    def apply(self, plan, row, stage):
        self.calls.append(stage['name'])
        effects = copy.deepcopy(row['effects'])
        if stage['name'] != 'ATTEST_NEW_GENERATION':
            effects[-1]['nativeRequestAttempted'] = True
            if not (self.missing_ack and row['nextStage'] == 9):
                effects[-1]['nativeResponse204'] = True
            self.store.cas(row, {**row, 'effects': effects, 'version': row['version'] + 1})
        if self.crash and row['nextStage'] == 9:
            raise OSError('SIMULATED_AMBIGUOUS_RELEASE')

    def observe(self, plan, row, stage):
        index = row['nextStage']; self.observations.append(index)
        if self.unknown.get(index, 0):
            self.unknown[index] -= 1
            return 'UNKNOWN', {'applicationReadinessProven': False}
        proof = {'newGeneration': copy.deepcopy(self.generation), 'durableNativeStartEvidence': True}
        if index == 11:
            proof.update(httpStatus=200, originalSemanticGetSucceeded=True)
        return 'APPLIED', proof


class SimulatedWitness:
    def __init__(self, runner):
        self.runner, self.denied, self.changed = runner, False, False

    def observe(self, stage):
        c.require(stage == 'ACTIVE' and not self.denied, 'SIMULATED_WITNESS_AUTHORITY_REVOKED')
        row = self.runner.current(); generation = copy.deepcopy(row['newGeneration'])
        if self.changed:
            generation['startTicks'] += 1
        return {'checkpoint': row['nextStage'], 'runtimeGeneration': generation}


class Controller(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('controller_proposal_fixture',
            root / 'semantic_registry_recovery_composition/compose.py')
        compose = importlib.util.module_from_spec(spec); spec.loader.exec_module(compose)
        proposal = {'registry': {'containerId': 'a' * 64}, 'requiredGates': list(compose.GATES), 'unresolvedGateCount': 8}
        self.plan = compose.candidate_contract(proposal, 'b' * 64, 'c' * 64)
        temporary = tempfile.TemporaryDirectory(dir=Path.cwd()); self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name) / ('semantic-registry-recovery-' + self.plan['logicalOperationRef'])
        directory.mkdir(mode=0o700)
        self.store = c.Store(directory, self.plan['logicalOperationRef'])
        self.generation = {'containerId': 'a' * 64, 'bootId': '11111111-2222-3333-4444-555555555555',
                          'pid': 4242, 'startTicks': 12345, 'namespaceDevice': 4, 'namespaceInode': 12}
        self.clocks = [100., 50.]
        self.store.initialize(c.initial(self.plan, authority_hash='d' * 64, expires_unix=900,
            expires_monotonic=850, boot_id=self.generation['bootId'], predecessor_history_hash='e' * 64,
            created_unix=100, created_monotonic=50))
        self.ports = SimulatedPorts(self.store, self.generation)
        self.runner = c.Runner(self.plan, self.store, self.ports,
            boot_id=self.generation['bootId'], clock=lambda: tuple(self.clocks))
        self.witness = SimulatedWitness(self.runner)
        self.wait = controller.ColdStartWait(monotonic=lambda: self.clocks[1])

    def advance(self, target):
        while self.runner.current()['nextStage'] < target:
            self.runner.step()

    def unknown(self, index):
        self.advance(index); self.ports.unknown[index] = 1
        before = self.runner.current(); after = self.runner.step()
        return before, after

    def test_acknowledged_release_cold_start_and_final_get_share_one_wait_and_no_new_effect(self):
        for index in (9, 10, 11):
            before, after = self.unknown(index)
            prior_reads = after['readAttempts']; prior_calls = list(self.ports.calls)
            delay = self.wait.defer(self.runner, before, after, self.witness)
            self.clocks[:] = [value + delay for value in self.clocks]
            self.wait.before_poll(self.runner, self.witness)
            row = self.runner.step()
            self.assertEqual(row['nextStage'], index + 1)
            self.assertEqual(row['readAttempts'], prior_reads + 1)
            self.assertEqual(self.ports.calls, prior_calls)
        self.assertEqual(self.wait.observations, 3)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)
        self.assertTrue(row['originalSemanticGetSucceeded'])

    def test_missing_release_ack_never_enters_automatic_observation_wait(self):
        self.ports.missing_ack = True
        before, after = self.unknown(9)
        with self.assertRaisesRegex(c.RecoveryDenied, 'AMBIGUOUS_RELEASE'):
            self.wait.defer(self.runner, before, after, self.witness)
        self.assertEqual(self.wait.observations, 0)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)

    def test_earlier_unknown_is_not_reclassified_as_cold_start(self):
        before, after = self.unknown(3)
        with self.assertRaisesRegex(c.RecoveryDenied, 'NATIVE_OUTCOME_REQUIRES_RECONCILIATION'):
            self.wait.defer(self.runner, before, after, self.witness)
        self.assertEqual(self.wait.observations, 0)

    def test_wait_requires_same_current_generation_and_authority(self):
        before, after = self.unknown(9)
        self.witness.changed = True
        with self.assertRaisesRegex(c.RecoveryDenied, 'CURRENT_GENERATION_REQUIRED'):
            self.wait.defer(self.runner, before, after, self.witness)
        self.witness.changed = False; self.witness.denied = True
        with self.assertRaisesRegex(c.RecoveryDenied, 'WITNESS_AUTHORITY_REVOKED'):
            self.wait.defer(self.runner, before, after, self.witness)

    def test_concurrent_journal_progress_during_wait_is_not_adopted(self):
        before, after = self.unknown(9)
        self.wait.defer(self.runner, before, after, self.witness)
        self.runner.step()
        with self.assertRaisesRegex(c.RecoveryDenied, 'WAIT_JOURNAL_CHANGED'):
            self.wait.before_poll(self.runner, self.witness)

    def test_elapsed_bound_and_clock_regression_stop_without_a_second_signal(self):
        before, after = self.unknown(9)
        self.wait.defer(self.runner, before, after, self.witness)
        self.clocks[1] += controller.COLD_START_WAIT_SECONDS
        with self.assertRaisesRegex(c.RecoveryDenied, 'OBSERVATION_WINDOW_EXHAUSTED'):
            self.wait.before_poll(self.runner, self.witness)
        self.clocks[1] = 49
        with self.assertRaisesRegex(c.RecoveryDenied, 'WAIT_CLOCK_CHANGED'):
            self.wait.before_poll(self.runner, self.witness)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)

    def test_additional_observation_cap_does_not_reset_across_pending_reads(self):
        self.advance(9); self.ports.unknown[9] = 100
        for _ in range(controller.COLD_START_ADDITIONAL_OBSERVATIONS):
            before = self.runner.current(); row = self.runner.step()
            self.wait.defer(self.runner, before, row, self.witness)
            self.wait.before_poll(self.runner, self.witness)
        before = self.runner.current(); row = self.runner.step()
        with self.assertRaisesRegex(c.RecoveryDenied, 'OBSERVATION_LIMIT_EXHAUSTED'):
            self.wait.defer(self.runner, before, row, self.witness)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)

    def test_original_durable_read_budget_remains_authoritative(self):
        self.advance(10)
        row = self.store.read()
        self.store.cas(row, {**row, 'version': row['version'] + 1, 'readAttempts': 127})
        before, after = self.unknown(10)
        self.wait.defer(self.runner, before, after, self.witness)
        self.wait.before_poll(self.runner, self.witness)
        with self.assertRaisesRegex(c.RecoveryDenied, 'RECOVERY_READ_BUDGET_EXHAUSTED'):
            self.runner.step()
        self.assertEqual(self.store.read()['readAttempts'], 128)

    def test_signed_window_expiration_during_wait_stops_before_another_observation(self):
        before, after = self.unknown(10)
        self.wait.defer(self.runner, before, after, self.witness)
        self.clocks[0] = 900
        with self.assertRaisesRegex(c.RecoveryDenied, 'CURRENT_FINITE_RECOVERY_SCOPE_REQUIRED'):
            self.wait.before_poll(self.runner, self.witness)
        self.assertEqual(self.store.read()['readAttempts'], after['readAttempts'])

    def coordinated(self, *, missing_ack=False, crash=False, end_on_wait=False, termination='token_expiry'):
        self.advance(4)
        self.ports.unknown = {9: 1, 10: 1, 11: 1}
        self.ports.missing_ack, self.ports.crash = missing_ack, crash
        finish, waiting, heartbeat = threading.Event(), threading.Event(), threading.Event()
        case = self; records = []; self.last_records = records
        class SimulatedWorker:
            def __init__(self):
                self.ended, self.shared_lock, self.overlap = False, None, False
                self.row = {'state': 'ACTIVE', 'reason': 'PUBLICATION_VERIFIED',
                    'contextRef': 'fixture-context', 'generationRef': 'fixture-generation', 'policyHash': 'fixture-policy',
                    'startedWall': 100, 'startedMonotonic': 50, 'lastWall': 100, 'lastMonotonic': 50,
                    'tokenExpiresWall': 800, 'tokenExpiresMonotonic': 750}
                self.r = SimpleNamespace(journal=SimpleNamespace(read=lambda: copy.deepcopy(self.row)),
                    now=lambda: tuple(case.clocks), remaining=lambda row: 800-(case.clocks[0]-100),
                    policy=SimpleNamespace(max_elapsed=800), validate=lambda row: None)
            def run(self, stop, observe, coordination_lock):
                self.shared_lock = coordination_lock
                try:
                    with coordination_lock:
                        observe({'state': 'ACTIVE'})
                    while not finish.is_set() and not stop.wait(.001):
                        with coordination_lock:
                            self.overlap |= case.ports.in_step
                            if waiting.is_set():
                                heartbeat.set()
                                if end_on_wait:
                                    return {'state': 'BLOCKED'}
                    if termination == 'raise':
                        raise RuntimeError('PRIVATE_SIMULATED_OWNER_FAILURE')
                    if termination == 'token_expiry':
                        case.clocks[:] = [800, 750]
                        self.row.update(state='RECONCILE_REQUIRED', reason='TOKEN_VALIDITY_WINDOW_EXPIRED',
                                        lastWall=800, lastMonotonic=750)
                    elif termination == 'blocked':
                        self.row.update(state='BLOCKED', reason='AUTHORITY_REVOKED')
                    else:
                        self.row.update(state='CANCELLED', reason='CANCELLED_BY_OWNER')
                    return copy.deepcopy(self.row)
                finally:
                    self.ended = True
        worker = SimulatedWorker()
        prefix = SimpleNamespace(current=self.runner.current, ports=SimpleNamespace(witness=self.witness))
        factory = ModuleType('tools.semantic_registry_recovery_execution.postboot_factory')
        factory.build_on_bootstrap = lambda *args: self.runner
        owner = ModuleType('tools.semantic_registry_postboot_owner.owner')
        owner.build_worker = lambda *args: worker
        scheduler = ModuleType('tools.semantic_registry_postboot_owner.scheduler')
        scheduler.PostbootRenewalWorker = SimulatedWorker
        actual_step = self.runner.step
        def tracked_step():
            self.ports.in_step = True
            try:
                time.sleep(.002)
                return actual_step()
            finally:
                self.ports.in_step = False
        def emit(value):
            records.append(value)
            if value.get('status') == 'READ_ONLY_COLD_START_WAIT':
                waiting.set()
            if value.get('status') == 'ORIGINAL_SERVICE_GET_200_WITH_FINITE_OWNER':
                self.assertTrue(heartbeat.is_set(), 'Worker must run while controller waits')
                finish.set()
        with patch.dict(sys.modules, {factory.__name__: factory, owner.__name__: owner, scheduler.__name__: scheduler}), \
                patch.object(controller.bootstrap, 'build', return_value=prefix), \
                patch.object(controller, 'COLD_START_POLL_SECONDS', .03), \
                patch.object(self.runner, 'step', tracked_step):
            try:
                result = controller.continue_recovery({}, {'budget': {'attemptTimeoutSeconds': 1}},
                    object(), b'fixture', None, None, emit)
            finally:
                self.assertTrue(worker.ended)
                self.assertFalse(worker.overlap)
        return result, records

    def test_coordinator_releases_shared_lock_while_waiting_and_keeps_worker_until_success(self):
        result, records = self.coordinated()
        self.assertTrue(result['originalSemanticGetSucceededDuringWindow'])
        self.assertTrue(result['ownerSessionEnded'])
        self.assertEqual(result['status'], 'FINITE_PUBLISHED_TOKEN_WINDOW_ENDED')
        self.assertFalse(result['continuousServiceRenewalEstablished'])
        self.assertEqual(sum(v.get('status') == 'READ_ONLY_COLD_START_WAIT' for v in records), 3)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)

    def test_coordinator_stops_owner_on_missing_ack_without_automatic_reconciliation(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'AMBIGUOUS_RELEASE'):
            self.coordinated(missing_ack=True)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)

    def test_native_transport_exception_is_not_swallowed_or_retried(self):
        with self.assertRaisesRegex(OSError, 'SIMULATED_AMBIGUOUS_RELEASE'):
            self.coordinated(crash=True)
        self.assertEqual(self.ports.calls.count('RELEASE_SAME_GENERATION_SIGUSR1'), 1)

    def test_owner_termination_during_wait_stops_before_next_read(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'OWNER_ENDED_BEFORE_RECOVERY'):
            self.coordinated(end_on_wait=True)
        self.assertEqual(self.store.read()['nextStage'], 9)
        self.assertEqual(self.ports.observations.count(9), 1)

    def test_owner_exception_after_success_preserves_get_truth_and_stops(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'OWNER_TERMINATION_REQUIRES_RECONCILIATION'):
            self.coordinated(termination='raise')
        result = self.last_records[-1]
        self.assertEqual(result['status'], 'UNEXPECTED_OWNER_TERMINATION')
        self.assertTrue(result['originalSemanticGetSucceededDuringWindow'])
        self.assertFalse(result['currentOwnerAdmissionProven'])
        self.assertNotIn('PRIVATE_SIMULATED_OWNER_FAILURE', str(self.last_records))

    def test_owner_revocation_after_success_cannot_be_reported_as_normal_end(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'OWNER_TERMINATION_REQUIRES_RECONCILIATION'):
            self.coordinated(termination='blocked')
        self.assertEqual(self.last_records[-1]['status'], 'UNEXPECTED_OWNER_TERMINATION')
        self.assertTrue(self.last_records[-1]['originalSemanticGetSucceededDuringWindow'])

    def test_unrequested_owner_cancellation_after_success_is_unexpected(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'OWNER_TERMINATION_REQUIRES_RECONCILIATION'):
            self.coordinated(termination='cancelled')
        self.assertEqual(self.last_records[-1]['status'], 'UNEXPECTED_OWNER_TERMINATION')

    def test_expected_expiry_requires_closed_reason_and_actual_consistent_clocks(self):
        active = {'state': 'ACTIVE', 'reason': 'NONE', 'contextRef': 'fixture', 'generationRef': 'generation',
            'policyHash': 'policy', 'startedWall': 100, 'startedMonotonic': 50, 'lastWall': 110, 'lastMonotonic': 60,
            'tokenExpiresWall': 300, 'tokenExpiresMonotonic': 250}
        native = {'expiresUnix': 250, 'expiresMonotonic': 200}
        final = dict(active); now = [300, 250]
        worker = SimpleNamespace(r=SimpleNamespace(journal=SimpleNamespace(read=lambda: copy.deepcopy(final)),
            validate=lambda row: None, now=lambda: tuple(now), policy=SimpleNamespace(max_elapsed=500)))
        def status():
            return controller.owner_end_status(worker, {'row': copy.deepcopy(final)}, active, native)
        final.update(state='RECONCILE_REQUIRED', reason='TOKEN_VALIDITY_WINDOW_EXPIRED')
        self.assertEqual(status(), 'UNEXPECTED_OWNER_TERMINATION')  # Row stopped before expiry.
        final.update(lastWall=300, lastMonotonic=250)
        self.assertEqual(status(), 'FINITE_PUBLISHED_TOKEN_WINDOW_ENDED')
        final.update(state='BLOCKED', reason='LOCAL_AUTHORITY_UNPROVEN')
        self.assertEqual(status(), 'UNEXPECTED_OWNER_TERMINATION')  # Expiry cannot explain this generic failure.
        final['reason'] = 'AUTHORITY_EXPIRED'
        self.assertEqual(status(), 'FINITE_OWNER_AUTHORITY_WINDOW_ENDED')  # Signed window can precede max_elapsed.
        final.update(state='PAUSED_EXHAUSTED', reason='FINITE_OWNER_OPERATION_EXHAUSTED')
        self.assertEqual(status(), 'UNEXPECTED_OWNER_TERMINATION')
        now[:] = [600, 550]; final.update(lastWall=600, lastMonotonic=550)
        self.assertEqual(status(), 'FINITE_OWNER_OPERATION_WINDOW_ENDED')
        now[:] = [599, 549]
        self.assertEqual(status(), 'UNEXPECTED_OWNER_TERMINATION')  # Future/fabricated stop clocks.


if __name__ == '__main__':
    unittest.main()
