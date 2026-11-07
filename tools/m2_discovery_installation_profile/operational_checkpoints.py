"""Concrete late Registry checkpoints under the original transition fence.

Observe migration, unpause/signal and Java verification without re-entering the
initial provider mandate. These are operational witnesses, not complete cutover
checkpoint receipts: private artifact membership and other admissions remain
separate. No callbacks, signing, dispatch, journal repair or new retry budget.
"""
import copy
from .custody_capture import decode, digest, require
from .application import DiscoveryApplication
from .executor import DiscoveryExecutor
from .lease_materialization import WorkerMaterialization
from .lease_start_owner import PHASE as WORKER_PHASE
from .current_worker import read_installed_material
from .current_operational_worker import verify_operational_installation
from .node_owner import ObservationBudget
from . import lease_observation
from gated_release_adapter import GatedReleaseAdapter
from .verifying_registry_binding import VerifyingRegistryBinding
from transition_journal import PHASES

EXECUTOR_POINTS = frozenset({'BEFORE_NATIVE_EFFECT', 'AFTER_NATIVE_EFFECT',
    'BEFORE_NATIVE_RECONCILIATION', 'AFTER_NATIVE_RECONCILIATION'})
POINTS = {
    'ADMIT_MIGRATION': EXECUTOR_POINTS,
    'START_REPLACEMENT': EXECUTOR_POINTS | {'BEFORE_UNPAUSE', 'BEFORE_PREAPPLICATION_SIGUSR1'},
    'VERIFY_APPLICATION': EXECUTOR_POINTS | {'BEFORE_APPLICATION_VERIFICATION',
        'BEFORE_APPLICATION_READINESS', 'AFTER_APPLICATION_READINESS'},
}


class NativeOperationalCheckpoints:
    def __init__(self, application):
        require(type(application) is DiscoveryApplication and type(application.executor) is DiscoveryExecutor,
            'ACTUAL_DISCOVERY_APPLICATION_AND_EXECUTOR_FOR_OPERATIONAL_CHECKPOINTS_REQUIRED')
        self.app = application
        self.worker = application.infrastructure_owners[WORKER_PHASE]
        self.release = application.executor.adapters['START_REPLACEMENT']
        require(type(self.worker) is WorkerMaterialization and type(self.release) is GatedReleaseAdapter,
            'ACTUAL_COMPLETED_WORKER_AND_GATED_RELEASE_REQUIRED')
        self.ids = tuple(map(id, (application, application.executor, self.worker,
            application.node_owner, application.discovery_parent, self.release)))

    def guard(self, phase, point, row):
        a, w, r = self.app, self.worker, self.release
        a.verify_scope(); w.check_scope()
        require(self.ids == tuple(map(id, (a, a.executor, w, a.node_owner, a.discovery_parent, r)))
            and type(a.executor) is DiscoveryExecutor and a.executor.discovery_parent is w.parent
            and a.infrastructure_owners[WORKER_PHASE] is w and a.node_owner is w.node
            and a.discovery_parent is w.parent and a.transition is w.transition and a.store is w.store
            and a.authority is w.authority and a.raw == w.authority_raw
            and a.executor.adapters['START_REPLACEMENT'] is r
            and r.engine is w.node.engine and r.transition is a.transition and r.store is a.store
            and r.intent == a.intents['START_REPLACEMENT']
            and r.request_hash == a.request_hash == w.request_hash
            and r.intent_hash == a.intent_hashes['START_REPLACEMENT']
            and decode(a.raw)['phaseIntentHashes'] == a.intent_hashes
            and phase in POINTS and point in POINTS[phase] and row == a.transition.read(),
            'EXACT_SAME_OPERATIONAL_CHECKPOINT_OWNERS_POINT_AND_HISTORY_REQUIRED')
        w.parent.registry_child(w.authority, w.authority_raw)
        w.parent.guard('operationalLeaseInstallation', w.component)
        a.executor.additional_authority_fields()
        require(a.authority(a.raw) is True, 'CURRENT_OPERATIONAL_CHECKPOINT_CHILD_AUTHORITY_REQUIRED')
        index = PHASES.index(phase); effects = row.get('effects')
        require(row.get('state') == 'IN_FLIGHT' and type(row.get('nextPhase')) is int
            and row['nextPhase'] == index and row.get('creationRequestHash') == w.request_hash
            and row.get('transitionAuthorityEvidenceHash') == a.raw_hash
            and type(effects) is list and len(effects) == index + 1
            and [e.get('phase') for e in effects] == list(PHASES[:index + 1])
            and all(e.get('state') == 'APPLIED' for e in effects[:index])
            and effects[-1].get('state') == 'IN_FLIGHT'
            and all(e.get('intentHash') == a.intent_hashes[e['phase']] for e in effects),
            'EXACT_CONSUMED_OPERATIONAL_PHASE_AND_COMPLETED_PREFIX_REQUIRED')
        # Authenticate all completed payloads, not just the worker receipt.
        for effect in effects[:index]:
            a.store.read(effect['phase'], effect['nativeEvidenceHash'])
        effect = effects[PHASES.index(WORKER_PHASE)]
        receipt = a.store.read(WORKER_PHASE, effect['nativeEvidenceHash'])
        require(receipt['schema'] == 'ouf.discovery-distinct-installed-lease-worker-started.v1'
            and receipt['transitionContextHash'] == a.transition.context
            and receipt['intentHash'] == w.intent_hash == a.intent_hashes[WORKER_PHASE]
            and receipt['creationRequestHash'] == w.request_hash
            and receipt['templateHash'] == w.template_hash,
            'EXACT_ORIGINAL_COMPLETED_OPERATIONAL_WORKER_RECEIPT_REQUIRED')
        return receipt

    def generation(self, phase, point):
        a, r = self.app, self.release
        if phase == 'ADMIT_MIGRATION':
            return a.node_owner.verify_retained()
        if phase == 'VERIFY_APPLICATION':
            return VerifyingRegistryBinding(r.engine, a.transition, a.request, a.store).observe()
        # The actual release adapter binds the staged process/configuration.
        # Reconciliation may encounter the paused gate, unpaused gate or Java;
        # observing any of these never authorizes another unpause or signal.
        _, actual, process = r.current(a.intents['START_REPLACEMENT'])
        state = actual['State']; kind = process.get('processKind')
        paused = state.get('Paused')
        require(type(paused) is bool and state.get('Restarting') is False
            and state.get('Status') == ('paused' if paused else 'running')
            and kind in {'GATE_WAITING', 'APPLICATION_RUNNING'}
            and (not paused or kind == 'GATE_WAITING'),
            'CURRENT_OPERATIONAL_RELEASE_PROCESS_STATE_REQUIRED')
        if point in {'BEFORE_NATIVE_EFFECT', 'BEFORE_UNPAUSE'}:
            require(paused and kind == 'GATE_WAITING', 'CURRENT_PAUSED_GATE_REQUIRED_BEFORE_UNPAUSE')
            a.node_owner.verify_retained()
        elif point == 'BEFORE_PREAPPLICATION_SIGUSR1':
            require(not paused and kind == 'GATE_WAITING', 'CURRENT_UNPAUSED_GATE_REQUIRED_BEFORE_SIGNAL')
        return {'runtimeBinding': r.engine.runtime_binding(actual), 'process': process,
            'paused': paused, 'processKind': kind}

    def observe(self, phase, point, current_row):
        row = copy.deepcopy(current_row); budget = ObservationBudget(180)
        retained = self.guard(phase, point, row); w = self.worker
        before = self.generation(phase, point); budget.check()
        material, proposal, snapshot, configuration, prefix, claim_hash, completed_hash = read_installed_material(w, budget)
        require(retained['configurationHash'] == digest(proposal['configuration'])
            and retained['claimHash'] == claim_hash and completed_hash == digest(retained)
            and all(retained[k] == v for k, v in prefix.items()),
            'OPERATIONAL_CHECKPOINT_ORIGINAL_MATERIAL_AND_RECEIPT_DIFFER')
        handoff = verify_operational_installation(w, material, proposal, configuration)
        w.verify_generation(material)
        observed = lease_observation.observe(configuration, proposal['serviceUnit']['configurationAnchor'],
            unit_name=w.start_scope['unitName'], systemctl=w.start_scope['manager'])
        old = retained['installedWorkerObservation']
        require(all(observed[k] == old[k] for k in
                ('configurationHash', 'scopeHash', 'generationRef', 'managerProcessId'))
            and all(observed[k] is True for k in
                ('managerProcessRunning', 'workerCheckpointActive', 'bothOwnedLeaseFamiliesPositive'))
            and all(type(observed[k]) is int and observed[k] >= old[k] for k in ('recoveryAttempts', 'publications')),
            'CURRENT_OPERATIONAL_CHECKPOINT_WORKER_AND_POSITIVE_LEASES_REQUIRED')
        w.verify_generation(material)
        require(verify_operational_installation(w, material, proposal, configuration) == handoff
            and read_installed_material(w, budget) == (material, proposal, snapshot, configuration, prefix, claim_hash, completed_hash)
            and self.generation(phase, point) == before and self.guard(phase, point, row) == retained,
            'OPERATIONAL_CHECKPOINT_CHANGED_DURING_NATIVE_OBSERVATION')
        budget.check()
        return {'schema': 'ouf.discovery-native-operational-checkpoint-witness.v1', 'phase': phase, 'point': point,
            'currentHistoryHash': digest(row), 'generationHash': digest(before), 'operationalHandoffHash': digest(handoff),
            'installedWorkerObservationHash': digest(observed), 'currentSignedOperationalInstallationVerified': True,
            'currentWorkerAndPositiveOwnedLeasesObserved': True, 'initialProviderMandateExtended': False,
            'newGenerationAuthorized': False, 'completeCutoverCheckpointProven': False, 'fullCohortProven': False,
            'nativeMutationDispatched': False, 'producerReleaseDispatched': False, 'runtimeAuthorityIssued': False,
            'targetApplyAuthorized': False, 'budgetReset': False, 'releaseAcceptance': False}
