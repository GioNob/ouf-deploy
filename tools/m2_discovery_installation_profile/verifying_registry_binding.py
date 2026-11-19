"""Current released process while application verification is still in flight.

RunningWorkloadBinding deliberately requires completed VERIFY_APPLICATION; using
it inside that phase creates a circular precondition. This reader authenticates
the completed START_REPLACEMENT receipt and process without inventing readiness
or demanding an application-verification receipt before it can exist.
"""
import copy
from .custody_capture import digest, require
from engine_creation import Engine
from native_evidence_store import NativeEvidenceStore
from transition_journal import Transition, PHASES
from gated_process_observation import GatedProcessObservation

PHASE = 'VERIFY_APPLICATION'


class VerifyingRegistryBinding:
    def __init__(self, engine, transition, request, store):
        require(type(engine) is Engine and type(transition) is Transition and type(store) is NativeEvidenceStore,
            'TYPED_IN_FLIGHT_REGISTRY_BINDING_REQUIRED')
        self.engine, self.transition, self.store = engine, transition, store
        self.request = copy.deepcopy(request); self.request_hash = digest(request)
        self.process = GatedProcessObservation(request)
        self.ids = tuple(map(id, (engine, transition, store, self.process)))

    def current(self):
        require(self.ids == tuple(map(id, (self.engine, self.transition, self.store, self.process)))
            and digest(self.request) == self.request_hash, 'IN_FLIGHT_REGISTRY_BINDING_OWNER_OR_REQUEST_CHANGED')
        row = self.transition.read(); index = PHASES.index(PHASE); effects = row.get('effects')
        require(row.get('state') == 'IN_FLIGHT' and type(row.get('nextPhase')) is int and row['nextPhase'] == index
            and row.get('creationRequestHash') == self.request_hash and type(effects) is list
            and len(effects) == index + 1 and [e.get('phase') for e in effects] == list(PHASES[:index + 1])
            and all(e.get('state') == 'APPLIED' for e in effects[:index]) and effects[-1].get('state') == 'IN_FLIGHT',
            'EXACT_RELEASED_REGISTRY_AND_IN_FLIGHT_VERIFICATION_CURSOR_REQUIRED')
        release = effects[PHASES.index('START_REPLACEMENT')]
        before = self.store.read('START_REPLACEMENT', release['nativeEvidenceHash'])
        require(before.get('schema') == 'ouf.semantic-gated-application-release.v1'
            and before.get('transitionContextHash') == self.transition.context
            and before.get('intentHash') == release.get('intentHash')
            and before.get('processKind') == 'APPLICATION_RUNNING',
            'EXACT_COMPLETED_APPLICATION_RELEASE_BEFORE_VERIFICATION_REQUIRED')
        return row, before

    def observe(self):
        row, before = self.current(); e = self.engine
        actual = e.matching_configuration(self.transition, self.request, e.inspect(self.transition))
        binding = e.runtime_binding(actual); process = self.process.observe(binding['pid'])
        require(actual['State']['Running'] is True and actual['State']['Paused'] is False
            and actual['State']['Restarting'] is False and actual['State']['Status'] == 'running'
            and actual['RestartCount'] == 0 and binding == before['runtimeBinding']
            and process['generation'] == before['generation'] and process['processKind'] == 'APPLICATION_RUNNING',
            'SAME_RELEASED_RUNNING_REGISTRY_DURING_VERIFICATION_REQUIRED')
        require(self.current() == (row, before) and e.runtime_binding(e.inspect(self.transition)) == binding
            and self.process.observe(binding['pid']) == process,
            'VERIFYING_REGISTRY_CHANGED_DURING_NATIVE_OBSERVATION')
        return {'runtimeBinding': binding, 'process': process}
