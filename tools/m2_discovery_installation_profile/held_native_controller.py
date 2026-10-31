"""One fenced, read-only composition of the qualified READY12 native owners.

This does not emit the complete checkpoint required for publication or release.
Selected artifact membership joins current publisher and migration/image owners;
complete private custody/workload bearer admissions remain separate. No native
observer can be supplied as a callback or positive flag.
"""
from .custody_capture import digest, require
from .selected_runtime import DiscoverySelectedRuntime
from .application import DiscoveryApplication
from .executor import DiscoveryExecutor
from .current_cohort import CurrentCohortRuntime, ADDITIONAL_INPUTS
from .current_databases import CurrentCohortDatabases
from .current_publisher import CurrentPublisherCustody
from .current_tls import CurrentTlsIdentities
from .current_iam_workload import CurrentWorkloadIam
from .current_retirement import CurrentRetirementAndBackup
from .current_producer_fence import CurrentProducerFence
from .current_operational_worker import CurrentOperationalWorker
from .running_admission import RunningRegistryAdmission
from .artifact_membership import CurrentArtifactMembership
from .node_owner import ObservationBudget
from application_verification_adapter import ApplicationVerificationAdapter


class HeldNativeController:
    def __init__(self, *, selected, runtime, databases, publisher, tls, iam, retirement, producers, operational, membership):
        self.selected, self.runtime = selected, runtime
        self.databases, self.publisher, self.tls, self.iam = databases, publisher, tls, iam
        self.retirement, self.producers, self.operational = retirement, producers, operational
        self.membership = membership
        self.ids = tuple(map(id, self.owners()))
        self.guard()

    def owners(self):
        return (self.selected, self.runtime, self.databases, self.publisher, self.tls,
            self.iam, self.retirement, self.producers, self.operational, self.membership)

    def lineage(self):
        owners = self.owners()
        types = (DiscoverySelectedRuntime, CurrentCohortRuntime, CurrentCohortDatabases,
            CurrentPublisherCustody, CurrentTlsIdentities, CurrentWorkloadIam,
            CurrentRetirementAndBackup, CurrentProducerFence, CurrentOperationalWorker, CurrentArtifactMembership)
        require(tuple(map(id, owners)) == self.ids and all(type(o) is t for o, t in zip(owners, types)),
            'EXACT_NATIVE_HELD_CONTROLLER_OWNERS_REQUIRED')
        s, r = self.selected, self.runtime; a = s.installation.application
        require(type(a) is DiscoveryApplication and type(a.executor) is DiscoveryExecutor
            and r.selected is self.producers.selected is self.operational.selected is s
            and self.databases.runtime is self.tls.runtime is self.iam.runtime is r
            and self.tls.operational is self.operational
            and self.publisher.parent is self.retirement.parent is a.discovery_parent is s.images.parent
            and a.executor.discovery_parent is a.discovery_parent
            and self.retirement.app is self.producers.app is a and self.retirement.installed is True
            and self.publisher.runtime_inputs == self.retirement.runtime_inputs == r.inputs
            and self.membership.publisher is self.publisher and self.membership.databases is self.databases
            and self.membership.images is s.images
            and set(r.inputs.get('additionalInputsHashes', {})) == ADDITIONAL_INPUTS,
            'SAME_EXACT_PARENT_RUNTIME_APPLICATION_AND_ALL_INPUTS_FOR_HELD_CONTROLLER_REQUIRED')
        adapter = a.executor.adapters['VERIFY_APPLICATION']
        require(type(adapter) is ApplicationVerificationAdapter and adapter.engine is s.images.engine
            and adapter.transition is a.transition and adapter.store is a.store
            and adapter.request == a.request and adapter.intent == a.intents['VERIFY_APPLICATION'],
            'SAME_NATIVE_REGISTRY_READINESS_FOR_HELD_CONTROLLER_REQUIRED')
        a.executor.additional_authority_fields()
        require(a.authority(a.raw) is True, 'CURRENT_HELD_CONTROLLER_CHILD_AUTHORITY_REQUIRED')
        return s.held()

    def guard(self):
        row = self.lineage()
        # Validate all inputs at the boundaries. Each concrete observer also
        # validates its own inputs before/after I/O. Avoid multiplying every
        # native guard by every unrelated observation inside the same budget.
        for owner in self.owners(): owner.guard()
        require(self.lineage() == row, 'HELD_CONTROLLER_HISTORY_CHANGED_DURING_OWNER_GUARDS')
        return row

    def observe(self):
        # This is the transition invocation fence, never the worker's lifetime
        # lock or the lease/kernel mutation lock. No wait/retry runs inside it.
        with self.selected.images.window.transition.invocation():
            row = self.guard(); budget = ObservationBudget(180)
            a = self.selected.installation.application
            registry = RunningRegistryAdmission(a.node_owner, a.executor.adapters['VERIFY_APPLICATION'].channel)
            proofs = {}
            def read(name, operation):
                require(self.lineage() == row, 'HELD_CONTROLLER_HISTORY_CHANGED_BEFORE_NATIVE_READ')
                budget.check(); proof = operation(); budget.check()
                require(self.lineage() == row, 'HELD_CONTROLLER_HISTORY_CHANGED_AFTER_NATIVE_READ')
                require(type(proof) is dict and
                    ('heldHistoryHash' not in proof or proof['heldHistoryHash'] == digest(row)) and
                    ('currentHistoryHash' not in proof or proof['currentHistoryHash'] == digest(row)),
                    'SAME_HELD_CONTROLLER_NATIVE_WITNESS_HISTORY_REQUIRED')
                proofs[name] = proof
            read('images', self.selected.images.verify)
            read('registry', registry.observe)
            read('operationalWorker', self.operational.observe)
            read('runtime', self.runtime.observe)
            read('publisher', self.publisher.observe)
            read('artifactMembership', self.membership.observe)
            require(proofs['artifactMembership']['selectedImageAndMigrationMembershipProven'] is True
                and proofs['artifactMembership']['publisherEvidenceHash'] == digest(proofs['publisher']),
                'SAME_CURRENT_PUBLISHER_AND_SELECTED_ARTIFACT_MEMBERSHIP_REQUIRED')
            read('databases', self.databases.observe)
            read('tls', self.tls.observe)
            read('iamConfiguration', self.iam.observe)
            read('retirement', lambda: self.retirement.retired(budget))
            read('backup', self.retirement.retained_backup)
            read('producers', self.producers.observe)
            # Recheck volatile generations/leases at the end of the interval.
            read('finalRegistry', registry.observe)
            read('finalOperationalWorker', self.operational.observe)
            read('finalRuntime', self.runtime.observe)
            read('finalProducers', self.producers.observe)
            read('finalArtifactMembership', self.membership.observe)
            read('finalImages', self.selected.images.verify)
            require(proofs['images'] == proofs['finalImages']
                and proofs['registry'] == proofs['finalRegistry']
                and proofs['runtime'] == proofs['finalRuntime']
                and proofs['artifactMembership'] == proofs['finalArtifactMembership']
                and proofs['producers'] == proofs['finalProducers'],
                'HELD_CONTROLLER_NATIVE_GENERATIONS_CHANGED_DURING_OBSERVATION_INTERVAL')
            require(self.guard() == row, 'HELD_CONTROLLER_FINAL_HISTORY_CHANGED'); budget.check()
            return {'schema': 'ouf.discovery-held-native-controller-witness.v1',
                'parentAuthorityHash': a.discovery_parent.sha, 'childAuthorityHash': a.raw_hash,
                'heldHistoryHash': digest(row), 'nativeRuntimeInputsHash': self.runtime.input_hash,
                'ownerEvidenceHashes': {name: digest(proof) for name, proof in proofs.items()},
                'allBoundNativeObserversCompleted': True, 'singleTransitionInvocationFenceHeld': True,
                'selectedImageAndMigrationMembershipProven': True,
                'observationIntervalIsAtomicSnapshot': False, 'artifactMembershipProven': False,
                'completePrivateCustodyProven': False, 'actualWorkloadBearerAdmissionProven': False,
                'completeCutoverCheckpointProven': False, 'fullCohortProven': False,
                'capabilitiesPublished': False, 'producerReleaseDispatched': False,
                'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
                'budgetReset': False, 'releaseAcceptance': False}
