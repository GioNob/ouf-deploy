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
from .package_membership import CurrentPackageMembership
from .current_gateway_routes import CurrentGatewayRoutes
from .current_retained_mounts import CurrentRetainedMountMetadata
from .retained_mount_intake import CANDIDATE_HASH, RESULT_HASH
from .retained_mount_lifecycle import CONTRACT_HASH as MOUNT_LIFECYCLE_HASH
from .current_retained_static import CurrentRetainedStaticBytes
from .current_retained_views import CurrentRetainedMountViews
from .retained_static_intake import CANDIDATE_HASH as STATIC_CANDIDATE_HASH, RESULT_HASH as STATIC_RESULT_HASH
from .retained_view_intake import CANDIDATE_HASH as VIEW_CANDIDATE_HASH, RESULT_HASH as VIEW_RESULT_HASH
from .node_owner import ObservationBudget
from application_verification_adapter import ApplicationVerificationAdapter


class HeldNativeController:
    def __init__(self, *, selected, runtime, databases, publisher, tls, iam, retirement, producers, operational, membership, packages, gateway_routes, mounts, static_bytes, mount_views):
        self.selected, self.runtime = selected, runtime
        self.databases, self.publisher, self.tls, self.iam = databases, publisher, tls, iam
        self.retirement, self.producers, self.operational = retirement, producers, operational
        self.membership = membership
        self.packages = packages
        self.gateway_routes = gateway_routes
        self.mounts = mounts
        self.static_bytes = static_bytes
        self.mount_views = mount_views
        self.ids = tuple(map(id, self.owners()))
        self.guard()

    def owners(self):
        return (self.selected, self.runtime, self.databases, self.publisher, self.tls,
            self.iam, self.retirement, self.producers, self.operational, self.membership, self.packages, self.gateway_routes, self.mounts, self.static_bytes, self.mount_views)

    def lineage(self):
        owners = self.owners()
        types = (DiscoverySelectedRuntime, CurrentCohortRuntime, CurrentCohortDatabases,
            CurrentPublisherCustody, CurrentTlsIdentities, CurrentWorkloadIam,
            CurrentRetirementAndBackup, CurrentProducerFence, CurrentOperationalWorker, CurrentArtifactMembership,
            CurrentPackageMembership, CurrentGatewayRoutes, CurrentRetainedMountMetadata, CurrentRetainedStaticBytes, CurrentRetainedMountViews)
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
            and self.packages.membership is self.membership and self.packages.runtime is r
            and self.mounts.runtime is r
            and self.static_bytes.mounts is self.mounts and self.static_bytes.runtime is r
            and self.mount_views.static_bytes is self.static_bytes and self.mount_views.runtime is r
            and self.gateway_routes.selected is s and self.gateway_routes.runtime is s.gateway
            and self.gateway_routes.window.app is a and self.gateway_routes.window.executor is a.executor
            and self.gateway_routes.window.parent is a.discovery_parent
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
            read('retainedMountMetadata', self.mounts.observe)
            require(proofs['retainedMountMetadata']['schema']=='ouf.discovery-current-retained-mount-metadata.v2'
                and proofs['retainedMountMetadata']['currentRetainedStaticMetadataMatchesCapturedCandidate'] is True
                and proofs['retainedMountMetadata']['liveMountRootsMatchCapturedCustody'] is True
                and proofs['retainedMountMetadata']['liveMembersObservedOrAdmitted'] is False
                and proofs['retainedMountMetadata']['lifecycleContractHash']==MOUNT_LIFECYCLE_HASH
                and proofs['retainedMountMetadata']['nativeRuntimeInputsHash']==self.runtime.input_hash
                and proofs['retainedMountMetadata']['candidateHash']==CANDIDATE_HASH
                and proofs['retainedMountMetadata']['captureResultHash']==RESULT_HASH
                and proofs['retainedMountMetadata']['expectedMountPolicyEstablished'] is False
                and proofs['retainedMountMetadata']['mountedFileContentBytesRead']==0
                and proofs['retainedMountMetadata']['newCaptureScopeCreated'] is False,
                'SAME_CURRENT_RETAINED_CAPTURE_METADATA_WITHOUT_POLICY_OR_CONTENT_READ_REQUIRED')
            read('retainedStaticBytes', self.static_bytes.observe)
            require(proofs['retainedStaticBytes']['schema']=='ouf.discovery-current-retained-static-bytes.v1'
                and proofs['retainedStaticBytes']['nativeRuntimeInputsHash']==self.runtime.input_hash
                and proofs['retainedStaticBytes']['currentStaticFileBytesMatchCapturedCandidate'] is True
                and proofs['retainedStaticBytes']['candidateHash']==STATIC_CANDIDATE_HASH
                and proofs['retainedStaticBytes']['captureResultHash']==STATIC_RESULT_HASH
                and proofs['retainedStaticBytes']['metadataCandidateHash']==CANDIDATE_HASH
                and proofs['retainedStaticBytes']['lifecycleContractHash']==MOUNT_LIFECYCLE_HASH
                and proofs['retainedStaticBytes']['lifecyclePlanHash']==proofs['retainedMountMetadata']['lifecyclePlanHash']
                and proofs['retainedStaticBytes']['directEngineGets']==0
                and proofs['retainedStaticBytes']['liveTokenAndOperationalStoreContentBytesRead']==0
                and proofs['retainedStaticBytes']['liveMembersObservedOrAdmitted'] is False
                and proofs['retainedStaticBytes']['expectedPermissionOrContentPolicyEstablished'] is False
                and proofs['retainedStaticBytes']['newCaptureScopeCreated'] is False,
                'CURRENT_STATIC_BYTE_CONTINUITY_WITHOUT_LIVE_ADMISSION_OR_POLICY_REQUIRED')
            read('retainedMountViews', self.mount_views.observe)
            require(proofs['retainedMountViews']['schema']=='ouf.discovery-current-retained-mount-views.v2'
                and proofs['retainedMountViews']['nativeRuntimeInputsHash']==self.runtime.input_hash
                and proofs['retainedMountViews']['staticCandidateHash']==STATIC_CANDIDATE_HASH
                and proofs['retainedMountViews']['viewCandidateHash']==VIEW_CANDIDATE_HASH
                and proofs['retainedMountViews']['viewResultHash']==VIEW_RESULT_HASH
                and proofs['retainedMountViews']['lifecycleContractHash']==MOUNT_LIFECYCLE_HASH
                and proofs['retainedMountViews']['currentMountDeclarationsMatchEffectiveViews'] is True
                and proofs['retainedMountViews']['currentLiveLeafCustodyMatchesCapturedMetadata'] is True
                and proofs['retainedMountViews']['liveLeafMetadataNodes']==8
                and proofs['retainedMountViews']['readonlyMounts']==25 and proofs['retainedMountViews']['writableMounts']==4
                and proofs['retainedMountViews']['retainedProcessCount']==10
                and proofs['retainedMountViews']['directEngineGets']==0
                and proofs['retainedMountViews']['mountedFileContentBytesRead']==0
                and proofs['retainedMountViews']['liveOwnerAuthenticated'] is False
                and proofs['retainedMountViews']['liveDirectoryMembershipObserved'] is False
                and proofs['retainedMountViews']['newCaptureScopeCreated'] is False,
                'CURRENT_RETAINED_KERNEL_VIEWS_WITHOUT_CONTENT_OR_LIVE_ADMISSION_REQUIRED')
            read('gatewayRoutes', self.gateway_routes.observe)
            require(proofs['gatewayRoutes']['currentRoutesMatchReviewedPublicationProgress'] is True
                and proofs['gatewayRoutes']['currentGatewayConfigurationAndAdminExecutableObserved'] is True
                and proofs['gatewayRoutes']['publicationCheckpointReentered'] is False
                and proofs['gatewayRoutes']['routeWrites'] == 0,
                'CURRENT_READONLY_GATEWAY_ROUTE_PROGRESS_REQUIRED')
            read('publisher', self.publisher.observe)
            read('artifactMembership', self.membership.observe)
            require(proofs['artifactMembership']['selectedImageAndMigrationMembershipProven'] is True
                and proofs['artifactMembership']['publisherEvidenceHash'] == digest(proofs['publisher']),
                'SAME_CURRENT_PUBLISHER_AND_SELECTED_ARTIFACT_MEMBERSHIP_REQUIRED')
            read('sixModulePackage', self.packages.observe)
            require(proofs['sixModulePackage']['sixModulePackageBytesProven'] is True
                and proofs['sixModulePackage']['fiveReviewedModuleImageIdentitiesProven'] is True
                and proofs['sixModulePackage']['publisherEvidenceHash'] == digest(proofs['publisher'])
                and proofs['sixModulePackage']['namedMembershipEvidenceHash'] == digest(proofs['artifactMembership']),
                'SAME_CURRENT_PUBLISHER_NAMED_MEMBERSHIP_AND_COMPLETE_PACKAGE_REQUIRED')
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
            read('finalRetainedMountMetadata', self.mounts.observe)
            read('finalRetainedStaticBytes', self.static_bytes.observe)
            read('finalRetainedMountViews', self.mount_views.observe)
            read('finalGatewayRoutes', self.gateway_routes.observe)
            read('finalProducers', self.producers.observe)
            read('finalArtifactMembership', self.membership.observe)
            read('finalSixModulePackage', self.packages.observe)
            read('finalImages', self.selected.images.verify)
            require(proofs['images'] == proofs['finalImages']
                and proofs['registry'] == proofs['finalRegistry']
                and proofs['runtime'] == proofs['finalRuntime']
                and proofs['retainedMountMetadata'] == proofs['finalRetainedMountMetadata']
                and proofs['retainedStaticBytes'] == proofs['finalRetainedStaticBytes']
                and proofs['retainedMountViews'] == proofs['finalRetainedMountViews']
                and proofs['gatewayRoutes'] == proofs['finalGatewayRoutes']
                and proofs['artifactMembership'] == proofs['finalArtifactMembership']
                and proofs['sixModulePackage'] == proofs['finalSixModulePackage']
                and proofs['producers'] == proofs['finalProducers'],
                'HELD_CONTROLLER_NATIVE_GENERATIONS_CHANGED_DURING_OBSERVATION_INTERVAL')
            require(self.guard() == row, 'HELD_CONTROLLER_FINAL_HISTORY_CHANGED'); budget.check()
            return {'schema': 'ouf.discovery-held-native-controller-witness.v8',
                'parentAuthorityHash': a.discovery_parent.sha, 'childAuthorityHash': a.raw_hash,
                'heldHistoryHash': digest(row), 'nativeRuntimeInputsHash': self.runtime.input_hash,
                'ownerEvidenceHashes': {name: digest(proof) for name, proof in proofs.items()},
                'allBoundNativeObserversCompleted': True, 'singleTransitionInvocationFenceHeld': True,
                'selectedImageAndMigrationMembershipProven': True,
                'sixModulePackageBytesProven': True, 'fiveReviewedModuleImageIdentitiesProven': True,
                'currentGatewayRoutesAndAdminCustodyObserved': True,
                'currentRetainedStaticMetadataAndLiveRootsMatchAcceptedCapture':True,
                'retainedLiveMembersObservedOrAdmitted':False,
                'currentStaticFileBytesMatchAcceptedCandidate':True,
                'currentRetainedKernelMountViewsMatchDeclarations':True,
                'currentLiveLeafCustodyMatchesCapturedMetadata':True,
                'expectedRetainedMountPolicyEstablished':False,
                'observationIntervalIsAtomicSnapshot': False, 'artifactMembershipProven': False,
                'completePrivateCustodyProven': False, 'actualWorkloadBearerAdmissionProven': False,
                'completeCutoverCheckpointProven': False, 'fullCohortProven': False,
                'capabilitiesPublished': False, 'producerReleaseDispatched': False,
                'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
                'budgetReset': False, 'releaseAcceptance': False}
