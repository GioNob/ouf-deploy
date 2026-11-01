"""Single-fence composition and denials; native owner leaves are modeled.

The individual native suites remain authoritative for their own I/O. No actual
combined DB/TLS/IAM/OCI cohort or target application E2E is claimed here.
"""
import copy, sys, unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_selected_runtime  # retained import setup
from tools.m2_discovery_installation_profile import held_native_controller as m


class HeldController(unittest.TestCase):
    def prepared(self):
        row = {'state': 'READY', 'nextPhase': 12, 'version': 42}; calls = []; occupied = [False]
        @contextmanager
        def invocation():
            if occupied[0]: raise BlockingIOError('OCCUPIED_TRANSITION_FENCE')
            occupied[0] = True
            try: yield
            finally: occupied[0] = False
        transition = SimpleNamespace(invocation=invocation)
        def held(expected=None):
            if expected is not None and expected != row: raise ValueError('HELD_HISTORY_CHANGED')
            return copy.deepcopy(row)
        selected = object.__new__(m.DiscoverySelectedRuntime); selected.guard = Mock(); selected.held = held
        parent = SimpleNamespace(sha='a'*64)
        selected.images = SimpleNamespace(parent=parent, engine=object(), window=SimpleNamespace(transition=transition))
        app = object.__new__(m.DiscoveryApplication); app.discovery_parent = parent; app.raw_hash = 'b'*64
        app.raw = b'modeled-child'; app.authority = Mock(return_value=True); app.node_owner = object()
        app.transition = transition; app.store = object(); app.request = {'modeledRequest': True}
        app.intents = {'VERIFY_APPLICATION': {'modeledReadinessIntent': True}}
        app.executor = object.__new__(m.DiscoveryExecutor); app.executor.discovery_parent = parent
        app.executor.additional_authority_fields = Mock()
        adapter = object.__new__(m.ApplicationVerificationAdapter); adapter.engine = selected.images.engine
        adapter.transition = transition; adapter.store = app.store; adapter.request = copy.deepcopy(app.request)
        adapter.intent = copy.deepcopy(app.intents['VERIFY_APPLICATION']); adapter.channel = object()
        app.executor.adapters = {'VERIFY_APPLICATION': adapter}
        selected.installation = SimpleNamespace(application=app)
        objects = {}
        for name, cls in (('runtime', m.CurrentCohortRuntime), ('databases', m.CurrentCohortDatabases),
            ('publisher', m.CurrentPublisherCustody), ('tls', m.CurrentTlsIdentities), ('iam', m.CurrentWorkloadIam),
            ('retirement', m.CurrentRetirementAndBackup), ('producers', m.CurrentProducerFence),
            ('operational', m.CurrentOperationalWorker), ('membership', m.CurrentArtifactMembership),
            ('packages', m.CurrentPackageMembership), ('gateway_routes', m.CurrentGatewayRoutes),
            ('mounts', m.CurrentRetainedMountMetadata), ('static_bytes',m.CurrentRetainedStaticBytes)):
            objects[name] = object.__new__(cls); objects[name].guard = Mock()
        runtime = objects['runtime']; runtime.selected = selected; runtime.input_hash = 'c'*64
        runtime.inputs = {'additionalInputsHashes': {k: 'd'*64 for k in m.ADDITIONAL_INPUTS}}
        for name in ('databases', 'tls', 'iam'): objects[name].runtime = runtime
        for name in ('producers', 'operational'): objects[name].selected = selected
        objects['tls'].operational = objects['operational']
        for name in ('publisher', 'retirement'):
            objects[name].parent = parent; objects[name].runtime_inputs = copy.deepcopy(runtime.inputs)
        for name in ('producers', 'retirement'): objects[name].app = app
        objects['retirement'].installed = True
        objects['membership'].publisher = objects['publisher']; objects['membership'].databases = objects['databases']
        objects['membership'].images = selected.images
        objects['mounts'].runtime = runtime
        objects['static_bytes'].runtime=runtime;objects['static_bytes'].mounts=objects['mounts']
        objects['packages'].membership = objects['membership']; objects['packages'].runtime = runtime
        selected.gateway = object()
        objects['gateway_routes'].selected = selected; objects['gateway_routes'].runtime = selected.gateway
        objects['gateway_routes'].window = SimpleNamespace(app=app, executor=app.executor, parent=parent)
        def operation(name):
            def run(*args):
                self.assertTrue(occupied[0], name+' must use the invocation fence')
                calls.append(name); result = {'schema': 'modeled-'+name, 'heldHistoryHash': m.digest(row)}
                if name == 'membership':
                    result.update(selectedImageAndMigrationMembershipProven=True,
                        publisherEvidenceHash=m.digest({'schema':'modeled-publisher','heldHistoryHash':m.digest(row)}))
                if name == 'packages':
                    publisher = {'schema':'modeled-publisher','heldHistoryHash':m.digest(row)}
                    named = {'schema':'modeled-membership','heldHistoryHash':m.digest(row),
                        'selectedImageAndMigrationMembershipProven': True, 'publisherEvidenceHash':m.digest(publisher)}
                    result.update(sixModulePackageBytesProven=True, fiveReviewedModuleImageIdentitiesProven=True,
                        publisherEvidenceHash=m.digest(publisher), namedMembershipEvidenceHash=m.digest(named))
                if name == 'mounts':
                    result.update(schema='ouf.discovery-current-retained-mount-metadata.v2',
                        currentRetainedStaticMetadataMatchesCapturedCandidate=True,
                        liveMountRootsMatchCapturedCustody=True,liveMembersObservedOrAdmitted=False,
                        lifecycleContractHash=m.MOUNT_LIFECYCLE_HASH,lifecyclePlanHash='e'*64,
                        nativeRuntimeInputsHash=runtime.input_hash,candidateHash=m.CANDIDATE_HASH,
                        captureResultHash=m.RESULT_HASH,expectedMountPolicyEstablished=False,
                        mountedFileContentBytesRead=0,newCaptureScopeCreated=False)
                if name == 'static_bytes':
                    result.update(schema='ouf.discovery-current-retained-static-bytes.v1',
                        currentStaticFileBytesMatchCapturedCandidate=True,nativeRuntimeInputsHash=runtime.input_hash,
                        candidateHash=m.STATIC_CANDIDATE_HASH,captureResultHash=m.STATIC_RESULT_HASH,
                        metadataCandidateHash=m.CANDIDATE_HASH,lifecycleContractHash=m.MOUNT_LIFECYCLE_HASH,
                        lifecyclePlanHash='e'*64,directEngineGets=0,liveTokenAndOperationalStoreContentBytesRead=0,
                        liveMembersObservedOrAdmitted=False,expectedPermissionOrContentPolicyEstablished=False,newCaptureScopeCreated=False)
                if name == 'gateway_routes':
                    result.update(currentRoutesMatchReviewedPublicationProgress=True,
                        currentGatewayConfigurationAndAdminExecutableObserved=True,
                        publicationCheckpointReentered=False, routeWrites=0)
                return result
            return Mock(side_effect=run)
        for name in ('runtime', 'databases', 'publisher', 'tls', 'iam', 'producers', 'operational', 'membership', 'packages', 'gateway_routes', 'mounts', 'static_bytes'):
            objects[name].observe = operation(name)
        objects['retirement'].retired = operation('retirement'); objects['retirement'].retained_backup = operation('backup')
        selected.images.verify = operation('images')
        registry = SimpleNamespace(observe=operation('registry'))
        p = patch.object(m, 'RunningRegistryAdmission', return_value=registry); p.start(); self.addCleanup(p.stop)
        controller = m.HeldNativeController(selected=selected, **objects)
        return controller, objects, row, calls, occupied, registry

    def test_all_concrete_observers_share_one_fence_without_publication_or_release_receipt(self):
        controller, _, row, calls, occupied, _ = self.prepared(); original = copy.deepcopy(row)
        result = controller.observe()
        self.assertEqual(calls, ['images','registry','operational','runtime','mounts','static_bytes','gateway_routes','publisher','membership','packages','databases','tls','iam',
            'retirement','backup','producers','registry','operational','runtime','mounts','static_bytes','gateway_routes','producers','membership','packages','images'])
        self.assertEqual(row, original); self.assertFalse(occupied[0]); self.assertEqual(len(result['ownerEvidenceHashes']), 26)
        self.assertTrue(result['singleTransitionInvocationFenceHeld']); self.assertTrue(result['allBoundNativeObserversCompleted'])
        self.assertNotEqual(result['schema'], 'ouf.semantic-cutover-native-checkpoint.v1')
        for key in ('observationIntervalIsAtomicSnapshot', 'artifactMembershipProven', 'completePrivateCustodyProven',
            'actualWorkloadBearerAdmissionProven', 'completeCutoverCheckpointProven', 'fullCohortProven', 'capabilitiesPublished',
            'producerReleaseDispatched', 'runtimeAuthorityIssued', 'targetApplyAuthorized', 'budgetReset', 'releaseAcceptance'):
            self.assertIs(result[key], False)

    def test_mount_witness_cannot_substitute_capture_content_reads_policy_or_new_scope(self):
        for field in ('candidateHash','captureResultHash','nativeRuntimeInputsHash',
            'expectedMountPolicyEstablished','mountedFileContentBytesRead','newCaptureScopeCreated'):
            controller,objects,_,_,occupied,_=self.prepared();original=objects['mounts'].observe.side_effect
            def wrong():
                proof=original();proof[field]=('f'*64 if field.endswith('Hash') else True);return proof
            objects['mounts'].observe.side_effect=wrong
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'SAME_CURRENT_RETAINED_CAPTURE_METADATA'):
                controller.observe()
            objects['gateway_routes'].observe.assert_not_called();self.assertFalse(occupied[0])

    def test_concurrent_invocation_denies_before_any_observer(self):
        controller, _, _, calls, occupied, _ = self.prepared(); occupied[0] = True
        with self.assertRaises(BlockingIOError): controller.observe()
        self.assertEqual(calls, [])

    def test_static_witness_cannot_substitute_policy_live_admission_or_engine_access(self):
        for field in ('candidateHash','metadataCandidateHash','captureResultHash','lifecyclePlanHash',
            'currentStaticFileBytesMatchCapturedCandidate','liveMembersObservedOrAdmitted',
            'expectedPermissionOrContentPolicyEstablished','directEngineGets','liveTokenAndOperationalStoreContentBytesRead'):
            controller,objects,_,_,occupied,_=self.prepared();original=objects['static_bytes'].observe.side_effect
            def changed():
                proof=original();proof[field]=('f'*64 if field.endswith('Hash') else
                    False if field=='currentStaticFileBytesMatchCapturedCandidate' else 1);return proof
            objects['static_bytes'].observe.side_effect=changed
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'CURRENT_STATIC_BYTE_CONTINUITY'):
                controller.observe()
            objects['gateway_routes'].observe.assert_not_called();self.assertFalse(occupied[0])

    def test_static_byte_proof_must_remain_equal_at_both_interval_boundaries(self):
        controller,objects,_,_,occupied,_=self.prepared();original=objects['static_bytes'].observe.side_effect;calls=[]
        def changed():
            proof=original();calls.append(1);proof['staticInputPinsHash']=str(len(calls))*64;return proof
        objects['static_bytes'].observe.side_effect=changed
        with self.assertRaisesRegex(ValueError,'NATIVE_GENERATIONS_CHANGED'):controller.observe()
        self.assertFalse(occupied[0]);self.assertEqual(len(calls),2)

    def test_foreign_or_replaced_owner_or_input_cannot_join_native_witnesses(self):
        for failure in ('type', 'runtime', 'worker', 'parent', 'input', 'retirement', 'packages', 'gateway_routes', 'mounts', 'static_bytes'):
            controller, objects, _, calls, _, _ = self.prepared()
            if failure == 'type': controller.publisher = SimpleNamespace(guard=Mock(), observe=Mock())
            elif failure == 'runtime': objects['tls'].runtime = object()
            elif failure == 'worker': objects['tls'].operational = object()
            elif failure == 'parent': objects['publisher'].parent = object()
            elif failure == 'input': objects['publisher'].runtime_inputs['additionalInputsHashes']['custody'] = 'f'*64
            elif failure == 'packages': objects['packages'].membership = object()
            elif failure == 'mounts': objects['mounts'].runtime = object()
            elif failure == 'static_bytes': objects['static_bytes'].mounts=object()
            elif failure == 'gateway_routes': objects['gateway_routes'].window.parent = object()
            else: objects['retirement'].installed = False
            with self.subTest(failure=failure), self.assertRaises(ValueError): controller.observe()
            self.assertEqual(calls, [])

    def test_wrong_readiness_channel_binding_denies_before_native_read(self):
        controller, _, _, calls, _, _ = self.prepared()
        controller.selected.installation.application.executor.adapters['VERIFY_APPLICATION'].store = object()
        with self.assertRaisesRegex(ValueError, 'SAME_NATIVE_REGISTRY_READINESS'): controller.observe()
        self.assertEqual(calls, [])

    def test_history_drift_between_observers_stops_dependents_and_releases_fence(self):
        controller, objects, row, calls, occupied, _ = self.prepared()
        original = objects['databases'].observe.side_effect
        def change():
            proof = original(); row['version'] += 1; return proof
        objects['databases'].observe.side_effect = change
        with self.assertRaisesRegex(ValueError, 'HISTORY_CHANGED_AFTER'): controller.observe()
        objects['tls'].observe.assert_not_called(); self.assertFalse(occupied[0]); self.assertEqual(row['version'], 43)

    def test_wrong_receipt_history_stops_dependents(self):
        controller, objects, _, _, _, _ = self.prepared()
        objects['publisher'].observe.side_effect = None
        objects['publisher'].observe.return_value = {'heldHistoryHash': 'f'*64}
        with self.assertRaisesRegex(ValueError, 'SAME_HELD_CONTROLLER_NATIVE_WITNESS_HISTORY'): controller.observe()
        objects['databases'].observe.assert_not_called()

    def test_membership_must_use_the_same_current_publisher_proof(self):
        controller, objects, _, _, _, _ = self.prepared()
        original = objects['membership'].observe.side_effect
        def wrong_publisher():
            result = original(); result['publisherEvidenceHash'] = 'f'*64; return result
        objects['membership'].observe.side_effect = wrong_publisher
        with self.assertRaisesRegex(ValueError, 'SAME_CURRENT_PUBLISHER_AND_SELECTED_ARTIFACT'): controller.observe()
        objects['databases'].observe.assert_not_called()

    def test_complete_package_must_join_both_exact_named_membership_and_publisher(self):
        for field in ('publisherEvidenceHash', 'namedMembershipEvidenceHash', 'sixModulePackageBytesProven'):
            controller, objects, _, _, occupied, _ = self.prepared()
            original = objects['packages'].observe.side_effect
            def changed():
                proof = original(); proof[field] = False if field == 'sixModulePackageBytesProven' else 'f'*64
                return proof
            objects['packages'].observe.side_effect = changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'COMPLETE_PACKAGE_REQUIRED'): controller.observe()
            objects['databases'].observe.assert_not_called(); self.assertFalse(occupied[0])

    def test_gateway_observer_cannot_substitute_a_write_or_reenter_the_publication_checkpoint(self):
        for field in ('publicationCheckpointReentered', 'routeWrites'):
            controller, objects, _, _, occupied, _ = self.prepared()
            original = objects['gateway_routes'].observe.side_effect
            def changed():
                proof = original(); proof[field] = True if field == 'publicationCheckpointReentered' else 1
                return proof
            objects['gateway_routes'].observe.side_effect = changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'READONLY_GATEWAY_ROUTE_PROGRESS'): controller.observe()
            objects['publisher'].observe.assert_not_called(); self.assertFalse(occupied[0])

    def test_revocation_after_native_read_stops_following_read_without_repair(self):
        controller, objects, _, _, occupied, registry = self.prepared()
        original = registry.observe.side_effect
        def revoke():
            proof = original()
            controller.selected.installation.application.authority.side_effect = ValueError('CURRENT_PARENT_REVOKED')
            return proof
        registry.observe.side_effect = revoke
        with self.assertRaisesRegex(ValueError, 'CURRENT_PARENT_REVOKED'): controller.observe()
        objects['operational'].observe.assert_not_called(); self.assertFalse(occupied[0])

    def test_native_failure_is_not_retried_and_invocation_can_be_reacquired(self):
        controller, objects, _, _, occupied, _ = self.prepared()
        objects['tls'].observe.side_effect = TimeoutError('NATIVE_TLS_UNAVAILABLE')
        with self.assertRaises(TimeoutError): controller.observe()
        objects['tls'].observe.assert_called_once(); objects['iam'].observe.assert_not_called(); self.assertFalse(occupied[0])
        with controller.selected.images.window.transition.invocation(): pass

    def test_final_generation_drift_never_returns_combined_success(self):
        controller, _, _, _, occupied, registry = self.prepared()
        original = registry.observe.side_effect; count = [0]
        def changed():
            result = original(); count[0] += 1; result['generation'] = count[0]; return result
        registry.observe.side_effect = changed
        with self.assertRaisesRegex(ValueError, 'NATIVE_GENERATIONS_CHANGED'): controller.observe()
        self.assertFalse(occupied[0])


if __name__ == '__main__': unittest.main()
