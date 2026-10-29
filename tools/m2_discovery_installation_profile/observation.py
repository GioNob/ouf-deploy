"""Read-only discovery frame witness using existing native owner primitives.

The independent policy is still separately authenticated by the node owner.
This witness grants no signature, execution, lease, provider or DB admission.
"""
import time
from pathlib import Path
from projected_frame_observation import ProjectedFrameObservation
from configtree_mount_observation import ConfigtreeMountObservation
from tools.m2_discovery_installation_profile.paused_binding import DiscoveryPausedWorkloadBinding as PausedWorkloadBinding
from transition_journal import PHASES, digest, hash_value, require
from tools.m2_discovery_installation_profile.token_mount_observation import DiscoveryTokenMountObservation as RenewableTokenMountObservation, generation as token_generation
from tools.semantic_policy_token_owner.producer import DomainOwner
from tools.semantic_provider_deployment_authentication import decode, attributes
from tools.m2_discovery_installation_profile.frame import validate_observation_policy
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile


class DiscoveryFrameObservation(ProjectedFrameObservation):
    def __init__(self, configured, budget, owner_gate, paused_binding, execution_profile):
        require(isinstance(owner_gate, DomainOwner) and type(paused_binding) is PausedWorkloadBinding
                and type(execution_profile) is DiscoveryProfile, 'TYPED_DISCOVERY_FRAME_OWNER_AND_PROFILE_REQUIRED')
        transition = paused_binding.transition
        require(paused_binding.profile is execution_profile and transition.execution_profile is None and transition.phases == PHASES
                and transition.read()['creationRequestHash'] == execution_profile.compiled['creationRequestHash']
                and paused_binding.request_hash == execution_profile.compiled['creationRequestHash'],
                'DISCOVERY_REQUIRES_FULL_CURRENT_TRANSITION_AND_CREATION_BINDING')
        super().__init__(configured, budget)
        self.token_owner, self.pause_binding, self.profile = owner_gate, paused_binding, execution_profile
        self.profile_hash = execution_profile.verify(execution_profile.request)

    def observe(self, generation, bundle_path, application_hash, artifact_hash):
        require(self.profile.verify(self.profile.request) == self.profile_hash
                and artifact_hash == self.configured['configuration']['sha256'] and hash_value(application_hash),
                'EXACT_DISCOVERY_FRAME_PROFILE_AND_ARTIFACT_REQUIRED')
        paused = self.pause_binding.observe()
        require(paused['creationRequestHash'] == self.profile.compiled['creationRequestHash']
                and paused['runtimeBinding']['pid'] == generation['pid'], 'DISCOVERY_PAUSED_GENERATION_DRIFT')
        private = self.pinned(); policy = decode(private['configuration'], 131072)
        require(validate_observation_policy(policy, self.profile) == self.profile_hash, 'DISCOVERY_FRAME_PROFILE_DRIFT')
        raw = self.bundle(bundle_path); bundle = decode(raw, 131072)
        require(digest(bundle) == application_hash == digest(policy['expectedOci']), 'DISCOVERY_COMPLETE_OCI_DRIFT')
        modules, schema = self.owner(private['source'])
        review, mounts, frame = (modules[k] for k in ('review_semantic_oci_policy', 'observe_semantic_mount_view', 'observe_semantic_creation_frame'))

        def metadata():
            for f in policy['fileBindings'].values():
                self.budget.check()
                require(digest(attributes(Path(f['source']).lstat())) == f['metadataHash'],
                        'DISCOVERY_FILE_METADATA_IDENTITY_DRIFT')

        metadata()
        approved = review.configured_profile(bundle, policy['expectedOci'], policy['manifest'], policy['startup'], policy['approvedHooks'], schema)
        current = mounts.generation(generation['pid'], self.budget)
        require({k: current[k] for k in ('pid', 'startTicks')} == {k: generation[k] for k in ('pid', 'startTicks')}
                and current['networkNamespaceInode'] == generation['namespaceInode'], 'DISCOVERY_FRAME_PROCESS_GENERATION_DRIFT')
        files = frame.source_mount_frame(generation['pid'], current, bundle, policy['sources'], self.budget)
        directory = ConfigtreeMountObservation(policy['configtree'], self.budget).observe(generation)
        token = RenewableTokenMountObservation(policy['renewableToken'], self.token_owner,
            time.monotonic() + self.budget.remaining(30), pause_binding=self.pause_binding).observe(
                token_generation(generation['pid'], allow_frozen=True))
        metadata()
        require(self.profile.verify(self.profile.request) == self.profile_hash and self.pinned() == private
                and self.bundle(bundle_path) == raw and mounts.generation(generation['pid'], self.budget) == current
                and self.pause_binding.observe() == paused, 'DISCOVERY_FRAME_CHANGED_DURING_OBSERVATION')
        self.budget.check()
        result = {'schema': 'ouf.semantic-configured-paused-discovery-seven-mount-frame.v1',
            'executionProfileHash': self.profile_hash, 'configuredPolicy': approved, 'sourceMountFrame': files,
            'configtreeMountFrame': directory, 'renewableTokenMountFrame': token, 'sevenMountShapeObserved': True,
            'policyAuthenticationProven': False, 'completeCreationAccepted': False, 'signaturesIssued': 0, 'startAuthorized': False}
        return digest(result), {Path(self.configured[k]['path']): v for k, v in private.items()}
