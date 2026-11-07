"""Fresh Registry admission after the attested gate execs Java in-place.

The paused observer remains closed and unchanged. This separate reader uses
the existing running-process and renewable-token contracts, the independently
compiled seven-mount policy and current scoped acceptance signature. It never
signs, pauses, signals, starts, repairs a journal or obtains a new token.
"""
import copy,hashlib,time
from pathlib import Path
from .custody_capture import digest,encoded,require
from .node_owner import DiscoveryNodeOwner,ObservationBudget
from .frame import compile_policy,validate_observation_policy
from .native_profile import DiscoveryProfile
from tools.semantic_provider_deployment_authentication import private_bytes,attributes,decode
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_admission import transport_hash
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation,generation
from gated_process_observation import RunningWorkloadBinding
from projected_frame_observation import ProjectedFrameObservation
from configtree_mount_observation import ConfigtreeMountObservation
from compile_file_only_frame_policy import private_bridge_namespace_name
from application_verification_adapter import ApplicationReadinessChannel


class RunningDiscoveryFrame:
    def __init__(self,node,budget):
        require(type(node) is DiscoveryNodeOwner and type(node.profile) is DiscoveryProfile
            and type(budget) is ObservationBudget,'ACTUAL_DISCOVERY_NODE_AND_RUNNING_OBSERVATION_BUDGET_REQUIRED')
        self.node,self.budget=node,budget
        self.running=RunningWorkloadBinding(node.engine,node.transition,node.request,node.store)
        self.ids=tuple(map(id,(node,node.engine,node.transition,node.store,node.profile,node.token_owner)))

    def current(self):
        n=self.node
        require(self.ids==tuple(map(id,(n,n.engine,n.transition,n.store,n.profile,n.token_owner)))
            and n.profile.verify(n.request)==n.recipe['executionProfileHash'],
            'RUNNING_DISCOVERY_NODE_OWNER_OR_PROFILE_CHANGED')
        self.budget.check();row=n.current(n.intent,retained=True)
        require(row['state']=='READY' and row['nextPhase']==12,
            'VERIFIED_REGISTRY_WITH_RELEASE_BARRIER_HELD_REQUIRED')
        return row

    def policy(self,actual):
        n=self.node;cid=actual['Id'];context=copy.deepcopy(n.recipe['dockerContext'])
        layout=context.pop('rootfsLayout','graphdriver-merged-dir-v1')
        require(layout in ('docker-containerd-overlayfs-v1','graphdriver-merged-dir-v1'),
            'EXACT_REVIEWED_RUNNING_ROOTFS_LAYOUT_REQUIRED')
        merged=(context['storageParent']+'/rootfs/overlayfs/'+cid if layout=='docker-containerd-overlayfs-v1'
            else actual.get('GraphDriver',{}).get('Data',{}).get('MergedDir'))
        require(type(merged) is str and Path(merged).is_absolute()
            and Path(merged).is_relative_to(context['storageParent']),
            'RUNNING_REGISTRY_ROOTFS_OUTSIDE_REVIEWED_STORAGE')
        context.update(containerId=cid,rootfsPath=merged,networkNamespaceName=private_bridge_namespace_name(n.request))
        policy=compile_policy(n.recipe['template'],n.recipe['launch'],context,execution_profile=n.profile)
        require(validate_observation_policy(policy,n.profile)==n.profile.sha256,
            'INDEPENDENT_RUNNING_DISCOVERY_POLICY_REQUIRED')
        return policy

    def acceptance(self,raw,policy,cid):
        """Authenticate retained creation acceptance without claiming a new seal."""
        n=self.node;ctx=n.authority.context;child=decode(n.raw,131072);started=n.authority.clock()
        expected={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1',
            'issuerRef':ctx['attestorRef'],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],
            **{k:n.recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')},
            'applicationHash':digest(policy['expectedOci']),'artifactHash':hashlib.sha256(encoded(policy)).hexdigest(),
            'transportHash':transport_hash(n.recipe['observationConfiguration']['candidate']),
            'transitionContextHash':n.transition.context,'creationRequestHash':digest(n.request),
            'phaseIntentHash':n.intent_hash,'containerId':cid,'generationBinding':'OBSERVED_PAUSED_GATED',
            'rootfsSeal':n.recipe['expectedRootfsSeal'],'issuedAt':child['issuedAt'],'expiresAt':child['expiresAt'],
            'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
        accepted=decode(raw,131072)
        require(accepted==expected and accepted['attestationAuthorized'] is True and accepted['completeCreationAccepted'] is True
            and type(accepted['issuedAt']) is int and type(accepted['expiresAt']) is int
            and accepted['issuedAt']<=started<accepted['expiresAt']
            and 0<accepted['expiresAt']-accepted['issuedAt']<=3600,
            'CURRENT_INDEPENDENT_RUNNING_NODE_ACCEPTANCE_REQUIRED')
        require(n.verifier(raw,'CREATION_ATTESTATION',ctx['attestorRef'],ctx['installationRef'],ctx['entityRef']) is True,
            'CURRENT_RUNNING_NODE_ACCEPTANCE_SIGNATURE_REQUIRED')
        require(started<=n.authority.clock()<accepted['expiresAt'],'RUNNING_NODE_ACCEPTANCE_CLOCK_OR_WINDOW_CHANGED')
        return accepted

    def observe(self):
        n=self.node;row=self.current();before=self.running.observe()
        actual=n.engine.matching_configuration(n.transition,n.request,n.engine.inspect(n.transition))
        require(n.engine.runtime_binding(actual)==before['runtimeBinding'],'RUNNING_REGISTRY_BINDING_CHANGED')
        policy=self.policy(actual);raw_policy=encoded(policy);policy_path=n.root/'frame-policy.json'
        require(private_bytes(policy_path,131072)==raw_policy,'INDEPENDENT_RUNNING_POLICY_BYTES_CHANGED')
        configured={'source':n.recipe['frameSourceBinding'],
            'configuration':{'path':str(policy_path),'sha256':hashlib.sha256(raw_policy).hexdigest()},
            'bundleParents':n.recipe['observationConfiguration']['bundleParents']}
        frame=ProjectedFrameObservation(configured,self.budget);private=frame.pinned()
        bundle_path=Path(n.recipe['dockerContext']['bundleParent'])/actual['Id']/'config.json'
        raw_bundle=frame.bundle(bundle_path);bundle=decode(raw_bundle,131072)
        require(digest(bundle)==digest(policy['expectedOci']),'RUNNING_COMPLETE_OCI_DIFFERS_FROM_INDEPENDENT_RECIPE')
        # Authenticate the existing attestation against these same independent
        # frame/source/profile/generation references. No new acceptance issued.
        authorization=private_bytes(n.root/'paused-acceptance.json',131072)
        accepted=self.acceptance(authorization,policy,actual['Id'])
        accepted_effect=next(e for e in row['effects'] if e['phase']=='ATTEST_NEW_OCI_PEER' and e['state']=='APPLIED')
        receipt=n.store.read('ATTEST_NEW_OCI_PEER',accepted_effect['nativeEvidenceHash'])
        require(receipt['schema']=='ouf.semantic-owner-signed-paused-node-phase.v1'
            and receipt['transitionContextHash']==n.transition.context and receipt['intentHash']==n.intent_hash
            and receipt['creationRequestHash']==digest(n.request)
            and receipt['generation']==before['process']['generation'] and receipt['containerId']==actual['Id']
            and receipt['rootfsSeal']==accepted['rootfsSeal']
            and receipt['completeNativeObservationPerformed'] is True
            and receipt['currentScopedAcceptanceSignatureVerified'] is True,
            'SAME_ATTESTED_GENERATION_AFTER_GATE_EXEC_REQUIRED')
        modules,schema=frame.owner(private['source'])
        review=modules['review_semantic_oci_policy'];mounts=modules['observe_semantic_mount_view']
        files=modules['observe_semantic_creation_frame']
        def metadata():
            for f in policy['fileBindings'].values():
                self.budget.check();require(digest(attributes(Path(f['source']).lstat()))==f['metadataHash'],
                    'RUNNING_DISCOVERY_FILE_CUSTODY_CHANGED')
        metadata()
        approved=review.configured_profile(bundle,policy['expectedOci'],policy['manifest'],policy['startup'],policy['approvedHooks'],schema)
        pid=before['runtimeBinding']['pid'];native=NativeBackend.generation(None,pid)
        require(native==before['process']['generation'],'RUNNING_DISCOVERY_NATIVE_GENERATION_CHANGED')
        mounted=mounts.generation(pid,self.budget)
        require(mounted['pid']==native['pid'] and mounted['startTicks']==native['startTicks']
            and mounted['networkNamespaceInode']==native['namespaceInode'],'RUNNING_DISCOVERY_MOUNT_GENERATION_CHANGED')
        static=files.source_mount_frame(pid,mounted,bundle,policy['sources'],self.budget)
        configtree=ConfigtreeMountObservation(policy['configtree'],self.budget).observe(native)
        token=RenewableTokenMountObservation(policy['renewableToken'],n.token_owner,
            time.monotonic()+self.budget.remaining(30),running_binding=self.running).observe(generation(pid,allow_frozen=True))
        metadata();self.acceptance(authorization,policy,actual['Id'])
        require(self.current()==row and self.running.observe()==before and frame.pinned()==private
            and frame.bundle(bundle_path)==raw_bundle and private_bytes(policy_path,131072)==raw_policy
            and private_bytes(n.root/'paused-acceptance.json',131072)==authorization
            and mounts.generation(pid,self.budget)==mounted,
            'RUNNING_DISCOVERY_FRAME_CHANGED_DURING_OBSERVATION')
        self.budget.check()
        return {'schema':'ouf.discovery-current-running-registry-frame.v1','runtimeBinding':before['runtimeBinding'],
            'processGenerationHash':digest(native),'executionProfileHash':n.profile.sha256,
            'acceptanceHash':hashlib.sha256(authorization).hexdigest(),'creationRootfsSealHash':digest(accepted['rootfsSeal']),
            'currentFrameHash':digest({'policy':approved,'files':static,'configtree':configtree,'token':token}),
            'sameAttestedGenerationNowRunningJava':True,'sevenCurrentMountsObserved':True,
            'currentMountedTokenAdmissionObserved':True,'rootfsResealedWhileRunning':False,
            'fullCohortProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}


class RunningRegistryAdmission:
    def __init__(self,node,readiness):
        require(type(node) is DiscoveryNodeOwner and type(readiness) is ApplicationReadinessChannel,
            'ACTUAL_DISCOVERY_NODE_AND_REGISTRY_READINESS_CHANNEL_REQUIRED')
        self.node,self.readiness=node,readiness;self.ids=(id(node),id(readiness));self.scope_hash=readiness.scope_hash

    def current(self):
        n=self.node;self.readiness.exact()
        require(self.ids==(id(n),id(self.readiness)) and self.readiness.scope_hash==self.scope_hash
            and decode(n.raw,131072)['phaseIntentHashes']['VERIFY_APPLICATION']==digest({
                'creationRequestHash':digest(n.request),'readinessScopeHash':self.scope_hash,
                'priorReleaseEvidencePhase':'START_REPLACEMENT'}),'SIGNED_CURRENT_REGISTRY_READINESS_SCOPE_REQUIRED')
        actual=n.engine.matching_configuration(n.transition,n.request,n.engine.inspect(n.transition))
        networks=actual.get('NetworkSettings',{}).get('Networks',{})
        require(any(v.get('IPAddress')==self.readiness.scope['health']['address'] for v in networks.values()),
            'CURRENT_HEALTH_ADDRESS_OUTSIDE_VERIFIED_REGISTRY')
        return n.engine.runtime_binding(actual)

    def observe(self):
        binding=self.current()
        budget=ObservationBudget(30);reader=RunningDiscoveryFrame(self.node,budget)
        before=reader.observe();health=self.readiness.health()
        require(health is not None,'CURRENT_RUNNING_REGISTRY_HEALTH_REQUIRED')
        database=self.readiness.database();budget.check()
        require(before['runtimeBinding']==binding and reader.observe()==before and self.readiness.health()==health
            and self.readiness.database()==database,'RUNNING_REGISTRY_ADMISSION_CHANGED_DURING_READ')
        require(self.current()==binding,'RUNNING_REGISTRY_ADMISSION_CHANNEL_CHANGED')
        budget.check()
        return {'schema':'ouf.discovery-current-running-registry-admission.v1','frame':before,
            'health':health,'database':database,'fullCohortProven':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
