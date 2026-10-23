"""Complete paused observation and one scoped signature for Registry recovery.

This is a native owner component, not a launcher or authority issuer. A distinct
signed recovery-node scope binds the independently reviewed recipe. No old
Transition/acceptance is adopted; absent/partial issuance is never retransmitted.
"""
import copy,hashlib,json,os,stat
from pathlib import Path
from .core import require,digest,encoded,validate_plan
from .lifecycle import Lifecycle
from .paused_binding import RecoveryPausedBinding
from .process_binding import RecoveryProcessBinding
from file_only_profile import FileOnlyProfile
from .frame_observation import RecoveryFileOnlyFrameObservation as FileOnlyFrameObservation
from .node_observation import RecoveryNodeObservation as PausedNodeObservation
from paused_node_acceptance import PausedNodeAcceptance
from file_only_node_owner import ObservationBudget
from compile_file_only_frame_policy import compile_policy,private_bridge_namespace_name
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes,decode,ancestors
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_installer_approval import publish_once
from tools.semantic_provider_node_observation import NodeObservation,rootfs_seal
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_admission import transport_hash

def node_scope(plan,recipe,profile):
    return {'schema':'ouf.semantic-registry-recovery-node-scope.v1',
        'planHash':digest(plan),'logicalOperationRef':plan['logicalOperationRef'],
        'nodeRecipeHash':digest(recipe),'executionProfileHash':profile.verify(profile.request),
        'sourceClosureHash':recipe['sourceClosureHash'],'sameFreshGenerationRequired':True,
        'completeIndependentRootfsRequired':True,'maximumSignatureAttempts':1}

class RecoveryNodeOwner:
    def __init__(self,lifecycle,profile,token_owner,verifier,signer,recipe):
        require(type(lifecycle) is Lifecycle and type(profile) is FileOnlyProfile
            and type(token_owner) is InstalledTokenOwner and token_owner.observer is True
            and type(verifier) is DetachedAuthenticator and type(signer) is ExistingEd25519Signer,
            'ACTUAL_RECOVERY_NODE_OWNERS_REQUIRED')
        self.lifecycle,self.profile,self.token_owner=lifecycle,profile,token_owner
        self.verifier,self.signer=verifier,signer
        self.plan=copy.deepcopy(lifecycle.plan);validate_plan(self.plan)
        self.recipe=copy.deepcopy(recipe)
        self.scope=node_scope(self.plan,recipe,profile)
        authority=lifecycle.authority
        require(profile is authority.authority.execution_profile
            and token_owner.authority is authority.authority and token_owner.raw==authority.raw
            and verifier is authority.authority.verifier and signer.verifier is verifier
            and signer.scope=={'role':'CREATION_ATTESTATION',
                'issuerRef':authority.authority.context['attestorRef'],
                'installationRef':authority.authority.context['installationRef'],
                'entityRef':authority.authority.context['entityRef']},
            'ONE_CURRENT_RECOVERY_AUTHORITY_AND_SCOPED_NODE_SIGNER_REQUIRED')
        fields={'schema','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash','expectedRootfsSeal','template','launch',
            'dockerContext','runtimeRoot','observationConfiguration','frameSourceBinding','renewableToken','delegationKeyMetadataHash',
            'proposalReceiptKey','transactionId','observationSeconds'}
        require(type(recipe) is dict and set(recipe)==fields
            and recipe['schema']=='ouf.semantic-file-only-node-recipe.v1'
            and recipe['sourceClosureHash']==authority.authority.expected['sourceClosureHash'],
            'INDEPENDENT_CURRENT_SOURCE_BOUND_RECOVERY_RECIPE_REQUIRED')
        # Recovery accepts an already custodied, independently reviewed output
        # binding. It never materializes a directory or revives an old worker.
        require(set(recipe['renewableToken'])=={'source','target','fileName','gid','directoryDevice','directoryInode',
            'ownerBindingHash','maxBytes','minimumRemainingSeconds'},
            'CURRENT_INODE_BOUND_TOKEN_OUTPUT_REQUIRED')
        self.root=lifecycle.store.root/'node';ancestors(self.root/'placeholder')
        s=self.root.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,
            'PRIVATE_RECOVERY_NODE_DIRECTORY_REQUIRED')
        self.directory_pin=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
        self.guard()

    def guard(self):
        require(node_scope(self.plan,self.recipe,self.profile)==self.scope
            and self.plan==self.lifecycle.plan,'RECOVERY_NODE_RECIPE_OR_PLAN_CHANGED')
        native=self.lifecycle;row=native.journal()
        require(json.loads(native.authority.raw).get('semanticRegistryRecoveryNode')==self.scope,
            'CURRENT_SIGNED_INDEPENDENT_RECOVERY_NODE_SCOPE_REQUIRED')
        s=self.root.lstat()
        require((s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)==self.directory_pin,
            'RECOVERY_NODE_DIRECTORY_CHANGED')
        self.profile.verify(native.request)
        self.token_owner.guard(self.token_owner.binding.digest())
        return row

    def publish(self,path,raw):
        require(path.parent==self.root and path.name=='frame-policy.json','CLOSED_RECOVERY_NODE_POLICY_PATH_REQUIRED')
        if os.path.lexists(path):require(private_bytes(path)==raw,'RECOVERY_NODE_POLICY_CHANGED')
        else:publish_once(path,raw,'RECOVERY_NODE_POLICY_PUBLICATION_RACE')

    def native_observation(self):
        checkpoint=self.guard();recipe=self.recipe
        paused=RecoveryPausedBinding(self.lifecycle,self.profile);before=paused.observe()
        native=self.lifecycle.inspect();cid=before['runtimeBinding']['containerId']
        budget=ObservationBudget(recipe['observationSeconds'])
        config=copy.deepcopy(recipe['observationConfiguration']);runner=NodeObservation(config,budget)
        state=decode(runner.run(config['runtimeBinding'],['--root',recipe['runtimeRoot'],'state',cid],16384),16384)
        paused.verify_runc_state(state,before)
        context=copy.deepcopy(recipe['dockerContext'])
        fields={'schema','bundleParent','metadataParent','networkNamespaceParent','cgroupDriver','storageParent'}
        require(set(context) in (fields,fields|{'rootfsLayout'}),'EXACT_REVIEWED_DOCKER_CONTEXT_PARENTS_REQUIRED')
        require(state.get('bundle')==context['bundleParent']+'/'+cid,'NODE_BUNDLE_OUTSIDE_REVIEWED_DOCKER_CONTEXT')
        sandbox=native.get('NetworkSettings',{}).get('SandboxKey')
        require(type(sandbox) is str and str(Path(sandbox).parent)==context['networkNamespaceParent'],'NODE_SANDBOX_OUTSIDE_REVIEWED_PARENT')
        layout=context.pop('rootfsLayout','graphdriver-merged-dir-v1')
        require(layout in ('graphdriver-merged-dir-v1','docker-containerd-overlayfs-v1'),'REVIEWED_ROOTFS_LAYOUT_REQUIRED')
        merged=(context['storageParent']+'/rootfs/overlayfs/'+cid if layout=='docker-containerd-overlayfs-v1'
            else native.get('GraphDriver',{}).get('Data',{}).get('MergedDir'))
        require(type(merged) is str and Path(merged).is_absolute() and Path(merged).is_relative_to(context['storageParent']),
            'EXACT_NATIVE_IMAGE_MERGED_ROOTFS_REQUIRED')
        require(Path(sandbox).stat().st_ino==(Path('/proc')/str(before['runtimeBinding']['pid'])/'ns/net').stat().st_ino,
            'PAUSED_DOCKER_SANDBOX_NAMESPACE_IDENTITY_DRIFT')
        context.update(containerId=cid,networkNamespaceName=private_bridge_namespace_name(self.lifecycle.request),rootfsPath=merged)
        token=copy.deepcopy(recipe['renewableToken'])
        policy=compile_policy(recipe['template'],recipe['launch'],context,execution_profile=self.profile,
            renewable_token=token,delegation_key_metadata_hash=recipe['delegationKeyMetadataHash'],proposal_receipt_key=recipe['proposalReceiptKey'])
        raw_policy=encoded(policy);policy_path=self.root/'frame-policy.json';self.publish(policy_path,raw_policy)
        configured={'source':recipe['frameSourceBinding'],'configuration':{'path':str(policy_path),'sha256':hashlib.sha256(raw_policy).hexdigest()},
            'bundleParents':config['bundleParents']}
        frame=FileOnlyFrameObservation(configured,budget,self.token_owner,paused,self.profile);observer=PausedNodeObservation(config,budget,paused,frame)
        request={'containerId':cid,'transactionId':recipe['transactionId'],'applicationHash':digest(policy['expectedOci']),
            'artifactHash':configured['configuration']['sha256'],'transportHash':transport_hash(config['candidate']),
            'generation':NativeBackend.generation(None,before['runtimeBinding']['pid'])}
        node_context={'schema':'ouf.semantic-paused-node-context.v1','transitionContextHash':self.plan['logicalOperationRef'],
            'creationRequestHash':digest(self.lifecycle.request),'stageEvidenceHash':before['stageEvidenceHash'],
            'runtimeRoot':recipe['runtimeRoot'],'bundleHash':request['applicationHash']}
        observed=observer.observe(request,node_context,frame.bundle)
        require(observed['rootfsSeal']==recipe['expectedRootfsSeal'],'INDEPENDENT_IMAGE_ROOTFS_SEAL_MISMATCH')
        expected={k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')}
        expected.update({k:request[k] for k in ('applicationHash','artifactHash','transportHash')},
            transitionContextHash=self.plan['logicalOperationRef'],creationRequestHash=digest(self.lifecycle.request),
            phaseIntentHash=self.plan['stages'][5]['intentHash'])
        authority=self.lifecycle.authority;ctx={k:authority.authority.context[k] for k in ('installationRef','entityRef','attestorRef')}
        auth=decode(authority.raw,131072)
        value={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1','issuerRef':ctx['attestorRef'],
            'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],**expected,'containerId':cid,
            'generationBinding':'OBSERVED_PAUSED_GATED','rootfsSeal':recipe['expectedRootfsSeal'],
            'issuedAt':auth['issuedAt'],'expiresAt':auth['expiresAt'],'state':'ACTIVE',
            'attestationAuthorized':True,'completeCreationAccepted':True}
        acceptance=PausedNodeAcceptance(self.verifier,ctx,expected,authority.authority.clock)
        require(self.guard()==checkpoint and paused.observe()==before,'RECOVERY_NODE_CHANGED_DURING_NATIVE_OBSERVATION')
        return observed,acceptance,encoded(value)

    def apply(self):
        row=self.guard()
        require(row['state']=='IN_FLIGHT' and row['nextStage']==5 and len(row['effects'])==6
            and row['effects'][-1]['stage']=='ATTEST_NEW_GENERATION'
            and row['effects'][-1]['state']=='CLAIMED','EXACT_RECOVERY_ATTESTATION_CLAIM_REQUIRED')
        require(row['effects'][-1].get('nativeAttestationAttempted') is not True,
            'RECOVERY_ATTESTATION_ALREADY_ATTEMPTED_OBSERVE_ONLY')
        observed,acceptance,raw=self.native_observation()
        signature_path=self.verifier.signature_directory/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')
        auth_path=self.root/'paused-acceptance.json'
        require(not os.path.lexists(auth_path) and not os.path.lexists(signature_path),
            'EXISTING_RECOVERY_NODE_ISSUANCE_REQUIRES_RECONCILIATION')
        require(self.guard()==row,'RECOVERY_CHANGED_BEFORE_NODE_SIGNATURE_CLAIM')
        effects=copy.deepcopy(row['effects']);effects[-1].update(nativeAttestationAttempted=True,
            nativeAcceptanceHash=hashlib.sha256(raw).hexdigest(),nativeObservationHash=digest(observed))
        self.lifecycle.store.cas(row,{**row,'effects':effects,'version':row['version']+1})
        self.guard()
        # The durable signature claim must not outlive the exact native pause
        # observed before it. A changed PID/netns/clock is never signed.
        current,_,expected=self.native_observation()
        require(current==observed and expected==raw,'RECOVERY_NODE_CHANGED_BEFORE_SIGNATURE')
        publish_once(self.root/'paused-observation.json',encoded(observed),
            'RECOVERY_NODE_OBSERVATION_ALREADY_PRESENT')
        envelope=self.signer.sign(raw)
        publish_once(signature_path,envelope,'RECOVERY_NODE_SIGNATURE_ALREADY_PRESENT')
        publish_once(auth_path,raw,'RECOVERY_NODE_ACCEPTANCE_ALREADY_PRESENT')
        acceptance.verify(raw,observed,self.lifecycle.cid)
        self.guard()

    def observe(self):
        row=self.guard()
        require(row['nextStage'] in (5,6,7) and len(row['effects'])>=6,
            'CURRENT_RECOVERY_ATTESTATION_OR_RETAINED_CHECKPOINT_REQUIRED')
        effect=row['effects'][5]
        if effect.get('nativeAttestationAttempted') is not True:return 'UNKNOWN',{}
        auth_path=self.root/'paused-acceptance.json'
        expected_hash=effect.get('nativeAcceptanceHash')
        if not os.path.lexists(auth_path):return 'UNKNOWN',{}
        raw=private_bytes(auth_path,131072)
        require(hashlib.sha256(raw).hexdigest()==expected_hash,'RECOVERY_NODE_ACCEPTANCE_CHANGED')
        signature_path=self.verifier.signature_directory/(expected_hash+'.CREATION_ATTESTATION.json')
        if not os.path.lexists(signature_path):return 'UNKNOWN',{}
        before,acceptance,expected=self.native_observation()
        require(raw==expected,'RECOVERY_NODE_EXPECTED_ACCEPTANCE_CHANGED')
        verification=acceptance.verify(raw,before,self.lifecycle.cid)
        after,second,expected_after=self.native_observation()
        require(before==after and expected_after==raw and private_bytes(auth_path,131072)==raw
            and second.verify(raw,after,self.lifecycle.cid)==verification
            and self.guard()==row,'RECOVERY_NODE_CHANGED_DURING_SIGNATURE_VERIFICATION')
        return 'APPLIED',{'schema':'ouf.semantic-registry-recovery-signed-node.v1',
            'newGeneration':copy.deepcopy(row['newGeneration']),
            'nativeObservationHash':digest(before),'acceptanceVerificationHash':digest(verification),
            'acceptanceHash':expected_hash,'rootfsSeal':before['rootfsSeal'],
            'creationFrameHash':before['creationFrameHash'],
            'completeNativeObservationPerformed':True,'currentScopedAcceptanceSignatureVerified':True,
            'runtimeAuthorityIssued':False,'releaseAcceptance':False}

    def verify_retained(self):
        state,proof=self.observe()
        require(state=='APPLIED','CURRENT_RETAINED_RECOVERY_NODE_ACCEPTANCE_REQUIRED')
        return proof

    def retained_signature(self):
        """Current signature for the durably observed pause, after its unpause.

        This is explicitly retained evidence, never a claim of current pause.
        The separate active-frame observer rechecks the live generation/files.
        """
        row=self.guard();effect=row['effects'][5]
        require(row['nextStage']>=6 and effect['state']=='APPLIED'
            and effect.get('nativeAttestationAttempted') is True,
            'APPLIED_RECOVERY_NODE_ACCEPTANCE_REQUIRED')
        observed=decode(private_bytes(self.root/'paused-observation.json',131072),131072)
        require(digest(observed)==effect['nativeObservationHash']
            and observed['generation']=={k:row['newGeneration'][k] for k in ('pid','startTicks','namespaceInode')},
            'RETAINED_RECOVERY_PAUSED_OBSERVATION_CHANGED')
        raw=private_bytes(self.root/'paused-acceptance.json',131072)
        require(hashlib.sha256(raw).hexdigest()==effect['nativeAcceptanceHash'],
            'RETAINED_RECOVERY_NODE_ACCEPTANCE_CHANGED')
        policy_raw=private_bytes(self.root/'frame-policy.json',131072);policy=decode(policy_raw,131072)
        recipe=self.recipe
        expected={k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')}
        expected.update(applicationHash=digest(policy['expectedOci']),artifactHash=hashlib.sha256(policy_raw).hexdigest(),
            transportHash=transport_hash(recipe['observationConfiguration']['candidate']),
            transitionContextHash=self.plan['logicalOperationRef'],creationRequestHash=digest(self.lifecycle.request),
            phaseIntentHash=self.plan['stages'][5]['intentHash'])
        authority=self.lifecycle.authority
        ctx={k:authority.authority.context[k] for k in ('installationRef','entityRef','attestorRef')}
        proof=PausedNodeAcceptance(self.verifier,ctx,expected,authority.authority.clock).verify(raw,observed,self.lifecycle.cid)
        require(self.guard()==row,'RECOVERY_CHANGED_DURING_RETAINED_SIGNATURE_READ')
        return observed,proof

    def active_frame(self):
        row=self.guard();retained,signature=self.retained_signature()
        binding=RecoveryProcessBinding(self.lifecycle,self.profile);before=binding.observe()
        recipe=self.recipe;budget=ObservationBudget(recipe['observationSeconds'])
        raw=private_bytes(self.root/'frame-policy.json',131072)
        configured={'source':recipe['frameSourceBinding'],
            'configuration':{'path':str(self.root/'frame-policy.json'),'sha256':hashlib.sha256(raw).hexdigest()},
            'bundleParents':recipe['observationConfiguration']['bundleParents']}
        frame=FileOnlyFrameObservation(configured,budget,self.token_owner,binding,self.profile)
        generation={k:row['newGeneration'][k] for k in ('pid','startTicks','namespaceInode')}
        frame_hash,_=frame.observe(generation,Path(retained['bundle'])/'config.json',
            retained['applicationHash'],configured['configuration']['sha256'])
        kind=before['process']['processKind']
        # Before the signal the shell has no permission to mutate image files.
        # Recheck the complete image seal after unpause and immediately before
        # dispatch. Never use the historical running-JVM exception here.
        sealed=False
        if kind=='GATE_WAITING':
            require(rootfs_seal(Path(retained['rootfs']),recipe['observationConfiguration']['rootfsLimits'],budget)
                ==recipe['expectedRootfsSeal'],'ACTIVE_WAIT_GATE_ROOTFS_CHANGED')
            sealed=True
        require(binding.observe()==before and self.guard()==row,'RECOVERY_ACTIVE_FRAME_CHANGED')
        return {'schema':'ouf.semantic-registry-recovery-active-frame.v1','newGeneration':copy.deepcopy(row['newGeneration']),
            'processKind':kind,'frameHash':frame_hash,'retainedSignatureVerificationHash':digest(signature),
            'preJavaFullRootfsSealVerified':sealed,'runningJvmRootfsIntegrityProven':False,
            'runtimeAuthorityIssued':False,'releaseAcceptance':False}

