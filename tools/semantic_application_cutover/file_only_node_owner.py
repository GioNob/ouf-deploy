"""One scoped native paused-node attestation inside the approved file cutover.

The review binds an independent OCI recipe and CI image rootfs seal. Docker
identity/path parameters are resolved only after creation; observed OCI is never
used as its own expected policy. Partial signature issuance is not retransmitted.
"""
import copy,hashlib,json,os,time
from pathlib import Path
from transition_journal import digest,hash_value,require
from engine_creation import Engine
from file_only_profile import FileOnlyProfile
from file_only_frame_observation import FileOnlyFrameObservation
from paused_workload_binding import PausedWorkloadBinding
from paused_node_observation import PausedNodeObservation
from paused_node_acceptance import PausedNodeAcceptance
from paused_attestation_adapter import PausedAttestationAdapter
from native_evidence_store import NativeEvidenceStore
from cutover_authority import CutoverAuthority
from compile_file_only_frame_policy import compile_policy
from tools.semantic_policy_token_owner.producer import DomainOwner
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes,decode,ancestors
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_installer_approval import publish_once
from tools.semantic_provider_node_observation import NodeObservation
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_admission import transport_hash
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
from tools.semantic_policy_token_owner.producer import protected_directory
import migration_root_custody as output_custody
import iam_binding_candidate as retained_evidence

PHASE='ATTEST_NEW_OCI_PEER'
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
class ObservationBudget:
    def __init__(self,seconds):
        require(type(seconds) is int and 1<=seconds<=180,'FINITE_NATIVE_NODE_OBSERVATION_REQUIRED');self.until=time.monotonic()+seconds
    def remaining(self,maximum=2):
        left=self.until-time.monotonic();require(left>0,'NATIVE_NODE_OBSERVATION_DEADLINE');return min(maximum,left)
    def check(self):self.remaining()

class FileOnlyNodeOwner:
    def __init__(self,engine,transition,request,intent,store,profile,token_owner,authority,authority_raw,verifier,signer,recipe,directory):
        require(type(engine) is Engine and type(store) is NativeEvidenceStore and type(profile) is FileOnlyProfile
            and isinstance(token_owner,DomainOwner) and type(authority) is CutoverAuthority and type(verifier) is DetachedAuthenticator
            and type(signer) is ExistingEd25519Signer,'TYPED_COMPLETE_FILE_ONLY_NODE_OWNER_REQUIRED')
        require(transition.execution_profile is profile and authority.execution_profile is profile and authority.verifier is verifier
            and signer.verifier is verifier and signer.scope=={'role':'CREATION_ATTESTATION','issuerRef':authority.context['attestorRef'],
                'installationRef':authority.context['installationRef'],'entityRef':authority.context['entityRef']},'SHARED_APPROVED_NODE_SIGNING_CONTEXT_REQUIRED')
        fields={'schema','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash','expectedRootfsSeal','template','launch',
            'dockerContext','runtimeRoot','observationConfiguration','frameSourceBinding','renewableToken','delegationKeyMetadataHash',
            'proposalReceiptKey','transactionId','observationSeconds'}
        require(type(recipe) is dict and set(recipe)==fields and recipe['schema']=='ouf.semantic-file-only-node-recipe.v1'
            and recipe['sourceClosureHash']==authority.expected['sourceClosureHash'] and all(hash_value(recipe[k])
                for k in ('qualifiedPackageHash','imageConfigurationHash','transactionId')),'EXACT_INDEPENDENT_FILE_ONLY_NODE_RECIPE_REQUIRED')
        require(intent=={'creationRequestHash':digest(request),'sourceClosureHash':recipe['sourceClosureHash'],
            'qualifiedPackageHash':recipe['qualifiedPackageHash'],'imageConfigurationHash':recipe['imageConfigurationHash'],
            'nodeRecipeHash':digest(recipe)},'SIGNED_FILE_ONLY_NODE_RECIPE_REQUIRED')
        self.engine,self.transition,self.store,self.profile,self.token_owner=engine,transition,store,profile,token_owner
        self.authority,self.raw,self.verifier,self.signer=authority,authority_raw,verifier,signer
        self.recipe,self.request,self.intent=map(copy.deepcopy,(recipe,request,intent));self.recipe_hash=digest(recipe);self.intent_hash=digest(intent)
        self.root=Path(directory);ancestors(self.root/'placeholder');s=self.root.lstat()
        require(self.root.is_absolute() and self.root.is_dir() and s.st_uid==s.st_gid==0 and s.st_mode&0o777==0o700,'PRIVATE_NODE_OWNER_DIRECTORY_REQUIRED')
        self.directory_binding=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode);self.adapter=None
    def current(self,intent,retained=False):
        s=self.root.lstat();require((s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)==self.directory_binding
            and digest(self.recipe)==self.recipe_hash and digest(intent)==digest(self.intent)==self.intent_hash,'FILE_ONLY_NODE_OWNER_SCOPE_DRIFT')
        self.profile.verify(self.request);require(self.authority(self.raw) is True,'CURRENT_FULL_ACTION_NODE_AUTHORITY_REQUIRED')
        row=self.transition.read()
        if retained:
            previous=[e for e in row['effects'] if e['phase']==PHASE and e['state']=='APPLIED' and e['intentHash']==self.intent_hash]
            require(len(previous)==1,'RETAINED_COMPLETED_NODE_ATTESTATION_REQUIRED')
            self.store.read(PHASE,previous[0]['nativeEvidenceHash'])
        else:
            require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==PHASE and row['effects'][-1]['intentHash']==self.intent_hash,
                'DURABLE_SCOPED_NODE_ATTESTATION_REQUIRED')
        return row
    def publish(self,path,raw):
        if os.path.lexists(path):require(private_bytes(path)==raw,'FILE_ONLY_NODE_EVIDENCE_DRIFT')
        else:publish_once(path,raw,'FILE_ONLY_NODE_EVIDENCE_RACE')
    def token_binding(self):
        """Materialize a signed future directory only from its same-action receipt.

        The proposal stays unchanged. Existing inode-bound v1 inputs retain
        their original semantics; new custody is never adopted from stat alone.
        """
        expected=copy.deepcopy(self.recipe['renewableToken'])
        if 'directoryCustodyScopeHash' not in expected:return expected
        owner=self.token_owner
        require(type(owner) is InstalledTokenOwner and owner.observer is True
            and owner.authority is self.authority and owner.raw==self.raw,
            'SAME_ACTUAL_INSTALLED_OWNER_FOR_FUTURE_OUTPUT_REQUIRED')
        owner.await_active(owner.binding.digest())
        scope=json.loads(self.raw)['policyTokenOutputCustody']
        require(digest(scope)==expected['directoryCustodyScopeHash']
            and expected['ownerBindingHash']==owner.binding.digest()
            and expected['source']==scope['path']==owner.binding.output_directory
            and expected['fileName']==owner.binding.output_member and expected['gid']==owner.binding.output_gid,
            'SAME_SIGNED_OUTPUT_SCOPE_AND_OWNER_BINDING_REQUIRED')
        with retained_evidence.protected_parent() as directory:
            host=retained_evidence.read_member(directory,'policy-token-migration-host-inputs-'+scope['hostInputsHash']+'.private.json')
            require(hashlib.sha256(host).hexdigest()==scope['hostInputsHash'],'OUTPUT_HOST_INPUT_RECEIPT_DRIFT')
            custody=output_custody.TokenOutputCustody(self.authority,self.raw,host,
                scope['completedRootEvidenceHash'],scope['rootCreationSourceClosureHash'])
            require(custody.scope==scope,'EXACT_ACTUAL_OUTPUT_CUSTODY_OWNER_REQUIRED');custody.guard()
            raw=retained_evidence.read_member(directory,custody.name)
            row=custody.validate(retained_evidence.decode(raw))
            require(row['state']=='OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED','COMPLETED_OUTPUT_CREATION_RECEIPT_REQUIRED')
            with protected_directory(custody.parent_identity['path']) as parent:
                info=os.fstat(parent)
                require({'device':info.st_dev,'inode':info.st_ino}==
                    {k:custody.parent_identity[k] for k in ('device','inode')},'OUTPUT_RECEIPT_PARENT_IDENTITY_DRIFT')
                child=os.open('token-output',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                try:custody.check_child(parent,child,row)
                finally:os.close(child)
            require(retained_evidence.read_member(directory,custody.name)==raw,'OUTPUT_CREATION_RECEIPT_CHANGED')
            custody.guard();owner.guard(owner.binding.digest())
        expected.pop('directoryCustodyScopeHash')
        expected.update(directoryDevice=row['outputIdentity']['device'],directoryInode=row['outputIdentity']['inode'])
        return expected
    def resolve(self,intent,retained=False):
        self.current(intent,retained)
        if self.adapter is not None and not retained:return self.adapter
        recipe=self.recipe;budget=ObservationBudget(recipe['observationSeconds']);paused=PausedWorkloadBinding(self.engine,self.transition,self.request,self.store)
        before=paused.observe();native=self.engine.inspect(self.transition);cid=before['runtimeBinding']['containerId']
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
        context.update(containerId=cid,networkNamespaceName=Path(sandbox).name,rootfsPath=merged)
        token=self.token_binding()
        policy=compile_policy(recipe['template'],recipe['launch'],context,execution_profile=self.profile,
            renewable_token=token,delegation_key_metadata_hash=recipe['delegationKeyMetadataHash'],proposal_receipt_key=recipe['proposalReceiptKey'])
        raw_policy=encoded(policy);policy_path=self.root/'frame-policy.json';self.publish(policy_path,raw_policy)
        configured={'source':recipe['frameSourceBinding'],'configuration':{'path':str(policy_path),'sha256':hashlib.sha256(raw_policy).hexdigest()},
            'bundleParents':config['bundleParents']}
        frame=FileOnlyFrameObservation(configured,budget,self.token_owner,paused,self.profile);observer=PausedNodeObservation(config,budget,paused,frame)
        request={'containerId':cid,'transactionId':recipe['transactionId'],'applicationHash':digest(policy['expectedOci']),
            'artifactHash':configured['configuration']['sha256'],'transportHash':transport_hash(config['candidate']),
            'generation':NativeBackend.generation(None,before['runtimeBinding']['pid'])}
        node_context={'schema':'ouf.semantic-paused-node-context.v1','transitionContextHash':self.transition.context,
            'creationRequestHash':self.intent['creationRequestHash'],'stageEvidenceHash':before['stageEvidenceHash'],
            'runtimeRoot':recipe['runtimeRoot'],'bundleHash':request['applicationHash']}
        observed=observer.observe(request,node_context,frame.bundle)
        require(observed['rootfsSeal']==recipe['expectedRootfsSeal'],'INDEPENDENT_IMAGE_ROOTFS_SEAL_MISMATCH')
        expected={k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')}
        expected.update({k:request[k] for k in ('applicationHash','artifactHash','transportHash')},transitionContextHash=self.transition.context,
            creationRequestHash=self.intent['creationRequestHash'],phaseIntentHash=self.intent_hash)
        ctx={k:self.authority.context[k] for k in ('installationRef','entityRef','attestorRef')}
        auth=decode(self.raw,131072)
        value={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1','issuerRef':ctx['attestorRef'],
            'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],**expected,'containerId':cid,'generationBinding':'OBSERVED_PAUSED_GATED',
            'rootfsSeal':recipe['expectedRootfsSeal'],'issuedAt':auth['issuedAt'],'expiresAt':auth['expiresAt'],
            'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
        raw=encoded(value);auth_path=self.root/'paused-acceptance.json';signature_path=self.verifier.signature_directory/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')
        claim=self.root/'attestation-issuance-claim.json'
        if os.path.lexists(claim):
            require(private_bytes(claim)==encoded({'transitionContextHash':self.transition.context,'authorizationHash':hashlib.sha256(raw).hexdigest(),
                'nodeRecipeHash':self.recipe_hash}) and os.path.lexists(auth_path) and os.path.lexists(signature_path),'PARTIAL_NODE_ISSUANCE_RECONCILIATION_REQUIRED')
            require(private_bytes(auth_path)==raw,'NODE_ACCEPTANCE_AUTHORIZATION_DRIFT')
        else:
            require(not retained,'COMPLETED_NODE_ISSUANCE_REQUIRED_NO_RESIGNING')
            self.current(intent)
            publish_once(claim,encoded({'transitionContextHash':self.transition.context,'authorizationHash':hashlib.sha256(raw).hexdigest(),
                'nodeRecipeHash':self.recipe_hash}),'NODE_ATTESTATION_ISSUANCE_ALREADY_CONSUMED')
            self.current(intent);envelope=self.signer.sign(raw);publish_once(signature_path,envelope,'NODE_ATTESTATION_SIGNATURE_ALREADY_PRESENT')
            publish_once(auth_path,raw,'NODE_ATTESTATION_AUTHORIZATION_ALREADY_PRESENT')
        acceptance=PausedNodeAcceptance(self.verifier,ctx,expected,self.authority.clock);acceptance.verify(raw,observed,cid)
        self.current(intent,retained)
        self.adapter=PausedAttestationAdapter(self.transition,self.intent,self.store,observer,acceptance,request,node_context,
            {'path':str(auth_path),'sha256':hashlib.sha256(raw).hexdigest()})
        return self.adapter
    def apply(self,intent):self.resolve(intent).apply(intent)
    def observe(self,intent):return self.resolve(intent).observe(intent)
    def verify_retained(self):
        """Fresh native paused proof/current signature before admission/unpause.

        This creates no signature or claim and cannot repair missing issuance.
        Reconstructing the observer gives each bounded read its own deadline.
        """
        adapter=self.resolve(self.intent,retained=True)
        raw=adapter.authorization()
        before=adapter.observer.observe(adapter.request,adapter.context,adapter.observer.frame.bundle)
        proof=adapter.acceptance.verify(raw,before,adapter.request['containerId'])
        after=adapter.observer.observe(adapter.request,adapter.context,adapter.observer.frame.bundle)
        require(before==after and adapter.authorization()==raw,'RETAINED_PAUSED_NODE_CHANGED_DURING_READ')
        self.current(self.intent,retained=True)
        return {'nativeObservationHash':digest(before),'acceptanceVerificationHash':digest(proof)}
