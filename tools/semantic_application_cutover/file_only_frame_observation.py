"""Complete file-only OCI frame: consultation/receipt keys, DB and owner token.

Reuse the existing pinned OCI, mount and token-owner primitives. Disabling
external discovery does not disable IAM, token admission or native acceptance.
"""
import time
from pathlib import Path
from projected_frame_observation import ProjectedFrameObservation
from configtree_mount_observation import ConfigtreeMountObservation
from paused_workload_binding import PausedWorkloadBinding
from file_only_profile import FileOnlyProfile
from transition_journal import digest,hash_value,require
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation,generation as token_generation
from tools.semantic_policy_token_owner.producer import DomainOwner
from tools.semantic_provider_deployment_authentication import decode,attributes

class FileOnlyFrameObservation(ProjectedFrameObservation):
    def __init__(self,configured,budget,owner_gate,paused_binding,execution_profile):
        require(isinstance(owner_gate,DomainOwner) and type(paused_binding) is PausedWorkloadBinding
                and type(execution_profile) is FileOnlyProfile,'TYPED_FILE_ONLY_TOKEN_OWNER_AND_PROFILE_REQUIRED')
        require(getattr(paused_binding.transition,'execution_profile',None) is execution_profile,
                'EXACT_FILE_ONLY_FRAME_TRANSITION_PROFILE_REQUIRED')
        super().__init__(configured,budget)
        self.token_owner,self.pause_binding,self.profile=owner_gate,paused_binding,execution_profile
        self.profile_hash=execution_profile.verify(execution_profile.request)
    def observe(self,generation,bundle_path,application_hash,artifact_hash):
        require(self.profile.verify(self.profile.request)==self.profile_hash and artifact_hash==self.configured['configuration']['sha256']
                and hash_value(application_hash),'EXACT_FILE_ONLY_FRAME_PROFILE_REQUIRED')
        private=self.pinned();policy=decode(private['configuration'],131072)
        fields={'schema','executionProfileHash','expectedOci','manifest','startup','approvedHooks','sources','configtree','renewableToken',
                'delegationKeyTarget','delegationKeyMetadataHash','proposalReceiptKey'}
        require(set(policy)==fields and policy['schema']=='ouf.semantic-configured-file-only-four-mount-frame-policy.v1'
                and policy['executionProfileHash']==self.profile_hash and type(policy['sources']) is list and len(policy['sources'])==2
                and policy['configtree']==self.profile.configtree,'EXACT_FILE_ONLY_FOUR_MOUNT_POLICY_REQUIRED')
        raw=self.bundle(bundle_path);bundle=decode(raw,131072)
        require(digest(bundle)==application_hash==digest(policy['expectedOci']),'INDEPENDENT_FILE_ONLY_COMPLETE_OCI_DRIFT')
        modules,schema=self.owner(private['source']);review=modules['review_semantic_oci_policy'];mounts=modules['observe_semantic_mount_view'];frame=modules['observe_semantic_creation_frame']
        bindings=[{k:item[k] for k in ('source','target','readOnly')} for item in policy['sources']]
        bindings.append({k:policy['configtree'][k] for k in ('source','target','readOnly')})
        bindings.append({k:policy['renewableToken'][k] for k in ('source','target')}|{'readOnly':True})
        key,receipt=policy['sources']
        require(policy['delegationKeyTarget']==key['target'] and key['uid']==key['gid']==10001 and key['mode']==0o400
                and key['readOnly'] is True and hash_value(policy['delegationKeyMetadataHash']), 'ORIGINAL_STATIC_CONSULTATION_KEY_REQUIRED')
        signed_receipt=policy['proposalReceiptKey']
        require(type(signed_receipt) is dict and set(signed_receipt)=={'source','target','readOnly','uid','gid','mode','maxBytes','sha256','metadataHash'}
                and receipt=={k:v for k,v in signed_receipt.items() if k!='metadataHash'} and receipt['uid']==0 and receipt['gid']==10001
                and receipt['mode']==0o440 and receipt['readOnly'] is True and type(receipt['maxBytes']) is int and 1<=receipt['maxBytes']<=256
                and hash_value(receipt['sha256']) and hash_value(signed_receipt['metadataHash']),'DISTINCT_ROOT_OWNED_PROPOSAL_RECEIPT_KEY_REQUIRED')
        require(len({b['source'] for b in bindings})==len({b['target'] for b in bindings})==4 and bindings==policy['manifest']['mounts']
                and not any(a['target'].startswith(b['target']+'/') or a['source'].startswith(b['source']+'/')
                    for a in bindings for b in bindings if a is not b),'DISTINCT_NONSHADOWING_FILE_ONLY_MOUNTS_REQUIRED')
        def key_identity():
            require(digest(attributes(Path(key['source']).lstat()))==policy['delegationKeyMetadataHash']
                    and digest(attributes(Path(receipt['source']).lstat()))==signed_receipt['metadataHash'],'FILE_ONLY_KEY_METADATA_IDENTITY_DRIFT')
        key_identity();approved=review.configured_profile(bundle,policy['expectedOci'],policy['manifest'],policy['startup'],policy['approvedHooks'],schema)
        current=mounts.generation(generation['pid'],self.budget)
        require({k:current[k] for k in ('pid','startTicks')}=={k:generation[k] for k in ('pid','startTicks')}
                and current['networkNamespaceInode']==generation['namespaceInode'],'FILE_ONLY_FRAME_PROCESS_GENERATION_DRIFT')
        files=frame.source_mount_frame(generation['pid'],current,bundle,policy['sources'],self.budget)
        directory=ConfigtreeMountObservation(policy['configtree'],self.budget).observe(generation)
        token=RenewableTokenMountObservation(policy['renewableToken'],self.token_owner,time.monotonic()+self.budget.remaining(30),
            pause_binding=self.pause_binding).observe(token_generation(generation['pid'],allow_frozen=True))
        key_identity();require(self.pinned()==private and self.bundle(bundle_path)==raw and mounts.generation(generation['pid'],self.budget)==current,
            'FILE_ONLY_FRAME_CHANGED_DURING_OBSERVATION')
        self.budget.check()
        result={'schema':'ouf.semantic-configured-paused-file-only-four-mount-frame.v1','executionProfileHash':self.profile_hash,
            'configuredPolicy':approved,'sourceMountFrame':files,'configtreeMountFrame':directory,'renewableTokenMountFrame':token,
            'fourMountShapeObserved':True,'policyAuthenticationProven':False,'completeCreationAccepted':False,'signaturesIssued':0,'startAuthorized':False}
        return digest(result),{Path(self.configured[k]['path']):v for k,v in private.items()}

