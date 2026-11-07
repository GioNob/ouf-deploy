"""Discovery-specific owner-signed paused-node acceptance phase for Executor.

No issuance, keys, signal, lease, migration or start. The sealed checkpoint
separately owns publisher/supply-chain and current HUMAN source authority.
An unsigned observation or an absent/mismatched acceptance cannot advance.
"""
import copy,hashlib
from pathlib import Path
from transition_journal import require,digest,hash_value
from native_evidence_store import NativeEvidenceStore
from tools.m2_discovery_installation_profile.node_observation import DiscoveryNodeObservation
from paused_node_acceptance import PausedNodeAcceptance
from tools.m2_discovery_installation_profile.observation import DiscoveryFrameObservation
from tools.semantic_provider_deployment_authentication import private_bytes

PHASE='ATTEST_NEW_OCI_PEER'
class DiscoveryPausedAttestationAdapter:
    def __init__(self,transition,intent,store,observer,acceptance,request,context,authorization_binding):
        require(type(observer) is DiscoveryNodeObservation and type(observer.frame) is DiscoveryFrameObservation
                and type(acceptance) is PausedNodeAcceptance and type(store) is NativeEvidenceStore,
                'TYPED_DISCOVERY_PAUSED_NODE_OWNER_PHASE_REQUIRED')
        require(type(authorization_binding) is dict and set(authorization_binding)=={'path','sha256'}
                and Path(authorization_binding['path']).is_absolute() and hash_value(authorization_binding['sha256']),
                'PINNED_EXISTING_PAUSED_ACCEPTANCE_REQUIRED')
        self.transition,self.store,self.observer,self.acceptance=transition,store,observer,acceptance
        self.intent,self.request,self.context,self.authorization_binding=map(copy.deepcopy,(intent,request,context,authorization_binding))
        self.intent_hash=digest(intent);self.request_hash=digest(request);self.context_hash=digest(context)
        expected=acceptance.expected
        self.acceptance_scope_hash=digest({'context':acceptance.context,'expected':expected})
        recipe_field={}
        if 'nodeRecipeHash' in intent:
            require(hash_value(intent['nodeRecipeHash']),'EXACT_DISCOVERY_NODE_RECIPE_HASH_REQUIRED')
            recipe_field={'nodeRecipeHash':intent['nodeRecipeHash']}
        require(intent=={'creationRequestHash':expected['creationRequestHash'],'sourceClosureHash':expected['sourceClosureHash'],
                         'qualifiedPackageHash':expected['qualifiedPackageHash'],'imageConfigurationHash':expected['imageConfigurationHash'],**recipe_field}
                and expected['phaseIntentHash']==self.intent_hash
                and expected['transitionContextHash']==transition.context
                and all(request.get(k)==expected[k] for k in ('applicationHash','artifactHash','transportHash'))
                and context.get('transitionContextHash')==transition.context
                and context.get('creationRequestHash')==expected['creationRequestHash'],
                'EXACT_SIGNED_PAUSED_NODE_SCOPE_AND_RECIPE_REQUIRED')
    def exact(self,intent):
        row=self.transition.read()
        require(digest(intent)==self.intent_hash==digest(self.intent) and digest(self.request)==self.request_hash
                and digest({'context':self.acceptance.context,'expected':self.acceptance.expected})==self.acceptance_scope_hash
                and digest(self.context)==self.context_hash and row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==PHASE
                and row['effects'][-1]['intentHash']==self.intent_hash and row['creationRequestHash']==self.intent['creationRequestHash'],
                'CURRENT_EXECUTOR_PAUSED_ATTESTATION_SCOPE_REQUIRED')
        return row
    def authorization(self):
        raw=private_bytes(Path(self.authorization_binding['path']),131072)
        require(hashlib.sha256(raw).hexdigest()==self.authorization_binding['sha256'],'PAUSED_NODE_ACCEPTANCE_FILE_DRIFT')
        return raw
    def apply(self,intent):
        # Effect-free. Reconciliation performs both native observation and
        # current signature verification; no no-op return can mark APPLIED.
        self.exact(intent);self.authorization()
    def observe(self,intent):
        self.exact(intent);raw=self.authorization()
        before=self.observer.observe(self.request,self.context,self.observer.frame.bundle)
        verification=self.acceptance.verify(raw,before,self.request['containerId'])
        after=self.observer.observe(self.request,self.context,self.observer.frame.bundle)
        require(after==before and self.authorization()==raw,'PAUSED_NODE_OR_ACCEPTANCE_CHANGED_DURING_VERIFICATION')
        require(self.acceptance.verify(raw,after,self.request['containerId'])==verification,'PAUSED_NODE_CURRENT_SIGNATURE_OR_POLICY_CHANGED')
        self.exact(intent)
        evidence={'schema':'ouf.semantic-owner-signed-paused-node-phase.v1','transitionContextHash':self.transition.context,
                  'intentHash':self.intent_hash,'creationRequestHash':self.intent['creationRequestHash'],'containerId':self.request['containerId'],
                  'nativeObservationHash':digest(before),'acceptanceVerificationHash':digest(verification),
                  'generation':before['generation'],'rootfsSeal':before['rootfsSeal'],'creationFrameHash':before['creationFrameHash'],
                  'completeNativeObservationPerformed':True,'currentScopedAcceptanceSignatureVerified':True,
                  'publisherCryptoVerifiedHere':False,'supplyChainRequiredBySealedCheckpoint':True,
                  'runtimeAuthorityIssued':False,'signaturesIssued':0,'applicationStartAuthorized':False,'notReleaseAcceptance':True}
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence

