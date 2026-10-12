"""Verify explicit paused-workload acceptance, never infer it from observation.

Read-only crypto gate. A NEW finite source-bound infrastructure HUMAN execution
mandate is separately required by Executor. This owner authorization pins the
independently prepared complete OCI policy and expected rootfs/image/package;
unsigned observations, metadata and hashes cannot grant acceptance or signing.
"""
import copy,hashlib,time
from transition_journal import digest,hash_value,require
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,decode

REVIEWED={'transitionContextHash','creationRequestHash','sourceClosureHash','phaseIntentHash','artifactHash','applicationHash','transportHash','imageConfigurationHash','qualifiedPackageHash'}

class PausedNodeAcceptance:
    def __init__(self,verifier,context,expected,clock=time.time):
        require(type(verifier) is DetachedAuthenticator,'TYPED_SCOPED_ED25519_NODE_VERIFIER_REQUIRED')
        require(type(context) is dict and set(context)=={'installationRef','entityRef','attestorRef'},'EXACT_PAUSED_NODE_AUTHORITY_CONTEXT_REQUIRED')
        require(type(expected) is dict and set(expected)==REVIEWED and all(hash_value(v) for v in expected.values()),'INDEPENDENT_REVIEWED_PAUSED_NODE_BINDINGS_REQUIRED')
        self.verifier,self.context,self.expected,self.clock=verifier,copy.deepcopy(context),copy.deepcopy(expected),clock
    def verify(self,raw,observed,container_id):
        started=self.clock();value=decode(raw,131072);ctx=self.context
        fields={'schema','issuerRef','installationRef','entityRef',*REVIEWED,'containerId','generationBinding','rootfsSeal','issuedAt','expiresAt','state','attestationAuthorized','completeCreationAccepted'}
        require(set(value)==fields and value['schema']=='ouf.semantic-paused-node-acceptance-authorization.v1'
                and value['issuerRef']==ctx['attestorRef'] and value['installationRef']==ctx['installationRef'] and value['entityRef']==ctx['entityRef'],
                'EXACT_PAUSED_NODE_ACCEPTANCE_AUTHORITY_REQUIRED')
        require(all(value[k]==v for k,v in self.expected.items()) and value['containerId']==container_id
                and hash_value(container_id) and value['generationBinding']=='OBSERVED_PAUSED_GATED'
                and value['state']=='ACTIVE' and value['attestationAuthorized'] is True and value['completeCreationAccepted'] is True,
                'REVIEWED_PAUSED_NODE_ACCEPTANCE_SCOPE_DRIFT')
        now=self.clock();require(type(value['issuedAt']) is int and type(value['expiresAt']) is int
                and value['issuedAt']<=now<value['expiresAt'] and 0<value['expiresAt']-value['issuedAt']<=3600,'FINITE_CURRENT_PAUSED_NODE_ACCEPTANCE_REQUIRED')
        seal=value['rootfsSeal'];require(type(seal) is dict and set(seal)=={'schema','sha256','entries','bytes'}
                and seal['schema']=='ouf.semantic-rootfs-seal.v1' and hash_value(seal['sha256'])
                and type(seal['entries']) is int and 1<=seal['entries']<=100000
                and type(seal['bytes']) is int and 0<=seal['bytes']<=8589934592,'EXACT_INDEPENDENTLY_ACCEPTED_ROOTFS_SEAL_REQUIRED')
        require(self.verifier(raw,'CREATION_ATTESTATION',ctx['attestorRef'],ctx['installationRef'],ctx['entityRef']) is True,'CURRENT_PAUSED_NODE_ACCEPTANCE_SIGNATURE_REQUIRED')
        require(type(observed) is dict and observed.get('schema')=='ouf.semantic-paused-node-observation.v1'
                and observed.get('applicationHash')==self.expected['applicationHash'] and observed.get('rootfsSeal')==seal
                and hash_value(observed.get('creationFrameHash')) and observed.get('state',{}).get('id')==container_id
                and observed.get('state',{}).get('status')=='paused'
                and observed.get('nativeStateContract',{}).get('stateContract')=='RUNC_PAUSED_ENGINE_PAUSED'
                and observed['nativeStateContract'].get('containerId')==container_id,'EXACT_OBSERVED_PAUSED_NODE_OCI_ROOTFS_AND_STATE_REQUIRED')
        generation=observed.get('generation');require(type(generation) is dict and set(generation)=={'pid','startTicks','namespaceInode'}
                and all(type(v) is int and v>1 for v in generation.values())
                and observed['state'].get('pid')==generation['pid']==observed['nativeStateContract'].get('pid'),'EXACT_OBSERVED_PAUSED_NODE_GENERATION_REQUIRED')
        require(self.clock()>=started and self.clock()<value['expiresAt'],'PAUSED_NODE_ACCEPTANCE_CLOCK_OR_WINDOW_CHANGED')
        return {'schema':'ouf.semantic-paused-node-acceptance-verification.v1','authorizationHash':hashlib.sha256(raw).hexdigest(),
                'observationHash':digest(observed),'containerId':container_id,'generation':copy.deepcopy(generation),
                **self.expected,'rootfsSeal':copy.deepcopy(seal),'creationFrameHash':observed['creationFrameHash'],
                'nativeObservationPerformedHere':False,'observedReportAuthenticatedHere':False,'currentRoleSignatureVerified':True,'explicitPausedNodeAcceptanceVerified':True,
                'signaturesIssued':0,'runtimeAuthorityIssued':False,'startAuthorized':False,'notReleaseAcceptance':True}
