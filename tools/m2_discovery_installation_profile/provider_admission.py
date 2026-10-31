"""Read retained provider admission without creating or starting a provider.

Reuse the existing signed deployment protocol and consumption record. A running
Docker process or an unsigned observation is insufficient. This finite reader is
for initial worker installation; it does not renew a runtime or boot mandate.
"""
import copy,hashlib
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from .parent_authority import DiscoveryParentAuthority
from .lease_installation_template import recompile,hashed
from .lease_unit import path
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes
from tools.semantic_provider_deployment_protocol import validate_final,window
from tools.semantic_provider_deployment_consumption import Consumption
from tools.semantic_provider_lease_coordination import PrivateJournal

RECIPE_FIELDS={'schema','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash',
    'expectedRootfsSeal','expectedImageId','artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash'}
RECORDS={'intent','attestation','approval','acceptanceMandate','consumption'}


def admission_scope(template,recipe,records,configuration_hash):
    t=recompile(template)
    require(type(recipe) is dict and set(recipe)==RECIPE_FIELDS
        and recipe['schema']=='ouf.discovery-provider-independent-node-recipe.v1'
        and all(hashed(recipe[k]) for k in RECIPE_FIELDS-{'schema','expectedRootfsSeal','expectedImageId'})
        and recipe['sourceClosureHash']==t['sourceClosureHash']
        and recipe['expectedImageId']==t['expectedImages']['provider']
        and t['expectedNodeProfiles']['provider']=={'nodeRecipeHash':digest(recipe),
            'imageConfigurationHash':recipe['imageConfigurationHash'],'rootfsSealHash':digest(recipe['expectedRootfsSeal'])},
        'INDEPENDENT_REVIEWED_PROVIDER_RECIPE_REQUIRED')
    seal=recipe['expectedRootfsSeal']
    require(type(seal) is dict and set(seal)=={'schema','sha256','entries','bytes'}
        and seal['schema']=='ouf.semantic-rootfs-seal.v1' and hashed(seal['sha256'])
        and type(seal['entries']) is int and 1<=seal['entries']<=100000
        and type(seal['bytes']) is int and 0<=seal['bytes']<=8589934592,
        'EXACT_INDEPENDENT_PROVIDER_ROOTFS_SEAL_REQUIRED')
    require(type(records) is dict and set(records)==RECORDS
        and len({path(v) for v in records.values()})==len(RECORDS) and hashed(configuration_hash),
        'EXACT_DISTINCT_PROVIDER_ADMISSION_RECORD_PATHS_REQUIRED')
    return {'schema':'ouf.discovery-retained-provider-admission-scope.v1','templateHash':digest(t),
        'nodeRecipeHash':digest(recipe),'sourceClosureHash':t['sourceClosureHash'],
        'records':copy.deepcopy(records),'configurationHash':configuration_hash,
        'requiresCurrentSignedProtocolAndStartedConsumption':True,
        'containerLifecycleOperationsAuthorized':False,'historicalAuthorityReuseAllowed':False}


class RetainedProviderAdmission:
    def __init__(self,*,parent,template,recipe,records,configuration_hash):
        require(type(parent) is DiscoveryParentAuthority and type(parent.verifier) is DetachedAuthenticator,
            'TYPED_CURRENT_PROVIDER_PARENT_AND_VERIFIER_REQUIRED')
        self.parent=parent;self.template=recompile(template);self.recipe=copy.deepcopy(recipe)
        self.scope=admission_scope(template,recipe,records,configuration_hash)
        self.scope_hash=digest(self.scope);self.parent_hash=parent.sha

    def current(self,snapshot):
        require(type(self.parent) is DiscoveryParentAuthority and type(self.parent.verifier) is DetachedAuthenticator
            and self.parent.sha==self.parent_hash
            and self.scope==admission_scope(self.template,self.recipe,self.scope['records'],self.scope['configurationHash'])
            and digest(self.scope)==self.scope_hash,'RETAINED_PROVIDER_ADMISSION_SCOPE_DRIFT')
        # This component is deliberately separate from the Registry child and
        # worker publication. A future provider lifecycle controller must bind
        # its installation action separately, never hide it in this reader.
        self.parent.guard('providerInstallation',self.scope)
        raws={k:private_bytes(Path(v)) for k,v in self.scope['records'].items()}
        ctx=self.parent.context;clock=self.parent.clock;verify=self.parent.verifier
        evidence=validate_final(raws['intent'],raws['attestation'],raws['approval'],ctx,verify,clock)
        attestation=decode(raws['attestation']);intent=decode(raws['intent']);mandate=decode(raws['acceptanceMandate'])
        require(attestation['schema']=='ouf.semantic-created-candidate-attestation.v2',
            'PROVIDER_COMPLETE_AUTHENTICATED_CREATION_FRAME_REQUIRED')
        fields={'schema','issuerRef','installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
            'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation','rootfsSeal',
            'issuedAt','expiresAt','state','attestationAuthorized','completeCreationAccepted'}
        require(type(mandate) is dict and set(mandate)==fields
            and mandate['schema']=='ouf.semantic-node-creation-acceptance-mandate.v1'
            and mandate['issuerRef']==ctx['attestorRef']
            and all(mandate[k]==ctx[k] for k in ('installationRef','entityRef'))
            and all(mandate[k]==attestation[k] for k in ('containerId','transactionId','intentHash','artifactHash',
                'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation'))
            and mandate['rootfsSeal']==self.recipe['expectedRootfsSeal']
            and mandate['state']=='ACTIVE' and mandate['attestationAuthorized'] is True
            and mandate['completeCreationAccepted'] is True,
            'EXACT_SIGNED_PROVIDER_ROOTFS_AND_GENERATION_ACCEPTANCE_REQUIRED')
        window(mandate,clock())
        require(intent['issuedAt']<=mandate['issuedAt'] and mandate['expiresAt']<=intent['expiresAt']
            and verify(raws['acceptanceMandate'],'CREATION_ATTESTATION',ctx['attestorRef'],ctx['installationRef'],ctx['entityRef']) is True,
            'CURRENT_PROVIDER_ROOTFS_ACCEPTANCE_SIGNATURE_REQUIRED')
        require(all(intent[k]==self.recipe[k] for k in
            ('artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')),
            'PROVIDER_PROTOCOL_MUST_MATCH_INDEPENDENT_RECIPE')
        peer=snapshot['peers']['provider'];profile=snapshot['profiles']['provider']
        require(snapshot['desiredProfileHash']==self.template['configurationTemplate']['desiredProfileHash']
            and peer['containerId']==evidence['scope']['containerId']
            and peer['imageId']==self.recipe['expectedImageId']
            and profile=={**self.template['expectedNodeProfiles']['provider'],'applicationHash':evidence['scope']['applicationHash']}
            and evidence['generation']=={'pid':peer['pid'],'startTicks':peer['startTicks'],
                'namespaceInode':peer['namespace']['identity'][1]},
            'SAME_INDEPENDENTLY_ADMITTED_PROVIDER_AND_LEASE_GENERATION_REQUIRED')
        binding={k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId')}
        binding.update(intentHash=evidence['intentHash'],configurationHash=self.scope['configurationHash'])
        journal=PrivateJournal(Path(self.scope['records']['consumption']))
        consumption=Consumption(binding,journal,None).record()  # Read only; no lock/mutation method is called.
        require(consumption['state']=='STARTED' and consumption['bundleHash']==profile['applicationHash']
            and consumption['generation']==evidence['generation'] and consumption['evidenceHash']==digest(evidence)
            and consumption['approvalHash']==evidence['approvalHash'],
            'EXACT_STARTED_PROVIDER_CONSUMPTION_REQUIRED_NO_ADOPTION')
        require(all(private_bytes(Path(self.scope['records'][k]))==raw for k,raw in raws.items()),
            'PROVIDER_ADMISSION_CHANGED_DURING_READ')
        window(mandate,clock());window(intent,clock());self.parent.guard('providerInstallation',self.scope)
        return {'schema':'ouf.discovery-current-retained-provider-admission.v1','scopeHash':self.scope_hash,
            'recordsHash':digest({k:hashlib.sha256(v).hexdigest() for k,v in raws.items()}),
            'validatedEvidenceHash':digest(evidence),'consumptionHash':digest(consumption),
            'containerId':peer['containerId'],'generation':copy.deepcopy(evidence['generation']),
            'nativeObservationPerformedHere':False,'providerReadinessProven':False,
            'signaturesIssued':0,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
