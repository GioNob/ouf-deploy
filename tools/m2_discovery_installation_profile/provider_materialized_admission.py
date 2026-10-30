"""Read the new owned provider's v4 admission for initial worker installation.

Static review binds the independent recipe before CID allocation. Concrete
artifact/transport/configuration hashes are recompiled from owned identities;
signed v2 creation, rootfs mandate, STARTED consumption and adapter must agree.
No key, lifecycle operation, repair, legacy-provider adoption or budget reset.
"""
import hashlib
from pathlib import Path
from .custody_capture import digest,decode,require
from . import provider_installation_template as provider_templates
from .lease_installation_template import recompile
from .provider_profile_publication import ProviderProfilePublication
from .provider_profiles import ProviderInitialIssuer
from .provider_admission import RECORDS
from tools.semantic_provider_deployment_authentication import private_bytes
from tools.semantic_provider_deployment_protocol import validate_final,window
from tools.semantic_provider_deployment_consumption import Consumption
from tools.semantic_provider_lease_coordination import PrivateJournal

def admission_scope(lease_template,provider_template,creation_scope,profile_scope):
    lease=recompile(lease_template);provider=provider_templates.recompile(provider_template)
    recipe=provider_templates.node_recipe(provider)
    require(lease['sourceClosureHash']==recipe['sourceClosureHash']
        and lease['expectedImages']['provider']==recipe['expectedImageId']
        and lease['expectedNodeProfiles']['provider']==provider_templates.expected_node_profile(provider)
        and creation_scope['templateHash']==profile_scope['providerTemplateHash']==digest(provider)
        and profile_scope['creationScopeHash']==digest(creation_scope),
        'SAME_STATIC_PROVIDER_CREATION_PROFILE_AND_WORKER_EXPECTATIONS_REQUIRED')
    return {'schema':'ouf.discovery-materialized-provider-admission-scope.v1','templateHash':digest(lease),
        'providerTemplateHash':digest(provider),'nodeRecipeHash':digest(recipe),
        'creationScopeHash':digest(creation_scope),'profileScopeHash':digest(profile_scope),
        'registryRoot':profile_scope['registryRoot'],'requiresCurrentSignedProtocolAndStartedConsumption':True,
        'requiresOwnedNewCreationAndCompiledExactFrame':True,'containerLifecycleOperationsAuthorized':False,
        'historicalAuthorityReuseAllowed':False}

class MaterializedProviderAdmission:
    def __init__(self,*,publication,lease_template):
        require(type(publication) is ProviderProfilePublication and type(publication.issuer) is ProviderInitialIssuer,
            'TYPED_OWNED_PROVIDER_PROFILE_PUBLICATION_REQUIRED')
        self.publication=publication;self.issuer=publication.issuer;self.creation=self.issuer.creation
        self.parent=self.creation.parent;self.template=recompile(lease_template)
        self.scope=admission_scope(self.template,self.issuer.template,self.creation.scope,self.issuer.scope)
        self.scope_hash=digest(self.scope);self.parent_hash=self.parent.sha
    def current(self,snapshot):
        require(type(self.publication) is ProviderProfilePublication and self.publication.issuer is self.issuer
            and type(self.issuer) is ProviderInitialIssuer and self.issuer.creation is self.creation
            and self.creation.parent is self.parent and self.parent.sha==self.parent_hash
            and self.scope==admission_scope(self.template,self.issuer.template,self.creation.scope,self.issuer.scope)
            and digest(self.scope)==self.scope_hash and self.creation.component['admission']==self.scope,
            'EXACT_REVIEWED_MATERIALIZED_PROVIDER_ADMISSION_SCOPE_REQUIRED')
        self.parent.guard('providerInstallation',self.creation.component)
        require(self.publication.observe(initial=False)[0]=='APPLIED','COMPLETE_OWNED_PROVIDER_PROFILE_PUBLICATION_REQUIRED')
        material=self.publication.material();root=Path(material['root']);cid=self.creation.owned_id()
        paths={'intent':root/'intent.json','attestation':root/'attestation.json','approval':root/'approval.json',
            'acceptanceMandate':root/'node-acceptance.json','consumption':root/'deployment.json'}
        require(set(paths)==RECORDS,'EXACT_NEW_PROVIDER_PROTOCOL_RECORD_SET_REQUIRED')
        raws={k:private_bytes(p) for k,p in paths.items()}
        ctx=self.parent.context;verify=self.parent.verifier;clock=self.parent.clock
        evidence=validate_final(raws['intent'],raws['attestation'],raws['approval'],ctx,verify,clock)
        intent=decode(raws['intent']);attestation=decode(raws['attestation']);mandate=decode(raws['acceptanceMandate'])
        proposal=material['materialized']
        require(raws['intent']==material['files'][str(paths['intent'])]
            and attestation['schema']=='ouf.semantic-created-candidate-attestation.v2'
            and attestation['containerId']==cid and attestation['applicationHash']==proposal['applicationHash']
            and intent['artifactHash']==proposal['artifactHash'] and intent['transportHash']==proposal['transportHash']
            and intent['runtimeExecutableHash']==self.issuer.template['runtimeBinding']['sha256'],
            'OWNED_PROVIDER_PROTOCOL_MUST_MATCH_INDEPENDENT_MATERIALIZATION')
        fields={'schema','issuerRef','installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
            'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation','rootfsSeal',
            'issuedAt','expiresAt','state','attestationAuthorized','completeCreationAccepted'}
        require(type(mandate) is dict and set(mandate)==fields
            and mandate['schema']=='ouf.semantic-node-creation-acceptance-mandate.v1'
            and mandate['issuerRef']==ctx['attestorRef']
            and all(mandate[k]==ctx[k] for k in ('installationRef','entityRef'))
            and all(mandate[k]==attestation[k] for k in ('containerId','transactionId','intentHash','artifactHash',
                'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation'))
            and mandate['rootfsSeal']==self.issuer.template['expectedRootfsSeal'] and mandate['state']=='ACTIVE'
            and mandate['attestationAuthorized'] is True and mandate['completeCreationAccepted'] is True,
            'EXACT_SIGNED_NEW_PROVIDER_ROOTFS_AND_GENERATION_REQUIRED')
        window(mandate,clock());require(intent['issuedAt']<=mandate['issuedAt'] and mandate['expiresAt']<=intent['expiresAt']
            and verify(raws['acceptanceMandate'],'CREATION_ATTESTATION',ctx['attestorRef'],ctx['installationRef'],ctx['entityRef']) is True,
            'CURRENT_NEW_PROVIDER_ROOTFS_MANDATE_SIGNATURE_REQUIRED')
        peer=snapshot['peers']['provider'];profile=snapshot['profiles']['provider']
        require(snapshot['desiredProfileHash']==self.template['configurationTemplate']['desiredProfileHash']
            and peer['containerId']==cid and peer['imageId']==self.template['expectedImages']['provider']
            and profile=={**self.template['expectedNodeProfiles']['provider'],'applicationHash':proposal['applicationHash']}
            and evidence['generation']=={'pid':peer['pid'],'startTicks':peer['startTicks'],
                'namespaceInode':peer['namespace']['identity'][1]},'SAME_OWNED_PROVIDER_AND_WORKER_NATIVE_GENERATION_REQUIRED')
        configuration_hash=digest(material['profiles']['broker.json'])
        binding={k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId')}
        binding.update(intentHash=evidence['intentHash'],configurationHash=configuration_hash)
        consumption=Consumption(binding,PrivateJournal(paths['consumption']),None).record()
        require(consumption['state']=='STARTED' and consumption['bundleHash']==proposal['applicationHash']
            and consumption['generation']==evidence['generation'] and consumption['evidenceHash']==digest(evidence)
            and consumption['approvalHash']==evidence['approvalHash'],
            'EXACT_NEW_PROVIDER_STARTED_CONSUMPTION_REQUIRED')
        adapter_path=root/'adapter.json';adapter_raw=private_bytes(adapter_path);adapter=decode(adapter_raw)
        fields={'schema','containerId','configurationHash','state','runtimeRoot','bundleHash','driverHash'}
        initial=decode(material['files'][str(adapter_path)])
        require(type(adapter) is dict and set(adapter)==fields and adapter['schema']==initial['schema']
            and adapter['containerId']==cid and adapter['configurationHash']==initial['configurationHash']
            and adapter['state']=='STARTED' and adapter['bundleHash']==proposal['applicationHash']
            and adapter['driverHash']==consumption['driverHash'] and type(adapter['runtimeRoot']) is str
            and provider_templates.absolute(adapter['runtimeRoot'])
            and any(Path(adapter['runtimeRoot'])!=Path(p) and Path(adapter['runtimeRoot']).is_relative_to(p)
                for p in self.issuer.scope['runtimeRootParents']),
            'EXACT_OWNED_PROVIDER_STARTED_V4_ADAPTER_REQUIRED')
        require(all(private_bytes(paths[k])==v for k,v in raws.items()) and private_bytes(adapter_path)==adapter_raw,
            'MATERIALIZED_PROVIDER_ADMISSION_CHANGED_DURING_READ')
        window(mandate,clock());self.parent.guard('providerInstallation',self.creation.component)
        return {'schema':'ouf.discovery-current-materialized-provider-admission.v1','scopeHash':self.scope_hash,
            'recordsHash':digest({k:hashlib.sha256(v).hexdigest() for k,v in raws.items()}),
            'validatedEvidenceHash':digest(evidence),'consumptionHash':digest(consumption),'adapterHash':hashlib.sha256(adapter_raw).hexdigest(),
            'containerId':cid,'generation':evidence['generation'],'nativeObservationPerformedHere':False,
            'providerReadinessProven':False,'signaturesIssued':0,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
