"""Owned kernel transport phase for an already attested paused discovery workload.

The current full cutover authorizes this phase, never a captured historical
driver. Expected nft footprint is compiled in a separate namespace. Recovery
only reads kernel state and commits its existing owned journal; no apply replay.
"""
import copy,hashlib,json,os
from pathlib import Path
from transition_journal import digest,require
from cutover_authority import CutoverAuthority
from native_evidence_store import NativeEvidenceStore
from tools.m2_discovery_installation_profile.node_owner import DiscoveryNodeOwner
from tools.m2_discovery_installation_profile.transport_template import isolated_footprint,Budget
from tools.semantic_provider_deployment_authentication import private_bytes,decode,ancestors
from tools.semantic_provider_installer_approval import publish_once
from tools.semantic_provider_deployment_producer import program
from tools.semantic_provider_lease_coordination import Coordinator,PrivateJournal
from tools.semantic_provider_preexec import Preexec
from tools.semantic_provider_preexec_native import NativeBackend
from .engine_transport_backend import EngineTransportBackend

PHASE='INSTALL_AUTHENTICATED_TRANSPORT'
FILES=('claim.json','profile.json','template.json','profile-seal.json','preexec-journal.json')
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


class TransportInstallationAdapter:
    def __init__(self,*,transition,store,authority,authority_raw,node_owner,coordinator,recipe,directory,intent):
        require(type(store) is NativeEvidenceStore and type(authority) is CutoverAuthority
            and authority.execution_profile is None and type(node_owner) is DiscoveryNodeOwner
            and node_owner.transition is transition and node_owner.store is store
            and node_owner.authority is authority and node_owner.raw==authority_raw
            and type(coordinator) is Coordinator and coordinator.owner.configuration==coordinator.configuration,'SHARED_NATIVE_DISCOVERY_TRANSPORT_OWNERS_REQUIRED')
        fields={'schema','sourceClosureHash','nodeRecipeHash','coordinatorBindingHash','leaseConfigurationHash',
            'leaseStructureHash','commands','nativeBudgetSeconds','isolationSeconds'}
        require(type(recipe) is dict and set(recipe)==fields
            and recipe['schema']=='ouf.semantic-discovery-transport-recipe.v1'
            and recipe['sourceClosureHash']==authority.expected['sourceClosureHash']
            and recipe['nodeRecipeHash']==digest(node_owner.recipe)
            and recipe['coordinatorBindingHash']==digest(coordinator.binding)
            and recipe['leaseConfigurationHash']==digest(coordinator.configuration)
            and recipe['leaseStructureHash']==coordinator.owner.backend.expected
            and type(recipe['commands']) is dict and set(recipe['commands'])=={'ip','nsenter','nft'}
            and all(recipe['commands'][k]==node_owner.recipe['observationConfiguration']['commands'][k] for k in ('ip','nsenter'))
            and type(recipe['nativeBudgetSeconds']) is int and 1<=recipe['nativeBudgetSeconds']<=5
            and type(recipe['isolationSeconds']) is int and 1<=recipe['isolationSeconds']<=30,
            'EXACT_INDEPENDENT_DISCOVERY_TRANSPORT_RECIPE_REQUIRED')
        request_hash=digest(node_owner.request)
        require(intent=={'creationRequestHash':request_hash,'nodeRecipeHash':recipe['nodeRecipeHash'],
            'transportRecipeHash':digest(recipe),'priorEvidencePhase':'ATTEST_NEW_OCI_PEER'}
            and decode(authority_raw,131072)['phaseIntentHashes'][PHASE]==digest(intent),
            'SIGNED_DISCOVERY_TRANSPORT_RECIPE_REQUIRED')
        self.phase,self.transition,self.store,self.authority,self.authority_raw=PHASE,transition,store,authority,authority_raw
        self.node_owner,self.coordinator=node_owner,coordinator
        self.recipe,self.intent=copy.deepcopy(recipe),copy.deepcopy(intent)
        self.recipe_hash,self.intent_hash,self.request_hash=digest(recipe),digest(intent),request_hash
        self.raw_hash=hashlib.sha256(authority_raw).hexdigest()
        self.root=Path(directory);ancestors(self.root/'placeholder');s=self.root.lstat()
        require(self.root.is_dir() and s.st_uid==s.st_gid==0 and s.st_mode&0o777==0o700
            and self.root!=node_owner.root and not self.root.is_relative_to(node_owner.root)
            and not node_owner.root.is_relative_to(self.root),'SEPARATE_PRIVATE_TRANSPORT_DIRECTORY_REQUIRED')
        self.directory_binding=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)

    def current(self,intent):
        s=self.root.lstat()
        require(type(self.node_owner) is DiscoveryNodeOwner and type(self.coordinator) is Coordinator
            and self.node_owner.authority is self.authority and self.node_owner.raw==self.authority_raw
            and self.node_owner.transition is self.transition and self.node_owner.store is self.store
            and self.coordinator.owner.configuration==self.coordinator.configuration
            and (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)==self.directory_binding
            and digest(self.recipe)==self.recipe_hash and digest(intent)==digest(self.intent)==self.intent_hash
            and digest(self.node_owner.request)==self.request_hash
            and digest(self.node_owner.recipe)==self.recipe['nodeRecipeHash']
            and digest(self.coordinator.binding)==self.recipe['coordinatorBindingHash']
            and digest(self.coordinator.configuration)==self.recipe['leaseConfigurationHash']
            and self.coordinator.owner.backend.expected==self.recipe['leaseStructureHash']
            and hashlib.sha256(self.authority_raw).hexdigest()==self.raw_hash
            and self.authority(self.authority_raw) is True,'CURRENT_DISCOVERY_TRANSPORT_SCOPE_REQUIRED')
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==PHASE
            and row['effects'][-1]['intentHash']==self.intent_hash
            and row['creationRequestHash']==self.request_hash,'DURABLE_DISCOVERY_TRANSPORT_BOUNDARY_REQUIRED')
        return row

    def native_base(self,intent):
        self.current(intent);proof=self.node_owner.verify_retained()
        observer=self.node_owner.adapter.observer
        profile=copy.deepcopy(observer.transport_profile);generation=copy.deepcopy(observer.transport_generation)
        require(profile['policy']['schema']=='ouf.semantic-shared-faces.v2'
            and profile['bundleHash']==self.node_owner.adapter.request['applicationHash']
            and profile['applicationStartAuthorized'] is False and profile['infrastructureAuthorityComplete'] is False
            and profile['expectedFootprint']=='0'*64
            and profile['namespaceInode']==generation['namespaceInode'],
            'CURRENT_ATTESTED_DISCOVERY_TRANSPORT_WITH_FINITE_LEASE_GUARD_REQUIRED')
        require(NativeBackend.generation(None,generation['pid'])==generation,'CURRENT_TRANSPORT_PROCESS_GENERATION_REQUIRED')
        self.current(intent);return profile,generation,proof

    def backend(self,profile):
        budget=Budget(self.recipe['nativeBudgetSeconds'])
        paths={key:program(value,budget) for key,value in self.recipe['commands'].items()}
        node=self.node_owner;generation=node.adapter.observer.transport_generation
        actual=node.engine.matching_configuration(self.transition,node.request,node.engine.inspect(self.transition))
        require(actual['Id']==profile['containerId'] and actual['State']['Pid']==generation['pid']
            and actual['State']['Running'] is True and actual['State']['Paused'] is True,
            'SAME_PAUSED_DISCOVERY_DOCKER_NAMESPACE_REFERENCE_REQUIRED')
        return EngineTransportBackend(profile,paths,self.recipe['nativeBudgetSeconds'],
            bundle_parent=node.recipe['dockerContext']['bundleParent'],
            namespace_reference=actual['NetworkSettings']['SandboxKey'],generation=generation)

    def prepared(self,intent,base):
        values={name:decode(private_bytes(self.root/name,131072),131072) for name in FILES}
        claim,profile,template,seal=(values[n] for n in FILES[:4])
        require(claim=={'schema':'ouf.discovery-transport-phase-claim.v1','transitionContextHash':self.transition.context,
                'intentHash':self.intent_hash,'authorityHash':self.raw_hash,'recipeHash':self.recipe_hash}
            and seal=={'schema':'ouf.discovery-transport-profile-seal.v1','profileHash':digest(profile),
                'templateHash':digest(template),'phaseClaimHash':digest(claim)}
            and template['profileHash']==digest({**profile,'expectedFootprint':'0'*64})
            and template['footprint']==profile['expectedFootprint']
            and template['isolated'] is True and template['hostRulesChanged'] is False,
            'EXACT_PREPARED_DISCOVERY_TRANSPORT_PROFILE_REQUIRED')
        descriptive={**profile,'expectedFootprint':'0'*64,'infrastructureAuthorityComplete':False}
        require(descriptive==base and profile['applicationStartAuthorized'] is False,
            'TRANSPORT_PROFILE_OUTSIDE_ATTESTED_NODE_RECIPE')
        return profile,template,values['preexec-journal.json']

    def apply(self,intent):
        base,generation,proof=self.native_base(intent)
        require(not any(os.path.lexists(self.root/name) for name in FILES),'TRANSPORT_PREPARATION_OR_APPLY_ALREADY_ATTEMPTED')
        claim={'schema':'ouf.discovery-transport-phase-claim.v1','transitionContextHash':self.transition.context,
            'intentHash':self.intent_hash,'authorityHash':self.raw_hash,'recipeHash':self.recipe_hash}
        publish_once(self.root/'claim.json',encoded(claim),'DISCOVERY_TRANSPORT_CLAIM_ALREADY_PRESENT')
        profile={**base,'infrastructureAuthorityComplete':True}
        from tools.semantic_provider_deployment_admission import mirrors
        indexes={f['peerIngress']['ifindex'] for f in profile['policy']['flows'] if f['peerIngress']['kind']!='HOST'}
        hosts=[{'ifindex':i,'ifname':__import__('socket').if_indextoname(i)} for i in indexes]
        links=mirrors(profile,hosts)
        template=isolated_footprint(profile,links,{k:self.recipe['commands'][k] for k in ('ip','nft')},
            seconds=self.recipe['isolationSeconds'])
        profile['expectedFootprint']=template['footprint']
        self.current(intent)
        require(NativeBackend.generation(None,generation['pid'])==generation,'TRANSPORT_GENERATION_CHANGED_BEFORE_INSTALLATION')
        publish_once(self.root/'profile.json',encoded(profile),'DISCOVERY_TRANSPORT_PROFILE_ALREADY_PRESENT')
        publish_once(self.root/'template.json',encoded(template),'DISCOVERY_TRANSPORT_TEMPLATE_ALREADY_PRESENT')
        publish_once(self.root/'profile-seal.json',encoded({'schema':'ouf.discovery-transport-profile-seal.v1',
            'profileHash':digest(profile),'templateHash':digest(template),'phaseClaimHash':digest(claim)}),
            'DISCOVERY_TRANSPORT_PROFILE_SEAL_ALREADY_PRESENT')
        initial={'schema':'ouf.semantic-preexec-journal.v1','transactionId':profile['transactionId'],
            'configurationHash':digest(profile),'state':'STAGED','sharedStructureHash':None,'containerGeneration':None}
        publish_once(self.root/'preexec-journal.json',encoded(initial),'DISCOVERY_TRANSPORT_JOURNAL_ALREADY_PRESENT')
        owner=Preexec(profile,self.backend(profile),self.coordinator,PrivateJournal(self.root/'preexec-journal.json'))
        def authorize():
            self.current(intent)
            require(NativeBackend.generation(None,generation['pid'])==generation,'CURRENT_TRANSPORT_PROCESS_GENERATION_REQUIRED')
        owner.operate('apply',authorizer=authorize)

    def observe(self,intent):
        base,generation,proof=self.native_base(intent)
        if not all(os.path.lexists(self.root/name) for name in FILES):
            return 'UNKNOWN',{'transportPreparationIncomplete':True,'applyReplayAllowed':False}
        profile,template,_=self.prepared(intent,base)
        owner=Preexec(profile,self.backend(profile),self.coordinator,PrivateJournal(self.root/'preexec-journal.json'))
        with self.coordinator.hold_lock():
            self.current(intent);owner.quiesced();value=owner.record()
            require(value['containerGeneration'] is None,'TRANSPORT_OWNER_MUST_NOT_GRANT_PROCESS_START')
            owner.backend.bindings(profile,None);tables=owner.backend.tables()
            if value['state']=='STAGED' and tables is None:
                return 'NO_EFFECT',{'ownedTransportEffectAbsent':True,'applyReplayAllowed':False}
            if tables is None:
                return 'UNKNOWN',{'transportKernelEffectUnproven':True,'applyReplayAllowed':False}
            require(value['state'] in ('INSTALLING','PROTECTED')
                and owner.backend.footprint(tables)==profile['expectedFootprint'],
                'OWNED_DISCOVERY_TRANSPORT_TEMPLATE_OR_JOURNAL_DRIFT')
            structure=owner.backend.structure_hash(tables)
            require(value['sharedStructureHash'] in (None,structure),'DISCOVERY_TRANSPORT_STRUCTURE_DRIFT')
            if value['state']=='INSTALLING':
                # Native write already observed: commit only this owned journal.
                # Never call operate(reconcile), which may recreate missing tables.
                pending={**value,'state':'PROTECTED','sharedStructureHash':structure}
                owner.publish(value,pending);value=pending
            owner.verified(value)
            require(NativeBackend.generation(None,generation['pid'])==generation,
                'TRANSPORT_GENERATION_CHANGED_DURING_RECONCILIATION')
        self.current(intent)
        evidence={'schema':'ouf.discovery-authenticated-transport-installed.v1',
            'transitionContextHash':self.transition.context,'intentHash':self.intent_hash,
            'creationRequestHash':self.request_hash,'profileHash':digest(profile),'templateHash':digest(template),
            'generation':generation,'nodeProofHash':digest(proof),'sharedStructureHash':structure,
            'expectedFootprint':profile['expectedFootprint'],'leaseConfigurationHash':self.recipe['leaseConfigurationHash'],
            'applyReplayAllowed':False,'applicationStartAuthorized':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence
