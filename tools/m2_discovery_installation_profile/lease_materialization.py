"""Late initial worker materialization from current independently admitted peers.

The static worker component is reviewed before either new CID exists. This
owner waits for the signed Registry transport phase, owns one fresh logical
fence, captures/rechecks both real generations and retains the original clocks.
It then builds the existing issuer/files/registration/start phase. No signing,
manager command, DNS refresh, container operation or mutable ledger reset here.
"""
import copy,hashlib,os,re,socket,struct,time
from pathlib import Path
from .custody_capture import digest,encoded,decode,require
from .parent_authority import DiscoveryParentAuthority
from .node_owner import DiscoveryNodeOwner
from .provider_admission import RetainedProviderAdmission
from .provider_materialized_admission import MaterializedProviderAdmission
from .lease_installation_template import recompile,materialize,CAPSULE_SHA,CAPSULE_BYTES
from .lease_start_owner import LeaseStartAdapter,start_scope,PHASE
from .lease_file_installation import LeaseFileInstallation,compile_material,publication_scope,inode
from .lease_registration import LeaseRegistration,registered_component
from .lease_attestation import LeaseAttestationIssuer,attested_component,issuance_scope
from .lease_installation_phase import WorkerInstallationPhase,sequenced_component,sequence_scope
from .native_generation_probe import NativeLeaseGenerationProbe,DOCKER_FIELDS,generation_reference,ticks
from .installed_lease_guard import boot_id
from .installation_lock import observed_logical_inode
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,ancestors,private_bytes
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json,protected_file
from engine_creation import Engine
from transition_journal import PHASES

PROVIDERS=(RetainedProviderAdmission,MaterializedProviderAdmission)

def stable_native(value):
    return {k:value[k] for k in DOCKER_FIELDS}|{'RestartCount':value['RestartCount'],
        'State':{k:value['State'][k] for k in ('Pid','Running','Paused','Restarting','StartedAt')}}

class WorkerMaterialization:
    def __init__(self,*,node_owner,provider,signer,capsule,installation_sources=None):
        require(type(node_owner) is DiscoveryNodeOwner and type(provider) in PROVIDERS
            and type(provider.parent) is DiscoveryParentAuthority and type(signer) is ExistingEd25519Signer
            and type(signer.verifier) is DetachedAuthenticator,'TYPED_LATE_WORKER_ADMISSION_AND_SIGNER_REQUIRED')
        self.node,self.provider,self.signer=node_owner,provider,signer;self.parent=provider.parent
        self.template=recompile(provider.template);self.template_hash=digest(self.template)
        self.authority,self.authority_raw=node_owner.authority,bytes(node_owner.raw)
        self.transition,self.store=node_owner.transition,node_owner.store
        self.phase=PHASE;self.request_hash=digest(node_owner.request)
        self.component=copy.deepcopy(self.parent.review['components']['operationalLeaseInstallation'])
        require(self.component.get('schema')=='ouf.discovery-worker-sequenced-installation-scope.v1',
            'EXACT_REVIEWED_SEQUENCED_WORKER_COMPONENT_REQUIRED')
        att=self.component['component'];managed=att['installation'];files=managed['installation']
        self.start_scope=copy.deepcopy(files['start']);self.publication=files['publication']['journalDirectory']
        self.registration=copy.deepcopy(managed['registration']);self.issuance=copy.deepcopy(att['issuance'])
        self.sequence=copy.deepcopy(self.component['sequence']);self.root=Path(self.issuance['journalDirectory'])
        self.root_pin=inode(self.root);self.component_hash=digest(self.component);self.parent_hash=self.parent.sha
        self.intent={'creationRequestHash':self.request_hash,'nodeRecipeHash':digest(self.node.recipe),
            'leaseInstallationScopeHash':digest(self.start_scope),'priorEvidencePhase':'INSTALL_AUTHENTICATED_TRANSPORT'}
        self.intent_hash=digest(self.intent);self.capsule=bytes(capsule)
        self.extra=copy.deepcopy({} if installation_sources is None else installation_sources)
        require(type(capsule) is bytes and len(capsule)==CAPSULE_BYTES and hashlib.sha256(capsule).hexdigest()==CAPSULE_SHA
            and type(self.extra) is dict and all(type(k) is str and type(v) is bytes for k,v in self.extra.items())
            and sum(len(v) for v in self.extra.values())<=8388608,'EXACT_BOUNDED_WORKER_MATERIALIZATION_SOURCES_REQUIRED')
        self.probe=NativeLeaseGenerationProbe(self.issuance['observationRoot'])
        self.check_scope()
    def check_scope(self):
        require(type(self.node) is DiscoveryNodeOwner and type(self.provider) in PROVIDERS
            and self.provider.parent is self.parent and self.parent.sha==self.parent_hash
            and self.node.authority is self.authority and self.node.raw==self.authority_raw
            and self.node.transition is self.transition and self.node.store is self.store
            and digest(self.node.request)==self.request_hash and self.template==recompile(self.provider.template)
            and digest(self.template)==self.template_hash and digest(self.component)==self.component_hash,
            'LATE_WORKER_SCOPE_OR_OWNER_DRIFT')
        c=self.template['configurationTemplate'];r=self.node.recipe
        require(self.template['sourceClosureHash']==self.parent.scope['sourceClosureHash']
            and c['installationInputsHash']==self.parent.scope['installationInputsHash']
            and c['desiredProfileHash']==self.parent.scope['desiredProfileHash']
            and c['verification']['context']=={k:self.parent.context[k] for k in ('installationRef','entityRef','attestorRef')}
            and self.template['expectedNodeProfiles']['registry']=={'nodeRecipeHash':digest(r),
                'imageConfigurationHash':r['imageConfigurationHash'],'rootfsSealHash':digest(r['expectedRootfsSeal'])},
            'SAME_PARENT_TEMPLATE_AND_INDEPENDENT_REGISTRY_RECIPE_REQUIRED')
        if type(self.provider) is MaterializedProviderAdmission:
            creation=self.provider.creation
            require(self.node.engine is creation.engine and self.node.authority is creation.window.child
                and self.node.raw==creation.window.raw and self.node.recipe==self.provider.issuer.scope['registryRecipe'],
                'SAME_NEW_PROVIDER_AND_REGISTRY_INSTALLATION_REQUIRED')
        start=start_scope(self.template,unit_name=self.start_scope['unitName'],manager=self.start_scope['manager'],
            directory=self.start_scope['journalDirectory'])
        bare=publication_scope(self.template,start,self.publication)
        managed=registered_component(self.template,bare,self.registration)
        issuance=issuance_scope(self.template,self.provider.scope,directory=self.issuance['journalDirectory'],
            signature_directory=self.issuance['signatureDirectory'],observation_root=self.issuance['observationRoot'],
            key_binding=self.issuance['keyBinding'],key_ref=self.issuance['keyRef'])
        att=attested_component(self.template,managed,issuance)
        scope=sequence_scope(self.template,att,directory=self.sequence['journalDirectory'])
        require(self.start_scope==start and self.issuance==issuance and self.sequence==scope
            and self.component==sequenced_component(self.template,att,scope)
            and self.signer.key==issuance['keyBinding'] and self.signer.key_ref==issuance['keyRef']
            and self.signer.scope=={'role':'CREATION_ATTESTATION','issuerRef':self.parent.context['attestorRef'],
                'installationRef':self.parent.context['installationRef'],'entityRef':self.parent.context['entityRef']}
            and str(self.signer.verifier.signature_directory)==issuance['signatureDirectory'],
            'EXACT_REVIEWED_LATE_WORKER_PHASE_AND_ISOLATED_SIGNER_REQUIRED')
        with directory(self.root):require(inode(self.root)==self.root_pin,'WORKER_MATERIALIZATION_DIRECTORY_DRIFT')
    def current(self,intent):
        self.check_scope();require(intent==self.intent,'EXACT_SIGNED_LATE_WORKER_INTENT_REQUIRED')
        self.parent.registry_child(self.authority,self.authority_raw)
        self.parent.guard('operationalLeaseInstallation',self.component)
        row=self.transition.read();signed=decode(self.authority_raw);index=PHASES.index(PHASE)
        require(row['state']=='IN_FLIGHT' and row['nextPhase']==index and len(row['effects'])==index+1
            and row['creationRequestHash']==self.request_hash
            and row['transitionAuthorityEvidenceHash']==hashlib.sha256(self.authority_raw).hexdigest()
            and [e['phase'] for e in row['effects']]==list(PHASES[:index+1])
            and all(e['state']==('APPLIED' if n<index else 'IN_FLIGHT')
                and e['intentHash']==signed['phaseIntentHashes'][e['phase']]
                and e['authorityEvidenceHash']==row['transitionAuthorityEvidenceHash'] for n,e in enumerate(row['effects']))
            and signed['phaseIntentHashes'][PHASE]==self.intent_hash,'EXACT_LATE_WORKER_PHASE_AFTER_AUTHENTICATED_TRANSPORT_REQUIRED')
        return row
    def capture_native(self):
        """Only metadata/hashes; raw Config/Env never leave this local function."""
        engine=self.node.engine;require(type(engine) is Engine,'SAME_NATIVE_WORKER_ENGINE_REQUIRED')
        engine.check_socket();selected=Path(engine.path).resolve(strict=True)
        require(str(selected) in ('/run/docker.sock','/var/run/docker.sock'),'FIXED_LOCAL_WORKER_ENGINE_REQUIRED')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2);client.connect(str(selected))
            credentials=list(struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        require(credentials[0]>1 and credentials[1:]==[0,0],'ROOT_NATIVE_WORKER_ENGINE_PEER_REQUIRED')
        engine_ticks=ticks(credentials[0]);binding={'socketPath':str(selected),'socketBinding':list(engine.binding),
            'peerCredentials':credentials,'startTicks':engine_ticks}
        if type(self.provider) is MaterializedProviderAdmission:cid=self.provider.creation.owned_id()
        else:cid=decode(private_bytes(Path(self.provider.scope['records']['intent'])))['containerId']
        registry=self.node.engine.inspect(self.transition)
        status,provider=engine.request('GET','/v1.44/containers/'+cid+'/json')
        require(status==200 and provider['Id']==cid,'EXACT_WORKER_PROVIDER_OBSERVATION_REQUIRED')
        native={'registry':registry,'provider':provider};peers={}
        for role,value in native.items():
            s=value['State'];pid=s['Pid'];before=ticks(pid)
            require(value['Image']==self.template['expectedImages'][role] and value['RestartCount']==0
                and s['Running'] is True and s['Restarting'] is False
                and s['Paused'] is (role=='registry'),'CURRENT_PAUSED_REGISTRY_AND_RUNNING_PROVIDER_REQUIRED')
            ns=Path(value['NetworkSettings']['SandboxKey']).resolve(strict=True);ancestors(ns)
            require(ns.parent==Path('/run/docker/netns'),'CLOSED_DOCKER_WORKER_NAMESPACE_REQUIRED')
            info=ns.stat();process=Path('/proc')/str(pid)/'ns/net'
            require(info.st_uid==0 and (info.st_dev,info.st_ino)==(process.stat().st_dev,process.stat().st_ino)
                and before==ticks(pid),'SAME_WORKER_NATIVE_PROCESS_NAMESPACE_REQUIRED')
            peers[role]={'containerId':value['Id'],'imageId':value['Image'],'dockerBindingHash':digest({k:value[k] for k in DOCKER_FIELDS}),
                'pid':pid,'startedAt':s['StartedAt'],'startTicks':before,'namespace':{'path':str(ns),'identity':[info.st_dev,info.st_ino]},
                'allowedPausedStates':[False,True] if role=='registry' else [False]}
        if type(self.provider) is MaterializedProviderAdmission:app=self.provider.publication.material()['materialized']['applicationHash']
        else:app=decode(private_bytes(Path(self.provider.scope['records']['attestation'])))['applicationHash']
        profiles={role:{**self.template['expectedNodeProfiles'][role],'applicationHash':
            self.node.adapter.request['applicationHash'] if role=='registry' else app} for role in native}
        result={'schema':'ouf.discovery-lease-generation-observation.v1',
            'desiredProfileHash':self.template['configurationTemplate']['desiredProfileHash'],'profiles':profiles,
            'nativeProfileHash':digest(profiles),'bootId':boot_id('/proc/sys/kernel/random/boot_id'),
            'engineBinding':binding,'peers':peers}
        result['generationRef']=generation_reference(result)
        status,after=engine.request('GET','/v1.44/containers/'+cid+'/json')
        require(status==200 and stable_native(after)==stable_native(provider)
            and stable_native(engine.inspect(self.transition))==stable_native(registry)
            and ticks(credentials[0])==engine_ticks,'WORKER_CAPTURE_NATIVE_GENERATIONS_CHANGED')
        return result
    def snapshot(self,intent):
        row=self.current(intent);self.node.verify_retained();value=self.capture_native()
        # Pure materialization validates both independent node profiles/images;
        # the temporary inode is syntax only and is never published or adopted.
        materialize(self.template,value,[0,1,0,0,0o100600,1])
        self.provider.current(value);self.node.verify_retained()
        require(self.current(intent)==row and value['bootId']==boot_id('/proc/sys/kernel/random/boot_id'),
            'WORKER_ADMISSIONS_CHANGED_DURING_MATERIALIZATION')
        return value
    def claim(self,initial_time):
        return {'schema':'ouf.discovery-worker-materialization-claim.v1','componentHash':self.component_hash,
            'parentAuthorityHash':self.parent_hash,'childAuthorityHash':hashlib.sha256(self.authority_raw).hexdigest(),
            'templateHash':self.template_hash,'intentHash':self.intent_hash,'initialTime':list(initial_time),
            'capsuleHash':hashlib.sha256(self.capsule).hexdigest(),
            'installationSourceHashes':{k:hashlib.sha256(v).hexdigest() for k,v in self.extra.items()},
            'materializationAttempts':1,'automaticReplayAllowed':False,'budgetReset':False}
    def verify_generation(self,material):
        receipt=material['generation']
        require(self.probe(copy.deepcopy(receipt))=={k:receipt[k] for k in
            ('nativeObservationHash','nativeProfileHash','generationRef','bootId')},
            'EXACT_CURRENT_WORKER_MATERIALIZATION_GENERATION_REQUIRED')
    def prepare_once(self,intent):
        self.current(intent);claim=self.claim((time.time(),time.monotonic()));lock=Path(self.template['configurationTemplate']['commonInvocationLock'])
        with directory(self.root) as parent:new_file(parent,'materialization-claim.json',encoded(claim))
        self.current(intent)
        with directory(lock.parent) as parent:new_file(parent,lock.name,b'')
        lock_inode=inode(lock);value=self.snapshot(intent);path=self.probe.root/(digest(value)+'.json')
        with directory(path.parent) as parent:new_file(parent,path.name,encoded(value))
        proposal=materialize(self.template,value,lock_inode)
        material=compile_material(self.template,proposal,self.capsule,initial_time=claim['initialTime'],installation_sources=self.extra)
        self.verify_generation(material);self.provider.current(value);self.current(intent)
        owned={'schema':'ouf.discovery-worker-materialization-owned.v1','claimHash':digest(claim),
            'logicalLockIdentity':lock_inode,'snapshotHash':digest(value),'snapshotIdentity':inode(path),
            'proposalHash':digest(proposal),'materialSealHash':digest(material['seal'])}
        with observed_logical_inode(lock,lock_inode),directory(self.root) as parent:
            require(private_json(self.root/'materialization-claim.json')==claim,'WORKER_MATERIALIZATION_CLAIM_DRIFT')
            new_file(parent,'materialization-owned.json',encoded(owned))
        return self.prepared(intent)
    def prepared(self,intent):
        self.current(intent)
        if not os.path.lexists(self.root/'materialization-owned.json'):return None
        claim=private_json(self.root/'materialization-claim.json');require(claim==self.claim(claim['initialTime']),
            'EXACT_RETAINED_WORKER_MATERIALIZATION_CLAIM_REQUIRED')
        owned=private_json(self.root/'materialization-owned.json')
        require(set(owned)=={'schema','claimHash','logicalLockIdentity','snapshotHash','snapshotIdentity','proposalHash','materialSealHash'}
            and owned['schema']=='ouf.discovery-worker-materialization-owned.v1' and owned['claimHash']==digest(claim)
            and all(type(owned[k]) is str and re.fullmatch('[0-9a-f]{64}',owned[k])
                for k in ('snapshotHash','proposalHash','materialSealHash')),
            'EXACT_OWNED_WORKER_MATERIALIZATION_REQUIRED')
        path=self.probe.root/(owned['snapshotHash']+'.json')
        value=decode(protected_file(path,1048576,expected=owned['snapshotHash'],modes=(0o600,)))
        require(inode(path)==owned['snapshotIdentity'],'OWNED_WORKER_MATERIALIZATION_SNAPSHOT_INODE_DRIFT')
        lock=self.template['configurationTemplate']['commonInvocationLock']
        with observed_logical_inode(lock,owned['logicalLockIdentity']):
            proposal=materialize(self.template,value,owned['logicalLockIdentity'])
            material=compile_material(self.template,proposal,self.capsule,initial_time=claim['initialTime'],installation_sources=self.extra)
            require(digest(proposal)==owned['proposalHash'] and digest(material['seal'])==owned['materialSealHash'],
                'EXACT_RETAINED_WORKER_MATERIAL_AND_ORIGINAL_CLOCKS_REQUIRED')
        self.node.verify_retained();self.provider.current(value);self.verify_generation(material);self.current(intent)
        start=LeaseStartAdapter(parent=self.parent,authority=self.authority,authority_raw=self.authority_raw,
            transition=self.transition,store=self.store,node_owner=self.node,template=self.template,proposal=proposal,
            scope=self.start_scope,intent=intent,publication_directory=self.publication,
            attestation_scope=self.issuance,registration_scope=self.registration,sequence_scope=self.sequence)
        files=LeaseFileInstallation(start,material,verifier=self.signer.verifier,probe=self.probe)
        issuer=LeaseAttestationIssuer(installation=files,provider=self.provider,signer=self.signer)
        return WorkerInstallationPhase(issuer=issuer,registration=LeaseRegistration(files))
    def apply(self,intent):self.prepare_once(intent).apply(intent)
    def continue_installation(self,intent):
        phase=self.prepared(intent);require(phase is not None,'COMPLETE_WORKER_MATERIALIZATION_REQUIRED_NO_REPREPARATION')
        return phase.continue_installation(intent)
    def observe(self,intent):
        phase=self.prepared(intent)
        if phase is None:return 'UNKNOWN',{'materializationIncomplete':True,'automaticReplayAllowed':False,'budgetReset':False}
        return phase.observe(intent)
