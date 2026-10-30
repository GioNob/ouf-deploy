"""One reviewed named-runtime wrapper CAS and one provider start attempt.

Reuse the existing guarded switch primitive and v4 broker/attestor/consumption.
No daemon reload, old candidate start, key generation, direct runc start,
configuration overwrite or automatic mutation replay. Uncertain starts are read.
"""
import copy,hashlib,os,stat
from pathlib import Path
from .custody_capture import digest,encoded,decode,require
from .provider_profile_publication import ProviderProfilePublication
from .provider_materialized_admission import MaterializedProviderAdmission
from .provider_creation import ProviderCreation
from .provider_profiles import ProviderInitialIssuer
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json
from tools.semantic_provider_lease_coordination import Coordinator,PrivateJournal,hold_common_lock
from tools.semantic_provider_lease_owner import LeaseOwner
from tools.semantic_provider_lease_nft import NftBackend
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_producer import program
from tools.m2_discovery_installation_profile.transport_template import Budget
from guarded_runtime_switch import switch_existing_wrapper,custody,wrapper_bytes

WRAPPER_DIRECTORIES=frozenset(('/usr/local/sbin',))

def host_namespace():return os.stat('/proc/self/ns/net').st_ino
def process_namespace(pid):return os.stat('/proc/'+str(pid)+'/ns/net')
def runtime_scope(profile_scope,*,wrapper_binding,common_lock_identity,native_read_seconds=5):
    require(type(profile_scope) is dict and profile_scope.get('schema')=='ouf.discovery-provider-profile-installation-scope.v1',
        'EXACT_PROVIDER_PROFILE_SCOPE_REQUIRED_BEFORE_RUNTIME_INSTALLATION')
    require(type(wrapper_binding) is dict and set(wrapper_binding)=={'path','sha256'}
        and Path(wrapper_binding['path']).parent.as_posix() in WRAPPER_DIRECTORIES
        and Path(wrapper_binding['path']).name.startswith('ouf-')
        and type(wrapper_binding['sha256']) is str and len(wrapper_binding['sha256'])==64
        and set(wrapper_binding['sha256'])<=set('0123456789abcdef'),
        'EXPLICIT_ROOT_NAMED_RUNTIME_WRAPPER_BINDING_REQUIRED')
    require(type(common_lock_identity) is list and len(common_lock_identity)==9
        and all(type(v) is int and v>=0 for v in common_lock_identity)
        and common_lock_identity[2:7]==[0,0,0o100600,1,0]
        and type(native_read_seconds) is int and 1<=native_read_seconds<=30,
        'EXACT_EXISTING_PROVIDER_NATIVE_LOCK_AND_BOUNDED_READ_REQUIRED')
    return {'schema':'ouf.discovery-provider-runtime-installation-scope.v1','profiles':copy.deepcopy(profile_scope),
        'wrapperBinding':copy.deepcopy(wrapper_binding),'commonLockIdentity':copy.deepcopy(common_lock_identity),
        'nativeReadSeconds':native_read_seconds,'maximumWrapperSwitches':1,'maximumProviderStartAttempts':1,
        'daemonReloadOrRestartAuthorized':False,'historicalCandidateMutationAuthorized':False,'automaticReplayAllowed':False}

class ProviderRuntimeInstallation:
    def __init__(self,*,publication,admission,scope,coordinator):
        require(type(publication) is ProviderProfilePublication and type(publication.issuer) is ProviderInitialIssuer
            and type(admission) is MaterializedProviderAdmission and admission.publication is publication
            and type(coordinator) is Coordinator and type(coordinator.owner) is LeaseOwner
            and type(coordinator.owner.backend) is NftBackend,
            'SHARED_TYPED_PROVIDER_PUBLICATION_ADMISSION_AND_NATIVE_COORDINATOR_REQUIRED')
        self.publication,self.admission,self.coordinator=publication,admission,coordinator
        self.issuer=publication.issuer;self.creation=self.issuer.creation;self.parent=self.creation.parent
        self.scope=copy.deepcopy(scope);self.scope_hash=digest(scope);self.root=publication.root
        self.check_scope()
    def check_scope(self):
        require(type(self.publication) is ProviderProfilePublication and self.publication.issuer is self.issuer
            and self.issuer.creation is self.creation and self.creation.parent is self.parent
            and self.admission.publication is self.publication and self.admission.creation is self.creation
            and self.scope==runtime_scope(self.issuer.scope,wrapper_binding=self.scope['wrapperBinding'],
                common_lock_identity=self.scope['commonLockIdentity'],native_read_seconds=self.scope['nativeReadSeconds'])
            and digest(self.scope)==self.scope_hash and self.creation.component['installation']==self.scope,
            'EXACT_PARENT_REVIEWED_PROVIDER_RUNTIME_INSTALLATION_REQUIRED')
        self.issuer.check_scope();self.parent.guard('providerInstallation',self.creation.component)
        prep=self.issuer.scope['preparerTemplate'];c=self.coordinator
        require(type(c) is Coordinator and type(c.owner) is LeaseOwner and type(c.owner.backend) is NftBackend
            and c.configuration==c.owner.configuration==prep['kernel'] and c.dns_profile==c.owner.profile==prep['dns']
            and c.binding==prep['coordinationBinding'] and c.owner.backend.expected==c.binding['leaseStructureHash']
            and c.owner.backend.command==[prep['commands']['nft']] and c.owner.backend.budget==self.scope['nativeReadSeconds']
            and type(getattr(c.read,'__self__',None)) is PrivateJournal
            and c.read.__func__ is PrivateJournal.read and c.read.__self__.path==Path(prep['coordinationJournal'])
            and getattr(c.write,'__self__',None) is c.read.__self__ and c.write.__func__ is PrivateJournal.write,
            'SAME_SEALED_PROVIDER_NATIVE_CONFIGURATION_JOURNAL_AND_BACKEND_REQUIRED')
    def proposal(self):
        self.check_scope();material=self.publication.material()
        configuration=str(self.root/'runtime-configuration.json')
        return material,wrapper_bytes(self.issuer.scope['pythonBinding']['path'],self.issuer.scope['sourceRoot'],configuration)
    def native_configuration(self):
        self.check_scope();status,info=self.creation.engine.request('GET','/v1.44/info')
        require(status==200 and type(info) is dict and info.get('ServerVersion')=='29.8.1'
            and info.get('Driver')=='overlayfs' and info.get('CgroupDriver')=='systemd',
            'QUALIFIED_PROVIDER_RUNTIME_ENGINE_REQUIRED')
        name=self.creation.template['creationRequest']['HostConfig']['Runtime']
        registered=info.get('Runtimes',{}).get(name)
        require(type(registered) is dict and registered.get('path')==self.scope['wrapperBinding']['path']
            and registered.get('runtimeArgs') in (None,[]),'EXACT_SELECTED_NAMED_PROVIDER_RUNTIME_REQUIRED')
        return digest(registered)
    def native_guard_locked(self,fd):
        self.check_scope();self.creation.current()
        require(self.publication.observe(initial=True)[0]=='APPLIED','EXACT_INITIAL_PROVIDER_PROFILES_BEFORE_NATIVE_DISPATCH_REQUIRED')
        prep=self.issuer.scope['preparerTemplate'];lock=prep['lockFile']
        raw,identity=custody(lock,0o600)
        require(raw==b'' and list(identity)==self.scope['commonLockIdentity']
            and (os.fstat(fd).st_dev,os.fstat(fd).st_ino)==tuple(identity[:2]),
            'SAME_HELD_PROVIDER_NATIVE_LOCK_REQUIRED')
        require(host_namespace()==prep['hostNetworkNamespace'],'PROVIDER_NATIVE_HOST_NAMESPACE_DRIFT')
        budget=Budget(self.scope['nativeReadSeconds'])
        for name,path in prep['commands'].items():program({'path':path,'sha256':prep['commandHashes'][name]},budget)
        program(self.creation.template['runtimeBinding'],budget);program(self.issuer.scope['pythonBinding'],budget)
        before=self.coordinator.journal();sets=self.coordinator.sets()
        require(before['state']=='QUIESCED' and before['leaseAuthorized'] is False and before['startAuthorized'] is False
            and all(not v for v in before['leaseAddresses']) and all(not v for v in sets)
            and self.coordinator.journal()==before,'CURRENT_QUIESCED_PROVIDER_NATIVE_GUARD_REQUIRED')
        self.native_configuration();self.creation.current()
    def switch_once(self):
        material,proposed=self.proposal();self.creation.current();self.native_configuration()
        prior=self.scope['wrapperBinding'];expected=wrapper_bytes(self.issuer.scope['pythonBinding']['path'],
            self.issuer.scope['sourceRoot'],self.issuer.scope['priorRuntimeConfigurationBinding']['path'])
        require(custody(prior['path'],0o755)[0]==expected
            and hashlib.sha256(expected).hexdigest()==prior['sha256'],'EXACT_CURRENT_PROVIDER_WRAPPER_CONFIGURATION_REQUIRED')
        return switch_existing_wrapper(prior['path'],prior['sha256'],proposed,self.root,
            self.issuer.scope['preparerTemplate']['lockFile'],self.scope['commonLockIdentity'],
            lambda fd,phase:self.native_guard_locked(fd))
    def observe_switch(self):
        material,proposed=self.proposal();self.native_configuration()
        path=self.root/'runtime-switch-claim.json'
        if not os.path.lexists(path):return 'UNKNOWN',{'ownedSwitchClaimPresent':False,'automaticReplayAllowed':False}
        claim=private_json(path)
        require(claim=={'schema':'ouf.semantic-provider-runtime-switch-claim.v1','state':'SWITCHING',
            'priorWrapperHash':self.scope['wrapperBinding']['sha256'],'proposedWrapperHash':hashlib.sha256(proposed).hexdigest(),
            'containerLifecycleOperations':0,'notReleaseAcceptance':True},'EXACT_RETAINED_PROVIDER_WRAPPER_SWITCH_REQUIRED')
        prior=custody(self.root/'prior-runtime-wrapper.sh',0o600)[0]
        require(hashlib.sha256(prior).hexdigest()==self.scope['wrapperBinding']['sha256'],'PROVIDER_PRIOR_WRAPPER_BACKUP_DRIFT')
        actual,identity=custody(self.scope['wrapperBinding']['path'],0o755)
        if actual!=proposed:return 'UNKNOWN',{'ownedSwitchClaimPresent':True,'installedWrapperUnproven':True,'automaticReplayAllowed':False}
        return 'APPLIED',{'schema':'ouf.discovery-provider-runtime-wrapper-switched.v1','scopeHash':self.scope_hash,
            'claimHash':digest(claim),'installedWrapperHash':hashlib.sha256(actual).hexdigest(),
            'daemonReloadOrRestartPerformed':False,'providerStartPerformed':False,'automaticReplayAllowed':False}
    def start_claim(self):
        row=self.creation.retained()
        return {'schema':'ouf.discovery-provider-start-claim.v1','scopeHash':self.scope_hash,
            'parentAuthorityHash':self.parent.sha,'containerId':self.creation.owned_id(),
            'creationEvidenceHash':row['nativeCreatedEvidenceHash'],'registryWindowHash':row['windowHash'],
            'startAttempts':1,'automaticReplayAllowed':False}
    def start_once(self):
        self.check_scope();self.creation.current()
        require(self.observe_switch()[0]=='APPLIED' and self.creation.observe()[0]=='APPLIED',
            'CURRENT_OWNED_PROVIDER_SWITCH_AND_UNSTARTED_CANDIDATE_REQUIRED')
        prep=self.issuer.scope['preparerTemplate'];claim=self.start_claim()
        # The old common native inode is held only for the guard/claim, never
        # over Docker: the broker/preparer/driver must acquire it themselves.
        with hold_common_lock(Path(prep['lockFile'])):
            fd=os.open(prep['lockFile'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:self.native_guard_locked(fd)
            finally:os.close(fd)
            with directory(self.root) as journal:new_file(journal,'provider-start-claim.json',encoded(claim))
        self.creation.current();require(self.creation.observe()[0]=='APPLIED' and self.observe_switch()[0]=='APPLIED',
            'PROVIDER_START_BOUNDARY_CHANGED_BEFORE_DISPATCH')
        with directory(self.root) as journal:new_file(journal,'provider-start-dispatch.json',encoded(claim))
        self.creation.current();require(private_json(self.root/'provider-start-claim.json')==claim
            and private_json(self.root/'provider-start-dispatch.json')==claim,'PROVIDER_START_DISPATCH_DRIFT')
        status,_=self.creation.engine.request('POST','/v1.44/containers/'+claim['containerId']+'/start')
        require(status==204,'PROVIDER_START_OUTCOME_REQUIRES_RECONCILIATION')
    def observe_started(self):
        self.check_scope()
        if not os.path.lexists(self.root/'provider-start-claim.json'):
            return 'UNKNOWN',{'ownedStartClaimPresent':False,'automaticReplayAllowed':False}
        claim=self.start_claim()
        require(private_json(self.root/'provider-start-claim.json')==claim,'EXACT_RETAINED_PROVIDER_START_CLAIM_REQUIRED')
        if not os.path.lexists(self.root/'provider-start-dispatch.json'):
            return 'UNKNOWN',{'ownedStartClaimPresent':True,'startDispatchUnproven':True,'automaticReplayAllowed':False}
        require(private_json(self.root/'provider-start-dispatch.json')==claim and self.observe_switch()[0]=='APPLIED',
            'EXACT_PROVIDER_START_DISPATCH_AND_WRAPPER_REQUIRED')
        cid=claim['containerId'];status,actual=self.creation.engine.request('GET','/v1.44/containers/'+cid+'/json')
        if status!=200:return 'UNKNOWN',{'ownedStartClaimPresent':True,'providerRunningUnproven':True,'automaticReplayAllowed':False}
        require(type(actual) is dict,'EXACT_PROVIDER_RUNNING_NATIVE_OBJECT_REQUIRED')
        # Shared Engine consistency compares the full declared request, with
        # only its already qualified Moby started OOM default normalization.
        from engine_creation import Engine
        Engine.matching_configuration(self.creation.engine,self.creation.naming,self.creation.template['creationRequest'],actual)
        state=actual['State']
        if state.get('Running') is not True or state.get('Paused') is not False or state.get('Restarting') is not False:
            return 'UNKNOWN',{'ownedStartClaimPresent':True,'providerRunningUnproven':True,'automaticReplayAllowed':False}
        require(actual['Id']==cid and type(state.get('Pid')) is int and state['Pid']>1,'EXACT_RUNNING_OWNED_PROVIDER_REQUIRED')
        generation=NativeBackend.generation(None,state['Pid'])
        namespace=process_namespace(state['Pid'])
        material=self.publication.material();snapshot={'desiredProfileHash':self.admission.template['configurationTemplate']['desiredProfileHash'],
            'profiles':{'provider':{**self.admission.template['expectedNodeProfiles']['provider'],
                'applicationHash':material['materialized']['applicationHash']}},
            'peers':{'provider':{'containerId':cid,'imageId':actual['Image'],'pid':state['Pid'],
                'startTicks':generation['startTicks'],'namespace':{'identity':[namespace.st_dev,namespace.st_ino]}}}}
        proof=self.admission.current(snapshot)
        status,after=self.creation.engine.request('GET','/v1.44/containers/'+cid+'/json')
        require(status==200 and after==actual and NativeBackend.generation(None,state['Pid'])==generation,
            'PROVIDER_CHANGED_DURING_STARTED_ADMISSION_READ')
        return 'APPLIED',{'schema':'ouf.discovery-provider-started-and-admitted.v1','scopeHash':self.scope_hash,
            'containerId':cid,'generation':generation,'admissionHash':digest(proof),'claimHash':digest(claim),
            'applicationReadinessProven':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}
