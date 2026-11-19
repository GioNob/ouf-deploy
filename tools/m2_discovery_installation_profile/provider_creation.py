"""One new provider Engine create, only inside the owned Registry gate window.

No provider start, signer, broker install, old-provider mutation or automatic
retry. A lost create response is reconciled by the exact source-owned name and
request; absence is UNKNOWN. Creation does not admit the OCI or its application.
"""
import copy,os,re,types
from pathlib import Path
from .custody_capture import digest,encoded,require
from .parent_authority import DiscoveryParentAuthority
from .gate_peer_window import GatePeerWindow
from . import provider_installation_template as templates
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json
from engine_creation import Engine
from recovery_journal import Journal

ROW_FIELDS={'schema','scopeHash','parentAuthorityHash','creationRequestHash','windowHash',
    'registryRuntimeBinding','registryGeneration','state','version','containerId','nativeCreatedEvidenceHash'}
PROVIDER_STAGES=('CREATE','ISSUE','PUBLISH','SWITCH','START')

def provider_sequence_scope(creation,installation,admission,*,journal_directory):
    root=templates.absolute(str(journal_directory))
    require(type(creation) is dict and creation.get('schema')=='ouf.discovery-provider-creation-scope.v1'
        and type(installation) is dict and installation.get('schema')=='ouf.discovery-provider-runtime-installation-scope.v1'
        and type(admission) is dict and admission.get('schema')=='ouf.discovery-materialized-provider-admission-scope.v1'
        and installation['profiles']['creationScopeHash']==admission['creationScopeHash']==digest(creation)
        and admission['profileScopeHash']==digest(installation['profiles'])
        and len(Path(root).parts)>=4,'EXACT_PROVIDER_SEQUENCE_COMPONENTS_REQUIRED')
    roots=(creation['journalDirectory'],installation['profiles']['journalDirectory'],installation['profiles']['registryRoot'])
    require(all(not Path(root).is_relative_to(p) and not Path(p).is_relative_to(root) for p in roots),
        'DISTINCT_PROVIDER_SEQUENCE_JOURNAL_REQUIRED')
    return {'schema':'ouf.discovery-provider-installation-sequence-scope.v1',
        'creationScopeHash':digest(creation),'installationScopeHash':digest(installation),'admissionScopeHash':digest(admission),
        'journalDirectory':root,'stages':list(PROVIDER_STAGES),'maximumDispatchesPerStage':1,
        'observationPolicy':{'schema':'ouf.discovery-gate-window-reconciliation-policy.v1',
            'maximumObservationsPerStage':3,'delaysSeconds':[0,1,3],'jitterFraction':0.2,
            'deadline':'SAME_ORIGINAL_PARENT_CHILD_AND_GATE_WINDOW','mutationRetryAllowed':False},
        'mustCloseRegistryGateBeforeReturn':True,'closedWindowReopenAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False}

def creation_scope(template,gate_window_scope,journal_directory):
    t=templates.recompile(template);root=templates.absolute(str(journal_directory))
    require(type(gate_window_scope) is dict and gate_window_scope.get('schema')=='ouf.discovery-gate-peer-window-scope.v1'
        and t['sourceClosureHash']==gate_window_scope['sourceClosureHash']
        and len(Path(root).parts)>=4 and not Path(root).is_relative_to(gate_window_scope['journalDirectory'])
        and not Path(gate_window_scope['journalDirectory']).is_relative_to(root),
        'DISTINCT_PROVIDER_CREATE_AND_SAME_SOURCE_GATE_WINDOW_REQUIRED')
    context=digest({'templateHash':digest(t),'journalDirectory':root})
    return {'schema':'ouf.discovery-provider-creation-scope.v1','templateHash':digest(t),
        'creationRequestHash':digest(t['creationRequest']),'gatePeerWindowScopeHash':digest(gate_window_scope),
        'journalDirectory':root,'context':context,'maximumCreateAttempts':1,
        'providerStartAuthorized':False,'historicalProviderMutationAuthorized':False,
        'creationIsNotNativeAdmission':True,'automaticReplayAllowed':False}

def creation_component(scope,installation=None):
    if installation is None:return copy.deepcopy(scope)
    require(type(installation) is dict and installation.get('schema') in {
        'ouf.discovery-composed-provider-installation-scope.v1','ouf.discovery-composed-provider-installation-scope.v2'}
        and set(installation)=={'schema','creation','installation','admission'}|(
            {'sequence'} if installation['schema'].endswith('.v2') else set())
        and installation['creation']==scope and all(type(installation[k]) is dict and bool(installation[k]) for k in ('installation','admission')),
        'EXACT_EXPLICIT_PROVIDER_CREATION_INSTALLATION_AND_ADMISSION_REVIEW_REQUIRED')
    if installation['schema'].endswith('.v2'):
        require(installation['sequence']==provider_sequence_scope(scope,installation['installation'],installation['admission'],
            journal_directory=installation['sequence']['journalDirectory']),'EXACT_REVIEWED_PROVIDER_SEQUENCE_REQUIRED')
    return copy.deepcopy(installation)

class ProviderCreation:
    def __init__(self,*,parent,window,template,journal_directory,installation_component=None):
        require(type(parent) is DiscoveryParentAuthority and type(window) is GatePeerWindow
            and window.parent is parent and type(window.engine) is Engine,
            'SAME_TYPED_PROVIDER_PARENT_ENGINE_AND_GATE_WINDOW_REQUIRED')
        self.parent,self.window,self.engine=parent,window,window.engine
        self.template=templates.recompile(template);self.template_hash=digest(self.template)
        self.scope=creation_scope(self.template,window.scope,journal_directory);self.scope_hash=digest(self.scope)
        self.component=creation_component(self.scope,installation_component);self.parent_hash=parent.sha
        self.root=Path(self.scope['journalDirectory']);self.journal=Journal(self.root)
        require(not self.root.is_relative_to(window.store.root) and not window.store.root.is_relative_to(self.root),
            'SEPARATE_PROVIDER_CREATION_EVIDENCE_DIRECTORY_REQUIRED')
        self.naming=types.SimpleNamespace(context='provider-'+self.scope['context'])
        self.name=Engine.name(self.naming)
    def sealed(self):
        require(type(self.parent) is DiscoveryParentAuthority and type(self.window) is GatePeerWindow
            and self.window.parent is self.parent and self.engine is self.window.engine and type(self.engine) is Engine
            and self.parent.sha==self.parent_hash and digest(self.template)==self.template_hash
            and self.scope==creation_scope(self.template,self.window.scope,self.root) and digest(self.scope)==self.scope_hash
            and self.component==creation_component(self.scope,None if self.component==self.scope else self.component)
            and self.name==Engine.name(types.SimpleNamespace(context='provider-'+self.scope['context'])),
            'PROVIDER_CREATION_SCOPE_OR_OWNER_DRIFT')
        self.journal.check_directory();self.parent.guard('providerInstallation',self.component)
    def current(self):
        self.sealed();self.window.current();proof=self.window.observe_open()
        require(proof['applicationSignalAuthorized'] is False and proof['ociAdmissionGranted'] is False,
            'RUNNING_WAIT_GATE_IS_NOT_REGISTRY_ADMISSION')
        return proof
    def observation_window(self):
        self.sealed();self.window.sealed()
        value=self.window.retained()
        if value['state'] in {'OPENING','OPEN'}:return self.current()
        value=self.window.observe_closed()
        # Closure only changes state/pauseAttempts. Retain the opening identity
        # for read-only reconciliation after the peer_window finally block.
        opened={**value,'state':'OPEN','pauseAttempts':0}
        return {'schema':'ouf.discovery-running-gate-peer-window.v1','windowHash':digest(opened),
            'runtimeBinding':value['runtimeBinding'],'generation':value['generation'],
            'applicationSignalAuthorized':False,'ociAdmissionGranted':False,'providerAdmissionIsSeparate':True}
    def inspect(self):
        status,value=self.engine.request('GET','/v1.44/containers/'+self.name+'/json')
        if status==404:return None
        require(status==200 and type(value) is dict,'EXACT_PROVIDER_CREATION_INSPECTION_REQUIRED')
        return value
    def matches(self,value):
        return Engine.matching_created(self.engine,self.naming,self.template['creationRequest'],value)
    def retained(self):
        self.sealed();row=self.journal.read()
        require(type(row) is dict and set(row)==ROW_FIELDS
            and row['schema']=='ouf.discovery-provider-creation-journal.v1' and row['scopeHash']==self.scope_hash
            and row['parentAuthorityHash']==self.parent_hash and row['creationRequestHash']==self.scope['creationRequestHash']
            and row['state'] in {'CREATING','CREATED'} and type(row['version']) is int
            and row['version']==int(row['state']=='CREATED')
            and (row['containerId'] is None and row['nativeCreatedEvidenceHash'] is None if row['state']=='CREATING'
                else templates.hashed(row['containerId']) and templates.hashed(row['nativeCreatedEvidenceHash'])),
            'EXACT_RETAINED_PROVIDER_CREATION_REQUIRED')
        w=self.window.retained()
        require(w['runtimeBinding']==row['registryRuntimeBinding'] and w['generation']==row['registryGeneration'],
            'PROVIDER_CREATION_REGISTRY_GENERATION_DRIFT')
        return row
    def publish_created(self,row,actual):
        self.matches(actual);require(actual['Id']!=row['registryRuntimeBinding']['containerId'],
            'DISTINCT_NEW_PROVIDER_REQUIRED')
        expected=digest(actual);path=self.root/'created-native.private.json'
        with directory(self.root) as parent:
            if os.path.lexists(path):require(private_json(path)==actual,'PROVIDER_CREATED_NATIVE_RECORD_DRIFT')
            else:new_file(parent,path.name,encoded(actual))
        after={**row,'state':'CREATED','version':1,'containerId':actual['Id'],'nativeCreatedEvidenceHash':expected}
        self.journal.compare_and_save(row,after)
        require(self.retained()==after,'PROVIDER_CREATION_COMMIT_READBACK_DRIFT');return after
    def create_once(self):
        proof=self.current();require(self.inspect() is None,'EXISTING_PROVIDER_NAME_REQUIRES_RECONCILIATION')
        initial={'schema':'ouf.discovery-provider-creation-journal.v1','scopeHash':self.scope_hash,
            'parentAuthorityHash':self.parent_hash,'creationRequestHash':self.scope['creationRequestHash'],
            'windowHash':proof['windowHash'],'registryRuntimeBinding':proof['runtimeBinding'],
            'registryGeneration':proof['generation'],'state':'CREATING','version':0,
            'containerId':None,'nativeCreatedEvidenceHash':None}
        with protected_directory(self.root):
            self.journal.initialize(initial)
            with self.journal.invocation():
                require(self.current()==proof and self.retained()==initial and self.inspect() is None,
                    'EXACT_PROVIDER_PRECREATE_WINDOW_AND_ABSENCE_REQUIRED')
                with directory(self.root) as parent:new_file(parent,'create-dispatch.json',encoded({'scopeHash':self.scope_hash,'attempt':1}))
                require(self.current()==proof and self.retained()==initial,'PROVIDER_CREATE_DISPATCH_RECORD_DRIFT')
                status,value=self.engine.request('POST','/v1.44/containers/create?name='+self.name,self.template['creationRequest'])
                require(status==201 and type(value) is dict and templates.hashed(value.get('Id')),
                    'PROVIDER_CREATE_OUTCOME_REQUIRES_RECONCILIATION')
                actual=self.matches(self.inspect());require(actual['Id']==value['Id'],'PROVIDER_CREATE_RESPONSE_IDENTITY_DRIFT')
                require(self.current()==proof and self.retained()==initial,'PROVIDER_CREATE_BOUNDARY_CHANGED')
                return self.publish_created(initial,actual)
    def observe(self):
        proof=self.observation_window()
        if not os.path.lexists(self.journal.record):return 'UNKNOWN',{'ownedCreateClaimPresent':False,'automaticReplayAllowed':False}
        with protected_directory(self.root),self.journal.invocation():
            row=self.retained();require(row['windowHash']==proof['windowHash'],'SAME_PROVIDER_CREATE_WINDOW_REQUIRED')
            dispatch=self.root/'create-dispatch.json'
            if not os.path.lexists(dispatch):return 'UNKNOWN',{'ownedCreateClaimPresent':True,'createDispatchUnproven':True,'automaticReplayAllowed':False}
            require(private_json(dispatch)=={'scopeHash':self.scope_hash,'attempt':1},'EXACT_ONE_PROVIDER_CREATE_DISPATCH_REQUIRED')
            actual=self.inspect()
            if actual is None:return 'UNKNOWN',{'ownedCreateClaimPresent':True,'nativeNameAbsentIsNotNoEffect':True,'automaticReplayAllowed':False}
            self.matches(actual);require(self.inspect()==actual and self.observation_window()==proof,'PROVIDER_CREATION_CHANGED_DURING_OBSERVATION')
            if row['state']=='CREATING':row=self.publish_created(row,actual)
            require(row['containerId']==actual['Id'] and row['nativeCreatedEvidenceHash']==digest(actual),
                'EXACT_OWNED_CREATED_PROVIDER_READBACK_REQUIRED')
            return 'APPLIED',{'schema':'ouf.discovery-provider-created.v1','scopeHash':self.scope_hash,
                'containerId':row['containerId'],'nativeCreatedEvidenceHash':row['nativeCreatedEvidenceHash'],
                'providerStarted':False,'nativeAdmissionGranted':False,'automaticReplayAllowed':False}
    def owned_id(self):
        """Retained creation ownership, including after start/window closure.

        This is not a fresh created/running observation or a provider admission.
        """
        row=self.retained();require(row['state']=='CREATED','OWNED_COMPLETED_PROVIDER_CREATION_REQUIRED')
        native=private_json(self.root/'created-native.private.json');self.matches(native)
        require(native['Id']==row['containerId'] and digest(native)==row['nativeCreatedEvidenceHash']
            and row['containerId']!=row['registryRuntimeBinding']['containerId'],'RETAINED_PROVIDER_CREATION_IDENTITY_DRIFT')
        return row['containerId']
