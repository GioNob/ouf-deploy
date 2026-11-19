"""Publish the reviewed Discovery delta under the current installation parent.

Uses the existing authorization state machine and APISIX namespace I/O. The
parent separately authorizes this component; the unchanged Registry child is
authenticated, never projected into a legacy aggregate publication authority.
The application's sealed native checkpoint must implement the pre-publication
point below. A modeled checkpoint is not target cohort admission or E2E proof.
"""
import copy,os
from contextlib import contextmanager
from .custody_capture import digest,encoded,require
from .publication_review import assemble
from .publication_primitives import PublicationPrimitives
from .selected_runtime import DiscoverySelectedRuntime
from .application import DiscoveryApplication
from .executor import DiscoveryExecutor
from .parent_authority import DiscoveryParentAuthority
from .gateway_runtime import DiscoveryGatewayRuntime
from tools.chatbot_file_cohort.authorization import AuthorizationDelta,OwnerTransport
from tools.chatbot_file_cohort.gateway import GatewayRoutes,NamespaceAdmin,publication_scope,apisix_runtime_binding
from tools.chatbot_file_cohort.gateway_runtime import proposed_transport
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json

POINT='BEFORE_DISCOVERY_CAPABILITY_PUBLICATION'
PHASE='RELEASE_PRODUCERS'
BINDING='publication-owner-binding.json'


class DiscoveryPublicationWindow:
    def __init__(self,selected,inputs,cohort_inputs,primitives):
        require(type(selected) is DiscoverySelectedRuntime and type(primitives) is PublicationPrimitives,
            'ACTUAL_SELECTED_DISCOVERY_RUNTIME_AND_PINNED_PUBLICATION_COMPILERS_REQUIRED')
        self.selected,self.primitives=selected,primitives
        self.parent=selected.images.parent;self.gate=selected.images.window
        app=selected.installation.application
        require(type(app) is DiscoveryApplication and type(app.executor) is DiscoveryExecutor
            and type(self.parent) is DiscoveryParentAuthority,'ACTUAL_DISCOVERY_APPLICATION_EXECUTOR_AND_PARENT_REQUIRED')
        self.app,self.executor=app,app.executor
        self.ids=tuple(map(id,(selected,self.parent,self.gate,app,self.executor,primitives)))
        self.parent_hash,self.child_hash=self.parent.sha,selected.mcp.action.authority_hash
        self.inputs,self.cohort_inputs=copy.deepcopy(inputs),copy.deepcopy(cohort_inputs)
        self.input_hash,self.cohort_hash=digest(inputs),digest(cohort_inputs)
        self.assembly=assemble(inputs,self.input_hash,cohort_inputs,primitives)
        self.component=copy.deepcopy(self.assembly['component']);self.component_hash=digest(self.component)
        self.fence=None
        self.lineage()

    def lineage(self):
        s=self.selected
        require(self.ids==tuple(map(id,(s,self.parent,self.gate,self.app,self.executor,self.primitives)))
            and type(s) is DiscoverySelectedRuntime and s.images.parent is self.parent
            and s.images.window is self.gate and s.installation.application is self.app
            and self.app.executor is self.executor and self.executor.discovery_parent is self.parent
            and self.parent.sha==self.parent_hash and s.mcp.action.authority_hash==self.child_hash
            and digest(self.inputs)==self.input_hash and digest(self.cohort_inputs)==self.cohort_hash
            and digest(self.component)==self.component_hash
            and assemble(self.inputs,self.input_hash,self.cohort_inputs,self.primitives)==self.assembly
            and self.assembly['component']==self.component,
            'DISCOVERY_PUBLICATION_OWNER_LINEAGE_OR_RECOMPILED_REVIEW_DRIFT')
        self.parent.guard('capabilityPublication',self.component)
        require(all(self.component[k]==self.parent.scope[k] for k in
            ('sourceClosureHash','installationInputsHash','desiredProfileHash'))
            and self.component['gatewayRuntimePlanHash']==digest(s.gateway.plan)
            and self.component['registryCreationRequestHash']==self.app.request_hash,
            'SAME_CURRENT_DISCOVERY_PUBLICATION_SOURCE_INPUTS_AND_INSTALLED_PLANS_REQUIRED')

    def guard(self):
        self.lineage();row=self.selected.held(self.fence)
        # This is the same sealed, scope-bound checkpoint channel the concrete
        # Registry application uses. No callback/receipt is accepted as an input
        # to this publication owner, and no authority is issued by this call.
        proof=self.executor.checkpoint(PHASE,POINT,row)
        require(type(proof) is dict and set(proof)=={'schema','phase','point','journalVersion','intentHash',
            'authorityHash','sourceClosureHash','nativeEvidenceHash'}
            and proof=={**proof,'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':PHASE,'point':POINT,
                'journalVersion':row['version'],'intentHash':self.app.intent_hashes[PHASE],
                'authorityHash':self.child_hash,'sourceClosureHash':self.parent.scope['sourceClosureHash']}
            and type(proof['nativeEvidenceHash']) is str and len(proof['nativeEvidenceHash'])==64
            and set(proof['nativeEvidenceHash'])<=set('0123456789abcdef'),
            'CURRENT_SEALED_PREPUBLICATION_NATIVE_CHECKPOINT_REQUIRED')
        self.lineage();require(self.selected.held(self.fence)==row,'PUBLICATION_NATIVE_CHECKPOINT_HISTORY_CHANGED')
        return row

    @contextmanager
    def invocation(self):
        require(self.fence is None,'DISCOVERY_PUBLICATION_INVOCATION_ALREADY_ACTIVE')
        with self.gate.transition.invocation():
            self.fence=self.guard()
            try:yield
            finally:self.fence=None


def binding(owner):
    w=owner.window
    return {'schema':'ouf.discovery-publication-owner-binding.v1','componentHash':w.component_hash,
        'parentAuthorityHash':w.parent_hash,'childAuthorityHash':w.child_hash,
        'owner':owner.kind,'planHash':owner.hash if owner.kind=='authorization' else owner.plan_hash,
        'journalDirectory':str(owner.journal.root),'automaticReplayAllowed':False,'budgetReset':False}


def initialize_binding(owner):
    owner.window.guard()
    require(str(owner.journal.root)==owner.window.component['journalDirectories'][owner.kind],
        'EXACT_PARENT_REVIEWED_PUBLICATION_JOURNAL_REQUIRED')
    with directory(owner.journal.root) as fd:
        # A binding-only/partially initialized root remains consumed. This path
        # is never a recovery initializer or a previous-parent adoption path.
        require(not os.listdir(fd),'EMPTY_INITIAL_DISCOVERY_PUBLICATION_JOURNAL_REQUIRED_NO_REPLAY')
        new_file(fd,BINDING,encoded(binding(owner)))


def check_binding(owner):
    owner.journal.check_directory()
    require(private_json(owner.journal.root/BINDING)==binding(owner),
        'CURRENT_PARENT_CHILD_AND_COMPONENT_PUBLICATION_BINDING_REQUIRED')


def claim(owner,name):
    return {'schema':'ouf.discovery-publication-effect-dispatch.v1','ownerBindingHash':digest(binding(owner)),
        'effect':name,'attempt':1,'automaticReplayAllowed':False}


def marker(name):return 'dispatch-'+digest(name)+'.json'


def dispatch(owner,name):
    owner.guard();require(owner.window.fence is not None,'CURRENT_REGISTRY_INVOCATION_FENCE_REQUIRED_FOR_PUBLICATION')
    with directory(owner.journal.root) as fd:new_file(fd,marker(name),encoded(claim(owner,name)))
    owner.guard()


def check_markers(owner,names):
    with directory(owner.journal.root) as fd:
        actual={p for p in os.listdir(fd) if p.startswith('dispatch-')}
    require(actual<=set(map(marker,names)),'PUBLICATION_MUTABLE_HISTORY_REGRESSED_BEHIND_DURABLE_DISPATCH')
    for name in names:
        p=owner.journal.root/marker(name)
        if os.path.lexists(p):require(private_json(p)==claim(owner,name),'PUBLICATION_DISPATCH_CUSTODY_OR_SCOPE_DRIFT')


class DiscoveryAuthorization(AuthorizationDelta):
    kind='authorization'
    def __init__(self,window,journal,transport):
        require(type(window) is DiscoveryPublicationWindow and type(journal) is Journal
            and type(transport) is OwnerTransport,'ACTUAL_DISCOVERY_AUTHORIZATION_COMPONENTS_REQUIRED')
        self.window=window
        action=AggregateAction(window.gate.child,window.gate.raw,window.parent.scope['sourceClosureHash'])
        super().__init__(action,window.assembly['authorizationPlan'],journal,transport,window.primitives.owner)
        self.owner_ids=tuple(map(id,(window,journal,transport,action)))

    def guard(self):
        require(self.owner_ids==tuple(map(id,(self.window,self.journal,self.transport,self.action)))
            and self.plan==self.window.assembly['authorizationPlan'] and digest(self.plan)==self.hash
            and self.scope==self.window.component['authorization']
            and self.action.authority is self.window.gate.child and self.action.raw==self.window.gate.raw
            and self.action.authority_hash==self.window.child_hash,
            'EXACT_PARENT_AUTHORIZED_DISCOVERY_DELTA_REQUIRED')
        check_binding(self);self.window.guard()

    def initialize(self):
        initialize_binding(self);super().initialize()

    def record(self):
        check_binding(self);row=super().record();check_markers(self,row['effects'])
        return row

    def effect(self,name,mutate,reconcile,*,retry_idempotent=False):
        def once():
            dispatch(self,name);return mutate()
        # Even the deduplicated role proposal keeps the parent-reviewed single
        # dispatch maximum. Ambiguity is read-only reconciliation, not replay.
        return super().effect(name,once,reconcile,retry_idempotent=False)

    def apply(self):
        with self.window.invocation():return super().apply()


class DiscoveryGatewayPublicationAdmin(NamespaceAdmin):
    def __init__(self,owner,binding):
        require(type(owner) is DiscoveryGatewayPublication,'ACTUAL_DISCOVERY_ROUTE_PUBLICATION_OWNER_REQUIRED')
        self.publication,self.owner_id=owner,id(owner)
        runtime=owner.window.selected.gateway
        require(type(runtime) is DiscoveryGatewayRuntime,'ACTUAL_CURRENT_DISCOVERY_GATEWAY_REQUIRED')
        super().__init__(runtime.engine,binding)
        self.reviewed_binding=proposed_transport(runtime.plan);self.reviewed_hash=digest(self.reviewed_binding)

    def check(self):
        p=self.publication;runtime=p.window.selected.gateway
        require(type(p) is DiscoveryGatewayPublication and id(p)==self.owner_id and p.transport is self
            and self.engine is runtime.engine and self.runtime_owner is None
            and self.reviewed_binding==p.plan['transportBinding']==proposed_transport(runtime.plan)
            and digest(self.reviewed_binding)==self.reviewed_hash
            and self.binding.get('runtimeBindingProfile')==runtime.plan.get('runtimeBindingProfile')
            and apisix_runtime_binding(runtime.generation(),self.binding.get('runtimeBindingProfile'))==self.binding['runtimeBinding'],
            'CURRENT_DISCOVERY_PUBLICATION_GATEWAY_GENERATION_REQUIRED')
        p.guard();super().check()

    def request(self,method,path,body=None):
        require(method in ('GET','PUT') and (method!='GET' or body is None),'CLOSED_DISCOVERY_PUBLICATION_NAMESPACE_REQUEST_REQUIRED')
        if method=='PUT':self.publication.before_put(path,body)
        return super().request(method,path,body)


class DiscoveryGatewayPublication(GatewayRoutes):
    kind='gateway'
    def __init__(self,window,journal):
        require(type(window) is DiscoveryPublicationWindow and type(journal) is Journal,
            'ACTUAL_DISCOVERY_GATEWAY_PUBLICATION_WINDOW_AND_JOURNAL_REQUIRED')
        self.window,self.journal=window,journal
        self.action=AggregateAction(window.gate.child,window.gate.raw,window.parent.scope['sourceClosureHash'])
        self.plan=copy.deepcopy(window.assembly['gatewayPlan']);self.plan_hash=digest(self.plan)
        self.scope=publication_scope(self.plan);self.owner_ids=tuple(map(id,(window,journal,self.action)))
        self.transport=None

    def connect(self):
        self.guard();runtime=self.window.selected.gateway
        observed=NamespaceAdmin.observe(runtime.engine,runtime.plan['newConfigBinding']['path'],runtime.plan.get('runtimeBindingProfile'))
        require(observed['pythonExecutable']==runtime.plan['pythonExecutable']
            and observed['adminKeyBinding']==runtime.plan['adminKeyBinding'],
            'SAME_REVIEWED_GATEWAY_PUBLICATION_EXECUTABLE_AND_ADMIN_CREDENTIAL_REQUIRED')
        self.transport=DiscoveryGatewayPublicationAdmin(self,observed);self.transport.check();return self.transport

    def guard(self):
        require(self.owner_ids==tuple(map(id,(self.window,self.journal,self.action)))
            and self.plan==self.window.assembly['gatewayPlan'] and digest(self.plan)==self.plan_hash
            and publication_scope(self.plan)==self.scope==self.window.component['gateway']
            and self.action.authority is self.window.gate.child and self.action.raw==self.window.gate.raw
            and self.action.authority_hash==self.window.child_hash,
            'EXACT_PARENT_AUTHORIZED_DISCOVERY_GATEWAY_PLAN_REQUIRED')
        check_binding(self);self.window.guard()

    def initialize(self):
        initialize_binding(self)
        if self.transport is None:self.connect()
        super().initialize()

    def record(self):
        check_binding(self);row=super().record();check_markers(self,[e['routeId'] for e in row['effects']]);return row

    def before_put(self,path,body):
        self.guard();row=self.record();n=row['nextStep']
        require(n<len(self.plan['changes']) and len(row['effects'])==n+1 and row['effects'][-1]['state']=='CLAIMED',
            'DURABLE_CURRENT_DISCOVERY_ROUTE_CLAIM_REQUIRED')
        change=self.plan['changes'][n]
        require(path=='/apisix/admin/routes/'+change['id'] and body==change['after'],
            'EXACT_CLAIMED_DISCOVERY_ROUTE_PUT_REQUIRED')
        dispatch(self,change['id'])

    def apply(self):
        if self.transport is None:self.connect()
        with self.window.invocation():return super().apply()


class DiscoveryPublication:
    def __init__(self,authorization,gateway):
        require(type(authorization) is DiscoveryAuthorization and type(gateway) is DiscoveryGatewayPublication
            and authorization.window is gateway.window,'SAME_DISCOVERY_PUBLICATION_WINDOW_AND_CONCRETE_OWNERS_REQUIRED')
        self.authorization,self.gateway,self.window=authorization,gateway,authorization.window
        self.ids=tuple(map(id,(authorization,gateway,self.window)))

    def apply(self):
        require(self.ids==tuple(map(id,(self.authorization,self.gateway,self.window)))
            and self.authorization.window is self.gateway.window is self.window,
            'DISCOVERY_PUBLICATION_COORDINATOR_OWNER_DRIFT')
        with self.window.invocation():
            held=self.window.guard()
            # Reuse the actual state machines inside the already held Registry
            # fence. An unconfirmed THS proposal exits immediately, preserving
            # the one-use effects and releasing the fence without any wait.
            authorization=AuthorizationDelta.apply(self.authorization)
            if self.gateway.transport is None:self.gateway.connect()
            gateway=GatewayRoutes.apply(self.gateway)
            require(self.authorization.verify()==authorization and self.gateway.verify()==gateway
                and self.window.guard()==held,'DISCOVERY_PUBLICATION_CHANGED_DURING_FINAL_RECONCILIATION')
        return {'schema':'ouf.discovery-governed-publication-receipt.v1','componentHash':self.window.component_hash,
            'parentAuthorityHash':self.window.parent_hash,'childAuthorityHash':self.window.child_hash,
            'authorizationEvidenceHash':digest(authorization),'gatewayEvidenceHash':digest(gateway),
            'governedDeltaReconciled':True,'producerReleaseDispatched':False,'fullCohortProven':False,
            'currentNativeAdmissionProven':False,
            'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'budgetReset':False,
            'applicationE2EProven':False,'releaseAcceptance':False}
