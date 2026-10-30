"""Bind the existing APISIX owner to the same current discovery parent/child.

Uses the actual existing AggregateAction and GatewayRuntime, not an authority
adapter or historical recovery adoption. Parent revocation is checked by the
overridden guard on every internal owner step. No keys, authority or release.
"""
import copy
from pathlib import Path
from .custody_capture import decode,digest,require
from .cohort_images import DiscoveryImages,checked_component
from .parent_authority import DiscoveryParentAuthority
from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime,runtime_scope,proposed_transport
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,apisix_runtime_binding
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal


def component(plan,journal_directory):
    path=Path(journal_directory)
    require(path.is_absolute() and str(path)==str(journal_directory) and '..' not in path.parts,
        'EXACT_DISCOVERY_GATEWAY_JOURNAL_DIRECTORY_REQUIRED')
    return {'schema':'ouf.discovery-gateway-runtime-component.v1','runtime':runtime_scope(plan),
        'journalDirectory':str(path),'sameRegistryParentAndChildRequired':True,
        'historicalRecoveryAdoptionAllowed':False,'automaticReplayAllowed':False}


class DiscoveryGatewayRuntime(GatewayRuntime):
    def __init__(self,*,images,plan,journal,boot=None):
        require(type(images) is DiscoveryImages and type(images.parent) is DiscoveryParentAuthority
            and type(journal) is Journal,'TYPED_DISCOVERY_IMAGES_PARENT_AND_GATEWAY_JOURNAL_REQUIRED')
        self.images,self.parent=images,images.parent
        self.window=images.window
        self.owner_ids=tuple(map(id,(images,self.parent,self.window,journal)))
        self.parent_hash=self.parent.sha
        self.discovery_scope=component(plan,str(journal.root))
        other_roots=[self.window.root,self.window.store.root,*[j.root for j in images.journals.values()]]
        require(all(not journal.root.is_relative_to(root) and not root.is_relative_to(journal.root)
            for root in other_roots),'SEPARATE_DISCOVERY_GATEWAY_JOURNAL_REQUIRED')
        self.cohort_component=checked_component(self.parent,images.scope)
        require(self.cohort_component['gatewayRuntime']==self.discovery_scope,
            'EXACT_PARENT_GATEWAY_PLAN_AND_JOURNAL_REQUIRED')
        child=decode(self.window.raw)
        require(child.get('gatewayRuntimeInstallation')==self.discovery_scope['runtime']
            and not child.get('applicationRegistryCutover',{}).get('postGrantRecovery'),
            'CURRENT_CHILD_GATEWAY_SCOPE_WITHOUT_HISTORICAL_ADOPTION_REQUIRED')
        action=AggregateAction(self.window.child,self.window.raw,self.parent.scope['sourceClosureHash'])
        super().__init__(action,self.window.engine,copy.deepcopy(plan),journal,
            clock=self.parent.clock,boot=boot)
        self.guard()

    def guard(self):
        require(self.owner_ids==tuple(map(id,(self.images,self.parent,self.window,self.journal)))
            and self.parent.sha==self.parent_hash and self.images.parent is self.parent
            and self.window is self.images.window and self.window.parent is self.parent
            and self.engine is self.window.engine and type(self.action) is AggregateAction
            and self.action.authority is self.window.child and self.action.raw==self.window.raw
            and component(self.plan,str(self.journal.root))==self.discovery_scope
            and checked_component(self.parent,self.images.scope)==self.cohort_component,
            'DISCOVERY_GATEWAY_OWNER_PARENT_CHILD_ENGINE_OR_JOURNAL_DRIFT')
        self.images.guard()
        self.parent.guard('cohortInstallation',self.cohort_component)
        super().guard()

    def transport(self):
        self.guard();self.generation()
        binding=NamespaceAdmin.observe(self.engine,self.plan['newConfigBinding']['path'],self.plan.get('runtimeBindingProfile'))
        require(binding['pythonExecutable']==self.plan['pythonExecutable']
            and binding['adminKeyBinding']==self.plan['adminKeyBinding'],
            'APPROVED_NAMESPACE_ADMIN_CREDENTIAL_CHANGED')
        return DiscoveryGatewayReadOnlyAdmin(self,binding)


class DiscoveryGatewayReadOnlyAdmin(NamespaceAdmin):
    """Use existing namespace I/O with an explicit typed discovery owner.

    The legacy journal-owner constructor intentionally accepts only its own
    exact type. This new channel composes the supported observed channel with
    its own parent/journal/generation checks; it does not impersonate that type.
    Runtime readiness needs GET only. Publication owns any future route writes.
    """
    def __init__(self,owner,binding):
        require(type(owner) is DiscoveryGatewayRuntime,'ACTUAL_DISCOVERY_GATEWAY_OWNER_REQUIRED')
        self.discovery_owner,self.discovery_owner_id=owner,id(owner)
        self.reviewed_runtime=proposed_transport(owner.plan)
        super().__init__(owner.engine,binding)
        self.reviewed_binding={'schema':'ouf.discovery-gateway-readonly-transport.v1',
            'parentAuthorityHash':owner.parent.sha,'componentHash':digest(owner.discovery_scope),
            'runtime':copy.deepcopy(self.reviewed_runtime),'routeWritesAllowed':False}
        self.reviewed_hash=digest(self.reviewed_binding)
        self.check()

    def check(self):
        owner=self.discovery_owner
        require(type(owner) is DiscoveryGatewayRuntime and id(owner)==self.discovery_owner_id
            and owner.engine is self.engine and self.runtime_owner is None
            and proposed_transport(owner.plan)==self.reviewed_runtime
            and self.reviewed_binding=={'schema':'ouf.discovery-gateway-readonly-transport.v1',
                'parentAuthorityHash':owner.parent.sha,'componentHash':digest(owner.discovery_scope),
                'runtime':self.reviewed_runtime,'routeWritesAllowed':False}
            and digest(self.reviewed_binding)==self.reviewed_hash,
            'DISCOVERY_GATEWAY_READONLY_TRANSPORT_OWNER_OR_REVIEW_DRIFT')
        owner.guard()
        require(self.binding.get('runtimeBindingProfile')==owner.plan.get('runtimeBindingProfile')
            and apisix_runtime_binding(owner.generation(),self.binding.get('runtimeBindingProfile'))==self.binding['runtimeBinding'],
            'CURRENT_DISCOVERY_GATEWAY_GENERATION_REQUIRED')
        super().check()

    def request(self,method,path,body=None):
        require(method=='GET' and body is None,'GATEWAY_ROUTE_WRITES_REQUIRE_SEPARATE_DISCOVERY_PUBLICATION_OWNER')
        return super().request(method,path,body)
