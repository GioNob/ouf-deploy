"""Closed discovery child extension bound to the current dual-role parent.

Reuse all ordered effects/checkpoints/fencing in Executor. Legacy and file-only
authority shapes stay closed. No projection/re-signing of the child bytes.
"""
import copy,re
from .custody_capture import decode,digest,require
from .audit import path
from .parent_authority import DiscoveryParentAuthority
from .cohort_images import checked_component,hashed
from cutover_executor import Executor
from cutover_authority import CutoverAuthority


def runtime_sections(component):
    gateway=component['gatewayRuntime'];mcp=component['mcp']
    require(set(gateway)=={'schema','runtime','journalDirectory','sameRegistryParentAndChildRequired',
        'historicalRecoveryAdoptionAllowed','automaticReplayAllowed','maximumDispatchAttemptsPerStep',
        'dispatchIndependentOfMutableJournal'} and gateway['schema']=='ouf.discovery-gateway-runtime-component.v2'
        and gateway['sameRegistryParentAndChildRequired'] is gateway['dispatchIndependentOfMutableJournal'] is True
        and gateway['historicalRecoveryAdoptionAllowed'] is gateway['automaticReplayAllowed'] is False
        and type(gateway['maximumDispatchAttemptsPerStep']) is int and gateway['maximumDispatchAttemptsPerStep']==1,
        'EXACT_PARENT_GATEWAY_V2_EXECUTION_SECTION_REQUIRED')
    path(gateway['journalDirectory']);runtime=gateway['runtime']
    require(set(runtime)=={'profile','planHash','oldContainerId','sameImageId','proposalKeyHash',
        'automaticRollbackAllowed','automaticWriteReplayAllowed'}
        and runtime['profile']=='ouf.chatbot-file-cohort.gateway-runtime.v1'
        and all(hashed(runtime[k]) for k in ('planHash','oldContainerId','proposalKeyHash'))
        and re.fullmatch('sha256:[a-f0-9]{64}',runtime['sameImageId'])
        and runtime['automaticRollbackAllowed'] is runtime['automaticWriteReplayAllowed'] is False,
        'EXACT_PARENT_GATEWAY_RUNTIME_SCOPE_REQUIRED')
    require(set(mcp)=={'schema','planHash','imageId','oldContainerId','journalDirectory','readinessDirectory',
        'sameRegistryParentAndChildRequired','historicalRecoveryAdoptionAllowed','automaticReplayAllowed','budgetReset'}
        and mcp['schema']=='ouf.discovery-mcp-replacement-component.v1'
        and all(hashed(mcp[k]) for k in ('planHash','oldContainerId'))
        and re.fullmatch('sha256:[a-f0-9]{64}',mcp['imageId'])
        and mcp['sameRegistryParentAndChildRequired'] is True
        and all(mcp[k] is False for k in ('historicalRecoveryAdoptionAllowed','automaticReplayAllowed','budgetReset')),
        'EXACT_PARENT_MCP_EXECUTION_SECTION_REQUIRED')
    path(mcp['journalDirectory']);path(mcp['readinessDirectory'])
    return {'gatewayRuntimeInstallation':runtime,'discoveryMcpInstallation':mcp}


class DiscoveryExecutor(Executor):
    def __init__(self,*args,parent,**kwargs):
        require(type(parent) is DiscoveryParentAuthority,'ACTUAL_DISCOVERY_EXECUTOR_PARENT_REQUIRED')
        self.discovery_parent=parent;self.parent_hash=parent.sha
        super().__init__(*args,**kwargs)
        require(type(self.authenticate) is CutoverAuthority and self.profile_hash is None
            and self.aggregate_action is None,'SEPARATE_THIRTEEN_PHASE_DISCOVERY_EXECUTOR_REQUIRED')
        self.owner_ids=tuple(map(id,(parent,self.authenticate,self.t)))
        self.component=copy.deepcopy(checked_component(parent,parent.review['components']['cohortInstallation']['images']))
        self.component_hash=digest(self.component)
        self.additional_authority_fields()

    def additional_authority_fields(self):
        parent=self.discovery_parent
        require(type(parent) is DiscoveryParentAuthority and parent.sha==self.parent_hash
            and self.owner_ids==tuple(map(id,(parent,self.authenticate,self.t)))
            and type(self.authenticate) is CutoverAuthority and self.profile_hash is None
            and self.aggregate_action is None and self.authority==decode(self.raw)
            and digest(self.component)==self.component_hash
            and self.component==checked_component(parent,parent.review['components']['cohortInstallation']['images']),
            'DISCOVERY_EXECUTOR_PARENT_CHILD_OR_COMPONENT_DRIFT')
        parent.registry_child(self.authenticate,self.raw)
        parent.guard('cohortInstallation',self.component)
        sections=runtime_sections(self.component)
        require(all(self.authority.get(k)==v for k,v in sections.items()),
            'SIGNED_DISCOVERY_RUNTIME_SECTIONS_MUST_MATCH_CURRENT_PARENT')
        return set(sections)
