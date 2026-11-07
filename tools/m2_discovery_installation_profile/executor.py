"""Closed discovery child extension bound to the current dual-role parent.

Reuse all ordered effects/checkpoints/fencing in Executor. Legacy and file-only
authority shapes stay closed. No projection/re-signing of the child bytes.
"""
import copy,re
from .custody_capture import decode,digest,require
from .audit import path
from .parent_authority import DiscoveryParentAuthority
from .cohort_images import checked_component,hashed
from cutover_executor import Executor,require as executor_require
from cutover_authority import CutoverAuthority
from transition_journal import Transition,PHASES,hash_value


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
        require(type(self.authenticate) is CutoverAuthority and type(self.t) is Transition and self.profile_hash is None
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

    def verify(self,phase,point,row):
        # The shared verifier is part of retained immutable artifacts. Keep its
        # bytes untouched. Only its v1/13-phase validation branch is specialized
        # here; all ordered dispatch/CAS/reconciliation remains inherited.
        check=executor_require
        check(set(self.adapters)==set(self.intents)==set(PHASES)
            and all(digest(self.intents[p])==self.intent_hashes[p] for p in PHASES),
            'IMMUTABLE_PHASE_ADAPTER_OR_INTENT_DRIFT')
        check(self.authenticate(self.raw) is True,'CURRENT_EXTERNAL_SIGNATURE_AND_POLICY_REQUIRED')
        check(self.phases==self.t.phases==PHASES and self.profile_hash is self.t.profile_hash is None
            and self.t.execution_profile is None,'CUTOVER_EXECUTOR_PROFILE_DRIFT')
        fields={'schema','issuedAt','expiresAt','creationRequestHash','predecessorHistoryHash',
            'predecessorIncidentRef','sourceClosureHash','phaseIntentHashes','automaticReplayAllowed',
            'databaseRestoreAuthorized','r12ReplayAuthorized','newDistinctLeaseWorkerRequired'}
        authority=self.authority;now=self.clock()
        check(set(authority)==fields|self.additional_authority_fields(),'EXACT_CUTOVER_AUTHORITY_SCOPE_REQUIRED')
        check(authority['schema']=='ouf.semantic-cutover-execution-authority.v1','EXACT_CUTOVER_AUTHORITY_SCHEMA_REQUIRED')
        check(hash_value(authority['sourceClosureHash']),'SIGNED_SOURCE_CLOSURE_HASH_REQUIRED')
        check(type(authority['issuedAt']) is int and type(authority['expiresAt']) is int
            and authority['issuedAt']<=now<authority['expiresAt'] and 0<authority['expiresAt']-authority['issuedAt']<=3600,
            'FINITE_CURRENT_CUTOVER_AUTHORITY_REQUIRED')
        check(authority['phaseIntentHashes']==self.intent_hashes,'SIGNED_PHASE_INTENT_DRIFT')
        check(all(authority[k] is False for k in ('automaticReplayAllowed','databaseRestoreAuthorized','r12ReplayAuthorized'))
            and authority['newDistinctLeaseWorkerRequired'] is True,'CUTOVER_REPLAY_RESTORE_OR_WORKER_POLICY_DRIFT')
        check(self.authority_hash==row['transitionAuthorityEvidenceHash'] and all(authority[k]==row[k]
            for k in ('creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')),
            'CUTOVER_AUTHORITY_HISTORY_OR_REQUEST_DRIFT')
        proof=self.checkpoint(phase,point,row)
        check(type(proof) is dict and set(proof)=={'schema','phase','point','journalVersion','intentHash',
            'authorityHash','sourceClosureHash','nativeEvidenceHash'},'EXACT_NATIVE_CHECKPOINT_RECEIPT_REQUIRED')
        check(proof=={**proof,'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
            'journalVersion':row['version'],'intentHash':self.intent_hashes[phase],'authorityHash':self.authority_hash,
            'sourceClosureHash':authority['sourceClosureHash']},'CURRENT_NATIVE_CHECKPOINT_BINDING_DRIFT')
        check(hash_value(proof['nativeEvidenceHash']),'NATIVE_CHECKPOINT_EVIDENCE_HASH_REQUIRED')
        return digest(proof)
