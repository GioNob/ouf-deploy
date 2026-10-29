"""Assemble the thirteen discovery phases under one current signed cutover.

No CLI, authority issuance, historical provider start, retry or native defaults.
The sealed installer must supply actual scoped transport and distinct-worker
owners; construction or fixture qualification does not implement those owners.
The existing eleven-phase FileOnlyProfile path remains unchanged.
"""
import copy,hashlib
from transition_journal import Transition,PHASES,digest,require
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from engine_creation import Engine
from native_evidence_store import NativeEvidenceStore
from gated_creation_plan import ENTRY
from gated_process_observation import GatedProcessObservation
from gated_stage_adapter import GatedStageAdapter
from gated_release_adapter import GatedReleaseAdapter
from application_verification_adapter import ApplicationReadinessChannel,ApplicationVerificationAdapter
from producer_release_adapter import ProducerReleaseAdapter
from core_adapter_factory import configure_owned_core
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile
from tools.m2_discovery_installation_profile.node_owner import DiscoveryNodeOwner
from tools.semantic_provider_deployment_authentication import decode

INFRASTRUCTURE_PHASES=('INSTALL_AUTHENTICATED_TRANSPORT','START_DISTINCT_LEASE_WORKER')


def scoped_owner(owner,phase,transition,store,authority,raw,request_hash,intent_hash):
    """A source-sealed native owner shares the exact action and evidence store.

    This is an internal assembly interface, never proof of native admission or
    an API allowing an untrusted caller to register arbitrary phase callbacks.
    Actual effect/reconciliation is owned by the independently sealed backend.
    """
    require(getattr(owner,'phase',None)==phase
        and getattr(owner,'transition',None) is transition
        and getattr(owner,'store',None) is store
        and getattr(owner,'authority',None) is authority
        and getattr(owner,'authority_raw',None)==raw
        and getattr(owner,'request_hash',None)==request_hash
        and getattr(owner,'intent_hash',None)==intent_hash
        and callable(getattr(owner,'apply',None)) and callable(getattr(owner,'observe',None)),
        'SHARED_SIGNED_DISCOVERY_INFRASTRUCTURE_OWNER_REQUIRED')


class DiscoveryApplication:
    def __init__(self,*,engine,transition,request,intents,store,before_store,admin,
                 retirement_channel,retirement_before_store,profile,authority,authority_raw,
                 verifier,attestation_signer,token_owner,node_recipe,node_directory,
                 readiness_scope,checkpoint,phase_checkpoint,backup_checkpoint,
                 infrastructure_owners,node_owner=None):
        require(type(profile) is DiscoveryProfile and type(transition) is Transition
            and transition.execution_profile is None and transition.profile_hash is None
            and transition.phases==PHASES and type(authority) is CutoverAuthority
            and authority.execution_profile is None and authority.profile_hash is None
            and authority.verifier is verifier and request.get('Entrypoint')==ENTRY,
            'EXACT_FULL_DISCOVERY_TRANSITION_AND_AUTHORITY_REQUIRED')
        require(type(engine) is Engine and type(store) is NativeEvidenceStore
            and type(before_store) is NativeEvidenceStore and store.root!=before_store.root
            and type(intents) is dict and set(intents)==set(PHASES)
            and type(infrastructure_owners) is dict and set(infrastructure_owners)==set(INFRASTRUCTURE_PHASES)
            and len({id(v) for v in infrastructure_owners.values()})==2
            and all(callable(v) for v in (checkpoint,phase_checkpoint,backup_checkpoint)),
            'COMPLETE_DISTINCT_DISCOVERY_OWNERS_AND_NATIVE_CHECKPOINTS_REQUIRED')
        profile_hash=profile.verify(request);request_hash=digest(request)
        require(intents['CREATE_REPLACEMENT']==request
            and authority.expected['creationRequestHash']==request_hash,
            'DISCOVERY_CREATION_AUTHORITY_OR_INTENT_DRIFT')
        signed=decode(authority_raw,131072)
        row=transition.read()
        require(signed.get('schema')=='ouf.semantic-cutover-execution-authority.v1'
            and signed.get('creationRequestHash')==request_hash==row['creationRequestHash']
            and signed.get('sourceClosureHash')==authority.expected['sourceClosureHash']
            and signed.get('phaseIntentHashes')=={p:digest(intents[p]) for p in PHASES}
            and signed.get('newDistinctLeaseWorkerRequired') is True
            and all(signed.get(k) is False for k in ('automaticReplayAllowed','databaseRestoreAuthorized','r12ReplayAuthorized'))
            and row['transitionAuthorityEvidenceHash']==hashlib.sha256(authority_raw).hexdigest(),
            'EXACT_SIGNED_THIRTEEN_PHASE_DISCOVERY_ACTION_REQUIRED')
        self.profile,self.profile_hash,self.request=profile,profile_hash,copy.deepcopy(request)
        self.transition,self.authority,self.raw,self.store=transition,authority,authority_raw,store
        self.request_hash,self.raw_hash=request_hash,hashlib.sha256(authority_raw).hexdigest()
        self.intents=copy.deepcopy(intents);self.intent_hashes={p:digest(i) for p,i in intents.items()}
        self.authority_scope_hash=digest({'expected':authority.expected,'context':authority.context})
        self.infrastructure_owners=dict(infrastructure_owners)
        self.owner_identity={p:id(o) for p,o in infrastructure_owners.items()}
        self.verify_scope()
        def native(phase):
            def check(point):
                self.verify_scope()
                return phase_checkpoint(phase,point,transition.read())
            return check
        def checked_checkpoint(phase,point,current):
            self.verify_scope()
            return checkpoint(phase,point,current)
        process=GatedProcessObservation(self.request)
        stage=GatedStageAdapter(engine,transition,self.request,store,process,native('STAGE_PAUSED_REPLACEMENT'))
        release=GatedReleaseAdapter(engine,transition,self.request,store,before_store,process,native('START_REPLACEMENT'))
        if node_owner is None:
            node=DiscoveryNodeOwner(engine,transition,self.request,self.intents['ATTEST_NEW_OCI_PEER'],store,profile,
                token_owner,authority,authority_raw,verifier,attestation_signer,node_recipe,node_directory)
        else:
            require(type(node_owner) is DiscoveryNodeOwner and node_owner.engine is engine
                and node_owner.transition is transition and node_owner.store is store
                and node_owner.authority is authority and node_owner.raw==authority_raw
                and node_owner.profile is profile and node_owner.token_owner is token_owner
                and node_owner.verifier is verifier and node_owner.signer is attestation_signer
                and node_owner.recipe==node_recipe and node_owner.root==__import__('pathlib').Path(node_directory)
                and node_owner.request==self.request
                and node_owner.intent==self.intents['ATTEST_NEW_OCI_PEER'],
                'EXACT_SHARED_PRECONSTRUCTED_DISCOVERY_NODE_OWNER_REQUIRED')
            node=node_owner
        readiness=ApplicationReadinessChannel(readiness_scope)
        owners={**self.infrastructure_owners,'ATTEST_NEW_OCI_PEER':node,
            'VERIFY_APPLICATION':ApplicationVerificationAdapter(engine,transition,self.request,self.intents['VERIFY_APPLICATION'],
                store,readiness,native('VERIFY_APPLICATION')),
            'RELEASE_PRODUCERS':ProducerReleaseAdapter(engine,transition,self.request,self.intents['RELEASE_PRODUCERS'],
                self.intents['QUIESCE_PRODUCERS'],store,before_store,readiness,native('RELEASE_PRODUCERS'))}
        adapters=configure_owned_core(engine,transition,self.request,store,admin,self.intents,owners,backup_checkpoint,
            retirement_channel,retirement_before_store,stage,release,execution_profile=None)
        self.executor=Executor(transition,authority_raw,authority,checked_checkpoint,adapters,self.intents,authority.clock)
        self.node_owner=node

    def verify_scope(self):
        require(type(self.profile) is DiscoveryProfile and self.profile.verify(self.request)==self.profile_hash
            and digest(self.request)==self.request_hash
            and self.transition.execution_profile is None and self.transition.phases==PHASES
            and self.authority.execution_profile is None
            and hashlib.sha256(self.raw).hexdigest()==self.raw_hash
            and digest({'expected':self.authority.expected,'context':self.authority.context})==self.authority_scope_hash
            and set(self.intents)==set(PHASES)
            and {p:digest(i) for p,i in self.intents.items()}==self.intent_hashes
            and set(self.infrastructure_owners)==set(INFRASTRUCTURE_PHASES),
            'DISCOVERY_APPLICATION_ASSEMBLY_SCOPE_DRIFT')
        for phase,owner in self.infrastructure_owners.items():
            require(id(owner)==self.owner_identity[phase],'DISCOVERY_INFRASTRUCTURE_OWNER_REPLACED')
            scoped_owner(owner,phase,self.transition,self.store,self.authority,self.raw,
                self.request_hash,self.intent_hashes[phase])

    def verify_registry_and_hold(self):
        """Hold after VERIFY_APPLICATION; dependent producers remain quiesced."""
        self.verify_scope()
        return self.executor.run(PHASES.index('VERIFY_APPLICATION')+1)

    def release_after_cohort_verification(self):
        """Current sealed checkpoint must prove the complete cohort before release."""
        self.verify_scope();row=self.transition.read()
        require(row['nextPhase']>=PHASES.index('RELEASE_PRODUCERS')
            and row['state'] in ('READY','IN_FLIGHT','COMPLETED'),
            'DISCOVERY_REGISTRY_VERIFIED_AND_FULL_COHORT_CHECKPOINT_REQUIRED')
        return self.executor.run()
