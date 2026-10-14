"""Concrete Registry subtransaction for the single reviewed cohort action.

The aggregate installer owns source/command/native checkpoints and the other
five deployments. Hold after Registry verification; release inventoried producers
only when that same installer proves the complete cohort ready. No CLI invents a
mandate or treats a component receipt as chatbot end-to-end acceptance.
"""
from transition_journal import require,digest
from cutover_executor import Executor
from cutover_authority import CutoverAuthority
from file_only_profile import FileOnlyProfile,PHASES
from file_only_node_owner import FileOnlyNodeOwner
from application_verification_adapter import ApplicationReadinessChannel,ApplicationVerificationAdapter
from producer_release_adapter import ProducerReleaseAdapter
from core_adapter_factory import configure_owned_core
from gated_process_observation import GatedProcessObservation
from gated_stage_adapter import GatedStageAdapter
from gated_release_adapter import GatedReleaseAdapter
from gated_creation_plan import ENTRY

class FileOnlyApplication:
    def __init__(self,*,engine,transition,request,intents,store,before_store,admin,
                 retirement_channel,retirement_before_store,profile,authority,authority_raw,
                 verifier,attestation_signer,token_owner,node_recipe,node_directory,
                 readiness_scope,checkpoint,phase_checkpoint,backup_checkpoint):
        require(type(profile) is FileOnlyProfile and transition.execution_profile is profile
            and type(authority) is CutoverAuthority and authority.execution_profile is profile
            and authority.verifier is verifier and request.get('Entrypoint')==ENTRY,
            'EXACT_GATED_FILE_ONLY_SHARED_AUTHORITY_REQUIRED')
        require(type(intents) is dict and set(intents)==set(PHASES)
            and callable(checkpoint) and callable(phase_checkpoint) and callable(backup_checkpoint),
            'COMPLETE_COHORT_OWNED_NATIVE_CHECKPOINTS_REQUIRED')
        profile.verify(request)
        def native(phase):return lambda point:phase_checkpoint(phase,point,transition.read())
        process=GatedProcessObservation(request)
        stage=GatedStageAdapter(engine,transition,request,store,process,native('STAGE_PAUSED_REPLACEMENT'))
        release=GatedReleaseAdapter(engine,transition,request,store,before_store,process,native('START_REPLACEMENT'))
        node=FileOnlyNodeOwner(engine,transition,request,intents['ATTEST_NEW_OCI_PEER'],store,profile,token_owner,authority,authority_raw,
            verifier,attestation_signer,node_recipe,node_directory)
        readiness=ApplicationReadinessChannel(readiness_scope)
        owners={'ATTEST_NEW_OCI_PEER':node,
            'VERIFY_APPLICATION':ApplicationVerificationAdapter(engine,transition,request,intents['VERIFY_APPLICATION'],store,readiness,native('VERIFY_APPLICATION')),
            'RELEASE_PRODUCERS':ProducerReleaseAdapter(engine,transition,request,intents['RELEASE_PRODUCERS'],intents['QUIESCE_PRODUCERS'],store,
                before_store,readiness,native('RELEASE_PRODUCERS'))}
        self.executor=Executor(transition,authority_raw,authority,checkpoint,
            configure_owned_core(engine,transition,request,store,admin,intents,owners,backup_checkpoint,retirement_channel,
                retirement_before_store,stage,release,execution_profile=profile),intents,authority.clock)
        self.transition=transition
    def verify_registry_and_hold(self):
        """Advance/reconcile through VERIFY_APPLICATION; do not release consumers."""
        return self.executor.run(PHASES.index('VERIFY_APPLICATION')+1)
    def release_after_cohort_verification(self):
        """The sealed current checkpoint must prove the reviewed full cohort ready."""
        row=self.transition.read()
        require(row['nextPhase']>=PHASES.index('RELEASE_PRODUCERS') and row['state'] in ('READY','IN_FLIGHT','COMPLETED'),
            'REGISTRY_VERIFIED_AND_FULL_COHORT_CHECKPOINT_REQUIRED')
        return self.executor.run()
