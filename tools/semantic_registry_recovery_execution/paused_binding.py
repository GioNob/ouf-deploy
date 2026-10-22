"""Current paused native binding for the distinct Registry recovery journal.

No original Transition is constructed, modified or replayed. The existing
complete OCI/frame observers may consume this exact typed binding; it grants
neither node acceptance nor a signature. Only the durably captured first start
generation, followed by the separately completed pause, can be observed here.
"""
import copy,time
from pathlib import Path
from .core import require,digest,validate_plan,generation,validate_current
from .lifecycle import Lifecycle

def profile_type():
    from file_only_profile import FileOnlyProfile
    return FileOnlyProfile

class RecoveryPausedBinding:
    def __init__(self,lifecycle,profile):
        require(type(lifecycle) is Lifecycle and type(profile) is profile_type(),
                'TYPED_RECOVERY_PAUSED_BINDING_REQUIRED')
        self.lifecycle,self.execution_profile=lifecycle,profile
        self.plan_hash=validate_plan(lifecycle.plan)
        self.request_hash=digest(lifecycle.request)
        self.profile_hash=profile.verify(lifecycle.request)
        self.current_row()

    def current_row(self):
        native=self.lifecycle
        require(validate_plan(native.plan)==self.plan_hash
                and digest(native.request)==self.request_hash
                and self.execution_profile.verify(native.request)==self.profile_hash,
                'RECOVERY_PAUSED_SCOPE_CHANGED')
        row=native.store.read()
        boot=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        validate_current(native.plan,row,boot,(time.time(),time.monotonic()))
        native.authority.guard(row)
        require(row['state']=='IN_FLIGHT' and row['nextStage'] in (4,5,6,7)
                and len(row['effects'])==row['nextStage']+1,
                'CURRENT_RECOVERY_PAUSED_CHECKPOINT_REQUIRED')
        start,pause=row['effects'][1],row['effects'][3]
        require(start['stage']=='START_NEW_WAIT_GATE' and pause['stage']=='PAUSE_NEW_WAIT_GATE'
                and start['state']==pause['state']=='APPLIED'
                and start.get('nativeRequestAttempted') is True and start.get('nativeResponse204') is True
                and pause.get('nativeRequestAttempted') is True and pause.get('nativeResponse204') is True,
                'DURABLE_SEPARATE_START_AND_PAUSE_REQUIRED')
        fresh=generation(row['newGeneration'])
        first=start.get('nativeFirstProcess')
        require(type(first) is dict and first.get('newGeneration')==fresh
                and first.get('processKind')=='GATE_WAITING' and first.get('paused') is False
                and start['nativeEvidence'].get('durableNativeStartEvidence') is True
                and start['nativeEvidence'].get('newGeneration')==fresh
                and pause['nativeEvidence'].get('newGeneration')==fresh
                and pause['nativeEvidence'].get('processKind')=='GATE_WAITING'
                and pause['nativeEvidence'].get('paused') is True
                and first.get('startedAt')==start['nativeEvidence'].get('startedAt')
                    ==pause['nativeEvidence'].get('startedAt'),
                'FIRST_DURABLE_RECOVERY_GENERATION_AND_PAUSE_PROOF_REQUIRED')
        return row

    def observe(self):
        before=self.current_row();native=self.lifecycle
        actual=native.inspect();proof=native.process_evidence(actual)
        require(actual['State']['Status']=='paused' and proof['paused'] is True
                and proof['processKind']=='GATE_WAITING'
                and proof['newGeneration']==before['newGeneration']
                and proof['startedAt']==before['effects'][1]['nativeFirstProcess']['startedAt'],
                'CURRENT_SAME_PAUSED_RECOVERY_GATE_REQUIRED')
        binding=native.engine.runtime_binding(actual)
        # Native Engine binding includes image/configuration/network identity.
        # Observe again after the kernel generation check and compare full pins.
        after=native.inspect();again=native.process_evidence(after)
        require(after['State']['Status']=='paused' and again==proof
                and native.engine.runtime_binding(after)==binding
                and self.current_row()==before,'RECOVERY_PAUSED_CHANGED_DURING_OBSERVATION')
        return {'schema':'ouf.semantic-paused-workload-binding.v1',
                'transitionContextHash':before['logicalOperationRef'],
                'creationRequestHash':self.request_hash,
                'stageEvidenceHash':before['effects'][3]['nativeEvidenceHash'],
                'runtimeBinding':copy.deepcopy(binding),'engineState':'paused',
                'ociAccepted':False,'rootfsAccepted':False,'peerAccepted':False,
                'signaturesIssued':0,'startAuthorized':False}

    def verify_runc_state(self,state,observation):
        fresh=self.observe();require(fresh==observation,'RECOVERY_PAUSED_OBSERVATION_STALE')
        binding=fresh['runtimeBinding']
        require(type(state) is dict and state.get('id')==binding['containerId']
                and state.get('status')=='paused' and state.get('pid')==binding['pid'],
                'EXACT_RECOVERY_RUNC_AND_ENGINE_PAUSED_IDENTITY_REQUIRED')
        return {'stateContract':'RUNC_PAUSED_ENGINE_PAUSED','containerId':binding['containerId'],
                'pid':binding['pid'],'pausedBindingHash':digest(fresh),
                'completeCreationAccepted':False}
