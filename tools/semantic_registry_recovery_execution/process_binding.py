"""Same new recovery generation after unpause, before/after its release signal."""
import copy
from .core import require,digest
from .lifecycle import Lifecycle
from file_only_profile import FileOnlyProfile

class RecoveryProcessBinding:
    def __init__(self,lifecycle,profile):
        require(type(lifecycle) is Lifecycle and type(profile) is FileOnlyProfile,
            'TYPED_ACTIVE_RECOVERY_PROCESS_BINDING_REQUIRED')
        self.lifecycle,self.execution_profile=lifecycle,profile
        self.profile_hash=profile.verify(lifecycle.request)
    def observe(self):
        native=self.lifecycle;before=native.journal();cursor=before['nextStage']
        require(self.execution_profile.verify(native.request)==self.profile_hash
            and before['state']=='IN_FLIGHT' and cursor in (7,8,9,10,11),
            'CURRENT_ACTIVE_RECOVERY_CHECKPOINT_REQUIRED')
        # Cursor7 can be the observation after the independently claimed
        # unpause; all later cursors must retain that completed exact effect.
        unpause=before['effects'][7]
        require(unpause['stage']=='UNPAUSE_ATTESTED_GENERATION'
            and unpause.get('nativeRequestAttempted') is True
            and (unpause['state']=='APPLIED' or cursor==7),
            'DURABLE_SAME_RECOVERY_UNPAUSE_REQUIRED')
        allowed={'GATE_WAITING'}
        if cursor>=10:allowed={'APPLICATION_RUNNING'}
        elif cursor==9 and before['effects'][9].get('nativeRequestAttempted') is True:
            allowed={'GATE_WAITING','APPLICATION_RUNNING'}
        actual=native.inspect();proof=native.process_evidence(actual)
        require(actual['State']['Status']=='running' and proof['paused'] is False
            and proof['newGeneration']==before['newGeneration'] and proof['processKind'] in allowed
            and proof['startedAt']==before['effects'][1]['nativeFirstProcess']['startedAt'],
            'CURRENT_SAME_ACTIVE_RECOVERY_PROCESS_REQUIRED')
        binding=native.runtime_binding(actual)
        following=native.inspect();again=native.process_evidence(following)
        require(following['State']['Status']=='running' and again==proof
            and native.runtime_binding(following)==binding and native.journal()==before,
            'ACTIVE_RECOVERY_PROCESS_CHANGED_DURING_OBSERVATION')
        return {'schema':'ouf.semantic-registry-recovery-active-process-binding.v1',
            'logicalOperationRef':before['logicalOperationRef'],
            'runtimeBindingProfile':'MOUNTS_SORTED_BY_DESTINATION_V1',
            'runtimeBinding':copy.deepcopy(binding),'process':proof,
            'signaturesIssued':0,'runtimeAuthorityIssued':False}
