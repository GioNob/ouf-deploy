"""Recovery-specific exact binding for the unchanged renewable mount witness.

The original observer still owns all file/mount/token admission checks. Its
optional native binding is supplied only after this constructor has verified the
distinct exact RecoveryPausedBinding; no old Transition/type is impersonated.
"""
from .core import require
from .paused_binding import RecoveryPausedBinding
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation

class RecoveryTokenMountObservation(RenewableTokenMountObservation):
    def __init__(self,expected,owner,deadline,*,pause_binding):
        require(type(pause_binding) is RecoveryPausedBinding,
                'EXACT_RECOVERY_PAUSED_TOKEN_BINDING_REQUIRED')
        super().__init__(expected,owner,deadline)
        self.pause_binding=pause_binding

