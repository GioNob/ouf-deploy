"""Recovery-specific exact binding for the unchanged renewable mount witness.

The original observer still owns all file/mount/token admission checks. Its
optional native binding is supplied only after this constructor has verified the
distinct exact RecoveryPausedBinding; no old Transition/type is impersonated.
"""
from .core import require
from .paused_binding import RecoveryPausedBinding
from .process_binding import RecoveryProcessBinding
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation

class RecoveryTokenMountObservation(RenewableTokenMountObservation):
    def __init__(self,expected,owner,deadline,*,pause_binding=None,running_binding=None):
        require((type(pause_binding) is RecoveryPausedBinding and running_binding is None)
                or (pause_binding is None and type(running_binding) is RecoveryProcessBinding),
                'EXACT_ONE_RECOVERY_TOKEN_PROCESS_BINDING_REQUIRED')
        super().__init__(expected,owner,deadline)
        self.pause_binding=pause_binding
        self.running_binding=running_binding

