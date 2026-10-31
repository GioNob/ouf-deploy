"""Recovery-specific exact binding for the unchanged renewable mount witness.

The original observer still owns all file/mount/token admission checks. Its
optional native binding is supplied only after this constructor has verified the
distinct exact RecoveryPausedBinding; no old Transition/type is impersonated.
The recovery reader proves EOF within the original mountinfo byte/deadline
limits: a short procfs read is not an entire mount table.
"""
import os
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

    def mountinfo(self,pid):
        self.guard()
        fd=os.open(f'/proc/{pid}/mountinfo',os.O_RDONLY|os.O_NOFOLLOW)
        try:
            raw=bytearray()
            while True:
                self.guard()
                chunk=os.read(fd,131073-len(raw))
                self.guard()
                raw.extend(chunk)
                require(len(raw)<=131072,'BOUNDED_MOUNTINFO_REQUIRED')
                if not chunk:
                    return bytes(raw)
        finally:
            os.close(fd)
