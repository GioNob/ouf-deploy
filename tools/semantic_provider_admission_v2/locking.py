"""Bounded acquisition of the unchanged, custody-checking common lock."""
from contextlib import contextmanager, ExitStack
import math
import time


class CommonLockTimeout(TimeoutError):
    """Public denial for contention beyond the caller's absolute deadline."""


@contextmanager
def wait_common_lock(path, deadline):
    """Retry acquisition only; never retry errors from the protected operation.

    Each attempt re-enters v1 and repeats all its custody checks. The deadline
    is monotonic and belongs to the caller; retries never replenish its budget.
    """
    from tools.semantic_provider_lease_coordination import hold_common_lock

    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("COMMON_LOCK_DEADLINE_REQUIRED")
    with ExitStack() as stack:
        while True:
            if time.monotonic() >= deadline:
                raise CommonLockTimeout("COMMON_LOCK_TIMEOUT")
            try:
                stack.enter_context(hold_common_lock(path))
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommonLockTimeout("COMMON_LOCK_TIMEOUT") from None
                time.sleep(min(0.05, remaining))
        if time.monotonic() >= deadline:
            raise CommonLockTimeout("COMMON_LOCK_TIMEOUT")
        yield
