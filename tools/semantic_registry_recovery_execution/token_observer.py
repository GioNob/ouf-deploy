"""Closed token-owner selection for fresh Registry recovery only.

The historical installed observer keeps its existing checks. A postboot owner
is a distinct concrete type, bound to this exact recovery lifecycle, and proves
its own current journal/boot/lease. No DomainOwner callback can substitute for
either production observer. Shared mount and historical observers are unchanged.
"""
from .core import require
from .installed_owner import guard_lease as retained_lease
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner


def require_observer(owner, lifecycle=None):
    if type(owner) is InstalledTokenOwner:
        require(owner.observer is True, 'ACTUAL_RETAINED_INSTALLED_OWNER_OBSERVER_REQUIRED')
        return owner
    from tools.semantic_registry_postboot_owner.owner import PostbootTokenOwner
    require(type(owner) is PostbootTokenOwner and owner.observer is True,
            'ACTUAL_CURRENT_BOOT_TOKEN_OWNER_OBSERVER_REQUIRED')
    if lifecycle is not None:
        require(owner.gate_witness.lifecycle is lifecycle,
                'POSTBOOT_TOKEN_OWNER_MUST_BIND_SAME_RECOVERY_LIFECYCLE')
    return owner


def guard_lease(owner, minimum_remaining=None):
    require_observer(owner)
    if type(owner) is InstalledTokenOwner:
        return retained_lease(owner, minimum_remaining)
    return owner.lease(minimum_remaining)
