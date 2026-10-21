"""Prospective finite-lease scheduler; never grants or re-arms authority.

The installation must seal this source in a NEW reviewed worker closure. It is
not an override for the consumed R9 process. Kernel expiry predicates stay strict.
"""
import ipaddress
import math
import time


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def window(coordinator, poll_seconds, *, clock=time.monotonic):
    """Bound the next wakeup by actual TTL, subtracting the entire read window."""
    flows = coordinator.configuration['providerFlows']
    require(type(poll_seconds) is int and 1 <= poll_seconds <= 300 and bool(flows),
            'BOUNDED_LEASE_POLL_REQUIRED')
    with coordinator.hold_lock():
        before = clock()
        journal = coordinator.journal()
        require(journal['state'] == 'LEASE_READY' and journal['leaseAuthorized'] is True
                and journal['startAuthorized'] is False, 'CURRENT_LEASE_AUTHORITY_REQUIRED')
        backend = coordinator.owner.backend
        backend.verify_ownership(coordinator.configuration)
        sets = backend.read_sets(coordinator.configuration)
        require(set(sets) == {(f, i) for f in ('inet', 'bridge') for i in range(len(flows))},
                'EXACT_LEASE_SET_BINDING_REQUIRED')
        ttls = []
        for i, flow in enumerate(flows):
            left, right = sets['inet', i], sets['bridge', i]
            require(bool(left) and set(left) == set(right) and len(left) <= 32
                    and set(left).issubset(set(journal['leaseAddresses'][i])),
                    'CURRENT_APPROVED_TWO_FAMILY_MEMBERSHIP_REQUIRED')
            for text in left:
                address = ipaddress.ip_address(text)
                require(str(address) == text and address.version == ipaddress.ip_address(flow['source']).version
                        and not (address.is_loopback or address.is_link_local or address.is_multicast
                                 or address.is_unspecified or address.is_reserved)
                        and (address.is_global or text in flow['allowedPrivateAddresses']),
                        'CURRENT_LEASE_ADDRESS_REQUIRED')
            for ttl in (*left.values(), *right.values()):
                require(type(ttl) in (int, float) and math.isfinite(ttl)
                        and 0 < ttl <= flow['leaseSeconds'], 'POSITIVE_FINITE_KERNEL_TTL_REQUIRED')
                ttls.append(ttl)
        backend.verify_ownership(coordinator.configuration)
        require(coordinator.journal() == journal, 'LEASE_JOURNAL_CHANGED_DURING_SCHEDULE')
        after = clock()
        require(math.isfinite(before) and math.isfinite(after) and 0 <= before <= after,
                'MONOTONIC_READ_WINDOW_REQUIRED')
        # A reported kernel TTL can have been sampled at any point during the
        # bounded read. Anchoring at its START is a conservative lower bound.
        deadline = before + min(ttls)
        remaining = deadline - after
        require(remaining > 0, 'LEASE_READ_WINDOW_EXHAUSTED')
        return {'deadlineMonotonic': deadline,
                'waitSeconds': min(poll_seconds, remaining / 2),
                'remainingSecondsLowerBound': remaining}


def supervise(coordinator, check_configuration, poll_seconds, stop, *, log=print, clock=time.monotonic):
    """Fresh DNS each cycle, adaptive wakeup, fail closed on expiry or drift."""
    try:
        check_configuration()
        if not stop.is_set():
            coordinator.fresh_start()
            log('SEMANTIC_COORDINATED_START=PASS OLD_SETS_REVOKED=true FRESH_DNS=true START_AUTHORIZED=false', flush=True)
            while True:
                next_window = window(coordinator, poll_seconds, clock=clock)
                if stop.wait(next_window['waitSeconds']):
                    break
                require(clock() < next_window['deadlineMonotonic'], 'LEASE_SCHEDULER_WAKE_DEADLINE_MISSED')
                check_configuration()
                require(clock() < next_window['deadlineMonotonic'], 'LEASE_CONFIGURATION_CHECK_DEADLINE_MISSED')
                coordinator.refresh()
                log('SEMANTIC_COORDINATED_CYCLE=PASS FRESH_DNS=true COMMON_LOCK=true ADAPTIVE_TTL_WAKE=true', flush=True)
    finally:
        coordinator.quiesce()
        log('SEMANTIC_COORDINATED_STOP=PASS SETS_REVOKED=true REAUTHORIZATION_REQUIRED=true', flush=True)
