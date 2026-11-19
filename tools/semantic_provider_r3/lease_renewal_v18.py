"""R3 v18 installation policy, also sealed inside the supervisor closure."""

INPUT = "leaseRenewal"
SCHEMA = "ouf.semantic-provider-lease-supervisor.v2"
INVALID = "R3_LEASE_RENEWAL_INVALID"
INCOMPATIBLE = "R3_LEASE_RENEWAL_BUDGET_INCOMPATIBLE"
# Match the v12 compiler, the finite recovery policy and the nft seconds reader.
MIN_NFT_SECONDS = 2
COMMIT_SECONDS = 1
GUARD_SECONDS = 1
ATTEMPT_SECONDS = 30
REVOCATION_SECONDS = 40


def integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def validate(value):
    if (type(value) is not dict or set(value) != {
            "renewalMarginSeconds", "lockWaitSeconds", "fastRetryCount",
            "fastRetryDelaysSeconds", "healthyResetSeconds"}):
        raise ValueError(INVALID)
    delays = value["fastRetryDelaysSeconds"]
    if not (integer(value["renewalMarginSeconds"], 1, 300)
            and integer(value["lockWaitSeconds"], 1, 20)
            and integer(value["fastRetryCount"], 0, 3)
            and type(delays) is list and len(delays) == value["fastRetryCount"]
            and all(integer(delay, 1, 5) for delay in delays)
            and delays == sorted(delays)
            and integer(value["healthyResetSeconds"], 1, 86400)):
        raise ValueError(INVALID)
    return value


def retry_reserve(profile):
    # The original absolute deadline already excludes the commit margin.
    return profile["timeoutSeconds"] + profile["applyBudgetSeconds"] + GUARD_SECONDS


def compiler_margin(profile):
    return profile["applyBudgetSeconds"] + MIN_NFT_SECONDS


def budgets(value, profile, flows, driver, attempt=ATTEMPT_SECONDS):
    validate(value)
    dns, apply, dns_lease = (profile.get(k) for k in (
        "timeoutSeconds", "applyBudgetSeconds", "maxLeaseSeconds"))
    leases = [flow.get("leaseSeconds") for flow in flows]
    if not (integer(driver, 5, 15) and integer(dns, 1, 30) and integer(apply, 1, 30)
            and integer(dns_lease, 1, 3600) and leases
            and all(integer(lease, 1, 3600) for lease in leases)):
        raise ValueError(INCOMPATIBLE)
    margin, cap = value["renewalMarginSeconds"], value["lockWaitSeconds"]
    # DNS is outside the lock. Budget the configured sequential DNS + lock
    # wait, and independently the driver's whole contention horizon. A cap
    # shorter than the driver budget deliberately abandons a contested attempt.
    required = max(dns + cap, driver) + compiler_margin(profile) + COMMIT_SECONDS + GUARD_SECONDS
    # Allow room for the compiler's apply deduction and integer TTL readback.
    effective_lease = min(dns_lease - apply, *leases)
    # Any configured retry must be possible at least in the best case. Actual
    # admission uses the lower bound measured on both families and runs on the
    # original attempt deadline, including every previous DNS query and wait.
    delays = value["fastRetryDelaysSeconds"]
    if not (required <= margin <= attempt + COMMIT_SECONDS
            and margin + 1 < effective_lease
            and (not delays or sum(delays) + retry_reserve(profile)
                 < min(attempt, effective_lease - COMMIT_SECONDS))):
        raise ValueError(INCOMPATIBLE)
