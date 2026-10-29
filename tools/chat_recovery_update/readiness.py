"""Readiness response contracts for the pending UDP/MCP update.

Pure response classification only: this module grants no transport or runtime
authority. The sealed owner must supply bytes from its reviewed endpoint and
persist retry state before another read. It does not retry mutations.
"""
import json
import math
import re
from email.utils import parsedate_to_datetime

CONTRACTS = frozenset(("spring-readiness", "empty-204"))
TRANSIENT = frozenset((429, 502, 503, 504))
MAXIMUM_BYTES = 65536

class ReadinessDenied(ValueError):
    pass

def require(condition, code):
    if not condition:
        raise ReadinessDenied(code)

def classify(contract, status, body, *, retry_after=None, now):
    """Return APPLIED/TRANSIENT; reject unproven and permanent responses."""
    require(contract in CONTRACTS, "UNKNOWN_READINESS_CONTRACT")
    require(type(status) is int and 100 <= status <= 599,
            "INVALID_HTTP_STATUS")
    require(type(body) is bytes and len(body) <= MAXIMUM_BYTES,
            "READINESS_RESPONSE_BOUND_EXHAUSTED")
    require(type(now) in (int, float) and math.isfinite(now),
            "FINITE_OBSERVATION_TIME_REQUIRED")
    if status in TRANSIENT:
        require(retry_after is None or
                type(retry_after) is str and len(retry_after) <= 128,
                "READINESS_RETRY_AFTER_REQUIRES_REVIEW")
        value = "0" if retry_after is None else retry_after.strip()
        if re.fullmatch(r"[0-9]{1,6}", value):
            delay = int(value)
        else:
            try:
                date = parsedate_to_datetime(value)
                require(date.tzinfo is not None,
                        "READINESS_RETRY_AFTER_REQUIRES_REVIEW")
                delay = max(0, date.timestamp() - now)
            except (ValueError, TypeError, OverflowError):
                raise ReadinessDenied(
                    "READINESS_RETRY_AFTER_REQUIRES_REVIEW") from None
        require(math.isfinite(delay) and delay >= 0,
                "READINESS_RETRY_AFTER_REQUIRES_REVIEW")
        # Never truncate Retry-After to fit the owner budget: the owner pauses
        # if this wait cannot fit its existing authority/deadline.
        return "TRANSIENT", {"retryAfterSeconds": delay}
    if contract == "empty-204":
        require(status == 204 and body == b"",
                "READINESS_PERMANENT_FAILURE")
    else:
        require(status == 200, "READINESS_PERMANENT_FAILURE")
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            raise ReadinessDenied("READINESS_BODY_INVALID") from None
        require(type(value) is dict and value.get("status") == "UP",
                "READINESS_NOT_PROVEN")
    return "APPLIED", {"httpStatus": status}
