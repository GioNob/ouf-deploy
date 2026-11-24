"""Contratto chiuso del manifesto PET C. validate non modifica l'input."""

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit


CONFIG = Path(__file__).resolve().parents[2] / "config" / "pet-c"
SCHEMA = json.loads((CONFIG / "manifest.schema.json").read_text(encoding="utf-8"))
ERROR_CODES = frozenset({
    "INVALID_JSON", "INVALID_MANIFEST", "INVALID_TIME", "WINDOW_TOO_LONG",
    "CAPACITY_NOT_D091", "REAL_PROBE_OVER_CAP", "SITE_MISMATCH",
    "UNSAFE_URL", "INVALID_MIX", "CANDIDATES_REQUIRED", "INVALID_SCOPE",
})


class Refusal(ValueError):
    """Messaggio pubblico limitato a un codice, senza riportare valori privati."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("INVALID_JSON")
        result[key] = value
    return result


def parse(raw):
    def reject(_):
        raise Refusal("INVALID_JSON")

    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=reject)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refusal("INVALID_JSON") from None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def numeric(value):
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _matches(value, spec):
    """Vocabolario strutturale dello schema; i vincoli tra campi sono in validate."""
    if "oneOf" in spec:
        return sum(_matches(value, branch) for branch in spec["oneOf"]) == 1
    if "const" in spec:
        expected = spec["const"]
        return type(value) is type(expected) and value == expected
    if "enum" in spec:
        return value in spec["enum"]
    kind = spec["type"]
    if kind == "object":
        props = spec["properties"]
        return (isinstance(value, dict) and set(spec["required"]) <= value.keys() <= props.keys()
                and all(_matches(item, props[key]) for key, item in value.items()))
    if kind == "array":
        return (isinstance(value, list) and len(value) >= spec["minItems"]
                and all(_matches(item, spec["items"]) for item in value)
                and (not spec.get("uniqueItems") or len(set(value)) == len(value)))
    if kind == "string":
        return isinstance(value, str) and re.fullmatch(spec.get("pattern", ".+"), value) is not None
    return (numeric(value) and (kind == "number" or type(value) is int)
            and spec.get("minimum", -math.inf) <= value <= spec.get("maximum", math.inf)
            and value > spec.get("exclusiveMinimum", -math.inf))


def _safe_url(raw, site):
    if not raw.isascii() or re.search(r"[\s\\@%?#]", raw):
        return False
    try:
        url = urlsplit(raw)
        host = url.hostname
        if not host or url.path not in ("", "/") or url.port == 0 or url.netloc.endswith(":"):
            return False
        authority = f"[{host}]" if ":" in host else host
        if url.port is not None:
            authority += f":{url.port}"
        if url.netloc.lower() != authority:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            label = r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
            if not all(re.fullmatch(label, part) for part in host.split(".")):
                return False
            local = "." not in host
        else:
            if not address.is_loopback:
                return False
            local = True
        return url.scheme == "https" or (site == "B" and local and url.scheme == "http")
    except ValueError:
        return False


def validate(data):
    """Restituisce il manifesto valido oppure solleva Refusal con un codice chiuso."""
    if not isinstance(data, dict):
        raise Refusal("INVALID_MANIFEST")
    props = SCHEMA["properties"]
    if "capacity" in data and not _matches(data["capacity"], props["capacity"]):
        raise Refusal("CAPACITY_NOT_D091")
    provider = data.get("provider")
    if isinstance(provider, dict) and provider.get("mode") == "real-probe":
        for key, cap in (("search", 1), ("fetch", 3)):
            if numeric(provider.get(key)) and provider[key] > cap:
                raise Refusal("REAL_PROBE_OVER_CAP")
    if not _matches(data, SCHEMA):
        raise Refusal("INVALID_MANIFEST")
    site = data["site"]
    rule = SCHEMA["allOf"][0]["then" if site == "A" else "else"]["properties"]
    if not set(data["scenarios"]) <= set(rule["scenarios"]["items"]["enum"]):
        raise Refusal("SITE_MISMATCH")
    if site == "A" and not set(rule["candidates"]["required"]) <= data["candidates"].keys():
        raise Refusal("CANDIDATES_REQUIRED")
    if site == "B" and provider["mode"] != "simulator":
        raise Refusal("SITE_MISMATCH")
    if provider["mode"] == "simulator" and not _safe_url(provider["baseUrl"], site):
        raise Refusal("UNSAFE_URL")
    try:
        start, end = (datetime.fromisoformat(data[k].replace("Z", "+00:00"))
                      for k in ("createdAt", "expiresAt"))
    except ValueError:
        raise Refusal("INVALID_TIME") from None
    if end <= start:
        raise Refusal("INVALID_TIME")
    if site == "A" and end - start > timedelta(hours=8):
        raise Refusal("WINDOW_TOO_LONG")
    if sum(Decimal(str(v)) for v in data["load"]["mix"].values()) != 1:
        raise Refusal("INVALID_MIX")
    if data["load"]["tenants"] != len(data["cleanup"]["tenants"]):
        raise Refusal("INVALID_SCOPE")
    return data
