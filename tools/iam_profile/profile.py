"""Validation of the closed T2 projection. No IAM access or credential resolution."""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


CONFIG = Path(__file__).resolve().parents[2] / "config" / "iam-profile"
SCHEMA = json.loads((CONFIG / "profile.schema.json").read_text(encoding="utf-8"))
ACTIONS = ("issue", "dispatch", "revoke", "status")
RENEW = "ouf.analysis.mandate.renewal-check"
THS = {"ouf.analysis.renewal.read", "ouf.analysis.renewal.decide"}
POOLS = ("Gateway", "MCP", "DB", "Semantic")


class Invalid(ValueError):
    """The message is a stable public code, never an input value."""


def require(condition, code):
    if not condition:
        raise Invalid(code)


def exact(value, keys, code):
    require(type(value) is dict and value.keys() == set(keys), code)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise Invalid("JSON_INVALID") from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "JSON_INVALID")
        return result

    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: require(False, "JSON_INVALID"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise Invalid("JSON_INVALID") from None


def materialize(template, parameters):
    """Whole-value substitution preserves integer types. The template is never executable."""
    require(type(parameters) is dict, "PARAMETERS_INVALID")
    used = set()

    def substitute(node):
        if isinstance(node, dict):
            return {key: substitute(value) for key, value in node.items()}
        if isinstance(node, list):
            return [substitute(value) for value in node]
        if isinstance(node, str) and node.startswith("${") and node.endswith("}"):
            key = node[2:-1]
            require(key in parameters, "PARAMETERS_INVALID")
            used.add(key)
            return parameters[key]
        return node

    result = substitute(template)
    require(used == parameters.keys(), "PARAMETERS_INVALID")
    return result


def https(value):
    try:
        parsed = urlsplit(value)
        return (value.startswith("https://") and parsed.hostname and parsed.port != 0
                and not re.search(r"[\s\\?#@\x00-\x1f\x7f]", value)
                and not parsed.netloc.endswith(":"))
    except ValueError:
        return False


def resolved(rule):
    if "$ref" in rule:
        return SCHEMA["$defs"][rule["$ref"].split("/")[-1]]
    return rule


def check_schema(value, rule, code="PROFILE_INVALID"):
    """Evaluate the keywords used by the bundled schema, without remote resolution."""
    rule = resolved(rule)
    if "const" in rule:
        require(value == rule["const"], code)
    if "enum" in rule:
        require(value in rule["enum"], code)
    kind = rule.get("type")
    if kind == "object":
        exact(value, rule["required"], code)
        for key, child in rule["properties"].items():
            check_schema(value[key], child, code)
    elif kind == "integer":
        require(type(value) is int and value >= rule["minimum"]
                and ("maximum" not in rule or value <= rule["maximum"]), code)
    elif kind == "string":
        require(type(value) is str, code)
        if rule.get("format") == "uri":
            require(https(value), "HTTPS_REQUIRED")
        else:
            require(re.fullmatch(rule["pattern"], value) is not None, code)
    elif kind == "array":
        require(type(value) is list and rule["minItems"] <= len(value) <= rule["maxItems"],
                "SCOPES_INVALID")
        for item in value:
            check_schema(item, rule["items"], "SCOPES_INVALID")
        require(len(set(value)) == len(value), "SCOPES_INVALID")
        if "contains" in rule:
            require(rule["contains"]["const"] in value, "SCOPES_INVALID")


def validate(profile, bindings):
    """Validate against the independent Gateway scope/audience projection."""
    check_schema(profile, SCHEMA)
    exact(bindings, ("gatewayAudience", "scopeByAction"), "BINDINGS_INVALID")
    actions = bindings["scopeByAction"]
    exact(actions, ACTIONS, "BINDINGS_INVALID")
    for value in actions.values():
        check_schema(value, SCHEMA["$defs"]["scope"], "BINDINGS_INVALID")
    require(not (set(actions.values()) & (THS | {RENEW})), "BINDINGS_INVALID")
    mcp, ths = (profile["clients"][key] for key in ("mcp", "ths"))
    require(mcp["clientId"] != ths["clientId"], "CLIENTS_NOT_DISTINCT")
    # The assignment resource-server (55h verifier) has its own service account.
    require(profile["grant"]["resourceServer"]["clientId"] not in (mcp["clientId"], ths["clientId"]),
            "CLIENTS_NOT_DISTINCT")
    require(set(mcp["scopes"]) == set(actions.values()) | {RENEW}, "SCOPES_INVALID")
    audience = profile["trust"]["gatewayAudience"]
    require(audience == bindings["gatewayAudience"] == mcp["audience"] == ths["audience"],
            "AUDIENCE_MISMATCH")
    require(urlsplit(profile["trust"]["gatewayOrigin"]).path in ("", "/"), "GATEWAY_ORIGIN_INVALID")
    limits = [profile["grant"]["revocationTtlSeconds"], *profile["iam"].values(),
              *(p["dataSlots"] for p in profile["pools"].values())]
    for limit in limits:
        require(max(limit["value"], limit["default"]) <= limit["maximum"], "LIMIT_INVALID")


def fields(obj, prefix=""):
    for key, value in obj.items():
        path = prefix + key
        if type(value) is dict:
            yield from fields(value, path + ".")
        else:
            yield path, value

