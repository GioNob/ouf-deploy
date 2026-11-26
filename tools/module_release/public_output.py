"""The release's private inputs stay in memory. Scrub values when returning results to a caller."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import re
from urllib.parse import unquote

from .contract import digest, require
from .profile_options import credential_name


_values = ContextVar("module_release_secrets", default=None)


# Keep both the encoded spelling and the password interpreted by the DSN consumer.
_url_password = re.compile(r"://[^/@?#\s:]*:([^/@?#\s]+)@|oracle:thin:[^/@\s]+/([^@\s]+)@", re.I)
_property_password = re.compile(r"""(?:^|[?&;\s])(?:sslpassword|password)\s*=\s*(?:'((?:\\.|[^'\\])*)'|((?:\\.|[^\s\\])+))""", re.I)


def dsn_values(text):
    for match in _url_password.finditer(text):
        raw = match[1] or match[2]
        yield raw
        yield unquote(raw)
    for match in _property_password.finditer(text):
        raw = match[1] if match[1] is not None else match[2]
        if match[2] and match[0][0] in "?&;":
            raw = re.split("[&;#]", raw, maxsplit=1)[0]
        if raw:
            yield raw
            yield unquote(re.sub(r"\\(.)", r"\1", raw))


def private_inputs(value, sensitive=False):
    """Collect credential values, including structured ENV and label values."""
    if isinstance(value, dict):
        for name, item in value.items():
            credential = credential_name(name)
            yield from private_inputs(item, sensitive or credential)
    elif isinstance(value, list):
        for item in value:
            yield from private_inputs(item, sensitive)
    elif isinstance(value, str) and value:
        yield from dsn_values(value)
        if sensitive:
            yield value
        if value.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(value, object_pairs_hook=lambda pairs: [{k: v} for k, v in pairs])
            except (ValueError, RecursionError):
                return
            yield from private_inputs(parsed, sensitive)


def profile_passwords(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from profile_passwords(item)
    elif isinstance(value, list):
        for item in value:
            yield from profile_passwords(item)
    elif isinstance(value, str):
        yield from dsn_values(value)


def secret_values(profile):
    found = set(profile_passwords(profile))
    if not isinstance(profile, dict) or "configDelta" not in profile:
        return found
    shown = profile.get("showValues")
    shown = set(shown) if isinstance(shown, list) and all(isinstance(k, str) for k in shown) else set()
    delta = profile.get("configDelta")
    if isinstance(delta, dict) and isinstance(delta.get("env"), list):
        for row in delta["env"]:
            name = row.get("name") if isinstance(row, dict) else None
            if isinstance(name, str) and not name.endswith("_FILE") and (
                    credential_name(name) or name in shown and name != "SPRING_FLYWAY_ENABLED"):
                found.update(row[k] for k in ("before", "after") if isinstance(row.get(k), str) and row[k])
    found.update(private_inputs(delta))
    return found


def predecessor(doc):
    values = _values.get()
    if values is not None and isinstance(doc, dict):
        config = doc.get("Config") or {}
        values.update(private_inputs(config.get("Labels")))
        for entry in config.get("Env") or ():
            key, _, value = entry.partition("=")
            values.update(private_inputs({key: value}))
    return doc


@contextmanager
def scope(profile):
    # Nested phases share the observations of this dispatch, including on failure.
    values = _values.get()
    if values is None:
        values = set()
    values.update(secret_values(profile))
    token = _values.set(values)
    try:
        yield
    finally:
        _values.reset(token)


def _map_strings(value, transform):
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, (list, tuple)):
        return [_map_strings(item, transform) for item in value]
    if isinstance(value, dict):
        result = {transform(key): _map_strings(item, transform) for key, item in value.items()}
        require(len(result) == len(value), "REDACTED_FIELD_COLLISION")
        return result
    return value


def public(value):
    values = _values.get()
    if not values:
        return value
    if isinstance(value, bytes):
        # A canonical encoding or signature cannot be rewritten after hashing/signing.
        require(all(secret.encode() not in value for secret in values), "REDACTION_COLLISION")
        return value
    replacements = {s: "sha256:" + digest(s) for s in values}
    pattern = re.compile("|".join(map(re.escape, sorted(values, key=lambda s: (-len(s), s)))))

    def replace(text):
        result = pattern.sub(lambda match: replacements[match[0]], text)
        require(not pattern.search(result), "REDACTION_COLLISION")
        return result

    return _map_strings(value, replace)


def select_request(envelope, cfg, stack):
    req = envelope["request"]
    if isinstance(req, dict) and req.get("operation") == "module-release" and isinstance(req.get("module"), str):
        modules = cfg.get("modules") if isinstance(cfg, dict) else None
        if isinstance(modules, dict):
            stack.enter_context(scope(modules.get(req["module"])))
    return req


def json_output(value, *, sort_keys=True):
    raw = json.dumps(public(value), sort_keys=sort_keys, separators=(",", ":")).encode()
    return public(raw)


def release_output(function):
    @wraps(function)
    def run(profile, *args, **kwargs):
        with scope(profile):
            return public(function(profile, *args, **kwargs))
    return run
