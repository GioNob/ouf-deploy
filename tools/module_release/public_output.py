"""The release's private inputs stay in memory. Only this projection crosses a journal or public boundary."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import re

from .contract import digest, migration_has_inline_secret, require
from .profile_options import credential_name, delta_has_inline_secret, env_reference, inline_secret


_values = ContextVar("module_release_secrets", default=None)


def private_inputs(value, sensitive=False):
    """Inspect typed profile data before any output, including nested migration options."""
    if isinstance(value, dict):
        for name, item in value.items():
            if env_reference(name, item):
                continue
            credential = credential_name(name)
            yield from private_inputs(item, sensitive or credential)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str) and item.startswith("--"):
                flag, sep, argument = item[2:].partition("=")
                if credential_name(flag, option=True):
                    if not sep and i + 1 < len(value):
                        argument = value[i + 1]
                    if isinstance(argument, str) and argument:
                        yield argument
            yield from private_inputs(item, sensitive)
    elif sensitive and isinstance(value, str) and value:
        yield value


def secret_values(profile):
    if not isinstance(profile, dict) or "configDelta" not in profile:
        return set()
    found = set()
    shown = profile.get("showValues")
    shown = set(shown) if isinstance(shown, list) and all(isinstance(k, str) for k in shown) else set()
    delta = profile.get("configDelta")
    if isinstance(delta, dict) and isinstance(delta.get("env"), list):
        for row in delta["env"]:
            name = row.get("name") if isinstance(row, dict) else None
            if isinstance(name, str) and not name.endswith("_FILE") and (
                    credential_name(name) or name in shown and name != "SPRING_FLYWAY_ENABLED"):
                found.update(row[k] for k in ("before", "after") if isinstance(row.get(k), str) and row[k])
    for section in ("migration", "gate", "candidate"):
        found.update(private_inputs(profile.get(section)))
    return found


@contextmanager
def scope(profile, *, admitting=False):
    values = None
    if isinstance(profile, dict) and "configDelta" in profile:
        # An admission refusal contains only a fixed code. Its spelling must be independent of the input.
        if not admitting or not (migration_has_inline_secret(profile) or delta_has_inline_secret(profile)):
            found = secret_values(profile).union(_values.get() or ())
            values = tuple(sorted(found, key=lambda s: (-len(s), s)))
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
    pattern = re.compile("|".join(map(re.escape, values)))

    def replace(text):
        result = pattern.sub(lambda match: replacements[match[0]], text)
        require(not pattern.search(result), "REDACTION_COLLISION")
        return result

    return _map_strings(value, replace)


def private_baseline(value):
    """Only for authenticated snapshots. The caller checks the original digest after reconstruction."""
    replacements = {"sha256:" + digest(s): s for s in _values.get() or ()}
    if not replacements:
        return value
    pattern = re.compile("|".join(map(re.escape, replacements)))
    return _map_strings(value, lambda text: pattern.sub(lambda m: replacements[m[0]], text))


def select_request(envelope, cfg, stack):
    req = envelope["request"]
    if isinstance(req, dict) and req.get("operation") == "module-release" and isinstance(req.get("module"), str):
        modules = cfg.get("modules") if isinstance(cfg, dict) else None
        if isinstance(modules, dict):
            stack.enter_context(scope(modules.get(req["module"]), admitting=True))
    return req


def checked_plan(name, value):
    if _values.get() is not None and name in ("plan", "plan.json", "migration-plan.json"):
        require(not inline_secret(value) and public(value) == value, "UNSAFE_RETURN_PLAN")
    return value


def json_output(value, *, sort_keys=True):
    raw = json.dumps(public(value), sort_keys=sort_keys, separators=(",", ":")).encode()
    return public(raw)


def release_output(function):
    @wraps(function)
    def run(profile, *args, **kwargs):
        with scope(profile, admitting=True):
            return public(function(profile, *args, **kwargs))
    return run
