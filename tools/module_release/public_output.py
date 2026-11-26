"""The release's private inputs stay in memory. Only this projection crosses a journal or public boundary."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import re

from .contract import digest, require


_values = ContextVar("module_release_secrets", default=())
_credential = re.compile(
    r"pass(?:wd|word|phrase)?|secret|token|credential|community|(?:^|[_.-])"
    r"(?:pwd|dsn|jwt|auth(?:orization)?|(?:api|private|sharedaccess|account|access|signing)?[_.-]?key|connection[_.-]?string)(?:$|[_.-])",
    re.I)


def private_inputs(value, sensitive=False):
    """Inspect typed profile data before any output, including nested migration options."""
    if isinstance(value, dict):
        for name, item in value.items():
            credential = isinstance(name, str) and _credential.search(name) and not name.lower().endswith("file")
            yield from private_inputs(item, sensitive or credential)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str) and item.startswith("--"):
                flag, sep, argument = item[2:].partition("=")
                if _credential.search(flag):
                    if not sep and i + 1 < len(value):
                        argument = value[i + 1]
                    if isinstance(argument, str) and argument:
                        yield argument
            yield from private_inputs(item, sensitive)
    elif sensitive and isinstance(value, str) and value:
        yield value


def secret_values(profile):
    if not isinstance(profile, dict):
        return set()
    found = set()
    shown = profile.get("showValues")
    shown = set(shown) if isinstance(shown, list) and all(isinstance(k, str) for k in shown) else set()
    delta = profile.get("configDelta")
    if isinstance(delta, dict) and isinstance(delta.get("env"), list):
        for row in delta["env"]:
            name = row.get("name") if isinstance(row, dict) else None
            if isinstance(name, str) and not name.endswith("_FILE") and (
                    _credential.search(name) or name in shown and name != "SPRING_FLYWAY_ENABLED"):
                found.update(row[k] for k in ("before", "after") if isinstance(row.get(k), str) and row[k])
    for section in ("migration", "gate", "candidate"):
        found.update(private_inputs(profile.get(section)))
    return found


@contextmanager
def scope(profile):
    values = set(_values.get()).union(secret_values(profile))
    token = _values.set(tuple(sorted(values, key=lambda s: (-len(s), s))))
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
    replacements = {"sha256:" + digest(s): s for s in _values.get()}
    if not replacements:
        return value
    pattern = re.compile("|".join(map(re.escape, replacements)))
    return _map_strings(value, lambda text: pattern.sub(lambda m: replacements[m[0]], text))


def select_request(envelope, cfg, stack):
    req = envelope["request"]
    if isinstance(req, dict) and req.get("operation") == "module-release" and isinstance(req.get("module"), str):
        modules = cfg.get("modules") if isinstance(cfg, dict) else None
        if isinstance(modules, dict):
            stack.enter_context(scope(modules.get(req["module"])))
    return req


def checked_plan(name, value):
    if name in ("plan", "plan.json", "migration-plan.json"):
        require(public(value) == value, "UNSAFE_RETURN_PLAN")
    return value


def json_output(value, *, sort_keys=True):
    raw = json.dumps(public(value), sort_keys=sort_keys, separators=(",", ":")).encode()
    return public(raw)


def release_output(function):
    @wraps(function)
    def run(profile, *args, **kwargs):
        with scope(profile):
            return public(function(profile, *args, **kwargs))
    return run
