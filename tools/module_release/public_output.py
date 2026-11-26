"""The release's private inputs stay in memory. Scrub values when returning results to a caller."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import re
from urllib.parse import unquote

from .contract import Held, digest, require
from .profile_options import credential_name


_values = ContextVar("module_release_secrets", default=None)
_module = ContextVar("module_release_public_module", default=None)


# Keep both the encoded spelling and the password interpreted by the DSN consumer.
_url_password = re.compile(r"://[^/@?#\s:]*:([^/@?#\s]+)@|oracle:thin:[^/@\s]+/([^@\s]+)@", re.I)
_property = re.compile(r"""(?<![\w.-])(?:-D|--?)?([\w.][\w.-]*)\s*=\s*""", re.I)
_operand = re.compile(r"""\{((?:\}\}|[^}])*)\}|'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|((?:\\.|[^\s\\])+)""")
_flag = re.compile(r"(?:^|\s)--([\w.-]+)\s+|(?:^|\s)-p(?=[^\s=]+(?:\s|$))")


def dsn_values(text):
    for match in _url_password.finditer(text):
        raw = match[1] or match[2]
        yield raw
        yield unquote(raw)
    for pattern in (_property, _flag):
        for match in pattern.finditer(text):
            if match[1] is not None and not (credential_name(match[1]) or match[1].lower() == "sig"):
                continue
            operand = _operand.match(text, match.end())
            if operand:
                raw = next(v for v in operand.groups() if v is not None)
                if operand[4] and match.start() and text[match.start() - 1] in "?&;":
                    raw = re.split("[&;#]", raw, maxsplit=1)[0]
                if raw:
                    yield raw
                    yield unquote(raw.replace("}}", "}") if operand[1] is not None else re.sub(r"\\(.)", r"\1", raw))


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
    # Admission compares the entire dedicated argv and reports only a fixed code.
    # An embedded DSN in a rejected argv must never rewrite that diagnostic.
    migration = profile.get("migration") if isinstance(profile, dict) else None
    if isinstance(migration, dict) and migration.get("mode") == "dedicated" and "command" in migration:
        profile = {**profile, "migration": {k: v for k, v in migration.items() if k != "command"}}
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


def inspected(doc):
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
    module_token = _module.set(profile.get("module", _module.get()) if isinstance(profile, dict) else _module.get())
    try:
        yield
    finally:
        _module.reset(module_token)
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


COLLISION = "SECRET_IDENTIFIER_COLLISION"


def identifier(value):
    values = _values.get()
    if values and str(value) in values:
        raise Held(COLLISION)
    return value


def check_identifiers(value):
    if not _values.get():
        return
    if isinstance(value, dict):
        for key, item in value.items():
            identifier(key)
            check_identifiers(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            check_identifiers(item)
    elif isinstance(value, (str, int)):
        identifier(value)
        if isinstance(value, str):
            # Approval lines embed digests and typed identifiers in prose.
            for stamp in re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", value):
                identifier(stamp)
            if match := re.match(r"ENV ([A-Z_][A-Z0-9_]*) da ", value):
                identifier(match[1])


def scrub(value):
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


def public(value):
    # The workflow includes the module alongside every successful phase response.
    if isinstance(value, dict) and _module.get():
        identifier(_module.get())
    check_identifiers(value)
    return scrub(value)


def check_record(name, data):
    if name in ("plan.json", "receipt.json", "return-receipt.json", "stage.json", "ready-before-signing.json"):
        if _module.get():
            identifier(_module.get())
        check_identifiers(data)


def public_error(message):
    if message == COLLISION:
        return COLLISION
    try:
        return public(message)
    except Held as exc:
        return str(exc)


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
            result = function(profile, *args, **kwargs)
            if result.get("reason") == COLLISION:
                return {"status": "HELD", "reason": COLLISION}
            try:
                return public(result)
            except Held as exc:
                if str(exc) != COLLISION or "status" not in result:
                    raise
                return {"status": "HELD", "reason": COLLISION}
    return run
