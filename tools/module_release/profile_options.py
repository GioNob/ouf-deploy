"""Module profile admission, shared with the isolated bootstrap."""
from collections.abc import Mapping
import json
import re
from urllib.parse import unquote


INLINE_SECRET = "CONFIG_DELTA_INLINE_SECRET"
_sensitive_word = (r"pass(?:wd|words?|phrase)?|pwd|secrets?|tokens?|credentials?|community|dsn|jwt|auths?|"
                   r"authorization|key|(?:api|private|sharedaccess|account|access|signing)[_.-]?key|"
                   r"shared[_.-]?access[_.-]?signature|connection[_.-]?string")
_credential = re.compile(r"(?:^|[_.-])(?:" + _sensitive_word + r")(?:$|[_.-])", re.I)
_option = re.compile(r"(?:[a-z0-9]+[_.-])*(?:" + _sensitive_word + r")", re.I)
_literal = re.compile(r"://[^/\s?#]*:[^/\s?#]*@|\b(?:basic|bearer)\s+\S+|-----BEGIN [^\n]*PRIVATE KEY|"
                      r"\boracle:thin:[^@\s]+/[^@\s]+@", re.I)
_assignment = re.compile(r"(?<![\w.-])(--?)?([\w.][\w.-]*)\s*=")
_long_option = re.compile(r"""(?:^|[\s'"])--([a-zA-Z][\w.-]*)(?=$|[\s='"])""")


def credential_name(name, *, option=False):
    if not isinstance(name, str):
        return False
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    if option:
        return bool(_option.fullmatch(words))
    if words.lower().endswith(("_file", "-file", ".file")):
        return False
    return bool(_credential.search(words) or re.search(r"password|passwd|passphrase|secret|token|credential", words, re.I))


def json_properties(pairs):
    # Keep duplicate keys so a later property cannot hide an earlier credential.
    return [{key: value} for key, value in pairs]


def env_reference(key, value):
    return (isinstance(key, str) and key.endswith("Env") and isinstance(value, str)
            and re.fullmatch(r"[A-Z_][A-Z0-9_]*", value) is not None)


def inline_secret(value):
    """Recognize credential-bearing fields, argv and nested JSON in release inputs."""
    if isinstance(value, dict):
        for key, item in value.items():
            if env_reference(key, item):
                continue
            if credential_name(key) or inline_secret(key) or inline_secret(item):
                return True
        return False
    if isinstance(value, list):
        return any(inline_secret(item) for item in value)
    if not isinstance(value, str):
        return False
    raw = value.strip()
    decoded = unquote(raw)
    if _literal.search(raw) or _literal.search(decoded):
        return True
    if any(credential_name(m[1], option=True) for m in _long_option.finditer(raw)):
        return True
    if raw.startswith("--"):
        _, equals, argument = raw.partition("=")
        if equals and inline_secret(argument):
            return True
    for field in _assignment.finditer(decoded):
        if credential_name(field[2], option=bool(field[1])) or field[2].lower() == "sig":
            return True
    for representation in dict.fromkeys((raw, decoded)):
        if representation.startswith(("{", "[", '"')):
            try:
                parsed = json.loads(representation, object_pairs_hook=json_properties)
            except ValueError:
                continue  # Non-JSON inputs, including IPv6 addresses, follow the usual field validation.
            if inline_secret(parsed):
                return True
    return False


def delta_has_inline_secret(profile):
    delta = profile.get("configDelta")
    if not isinstance(delta, dict):
        return False
    shown = profile.get("showValues")
    rows = delta.get("env")
    try:
        if isinstance(shown, list) and any(map(credential_name, shown)):
            return True
        if isinstance(rows, list) and any(isinstance(row, dict) and credential_name(row.get("name")) for row in rows):
            return True
        return any(inline_secret(profile.get(section)) for section in
                   ("configDelta", "migration", "gate", "candidate", "networks"))
    except RecursionError:
        return True


class UnsupportedOption(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise UnsupportedOption(code)


def validate_profile_options(profile, *, check=require):
    """Common to full release profiles and the smaller transport profiles."""
    if not isinstance(profile, Mapping):
        return  # The entry point owns malformed profile diagnostics.
    if "configDelta" in profile:
        delta = profile["configDelta"]
        check(isinstance(delta, dict), "INVALID_DELTA")
        check(bool(delta), "EMPTY_DELTA")
        check(not delta_has_inline_secret(profile), INLINE_SECRET)
    if "readyReturn" in profile:
        check(type(profile["readyReturn"]) is bool, "INVALID_READY_RETURN")


def reviewed(profile):
    if not isinstance(profile, Mapping):
        return False
    migration = profile.get("migration")
    return "configDelta" in profile or (profile.get("readyReturn") is True and isinstance(migration, Mapping)
            and migration.get("mode") == "none" and not {"database", "flyway"}.intersection(migration))


def reviewed_return_allowed(profile):
    migration = profile.get("migration")
    return reviewed(profile) and isinstance(migration, Mapping) and migration.get("mode") in ("none", "spring-flyway", "dedicated")


def validate_request_profiles(req, policy, *, check=require):
    if not isinstance(req, dict) or req.get("operation") not in ("module-release", "module-install"):
        return
    validate_module_profiles(req.get("module"), policy, release=req.get("operation") == "module-release", check=check)


def validate_module_profiles(name, policy, *, release, check=require):
    modules = policy.get("modules") if isinstance(policy, dict) else None
    if isinstance(name, str) and isinstance(modules, dict):
        names = (name, "mcp") if release and name == "onboarding" else (name,)
        for key in names:
            profile = modules.get(key)
            if isinstance(profile, Mapping):
                validate_profile_options(profile, check=check)


def validate_policy_profiles(policy, *, check=require):
    modules = policy.get("modules") if isinstance(policy, dict) else None
    if isinstance(modules, dict):
        for profile in modules.values():
            if isinstance(profile, Mapping):
                validate_profile_options(profile, check=check)
