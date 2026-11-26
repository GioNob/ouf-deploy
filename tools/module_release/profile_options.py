"""Module profile admission, shared with the isolated bootstrap."""
from collections.abc import Mapping


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
    if "readyReturn" in profile:
        check(type(profile["readyReturn"]) is bool, "INVALID_READY_RETURN")


def reviewed(profile):
    return isinstance(profile, Mapping) and ("configDelta" in profile or
            profile.get("readyReturn") is True and profile.get("migration", {}).get("mode") == "none"
            and not {"database", "flyway"}.intersection(profile["migration"]))


def return_allowed(profile):
    migration = profile["migration"]
    return bool({"database", "flyway"}.intersection(migration) or
                migration.get("mode") == "none" and reviewed(profile))


def validate_request_profiles(req, policy, *, check=require):
    if not isinstance(req, dict) or req.get("operation") not in ("module-release", "module-install"):
        return
    validate_module_profiles(req.get("module"), policy, release=req["operation"] == "module-release", check=check)


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
