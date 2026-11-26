"""Module profile admission, also loaded by the isolated bootstrap before application imports."""
from collections.abc import Mapping
import json
import stat


class UnsupportedOption(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise UnsupportedOption(code)


def validate_profile_options(profile, *, check=require):
    """Common to full release profiles and the smaller transport profiles."""
    if not isinstance(profile, Mapping):
        return  # The entry point owns malformed profile diagnostics.
    check("configDelta" not in profile, "CONFIG_DELTA_NOT_ENABLED")


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


def preflight_executor(root, stream):
    """Only a denial is authoritative before locking. Never import application modules here."""
    try:
        path = root / "profile.json"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            return None
        policy = json.loads(path.read_bytes())
        validate_policy_profiles(policy)
    except UnsupportedOption:
        # Only a request that uses this profile should be denied.
        pass
    except (OSError, ValueError, RecursionError):
        return None  # The locked reader owns custody and input errors.
    else:
        return None  # Preserve the normal entrypoint's stdin and lock ordering.

    try:
        raw = stream.read(8193)
    except (OSError, ValueError):
        return None  # Retry through the locked reader for its public diagnostic.
    if raw is None or len(raw) > 8192:
        return raw  # Let REQUEST_LIMIT take precedence, even for a decodable prefix.
    try:
        envelope = json.loads(raw)
        if isinstance(envelope, dict):
            validate_request_profiles(envelope.get("request"), policy)
    except UnsupportedOption as error:
        raise SystemExit(str(error)) from None
    except (ValueError, RecursionError):
        pass
    return raw
