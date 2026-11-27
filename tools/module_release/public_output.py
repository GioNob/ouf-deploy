"""Bind sensitive inputs at their source, before composing public plans and receipts."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

from .contract import Held, digest, private_field, private_profile, require, structured_secret
from .fingerprints import mac, read_key


_context = ContextVar("release_fingerprints", default=None)


def private_config(config):
    env = (entry.partition("=") for entry in config.get("Env") or ())
    return (structured_secret({k: v for k, v in config.items() if k != "Env"})
            or any(private_field(name) or structured_secret(value) for name, _, value in env))


@contextmanager
def scope(profile, run=None, *, key_path=...):
    previous = _context.get()
    if previous is not None and previous["profile"] is profile and run is None:
        yield
        return
    profile = profile if isinstance(profile, dict) else {}
    ci = profile.get("ci")
    ci = ci if isinstance(ci, dict) else {}
    if key_path is ...:
        key_path = previous["key_path"] if previous else profile.get("fingerprintKeyFile")
    state = {"profile": profile, "run": run or f"ci/{ci.get('repository')}/{ci.get('runId')}/{ci.get('runAttempt')}",
             "private": False, "key": None,
             "key_path": key_path}
    token = _context.set(state)
    try:
        yield
    finally:
        _context.reset(token)


def private_frame(doc):
    network = doc.get("NetworkSettings", {})
    # SandboxKey is the Engine's namespace path. Network names are identifiers.
    options = {k: v for k, v in network.items() if k not in ("SandboxKey", "Networks")}
    return (private_config(doc.get("Config", {})) or structured_secret(doc.get("HostConfig", {}))
            or structured_secret(doc.get("Args", [])) or structured_secret(doc.get("Mounts", []))
            or structured_secret(options) or any(structured_secret(ep) for ep in network.get("Networks", {}).values()))


def begin(profile, old, defaults):
    _context.get()["private"] = private_profile(profile) or private_frame(old) or private_config(defaults)


def observed_binding(name, doc, value):
    if run_fields() or private_frame(doc):
        return fingerprint(name, value)
    return digest(value)


def run_fields():
    ctx = _context.get()
    return {"fingerprintRun": ctx["run"]} if ctx and ctx["private"] else {}


def use_plan(plan):
    ctx = _context.get()
    if ctx is not None:
        ctx["private"] = "fingerprintRun" in plan
        if ctx["private"]:
            ctx["run"] = plan["fingerprintRun"]
    return plan


def fingerprint(name, value):
    ctx = _context.get()
    require(ctx is not None and ctx["profile"].get("journal"), "FINGERPRINT_CONTEXT_REQUIRED")
    if ctx["key"] is None:
        try:
            ctx["key"] = read_key(ctx["key_path"])
        except ValueError as exc:
            raise Held(str(exc)) from None
    return mac(ctx["key"], [ctx["profile"]["module"], ctx["run"]], name, value)


def binding(name, value):
    if name == "profile" and "fingerprintKeyFile" in value:
        value = {k: v for k, v in value.items() if k != "fingerprintKeyFile"}
    return fingerprint(name, value) if run_fields() else digest(value)


def journal_binding(name, value):
    # Older full-frame journals can contain private inputs even if the source plan predates HMAC.
    if name == "baseline.private.json" and isinstance(value, dict):
        return observed_binding(["journal", name], value, value)
    if name == "return-frame.json" and isinstance(value, dict) and "baseline" in value:
        if private_frame(value["baseline"]) or structured_secret(value.get("plan")):
            return fingerprint(["journal", name], value)
    elif structured_secret(value):
        return fingerprint(["journal", name], value)
    return binding(["journal", name], value)


def migration_binding(stage):
    use_plan(stage)
    return binding("migration-plan", stage)


def profile_binding(profile, plan):
    use_plan(plan)
    return binding("profile", profile)


def release_output(function):
    @wraps(function)
    def run(profile, *args, **kwargs):
        with scope(profile):
            return function(profile, *args, **kwargs)
    return run
