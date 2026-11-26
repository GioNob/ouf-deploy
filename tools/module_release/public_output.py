"""Bind sensitive inputs at their source, before composing public plans and receipts."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path

from .contract import Held, INGESTION_STARTUP_FLAGS, digest, inline_secret, require
from .fingerprints import mac, read_key


_context = ContextVar("release_fingerprints", default=None)
KEY_FILE = ".release-hmac.key"


def private_config(config):
    env = (entry.partition("=") for entry in config.get("Env") or ())
    return (inline_secret(config.get("Labels")) or inline_secret(config.get("Cmd")) or
            inline_secret(config.get("Entrypoint")) or inline_secret(config.get("Healthcheck")) or
            any(inline_secret({key: value}) for key, _, value in env))


@contextmanager
def scope(profile, run=None):
    previous = _context.get()
    if previous is not None and previous["profile"] is profile and run is None:
        yield
        return
    profile = profile if isinstance(profile, dict) else {}
    ci = profile.get("ci")
    ci = ci if isinstance(ci, dict) else {}
    state = {"profile": profile, "run": run or f"ci/{ci.get('repository')}/{ci.get('runId')}/{ci.get('runAttempt')}",
             "private": False, "key": None}
    token = _context.set(state)
    try:
        yield
    finally:
        _context.reset(token)


def begin(profile, old, defaults):
    ctx = _context.get()
    # receiptSigning declares key paths and the public key's digest.
    inputs = {name: item for name, item in profile.items() if name != "receiptSigning"}
    removed = profile.get("candidate", {}).get("removeArgs", ())
    ctx["private"] = ("configDelta" in profile or any(arg not in INGESTION_STARTUP_FLAGS for arg in removed)
                      or inline_secret(inputs) or private_config(old["Config"]) or private_config(defaults))


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
            ctx["key"] = read_key(Path(ctx["profile"]["journal"]) / KEY_FILE)
        except ValueError as exc:
            raise Held(str(exc)) from None
    return mac(ctx["key"], [ctx["profile"]["module"], ctx["run"]], name, value)


def binding(name, value):
    return fingerprint(name, value) if run_fields() else digest(value)


def journal_binding(name, value):
    # Older full-frame journals can contain private inputs even if the source plan predates HMAC.
    if inline_secret(value):
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
