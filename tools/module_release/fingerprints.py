"""Domain-separated private bindings shared with the isolated installer."""
import hmac
import json
import os
import stat
from pathlib import Path


def read_key(path):
    if (not isinstance(path, (str, Path)) or "\0" in str(path)
            or not Path(path).is_absolute() or ".." in Path(path).parts):
        raise ValueError("FINGERPRINT_KEY_UNAVAILABLE")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not (stat.S_ISREG(info.st_mode) and (os.name != "posix" or
                    info.st_uid == os.geteuid() and not info.st_mode & 0o077)):
                raise ValueError("FINGERPRINT_KEY_CUSTODY")
            key = stream.read(33)
    except OSError:
        raise ValueError("FINGERPRINT_KEY_UNAVAILABLE") from None
    if len(key) != 32:
        raise ValueError("FINGERPRINT_KEY_INVALID")
    return key


def mac(key, run, field, value):
    payload = json.dumps(["ouf-release-v1", run, field, value], sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode()
    return hmac.digest(key, payload, "sha256").hex()


def secret_sources(policy):
    paths = set()
    gateway = policy.get("gateway", {})
    if gateway.get("keyFile"):
        paths.add(Path(gateway["keyFile"]))
    for module in policy.get("modules", {}).values():
        signer = module.get("receiptSigning", {})
        if signer.get("privateKey"):
            paths.add(Path(signer["privateKey"]))
        for area in ("configDelta", "install"):
            section = module.get(area, {})
            if isinstance(section, dict):
                paths.update(Path(b["source"]) for b in section.get("binds", []) if b.get("mode") == "ro")
        roles = module.get("migration", {}).get("retentionAdmin019", {})
        paths.update(Path(roles[k]) for k in ("adminPassfile", "maintenancePassfile") if k in roles)
    return paths


def manifest_binding(root, files, public_binding, protected, previous):
    from types import ModuleType
    contract = ModuleType("release_contract")
    exec(files[root / "lib/module_release/contract.py"][0], contract.__dict__)
    profile = root / "profile.json"
    policy = json.loads(files[profile][0])
    key_path = policy.get("fingerprintKeyFile")
    sources = set()
    for side in (policy, json.loads(previous) if previous is not None else {}):
        if side.get("fingerprintKeyFile"):
            protected.add(Path(side["fingerprintKeyFile"]))
        sources.update(secret_sources(side))
    runs = {name: [p["ci"]["repository"], p["ci"]["runId"], p["ci"]["runAttempt"]]
            for name, p in policy["modules"].items()}

    def bind(path, data, mode):
        if path == profile:
            content = json.loads(data)
            try:
                private = (any(contract.private_profile(p) for p in content["modules"].values())
                           or contract.structured_secret({k: v for k, v in content.items()
                                                         if k not in ("modules", "fingerprintKeyFile")}))
            except (AttributeError, KeyError, TypeError, RecursionError):
                private = True
        else:
            # The inventory covers installer-owned code/books. A declared credential
            # source takes precedence over that role, including on replacement.
            private = path in sources
        if not private:
            return public_binding(data, mode)
        field = (path.relative_to(root) if path.is_relative_to(root) else path).as_posix()
        return {"hmacSha256": mac(read_key(key_path), [policy["commit"], runs], field, data.hex()), "mode": oct(mode)}

    return bind
