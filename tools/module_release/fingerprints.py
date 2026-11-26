"""Domain-separated private bindings shared with the isolated installer."""
import hmac
import json
import os
import stat


def read_key(path):
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


def file_binding(root, files, path, public_binding, data, mode):
    if path != root / "profile.json":
        return public_binding(data, mode)
    policy = json.loads(files[path][0])
    # The approved CI runs identify this installation even before an executor run exists.
    runs = {name: [p["ci"]["repository"], p["ci"]["runId"], p["ci"]["runAttempt"]]
            for name, p in policy["modules"].items()}
    key = read_key(root.parent / ".ouf-a2-install-hmac.key")
    return {"hmacSha256": mac(key, [policy["commit"], runs], "profile.json", data.hex()), "mode": oct(mode)}
