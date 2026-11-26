"""Check configured data paths against the predecessor's observed Linux mounts."""

from pathlib import PurePosixPath

from .contract import matches, require


def absolute_path(value):
    require(isinstance(value, str) and value.startswith("/") and not value.startswith("//")
            and "\0" not in value and ".." not in value.split("/"), "PERSISTENT_PATH_INVALID")
    return PurePosixPath(value)


def check_persistent_paths(profile, old):
    if "persistentPathEnv" not in profile:
        return
    names = profile["persistentPathEnv"]
    require(isinstance(names, list) and names and all(matches(r"[A-Za-z_][A-Za-z0-9_]*", n) for n in names)
            and len(names) == len(set(names)), "PERSISTENT_PATH_PROFILE_REQUIRED")
    mounts = old.get("Mounts") or []
    # Engine can represent --tmpfs in HostConfig.Tmpfs alone. It can shadow a parent bind.
    targets = {absolute_path(m["Destination"]): m for m in mounts}
    for dest in old["HostConfig"].get("Tmpfs") or {}:
        targets[absolute_path(dest)] = {"Type": "tmpfs"}
    require(targets, "PERSISTENT_MOUNTS_REQUIRED")
    env = old["Config"].get("Env") or []
    for name in names:
        values = [entry.split("=", 1)[1] for entry in env if entry.startswith(name + "=")]
        require(len(values) == 1, "PERSISTENT_PATH_ENV_REQUIRED")
        data = absolute_path(values[0])
        mount = next((targets[p] for p in (data, *data.parents) if p in targets), None)
        require(mount is not None, "PERSISTENT_PATH_UNCOVERED")
        require(mount["Type"] == "bind", "EXPLICIT_BIND_MOUNTS_REQUIRED")
        require(mount.get("RW") is True, "PERSISTENT_BIND_RW_REQUIRED")
        # A path below the bind can resolve, inside the container, through a symlink to volatile
        # storage that the inspect cannot see (review 61d-b, Astra). The data path must therefore be
        # the bind destination itself: a mount point is never a symlink in the container namespace.
        require(data in targets and targets[data] is mount, "PERSISTENT_PATH_NOT_BIND_ROOT")
