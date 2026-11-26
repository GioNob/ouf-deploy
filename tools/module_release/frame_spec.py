"""Closed Linux CREATE grammar shared by first install and reviewed frame changes."""
from contextlib import ExitStack
from collections.abc import Collection
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .contract import ENTRY, Held, IMAGE, NAME, SHA, argv, credential_name, matches


class SpecHeld(Held):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check(condition, code):
    if not condition:
        raise SpecHeld(code)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def path(value):
    check(isinstance(value, str) and matches(r"/[A-Za-z0-9_./@+-]+", value)
          and str(PurePosixPath(value)) == value and not value.startswith("//")
          and ".." not in value.split("/"), "INVALID_ABSOLUTE_PATH")
    return PurePosixPath(value)


def validate_env(entries, allowlist=None) -> list[str]:
    check(isinstance(entries, list), "INVALID_ENV")
    check(allowlist is None or isinstance(allowlist, Collection) and not isinstance(allowlist, (str, bytes)),
          "INVALID_ENV_ALLOWLIST")
    result = {}
    for entry in entries:
        check(isinstance(entry, dict) and set(entry) == {"name", "value"}, "INVALID_ENV")
        name, value = entry["name"], entry["value"]
        check(matches(r"[A-Z_][A-Z0-9_]*", name) and name not in result
              and (allowlist is None or name in allowlist), "ENV_NAME_DENIED")
        check(isinstance(value, str) and not re.search(r"[\x00-\x1f\x7f]", value), "INVALID_ENV")
        if name.endswith("_FILE"):
            path(value)
        else:
            check(not credential_name(name)
                  and not re.search(r"(?i)://[^/\s]*@|-----BEGIN .*PRIVATE KEY|\bbearer\s+", value),
                  "SECRET_ENV_DENIED")
        result[name] = value
    return [f"{name}={value}" for name, value in result.items()]


SYSTEM = tuple(map(PurePosixPath, ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
                                    "/run", "/sbin", "/sys", "/usr", "/var/lib/docker", "/var/lib/containerd",
                                    "/var/spool", "/var/log", "/var/run", "/opt/ouf-a2")))


def disjoint(source, excluded):
    return all(not source.is_relative_to(other) and not other.is_relative_to(source) for other in excluded)


def bind_shape(entry, roots, profile):
    check(isinstance(entry, dict) and {"source", "target", "mode"} <= set(entry)
          <= {"source", "target", "mode", "sha256"}, "INVALID_BIND")
    source, target = path(entry["source"]), path(entry["target"])
    check(isinstance(roots, list) and any(source.is_relative_to(path(root)) for root in roots)
          and disjoint(source, SYSTEM) and source.name != "docker.sock", "BIND_SOURCE_DENIED")
    for key in ("journal", "inbox", "dockerSocket"):
        value = profile.get(key) if isinstance(profile, dict) else None
        check(isinstance(value, str) and not value.startswith("//") and "\0" not in value
              and (Path(value).is_absolute() or PurePosixPath(value).is_absolute())
              and ".." not in Path(value).parts, "BIND_POLICY_REQUIRED")
        check(disjoint(source, [PurePosixPath(Path(value).as_posix())]), "BIND_SOURCE_DENIED")
    check(entry["mode"] in ("ro", "rw") and ("sha256" not in entry or
          entry["mode"] == "ro" and matches(SHA, entry["sha256"])), "INVALID_BIND_MODE")
    return {"Type": "bind", "Source": str(source), "Target": str(target), "ReadOnly": entry["mode"] == "ro"}


def bind_facts(entry, roots, *, profile, writable_uid=None, writable_groups=()):
    mount = bind_shape(entry, roots, profile)
    check(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"), "BIND_CUSTODY_UNPROVEN")
    parts = path(entry["source"]).parts[1:]
    # Open and pin every ancestor separately. No untrusted parent can replace
    # the checked leaf between this read and the Engine opening its pathname.
    with ExitStack() as stack:
        def opened(name, flags, parent=None):
            fd = os.open(name, flags | os.O_NOFOLLOW, dir_fd=parent)
            stack.callback(os.close, fd)
            return fd

        fd = opened("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in parts[:-1]:
            fd = opened(part, os.O_RDONLY | os.O_DIRECTORY, fd)
            info = os.fstat(fd)
            check(info.st_uid == 0 and not info.st_mode & 0o022, "BIND_PARENT_CUSTODY")
        fd = opened(parts[-1], os.O_RDONLY | os.O_NONBLOCK, fd)
        info = os.fstat(fd)
        owners = {0} if mount["ReadOnly"] or writable_uid is None else {0, writable_uid}
        shared = not mount["ReadOnly"] and info.st_gid in writable_groups
        check(info.st_uid in owners and not info.st_mode & (0o002 if shared else 0o022)
              and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), "BIND_SOURCE_CUSTODY")
        facts = {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid, "gid": info.st_gid,
                 "mode": info.st_mode}
        if "sha256" in entry:
            check(stat.S_ISREG(info.st_mode), "BIND_HASH_REQUIRES_FILE")
            value = hashlib.sha256()
            while chunk := os.read(fd, 1 << 20):
                value.update(chunk)
            facts["sha256"] = value.hexdigest()
            check(facts["sha256"] == entry["sha256"] and info.st_ctime_ns == os.fstat(fd).st_ctime_ns,
                  "BIND_DIGEST_CHANGED")
    return mount, facts


def validate_bind(entry, roots, *, profile=None) -> dict:
    """Pass policy bindRoots and profile= with journal, inbox and dockerSocket.

    The two-argument form also accepts a policy dict containing those paths
    and bindRoots. A bare root list cannot prove a private path is disjoint.
    Both forms check exclusions before opening the source.
    """
    if profile is None and isinstance(roots, dict):
        profile, roots = roots, roots.get("bindRoots")
    try:
        return bind_facts(entry, roots, profile=profile)[0]
    except OSError:
        raise SpecHeld("BIND_CUSTODY_UNPROVEN") from None


def validate_tmpfs(entry) -> tuple[str, str]:
    check(isinstance(entry, dict) and set(entry) == {"target", "options"}, "INVALID_TMPFS")
    target = str(path(entry["target"]))
    options = entry["options"]
    check(isinstance(options, str), "INVALID_TMPFS")
    parts = options.split(",")
    check(all(matches(r"rw|ro|noexec|nosuid|nodev|size=[1-9][0-9]*[kKmMgG]?|mode=0?[0-7]{3,4}", i)
              for i in parts) and len({i.partition("=")[0] for i in parts}) == len(parts)
          and not {"rw", "ro"} <= set(parts), "INVALID_TMPFS")
    return target, options


def validate_networks(entries, live_networks) -> dict:
    """live_networks maps policy names to {NetworkID, ips, aliases} from Engine inspect."""
    check(isinstance(entries, dict) and entries, "NETWORKS_REQUIRED")
    result = {}
    for name, binding in entries.items():
        check(matches(NAME, name) and name not in ("host", "none", "bridge", "default")
              and name in live_networks, "NETWORK_UNAVAILABLE")
        live = live_networks[name]
        check(matches(SHA, live["NetworkID"]) and isinstance(binding, dict)
              and set(binding) == {"ipv4", "aliases"}, "INVALID_NETWORK_BINDING")
        try:
            ip = str(ipaddress.IPv4Address(binding["ipv4"]))
        except (ValueError, TypeError):
            raise SpecHeld("INVALID_IPV4") from None
        aliases = binding["aliases"]
        check(ip == binding["ipv4"] and ip not in live["ips"], "IPV4_UNAVAILABLE")
        check(isinstance(aliases, list) and all(matches(NAME, a) for a in aliases)
              and len({a.lower() for a in aliases}) == len(aliases)
              and not {a.lower() for a in aliases}.intersection(a.lower() for a in live["aliases"]),
              "ALIAS_UNAVAILABLE")
        result[name] = {"IPAMConfig": {"IPv4Address": ip}, "Aliases": list(aliases)}
    return result


FIELDS = {"user", "groupAdd", "binds", "tmpfs", "readonlyRootfs", "env", "bindRoots", "failedName"}


def install_section(section):
    check(isinstance(section, dict) and {"user", "failedName"} <= set(section) <= FIELDS, "INSTALL_FIELDS")
    return {"groupAdd": [], "binds": [], "tmpfs": [], "readonlyRootfs": False, "env": [], "bindRoots": [], **section}


def install_shape(spec):
    section = install_section(spec["install"])
    check(matches(r"[1-9][0-9]*(?::[1-9][0-9]*)?", section["user"])
          and all(int(i) < 2**32-1 for i in section["user"].split(":")), "NONROOT_USER_REQUIRED")
    groups = section["groupAdd"]
    check(isinstance(groups, list) and all(matches(r"[1-9][0-9]*", g) and int(g) < 2**32-1 for g in groups)
          and len(set(groups)) == len(groups), "INVALID_GROUP_ADD")
    check(type(section["readonlyRootfs"]) is bool and matches(NAME, section["failedName"])
          and section["failedName"] != spec["container"], "INVALID_INSTALL_CONFIG")
    for key in ("binds", "bindRoots", "tmpfs"):
        check(isinstance(section[key], list), "INVALID_INSTALL_CONFIG")
    for root in section["bindRoots"]:
        path(root)
    mounts = [bind_shape(row, section["bindRoots"], spec) for row in section["binds"]]
    tmp = [validate_tmpfs(row) for row in section["tmpfs"]]
    targets = [path(m["Target"]) for m in mounts] + [path(target) for target, _ in tmp]
    check(all(disjoint(target, targets[:i]) for i, target in enumerate(targets)), "MOUNT_TARGET_OVERLAP")
    env = validate_env(section["env"])
    check_file_env(env, mounts)
    return mounts, dict(tmp), env


def check_file_env(env, mounts):
    """Check validated NAME=value entries against the final Docker HostConfig.Mounts."""
    ro = {m["Target"] for m in mounts if m["Type"] == "bind" and m.get("ReadOnly") is True}
    for entry in env:
        name, _, value = entry.partition("=")
        if name.endswith("_FILE"):
            check(value in ro, "FILE_ENV_REQUIRES_RO_BIND")


def check_image_volumes(image_config_volumes, spec) -> None:
    section = spec.get("install", spec)
    covered = {row["target"] for key in ("binds", "tmpfs") for row in section.get(key, [])}
    check(image_config_volumes is None or isinstance(image_config_volumes, dict)
          and set(image_config_volumes) <= covered, "IMAGE_VOLUME_UNCOVERED")


def build_create(spec, image_facts, plan_sha256) -> dict:
    """spec is the module profile. Image facts carry imageId, Config and observed networks."""
    return create_with_custody(spec, image_facts, plan_sha256)[0]


def create_request(spec, image_facts, plan_sha256):
    mounts, tmpfs, env = install_shape(spec)
    section = install_section(spec["install"])
    check(matches(IMAGE, image_facts["imageId"]) and matches(SHA, plan_sha256)
          and argv(spec["gate"]["command"]), "INVALID_CREATE_IDENTITY")
    check_image_volumes(image_facts["Config"].get("Volumes"), spec)
    endpoints = validate_networks(spec["networks"], image_facts["networks"])
    return {"Image": image_facts["imageId"], "User": section["user"], "Env": env,
            "Entrypoint": list(ENTRY), "Cmd": list(spec["gate"]["command"]),
            "Labels": {"ouf.install.plan": plan_sha256},
            "NetworkingConfig": {"EndpointsConfig": endpoints},
            "HostConfig": {"NetworkMode": sorted(endpoints)[0], "Mounts": mounts, "Tmpfs": tmpfs,
                           "ReadonlyRootfs": section["readonlyRootfs"], "GroupAdd": section["groupAdd"],
                           "RestartPolicy": {"Name": "no"}}}


def create_with_custody(spec, image_facts, plan_sha256):
    request = create_request(spec, image_facts, plan_sha256)
    section = install_section(spec["install"])
    uid = int(section["user"].split(":")[0])
    groups = set(map(int, section["groupAdd"] + section["user"].split(":")[1:]))
    try:
        custody = [bind_facts(row, section["bindRoots"], profile=spec, writable_uid=uid, writable_groups=groups)[1]
                   for row in section["binds"]]
    except OSError:
        raise SpecHeld("BIND_CUSTODY_UNPROVEN") from None
    return request, custody


_build_create = build_create


def build_create(spec, image_facts, plan_sha256) -> dict:
    from .contract import validate_profile_options
    validate_profile_options(spec, check=check)
    return _build_create(spec, image_facts, plan_sha256)
