"""Reviewed, additive changes to a retained container's CREATE frame."""
from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
import re

from .public_output import public, scope
from .profile_options import INLINE_SECRET, credential_name, delta_has_inline_secret, inline_secret
from .contract import NAME, matches
from .frame_spec import SpecHeld, canonical, check_file_env, disjoint, validate_bind, validate_env


def check(ok, code):
    if not ok:
        raise SpecHeld(code)


def delta_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_references(env, mounts):
    refs = [f"{row['name']}={row['after']}" for row in env if row["after"] is not None]
    check_file_env(refs, mounts)


def inspect_binds(mounts):
    return [{"Type": m["Type"], "Target": m["Destination"], "ReadOnly": m.get("RW") is False} for m in mounts]


def validate_value(name, value, allowlist=None):
    if value is not None:
        check(not credential_name(name) and not inline_secret(value), INLINE_SECRET)
        try:
            validate_env([{"name": name, "value": value}], allowlist)
        except SpecHeld as exc:
            if exc.code == "SECRET_ENV_DENIED":
                raise SpecHeld(INLINE_SECRET) from None
            raise
        if name == "SPRING_APPLICATION_JSON" or value.lstrip().startswith("{") or (
                value.lstrip().startswith("[") and not re.fullmatch(r"\[[0-9a-fA-F:.]+\]:[0-9]+", value)):
            try:
                json.loads(value)
            except (ValueError, RecursionError):
                raise SpecHeld("INVALID_ENV") from None


def validate_delta(delta, policy, module, *, predecessor_mounts=()):
    """policy is the installed profile for this module, outside configDelta."""
    check(policy.get("module") == module, "DELTA_POLICY_MODULE")
    check(not delta_has_inline_secret(dict(policy, configDelta=delta)), INLINE_SECRET)
    check(isinstance(delta, dict) and set(delta) <= {"env", "binds", "aliases"}, "INVALID_DELTA")
    env, binds, aliases = delta.get("env", []), delta.get("binds", []), delta.get("aliases", {})
    check(isinstance(env, list) and isinstance(binds, list) and isinstance(aliases, dict), "INVALID_DELTA")
    check(env or binds or any(aliases.values()), "EMPTY_DELTA")
    allowed, shown = policy.get("envAllowlist", []), policy.get("showValues", [])
    check(all(isinstance(v, list) and all(matches(r"[A-Z_][A-Z0-9_]*", k) for k in v)
              for v in (allowed, shown)) and set(shown) <= set(allowed), "INVALID_ENV_ALLOWLIST")
    seen = set()
    for row in env:
        check(isinstance(row, dict) and set(row) == {"name", "before", "after"}, "INVALID_ENV")
        name = row["name"]
        check(isinstance(name, str) and name not in seen, "AMBIGUOUS_ENV")
        seen.add(name)
        for value in (row["before"], row["after"]):
            validate_value(name, value, allowed)
        check(row["before"] != row["after"], "EMPTY_DELTA")
    mounts = inspect_binds(predecessor_mounts)
    targets = [PurePosixPath(m["Target"]) for m in mounts]
    for bind in binds:
        check(isinstance(bind, dict) and bind.get("mode") == "ro" and "sha256" in bind, "DELTA_RO_BIND_REQUIRED")
        mount = validate_bind(bind, policy)
        target = PurePosixPath(mount["Target"])
        check(disjoint(target, targets), "MOUNT_TARGET_OVERLAP")
        targets.append(target)
        mounts.append(mount)
    file_references(env, mounts)
    for network, additions in aliases.items():
        check(network in policy["networks"] and isinstance(additions, list) and additions
              and all(matches(NAME, alias) and not matches(r"[a-f0-9]{12}", alias) for alias in additions),
              "INVALID_DELTA_ALIAS")
        add_aliases(policy["networks"][network]["aliases"], additions)
    return delta


def add_aliases(existing, additions):
    names = {alias.lower() for alias in existing}
    for alias in additions:
        check(alias.lower() not in names, "DELTA_ALIAS_EXISTS")
        names.add(alias.lower())
    return [*existing, *additions]


def changed_env(entries, changes, predecessor):
    def values(items):
        found = {}
        for item in items or ():
            name, sep, value = item.partition("=")
            check(name not in found, "AMBIGUOUS_ENV")
            found[name] = value if sep else None
        return found

    old, effective = values(predecessor), values(entries)
    seen = set()
    for row in changes:
        name = row["name"]
        check(name not in seen, "AMBIGUOUS_ENV")
        seen.add(name)
        check(old.get(name) == row["before"], "DELTA_PRECONDITION_FAILED")
        if row["after"] is None:
            effective.pop(name, None)
        else:
            effective[name] = row["after"]
    return [name if value is None else f"{name}={value}" for name, value in effective.items()]


def overlay(create_body, delta, predecessor_env):
    """Apply CAS and additions to a private request. Leave its inputs untouched."""
    body = deepcopy(create_body)
    if delta.get("env"):
        body["Env"] = changed_env(body.get("Env"), delta["env"], predecessor_env)
    host = body["HostConfig"]
    if delta.get("binds"):
        existing = list(host.get("Binds") or ())
        host["Binds"] = existing + [f"{b['source']}:{b['target']}:ro" for b in delta["binds"]]
    endpoints = body["NetworkingConfig"]["EndpointsConfig"]
    for network, additions in delta.get("aliases", {}).items():
        check(network in endpoints, "INVALID_DELTA_ALIAS")
        ep = endpoints[network]
        ep["Aliases"] = add_aliases(ep.get("Aliases") or [], additions)
    return body


def expected_after(predecessor_inspect, delta):
    """Project only reviewed changes onto inspect, including realized bind mounts."""
    doc = deepcopy(predecessor_inspect)
    env = doc["Config"].get("Env")
    networks = doc["NetworkSettings"]["Networks"]
    projection = overlay({"Env": env, "HostConfig": doc["HostConfig"],
                          "NetworkingConfig": {"EndpointsConfig": networks}}, delta, env)
    if delta.get("env"):
        doc["Config"]["Env"] = projection["Env"]
    doc["HostConfig"] = projection["HostConfig"]
    for name, additions in delta.get("aliases", {}).items():
        ep = networks[name]
        ep["Aliases"] = projection["NetworkingConfig"]["EndpointsConfig"][name]["Aliases"]
        if ep.get("DNSNames") is not None:
            ep["DNSNames"] = list(dict.fromkeys(ep["DNSNames"] + additions))
    occupied = [PurePosixPath(m["Destination"]) for m in doc["Mounts"]]
    occupied.extend(map(PurePosixPath, doc["HostConfig"].get("Tmpfs") or {}))
    for bind in delta.get("binds", []):
        target = PurePosixPath(bind["target"])
        check(disjoint(target, occupied), "MOUNT_TARGET_OVERLAP")
        occupied.append(target)
        doc["Mounts"].append({"Type": "bind", "Source": bind["source"], "Destination": bind["target"],
                              "Mode": "ro", "RW": False, "Propagation": "rprivate"})
    file_references(delta.get("env", []), inspect_binds(doc["Mounts"]))
    return doc


def approval_lines(delta, show_values=(), *, inherited=()):
    profile = {"configDelta": delta, "showValues": list(show_values)}
    check(not delta_has_inline_secret(profile), INLINE_SECRET)
    env = delta.get("env", [])

    def display(name, value, *, replacement=False):
        validate_value(name, value)
        # In a mixed delta even the public flag can repeat a private value.
        if (replacement and len(env) == 1 and name == "SPRING_FLYWAY_ENABLED" and name in show_values
                and value in (None, "true", "false", "enabled", "disabled")
                and (value is None or public(value) == value and not any(value in item for item in inherited))):
            return "assente" if value is None else json.dumps(value, ensure_ascii=False)
        return "sha256 " + delta_digest(value)

    lines = []
    for row in env:
        name = row["name"]
        check(matches(r"[A-Z_][A-Z0-9_]*", name), "INVALID_ENV")
        label = name if public(name) == name else "sha256 " + delta_digest(name)
        lines.append(f"ENV {label} da {display(name, row['before'])} a {display(name, row['after'], replacement=label == name)}")
    for bind in delta.get("binds", []):
        check(matches(r"[0-9a-f]{64}", bind["sha256"]), "INVALID_BIND_DIGEST")
        lines.append(f"Bind destinazione sha256 {delta_digest(bind['target'])} · contenuto sha256 {bind['sha256']}")
    for network, additions in sorted(delta.get("aliases", {}).items()):
        lines.extend(f"Alias sha256 {delta_digest(alias)} · rete sha256 {delta_digest(network)}" for alias in additions)
    # A private value can coincide with a fixed keyword or part of a digest.
    # Never rewrite the grammar of a line that will be presented for approval.
    with scope(profile):
        check(public(lines) == lines, "REDACTION_COLLISION")
    return lines
