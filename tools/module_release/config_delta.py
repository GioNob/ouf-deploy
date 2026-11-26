"""Reviewed, additive changes to a retained container's CREATE frame."""
from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import unquote

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


def check_json_properties(pairs):
    # The decoder visits every object, including duplicate and escaped property names.
    for key, _ in pairs:
        check(not re.search(r"password|passwd|passphrase|secret|token|credential|api[._-]?key|private[._-]?key|"
                            r"(?:^|[._-])(?:pwd|auths?|authorization|jwt|key)$", key, re.IGNORECASE),
              "SECRET_ENV_DENIED")


def validate_value(name, value, allowlist=None):
    if value is not None:
        validate_env([{"name": name, "value": value}], allowlist)
        if not name.endswith("_FILE"):
            check(name != "DOCKER_AUTH_CONFIG" and not re.search(r"(?:^|_)(?:AUTH$|(?:AUTHORIZATION|PWD|CONNECTION_STRING)(?:_|$))", name),
                  "SECRET_ENV_DENIED")
        if name == "SPRING_APPLICATION_JSON" or value.lstrip().startswith("{") or (
                value.lstrip().startswith("[") and not re.fullmatch(r"\[[0-9a-fA-F:.]+\]:[0-9]+", value)):
            try:
                json.loads(value, object_pairs_hook=check_json_properties)
            except (ValueError, RecursionError):
                raise SpecHeld("INVALID_ENV") from None
        check(not re.search(r"\bbasic\s+[A-Za-z0-9+/]+=*|(?:password|passwd|pwd|token|secret|accountkey|"
                            r"sharedaccesskey|sharedaccesssignature|sig)\s*=|"
                            r"\boracle:thin:[^@\s]+/[^@\s]+@", unquote(value), re.IGNORECASE),
              "SECRET_ENV_DENIED")


def validate_delta(delta, policy, module, *, predecessor_mounts=()):
    """policy is the installed profile for this module, outside configDelta."""
    check(policy.get("module") == module, "DELTA_POLICY_MODULE")
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


def approval_lines(delta, show_values=()):
    env = delta.get("env", [])

    def display(name, value):
        validate_value(name, value)
        # In a mixed delta even the public flag can repeat a private value.
        if (len(env) == 1 and name == "SPRING_FLYWAY_ENABLED" and name in show_values
                and value in (None, "true", "false", "enabled", "disabled")):
            return "assente" if value is None else json.dumps(value, ensure_ascii=False)
        return "sha256 " + delta_digest(value)

    lines = []
    for row in env:
        name = row["name"]
        lines.append(f"ENV {name} da {display(name, row['before'])} a {display(name, row['after'])}")
    for bind in delta.get("binds", []):
        lines.append(f"Aggiungi bind in sola lettura su {bind['target']} · sha256 {bind['sha256']}")
    for network, additions in sorted(delta.get("aliases", {}).items()):
        lines.extend(f"Aggiungi alias {alias} alla rete {network}" for alias in additions)
    return lines
