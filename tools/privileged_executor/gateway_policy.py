"""Root installation bindings and the two closed Gateway request shapes."""
import ipaddress
from pathlib import Path
import re


KINDS = ("upstreams", "services", "plugin_configs", "plugin_metadata", "global_rules", "routes")
ID = r"[A-Za-z0-9._-]{1,64}"
MAX_CHANGE_PATHS = 64


def match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def valid_profile(profile):
    if not isinstance(profile, dict) or set(profile) != {
        "source", "values", "container", "dockerSocket", "keyFile", "host", "port", "adminPath"
    }:
        return False
    source = profile["source"]
    values = profile["values"]
    if not isinstance(source, dict) or set(source) != {"repository", "workflow"}:
        return False
    paths = (profile["dockerSocket"], profile["keyFile"])
    try:
        loopback = isinstance(profile["host"], str) and ipaddress.ip_address(profile["host"]).is_loopback
    except ValueError:
        return False
    return (loopback and type(profile["port"]) is int and 0 < profile["port"] < 65536
            and match(r"(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+", profile["adminPath"])
            and match(r"[A-Za-z0-9][A-Za-z0-9_.-]*/ouf-api-gateway", source["repository"])
            and match(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*\.ya?ml", source["workflow"])
            and match(r"[A-Za-z0-9][A-Za-z0-9_.-]*", profile["container"])
            and all(isinstance(p, str) and Path(p).is_absolute() and ".." not in Path(p).parts for p in paths)
            and isinstance(values, dict)
            and all(match(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", k) and (isinstance(v, str) or type(v) is int)
                    for k, v in values.items()))


def valid_request(req, common):
    number = r"[1-9][0-9]{0,19}"
    if req.get("phase") == "return":
        return set(req) == common | {"operation", "releaseRun"} and match(number, req["releaseRun"])
    return (set(req) == common | {"operation", "sourceRun", "artifact", "sourcePr", "sourceCommit"}
            and req["phase"] in ("plan", "apply") and match(r"[0-9a-f]{40}", req["sourceCommit"])
            and all(match(number, req[key]) for key in ("sourceRun", "sourcePr", "artifact")))
