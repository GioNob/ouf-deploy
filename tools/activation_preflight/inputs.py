"""Closed request contract and local source-tree boundaries."""
import json
import re
from pathlib import Path


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def require(condition):
    if not condition:
        raise ValueError("invalid input")


def fields(obj, keys, optional=()):
    require(isinstance(obj, dict) and set(keys) <= obj.keys() <= set(keys) | set(optional))


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)


def identifiers(values, *, empty=False):
    require(isinstance(values, list) and (empty or values) and all(map(identifier, values)))
    require(len(set(values)) == len(values))


def relative(value):
    require(isinstance(value, str) and all(identifier(part) for part in value.split("/")))


def inside(root, path):
    path = path.resolve()
    require(path.is_relative_to(root))
    return path


def request_caps(request):
    fields(request, ["contract", "capabilities"])
    require(request["contract"] == "ouf.activation-request.v1")
    caps = request["capabilities"]
    require(isinstance(caps, list) and caps)
    for cap in caps:
        fields(cap, "capabilityId owner operation requiredScope allowedActors ownerConfig "
               "ownerResourceAttributes gateway mcp roles".split())
        for key in ("capabilityId", "owner", "operation", "requiredScope"):
            require(identifier(cap[key]))
        identifiers(cap["allowedActors"])
        identifiers(cap["roles"])
        identifiers(cap["ownerResourceAttributes"], empty=True)
        owner = cap["ownerConfig"]
        fields(owner, ["file", "flags", "limits"])
        relative(owner["file"])
        identifiers(owner["limits"], empty=True)
        require(isinstance(owner["flags"], list))
        properties = list(owner["limits"])
        for flag in owner["flags"]:
            fields(flag, ["property", "expected"])
            require(type(flag["expected"]) is bool)
            properties.append(flag["property"])
        identifiers(properties)
        fields(cap["gateway"], ["capabilityFile", "routeIds"])
        relative(cap["gateway"]["capabilityFile"])
        identifiers(cap["gateway"]["routeIds"])
        fields(cap["mcp"], ["tool"], ["requiredAuthorizationCapability"])
        require(all(identifier(v) for v in cap["mcp"].values()))
    identifiers([cap["capabilityId"] for cap in caps])
    return caps


def source_dirs(bindings, caps):
    roots = {}
    for binding in bindings:
        name, separator, directory = binding.partition("=")
        require(identifier(name) and separator and directory and name not in roots)
        roots[name] = Path(directory).resolve(strict=True)
        require(roots[name].is_dir())
    require({"onboarding", "gateway", "mcp", *(c["owner"] for c in caps)} <= roots.keys())
    return roots
