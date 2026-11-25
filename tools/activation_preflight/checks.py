"""Checks against versioned sources and the ROLES view."""
import re

import yaml

from .inputs import inside, read_json, require, unique


class Issue(Exception):
    def __init__(self, code, detail, status="FAIL"):
        self.code = code
        self.detail = detail
        self.status = status


class ConfigLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        return unique(self.construct_pairs(node, deep=deep))


def documents(path):
    with path.open(encoding="utf-8-sig") as stream:
        yield from yaml.load_all(stream, Loader=ConfigLoader)


def flat_properties(mapping, prefix=""):
    require(isinstance(mapping, dict))
    for key, value in mapping.items():
        require(isinstance(key, str))
        name = prefix + key
        if isinstance(value, dict):
            yield from flat_properties(value, name + ".")
        else:
            yield name, value


def spring_values(path, *, profile_file=False):
    defaults, conditional = {}, set()
    for doc in documents(path):
        if doc is None:
            continue
        props = unique(flat_properties(doc))
        if (profile_file or "spring.profiles" in props or
                any(p.startswith("spring.config.activate.") for p in props)):
            conditional.update(props)
        else:
            defaults.update(props)
    return defaults, conditional


def owner_config(cap, root):
    config = cap["ownerConfig"]
    path = inside(root, root / config["file"])
    if re.fullmatch(r"application-.+\.ya?ml", path.name):
        raise Issue("OWNER_FLAG_PROFILE_ONLY", "Il file richiesto è specifico di un profilo.")
    defaults, conditional = spring_values(path) if path.is_file() else ({}, set())
    expected = {f["property"]: f["expected"] for f in config["flags"]}
    expected.update(dict.fromkeys(config["limits"]))
    missing = expected.keys() - defaults.keys()
    if missing:
        for sibling in sorted(path.parent.glob("application-*")):
            if sibling.suffix not in (".yml", ".yaml"):
                continue
            _, keys = spring_values(inside(root, sibling), profile_file=True)
            conditional.update(keys)
        if missing & conditional:
            raise Issue("OWNER_FLAG_PROFILE_ONLY", ", ".join(sorted(missing & conditional)))
        raise Issue("OWNER_PROPERTY_MISSING", ", ".join(sorted(missing)))
    for key, flag in expected.items():
        value = str(defaults[key])
        placeholder = re.fullmatch(r"\$\{[A-Za-z_][A-Za-z_0-9]*:([^{}]*)\}", value)
        if placeholder:
            value = placeholder[1]
        if flag is None:
            valid = re.fullmatch(r"[0-9]+", value) and int(value) > 0
        else:
            valid = value.lower() == str(flag).lower()
        if not valid:
            raise Issue("OWNER_DEFAULT_INVALID", key)


def registered(cap, root):
    source = inside(root, root / "src/main/java")
    files = list(source.rglob("ReleaseCapabilityRegistration.java"))
    require(len(files) == 1)
    java = inside(root, files[0]).read_text(encoding="utf-8")
    # Ignore comments without stripping comment-like characters in string literals.
    java = re.sub(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/',
                  lambda m: m[0] if m[0].startswith('"') else " ", java, flags=re.S)
    declarations = re.findall(r"\bCATALOGUES\s*=\s*List\.of\s*\(([^;()]*)\)\s*;", java)
    require(len(declarations) == 1)
    matches = []
    for literal in declarations[0].split(","):
        path = re.fullmatch(r'"(catalogue/[A-Za-z0-9_.-]+\.json)"', literal.strip())
        require(path)
        rows = read_json(inside(root, root / path[1]))
        require(isinstance(rows, list))
        matches.extend(row for row in rows if row["descriptor"]["capabilityId"] == cap["capabilityId"])
    if not matches:
        raise Issue("DESCRIPTOR_NOT_REGISTERED", "Capability assente dai cataloghi registrati.")
    if len(matches) == 1:
        row = matches[0]
        descriptor = row["descriptor"]
        if (row["ownerRef"] == cap["owner"] and descriptor["operation"] == cap["operation"]
                and descriptor["requiredScope"] == cap["requiredScope"]
                and sorted(descriptor["allowedActors"]) == sorted(cap["allowedActors"])):
            return
    raise Issue("DESCRIPTOR_MISMATCH", "Descrittore ambiguo o diverso dalla richiesta.")


def grant(cap, roles):
    if roles is None:
        raise Issue("ROLE_CATALOGUE_REQUIRED", "Vista ROLES assente.", "UNVERIFIABLE")
    for role in cap["roles"]:
        matches = [r for r in roles["roles"] if r["roleId"] == role]
        if len(matches) != 1:
            raise Issue("ROLE_NOT_FOUND", role)
        permissions = [p for p in matches[0]["permissions"] if p["capabilityId"] == cap["capabilityId"]]
        if not permissions:
            raise Issue("GRANT_MISSING", role)
        applicable = False
        for permission in permissions:
            constraints = permission["constraints"]
            if constraints is None:
                constraints = {}
            require(isinstance(constraints, dict))
            if constraints.get("effect") == "DENY" or permission.get("effect") == "DENY":
                raise Issue("GRANT_DENIED", role)
            require(constraints.get("effect") in (None, "ALLOW"))
            # Semantic vendor/authorization-sdk, AuthorizationPolicy.java (f630cc5),
            # GrantConstraints.matches lines 79-80. Here the input describes attribute
            # names, so we can verify presence, not the value of a particular resource.
            missing = []
            for selector, attr in (("allowedDataLabels", "dataAccessLabel"),
                                   ("allowedDetailLevels", "detailLevel")):
                values = constraints.get(selector)
                require(values is None or isinstance(values, list) and all(isinstance(v, str) for v in values))
                if values and attr not in cap["ownerResourceAttributes"]:
                    missing.append(attr)
            applicable |= not missing
        if not applicable:
            raise Issue("GRANT_ATTRIBUTES_MISSING", role)


def mcp_tool(cap, root):
    manifest = read_json(inside(root, root / "internal/manifest/capabilities.json"))
    mcp = cap["mcp"]
    rows = [r for r in manifest["capabilities"] if r.get("toolName") == mcp["tool"]]
    if len(rows) != 1:
        raise Issue("MCP_TOOL_NOT_FOUND", mcp["tool"])
    row = rows[0]
    auth = mcp.get("requiredAuthorizationCapability", cap["requiredScope"])
    if row["capabilityId"] != cap["capabilityId"] or row["requiredAuthorizationCapability"] != auth:
        raise Issue("MCP_TOOL_BINDING", mcp["tool"])
    if row.get("publicationState") != "ACTIVE":
        raise Issue("MCP_TOOL_INACTIVE", mcp["tool"])
