"""Read-only parts of the executor profile and Gateway installation contracts."""
from contextlib import contextmanager
import re

import gateway_bundle
import gateway_policy
from mandate import Held
from module_release import contract

from .checks import Issue, documents
from .inputs import fields, inside, require


@contextmanager
def profile_section(name):
    try:
        yield
    except (contract.Held, KeyError, ValueError, TypeError, AttributeError, IndexError) as exc:
        raise Issue("PROFILE_INVALID", name) from exc


def profile_valid(profile):
    for key in ("successorImage", "nextSuccessorImage"):
        with profile_section(key):
            image = profile[key]
            fields(image, ["ci", "inbox", "migrationsField", "predecessorMigrations"])
            fields(image["ci"], contract.CI_COORDINATES)
            contract.validate_ci(image["ci"])
    with profile_section("modules"):
        for name, module in profile["modules"].items():
            contract.validate(module)
            require(module["module"] == name)
    if "semanticDatabase" in profile:
        with profile_section("semanticDatabase"):
            require(contract.valid_semantic_database(profile["semanticDatabase"]))
    with profile_section("gateway"):
        require(gateway_policy.valid_profile(profile["gateway"]))
    with profile_section("runbooks"):
        validate_runbooks(profile["runbooks"])


def validate_runbooks(bindings):
    require(isinstance(bindings, dict))
    versions = {op: set() for op in ("start", "stop", "probe", "issue", "upgrade")}
    for key in bindings:
        match = re.fullmatch(r"(start|stop|probe|issue|upgrade)-([1-9][0-9]*)", key)
        require(match)
        versions[match[1]].add(int(match[2]))
    base = versions["start"]
    require(base and len(base) == max(base) - min(base) + 1)
    require(versions["stop"] == versions["probe"] == base)
    require(versions["issue"] == versions["upgrade"] == base - {min(base)})


def installation_values(bundle, profile):
    values = profile["gateway"]["values"]
    require(isinstance(values, dict))
    types = {}
    require(isinstance(bundle["placeholders"], list))
    for declaration in bundle["placeholders"]:
        fields(declaration, ["name", "type"])
        name, kind = declaration["name"], declaration["type"]
        require(gateway_bundle.matches(gateway_bundle.NAME, name) and name not in types)
        require(kind in ("string", "url", "integer", "secret"))
        types[name] = kind
    missing = types.keys() - values.keys()
    if missing:
        raise Issue("GATEWAY_VALUES_MISSING", ", ".join(f"{n} ({types[n]})" for n in sorted(missing)))
    if values.keys() - types.keys():
        raise Issue("GATEWAY_VALUES_UNUSED", "Il profilo contiene valori non dichiarati.")

    used = set()
    require(isinstance(bundle["resources"], list))
    routes = set()
    for row in bundle["resources"]:
        require(row["kind"] in gateway_policy.KINDS and isinstance(row["body"], dict))
        if row["kind"] == "routes":
            require(row["id"] not in routes)
            routes.add(row["id"])
        try:
            gateway_bundle.substitute(row["body"], types, values, used)
        except (ValueError, Held):
            # Identify the failing declaration using the same type checks, without
            # serializing a substituted body, a profile value or exception text.
            for name, kind in types.items():
                try:
                    gateway_bundle.substitute({"$installation": name}, types, values, set())
                except (ValueError, Held):
                    raise Issue("GATEWAY_VALUE_INVALID", f"{name} ({kind})") from None
            raise Issue("GATEWAY_PLACEHOLDER_INVALID", "Riferimento a placeholder non valido.") from None
    if used != types.keys():
        raise Issue("GATEWAY_VALUES_UNUSED", "Il bundle non usa tutti i placeholder dichiarati.")
    return routes


def gateway_installation(cap, root, bundle, profile):
    routes = installation_values(bundle, profile)
    gateway = cap["gateway"]
    path = inside(root, root / gateway["capabilityFile"])
    descriptor, = documents(path)
    if (descriptor["metadata"]["id"] != cap["capabilityId"]
            or descriptor["spec"]["operationType"] != cap["operation"]
            or descriptor["spec"]["scope"] != cap["requiredScope"]):
        raise Issue("GATEWAY_CAPABILITY_MISMATCH", "Identità, operazione o scope discordanti.")
    missing = set(gateway["routeIds"]) - routes
    if missing:
        raise Issue("GATEWAY_ROUTE_MISSING", ", ".join(sorted(missing)))
