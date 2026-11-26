"""Private module install policy and closed workflow request."""
from . import contract
from .contract import IMAGE, NAME, SHA, matches
from .frame_spec import check, install_shape, validate_networks


SCHEMA = "ouf.module-install.v1"


def valid_request(req, policy, common):
    from .profile_options import validate_module_profiles
    validate_module_profiles(req.get("module"), policy, release=False, check=contract.require)
    fields = common | {"operation", "schema", "module"}
    if "resumePlan" in req:
        fields.add("resumePlan")
        if req.get("phase") == "rollback" or not matches(SHA, req["resumePlan"]):
            return False
    name = req.get("module")
    return (set(req) == fields and req["schema"] == SCHEMA and matches(NAME, name)
            and "install" in policy.get("modules", {}).get(name, {})
            and req["phase"] in ("plan", "apply", "rollback"))


class _ReadinessFields(dict):
    """Keep the install grammar closed when an older common validator ignores an option."""
    def __init__(self, ready):
        super().__init__(ready)
        self.checked_keys = set()

    def __getitem__(self, key):
        self.checked_keys.add(key)
        return super().__getitem__(key)


def validate(p):
    contract.validate_profile_options(p)
    check(p.get("schema") in (SCHEMA, "ouf.module-release.v1") and matches(NAME, p.get("module"))
          and matches(NAME, p.get("container")), "INVALID_INSTALL_PROFILE")
    install_shape(p)
    check(isinstance(p["networks"], dict), "NETWORKS_REQUIRED")
    placeholders = {n: {"NetworkID": "0" * 64, "ips": [], "aliases": []} for n in p["networks"]}
    validate_networks(p["networks"], placeholders)
    # validate() currently takes a release profile. Supply its release-only
    # coordinates in a validation copy; none enter a plan, receipt or Engine call.
    check(isinstance(p["readiness"], dict), "INVALID_READINESS")
    ready = _ReadinessFields(p["readiness"])
    # The retained and failed release names are irrelevant to first creation.
    # Neither of these distinct validation-only names is reserved in Docker.
    unused = [n for n in ("unused", "unused1", "unused2") if n != p["container"]]
    common = {"migration": {"mode": "none", "rollbackCompatible": True},
              **p, "schema": "ouf.module-release.v1", "retainedName": unused[0], "failedName": unused[1],
              "oldImage": p.get("oldImage", p["ci"]["imageId"]), "readiness": ready}
    contract.validate(common)
    check(ready.keys() == ready.checked_keys, "INVALID_READINESS")
    ci = p["ci"]
    check(matches(NAME, ci["workflow"]) and type(ci["pullRequest"]) is int and ci["pullRequest"] > 0
          and "publisherFormat" not in ci and matches(NAME, ci.get("manifestSchema"))
          and matches(IMAGE, ci["imageId"]), "CI_PINS_REQUIRED")
