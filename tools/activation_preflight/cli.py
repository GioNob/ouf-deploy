"""One report row per check and requested capability."""
import argparse
import json
from pathlib import Path

import yaml
from module_release.contract import Held

from . import checks
from .inputs import read_json, request_caps, source_dirs
from .installation import gateway_installation, profile_valid


INPUT_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError,
                RecursionError, yaml.YAMLError, Held)


def object_file(path):
    # A missing optional flag and a supplied but invalid file have different semantics.
    try:
        obj = read_json(path)
        if isinstance(obj, dict):
            return obj
    except INPUT_ERRORS:
        pass
    return {}


def evaluate(cap, check, function, args, strict):
    try:
        function(*args)
    except checks.Issue as issue:
        status = "FAIL" if strict and issue.status == "UNVERIFIABLE" else issue.status
        code, detail = issue.code, issue.detail
    except INPUT_ERRORS:
        status, code, detail = "FAIL", "INPUT_INVALID", "Input del controllo assente o non valido."
    else:
        status, code, detail = "PASS", "OK", "Condizione verificata."
    return dict(capabilityId=cap["capabilityId"], check=check, status=status, code=code, detail=detail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in ("request", "profile", "gateway-bundle"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--source", action="append", required=True, metavar="MODULE=DIR")
    parser.add_argument("--role-catalogue", type=Path)
    parser.add_argument("--require-runtime", action="store_true")
    args = parser.parse_args(argv)
    try:
        caps = request_caps(read_json(args.request))
        roots = source_dirs(args.source, caps)
    except INPUT_ERRORS:
        parser.error("richiesta o associazioni --source non valide")

    profile = object_file(args.profile)
    bundle = object_file(args.gateway_bundle)
    roles = None
    if args.role_catalogue is not None:
        roles = object_file(args.role_catalogue)
        if "structuredContent" in roles:
            roles = roles["structuredContent"] if not roles.get("isError") else {}
            if not isinstance(roles, dict):
                roles = {}
    rows = []
    for cap in caps:
        for name, function, inputs in (
            ("OWNER_CONFIG", checks.owner_config, (cap, roots[cap["owner"]])),
            ("DESCRIPTOR_REGISTERED", checks.registered, (cap, roots["onboarding"])),
            ("GRANT_APPLICABLE", checks.grant, (cap, roles)),
            ("GATEWAY_INSTALLATION", gateway_installation, (cap, roots["gateway"], bundle, profile)),
            ("MCP_TOOL", checks.mcp_tool, (cap, roots["mcp"])),
            ("PROFILE_VALID", profile_valid, (profile,)),
        ):
            rows.append(evaluate(cap, name, function, inputs, args.require_runtime))
    statuses = {row["status"] for row in rows}
    overall = next(status for status in ("FAIL", "UNVERIFIABLE", "PASS") if status in statuses)
    print(json.dumps(dict(contract="ouf.activation-preflight-report.v1", status=overall, checks=rows)))
    return int(overall == "FAIL")
