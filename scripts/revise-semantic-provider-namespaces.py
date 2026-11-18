#!/usr/bin/env python3
"""D-053 additive revision of the installation profile: providerNamespaces only.

The historical installer (scripts/prepare-semantic-provider-installation.py) stays byte
for byte unchanged: it is part of the hash-bound B1 installation delivery. This script
loads it as a library (its main() is not run) and reuses its custody, revision and
publication primitives. Plan, apply and restore; no other profile field may change.
"""
import argparse
import os
from pathlib import Path
import re
import runpy
import sys

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))
_P = runpy.run_path(str(HERE.parent / 'prepare-semantic-provider-installation.py'),
                    run_name='prepare_semantic_provider_installation')
Held, require, canonical, digest = _P['Held'], _P['require'], _P['canonical'], _P['digest']
absolute, revision_base, revise = _P['absolute'], _P['revision_base'], _P['revise']
HEX = re.compile(r'[0-9a-f]{64}')

from tools.semantic_provider_config import contract  # noqa: E402
from tools.semantic_provider_routes.routes import Held as ContractHeld  # noqa: E402


def namespace_revision(args):
    """Return (proposal, new profile bytes) for an additive revision or its exact restore."""
    destination = absolute(contract.PROFILE_PATH)
    writes = {"profileFile": str(destination), "owner": "root:root", "mode": "0600", "directoriesIfMissing": []}
    current, binding = revision_base(destination, args.revise_from_sha256)
    require(digest(canonical(current) + b"\n") == args.revise_from_sha256, "REVISION_BASE_PROFILE_UNPROVEN")

    def additive(previous, row):
        require(contract.DECLARATION not in previous and previous.get("installationRef") == destination.parent.name
                and previous.get("externalEndpoints", {}).get("provider", {}).get("sourceRole") == "adapter",
                "NAMESPACE_REVISION_BASE_UNPROVEN")
        profile = previous | {contract.DECLARATION: [row]}
        try:
            contract.declaration(profile)
        except ContractHeld as error:
            raise Held(str(error)) from None
        return profile

    if args.restore:
        superseded = destination.with_name(destination.name + ".superseded-" + args.original_profile_sha256)
        profile, _ = revision_base(superseded, args.original_profile_sha256)
        require(digest(canonical(profile) + b"\n") == args.original_profile_sha256
                and type(current.get(contract.DECLARATION)) is list and len(current[contract.DECLARATION]) == 1
                and canonical(additive(profile, current[contract.DECLARATION][0])) == canonical(current),
                "NAMESPACE_RESTORE_DELTA_UNPROVEN")
    else:
        profile = additive(current, {"endpointRef": args.namespace_endpoint_ref,
                                     "namespacePrefixes": args.namespace_prefix})
    proposal = binding | {"writes": writes, "profileSha256": digest(canonical(profile) + b"\n"),
                          "providerNamespaces": (current if args.restore else profile)[contract.DECLARATION],
                          "profileDiff": [{"path": "/" + contract.DECLARATION,
                                           "change": "removed" if args.restore else "added"}]}
    return proposal | {"planSha256": digest(canonical(proposal))}, canonical(profile) + b"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("plan", "apply", "restore"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--revise-from-sha256", required=True)
    parser.add_argument("--namespace-endpoint-ref")
    parser.add_argument("--namespace-prefix", action="append")
    parser.add_argument("--original-profile-sha256")
    args = parser.parse_args()
    if args.restore:
        valid = (args.namespace_endpoint_ref is None and args.namespace_prefix is None
                 and HEX.fullmatch(args.original_profile_sha256 or ""))
    else:
        valid = (args.namespace_endpoint_ref is not None and bool(args.namespace_prefix)
                 and args.original_profile_sha256 is None)
    if (not valid or not HEX.fullmatch(args.revise_from_sha256)
            or (args.apply and not HEX.fullmatch(args.plan_sha256 or ""))
            or (not args.apply and args.plan_sha256 is not None)):
        parser.error("expected a pinned namespace revision or restore")
    report = {"schema": "ouf.semantic-provider-installation.plan.v1", "status": "HELD", "privateKeysRead": 0}
    try:
        require(os.geteuid() == 0 and os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        os.umask(0o077)
        proposal, raw = namespace_revision(args)
        report.update(proposal)
        if args.plan:
            report["status"] = "PLAN_READY"
        else:
            require(args.restore or args.plan_sha256 == proposal["planSha256"], "PLAN_DIGEST_CHANGED")
            report["revisionOutcome"] = {}
            report["supersededFile"] = revise(proposal, raw, report["revisionOutcome"])
            report["status"] = ("SEMANTIC_PROVIDER_INSTALLATION_PROFILE_RESTORED" if args.restore
                                else "SEMANTIC_PROVIDER_INSTALLATION_PROFILE_REVISED")
        print(canonical(report).decode(), flush=True)
        return 0
    except Held as error:
        report["reason"] = str(error)
    except Exception:
        report["reason"] = "INTERNAL_ERROR"
    print(canonical(report).decode(), flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
