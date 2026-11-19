#!/usr/bin/env python3
"""Project, plan, publish or restore the D-052 APISIX route source."""

import argparse
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_routes import publication as P
from tools.semantic_provider_routes.routes import canonical, require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ("project", "plan", "apply", "restore"):
        group.add_argument("--" + mode, dest="mode", action="store_const", const=mode)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args(argv)
    if (args.mode == "apply" and args.plan_sha256 is None
            or args.plan_sha256 is not None and (args.mode not in {"apply", "restore"}
                                                or not re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256))):
        parser.error("--apply requires --plan-sha256; --restore accepts the same optional pin")
    progress = {"claimCreated": False, "sourceReplaced": False}
    try:
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.dont_write_bytecode, "ISOLATED_ROOT_REQUIRED")
        os.umask(0o077)
        if args.mode == "project":
            result = {"status": "ROUTES_D052_PROJECTED", "projection": P.projection()}
        else:
            result = P.execute(args.mode, args.plan_sha256, progress=progress)
        print(canonical({"schema": P.SCHEMA, **P.FLAGS, **result}).decode(), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(canonical({"schema": P.SCHEMA, "status": "PARTIAL" if any(progress.values()) else "HELD",
                         "reason": P.public_error(error), **progress,
                         "claim": str(P.CLAIM), "claimExists": os.path.lexists(P.CLAIM),
                         **P.FLAGS}).decode(), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
