#!/usr/bin/env python3
"""Prepare B1 revision 3 against the retained, stopped provider cohort."""

import argparse
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_routes import b1, publication as P
from tools.semantic_provider_routes.routes import canonical, require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ("plan", "apply"):
        group.add_argument("--" + mode, dest="mode", action="store_const", const=mode)
    parser.add_argument("--routes-receipt-sha256", required=True)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{64}", args.routes_receipt_sha256):
        parser.error("invalid --routes-receipt-sha256")
    if ((args.mode == "apply") != (args.plan_sha256 is not None)
            or args.plan_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256)):
        parser.error("--plan-sha256 is required only with --apply")
    progress = {"outputCreated": False}
    try:
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.dont_write_bytecode, "ISOLATED_ROOT_REQUIRED")
        os.umask(0o077)
        result = b1.execute(args.mode, args.routes_receipt_sha256, args.plan_sha256, progress=progress)
        print(canonical({"schema": b1.SCHEMA, **P.FLAGS, **result}).decode(), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(canonical({"schema": b1.SCHEMA, "status": "PARTIAL" if progress["outputCreated"] else "HELD",
                         "reason": P.public_error(error), **progress,
                         "output": str(b1.OUTPUT), "outputExists": os.path.lexists(b1.OUTPUT),
                         **P.FLAGS}).decode(), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
