#!/usr/bin/env python3
"""OUF capture CLI. Only stable reason codes and projected metadata go to stdout."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from capture.apply import apply
from capture.contract import Held, profile, registry, require
from capture.host import Host
from capture.plan import make_plan
from capture.verify import verify


def run(args):
    entries = registry()
    if args.mode == "verify":
        return dict(status="VERIFIED", archives=verify(args.folder, entries, args.identity, args.age)), 0
    require(sys.platform == "linux" and os.geteuid() == 0 and sys.flags.isolated, "ROOT_ISOLATED_REQUIRED")
    os.umask(0o077)
    os.setpriority(os.PRIO_PROCESS, 0, 19)
    cfg = profile(args.profile, entries)
    host = Host(cfg)
    commit = os.environ.get("OUF_CAPTURE_COMMIT") or subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "INVALID_COMMIT")
    if args.mode == "apply":
        require(re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256), "INVALID_PLAN_DIGEST")
        result = apply(host, cfg, entries, args.profile, commit, args.plan_sha256)
        return dict(status="COMPLETE", planSha256=result["planSha256"], archives=sorted(result["archives"])), 0
    plan, digest = make_plan(host, cfg, entries, args.profile, commit)
    sizes = {k: v["estimate"] for k, v in plan["families"].items()}
    measures = dict(estimatedBytes=plan["estimatedBytes"], familyBytes=sizes,
                    excludedItems=len(plan["excluded"]))
    if args.measure:
        return measures, int(bool(plan["reasons"]))
    return dict(status="HELD" if plan["reasons"] else "PLANNED", reasons=plan["reasons"],
                planSha256=digest, **measures, families=plan["families"], excluded=plan["excluded"],
                unclassified=plan["unclassified"]), int(bool(plan["reasons"]))


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("plan", "apply"):
        command = sub.add_parser(mode)
        command.add_argument("profile", type=Path)
        if mode == "plan":
            command.add_argument("--measure", action="store_true")
        else:
            command.add_argument("--plan-sha256", required=True)
    command = sub.add_parser("verify")
    command.add_argument("folder", type=Path)
    command.add_argument("--identity", type=Path)
    command.add_argument("--age", default="age")
    args = parser.parse_args(argv)
    try:
        result, code = run(args)
    except Held as exc:
        result, code = dict(status="HELD", reason=str(exc)), 1
    except (OSError, ValueError, TypeError, KeyError, IndexError, StopIteration,
            subprocess.SubprocessError, tarfile.TarError, RecursionError):
        result, code = dict(status="HELD", reason="CAPTURE_IO_OR_FORMAT"), 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
