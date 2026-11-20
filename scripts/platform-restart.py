#!/usr/bin/env python3
"""Operator CLI, also installed as the archive's __main__.py."""
import argparse
import os
from pathlib import Path
import sys

if Path(__file__).is_file():  # Repository entry point. A zipapp already contains the package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from platform_restart.controller import Controller, claim_boot, incident, receipt, stamp
from platform_restart.docker import Docker
from platform_restart.profile import Held, canonical, custody, load_profile, private_dir, require, sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["plan", "apply", "boot"])
    parser.add_argument("--action", choices=["start", "stop"])
    parser.add_argument("--plan-sha256")
    for field in ("profile", "profile-sha256", "receipts", "incidents"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    if ((args.mode == "boot") != (args.action is None)
            or (args.mode == "apply") != (args.plan_sha256 is not None)):
        parser.error("plan/apply require --action; only apply requires --plan-sha256")
    action = args.action or "start"
    try:
        import fcntl
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        private_dir(args.receipts)
        private_dir(args.incidents)
        # Both paths come from the installation, independently of the bytes under validation.
        fd = os.open(args.receipts, os.O_DIRECTORY)
        try:
            fallback = dict(schema="ouf.platform-restart-receipt.v1", mode=args.mode, action=action,
                            startedAt=stamp(), status="HELD", level=None, container=None, events=[],
                            profileSha256=args.profile_sha256)
            boot_id = None
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.mode == "boot":
                    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                custody(args.profile)
                cfg = load_profile(Path(args.profile).read_bytes(), args.profile_sha256)
                require(cfg["receipts"] == args.receipts and cfg["incidents"] == args.incidents,
                        "OUTPUT_BINDING_CHANGED")
                source_hash = sha(Path(sys.argv[0]).read_bytes())
            except (OSError, Held) as error:
                fallback["reason"] = (str(error) if isinstance(error, Held) else
                                      "OPERATION_BUSY" if isinstance(error, BlockingIOError) else "IO_FAILED")
                if boot_id:
                    try:
                        claim_boot(args.receipts, boot_id)
                    except Held as marker_error:
                        fallback["reason"] = str(marker_error)
                if args.mode == "boot" and fallback["reason"] != "BOOT_ALREADY_ATTEMPTED":
                    incident(args.incidents, fallback)
                result = {**fallback, "receipt": receipt(args.receipts, fallback)}
            else:
                result = Controller(cfg, args.profile_sha256, Docker(cfg), source_hash=source_hash).run(
                    args.mode, action, args.plan_sha256, boot_id)
        finally:
            os.close(fd)
    except (OSError, ImportError, Held):
        print("<3>PLATFORM_RESTART_CUSTODY_OR_IO_FAILED", file=sys.stderr)
        return 1
    print(canonical(result).decode())
    return int(result["status"] == "HELD")


if __name__ == "__main__":
    raise SystemExit(main())
