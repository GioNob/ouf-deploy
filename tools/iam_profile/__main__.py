"""python -m tools.iam_profile ACTION PROFILE SNAPSHOT [EVIDENCE] [--parameters FILE]"""
import argparse
import http.client
import sys

from .plan import gate, plan, receipt
from .profile import Invalid, canonical, materialize, read_json, require, validate
from .qualify import LiveProbe, operator_signal, qualify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "plan", "receipt", "gate", "qualify"))
    parser.add_argument("profile")
    parser.add_argument("snapshot")
    parser.add_argument("evidence", nargs="?", help="receipt for gate or private probe settings for qualify")
    parser.add_argument("--parameters", help="resolve whole values in the profile template")
    args = parser.parse_args()
    try:
        profile = read_json(args.profile)
        if args.parameters:
            profile = materialize(profile, read_json(args.parameters))
        snapshot = read_json(args.snapshot)
        require(args.action in ("gate", "qualify") or args.evidence is None, "INPUT_INVALID")
        if args.action == "gate":
            evidence = read_json(args.evidence) if args.evidence else None
            result = gate(profile, snapshot, evidence)
        elif args.action == "receipt":
            result = receipt(profile, snapshot)
        elif args.action == "plan":
            result = plan(profile, snapshot)
        elif args.action == "validate":
            validate(profile, snapshot.get("gatewayBindings") if isinstance(snapshot, dict) else None)
            result = {"status": "VALID"}
        else:
            require(args.evidence is not None, "PET_CONFIG_INVALID")
            # Only run the live PET against the reviewed effective configuration.
            projected = plan(profile, snapshot)
            require(all(row["action"] in ("unchanged", "foreign") for row in projected["diff"]),
                    "PROFILE_DRIFT")
            probe = LiveProbe(profile, read_json(args.evidence))
            result = qualify(profile, snapshot["gatewayBindings"], probe, begin_revocation=operator_signal)
    except Invalid as exc:
        result = {"status": "HELD", "code": str(exc)}
    except (http.client.HTTPException, OSError, ValueError, TypeError, KeyError, EOFError, AttributeError, RecursionError):
        result = {"status": "HELD", "code": "INPUT_OR_PROBE_INVALID"}
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 2 if result.get("status") == "HELD" else 0


if __name__ == "__main__":
    raise SystemExit(main())

