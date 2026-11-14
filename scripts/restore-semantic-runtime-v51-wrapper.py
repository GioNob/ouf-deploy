#!/usr/bin/env python3
"""Governed undo of task-29b: restore the B1 (v5) runtime wrapper. No container lifecycle calls.

Human-invoked, --plan / --apply --plan-sha256. Restores the exact bytes the
v5.1 switch retained in <v51-root>/switch/prior-runtime-wrapper.sh, through the
unchanged guarded switch primitive, in a NEW claim root. Allowed only while B2
has not progressed: v5.1 and v5 arming roots empty, both successors created and
never started, B1 source/configuration unchanged. Independent of the v5.1
install receipt, so it also works after a partial install. The task-26 restore
(v5 -> v4) remains available as a second level.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "ouf.semantic-runtime-v51-wrapper-restore.v1"
COHORT = "tools/semantic_cohort_admission/cohort-draft"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}")
COUNTERS = dict(containerLifecycleOperations=0, dockerStartRequests=0, nftWrites=0,
                daemonRestarted=False, privateKeysRead=0, signaturesIssued=0,
                startAuthorized=False, leaseAuthorized=False)
PUBLIC_ERRORS = ("Held", "Denied", "TransactionDenied")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def dependencies():
    namespace = types.ModuleType("tools")
    namespace.__path__ = [str(ROOT / "tools"), str(ROOT / COHORT / "tools")]
    sys.modules["tools"] = namespace
    sys.path[:0] = [str(ROOT / "tools/semantic_transaction_profiles"),
                    str(ROOT / "tools/semantic_frame_compiler")]
    from tools.semantic_runtime_v51_install import common as C
    import guarded_runtime_switch as S
    return types.SimpleNamespace(C=C, S=S)


def observe(args, d, *, after_rename=False):
    """Fresh read-only observation. No lock acquisition and no publication."""
    C, S = d.C, d.S
    v51 = C.absolute(args.v51_root)
    current, wrapper_identity = S.custody(args.wrapper, 0o755)
    if not after_rename and C.sha(current) == args.prior_wrapper_sha256:
        raise C.Held("NOTHING_TO_RESTORE")
    expected = args.prior_wrapper_sha256 if after_rename else args.installed_wrapper_sha256
    C.require(C.sha(current) == expected, "INSTALLED_WRAPPER_DRIFT")
    if not after_rename:
        C.require(C.wrapper_targets(current)[1] == str(v51 / "source" / C.RUNTIME), "INSTALLED_WRAPPER_TARGET_DRIFT")
    claim_raw, _ = S.custody(v51 / "switch/runtime-switch-claim.json", 0o600)
    claim = C.parse(claim_raw, "V51_SWITCH_CLAIM_MISMATCH")
    C.require(claim.get("schema") == "ouf.semantic-provider-runtime-switch-claim.v1"
              and claim.get("priorWrapperHash") == args.prior_wrapper_sha256
              and claim.get("proposedWrapperHash") == args.installed_wrapper_sha256, "V51_SWITCH_CLAIM_MISMATCH")
    prior, prior_identity = S.custody(v51 / "switch/prior-runtime-wrapper.sh", 0o600)
    C.require(C.sha(prior) == args.prior_wrapper_sha256, "PRIOR_WRAPPER_BACKUP_DRIFT")
    b1 = C.b1_state(S, args.b1_root, args.b1_plan_sha256)
    evidence = b1["evidence"]
    C.require(evidence["installedWrapperSha256"] == args.prior_wrapper_sha256, "PRIOR_WRAPPER_NOT_B1")
    python, source, configuration = C.wrapper_targets(prior)
    C.require(python == b1["config"]["pythonPath"] and source == evidence["source"]["path"]
              and configuration == evidence["configuration"]["path"], "PRIOR_WRAPPER_TARGET_DRIFT")
    C.executable_hash(python, b1["config"]["pythonSha256"])
    C.empty_directory(v51 / "arming", S, "B2_ARMING_PRESENT_RESTORE_DENIED")
    frames = C.successor_frames(args.docker, args.docker_sha256, args.docker_socket, evidence["containerIds"])
    lock = C.guard_lock(S, args.lock)
    return {"schema": SCHEMA, "v51Root": str(v51), "claimSha256": C.sha(claim_raw),
            "priorWrapper": {"path": str(v51 / "switch/prior-runtime-wrapper.sh"), "sha256": C.sha(prior),
                             "identity": list(prior_identity), "byteLength": len(prior)},
            "b1": evidence, "successorFrames": frames, "lock": lock,
            "wrapper": {"path": args.wrapper, "sha256": C.sha(current),
                        **({} if after_rename else {"identity": list(wrapper_identity)})},
            "restoreRoot": str(C.absolute(args.output_root) / args.output_name), **COUNTERS}


def plan(args, d):
    C, S = d.C, d.S
    out = C.absolute(args.output_root)
    C.require(NAME.fullmatch(args.output_name) is not None, "RESTRICTED_OUTPUT_NAME_REQUIRED")
    # Observe first: an already restored wrapper reports NOTHING_TO_RESTORE, the useful verdict.
    state = observe(args, d)
    for ancestor in (out, *out.parents):
        S.directory(ancestor)
    C.require(not os.path.lexists(out / args.output_name), "RESTORE_OUTPUT_ALREADY_EXISTS")
    C.require(out / args.output_name != C.absolute(args.v51_root) / "switch", "NEW_CLAIM_ROOT_REQUIRED")
    state["planSha256"] = C.sha(encoded(state))
    return state


def stable(state):
    return {k: v for k, v in state.items() if k not in ("wrapper", "planSha256")}


def apply(args, d, proposal, report):
    C, S = d.C, d.S
    C.require(args.plan_sha256 == proposal["planSha256"], "RESTORE_PLAN_DIGEST_CHANGED")
    root = Path(proposal["restoreRoot"])
    root.mkdir(mode=0o700)
    report.update(restoreRoot=str(root), outputCreated=True, doNotRerunApply=True)
    S.sync(root.parent)
    prior = S.custody(proposal["priorWrapper"]["path"], 0o600)[0]
    C.require(C.sha(prior) == args.prior_wrapper_sha256, "PRIOR_WRAPPER_BACKUP_DRIFT")

    def verify_locked(fd, phase):
        current = observe(args, d, after_rename=phase == "AFTER_RENAME")
        C.require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == tuple(proposal["lock"]["identity"][:2])
                  and stable(current) == stable(proposal), "RESTORE_OBSERVATION_DRIFT")

    outcome = S.switch_existing_wrapper(args.wrapper, args.installed_wrapper_sha256, prior, root,
                                        args.lock, proposal["lock"]["identity"], verify_locked)
    raw = S.custody(args.wrapper, 0o755)[0]
    C.require(raw == prior, "RESTORED_WRAPPER_READBACK_DRIFT")
    report.update(status="SEMANTIC_RUNTIME_V51_WRAPPER_RESTORED", planSha256=proposal["planSha256"],
                  switchOutcome="REPLACED", primitiveResult=outcome,
                  wrapperBefore=args.installed_wrapper_sha256, wrapperAfter=C.sha(raw))
    S.publish_once(root / "restore-result.json", encoded(report) + b"\n")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("v51-root", "b1-root", "b1-plan-sha256", "wrapper", "installed-wrapper-sha256",
                 "prior-wrapper-sha256", "lock", "docker", "docker-sha256", "docker-socket",
                 "output-root", "output-name"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    for name, value in vars(args).items():
        if name.endswith("sha256") and value is not None and not re.fullmatch("[0-9a-f]{64}", value):
            parser.error("invalid SHA-256 for --" + name.replace("_", "-"))
    if args.installed_wrapper_sha256 == args.prior_wrapper_sha256:
        parser.error("installed and prior wrapper hashes must differ")
    if not re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket):
        parser.error("--docker-socket must be unix:///<path>")
    if (args.apply and args.plan_sha256 is None) or (args.plan and args.plan_sha256 is not None):
        parser.error("apply requires --plan-sha256; plan forbids it")
    return args


def main(argv=None):
    args = arguments(argv)
    report = {"schema": SCHEMA, "status": "HELD", "switchOutcome": "UNCHANGED", "doNotRerunApply": False,
              **COUNTERS}
    d = None
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise PermissionError("ROOT_CUSTODY_REQUIRED")
        if not (sys.flags.isolated and sys.dont_write_bytecode):
            raise PermissionError("ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        d = dependencies()
        proposal = plan(args, d)
        if args.plan:
            report.update(proposal, status="PLAN_READY")
        else:
            apply(args, d, proposal, report)
    except Exception as error:
        known = type(error).__name__ in PUBLIC_ERRORS
        reason = str(error) if isinstance(error, PermissionError) else (
            d.C.public_reason(error) if d is not None and known else type(error).__name__)
        report.update(status="HELD", reason=reason, **COUNTERS)
        primitive = getattr(error, "diagnosis", None)
        if type(primitive) is dict:
            report["primitive"] = {k: primitive[k] for k in ("stage", "switchOutcome", "wrapperReplaced",
                                                             "renameAttempted", "errorType") if k in primitive}
            report["switchOutcome"] = primitive.get("switchOutcome", report["switchOutcome"])
        if not known:
            import traceback
            report["callChain"] = [{"function": f.name, "line": f.lineno}
                                   for f in traceback.extract_tb(error.__traceback__)[-6:]]
        if report.get("outputCreated") and d is not None:
            report["doNotRerunApply"] = True
            try:
                d.S.publish_once(Path(report["restoreRoot"]) / "restore-result.json", encoded(report) + b"\n")
            except Exception:
                report["diagnosisSaved"] = False
    print(encoded(report).decode(), flush=True)
    return 1 if report["status"] == "HELD" else 0


if __name__ == "__main__":
    raise SystemExit(main())
