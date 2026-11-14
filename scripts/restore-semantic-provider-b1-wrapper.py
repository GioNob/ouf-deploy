#!/usr/bin/env python3
"""Governed B1 undo (task-26, D-025): restore the prior runtime wrapper.

Human-invoked, --plan / --apply --plan-sha256. Restores the exact bytes the B1
switch retained in <b1-root>/switch/prior-runtime-wrapper.sh, through the same
unchanged guarded switch primitive (claim, CAS and rename under the guard lock),
in a NEW claim root. Allowed only while B2 has not progressed: arming root empty,
both successors created and never started, prior wrapper target files unchanged.
No container lifecycle operation, no key read, no automatic retry.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "ouf.semantic-provider-b1-wrapper-restore.v1"
COHORT = "tools/semantic_cohort_admission/cohort-draft"
HEX = re.compile(r"[0-9a-f]{64}")
WRAPPER = re.compile(
    rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+) '
    rb'--configuration (/[A-Za-z0-9_./-]+) "\$@"\n')
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
COUNTERS = dict(containerLifecycleOperations=0, dockerStartRequests=0, nftWrites=0,
                daemonRestarted=False, privateKeysRead=0, signaturesIssued=0,
                startAuthorized=False, leaseAuthorized=False)


class Held(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Held(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def switch_module():
    """Import the unchanged switch primitive from the hash-verified delivery only."""
    namespace = types.ModuleType("tools")
    namespace.__path__ = [str(ROOT / "tools"), str(ROOT / COHORT / "tools")]
    sys.modules["tools"] = namespace
    sys.path[:0] = [str(ROOT / "tools/semantic_transaction_profiles"),
                   str(ROOT / "tools/semantic_frame_compiler")]
    import guarded_runtime_switch
    return guarded_runtime_switch


def absolute(value):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and path.as_posix() == value,
            "EXPLICIT_ABSOLUTE_PATH_REQUIRED")
    return path


def private_tree_empty(path, S):
    """Root 0700 directory with no entries at all (B2 has published nothing)."""
    for ancestor in (path, *path.parents):
        S.directory(ancestor)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "ARMING_ROOT_CUSTODY_UNPROVEN")
    require(not any(path.iterdir()), "B2_ARMING_PRESENT_RESTORE_DENIED")


def executable_hash(path, expected):
    path = absolute(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o111, "EXECUTABLE_CUSTODY_UNPROVEN")
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1048576):
            digest.update(chunk)
    require(digest.hexdigest() == expected, "EXECUTABLE_HASH_DRIFT")
    return str(path)


def docker_inspect(args, cid):
    docker = executable_hash(args.docker, args.docker_sha256)
    result = subprocess.run([docker, "--host", args.docker_socket, "inspect", cid],
                            stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=30)
    require(result.returncode == 0 and len(result.stdout) <= 4194304, "SUCCESSOR_INSPECT_FAILED")
    executable_hash(args.docker, args.docker_sha256)
    rows = json.loads(result.stdout)
    require(type(rows) is list and len(rows) == 1 and rows[0].get("Id") == cid, "SUCCESSOR_IDENTITY_UNPROVEN")
    return rows[0]


def observe(args, S, *, after_rename=False):
    """Fresh read-only observation. No lock acquisition and no publication."""
    b1 = absolute(args.b1_root)
    switch = b1 / "switch"
    claim_raw, _ = S.custody(switch / "runtime-switch-claim.json", 0o600)
    claim = json.loads(claim_raw)
    require(claim.get("schema") == "ouf.semantic-provider-runtime-switch-claim.v1"
            and claim.get("priorWrapperHash") == args.prior_wrapper_sha256
            and claim.get("proposedWrapperHash") == args.installed_wrapper_sha256,
            "B1_SWITCH_CLAIM_MISMATCH")
    prior, prior_identity = S.custody(switch / "prior-runtime-wrapper.sh", 0o600)
    require(sha(prior) == args.prior_wrapper_sha256, "PRIOR_WRAPPER_BACKUP_DRIFT")
    match = WRAPPER.fullmatch(prior)
    require(match is not None, "PRIOR_WRAPPER_SHAPE_UNPROVEN")
    python, source, configuration = (part.decode("ascii") for part in match.groups())
    executable_hash(python, args.python_sha256)
    source_path = absolute(source)
    mode = stat.S_IMODE(source_path.lstat().st_mode)
    require(mode in (0o600, 0o644, 0o755), "PRIOR_SOURCE_CUSTODY_UNPROVEN")
    source_raw, source_identity = S.custody(source_path, mode)
    require(sha(source_raw) == args.prior_source_sha256, "PRIOR_SOURCE_DRIFT")
    config_raw, config_identity = S.custody(configuration, 0o600)
    require(sha(config_raw) == args.prior_configuration_sha256, "PRIOR_CONFIGURATION_DRIFT")
    require(json.loads(config_raw).get("schema") == "ouf.semantic-docker-runtime-adapter.v4",
            "PRIOR_CONFIGURATION_NOT_V4")
    current, wrapper_identity = S.custody(args.wrapper, 0o755)
    expected_current = args.prior_wrapper_sha256 if after_rename else args.installed_wrapper_sha256
    if not after_rename and sha(current) == args.prior_wrapper_sha256:
        raise Held("NOTHING_TO_RESTORE")
    require(sha(current) == expected_current, "INSTALLED_WRAPPER_DRIFT")
    private_tree_empty(b1 / "arming", S)
    frames = {}
    for cid in args.successor:
        doc = docker_inspect(args, cid)
        state = doc["State"]
        require(state["Status"] == "created" and state["Running"] is False and state["Pid"] == 0
                and state["StartedAt"] == "0001-01-01T00:00:00Z" and doc["RestartCount"] == 0,
                "SUCCESSOR_PROGRESSED_RESTORE_DENIED")
        frames[cid] = sha(encoded({k: doc[k] for k in ("Id", "Image", "Config", "HostConfig", "Mounts")}))
    lock_raw, lock_identity = S.custody(args.lock, 0o600)
    require(lock_raw == b"", "GUARD_LOCK_NOT_EMPTY")
    return {"schema": SCHEMA, "b1Root": str(b1), "claimSha256": sha(claim_raw),
            "priorWrapper": {"path": str(switch / "prior-runtime-wrapper.sh"), "sha256": sha(prior),
                             "identity": list(prior_identity), "byteLength": len(prior)},
            "priorTargets": {"python": python, "source": {"path": source, "sha256": sha(source_raw),
                                                          "identity": list(source_identity)},
                             "configuration": {"path": configuration, "sha256": sha(config_raw),
                                               "identity": list(config_identity)}},
            "wrapper": {"path": args.wrapper, "sha256": sha(current),
                        **({} if after_rename else {"identity": list(wrapper_identity)})},
            "successorFrames": frames, "lock": {"path": args.lock, "identity": list(lock_identity)},
            "restoreRoot": str(absolute(args.output_root) / args.output_name), **COUNTERS}


def plan(args, S):
    out = absolute(args.output_root)
    for ancestor in (out, *out.parents):
        S.directory(ancestor)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.output_name), "RESTRICTED_OUTPUT_NAME_REQUIRED")
    require(not os.path.lexists(out / args.output_name), "RESTORE_OUTPUT_ALREADY_EXISTS")
    require(out / args.output_name != absolute(args.b1_root) / "switch", "NEW_CLAIM_ROOT_REQUIRED")
    state = observe(args, S)
    state["planSha256"] = sha(encoded(state))
    return state


def stable_part(state):
    return {k: v for k, v in state.items() if k not in ("wrapper", "planSha256")}


def apply(args, S, proposal, report):
    require(args.plan_sha256 == proposal["planSha256"], "RESTORE_PLAN_DIGEST_CHANGED")
    root = Path(proposal["restoreRoot"])
    root.mkdir(mode=0o700)
    report.update(restoreRoot=str(root), outputCreated=True, doNotRerunApply=True)
    S.sync(root.parent)
    prior = S.custody(proposal["priorWrapper"]["path"], 0o600)[0]
    require(sha(prior) == args.prior_wrapper_sha256, "PRIOR_WRAPPER_BACKUP_DRIFT")

    def verify_locked(fd, phase):
        current = observe(args, S, after_rename=phase == "AFTER_RENAME")
        require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == tuple(proposal["lock"]["identity"][:2])
                and stable_part(current) == stable_part(proposal), "RESTORE_OBSERVATION_DRIFT")

    outcome = S.switch_existing_wrapper(args.wrapper, args.installed_wrapper_sha256, prior, root,
                                        args.lock, proposal["lock"]["identity"], verify_locked)
    raw = S.custody(args.wrapper, 0o755)[0]
    require(raw == prior, "RESTORED_WRAPPER_READBACK_DRIFT")
    report.update(status="SEMANTIC_PROVIDER_B1_WRAPPER_RESTORED", planSha256=proposal["planSha256"],
                  switchOutcome="REPLACED", primitiveResult=outcome,
                  wrapperBefore=args.installed_wrapper_sha256, wrapperAfter=sha(raw))
    S.publish_once(root / "restore-result.json", encoded(report) + b"\n")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("b1-root", "wrapper", "installed-wrapper-sha256", "prior-wrapper-sha256",
                 "prior-source-sha256", "prior-configuration-sha256", "python-sha256", "lock",
                 "docker", "docker-sha256", "docker-socket", "output-root", "output-name"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--successor", action="append", required=True)
    args = parser.parse_args(argv)
    for name, value in vars(args).items():
        if name.endswith("sha256") and value is not None and not HEX.fullmatch(value):
            parser.error("invalid SHA-256 for --" + name.replace("_", "-"))
    if len(args.successor) != 2 or len(set(args.successor)) != 2 or not all(HEX.fullmatch(c) for c in args.successor):
        parser.error("exactly two distinct --successor container IDs required")
    if not re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket):
        parser.error("--docker-socket must be unix:///<path>")
    if (args.apply and args.plan_sha256 is None) or (args.plan and args.plan_sha256 is not None):
        parser.error("apply requires --plan-sha256; plan forbids it")
    return args


def main(argv=None):
    args = arguments(argv)
    report = {"schema": SCHEMA, "status": "HELD", "switchOutcome": "UNCHANGED",
              "doNotRerunApply": False, **COUNTERS}
    S = None
    try:
        require(os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        S = switch_module()
        proposal = plan(args, S)
        if args.plan:
            report.update(proposal, status="PLAN_READY")
        else:
            apply(args, S, proposal, report)
    except Exception as error:
        diagnosis = getattr(error, "diagnosis", {})
        reason = str(error) if isinstance(error, Held) or type(error).__name__ == "TransactionDenied" \
            else type(error).__name__
        report.update(diagnosis, status="HELD", reason=diagnosis.get("reason", reason))
        report.update(COUNTERS)
        if report.get("outputCreated") and S is not None:
            report["doNotRerunApply"] = True
            try:
                S.publish_once(Path(report["restoreRoot"]) / "restore-result.json", encoded(report) + b"\n")
            except Exception:
                report["diagnosisSaved"] = False
    print(encoded(report).decode(), flush=True)
    return 1 if report["status"] == "HELD" else 0


if __name__ == "__main__":
    raise SystemExit(main())
