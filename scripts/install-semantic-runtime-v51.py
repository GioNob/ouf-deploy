#!/usr/bin/env python3
"""Human-invoked v5.1 publication and guarded wrapper switch (task-29b). No container lifecycle calls.

Starting state is B1 as installed by task-25 (v5, INACTIVE, empty arming).
Plan writes nothing. Apply publishes a NEW root, proves it with the real v5.1
loader and an isolated smoke, then replaces the wrapper through the unchanged
switch_existing_wrapper primitive, re-observing at every phase.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "ouf.semantic-runtime-v51-installation.v1"
COHORT = "tools/semantic_cohort_admission/cohort-draft"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}")
COUNTERS = dict(containerLifecycleOperations=0, dockerStartRequests=0, nftWrites=0,
                daemonRestarted=False, privateKeysRead=0, signaturesIssued=0,
                startAuthorized=False, leaseAuthorized=False)
PUBLIC_ERRORS = ("Held", "Denied", "MandateDenied", "AuthorityDenied", "AcceptanceDenied",
                 "TransactionDenied")
COPIED = ("runtimePath", "runtimeSha256", "pythonPath", "pythonSha256", "driverPath", "driverSha256",
          "admissionPath", "admissionSha256", "registryRoot", "runtimeStateRoot", "opensslBinding",
          "armingIssuerRef", "candidates")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def dependencies():
    """Only the delivered trees: the runbook verified every byte before this import boundary."""
    namespace = types.ModuleType("tools")
    namespace.__path__ = [str(ROOT / "tools"), str(ROOT / COHORT / "tools")]
    sys.modules["tools"] = namespace
    sys.path[:0] = [str(ROOT / "tools/semantic_transaction_profiles"),
                    str(ROOT / "tools/semantic_frame_compiler")]
    from tools.semantic_runtime_v51_install import common as C
    from tools.semantic_b1_acceptance import acceptance as B
    import guarded_runtime_switch as S
    sources = {}
    for name, pin in C.CLOSURE.items():
        raw, _ = S.custody(ROOT / name, 0o600)
        C.require(C.sha(raw) == pin, "DELIVERED_CLOSURE_DRIFT")
        sources[name] = raw
    M = C.mandates_module(sources[C.MANDATES], ROOT / C.MANDATES)
    R = C.compiled(sources[C.RUNTIME], ROOT / C.RUNTIME, "ouf_delivered_runtime_v51",
                   C.CLOSURE[C.RUNTIME], "DELIVERED_CLOSURE_DRIFT")
    return types.SimpleNamespace(C=C, B=B, S=S, M=M, R=R, sources=sources)


def output_root(args, d, existing):
    parent = d.C.absolute(args.output_root)
    for path in (parent, *parent.parents):
        d.S.directory(path)
    d.C.require(NAME.fullmatch(args.output_name) is not None, "RESTRICTED_OUTPUT_NAME_REQUIRED")
    root = parent / args.output_name
    d.C.require(existing or not os.path.lexists(root), "V51_OUTPUT_ALREADY_EXISTS")
    return root


def configuration(old, acceptance, args, root, d):
    C = d.C
    config = {key: old[key] for key in COPIED}
    config.update(schema=C.V51_SCHEMA, sourceHash=C.CLOSURE[C.RUNTIME], acceptance=acceptance["binding"],
                  b1b2Anchor=old["b1b2TrustPolicy"], mandateRoot=args.mandate_root,
                  armingRoot=str(root / "arming"), armingVerifierPath=str(root / "source" / C.VERIFIER),
                  armingVerifierSha256=C.CLOSURE[C.VERIFIER],
                  b1b2AuthorityModule={"path": str(root / "source" / C.MANDATES), "sha256": C.CLOSURE[C.MANDATES]})
    syntax(config, d.R)
    return config


def syntax(config, R):
    """Plan-time replica of the v5.1 load_configuration checks, without filesystem custody.

    The real loader runs on the published bytes before the switch (apply).
    """
    R.require(type(config) is dict and set(config) == R.CONFIG_FIELDS and config["schema"] == R.SCHEMA,
              "EXACT_RUNTIME_V51_CONFIGURATION_REQUIRED")
    for key in ("sourceHash", "runtimeSha256", "pythonSha256", "driverSha256", "admissionSha256",
                "armingVerifierSha256"):
        R.require(R.hashed(config[key]), "V51_SHA256_REQUIRED")
    for key in ("runtimePath", "pythonPath", "driverPath", "admissionPath", "registryRoot", "runtimeStateRoot",
                "armingRoot", "armingVerifierPath", "mandateRoot"):
        R.absolute(config[key])
    for key in ("acceptance", "b1b2Anchor", "b1b2AuthorityModule"):
        R.file_binding(config[key])
    R.require(R.identity(config["armingIssuerRef"]), "V51_ISSUER_REQUIRED")
    candidates = config["candidates"]
    R.require(type(candidates) is dict and len(candidates) == 2
              and all(entry.get("phase") == "INACTIVE" for entry in candidates.values()),
              "EXACT_INACTIVE_CANDIDATE_REQUIRED")


def directories(root, C):
    return [root, root / "source", root / "source/tools", root / "source" / Path(C.RUNTIME).parent,
            root / "source" / Path(C.MANDATES).parent, root / "arming", root / "switch"]


def observe(args, d, *, proposal=None, phase=None):
    """Fresh full observation. No lock acquisition, publication or signer."""
    C = d.C
    root = output_root(args, d, existing=proposal is not None)
    b1 = C.b1_state(d.S, args.b1_root, args.b1_plan_sha256)
    old = b1["config"]
    evidence = b1["evidence"]
    raw, identity = d.S.custody(args.wrapper, 0o755)
    after = phase in ("AFTER_RENAME", "FINAL")
    if after:
        C.require(raw == proposal["wrapperProposed"]["text"].encode("ascii"), "V51_WRAPPER_READBACK_DRIFT")
    else:
        C.require(C.sha(raw) == args.wrapper_sha256 == evidence["installedWrapperSha256"], "B1_WRAPPER_DRIFT")
        python, source, config_path = C.wrapper_targets(raw)
        C.require(source == evidence["source"]["path"] and config_path == evidence["configuration"]["path"]
                  and python == old["pythonPath"], "B1_WRAPPER_TARGET_DRIFT")
    anchor, openssl = old["b1b2TrustPolicy"], old["opensslBinding"]
    gen2 = b1["v5"].read(Path(old["acceptance"]["path"]))
    C.require(C.sha(gen2) == old["acceptance"]["sha256"], "B1_ACCEPTANCE_DRIFT")
    acceptance = C.acceptance_v51(d.S, d.B, d.M, args.acceptance_root, gen2, anchor, args.mandate_root,
                                  openssl, old["armingIssuerRef"])
    C.require(acceptance["containerIds"] == evidence["containerIds"], "ACCEPTANCE_V51_CANDIDATES_MISMATCH")
    frames = C.successor_frames(args.docker, args.docker_sha256, args.docker_socket, evidence["containerIds"])
    lock = C.guard_lock(d.S, args.lock)
    config = configuration(old, acceptance, args, root, d)
    state = {"b1": evidence, "acceptance": acceptance, "successorFrames": frames, "lock": lock,
             "mandateRoot": args.mandate_root, "configuration": config, "root": str(root),
             "wrapperBefore": {"path": args.wrapper, "sha256": args.wrapper_sha256,
                               **({} if after else {"identity": list(identity)})}}
    if proposal is not None:
        verify_publication(root, config, d)
        C.require(stable(state) == stable(proposal), "V51_OBSERVATION_DRIFT")
        if not after:
            C.require(state["wrapperBefore"] == proposal["wrapperBefore"], "B1_WRAPPER_DRIFT")
    return state


def stable(state):
    keys = ("b1", "acceptance", "successorFrames", "lock", "mandateRoot", "configuration", "root")
    return {key: state[key] for key in keys}


def plan(args, d):
    C = d.C
    state = observe(args, d)
    root = Path(state["root"])
    config = state["configuration"]
    raw = C.encoded(config) + b"\n"
    wrapper = C.wrapper_bytes(config["pythonPath"], root)
    state.update(schema=SCHEMA, configurationSha256=C.sha(raw), softwareClosureCommit=C.CLOSURE_COMMIT,
                 wrapperProposed={"text": wrapper.decode("ascii"), "sha256": C.sha(wrapper),
                                  "byteLength": len(wrapper)},
                 writes={"directories": [str(path) for path in directories(root, C)], "directoryMode": "0700",
                         "fileMode": "0600", "owner": "root:root",
                         "files": {**{str(root / "source" / name): pin for name, pin in C.CLOSURE.items()},
                                   str(root / "runtime-configuration.json"): C.sha(raw)},
                         "resultFile": str(root / "result.json"), "switchEvidenceRoot": str(root / "switch"),
                         "wrapper": args.wrapper}, **COUNTERS)
    state["planSha256"] = C.sha(C.encoded(state))
    return state


def verify_publication(root, config, d):
    """The real v5.1 loader, compiled from the INSTALLED bytes, on the published configuration."""
    C = d.C
    for path in directories(root, C):
        C.private_directory(path)
    installed = {}
    for name, pin in C.CLOSURE.items():
        raw, _ = d.S.custody(root / "source" / name, 0o600)
        C.require(C.sha(raw) == pin, "V51_INSTALLED_CLOSURE_DRIFT")
        installed[name] = raw
    runtime = C.compiled(installed[C.RUNTIME], root / "source" / C.RUNTIME, "ouf_installed_runtime_v51",
                         C.CLOSURE[C.RUNTIME], "V51_INSTALLED_CLOSURE_DRIFT")
    path = root / "runtime-configuration.json"
    actual, raw = runtime.load_configuration(path)
    C.require(actual == config and raw == C.encoded(config) + b"\n", "V51_INSTALLED_CONFIG_DRIFT")
    runtime.verify_files(actual)
    C.require(runtime.arming_absence(path) == C.EMPTY_ARMING, "V51_ARMING_PRESENT")


def smoke(argv, C):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=C.ENV, timeout=12)
    C.require(result.returncode == 0, "V51_SMOKE_FAILED")


def apply(args, d, proposal, report):
    C, S = d.C, d.S
    C.require(args.plan_sha256 == proposal["planSha256"], "V51_PLAN_DIGEST_CHANGED")
    root = Path(proposal["root"])
    # mkdir is exclusive: it fails even for an empty pre-existing output root.
    root.mkdir(mode=0o700)
    report.update(root=str(root), outputCreated=True, doNotRerunApply=True, planSha256=proposal["planSha256"])
    S.sync(root.parent)
    for path in proposal["writes"]["directories"][1:]:
        Path(path).mkdir(mode=0o700)
        S.sync(Path(path).parent)
    for name, pin in C.CLOSURE.items():
        raw, _ = S.custody(ROOT / name, 0o600)
        C.require(C.sha(raw) == pin == C.sha(d.sources[name]), "DELIVERED_CLOSURE_DRIFT")
        S.publish_once(root / "source" / name, raw)
    config = proposal["configuration"]
    S.publish_once(root / "runtime-configuration.json", C.encoded(config) + b"\n")
    for path in reversed(proposal["writes"]["directories"]):
        S.sync(path)
    report["phase"] = "VERIFY_PUBLICATION"
    verify_publication(root, config, d)
    report["phase"] = "SMOKE"
    smoke([config["pythonPath"], "-I", "-B", str(root / "source" / C.RUNTIME),
           "--configuration", str(root / "runtime-configuration.json"), "--version"], C)

    def verify_locked(fd, phase):
        current = observe(args, d, proposal=proposal, phase=phase)
        C.require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == tuple(current["lock"]["identity"][:2]),
                  "V51_BORROWED_LOCK_DRIFT")

    report["phase"] = "SWITCH"
    before = proposal["wrapperBefore"]
    proposed = proposal["wrapperProposed"]["text"].encode("ascii")
    outcome = S.switch_existing_wrapper(before["path"], before["sha256"], proposed, root / "switch",
                                        proposal["lock"]["path"], proposal["lock"]["identity"], verify_locked)
    report.update(switchOutcome="REPLACED", wrapperReplaced=True, primitiveResult=outcome, phase="READBACK")
    raw, identity = S.custody(before["path"], 0o755)
    C.require(raw == proposed, "V51_WRAPPER_READBACK_DRIFT")
    smoke([before["path"], "--version"], C)
    observe(args, d, proposal=proposal, phase="FINAL")
    report.update(status="SEMANTIC_RUNTIME_V51_INSTALLED_INACTIVE", phase="COMPLETE",
                  wrapperBefore={k: before[k] for k in ("path", "sha256")},
                  wrapperAfter={"path": before["path"], "sha256": C.sha(raw), "identity": list(identity)},
                  configurationSha256=proposal["configurationSha256"],
                  priorConfigurationSha256=proposal["b1"]["configuration"]["sha256"],
                  acceptancePayloadSha256=proposal["acceptance"]["payloadSha256"],
                  containerIds=sorted(config["candidates"]))
    S.publish_once(root / "result.json", C.encoded(report) + b"\n")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("wrapper", "wrapper-sha256", "b1-root", "b1-plan-sha256", "acceptance-root", "mandate-root",
                 "lock", "docker", "docker-sha256", "docker-socket", "output-root", "output-name"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    for name, value in vars(args).items():
        if name.endswith("sha256") and value is not None and not re.fullmatch("[0-9a-f]{64}", value):
            parser.error("expected exact lowercase SHA-256 bindings")
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
        own = isinstance(error, PermissionError) and str(error) in ("ROOT_CUSTODY_REQUIRED", "ISOLATED_PYTHON_REQUIRED")
        known = known or own
        reason = str(error) if own else (
            d.C.public_reason(error) if d is not None and known else type(error).__name__)
        report.update(status="HELD", reason=reason, **COUNTERS)
        if getattr(error, "details", None):
            report["diagnosis"] = error.details
        primitive = getattr(error, "diagnosis", None)
        if type(primitive) is dict:
            report["primitive"] = {k: primitive[k] for k in ("stage", "switchOutcome", "wrapperReplaced",
                                                             "renameAttempted", "errorType") if k in primitive}
            report["switchOutcome"] = primitive.get("switchOutcome", report["switchOutcome"])
        if isinstance(error, OSError) and not own:
            report["errno"] = error.errno
        if not known:
            import traceback
            # Function names and line numbers only: no paths, values or exception text.
            report["callChain"] = [{"function": f.name, "line": f.lineno}
                                   for f in traceback.extract_tb(error.__traceback__)[-6:]]
        if reason == "V51_OUTPUT_ALREADY_EXISTS":
            report["doNotRerunApply"] = True
        if report.get("outputCreated") and d is not None:
            report["doNotRerunApply"] = True
            try:
                d.S.publish_once(Path(report["root"]) / "result.json", encoded(report) + b"\n")
            except Exception:
                report["diagnosisSaved"] = False
    print(encoded(report).decode(), flush=True)
    return 1 if report["status"] == "HELD" else 0


if __name__ == "__main__":
    raise SystemExit(main())
