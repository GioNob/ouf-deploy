"""Human-invoked R3 lifecycle; installed runtime remains the sole epoch writer."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import traceback

from tools.semantic_provider_r3 import install_common as I

A, C, V = I.A, I.C, I.V
require, canonical, sha = I.require, I.canonical, I.sha
SCHEMA = "ouf.semantic-provider-r3-operate.v1"
ROLES = ("adapter", "southbound")
TERMINAL = {"DELETED", "FAILED", "ABANDONED"}
COUNTERS = dict(dockerStartRequests=0, dockerStopRequests=0, dockerUpdateRequests=0,
                dockerRestartRequests=0, signaturesIssued=0, privateKeysRead=0)
SUCCESS = {"start": "SEMANTIC_PROVIDER_R3_STARTED",
           "restart-policy": "SEMANTIC_PROVIDER_R3_RESTART_POLICY_SET",
           "restart-one": "SEMANTIC_PROVIDER_R3_RESTARTED_WITHOUT_SIGNATURE",
           "stop": "SEMANTIC_PROVIDER_R3_STOPPED"}
CODE = re.compile(r"[A-Z][A-Z0-9_]{0,95}")


def decode(raw):
    """Docker/nft JSON is not canonical; still reject duplicate/nonfinite fields."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "R3_DUPLICATE_OBSERVATION_FIELD")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def command(path, digest, argv, timeout):
    """Never inherit stdin/environment or expose command output in an error."""
    binary = V.executable_hash(path, digest)
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([binary, *argv], stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=subprocess.DEVNULL,
                                    env=I.ENV, timeout=timeout)
            output.seek(0)
            raw = output.read(131073)
        require(len(raw) <= 131072, "R3_COMMAND_OUTPUT_UNBOUNDED")
        require(result.returncode == 0, "R3_COMMAND_FAILED")
        return raw
    finally:
        V.executable_hash(path, digest)


def docker(args, *argv, timeout=None):
    return command(args.docker, args.docker_sha256, ["--host", args.docker_socket, *argv],
                   args.timeout_seconds if timeout is None else timeout)


def error_fields(error):
    value = {"reason": I.public(error)}
    if isinstance(error, OSError):
        value["errno"] = error.errno
    if type(error).__name__ not in I.PUBLIC:
        value["callChain"] = [{"function": f.name, "line": f.lineno}
                              for f in traceback.extract_tb(error.__traceback__)[-6:]]
    return value


def public_code(value, code):
    require(value is None or type(value) is str and CODE.fullmatch(value), code)
    return value


def docker_fields(raw, cid):
    rows = decode(raw)
    require(type(rows) is list and len(rows) == 1 and rows[0].get("Id") == cid,
            "R3_EXACT_DOCKER_INSPECT_REQUIRED")
    row = rows[0]
    state, host = row["State"], row["HostConfig"]
    require(type(state["Status"]) is str and state["Status"] in
            {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
            and type(state["Running"]) is bool and type(state["Pid"]) is int
            and state["Pid"] >= 0 and type(state["StartedAt"]) is str
            and re.fullmatch(r"[0-9TZ:.+-]{1,64}", state["StartedAt"])
            and type(row["RestartCount"]) is int and row["RestartCount"] >= 0,
            "R3_DOCKER_STATE_INVALID")
    require(host["Runtime"] == "ouf-semantic-admitted-v2", "R3_DOCKER_RUNTIME_DRIFT")
    policy = host["RestartPolicy"]["Name"]
    require(policy in {"no", "always", "on-failure", "unless-stopped"}, "R3_DOCKER_RESTART_POLICY_INVALID")
    return {**{k: state[k] for k in ("Status", "Running", "Pid", "StartedAt")},
            "RestartCount": row["RestartCount"], "Runtime": host["Runtime"], "RestartPolicy": policy}


def terminal_binding(runtime, cfg, head, row):
    """Terminal history keeps its original configuration and authenticated entry."""
    require(row["state"] in TERMINAL, "R3_EPOCH_AUTHORIZATION_DRIFT")
    for sequence in range(1, head["sequence"] + 1):
        raw = runtime.read(Path(cfg["operation"]["authorizationRoot"]) / f"{sequence}.json")
        if sha(raw) == row["authorizationSha256"]:
            payload = A.validate(raw)
            require(payload["decision"] == "OPERATE" and payload["runtimeConfigurationSha256"] == row["configurationHash"],
                    "R3_EPOCH_AUTHORIZATION_DRIFT")
            return
    require(False, "R3_EPOCH_AUTHORIZATION_DRIFT")


def broker_denials(runtime, registry, cid, current):
    """Untrusted diagnostic files never alter the lifecycle outcome."""
    found = []
    if current is None:
        return found
    for number in (current, current - 1) if current > 1 else (current,):
        root = Path(registry) / cid / "epochs" / str(number)
        try:
            paths = sorted(root.glob("broker-denial-*.json"))
        except Exception:
            found.append({"invalid": "BROKER_DENIAL_LIST_FAILED"})
            continue
        for path in paths:
            try:
                raw = runtime.read(path)
                mode = path.name[len("broker-denial-"):-len(".json")]
                found.append(C.B.validate_denial(raw, cid, number, mode))
            except Exception:
                found.append({"invalid": "BROKER_DENIAL_INVALID"})
    return found


def observe(args, *, output_exists=False, deadline=None):
    """Read only. Compile the installed, hash-verified v5.2 and use its loaders."""
    S = I.native_switch()
    root = V.absolute(args.install_root)
    V.private_directory(root)
    I.output_directory(args.output_directory, root, S, absent=not output_exists)
    wrapper = S.custody(args.wrapper, 0o755)[0]
    require(sha(wrapper) == args.wrapper_sha256, "R3_WRAPPER_DRIFT")
    code_root = I.wrapper_code_root(root, wrapper)
    if code_root != root:
        V.private_directory(root / "versions")
        V.private_directory(code_root)
    runtime_path = code_root / "source" / C.RUNTIME
    runtime = I.compiled(S.custody(runtime_path, 0o600)[0], runtime_path,
                         "r3_operate_installed_runtime", sha((I.ROOT / C.RUNTIME).read_bytes()))
    cfg, raw = runtime.load_configuration(code_root / "runtime-configuration.json")
    runtime.verify_files(cfg)
    require(cfg["registryRoot"] == str(root / "registry")
            and cfg["operation"]["authorizationRoot"] == str(root / "authorization"),
            "R3_INSTALLED_ROOT_DRIFT")
    require(sha(wrapper) == args.wrapper_sha256
            and wrapper == I.wrapper_bytes(cfg["pythonPath"], code_root), "R3_WRAPPER_DRIFT")
    auth, epochs = runtime.operation_modules(cfg)
    heads = [runtime.authorization_head(cfg, raw, cid, auth) for cid in sorted(cfg["candidates"])]
    require(heads[0] == heads[1], "R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION")
    head = heads[0]
    authorization = {k: head[k] for k in ("sha256", "sequence", "decision")}
    boot = epochs.boot_id()

    def remaining():
        if deadline is None:
            return min(30, args.timeout_seconds)
        seconds = deadline - time.monotonic()
        require(seconds > 0, "R3_READBACK_TIMEOUT")
        return min(30, seconds)

    candidates = {}
    for cid, item in sorted(cfg["candidates"].items()):
        row = epochs.current(cfg["registryRoot"], cid)
        epoch = None
        if row is not None:
            if row["state"] in TERMINAL:
                terminal_binding(runtime, cfg, head, row)
            else:
                require(row["bootId"] == boot, "R3_EPOCH_BOOT_DRIFT")
                require(row["authorizationSha256"] == head["sha256"]
                        and row["configurationHash"] == sha(raw), "R3_EPOCH_AUTHORIZATION_DRIFT")
            epoch = {k: row[k] for k in ("epoch", "state", "bootId", "failure")}
            epoch["live"] = epochs.live(row, boot)
        # Historical journal is read with the installed validator, never rewritten.
        previous = None
        if row is not None and row["epoch"] > 1:
            number = row["epoch"] - 1
            old = epochs.validate_journal(runtime.read(Path(cfg["registryRoot"]) / cid /
                        "epochs" / str(number) / "adapter.json"), cid, number)
            terminal_binding(runtime, cfg, head, old)
            previous = {k: old[k] for k in ("epoch", "state")}
        frame = docker_fields(docker(args, "inspect", cid, timeout=remaining()), cid)
        if row is not None and row["state"] == "STARTED" and frame["Running"]:
            require(frame["Pid"] == row["generation"]["pid"], "R3_EPOCH_DOCKER_PID_DRIFT")
        candidates[item["role"]] = {"cid": cid, "epoch": epoch, "previousEpoch": previous, "docker": frame,
            "denials": broker_denials(runtime, cfg["registryRoot"], cid, row["epoch"] if row else None)}

    sup = C.document(runtime.bound_bytes(cfg["leaseQuiesce"]["configuration"]))
    require(sup["registryRoot"] == cfg["registryRoot"]
            and sup["authorizationRoot"] == cfg["operation"]["authorizationRoot"], "R3_SUPERVISOR_ROOT_DRIFT")
    properties = command(args.systemctl, args.systemctl_sha256,
        ["show", I.UNIT, "--property=ActiveState", "--property=SubState", "--property=NRestarts"], remaining())
    fields = dict(line.split("=", 1) for line in properties.decode("ascii").splitlines())
    require(set(fields) == {"ActiveState", "SubState", "NRestarts"}
            and fields["NRestarts"].isdigit(), "R3_SUPERVISOR_UNIT_INVALID")
    for name in ("ActiveState", "SubState"):
        require(re.fullmatch(r"[a-z-]{1,40}", fields[name]), "R3_SUPERVISOR_UNIT_INVALID")
    fields["NRestarts"] = int(fields["NRestarts"])
    status = C.document(S.custody(sup["statusPath"], 0o600)[0])
    require(status.get("schema") == "ouf.semantic-provider-lease-supervisor-status.v1"
            and status["state"] in {"WAITING", "ACTIVE", "PARKED_RATE_LIMITED", "STOPPED", "FAILED"}
            and type(status["epochs"]) is dict and set(status["epochs"]) == set(ROLES)
            and all(v is None or type(v) is int and v >= 1 for v in status["epochs"].values())
            and type(status["activationsLastHour"]) is int and status["activationsLastHour"] >= 0
            and (status["authorizationSequence"] is None or type(status["authorizationSequence"]) is int),
            "R3_SUPERVISOR_STATUS_INVALID")
    public_code(status["reason"], "R3_SUPERVISOR_REASON_INVALID")
    supervisor = {"unit": fields, **{k: status[k] for k in
                  ("state", "reason", "epochs", "activationsLastHour", "authorizationSequence")}}
    journal = C.document(S.custody(sup["coordinator"]["journalPath"], 0o600)[0])
    public_code(journal["state"], "R3_LEASE_STATE_INVALID")
    require(type(journal["leaseAuthorized"]) is bool, "R3_LEASE_STATE_INVALID")
    lease = {k: journal[k] for k in ("state", "leaseAuthorized")}
    nft = decode(command(args.nft, args.nft_sha256, ["-j", "list", "tables"], remaining()))
    tables = {(r["table"]["family"], r["table"]["name"]) for r in nft["nftables"] if "table" in r}
    present = {}
    for role in ROLES:
        name = head["authorization"]["roles"][role]["tableName"]
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name), "R3_TABLE_NAME_INVALID")
        present[role] = {"tableName": name, **{family: (family, name) in tables for family in ("inet", "bridge")}}
    runtime.verify_files(cfg)
    require(S.custody(args.wrapper, 0o755)[0] == wrapper, "R3_WRAPPER_DRIFT")
    for cid in sorted(cfg["candidates"]):
        require(runtime.authorization_head(cfg, raw, cid, auth) == head,
                "R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION")
    return {"configurationSha256": sha(raw), "authorization": authorization,
            "candidates": candidates, "supervisor": supervisor, "lease": lease, "tables": present}


def running(row):
    d, e = row["docker"], row["epoch"]
    return (d["Status"] == "running" and d["Running"] and d["Pid"] > 1
            and e is not None and e["state"] == "STARTED" and e["live"])


def service_active(observation):
    unit = observation["supervisor"]["unit"]
    return unit["ActiveState"] == "active" and unit["SubState"] == "running"


def active(observation):
    sup = observation["supervisor"]
    return (service_active(observation) and sup["state"] == "ACTIVE"
            and sup["authorizationSequence"] == observation["authorization"]["sequence"]
            and sup["epochs"] == {r: observation["candidates"][r]["epoch"]["epoch"] for r in ROLES})


def quiesced(observation):
    return observation["lease"] == {"state": "QUIESCED", "leaseAuthorized": False}


def preconditions(args, observation):
    rows, sup = observation["candidates"], observation["supervisor"]
    if args.action == "start":
        require(all((v["epoch"] is None or v["epoch"]["state"] in TERMINAL)
                    and v["docker"]["Status"] in {"created", "exited"}
                    and v["docker"]["Running"] is False and v["docker"]["Pid"] == 0
                    for v in rows.values()), "R3_START_CANDIDATES_NOT_IDLE")
        require(service_active(observation) and sup["state"] == "WAITING"
                and sup["authorizationSequence"] == observation["authorization"]["sequence"],
                "R3_START_SUPERVISOR_NOT_WAITING")
        require(quiesced(observation), "R3_START_LEASE_NOT_QUIESCED")
    elif args.action in {"restart-policy", "restart-one"}:
        require(all(running(v) for v in rows.values()), "R3_RUNNING_EPOCHS_REQUIRED")
        if args.action == "restart-one":
            require(active(observation), "R3_RESTART_SUPERVISOR_NOT_ACTIVE")
    else:
        require(any(v["docker"]["Running"] and v["docker"]["Status"] == "running"
                    for v in rows.values()), "R3_STOP_NO_RUNNING_CANDIDATE")


def proposal(args, observation):
    preconditions(args, observation)
    state = {"schema": SCHEMA, "action": args.action, "role": args.role,
             "installRoot": args.install_root, "outputDirectory": args.output_directory,
             "timeoutSeconds": args.timeout_seconds, "observation": observation,
             "bindings": {k: getattr(args, k) for k in ("wrapper", "wrapper_sha256", "docker",
                 "docker_sha256", "docker_socket", "systemctl", "systemctl_sha256", "nft", "nft_sha256")},
             **COUNTERS}
    return I.digest_plan(state)


def reached(args, before, after):
    if any(before[k] != after[k] for k in ("configurationSha256", "authorization")):
        return False
    if any(before["candidates"][r]["cid"] != after["candidates"][r]["cid"] for r in ROLES):
        return False
    rows = after["candidates"]
    if args.action == "stop":
        return (all(v["docker"]["Status"] == "exited" and not v["docker"]["Running"]
                    and v["docker"]["Pid"] == 0 and v["epoch"] is not None
                    and v["epoch"]["state"] in TERMINAL for v in rows.values())
                and service_active(after) and after["supervisor"]["state"] == "WAITING" and quiesced(after)
                and all(not t[f] for t in after["tables"].values() for f in ("inet", "bridge")))
    if not all(running(v) for v in rows.values()):
        return False
    if args.action == "restart-policy":
        return all(v["docker"]["RestartPolicy"] == "unless-stopped"
                   and v["epoch"] == before["candidates"][r]["epoch"]
                   and all(v["docker"][k] == before["candidates"][r]["docker"][k]
                           for k in ("Pid", "StartedAt", "RestartCount")) for r, v in rows.items())
    if not active(after):
        return False
    for role in ROLES:
        old, new = before["candidates"][role], rows[role]
        if args.action == "start" or role == args.role:
            number = (old["epoch"]["epoch"] if old["epoch"] else 0) + 1
            if new["epoch"]["epoch"] != number:
                return False
            if args.action == "restart-one" and new["previousEpoch"] != {
                    "epoch": number - 1, "state": "DELETED"}:
                return False
        elif new["epoch"] != old["epoch"] or new["docker"]["Pid"] != old["docker"]["Pid"]:
            return False
    return (after["lease"] == {"state": "LEASE_READY", "leaseAuthorized": True}
            and all(t[f] for t in after["tables"].values() for f in ("inet", "bridge")))


def requests(args, before):
    rows = before["candidates"]
    if args.action == "restart-one":
        return [(args.role, ["restart", "--time", "30", rows[args.role]["cid"]])]
    verb = {"start": ["start"], "stop": ["stop", "--time", "30"],
            "restart-policy": ["update", "--restart", "unless-stopped"]}[args.action]
    return [(role, [*verb, rows[role]["cid"]]) for role in ROLES
            if args.action != "stop" or rows[role]["docker"]["Running"]]


def poll(args, before, report):
    deadline = time.monotonic() + args.timeout_seconds
    while True:
        try:
            latest = observe(args, output_exists=True, deadline=deadline)
            report["lastObservation"] = latest
            report.pop("observationError", None)
            if reached(args, before, latest):
                return
        except Exception as error:
            report["observationError"] = error_fields(error)
        require(time.monotonic() < deadline, "R3_READBACK_TIMEOUT")
        time.sleep(min(.2, max(0, deadline - time.monotonic())))


def apply(args, plan, report):
    require(args.plan_sha256 == plan["planSha256"], "R3_PLAN_DIGEST_CHANGED")
    before = observe(args)
    report["lastObservation"] = before
    require(proposal(args, before) == plan, "R3_PLAN_DIGEST_CHANGED")
    output = Path(args.output_directory)
    # Do not hold runtime CID/guard locks: docker's children need those locks.
    output.mkdir(mode=0o700)
    report.update(outputCreated=True, doNotRerunApply=True, planSha256=plan["planSha256"])
    I.native_switch().sync(output.parent)
    I.write_once(output / "operate-claim.json", canonical(plan), report)
    calls = requests(args, before)
    counter = {"start": "dockerStartRequests", "stop": "dockerStopRequests",
               "restart-policy": "dockerUpdateRequests", "restart-one": "dockerRestartRequests"}[args.action]

    def invoke(argv):
        try:
            docker(args, *argv)
            return None
        except Exception as error:
            return error_fields(error)

    # Submit BOTH starts before waiting: cohort-ready needs the sibling's runc create.
    errors = []
    if args.action in {"start", "stop"}:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = []
            for role, argv in calls:
                report[counter] += 1  # count attempted requests even if exec/timeout fails
                report["doNotRerunApply"] = True
                futures.append((role, pool.submit(invoke, argv)))
            for role, future in futures:
                error = future.result()
                if error:
                    errors.append({"role": role, **error})
    else:
        for role, argv in calls:
            report[counter] += 1
            report["doNotRerunApply"] = True
            error = invoke(argv)
            if error:
                errors.append({"role": role, **error})
    report["requestErrors"] = errors
    poll(args, before, report)
    require(not errors, "R3_DOCKER_REQUEST_FAILED")
    report.update(status=SUCCESS[args.action])


def arguments(argv=None):
    parser = I.Arguments(description="Governed R3 lifecycle")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--action", required=True, choices=tuple(SUCCESS))
    parser.add_argument("--role", choices=ROLES)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    for name in ("install-root", "wrapper", "wrapper-sha256", "docker", "docker-sha256", "docker-socket",
                 "systemctl", "systemctl-sha256", "nft", "nft-sha256", "output-directory"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    require(1 <= args.timeout_seconds <= 600, "INVALID_ARGUMENTS")
    require((args.action == "restart-one") == (args.role is not None), "INVALID_ARGUMENTS")
    require(args.apply == (args.plan_sha256 is not None), "INVALID_ARGUMENTS")
    require(all(V.hashed(v) for k, v in vars(args).items() if k.endswith("sha256") and v is not None),
            "INVALID_ARGUMENTS")
    require(re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket), "INVALID_ARGUMENTS")
    return args


def main(argv=None):
    report = {"schema": SCHEMA, "status": "HELD", "doNotRerunApply": False, **COUNTERS}
    args = None
    try:
        args = arguments(argv)
        report.update(action=args.action, role=args.role)
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.flags.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        if args.apply and os.path.lexists(args.output_directory):
            report["doNotRerunApply"] = True
        with I.module_scope():
            observation = observe(args)
            report["lastObservation"] = observation
            plan = proposal(args, observation)
            if args.plan:
                report.update(plan, status="PLAN_READY")
            else:
                apply(args, plan, report)
    except Exception as error:
        report.update(status="HELD", **error_fields(error))
    if report.get("outputCreated"):
        try:
            I.write_once(Path(args.output_directory) / "result.json", canonical(report), report)
        except Exception as error:
            report.update(status="HELD", diagnosisSaved=False, **error_fields(error))
    print(canonical(report).decode("ascii"), flush=True)
    return int(report["status"] == "HELD")
