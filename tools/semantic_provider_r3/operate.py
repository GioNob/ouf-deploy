"""Human-invoked R3 lifecycle; installed runtime remains the sole epoch writer."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

from tools.semantic_provider_r3 import install_common as I
from tools.semantic_provider_r3 import volatile_restore as VR

A, C, V = I.A, I.C, I.V
require, canonical, sha = I.require, I.canonical, I.sha
SCHEMA = "ouf.semantic-provider-r3-operate.v1"
ROLES = ("adapter", "southbound")
TERMINAL = {"DELETED", "FAILED", "ABANDONED"}
COUNTERS = dict(dockerStartRequests=0, dockerStopRequests=0, dockerUpdateRequests=0,
                dockerRestartRequests=0, signaturesIssued=0, privateKeysRead=0, volatileEntriesRemoved=0)
SUCCESS = {"start": "SEMANTIC_PROVIDER_R3_STARTED",
           # Retained CLI choice; preconditions always deny it under D-045.
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


def observe(args, *, output_exists=False, deadline=None, locked_cids=()):
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
    runtime_raw = S.custody(runtime_path, 0o600)[0]
    runtime_hash = sha(runtime_raw)
    require(runtime_hash in I.installed_runtime_hashes(), "R3_SOURCE_HASH_DRIFT")
    runtime = I.compiled(runtime_raw, runtime_path, "r3_operate_installed_runtime", runtime_hash)
    cfg, raw = runtime.load_configuration(code_root / "runtime-configuration.json")
    runtime.verify_files(cfg)
    require(cfg["registryRoot"] == str(root / "registry")
            and cfg["operation"]["authorizationRoot"] == str(root / "authorization"),
            "R3_INSTALLED_ROOT_DRIFT")
    require(sha(wrapper) == args.wrapper_sha256
            and wrapper == I.wrapper_bytes(cfg["pythonPath"], code_root), "R3_WRAPPER_DRIFT")
    auth, epochs = runtime.operation_modules(cfg)
    cids = sorted(cfg["candidates"])
    sup = C.document(runtime.bound_bytes(cfg["leaseQuiesce"]["configuration"]))
    boot = epochs.boot_id()
    with ExitStack() as locks:
        recovery = False
        if getattr(args, "action", None) == "start":
            for cid in cids:
                row = epochs.current(cfg["registryRoot"], cid)
                if row and row["state"] not in TERMINAL and row["bootId"] != boot:
                    if locked_cids:
                        require(sorted(locked_cids) == cids, "R3_OPERATION_LOCK_DRIFT")
                    else:
                        locks.enter_context(I.operation_locks(root, cids))
                    lock = sup["coordinator"]["commonLockPath"]
                    locks.enter_context(I.guard(SimpleNamespace(lock=lock), V.guard_lock(S, lock)))
                    recovery = True
                    break
        return observe_cohort(args, deadline, runtime, cfg, raw, wrapper, auth, epochs, sup, boot, recovery)


def prove_previous_epoch(runtime, cfg, raw, head, cid, role, row, frame):
    require(head["decision"] == "OPERATE" and row["authorizationSha256"] == head["sha256"],
            "R3_PREVIOUS_BOOT_EPOCH_AUTHORIZATION")
    require(row["configurationHash"] == sha(raw), "R3_PREVIOUS_BOOT_EPOCH_CONFIGURATION")
    require(row["containerId"] == cid == head["authorization"]["roles"][role]["containerId"],
            "R3_PREVIOUS_BOOT_EPOCH_COHORT")
    require(frame["Status"] in {"exited", "created"} and frame["Running"] is False and frame["Pid"] == 0,
            "R3_PREVIOUS_BOOT_EPOCH_DOCKER")
    root = Path(row["runtimeRoot"] or "")
    parent = Path(cfg["runtimeStateRoot"])
    require(root.is_absolute() and root.resolve() == root and root.is_relative_to(parent) and root != parent,
            "R3_PREVIOUS_BOOT_EPOCH_RUNTIME_ROOT")
    try:
        status = runtime.inactive(cfg, cid, "state", root, ["--root", str(root), "state", cid])
    except Exception:
        require(False, "R3_PREVIOUS_BOOT_EPOCH_RUNC")
    require(status == 1, "R3_PREVIOUS_BOOT_EPOCH_RUNC")
    return {"epoch": row["epoch"], "abandonedJournalSha256": sha(canonical({**row, "state": "ABANDONED"}))}


def observe_cohort(args, deadline, runtime, cfg, raw, wrapper, auth, epochs, sup, boot, recovery):
    S = I.native_switch()
    heads = [runtime.authorization_head(cfg, raw, cid, auth) for cid in sorted(cfg["candidates"])]
    require(heads[0] == heads[1], "R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION")
    head = heads[0]
    version = C.composition_version(head['sequence'], head['authorization'])
    starting = getattr(args, 'action', None) in {'start', 'restart-one'}
    if starting and version >= 25:
        from .semantic_identity_v25 import semantic_kernel
        semantic_kernel()
    authorization = {k: head[k] for k in ("sha256", "sequence", "decision")}
    if 'compositionCeiling' in head['authorization']:
        authorization['compositionCeiling'] = head['authorization']['compositionCeiling']

    def remaining():
        if deadline is None:
            return min(30, args.timeout_seconds)
        seconds = deadline - time.monotonic()
        require(seconds > 0, "R3_READBACK_TIMEOUT")
        return min(30, seconds)

    candidates = {}
    abandon = {}
    for cid, item in sorted(cfg["candidates"].items()):
        row = epochs.current(cfg["registryRoot"], cid)
        epoch = None
        previous_boot = recovery and row is not None and row["state"] not in TERMINAL and row["bootId"] != boot
        if row is not None:
            if row["state"] in TERMINAL:
                terminal_binding(runtime, cfg, head, row)
            elif not previous_boot:
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
            if old["state"] == "ABANDONED":
                previous["abandonedJournalSha256"] = sha(canonical(old))
        frame = docker_fields(docker(args, "inspect", cid, timeout=remaining()), cid)
        if previous_boot:
            abandon[item["role"]] = prove_previous_epoch(runtime, cfg, raw, head, cid, item["role"], row, frame)
        elif row is not None and row["state"] == "STARTED" and frame["Running"]:
            require(frame["Pid"] == row["generation"]["pid"], "R3_EPOCH_DOCKER_PID_DRIFT")
        candidates[item["role"]] = {"cid": cid, "epoch": epoch, "previousEpoch": previous, "docker": frame,
            "denials": broker_denials(runtime, cfg["registryRoot"], cid, row["epoch"] if row else None)}

    if starting and version >= 25:
        from .semantic_identity_v25 import semantic_observe
        spec = sup['semanticIngress']
        first, _ = semantic_observe(spec['profile'], spec['commands'])
        second, _ = semantic_observe(spec['profile'], spec['commands'])
        require(first == second, 'R3_SEMANTIC_EPOCH_CHANGED')
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
    if version >= 25:
        epoch = status.get('semanticEpoch')
        require(epoch is None or type(epoch) is str and re.fullmatch('[0-9a-f]{64}', epoch),
                'R3_SUPERVISOR_STATUS_INVALID')
        supervisor['semanticEpoch'] = epoch
    journal = C.document(S.custody(sup["coordinator"]["journalPath"], 0o600)[0])
    public_code(journal["state"], "R3_LEASE_STATE_INVALID")
    require(type(journal["leaseAuthorized"]) is bool, "R3_LEASE_STATE_INVALID")
    lease = {k: journal[k] for k in ("state", "leaseAuthorized")}
    nft = decode(command(args.nft, args.nft_sha256, ["-j", "list", "tables"], remaining()))
    tables = {(r["table"]["family"], r["table"]["name"]) for r in nft["nftables"] if "table" in r}
    kernel_state = {}
    if starting and version >= 12:
        owner = C.document(runtime.bound_bytes(sup['coordinator']['ownerConfiguration']))
        require(owner['nftPath'] == args.nft and owner['nftSha256'] == args.nft_sha256
                and all(journal.get(k) == v for k, v in owner['binding'].items()),
                'R3_COORDINATOR_BINDING_DRIFT')
        kernel_state['leaseKernel'] = lease_kernel_state(owner, journal, tables,
            lambda family, name: decode(command(args.nft, args.nft_sha256,
                ['-j', 'list', 'table', family, name], remaining())), closed_required=bool(abandon))
    present = {}
    for role in ROLES:
        name = head["authorization"]["roles"][role]["tableName"]
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name), "R3_TABLE_NAME_INVALID")
        present[role] = {"tableName": name, **{family: (family, name) in tables for family in ("inet", "bridge")}}
    if abandon:
        require(lease == {"state": "QUIESCED", "leaseAuthorized": False}, "R3_PREVIOUS_BOOT_EPOCH_LEASE")
        require("leaseKernel" in kernel_state, "R3_PREVIOUS_BOOT_EPOCH_INGRESS")
        kernel_state.update(epochsToAbandon=abandon, recoveryBootId=boot)
        require(not any(t[f] for t in present.values() for f in ("inet", "bridge")),
                "R3_PREVIOUS_BOOT_EPOCH_INGRESS")
    runtime.verify_files(cfg)
    require(S.custody(args.wrapper, 0o755)[0] == wrapper, "R3_WRAPPER_DRIFT")
    for cid in sorted(cfg["candidates"]):
        require(runtime.authorization_head(cfg, raw, cid, auth) == head,
                "R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION")
    return {"configurationSha256": sha(raw), "authorization": authorization,
            "candidates": candidates, "supervisor": supervisor, "lease": lease, "tables": present, **kernel_state}


def lease_kernel_state(owner, journal, tables, read, *, closed_required=False):
    """Start gate only: no nft writes, seal adoption or migration effects."""
    kernel = owner['kernel']
    name = kernel['tableName']
    require(type(kernel.get('generation')) is int and kernel['generation'] == 2
            and kernel.get('providerFlowMatch') == 'ORIGINAL_TUPLE' and name.endswith('_g2'),
            'R3_LEASE_KERNEL_GENERATION_DRIFT')
    require(journal.get('state') != 'BLOCKED', 'R3_LEASE_KERNEL_JOURNAL_BLOCKED')
    require(not any((f, name[:-3]) in tables for f in ('inet', 'bridge')),
            'R3_LEASE_KERNEL_NOT_FINALIZED')
    require(all((f, name) in tables for f in ('inet', 'bridge')), 'R3_LEASE_KERNEL_STRUCTURE_DRIFT')
    actual = {f: read(f, name) for f in ('inet', 'bridge')}
    require(I.lease_structure_hash(actual) == owner['expectedStructureHash']
            == owner['binding']['leaseStructureHash'], 'R3_LEASE_KERNEL_STRUCTURE_DRIFT')
    if closed_required:
        # nft reports remaining time in whole seconds. A listed zero can
        # represent a final fraction of a second. Absence proves expiration.
        for table in actual.values():
            for item in table["nftables"]:
                if "set" in item:
                    require(item["set"].get("elem", []) == [], "R3_PREVIOUS_BOOT_EPOCH_INGRESS")
    return {'generation': 2, 'predecessorAbsent': True, 'structureHash': owner['expectedStructureHash']}


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
            and ('semanticEpoch' not in sup or sup['semanticEpoch'] is not None)
            and sup["authorizationSequence"] == observation["authorization"]["sequence"]
            and sup["epochs"] == {r: observation["candidates"][r]["epoch"]["epoch"] for r in ROLES})


def quiesced(observation):
    return observation["lease"] == {"state": "QUIESCED", "leaseAuthorized": False}


def preconditions(args, observation):
    require(args.action != "restart-policy", "R3_RESTART_POLICY_DISABLED_D045")
    rows, sup = observation["candidates"], observation["supervisor"]
    if args.action == "start":
        require(all(rows[r]["docker"]["RestartPolicy"] == "no" for r in ROLES),
                "R3_RESTART_POLICY_MUST_BE_NO")
        require(VR.cohort_idle(observation), "R3_START_CANDIDATES_NOT_IDLE")
        require(service_active(observation) and sup["state"] == "WAITING"
                and sup["authorizationSequence"] == observation["authorization"]["sequence"],
                "R3_START_SUPERVISOR_NOT_WAITING")
        require(quiesced(observation), "R3_START_LEASE_NOT_QUIESCED")
    elif args.action == "restart-one":
        require(all(running(v) for v in rows.values()), "R3_RUNNING_EPOCHS_REQUIRED")
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
    if args.action == "start":
        state["volatileRestore"] = VR.plan(args, observation)
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
    if args.action == "restart-policy":
        return False
    if not all(running(v) for v in rows.values()):
        return False
    if args.action == "start" and not all(v["docker"]["RestartPolicy"] == "no"
                                          for v in rows.values()):
        return False
    if not active(after):
        return False
    for role in ROLES:
        old, new = before["candidates"][role], rows[role]
        if args.action == "start" or role == args.role:
            number = (old["epoch"]["epoch"] if old["epoch"] else 0) + 1
            if new["epoch"]["epoch"] != number:
                return False
            if role in before.get("epochsToAbandon", {}):
                expected = {**before["epochsToAbandon"][role], "state": "ABANDONED"}
                if new["previousEpoch"] != expected or new["epoch"]["bootId"] != before["recoveryBootId"]:
                    return False
            if args.action == "restart-one" and new["previousEpoch"] != {
                    "epoch": number - 1, "state": "DELETED"}:
                return False
        elif new["epoch"] != old["epoch"] or new["docker"]["Pid"] != old["docker"]["Pid"]:
            return False
    return (after["lease"] == {"state": "LEASE_READY", "leaseAuthorized": True}
            and all(t[f] for t in after["tables"].values() for f in ("inet", "bridge")))


def requests(args, before):
    require(args.action != "restart-policy", "R3_RESTART_POLICY_DISABLED_D045")
    rows = before["candidates"]
    if args.action == "restart-one":
        return [(args.role, ["restart", "--time", "30", rows[args.role]["cid"]])]
    verb = {"start": ["start"], "stop": ["stop", "--time", "30"]}[args.action]
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
    if args.action == "start":
        VR.apply(args, before, plan["volatileRestore"], report,
                 lambda: observe(args, output_exists=True,
                                 locked_cids=[v["cid"] for v in before["candidates"].values()]))
    authorization = before['authorization']
    if args.action in {'start', 'restart-one'} and C.composition_version(authorization['sequence'], authorization) >= 12:
        # Volatile restore can take time: recheck the v12 gate immediately
        # before submitting any request that starts a container.
        current = observe(args, output_exists=True)
        preconditions(args, current)
        if "epochsToAbandon" in before or "epochsToAbandon" in current:
            require(current == before, "R3_PLAN_DIGEST_CHANGED")
    calls = requests(args, before)
    counter = {"start": "dockerStartRequests", "stop": "dockerStopRequests",
               "restart-one": "dockerRestartRequests"}[args.action]

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
    for name in ("volatile-rootfs-result", "volatile-rootfs-result-sha256", "volatile-source"):
        parser.add_argument("--" + name)
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
