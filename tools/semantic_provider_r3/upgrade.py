"""Governed, stopped-provider R3 upgrade; no signing or container mutations."""
import os
from pathlib import Path
import re
import sys

from tools.semantic_provider_r3 import install_common as I

A, C, V = I.A, I.C, I.V
require, canonical, sha = I.require, I.canonical, I.sha
SCHEMA = "ouf.semantic-provider-r3-upgrade.v1"
STOPPED = "R3_UPGRADE_REQUIRES_STOPPED_PROVIDER"


def version_root(root, version):
    require(type(version) is int and version >= 1, "R3_VERSION_REQUIRED")
    return root if version == 1 else root / "versions" / str(version)


def stopped_provider(runtime, cfg, args):
    """Use the installed epoch reader, including all retained historical journals."""
    S = I.native_switch()
    _, epochs = runtime.operation_modules(cfg)
    observations = {}
    for cid in sorted(cfg["candidates"]):
        base = Path(cfg["registryRoot"]) / cid
        V.private_directory(base)
        V.private_directory(base / "epochs")
        current = epochs.current(cfg["registryRoot"], cid)
        require(current is None or current["state"] in epochs.TERMINAL, STOPPED)
        history = {}
        for folder in sorted((base / "epochs").iterdir()):
            require(re.fullmatch(r"[1-9][0-9]{0,9}", folder.name) is not None, STOPPED)
            V.private_directory(folder)
            raw = S.custody(folder / "adapter.json", 0o600)[0]
            row = epochs.validate_journal(raw, cid, int(folder.name))
            require(row["state"] in epochs.TERMINAL, STOPPED)
            history[folder.name] = sha(raw)
        require(current is not None or not history, STOPPED)
        # Only Docker State is read; no Config/NetworkSettings comparison and no
        # lifecycle request. Previously started, now exited CIDs are admissible.
        frame = V.docker_inspect(args.docker, args.docker_sha256, args.docker_socket, cid)
        state = frame.get("State") or {}
        require(state.get("Status") in {"created", "exited", "dead"}
                and state.get("Running") is False and type(state.get("Pid")) is int
                and state["Pid"] == 0, STOPPED)
        observations[cid] = {"current": current, "journalHashes": history,
                             "dockerState": {k: state[k] for k in ("Status", "Running", "Pid")}}
    return observations


def read_inputs(args):
    reader = I.Reader()
    index = C.document(reader.read(args.inputs, args.inputs_sha256))
    require(set(index) == {"schema", "files", "sources"}
            and index["schema"] == "ouf.semantic-provider-r3-inputs.v1"
            and C.input_set(index["files"], index["sources"]),
            "R3_EXACT_INPUT_MANIFEST_REQUIRED")
    files = {k: reader.bound(v) for k, v in index["files"].items()}
    sources = {k: reader.bound(v) for k, v in index["sources"].items()}
    settings = C.document(files["settings"])
    tables = {}
    for item in args.table_name:
        role, sep, name = item.partition("=")
        require(sep and role in A.ROLES and role not in tables, "R3_EXACT_TABLE_ARGUMENTS_REQUIRED")
        tables[role] = name
    settings.update(installRoot=args.install_root, issuedAt=args.issued_at, tableNames=tables)
    files["settings"] = canonical(settings)
    return reader, files, sources, settings


def installed_runtime(root, code_root, payload):
    """Authenticate configuration BEFORE executing its runtime source bytes."""
    S = I.native_switch()
    V.private_directory(code_root)
    raw = S.custody(code_root / "runtime-configuration.json", 0o600)[0]
    require(sha(raw) == payload["runtimeConfigurationSha256"], "R3_INSTALLED_CONFIGURATION_DRIFT")
    cfg = C.document(raw)
    path = code_root / "source" / C.RUNTIME
    runtime = I.compiled(S.custody(path, 0o600)[0], path, "r3_upgrade_previous_runtime", cfg["sourceHash"])
    loaded, loaded_raw = runtime.load_configuration(code_root / "runtime-configuration.json")
    runtime.verify_files(loaded)
    require(loaded_raw == raw and loaded == cfg and cfg["registryRoot"] == str(root / "registry")
            and cfg["operation"]["authorizationRoot"] == str(root / "authorization"), "R3_INSTALLED_ROOT_DRIFT")
    return runtime, cfg, raw


def observe(args, *, published=False, unit_switched=False, switched=False):
    S = I.native_switch()
    root = V.absolute(args.install_root)
    V.private_directory(root)
    V.private_directory(root / "authorization")
    I.output_directory(args.output_directory, root, S, absent=not published)
    reader, files, sources, settings = read_inputs(args)
    _, head = I.authorization(settings, sources, root)
    require(head["decision"] == "OPERATE" and head["sequence"] >= 2, "R3_UPGRADE_SUCCESSOR_OPERATE_REQUIRED")
    version = head["sequence"]
    if C.composition_version(version, head["authorization"]) >= 25:
        from .semantic_identity_v25 import semantic_kernel
        semantic_kernel()
    old_root, new_root = version_root(root, version - 1), version_root(root, version)
    if os.path.lexists(root / "versions"):
        V.private_directory(root / "versions")
    previous_raw = S.custody(root / "authorization" / f"{version-1}.json", 0o600)[0]
    previous = A.validate(previous_raw)
    require(previous["sequence"] == version - 1 and previous["decision"] == "OPERATE"
            and head["authorization"]["supersedes"] == sha(previous_raw), "R3_UPGRADE_PREVIOUS_AUTHORIZATION_DRIFT")
    composed = C.compose({"files": files, "sources": sources}, version=version,
                         sequence=version, supersedes=sha(previous_raw))
    raw = S.custody(root / "authorization" / f"{version}.json", 0o600)[0]
    auth = I.payload_match(composed, head, raw)
    runtime, old_cfg, _ = installed_runtime(root, old_root, previous)
    cfg = C.document(composed["documents"][f"versions/{version}/runtime-configuration.json"])
    require(cfg["candidates"] == old_cfg["candidates"], "R3_UPGRADE_CANDIDATES_DRIFT")
    stopped = stopped_provider(runtime, old_cfg, args)
    coordinator = I.coordinator_state(settings, files, reader)
    old_sup = C.document(runtime.bound_bytes(old_cfg["leaseQuiesce"]["configuration"]))
    new_sup = C.document(composed["documents"][f"versions/{version}/supervisor/configuration.json"])
    shared_state(version, old_sup, new_sup, files, previous)
    old_wrapper = I.wrapper_bytes(old_cfg["pythonPath"], old_root)
    proposed = I.wrapper_bytes(cfg["pythonPath"], new_root)
    require(sha(old_wrapper) == args.current_wrapper_sha256, "R3_CURRENT_WRAPPER_BINDING_DRIFT")
    wrapper, wrapper_identity = S.custody(args.wrapper, 0o755)
    require(wrapper == (proposed if switched else old_wrapper), "R3_WRAPPER_DRIFT")
    old_unit = I.unit_bytes(root, old_cfg, old_sup, old_root)
    unit = I.unit_bytes(root, cfg, new_sup, new_root)
    unit_raw, unit_identity = S.custody(I.UNIT_PATH, 0o600)
    require(unit_raw == (unit if unit_switched else old_unit), "R3_UNIT_DRIFT")
    properties = I.systemctl(args, "show", I.UNIT, "--property=FragmentPath",
                            "--property=NeedDaemonReload", "--property=DropInPaths", "--property=LoadState")
    rows = dict(line.split("=", 1) for line in properties.decode("ascii").splitlines())
    require(rows.get("FragmentPath") == str(I.UNIT_PATH) and rows.get("NeedDaemonReload") == "no"
            and rows.get("DropInPaths") == "" and rows.get("LoadState") == "loaded", "R3_UNIT_DRIFT")
    if not published:
        require(not os.path.lexists(new_root), "R3_UPGRADE_VERSION_ALREADY_EXISTS")
    else:
        V.private_directory(new_root)
    lock = V.guard_lock(S, args.lock)
    reader.verify()
    dirs = [root / p for p in composed["layout"]["directories0700"]
            if p == "versions" or p.startswith(f"versions/{version}/") or p == f"versions/{version}"]
    state = {"schema": SCHEMA, "installRoot": str(root), "outputDirectory": args.output_directory,
        "versionBefore": version - 1, "versionAfter": version, "authorization": auth,
        "previousAuthorizationSha256": sha(previous_raw), "inputHashes": reader.hashes,
        "compositionInputHashes": composed["inputHashes"], "stoppedProvider": stopped,
        "coordinator": coordinator, "lock": lock,
        "configurationSha256": sha(composed["documents"][f"versions/{version}/runtime-configuration.json"]),
        "wrapperBefore": {"path": args.wrapper, "sha256": sha(old_wrapper)},
        "wrapperProposed": {"text": proposed.decode("ascii"), "sha256": sha(proposed)},
        "unitBefore": {"sha256": sha(old_unit), "text": old_unit.decode("ascii")},
        "unit": {"path": str(I.UNIT_PATH), "mode": "0600", "sha256": sha(unit), "text": unit.decode("ascii")},
        "systemctl": {"path": args.systemctl, "sha256": args.systemctl_sha256},
        "docker": {"path": args.docker, "sha256": args.docker_sha256, "socket": args.docker_socket},
        "writes": {"directories": [{"path": str(p), "mode": "0700"} for p in sorted(dirs)],
                   "files": [{"path": str(root / p), "mode": "0600", "sha256": sha(b)}
                             for p, b in sorted(composed["documents"].items())]}, **I.COUNTERS}
    if not switched:
        state["wrapperIdentity"] = list(wrapper_identity)
    if not unit_switched:
        state["unitIdentity"] = list(unit_identity)
    return state, composed


def shared_state(version, old, new, files, previous):
    """Only 11 -> 12 may select the owner published by the migration."""
    code = 'R3_UPGRADE_SHARED_STATE_DRIFT'
    require(old['statusPath'] == new['statusPath']
            and old['recoveryJournalRoot'] == new['recoveryJournalRoot'], code)
    if old['coordinator'] == {**new['coordinator'], 'dnsProfile': old['coordinator']['dnsProfile']}:
        return
    require(version == 12 and 'migrationReceipt' in files, code)
    C.migration_bindings(files)
    plan = C.document(files['migrationPlan'])
    prior = plan['context']['owner']
    settings, owner = C.document(files['settings']), C.document(files['coordinator'])
    require(old['coordinator']['ownerConfiguration']['sha256'] == sha(canonical(prior))
            and old['coordinator']['ownerConfiguration']['path'] == plan['context']['profile']['coordinatedConfiguration']
            and old['coordinator']['journalPath'] == prior['journalFile']
            and old['coordinator']['commonLockPath'] == prior['commonLockFile']
            and new['coordinator']['ownerConfiguration'] == settings['coordinatorBinding']
            and new['coordinator']['journalPath'] == owner['journalFile']
            and new['coordinator']['commonLockPath'] == owner['commonLockFile']
            and old['coordinator']['nftBinding'] == new['coordinator']['nftBinding']
            and plan['observation']['authorization']['sha256'] == sha(canonical(previous))
            and previous['lease']['ownerConfigurationSha256'] == sha(canonical(prior))
            and previous['lease']['leaseStructureHash'] == prior['expectedStructureHash'], code)


def comparable(state):
    return {k: v for k, v in state.items() if k not in {"planSha256", "wrapperIdentity", "unitIdentity"}}


def apply(args, proposal, composed, report):
    require(args.plan_sha256 == proposal["planSha256"], "R3_PLAN_DIGEST_CHANGED")
    S = I.native_switch()
    root, output = Path(args.install_root), Path(args.output_directory)
    new_root = version_root(root, proposal["versionAfter"])
    # Same order as runtime/restore: per-CID locks first, then wrapper guard.
    # Keep CID locks through publication, systemd and wrapper CAS; never run a
    # container command, and release the guard before restarting the supervisor.
    with I.operation_locks(root, proposal["stoppedProvider"]):
        with I.guard(args, proposal["lock"]):
            fresh, composed = observe(args)
            require(I.digest_plan(fresh) == proposal, "R3_OBSERVATION_DRIFT")
            I.mkdir_once(output, report)
            report.update(outputCreated=True, planSha256=proposal["planSha256"], phase="PUBLISH")
            I.write_once(output / "upgrade-claim.json", canonical(proposal), report)
            for row in sorted(proposal["writes"]["directories"], key=lambda r: (r["path"].count("/"), r["path"])):
                path = Path(row["path"])
                if path == root / "versions" and os.path.lexists(path):
                    V.private_directory(path)
                else:
                    I.mkdir_once(path, report)
            for relative, raw in sorted(composed["documents"].items()):
                I.write_once(root / relative, raw, report)
            report["phase"] = "VERIFY_PUBLICATION"
            cfg = I.verify_publication(root, composed, code_root=new_root, require_no_epochs=False)
            I.command(cfg["pythonPath"], cfg["pythonSha256"], ["-I", "-B", str(new_root / "source" / C.RUNTIME),
                      "--configuration", str(new_root / "runtime-configuration.json"), "--version"], "R3_DIRECT_SMOKE_FAILED")
            fresh, _ = observe(args, published=True)
            require(comparable(fresh) == comparable(proposal), "R3_OBSERVATION_DRIFT")
        report["phase"] = "STOP_SUPERVISOR"
        I.systemctl(args, "stop", I.UNIT)
        I.service_readback(args, "inactive")
        with I.guard(args, proposal["lock"]):
            fresh, _ = observe(args, published=True)
            require(comparable(fresh) == comparable(proposal), "R3_OBSERVATION_DRIFT")
            old_unit = proposal["unitBefore"]["text"].encode("ascii")
            expected = (old_unit, tuple(proposal["unitIdentity"]))
            require(S.custody(I.UNIT_PATH, 0o600) == expected, "R3_UNIT_DRIFT")
            temporary = I.UNIT_PATH.with_name("." + I.UNIT + ".r3-upgrade-" + proposal["planSha256"])
            I.write_once(temporary, proposal["unit"]["text"].encode("ascii"), report)
            require(S.custody(I.UNIT_PATH, 0o600) == expected, "R3_UNIT_DRIFT")
            os.replace(temporary, I.UNIT_PATH)
            S.sync(I.UNIT_PATH.parent)
        report["phase"] = "START_SUPERVISOR"
        I.systemctl(args, "daemon-reload")
        I.systemctl(args, "start", I.UNIT)
        sup = C.document(composed["documents"][f"versions/{proposal['versionAfter']}/supervisor/configuration.json"])
        I.service_readback(args, "active", sup, proposal["versionAfter"], retained_history=True)

        def verify_locked(fd, phase):
            switched = phase == "AFTER_RENAME"
            fresh, recomposed = observe(args, published=True, unit_switched=True, switched=switched)
            require(comparable(fresh) == comparable(proposal), "R3_OBSERVATION_DRIFT")
            require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == tuple(proposal["lock"]["identity"][:2]),
                    "R3_BORROWED_GUARD_DRIFT")
            if not switched:
                require(list(S.custody(args.wrapper, 0o755)[1]) == proposal["wrapperIdentity"], "R3_WRAPPER_IDENTITY_DRIFT")
            I.verify_publication(root, recomposed, code_root=new_root, require_no_epochs=False)
            I.service_readback(args, "active", sup, proposal["versionAfter"], retained_history=True)

        report["phase"] = "SWITCH"
        result = S.switch_existing_wrapper(args.wrapper, args.current_wrapper_sha256,
            proposal["wrapperProposed"]["text"].encode("ascii"), output, args.lock,
            proposal["lock"]["identity"], verify_locked)
        report.update(switchOutcome="REPLACED", primitiveResult=result, phase="READBACK")
        require(sha(S.custody(args.wrapper, 0o755)[0]) == proposal["wrapperProposed"]["sha256"], "R3_WRAPPER_READBACK_DRIFT")
        I.command(args.wrapper, proposal["wrapperProposed"]["sha256"], ["--version"], "R3_WRAPPER_SMOKE_FAILED")
        with I.guard(args, proposal["lock"]) as fd:
            verify_locked(fd, "AFTER_RENAME")
        report.update(status="SEMANTIC_PROVIDER_R3_UPGRADED_WAITING", phase="COMPLETE",
            installRoot=str(root), versionBefore=proposal["versionBefore"], versionAfter=proposal["versionAfter"],
            wrapperBefore=args.current_wrapper_sha256, wrapperAfter=proposal["wrapperProposed"]["sha256"],
            authorization=proposal["authorization"], configurationSha256=proposal["configurationSha256"],
            unit=proposal["unit"], documentHashes={p: sha(b) for p, b in composed["documents"].items()})
        I.write_once(output / "result.json", canonical(report), report)


def arguments(argv=None):
    parser = I.Arguments(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("install-root", "wrapper", "current-wrapper-sha256", "lock", "docker", "docker-sha256",
                 "docker-socket", "systemctl", "systemctl-sha256", "output-directory", "inputs", "inputs-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--issued-at", type=int, required=True)
    parser.add_argument("--table-name", nargs=2, required=True)
    args = parser.parse_args(argv)
    require(all(not name.endswith("sha256") or value is None or V.hashed(value)
                for name, value in vars(args).items()), "INVALID_ARGUMENTS")
    require(args.apply == (args.plan_sha256 is not None)
            and re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket), "INVALID_ARGUMENTS")
    return args


def main(argv=None):
    report = {"schema": SCHEMA, "status": "HELD", "switchOutcome": "UNCHANGED", "doNotRerunApply": False, **I.COUNTERS}
    args = None
    try:
        args = arguments(argv)
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.flags.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        if args.apply and os.path.lexists(args.output_directory):
            report["doNotRerunApply"] = True
        with I.module_scope():
            state, composed = observe(args)
            proposal = I.digest_plan(state)
            if args.plan:
                report.update(proposal, status="PLAN_READY")
            else:
                apply(args, proposal, composed, report)
    except Exception as error:
        # Same public error, errno, primitive and partial-result discipline as
        # install_common; never expose exception messages or command output.
        from tools.semantic_provider_r3.operate import error_fields
        report.update(status="HELD", **error_fields(error))
        primitive = getattr(error, "diagnosis", None)
        if type(primitive) is dict:
            if "errno" in primitive:
                report["errno"] = primitive["errno"]
            report["primitive"] = {k: primitive[k] for k in ("stage", "switchOutcome", "wrapperReplaced",
                                   "renameAttempted", "errorType") if k in primitive}
            report["switchOutcome"] = primitive.get("switchOutcome", report["switchOutcome"])
            report["doNotRerunApply"] |= bool(primitive.get("doNotRerunApply"))
        if report.get("outputCreated") and args is not None:
            try:
                I.write_once(Path(args.output_directory) / "result.json", canonical(report), report)
            except Exception:
                report["diagnosisSaved"] = False
    print(canonical(report).decode("ascii"), flush=True)
    return int(report["status"] == "HELD")
