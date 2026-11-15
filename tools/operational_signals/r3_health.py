"""Lock-free R3 reader. Installed hash-verified loaders are the validation boundary."""
from pathlib import Path
import os
import re
import subprocess
import time
from types import SimpleNamespace

from tools.operational_signals import CODE, atomic_status, public, require
from tools.semantic_provider_r3 import operate as O

I, V, C = O.I, O.V, O.C
SCHEMA = "ouf.semantic-provider-r3-health.v1"
STATES = {"WAITING", "ACTIVE", "PARKED_RATE_LIMITED", "STOPPED", "FAILED"}
INSTABILITY = {"R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION", "R3_SNAPSHOT_CHANGED",
               "RUNTIME_SWITCH_CUSTODY_CHANGED", "EPOCH_FILE_CHANGED_DURING_READ",
               "EPOCH_POINTER_JOURNAL_DRIFT", "EPOCH_BEYOND_POINTER", "MANDATE_INPUT_DRIFT",
               "OPERATION_FILE_CHANGED_DURING_READ", "OPERATION_CHAIN_CHANGED_DURING_VERIFICATION",
               "OPERATION_LEDGER_CHANGED_DURING_VERIFICATION", "OPERATION_CAS_CHANGED"}


def empty():
    return {"schema": SCHEMA, "checkedAt": int(time.time()),
            "head": {"decision": "UNPROVEN", "sequence": None},
            "supervisor": {"unitActive": False, "state": None, "reason": None,
                           "updatedAt": None, "activationsLastHour": None},
            "lease": {"state": None, "leaseAuthorized": None},
            "roles": {r: {"epoch": None, "state": None, "failure": None, "live": False,
                           "previousState": None, "dockerRunning": None, "denials": []} for r in O.ROLES},
            "readError": None}


def code(value):
    require(value is None or type(value) is str and CODE.fullmatch(value), "R3_HEALTH_CODE_INVALID")
    return value


def integer(value, minimum=0):
    require(value is None or type(value) is int and value >= minimum, "R3_HEALTH_INTEGER_INVALID")
    return value


def capture(binary, argv, timeout, env, limit=131072):
    """No temporary output file, unlike operate.command."""
    result = subprocess.run([binary, *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, env=env)
    require(len(result.stdout) <= limit, "R3_COMMAND_OUTPUT_UNBOUNDED")
    require(result.returncode == 0, "R3_COMMAND_FAILED")
    return result.stdout


def command(path, digest, argv, timeout):
    binary = V.executable_hash(path, digest)
    try:
        return capture(binary, argv, timeout, I.ENV)
    finally:
        V.executable_hash(path, digest)


def docker(args, verb, cid):
    require(verb == "inspect", "R3_HEALTH_INSPECT_ONLY")
    return command(args.docker, args.docker_sha256,
                   ["--host", args.docker_socket, "inspect", cid], args.timeout_seconds)


def memory_file(raw):
    """Anonymous, sealed RAM descriptor; never creates a filesystem pathname."""
    import fcntl
    require(hasattr(os, "memfd_create"), "R3_MEMORY_VERIFICATION_UNAVAILABLE")
    fd = os.memfd_create("ouf-public-verification", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            require(written > 0, "R3_MEMORY_VERIFICATION_UNPROVEN")
            view = view[written:]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def readonly_mandates(mandates):
    """Keep installed authentication/ledger logic; replace only its temporary-file transport."""
    class MemoryAuthenticator(mandates.MandateAuthenticator):
        def verify(self, payload, public_key, signature):
            executable = self.executable()
            descriptors = []
            try:
                raw = capture(executable, ["version"], self.timeout(), mandates.ENV, limit=256)
                version = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", raw)
                mandates.require(version is not None and version.group(1).decode("ascii")
                                 == self.openssl_binding["version"], "DETACHED_OPENSSL_VERSION_UNPROVEN")
                for data in (mandates.DER_PREFIX + public_key, signature, payload):
                    descriptors.append(memory_file(data))
                key, sig, frame = ("/proc/self/fd/"+str(fd) for fd in descriptors)
                result = subprocess.run([executable, "pkeyutl", "-verify", "-pubin", "-rawin", "-keyform", "DER",
                    "-inkey", key, "-sigfile", sig, "-in", frame], pass_fds=tuple(descriptors),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=self.timeout(), env=mandates.ENV)
                self.budget.check()
                mandates.require(result.returncode == 0, "DETACHED_SIGNATURE_INVALID")
            except (OSError, subprocess.TimeoutExpired):
                raise mandates.MandateDenied("DETACHED_VERIFICATION_UNPROVEN") from None
            finally:
                for fd in descriptors:
                    os.close(fd)
                self.executable()
    proxy = SimpleNamespace(**vars(mandates))
    proxy.MandateAuthenticator = MemoryAuthenticator
    return proxy


class Snapshot:
    """Detect replacement as well as mutation, without acquiring any writer lock."""
    def __init__(self, custody):
        self.custody, self.files = custody, {}

    def read(self, path, mode=0o600):
        key = (str(path), mode)
        try:
            value = self.custody(path, mode)
        except FileNotFoundError:
            require(False, "R3_SNAPSHOT_CHANGED")
        require(key not in self.files or self.files[key] == value, "R3_SNAPSHOT_CHANGED")
        self.files[key] = value
        return value[0]

    def verify(self):
        for path, mode in self.files:
            self.read(path, mode)


def installed(args, snapshot):
    """Same sealed runtime selection and checks as operate.observe, without its output/nft reads."""
    root = V.absolute(args.install_root)
    V.private_directory(root)
    wrapper = snapshot.read(args.wrapper, 0o755)
    require(O.sha(wrapper) == args.wrapper_sha256, "R3_WRAPPER_DRIFT")
    code_root = I.wrapper_code_root(root, wrapper)
    if code_root != root:
        V.private_directory(root / "versions")
        V.private_directory(code_root)
    path = code_root / "source" / C.RUNTIME
    runtime = I.compiled(snapshot.read(path), path, "r3_health_installed_runtime",
                         O.sha((I.ROOT / C.RUNTIME).read_bytes()))
    cfg, raw = runtime.load_configuration(code_root / "runtime-configuration.json")
    runtime.verify_files(cfg)
    require(cfg["registryRoot"] == str(root / "registry")
            and cfg["operation"]["authorizationRoot"] == str(root / "authorization"), "R3_INSTALLED_ROOT_DRIFT")
    require(wrapper == I.wrapper_bytes(cfg["pythonPath"], code_root), "R3_WRAPPER_DRIFT")
    return runtime, cfg, raw


def authorization(runtime, cfg):
    # runtime.authorization_head rejects authenticated STOP. Use its installed
    # authentication module directly so STOP remains a visible human decision.
    auth, epochs = runtime.operation_modules(cfg)
    op = cfg["operation"]
    bound = op["mandatesModule"]
    mandates = runtime.compiled(runtime.bound_bytes(bound), bound["path"], "r3_health_installed_mandates")
    mandates = readonly_mandates(mandates)

    def head():
        return auth.head(mandates, op["anchorBinding"], op["mandateRoot"], cfg["opensslBinding"],
                         op["authorizationRoot"], op["installationRef"], op["entityRef"],
                         op["issuerRef"], time.time)
    return head, epochs


def observe(args, result):
    snapshot = Snapshot(I.native_switch().custody)
    runtime, cfg, raw = installed(args, snapshot)
    read_head, epochs = authorization(runtime, cfg)
    head = read_head()
    require(head["decision"] in {"OPERATE", "STOP"} and type(head["sequence"]) is int
            and head["sequence"] >= 1, "R3_HEAD_INVALID")
    result["head"] = {"decision": head["decision"], "sequence": head["sequence"]}
    if head["decision"] == "OPERATE":
        require(head["authorization"]["runtimeConfigurationSha256"] == O.sha(raw),
                "OPERATION_RUNTIME_CONFIGURATION_DRIFT")
        for cid, item in cfg["candidates"].items():
            bound = head["authorization"]["roles"][item["role"]]
            require(bound["containerId"] == cid and bound["admissionConfigurationSha256"]
                    == cfg["admissionConfigurations"][cid]["sha256"], "OPERATION_ADMISSION_CONFIGURATION_DRIFT")
    boot = epochs.boot_id()
    rows = {}
    for cid, item in sorted(cfg["candidates"].items()):
        role = item["role"]
        require(role in O.ROLES and role not in rows, "R3_HEALTH_ROLES_INVALID")
        row = epochs.current(cfg["registryRoot"], cid)
        rows[role] = (cid, row)
        previous = None
        if row is not None:
            base = Path(cfg["registryRoot"]) / cid
            pointer = C.document(snapshot.read(base / "current"))
            journal = snapshot.read(base / "epochs" / str(row["epoch"]) / "adapter.json")
            require(pointer == {"epoch": row["epoch"], "journalSha256": O.sha(journal)}
                    and epochs.validate_journal(journal, cid, row["epoch"]) == row, "R3_SNAPSHOT_CHANGED")
            if row["state"] in O.TERMINAL:
                O.terminal_binding(runtime, cfg, head, row)
            elif head["decision"] == "OPERATE":
                require(row["bootId"] == boot, "R3_EPOCH_BOOT_DRIFT")
                require(row["authorizationSha256"] == head["sha256"]
                        and row["configurationHash"] == O.sha(raw), "R3_EPOCH_AUTHORIZATION_DRIFT")
            # A STOP supersedes the live epoch's OPERATE entry; authenticate that
            # historical binding without pretending that the epoch is terminal.
            else:
                historical_binding(runtime, cfg, head, row)
            if row["epoch"] > 1:
                n = row["epoch"] - 1
                old = epochs.validate_journal(snapshot.read(base / "epochs" / str(n) / "adapter.json"), cid, n)
                O.terminal_binding(runtime, cfg, head, old)
                previous = code(old["state"])
        frame = O.docker_fields(docker(args, "inspect", cid), cid)
        if row is not None and row["state"] == "STARTED" and frame["Running"]:
            require(frame["Pid"] == row["generation"]["pid"], "R3_EPOCH_DOCKER_PID_DRIFT")
        denials = O.broker_denials(SimpleNamespace(read=snapshot.read), cfg["registryRoot"], cid, row["epoch"] if row else None)
        denials = sorted((d for d in denials if "invalid" not in d and d["epoch"] == row["epoch"]),
                         key=lambda d: (d["at"], d["mode"], d["reason"]))[-4:]
        result["roles"][role] = {"epoch": integer(row["epoch"], 1) if row else None,
            "state": code(row["state"]) if row else None, "failure": code(row["failure"]) if row else None,
            "live": bool(row and epochs.live(row, boot)), "previousState": previous,
            "dockerRunning": frame["Running"],
            "denials": [{k: d[k] for k in ("mode", "reason", "at")} for d in denials]}
    require(set(rows) == set(O.ROLES), "R3_HEALTH_ROLES_INVALID")
    sup = C.document(runtime.bound_bytes(cfg["leaseQuiesce"]["configuration"]))
    require(sup["registryRoot"] == cfg["registryRoot"]
            and sup["authorizationRoot"] == cfg["operation"]["authorizationRoot"], "R3_SUPERVISOR_ROOT_DRIFT")
    properties = command(args.systemctl, args.systemctl_sha256,
        ["show", I.UNIT, "--property=ActiveState", "--property=SubState", "--property=NRestarts"], args.timeout_seconds)
    fields = dict(line.split("=", 1) for line in properties.decode("ascii").splitlines())
    require(set(fields) == {"ActiveState", "SubState", "NRestarts"} and fields["NRestarts"].isdigit()
            and all(re.fullmatch(r"[a-z-]{1,40}", fields[k]) for k in ("ActiveState", "SubState")),
            "R3_SUPERVISOR_UNIT_INVALID")
    status = C.document(snapshot.read(sup["statusPath"]))
    require(status.get("schema") == "ouf.semantic-provider-lease-supervisor-status.v1"
            and status["state"] in STATES and type(status["epochs"]) is dict
            and set(status["epochs"]) == set(O.ROLES)
            and all(v is None or type(v) is int and v >= 1 for v in status["epochs"].values())
            and type(status["activationsLastHour"]) is int and status["activationsLastHour"] >= 0
            and (status["authorizationSequence"] is None or type(status["authorizationSequence"]) is int),
            "R3_SUPERVISOR_STATUS_INVALID")
    result["supervisor"] = {"unitActive": O.service_active({"supervisor": {"unit": fields}}),
        "state": status["state"], "reason": code(status["reason"]),
        "updatedAt": integer(status["updatedAt"]), "activationsLastHour": status["activationsLastHour"]}
    journal = C.document(snapshot.read(sup["coordinator"]["journalPath"]))
    require(type(journal["leaseAuthorized"]) is bool, "R3_LEASE_STATE_INVALID")
    result["lease"] = {"state": code(journal["state"]), "leaseAuthorized": journal["leaseAuthorized"]}
    runtime.verify_files(cfg)
    snapshot.verify()
    for cid, before in rows.values():
        require(epochs.current(cfg["registryRoot"], cid) == before, "R3_SNAPSHOT_CHANGED")
    require(read_head() == head, "R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION")


def historical_binding(runtime, cfg, head, row):
    # terminal_binding's initial terminal-state guard is essential to operate.
    # Authenticate the historical payload here without changing that helper.
    for sequence in range(1, head["sequence"] + 1):
        raw = runtime.read(Path(cfg["operation"]["authorizationRoot"]) / f"{sequence}.json")
        if O.sha(raw) == row["authorizationSha256"]:
            value = O.A.validate(raw)
            require(value["decision"] == "OPERATE" and value["runtimeConfigurationSha256"] == row["configurationHash"],
                    "R3_EPOCH_AUTHORIZATION_DRIFT")
            return
    require(False, "R3_EPOCH_AUTHORIZATION_DRIFT")


def collect(args):
    for attempt in range(2):
        result = empty()
        try:
            with I.module_scope():
                observe(args, result)
            return result
        except Exception as error:
            reason = "R3_SNAPSHOT_CHANGED" if isinstance(error, FileNotFoundError) else public(error)
            if reason in INSTABILITY and attempt == 0:
                continue
            # Do not publish a mixture of snapshots after a concurrent change.
            if reason in INSTABILITY:
                result = empty()
            result["readError"] = reason
            return result


def arguments(argv=None):
    parser = I.Arguments(description="Read-only R3 operational health")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    for name in ("install-root", "wrapper", "wrapper-sha256", "docker", "docker-sha256", "docker-socket",
                 "systemctl", "systemctl-sha256", "nft", "nft-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--status-path", default="/var/lib/ouf-semantic-provider-health/status.json")
    args = parser.parse_args(argv)
    require(1 <= args.timeout_seconds <= 600 and all(V.hashed(v) for k, v in vars(args).items()
            if k.endswith("sha256")) and re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket),
            "INVALID_ARGUMENTS")
    return args


def main(argv=None):
    # Parse status destination independently: invalid observation parameters still
    # produce UNPROVEN/readError when a valid destination has been supplied.
    parser = I.Arguments(add_help=False)
    parser.add_argument("--status-path", default="/var/lib/ouf-semantic-provider-health/status.json")
    try:
        destination = parser.parse_known_args(argv)[0].status_path
        try:
            args = arguments(argv)
            status = V.absolute(destination)
            root = V.absolute(args.install_root)
            require(not status.is_relative_to(root) and status not in
                    {V.absolute(args.wrapper), V.absolute(args.docker), V.absolute(args.systemctl), V.absolute(args.nft)},
                    "R3_SEPARATE_STATUS_REQUIRED")
            result = collect(args)
        except Exception as error:
            if public(error) == "R3_SEPARATE_STATUS_REQUIRED":
                raise
            result = empty()
            result["readError"] = public(error)
        atomic_status(destination, result)
    except Exception:
        print("R3_HEALTH_STATUS_WRITE_FAILED", flush=True)
        return 1
    print("R3_HEALTH_STATUS_WRITTEN", flush=True)
    return 0
