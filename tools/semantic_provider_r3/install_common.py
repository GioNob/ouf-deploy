"""Human-invoked R3 installation/restore. No signing or container lifecycle calls.

Native imports are lazy so the payload/unit contracts can be tested on Windows.
The unchanged task-29b custody and switch primitives remain the native boundary.
"""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import traceback
import types

from tools.semantic_provider_r3 import compose as C
from tools.semantic_provider_operation import authorization as A
from tools.semantic_runtime_v51_install import common as V

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "ouf.semantic-provider-r3-installation.v1"
UNIT = "ouf-semantic-lease-supervisor-v2.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
COUNTERS = dict(containerLifecycleOperations=0, dockerStartRequests=0, nftWrites=0,
                daemonRestarted=False, privateKeysRead=0, signaturesIssued=0,
                startAuthorized=False, leaseAuthorized=False)
PUBLIC = (*V.PUBLIC_ERRORS, "OperationDenied", "ConsumptionDenied")
require, canonical, sha = A.require, A.canonical, A.sha


def native_switch():
    # Same delivery-only package boundary as 29b: the switch imports its legacy
    # authentication contracts from cohort-draft/tools, not a global package.
    import tools as package
    package.__path__ = [str(ROOT / "tools"), str(ROOT / "tools/semantic_cohort_admission/cohort-draft/tools")]
    for path in (ROOT / "tools/semantic_transaction_profiles", ROOT / "tools/semantic_frame_compiler"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import guarded_runtime_switch
    return guarded_runtime_switch


def compiled(raw, path, name, expected, package=None):
    require(sha(raw) == expected, "R3_SOURCE_HASH_DRIFT")
    module = types.ModuleType(name)
    module.__file__, module.__package__ = str(path), package or name.rpartition(".")[0]
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


@contextmanager
def module_scope():
    """Real loaders install historical names; never leak those into the caller."""
    before = sys.modules.copy()
    attributes = {name: vars(m).copy() for name, m in before.items()
                  if (name == "tools" or name.startswith("tools.")) and hasattr(m, "__path__")}
    try:
        yield
    finally:
        for name in set(sys.modules) - set(before):
            del sys.modules[name]
        sys.modules.update(before)
        for name, saved in attributes.items():
            vars(before[name]).clear()
            vars(before[name]).update(saved)


class Reader:
    """Only explicit public hash bindings; no authority profile or key input."""
    def __init__(self):
        self.hashes = {}

    def read(self, path, expected):
        path = V.absolute(str(path))
        require(V.hashed(expected), "R3_INPUT_HASH_REQUIRED")
        S = native_switch()
        for parent in path.parents:
            S.directory(parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and before.st_nlink == 1 and not before.st_mode & 0o022
                    and 0 < before.st_size <= 8388608, "R3_PUBLIC_INPUT_CUSTODY_REQUIRED")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(8388609)
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                      "st_size", "st_mtime_ns", "st_ctime_ns")
            identity = lambda s: tuple(getattr(s, f) for f in fields)
            require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                    == identity(path.lstat()), "R3_INPUT_CUSTODY_DRIFT")
        finally:
            os.close(fd)
        require(sha(raw) == expected, "R3_INPUT_HASH_DRIFT")
        require(str(path) not in self.hashes or self.hashes[str(path)] == expected, "R3_INPUT_BINDING_CONFLICT")
        self.hashes[str(path)] = expected
        return raw

    def bound(self, value):
        require(type(value) is dict and set(value) == {"path", "sha256"}, "R3_EXACT_INPUT_BINDING_REQUIRED")
        return self.read(value["path"], value["sha256"])

    def verify(self):
        for path, digest in list(self.hashes.items()):
            self.read(path, digest)


def payload_match(composed, head, raw):
    require(head["decision"] == "OPERATE", "R3_AUTHORIZATION_NOT_OPERATE")
    expected = A.validate(composed["authorization"])
    for field in ("sequence", "supersedes", "issuedAt", "decision"):
        expected[field] = head["authorization"][field]
    require(head["sequence"] >= 1 and sha(raw) == head["sha256"]
            and canonical(expected) == raw, "R3_AUTHORIZATION_PAYLOAD_MISMATCH")
    return {"sequence": head["sequence"], "sha256": head["sha256"], "decision": "OPERATE",
            "payloadByteMatch": True}


def unit_bytes(root, config, supervisor):
    writable = sorted({str(root / "supervisor/state"),
                       str(Path(supervisor["coordinator"]["journalPath"]).parent),
                       supervisor["coordinator"]["commonLockPath"]})
    paths = (config["pythonPath"], str(root), *writable)
    require(all(re.fullmatch(r"/[A-Za-z0-9_./-]+", p) for p in paths), "R3_CLOSED_SERVICE_PATH_REQUIRED")
    supervisor = root / "supervisor/configuration.json"
    digest = config["leaseQuiesce"]["configuration"]["sha256"]
    return ("[Unit]\nDescription=OUF semantic lease supervisor v2\n"
            "After=docker.service ouf-semantic-boot-guard.service\nBindsTo=docker.service\n\n"
            "[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\n"
            f"ExecStart={config['pythonPath']} -I -B {root}/source/scripts/semantic-provider-lease-supervisor-v2.py "
            f"--configuration {supervisor} --configuration-sha256 {digest}\n"
            "Restart=always\nRestartSec=2\nNoNewPrivileges=yes\nProtectSystem=full\n"
            f"ReadWritePaths={' '.join(writable)}\n"
            "ProtectHome=yes\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n"
            "ProtectControlGroups=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n"
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n"
            "Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C OPENSSL_CONF=/dev/null\n\n"
            "[Install]\nWantedBy=multi-user.target\n").encode("ascii")


def wrapper_bytes(python, root, runtime=C.RUNTIME):
    raw = (f'#!/bin/sh\nexec {python} -I -B {root}/source/{runtime} '
           f'--configuration {root}/runtime-configuration.json "$@"\n').encode("ascii")
    V.wrapper_targets(raw)
    return raw


def v51_state(args, S):
    root = V.absolute(args.v51_root)
    path = root / "source" / V.RUNTIME
    raw = S.custody(path, 0o600)[0]
    module = compiled(raw, path, "r3_installed_v51", V.CLOSURE[V.RUNTIME])
    cfg, cfg_raw = module.load_configuration(root / "runtime-configuration.json")
    module.verify_files(cfg)
    require(module.arming_absence(root / "runtime-configuration.json") == V.EMPTY_ARMING, "R3_V51_ARMING_PRESENT")
    return cfg, {"root": str(root), "configurationSha256": sha(cfg_raw), "sourceSha256": sha(raw)}


def coordinator_state(settings, files, reader):
    raw = reader.bound(settings["coordinatorBinding"])
    require(raw == files["coordinator"], "R3_COORDINATOR_INPUT_DRIFT")
    owner = C.document(raw)
    # Journal can change legitimately only outside this installation transaction.
    raw, _ = native_switch().custody(owner["journalFile"], 0o600)
    row = C.document(raw)
    require(row.get("state") == "QUIESCED" and row.get("leaseAuthorized") is False
            and row.get("startAuthorized") is False, "R3_COORDINATOR_NOT_QUIESCED")
    require(row.get("transactionId") == owner["binding"]["transactionId"]
            and all(row.get(k) == v for k, v in owner["binding"].items()), "R3_COORDINATOR_BINDING_DRIFT")
    require(row == C.document(files["coordinationJournal"]), "R3_COORDINATOR_JOURNAL_DRIFT")
    return {"path": owner["journalFile"], "canonicalSha256": sha(canonical(row))}


def authorization(settings, sources, root):
    M = compiled(sources[C.MANDATES], root / "source" / C.MANDATES, "r3_mandates", sha(sources[C.MANDATES]))
    relative = "tools/semantic_provider_operation/authorization.py"
    auth = compiled(sources[relative], root / "source" / relative, "r3_authorization", sha(sources[relative]))
    head = auth.head(M, settings["anchorBinding"], settings["mandateRoot"], settings["opensslBinding"],
                  str(root / "authorization"), settings["installationRef"], settings["entityRef"],
                  settings["issuerRef"], time.time)
    return M, head


def output_directory(path, root, S, absent=True):
    path = V.absolute(path)
    require(not path.is_relative_to(root) and not root.is_relative_to(path), "R3_SEPARATE_OUTPUT_REQUIRED")
    for parent in path.parents:
        S.directory(parent)
    require(not absent or not os.path.lexists(path), "R3_OUTPUT_ALREADY_EXISTS")
    return path


def observe_install(args, *, published=False, after=False):
    S = native_switch()
    root = V.absolute(args.install_root)
    for ancestor in root.parents:
        S.directory(ancestor)
    V.private_directory(root)
    if not published:
        require({p.name for p in root.iterdir()} == {"authorization"}, "R3_INSTALL_ROOT_NOT_AUTHORIZATION_ONLY")
    V.private_directory(root / "authorization")
    reader = Reader()
    index = C.document(reader.read(args.inputs, args.inputs_sha256))
    require(set(index) == {"schema", "files", "sources"}
            and index["schema"] == "ouf.semantic-provider-r3-inputs.v1"
            and set(index["files"]) == C.DATA_INPUTS and set(index["sources"]) == C.SOURCE_INPUTS,
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
    result = C.compose({"files": files, "sources": sources})
    M, head = authorization(settings, sources, root)
    payload_raw = S.custody(root / "authorization" / f"{head['sequence']}.json", 0o600)[0]
    auth = payload_match(result, head, payload_raw)
    old, v51 = v51_state(args, S)
    require(old["acceptance"]["sha256"] == sha(files["acceptance"])
            and old["b1b2Anchor"] == settings["anchorBinding"] and old["mandateRoot"] == settings["mandateRoot"],
            "R3_V51_ACCEPTANCE_CONTEXT_DRIFT")
    signature = reader.read(args.acceptance_signature, args.acceptance_signature_sha256)
    require(M.MandateAuthenticator(settings["anchorBinding"], settings["mandateRoot"], settings["opensslBinding"]).
            verify_b1b2_detached(files["acceptance"], signature, "ARTIFACT_ACCEPTANCE", old["armingIssuerRef"],
                                settings["installationRef"], settings["entityRef"]) is True,
            "R3_ACCEPTANCE_SIGNATURE_DENIED")
    config = C.document(result["documents"]["runtime-configuration.json"])
    require(set(old["candidates"]) == set(config["candidates"]), "R3_V51_CANDIDATES_DRIFT")
    old_wrapper = wrapper_bytes(old["pythonPath"], Path(args.v51_root), V.RUNTIME)
    require(sha(old_wrapper) == args.current_wrapper_sha256, "R3_CURRENT_WRAPPER_BINDING_DRIFT")
    proposed = wrapper_bytes(config["pythonPath"], root)
    raw, identity = S.custody(args.wrapper, 0o755)
    require(raw == (proposed if after else old_wrapper), "R3_WRAPPER_DRIFT")
    frames = V.successor_frames(args.docker, args.docker_sha256, args.docker_socket, sorted(config["candidates"]))
    lock = V.guard_lock(S, args.lock)
    coordinator = coordinator_state(settings, files, reader)
    V.executable_hash(args.systemctl, args.systemctl_sha256)
    output_directory(args.output_directory, root, S, absent=not published)
    S.directory(UNIT_PATH.parent)
    if not published:
        require(not os.path.lexists(UNIT_PATH), "R3_SUPERVISOR_UNIT_ALREADY_EXISTS")
    reader.verify()
    directories = [root / p for p in result["layout"]["directories0700"] if p != "authorization"]
    unit = unit_bytes(root, config, C.document(result["documents"]["supervisor/configuration.json"]))
    state = {"schema": SCHEMA, "installRoot": str(root), "outputDirectory": args.output_directory,
             "inputHashes": reader.hashes, "compositionInputHashes": result["inputHashes"],
             "authorization": auth, "v51": v51, "successorFrames": frames, "lock": lock,
             "coordinator": coordinator, "configurationSha256": sha(result["documents"]["runtime-configuration.json"]),
             "wrapperBefore": {"path": args.wrapper, "sha256": sha(old_wrapper)},
             "wrapperProposed": {"text": proposed.decode("ascii"), "sha256": sha(proposed)},
             "systemctl": {"path": args.systemctl, "sha256": args.systemctl_sha256},
             "docker": {"path": args.docker, "sha256": args.docker_sha256, "socket": args.docker_socket},
             "unit": {"path": str(UNIT_PATH), "mode": "0600", "sha256": sha(unit), "text": unit.decode("ascii")},
             "writes": {"directories": [{"path": str(p), "mode": "0700", "sha256": None} for p in sorted(directories)],
                        "files": [{"path": str(root / p), "mode": "0600", "sha256": sha(raw)}
                                  for p, raw in sorted(result["documents"].items())]}, **COUNTERS}
    if not published:
        state["wrapperIdentity"] = list(identity)
    return state, result


def digest_plan(state):
    return {**state, "planSha256": sha(canonical(state))}


def comparable(state):
    return {k: v for k, v in state.items() if k not in {"planSha256", "wrapperIdentity"}}


def no_epochs(root, cids):
    for cid in cids:
        base = root / "registry" / cid
        V.private_directory(base)
        V.private_directory(base / "epochs")
        require(not os.path.lexists(base / "current") and not any((base / "epochs").iterdir()),
                "R3_EPOCH_PRESENT_RESTORE_DENIED")
        require(native_switch().custody(base / "operation.lock", 0o600)[0] == b"", "R3_OPERATION_LOCK_NOT_EMPTY")


@contextmanager
def operation_locks(root, cids):
    """Serialize restore with v5.2 create, which locks the CID before the guard."""
    import fcntl
    descriptors = []
    try:
        for cid in sorted(cids):
            path = root / "registry" / cid / "operation.lock"
            raw, identity = native_switch().custody(path, 0o600)
            require(raw == b"", "R3_OPERATION_LOCK_NOT_EMPTY")
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(native_switch().custody(path, 0o600)[1] == identity
                    and (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == identity[:2], "R3_OPERATION_LOCK_DRIFT")
        yield
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def verify_publication(root, result):
    """Execute the installed loaders, with all imported application bytes sealed first."""
    S = native_switch()
    for relative in result["layout"]["directories0700"]:
        V.private_directory(root / relative)
    for relative, raw in result["documents"].items():
        require(S.custody(root / relative, 0o600)[0] == raw, "R3_PUBLICATION_DRIFT")
    with module_scope():
        def load(relative, name, package=None):
            raw = result["documents"]["source/" + relative]
            return compiled(S.custody(root / "source" / relative, 0o600)[0], root / "source" / relative,
                            name, sha(raw), package)
        # Explicit packages prevent imports from falling back to the delivery tree.
        for name in ("tools", "tools.semantic_provider_operation", "tools.semantic_provider_admission_v2"):
            package = types.ModuleType(name)
            package.__path__ = []
            sys.modules[name] = package
            if "." in name:
                setattr(sys.modules[name.rpartition(".")[0]], name.rpartition(".")[2], package)
        for name in ("authorization", "epochs"):
            module = load("tools/semantic_provider_operation/" + name + ".py",
                          "tools.semantic_provider_operation." + name)
            setattr(sys.modules["tools.semantic_provider_operation"], name, module)
            sys.modules[name] = module
        for name in ("consumption_v2", "evidence_v2", "broker_v2"):
            module = load("tools/semantic_provider_admission_v2/" + name + ".py",
                          "tools.semantic_provider_admission_v2." + name)
            setattr(sys.modules["tools.semantic_provider_admission_v2"], name, module)
        broker = module
        for role in A.ROLES:
            broker.load(root / "broker" / (role + ".json"))
        runtime = load(C.RUNTIME, "r3_installed_runtime_v52")
        cfg, raw = runtime.load_configuration(root / "runtime-configuration.json")
        runtime.verify_files(cfg)
        require(sha(raw) == sha(result["documents"]["runtime-configuration.json"]), "R3_CONFIGURATION_DRIFT")
        supervisor = load(C.SUPERVISOR, "r3_installed_supervisor")
        path = root / "supervisor/configuration.json"
        configuration = supervisor.Configuration(path, sha(result["documents"]["supervisor/configuration.json"]))
        configuration.custody()
        # Compose the real retained owner/recovery closure without running Service.
        supervisor.runtime(configuration)
    no_epochs(root, cfg["candidates"])
    return cfg


def command(path, digest, argv, code):
    binary = V.executable_hash(path, digest)
    result = subprocess.run([binary, *argv], stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=30)
    V.executable_hash(path, digest)
    require(result.returncode == 0 and len(result.stdout) <= 131072, code)
    return result.stdout


def systemctl(args, *argv):
    return command(args.systemctl, args.systemctl_sha256, list(argv), "R3_SYSTEMCTL_FAILED")


def service_readback(args, state, cfg=None, sequence=None):
    deadline = time.monotonic() + 30
    while True:
        properties = systemctl(args, "show", UNIT, "--property=ActiveState", "--property=SubState",
                               "--property=FragmentPath", "--property=NeedDaemonReload", "--property=DropInPaths",
                               "--property=LoadState")
        try:
            rows = dict(line.split("=", 1) for line in properties.decode("ascii").splitlines())
        except (UnicodeError, ValueError):
            raise A.OperationDenied("R3_SYSTEMCTL_READBACK_INVALID") from None
        ok = rows.get("ActiveState") == state and rows.get("FragmentPath") == str(UNIT_PATH)
        ok = ok and rows.get("NeedDaemonReload") == "no"
        ok = ok and rows.get("DropInPaths") == ""
        if state == "not-found":
            ok = (rows.get("LoadState") == "not-found" and rows.get("ActiveState") == "inactive"
                  and rows.get("SubState") == "dead" and rows.get("FragmentPath") == ""
                  and rows.get("NeedDaemonReload") == "no" and rows.get("DropInPaths") == "")
        if state == "active":
            ok = ok and rows.get("SubState") == "running"
            path = Path(cfg["statusPath"])
            if os.path.lexists(path):
                row = C.document(native_switch().custody(path, 0o600)[0])
                ok = ok and row.get("schema") == "ouf.semantic-provider-lease-supervisor-status.v1"
                ok = ok and row.get("state") == "WAITING" and row.get("reason") == "EPOCH_NOT_LIVE"
                ok = ok and row.get("epochs") == dict.fromkeys(A.ROLES) and row.get("renewals") == 0
                ok = ok and row.get("authorizationSequence") == sequence and row.get("activationsLastHour") == 0
            else:
                ok = False
        if ok:
            return
        require(time.monotonic() < deadline, "R3_SUPERVISOR_READBACK_TIMEOUT")
        time.sleep(.1)


@contextmanager
def guard(args, expected):
    import fcntl
    S = native_switch()
    fd = os.open(args.lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(V.guard_lock(S, args.lock) == expected and (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                == tuple(expected["identity"][:2]), "R3_BORROWED_GUARD_DRIFT")
        yield fd
    finally:
        os.close(fd)


def write_once(path, raw, report):
    """Mark effects immediately after O_EXCL succeeds, even if write/fsync fails."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    report["doNotRerunApply"] = True
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    native_switch().sync(Path(path).parent)


def mkdir_once(path, report):
    path.mkdir(mode=0o700)
    report["doNotRerunApply"] = True  # directory creation is already an effect
    native_switch().sync(path.parent)


def apply_install(args, proposal, result, report):
    S = native_switch()
    require(args.plan_sha256 == proposal["planSha256"], "R3_PLAN_DIGEST_CHANGED")
    root, output = Path(args.install_root), Path(args.output_directory)
    with guard(args, proposal["lock"]):
        current, result = observe_install(args)
        require(digest_plan(current) == proposal, "R3_PLAN_DIGEST_CHANGED")
        # Durable separate claim is also the switch evidence root.
        mkdir_once(output, report)
        report.update(outputCreated=True, planSha256=proposal["planSha256"])
        write_once(output / "installation-claim.json", canonical(proposal), report)
        for row in sorted(proposal["writes"]["directories"], key=lambda row: (row["path"].count("/"), row["path"])):
            mkdir_once(Path(row["path"]), report)
        for relative, raw in sorted(result["documents"].items()):
            write_once(root / relative, raw, report)
        report["phase"] = "VERIFY_PUBLICATION"
        cfg = verify_publication(root, result)
        fresh, _ = observe_install(args, published=True)
        require(comparable(fresh) == comparable(proposal), "R3_OBSERVATION_DRIFT")
        command(cfg["pythonPath"], cfg["pythonSha256"], ["-I", "-B", str(root / "source" / C.RUNTIME),
                "--configuration", str(root / "runtime-configuration.json"), "--version"], "R3_DIRECT_SMOKE_FAILED")
        write_once(UNIT_PATH, proposal["unit"]["text"].encode("ascii"), report)
    report["phase"] = "ENABLE_SUPERVISOR"
    systemctl(args, "daemon-reload")
    systemctl(args, "enable", "--now", UNIT)
    sup = C.document(result["documents"]["supervisor/configuration.json"])
    service_readback(args, "active", sup, proposal["authorization"]["sequence"])

    def verify_locked(fd, phase):
        fresh, recomposed = observe_install(args, published=True, after=phase == "AFTER_RENAME")
        require(comparable(fresh) == comparable(proposal), "R3_OBSERVATION_DRIFT")
        if phase != "AFTER_RENAME":
            require(list(S.custody(args.wrapper, 0o755)[1]) == proposal["wrapperIdentity"], "R3_WRAPPER_IDENTITY_DRIFT")
        require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == tuple(proposal["lock"]["identity"][:2]),
                "R3_BORROWED_GUARD_DRIFT")
        verify_publication(root, recomposed)
        require(S.custody(UNIT_PATH, 0o600)[0] == proposal["unit"]["text"].encode("ascii"), "R3_UNIT_DRIFT")
        service_readback(args, "active", sup, proposal["authorization"]["sequence"])

    report["phase"] = "SWITCH"
    outcome = S.switch_existing_wrapper(args.wrapper, args.current_wrapper_sha256,
        proposal["wrapperProposed"]["text"].encode("ascii"), output, args.lock,
        proposal["lock"]["identity"], verify_locked)
    report.update(switchOutcome="REPLACED", primitiveResult=outcome, phase="READBACK")
    require(sha(S.custody(args.wrapper, 0o755)[0]) == proposal["wrapperProposed"]["sha256"], "R3_WRAPPER_READBACK_DRIFT")
    command(args.wrapper, proposal["wrapperProposed"]["sha256"], ["--version"], "R3_WRAPPER_SMOKE_FAILED")
    with guard(args, proposal["lock"]) as fd:
        verify_locked(fd, "AFTER_RENAME")
    report.update(status="SEMANTIC_PROVIDER_R3_INSTALLED_WAITING", phase="COMPLETE",
                  installRoot=str(root), wrapperAfter=proposal["wrapperProposed"]["sha256"],
                  wrapperBefore=args.current_wrapper_sha256, configurationSha256=proposal["configurationSha256"],
                  authorization=proposal["authorization"], unit=proposal["unit"],
                  documentHashes={p: sha(raw) for p, raw in result["documents"].items()})
    write_once(output / "result.json", canonical(report), report)


def restore_observe(args, *, after=False, output_exists=False, unit_retired=False):
    S = native_switch()
    root = V.absolute(args.install_root)
    V.private_directory(root)
    output_directory(args.output_directory, root, S, absent=not output_exists)
    claim = V.absolute(args.installation_output_directory)
    V.private_directory(claim)
    receipt_raw = S.custody(claim / "result.json", 0o600)[0]
    receipt = C.document(receipt_raw)
    require(receipt.get("status") == "SEMANTIC_PROVIDER_R3_INSTALLED_WAITING"
            and receipt.get("installRoot") == str(root)
            and receipt.get("wrapperAfter") == args.current_wrapper_sha256
            and receipt.get("wrapperBefore") == args.prior_wrapper_sha256, "R3_INSTALL_RECEIPT_DRIFT")
    prior = S.custody(claim / "prior-runtime-wrapper.sh", 0o600)[0]
    switch = C.document(S.custody(claim / "runtime-switch-claim.json", 0o600)[0])
    require(sha(prior) == args.prior_wrapper_sha256
            and switch.get("priorWrapperHash") == args.prior_wrapper_sha256
            and switch.get("proposedWrapperHash") == args.current_wrapper_sha256, "R3_PRIOR_WRAPPER_BACKUP_DRIFT")
    old, v51 = v51_state(args, S)
    require(prior == wrapper_bytes(old["pythonPath"], Path(args.v51_root), V.RUNTIME), "R3_PRIOR_WRAPPER_TARGET_DRIFT")
    runtime_raw = S.custody(root / "source" / C.RUNTIME, 0o600)[0]
    # The delivery is trusted code, as in 29b; installed runtime must match it.
    delivered = (ROOT / C.RUNTIME).read_bytes()
    runtime = compiled(runtime_raw, root / "source" / C.RUNTIME, "r3_restore_runtime", sha(delivered))
    cfg, raw = runtime.load_configuration(root / "runtime-configuration.json")
    runtime.verify_files(cfg)
    require(sha(raw) == receipt["configurationSha256"], "R3_INSTALLED_CONFIGURATION_DRIFT")
    require(set(cfg["candidates"]) == set(old["candidates"]), "R3_V51_CANDIDATES_DRIFT")
    # Check before Docker/systemctl, with the requested dedicated epoch denial.
    no_epochs(root, cfg["candidates"])
    expected = wrapper_bytes(cfg["pythonPath"], root)
    require(sha(expected) == args.current_wrapper_sha256, "R3_INSTALLED_WRAPPER_TARGET_DRIFT")
    wrapper, identity = S.custody(args.wrapper, 0o755)
    require(wrapper == (prior if after else expected), "R3_WRAPPER_DRIFT")
    frames = V.successor_frames(args.docker, args.docker_sha256, args.docker_socket, sorted(cfg["candidates"]))
    lock = V.guard_lock(S, args.lock)
    supervisor = C.document(S.custody(root / "supervisor/configuration.json", 0o600)[0])
    unit = unit_bytes(root, cfg, supervisor)
    unit_path = Path(args.output_directory) / UNIT if unit_retired else UNIT_PATH
    require(S.custody(unit_path, 0o600)[0] == unit, "R3_UNIT_DRIFT")
    require(not unit_retired or not os.path.lexists(UNIT_PATH), "R3_UNIT_RETIREMENT_UNPROVEN")
    V.executable_hash(args.systemctl, args.systemctl_sha256)
    return {"schema": SCHEMA, "installRoot": str(root), "outputDirectory": args.output_directory,
            "installationOutputDirectory": str(claim), "receiptSha256": sha(receipt_raw), "v51": v51,
            "priorWrapperSha256": sha(prior), "installedWrapperSha256": sha(expected), "lock": lock,
            "successorFrames": frames, "configurationSha256": sha(raw),
            "systemctl": {"path": args.systemctl, "sha256": args.systemctl_sha256},
            "docker": {"path": args.docker, "sha256": args.docker_sha256, "socket": args.docker_socket},
            "wrapper": args.wrapper, "unitSha256": sha(unit), **COUNTERS}, prior


def apply_restore(args, proposal, prior, report):
    # Take the same locks in the same order as a native operation. An in-flight
    # create must finish before any restore observation or wrapper replacement.
    root = Path(args.install_root)
    with operation_locks(root, proposal["successorFrames"]):
        return restore_locked(args, proposal, prior, report)


def restore_locked(args, proposal, prior, report):
    require(args.plan_sha256 == proposal["planSha256"], "R3_PLAN_DIGEST_CHANGED")
    S = native_switch()
    with guard(args, proposal["lock"]):
        current, _ = restore_observe(args)
        require(digest_plan(current) == proposal, "R3_OBSERVATION_DRIFT")
        output = Path(args.output_directory)
        mkdir_once(output, report)
        report.update(outputCreated=True, planSha256=proposal["planSha256"])

    def verify_locked(fd, phase):
        current, _ = restore_observe(args, after=phase in ("AFTER_RENAME", "AFTER_RETIRE"),
                                     output_exists=True, unit_retired=phase == "AFTER_RETIRE")
        require(digest_plan(current) == proposal and (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                == tuple(proposal["lock"]["identity"][:2]), "R3_OBSERVATION_DRIFT")

    result = S.switch_existing_wrapper(args.wrapper, args.current_wrapper_sha256, prior, output,
                                      args.lock, proposal["lock"]["identity"], verify_locked)
    report.update(switchOutcome="REPLACED", primitiveResult=result, phase="DISABLE_SUPERVISOR")
    systemctl(args, "disable", "--now", UNIT)
    service_readback(args, "inactive")
    with guard(args, proposal["lock"]) as fd:
        verify_locked(fd, "AFTER_RENAME")
        report.update(phase="RETIRE_SUPERVISOR_UNIT")
        unit, identity = S.custody(UNIT_PATH, 0o600)
        require(sha(unit) == proposal["unitSha256"], "R3_UNIT_DRIFT")
        retired = output / UNIT
        # Copy exclusively, fsync and verify before unlinking. This also works
        # when the evidence root and /etc/systemd/system are different mounts.
        write_once(retired, unit, report)
        require(S.custody(retired, 0o600)[0] == unit, "R3_RETIRED_UNIT_HASH_DRIFT")
        require(S.custody(UNIT_PATH, 0o600) == (unit, identity), "R3_UNIT_DRIFT")
        UNIT_PATH.unlink()
        S.sync(UNIT_PATH.parent)
        report.update(retiredUnit={"path": str(retired), "sha256": sha(unit)}, phase="RELOAD_SUPERVISOR_UNIT")
    systemctl(args, "daemon-reload")
    service_readback(args, "not-found")
    with guard(args, proposal["lock"]) as fd:
        verify_locked(fd, "AFTER_RETIRE")
    require(S.custody(args.wrapper, 0o755)[0] == prior, "R3_RESTORED_WRAPPER_READBACK_DRIFT")
    report.update(status="SEMANTIC_PROVIDER_R3_RESTORED_V51", phase="COMPLETE",
                  wrapperAfter=sha(prior), wrapperBefore=args.current_wrapper_sha256, unitLoadState="not-found")
    write_once(output / "result.json", canonical(report), report)


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise A.OperationDenied("INVALID_ARGUMENTS")


def arguments(argv=None, restore=False):
    parser = Arguments(description="R3 restore" if restore else "R3 installer")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    names = ["install-root", "v51-root", "wrapper", "current-wrapper-sha256", "lock", "docker",
             "docker-sha256", "docker-socket", "systemctl", "systemctl-sha256", "output-directory"]
    names += (["installation-output-directory", "prior-wrapper-sha256"] if restore else
              ["inputs", "inputs-sha256", "acceptance-signature", "acceptance-signature-sha256"])
    for name in names:
        parser.add_argument("--" + name, required=True)
    if not restore:
        parser.add_argument("--issued-at", type=int, required=True)
        parser.add_argument("--table-name", nargs=2, required=True)
    args = parser.parse_args(argv)
    for name, value in vars(args).items():
        if name.endswith("sha256") and value is not None and not V.hashed(value):
            parser.error("sha256")
    if not re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket):
        parser.error("socket")
    if args.apply != (args.plan_sha256 is not None):
        parser.error("plan digest")
    return args


def public(error):
    if type(error).__name__ in PUBLIC and re.fullmatch(r"[A-Z][A-Z0-9_]{1,95}", str(error)):
        return str(error)
    if type(error).__name__ == "TransactionDenied":
        code = getattr(error, "diagnosis", {}).get("reason")
        if type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{1,95}", code):
            return code
    return "R3_INPUT_OR_IO_UNPROVEN"


def main(argv=None, restore=False):
    report = {"schema": SCHEMA, "status": "HELD", "switchOutcome": "UNCHANGED", "doNotRerunApply": False, **COUNTERS}
    args = None
    try:
        args = arguments(argv, restore)
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.flags.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        if args.apply and os.path.lexists(args.output_directory):
            report["doNotRerunApply"] = True
        with module_scope():
            if restore:
                state, material = restore_observe(args)
            else:
                state, material = observe_install(args)
            proposal = digest_plan(state)
            if args.plan:
                report.update(proposal, status="PLAN_READY")
            elif restore:
                apply_restore(args, proposal, material, report)
            else:
                apply_install(args, proposal, material, report)
    except Exception as error:
        report.update(status="HELD", reason=public(error))
        if isinstance(error, OSError):
            report["errno"] = error.errno
        if type(error).__name__ not in PUBLIC:
            report["callChain"] = [{"function": f.name, "line": f.lineno}
                                   for f in traceback.extract_tb(error.__traceback__)[-6:]]
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
                write_once(Path(args.output_directory) / "result.json", canonical(report), report)
            except Exception:
                report["diagnosisSaved"] = False
    print(canonical(report).decode("ascii"), flush=True)
    return int(report["status"] == "HELD")
