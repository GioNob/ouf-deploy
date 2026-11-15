"""Source-pinned epoch broker. Native IO is Linux root-only; policy is portable."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import types
from typing import Protocol

from tools.semantic_provider_operation import authorization
from .consumption_v2 import EpochConsumption, hashed, operating_role, require
from . import evidence_v2
from .locking import wait_common_lock

SCHEMA = "ouf.semantic-deployment-broker.v2"
JOURNAL_SCHEMA = "ouf.semantic-deployment-broker-journal.v2"
FIELDS = {"schema", "sourceRoot", "sourceHashes", "authorities", "operation", "role", "containerId",
          "registryRoot", "framePolicyBinding", "rootfsSealBinding", "transportBinding", "preparerTemplate",
          "runtimeRootParent", "rootfsLimits", "creationFrameObserverBinding"}
MODULES = ("materialize_southbound_kernel", "materialize_southbound_lease_refresh", "semantic_provider_dns",
           "semantic_provider_lease_nft", "semantic_provider_lease_owner", "materialize_semantic_shared_faces",
           "semantic_provider_lease_coordination", "semantic_provider_preexec", "semantic_provider_preexec_native",
           "semantic_provider_peer_bindings", "semantic_provider_deployment_admission",
           "semantic_provider_deployment_protocol", "semantic_provider_deployment_consumption",
           "semantic_provider_deployment_authentication", "semantic_provider_deployment_producer",
           "semantic_provider_node_observation")
ENTRYPOINTS = ("scripts/semantic-provider-deployment-broker-v2.py",
              "scripts/semantic-provider-admission-preparer-v2.py",
              "scripts/semantic-provider-preexec-hook-v2.py")
V2_MODULES = ("__init__", "locking", "consumption_v2", "evidence_v2", "reauthorization_v2",
              "broker_v2", "driver_v7", "preparer_v2")
SOURCES = ({"tools/" + name + ".py" for name in MODULES} | set(ENTRYPOINTS)
           | {"tools/semantic_provider_admission_v2/" + name + ".py" for name in V2_MODULES}
           | {"tools/semantic_provider_operation/authorization.py", "tools/semantic_provider_operation/epochs.py"})
MODES = {"authorize-create": "OPENING", "record-created": "CREATING", "cohort-ready": "CREATED",
         "prepare": "PREPARING", "cleanup": "DELETING"}
DENIAL_SCHEMA = "ouf.semantic-deployment-broker-denial.v1"


def denial_code(error):
    try:
        code = str(error)
    except Exception:
        return "INTERNAL_ERROR"
    return code if re.fullmatch(r"[A-Z0-9_]{1,80}", code) else "INTERNAL_ERROR"


def validate_denial(raw, cid, epoch, mode):
    """Closed public receipt, including every nested diagnostic field."""
    def check(ok):
        require(ok, "BROKER_DENIAL_INVALID")

    def code(value):
        return type(value) is str and re.fullmatch(r"[A-Z0-9_]{1,80}", value) is not None

    def name(value):
        return type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", value) is not None

    def mac(value):
        return type(value) is str and re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", value) is not None

    def ipv4(value):
        check(type(value) is str)
        check(str(ipaddress.IPv4Address(value)) == value)

    check(type(raw) is bytes and 0 < len(raw) <= 65536)
    value = authorization.decode(raw)
    check(set(value) == {"schema", "containerId", "epoch", "mode", "reason", "at", "cohort"}
          and value["schema"] == DENIAL_SCHEMA and hashed(value["containerId"]) and value["containerId"] == cid
          and type(value["epoch"]) is int and 1 <= value["epoch"] <= 10 ** 9 and value["epoch"] == epoch
          and type(value["mode"]) is str and value["mode"] in MODES and value["mode"] == mode
          and code(value["reason"]) and type(value["at"]) is int and 0 < value["at"] < 2 ** 53)
    cohort = value["cohort"]
    if cohort is None:
        return value
    check(type(cohort) is dict and set(cohort) == {"peers"} and type(cohort["peers"]) is list
          and 1 <= len(cohort["peers"]) <= 8)
    seen = set()
    for peer in cohort["peers"]:
        fields = {"containerId", "lastReason", "attempts", "runc", "networkBindings"}
        check(type(peer) is dict and fields <= set(peer) <= fields | {"snapshot", "snapshotError"}
              and hashed(peer["containerId"]) and peer["containerId"] not in seen and peer["containerId"] != cid
              and (peer["lastReason"] is None or code(peer["lastReason"]))
              and type(peer["attempts"]) is int and 0 <= peer["attempts"] < 2 ** 53)
        seen.add(peer["containerId"])
        if peer["runc"] is not None:
            check(type(peer["runc"]) is dict and set(peer["runc"]) == {"status", "pid"})
            Broker.public_runtime_row(peer["runc"])
        check(type(peer["networkBindings"]) is list and 1 <= len(peer["networkBindings"]) <= 8)
        for nic in peer["networkBindings"]:
            check(type(nic) is dict and set(nic) == {"interface", "ipv4", "mac", "bridge"}
                  and name(nic["interface"]) and name(nic["bridge"]) and mac(nic["mac"]))
            ipv4(nic["ipv4"])
        if "snapshotError" in peer:
            check(code(peer["snapshotError"]))
        if "snapshot" not in peer:
            continue
        snapshot = peer["snapshot"]
        check(type(snapshot) is dict and set(snapshot) == {"interfaces", "hosts"}
              and all(type(snapshot[k]) is list and len(snapshot[k]) <= 32 for k in snapshot)
              and len(authorization.canonical(snapshot)) <= 4096)
        for nic in snapshot["interfaces"]:
            check(type(nic) is dict and set(nic) == {"ifname", "ifindex", "link_index", "address", "ipv4", "ipv6Count"}
                  and name(nic["ifname"]) and nic["ifname"] != "lo"
                  and type(nic["ifindex"]) is int and nic["ifindex"] > 0
                  and (nic["link_index"] is None or type(nic["link_index"]) is int and nic["link_index"] > 0)
                  and (nic["address"] is None or mac(nic["address"]))
                  and type(nic["ipv4"]) is list and len(nic["ipv4"]) <= 32
                  and type(nic["ipv6Count"]) is int and 0 <= nic["ipv6Count"] <= 32)
            for address in nic["ipv4"]:
                ipv4(address)
        for host in snapshot["hosts"]:
            check(type(host) is dict and set(host) == {"link_index", "ifname", "master"}
                  and type(host["link_index"]) is int and host["link_index"] > 0
                  and all(host[k] is None or name(host[k]) for k in ("ifname", "master")))
    return value


def absolute(value):
    return (type(value) is str and value.startswith("/") and ".." not in value.split("/")
            and "//" not in value and "\x00" not in value and str(Path(value).as_posix()) == value)


def binding(value, extra=()):
    return (type(value) is dict and set(value) == {"path", "sha256", *extra}
            and absolute(value["path"]) and hashed(value["sha256"]))


def validate(raw):
    cfg = authorization.decode(raw)
    require(set(cfg) == FIELDS and cfg["schema"] == SCHEMA, "EXACT_BROKER_CONFIGURATION_REQUIRED")
    require(type(cfg["authorities"]) is dict and set(cfg["authorities"]) == {"installationRef", "entityRef", "issuerRef"}
            and all(authorization.identity(v) for v in cfg["authorities"].values()), "EXACT_BROKER_AUTHORITIES_REQUIRED")
    op = cfg["operation"]
    require(type(op) is dict and set(op) == {"authorizationRoot", "anchorBinding", "mandateRoot", "opensslBinding",
            "mandatesModule"} and all(absolute(op[k]) for k in ("authorizationRoot", "mandateRoot"))
            and binding(op["anchorBinding"]) and binding(op["mandatesModule"])
            and binding(op["opensslBinding"], ("version",)) and type(op["opensslBinding"]["version"]) is str
            and re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,63}", op["opensslBinding"]["version"]),
            "EXACT_BROKER_OPERATION_REQUIRED")
    require(cfg["role"] in ("adapter", "southbound") and hashed(cfg["containerId"]), "EXACT_BROKER_ROLE_REQUIRED")
    require(all(absolute(cfg[k]) for k in ("sourceRoot", "registryRoot", "runtimeRootParent")),
            "EXPLICIT_BROKER_PATH_REQUIRED")
    require(type(cfg["sourceHashes"]) is dict and set(cfg["sourceHashes"]) == SOURCES
            and all(hashed(v) for v in cfg["sourceHashes"].values()), "EXACT_BROKER_SOURCE_SET_REQUIRED")
    require(all(binding(cfg[k]) for k in ("framePolicyBinding", "rootfsSealBinding", "transportBinding", "preparerTemplate")),
            "EXACT_BROKER_BINDINGS_REQUIRED")
    frame = cfg["creationFrameObserverBinding"]
    require(type(frame) is dict and set(frame) == {"python", "source", "configuration"}
            and all(binding(v) for v in frame.values()) and frame["configuration"] == cfg["framePolicyBinding"],
            "EXACT_BROKER_FRAME_OBSERVER_REQUIRED")
    limits = cfg["rootfsLimits"]
    require(type(limits) is dict and set(limits) == {"maxEntries", "maxBytes", "maxDepth"}
            and all(type(v) is int for v in limits.values()) and 1 <= limits["maxEntries"] <= 100000
            and 1 <= limits["maxBytes"] <= 8589934592 and 1 <= limits["maxDepth"] <= 64,
            "BOUNDED_ROOTFS_LIMITS_REQUIRED")
    return cfg


def private(path):
    """Bootstrap reader: no unverified v1 module runs before custody/hash checks."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "PRIVATE_PATH_REQUIRED")
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "PRIVATE_ANCESTOR_REQUIRED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 131072,
                "PRIVATE_FILE_REQUIRED")
        raw = os.read(fd, 131073)
        require(len(raw) == info.st_size and attributes(info) == attributes(os.fstat(fd)), "PRIVATE_READ_DRIFT")
        return raw
    finally:
        os.close(fd)


def attributes(info):
    return tuple(getattr(info, k) for k in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                           "st_size", "st_mtime_ns", "st_ctime_ns"))


def read_binding(value):
    raw = private(value["path"])
    require(authorization.sha(raw) == value["sha256"], "BROKER_BOUND_FILE_DRIFT")
    return raw


def load(path):
    raw = private(path)
    cfg = validate(raw)
    root = Path(cfg["sourceRoot"])
    verified = verify_sources(cfg)
    import tools as package
    for name in MODULES:
        full = "tools." + name
        module = types.ModuleType(full)
        module.__package__, module.__file__ = "tools", str(root / "tools" / (name + ".py"))
        sys.modules[full] = module
        setattr(package, name, module)
        exec(compile(verified["tools/" + name + ".py"], module.__file__, "exec"), module.__dict__)
    require(private(path) == raw, "BROKER_CONFIGURATION_DRIFT")
    return cfg, raw


def verify_sources(cfg):
    """Recheck the entire closed package, including the running entrypoints."""
    require(type(cfg["sourceHashes"]) is dict and set(cfg["sourceHashes"]) == SOURCES
            and all(hashed(h) for h in cfg["sourceHashes"].values()), "EXACT_BROKER_SOURCE_SET_REQUIRED")
    root = Path(cfg["sourceRoot"])
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_SOURCE_ROOT_REQUIRED")
    verified = {p: private(root / p) for p in SOURCES}
    require(all(authorization.sha(raw) == cfg["sourceHashes"][p] for p, raw in verified.items()),
            "BROKER_SOURCE_PACKAGE_DRIFT")
    return verified


def epoch_module():
    # The existing epochs reader deliberately uses a top-level authorization import.
    sys.modules.setdefault("authorization", authorization)
    from tools.semantic_provider_operation import epochs
    return epochs


class PreparerPort(Protocol):
    """Task-38b owns grant validation/protection and writes only inside epochRoot.

    prepare returns {binding, evidenceHash, driverHash}; driver.json must exist.
    It must acquire the request's common lock itself, outside the broker lock.
    cleanup must prove removal of that same protected footprint before returning.
    """
    def prepare(self, request, state): ...
    def cleanup(self, request): ...


class UnavailablePreparer:
    def prepare(self, request, state):
        require(False, "PREPARER_V2_UNAVAILABLE")

    def cleanup(self, request):
        require(False, "PREPARER_V2_UNAVAILABLE")


class SubprocessPreparer:
    """Fixed local v2 entrypoint; request bytes are already sealed by the broker."""
    def invoke(self, request, mode, state=None):
        from tools.semantic_provider_deployment_authentication import VerificationBudget
        from tools.semantic_provider_deployment_producer import program
        path = Path(request["epochRoot"]) / "preparer.json"
        require(private(path) == authorization.canonical(request), "SUBPROCESS_PREPARER_REQUEST_DRIFT")
        template = request["template"]
        budget = VerificationBudget(18)
        python = {"path": template["pythonPath"], "sha256": template["pythonHash"]}
        executable = program(python, budget)
        cfg = validate(read_binding(request["configurationBinding"]))
        verify_sources(cfg)
        entry = Path(cfg["sourceRoot"]) / ENTRYPOINTS[1]
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([executable, "-I", "-B", str(entry), "--configuration", path.as_posix(), "--mode", mode],
                input=authorization.canonical(state) if state is not None else None,
                stdin=subprocess.DEVNULL if state is None else None, stdout=output, stderr=subprocess.DEVNULL,
                timeout=budget.remaining(18), env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            output.seek(0)
            raw = output.read(131073)
        require(result.returncode == 0 and len(raw) <= 131072, "SUBPROCESS_PREPARER_DENIED")
        program(python, budget)
        verify_sources(cfg)
        require(private(path) == authorization.canonical(request), "SUBPROCESS_PREPARER_REQUEST_DRIFT")
        # Worker prints a single canonical object followed by exactly one newline.
        require(raw.endswith(b"\n"), "SUBPROCESS_PREPARER_RESULT_DRIFT")
        value = authorization.decode(raw[:-1])
        if mode == "cleanup":
            require(value == {"state": "CLEANED"}, "SUBPROCESS_PREPARER_RESULT_DRIFT")
        else:
            require(set(value) == {"binding", "evidenceHash", "driverHash"} and value["binding"] == request["binding"]
                    and value["evidenceHash"] == request["evidenceBinding"]["sha256"] and hashed(value["driverHash"]),
                    "SUBPROCESS_PREPARER_RESULT_DRIFT")
        return value

    def prepare(self, request, state):
        return self.invoke(request, "prepare", state)

    def cleanup(self, request):
        return self.invoke(request, "cleanup")


class Broker:
    def __init__(self, cfg, raw, configuration_path, args, preparer=None, clock=time.time):
        from tools.semantic_provider_deployment_authentication import VerificationBudget, decode
        from tools.semantic_provider_lease_coordination import PrivateJournal
        require(validate(raw) == cfg, "BROKER_CONFIGURATION_DRIFT")
        self.cfg, self.raw, self.path, self.args, self.clock = cfg, raw, configuration_path, args, clock
        self.budget = VerificationBudget(18)
        self.preparer = preparer if preparer is not None else SubprocessPreparer()
        self.cid = cfg["containerId"]
        require(args.container_id == self.cid and type(args.epoch) is int and 1 <= args.epoch <= 10 ** 9
                and args.mode in MODES, "BROKER_INVOCATION_DRIFT")
        self.root = Path(cfg["registryRoot"]) / self.cid / "epochs" / str(args.epoch)
        require(args.bundle == str(self.root / "bundle"), "BROKER_BUNDLE_DRIFT")
        runtime, parent = Path(args.runtime_root), Path(cfg["runtimeRootParent"])
        require(absolute(args.runtime_root) and runtime == runtime.resolve()
                and runtime != parent and runtime.is_relative_to(parent), "BROKER_RUNTIME_ROOT_DRIFT")
        self.epochs = epoch_module()
        self.epochs.directory(self.root)
        self.denial_root = self.root
        self.cohort = None
        op = cfg["operation"]
        self.mandates_raw = read_binding(op["mandatesModule"])
        self.mandates = types.ModuleType("admission_v2_verified_mandates")
        exec(compile(self.mandates_raw, "<verified-mandates>", "exec"), self.mandates.__dict__)
        head = self.head()
        self.binding = {**{k: cfg["authorities"][k] for k in ("installationRef", "entityRef")},
                        "containerId": self.cid, "epoch": args.epoch, "authorizationSha256": head["sha256"],
                        "configurationHash": authorization.sha(raw)}
        self.role = operating_role(head, self.binding)
        require(head["authorization"]["roles"][cfg["role"]] == self.role, "BROKER_OPERATION_ROLE_DRIFT")
        self.template_raw = read_binding(cfg["preparerTemplate"])
        self.template = decode(self.template_raw, 131072)
        # Reuse the stable v1 template as data only; its old authority fields never run.
        fields = {"schema", "pythonPath", "pythonHash", "commands", "commandHashes", "candidate", "kernel", "dns",
                  "coordinationBinding", "coordinationJournal", "lockFile", "budgetSeconds", "hostNetworkNamespace"}
        require(set(self.template) == fields and self.template["schema"] == "ouf.semantic-admission-preparer-template.v1",
                "EXACT_BROKER_PREPARER_TEMPLATE_REQUIRED")
        candidate = self.template["candidate"]
        require(type(candidate) is dict and set(candidate) == {"containerId", "transactionId", "networkBindings", "transport",
                "tableName", "runtimeBinding"} and candidate["containerId"] == self.cid
                and binding(candidate["runtimeBinding"]) and absolute(self.template["lockFile"])
                and type(self.template["commands"]) is dict and type(self.template["commandHashes"]) is dict
                and all(k in self.template["commands"] and k in self.template["commandHashes"]
                        and binding({"path": self.template["commands"][k], "sha256": self.template["commandHashes"][k]})
                        for k in ("ip", "nsenter")), "EXACT_BROKER_CANDIDATE_TEMPLATE_REQUIRED")
        self.lock = lambda: wait_common_lock(Path(self.template["lockFile"]), self.budget.deadline)
        self.gate = EpochConsumption(self.binding, PrivateJournal(self.root / "deployment.json"), self.lock)
        self.journal = PrivateJournal(self.root / "broker-state.json")
        self.bound = {k: read_binding(cfg[k + "Binding"]) for k in evidence_v2.DOCUMENTS}
        expected = evidence_v2.documents(self.role, self.bound)
        require({k: candidate[k] for k in ("networkBindings", "transport", "tableName")} == expected["transport"],
                "BROKER_TRANSPORT_TEMPLATE_DRIFT")
        self.check_epoch(head)

    def head(self):
        op, ctx = self.cfg["operation"], self.cfg["authorities"]
        require(read_binding(op["mandatesModule"]) == self.mandates_raw, "BROKER_MANDATES_MODULE_DRIFT")
        return authorization.head(self.mandates, op["anchorBinding"], op["mandateRoot"], op["opensslBinding"],
                                  op["authorizationRoot"], ctx["installationRef"], ctx["entityRef"], ctx["issuerRef"],
                                  self.clock, self.budget)

    def check_epoch(self, head):
        value = self.epochs.current(self.cfg["registryRoot"], self.cid)
        require(value is not None and value["epoch"] == self.args.epoch and value["bootId"] == self.epochs.boot_id()
                and value["authorizationSha256"] == head["sha256"] and value["state"] == MODES[self.args.mode],
                "BROKER_CURRENT_EPOCH_DRIFT")
        if self.args.mode != "authorize-create":
            require(value["runtimeRoot"] == self.args.runtime_root, "BROKER_EPOCH_RUNTIME_DRIFT")
        return value

    def stable(self):
        self.budget.check()
        require(private(self.path) == self.raw and read_binding(self.cfg["preparerTemplate"]) == self.template_raw,
                "BROKER_INPUT_CHANGED")
        for name, raw in self.bound.items():
            require(read_binding(self.cfg[name + "Binding"]) == raw, "BROKER_BOUND_DOCUMENT_DRIFT")
        verify_sources(self.cfg)
        head = self.head()
        require(operating_role(head, self.binding) == self.role, "BROKER_OPERATION_ROLE_DRIFT")
        self.check_epoch(head)

    def initial(self):
        return {"schema": JOURNAL_SCHEMA, **self.binding, "state": "STAGED", "runtimeRoot": None,
                "bundleHash": None, "driverHash": None}

    def stage_locked(self):
        paths = [self.root / "deployment.json", self.root / "broker-state.json"]
        present = [os.path.lexists(p) for p in paths]
        if not any(present):
            require(not any(os.path.lexists(self.root / p) for p in
                            ("evidence.json", "preparer.json", "driver.json", "admission.json")),
                    "DO_NOT_REPLAY_DEPLOYMENT_CREATE")
            evidence_v2.write_exclusive(paths[0], self.gate.initial())
            evidence_v2.write_exclusive(paths[1], self.initial())
        else:
            require(all(present), "DO_NOT_REPLAY_DEPLOYMENT_CREATE")
        require(self.gate.record() == self.gate.initial() and self.record() == self.initial(),
                "DO_NOT_REPLAY_DEPLOYMENT_CREATE")

    def record(self):
        value = self.journal.read()
        require(type(value) is dict and set(value) == {"schema", *self.binding, "state", "runtimeRoot", "bundleHash", "driverHash"}
                and value["schema"] == JOURNAL_SCHEMA and all(value[k] == v for k, v in self.binding.items())
                and value["state"] in ("STAGED", "CREATING", "CREATED", "PREPARING", "PROTECTED", "CLEANED"),
                "FOREIGN_BROKER_JOURNAL")
        if value["state"] == "STAGED":
            require(all(value[k] is None for k in ("runtimeRoot", "bundleHash", "driverHash")), "BROKER_PHASE_DRIFT")
        else:
            require(value["runtimeRoot"] == self.args.runtime_root and hashed(value["bundleHash"])
                    and (hashed(value["driverHash"]) if value["state"] in ("PROTECTED", "CLEANED")
                         else value["driverHash"] is None), "BROKER_PHASE_DRIFT")
        return value

    def publish(self, old, **changes):
        require(self.record() == old, "BROKER_JOURNAL_CHANGED_UNDER_LOCK")
        value = {**old, **changes}
        self.journal.write(old, value)
        require(self.record() == value, "BROKER_PUBLICATION_UNPROVEN")
        return value

    def commands(self):
        return {k: {"path": self.template["commands"][k], "sha256": self.template["commandHashes"][k]}
                for k in ("ip", "nsenter")}

    def observer(self):
        from tools.semantic_provider_node_observation import NodeObservation
        return NodeObservation({}, self.budget)

    def runtime(self, state):
        from tools.semantic_provider_deployment_authentication import decode
        from tools.semantic_provider_deployment_admission import application_hash
        from tools.semantic_provider_preexec_native import NativeBackend
        self.stable()
        raw = self.observer().run(self.template["candidate"]["runtimeBinding"],
                                  ["--root", self.args.runtime_root, "state", self.cid], 16384)
        actual = decode(raw, 16384)
        require(type(state) is dict and actual.get("id") == self.cid and actual.get("bundle") == self.args.bundle
                and actual.get("status") == "created" and type(actual.get("pid")) is int and actual["pid"] > 1
                and all(actual.get(k) == state.get(k) for k in ("id", "bundle", "status", "pid")),
                "BROKER_LIVE_CREATED_STATE_DRIFT")
        app = application_hash(decode(private(Path(self.args.bundle) / "config.json"), 131072))
        return app, NativeBackend.generation(None, actual["pid"])

    def cohort_ready(self, state):
        from tools.semantic_provider_peer_bindings import declarations, collect, PeerNotReady
        from tools.semantic_provider_preexec_native import NativeBackend
        app, live = self.runtime(state)
        old, created = self.record(), self.gate.record()
        require(old["state"] == created["state"] == "CREATED" and old["bundleHash"] == created["bundleHash"] == app
                and created["generation"] == live, "BROKER_COHORT_CREATED_STATE_REQUIRED")
        peers = declarations(self.template["candidate"]["transport"], self.cid)
        if not peers:
            self.stable()
            return
        require(type(peers) is list and 1 <= len(peers) <= 8, "BOUNDED_PEER_COHORT_REQUIRED")
        diagnostics = {p["containerId"]: {"containerId": p["containerId"], "lastReason": None, "attempts": 0,
            "runc": None, "networkBindings": [{k: n[k] for k in ("interface", "ipv4", "mac", "bridge")}
                                            for n in p["networkBindings"]]} for p in peers}
        run = self.observer().run

        def probe(peer):
            # Lists have a different JSON shape from the bounded object decoder.
            rows = json.loads(run(self.template["candidate"]["runtimeBinding"],
                                  ["--root", self.args.runtime_root, "list", "--format", "json"]))
            require(type(rows) is list and len(rows) <= 1024 and all(type(r) is dict for r in rows),
                    "BOUNDED_COHORT_RUNTIME_INVENTORY_REQUIRED")
            for cid, diagnostic in diagnostics.items():
                listed = [r for r in rows if r.get("id") == cid]
                diagnostic["runc"] = None
                if len(listed) == 1:
                    try:
                        diagnostic["runc"] = self.public_runtime_row(listed[0])
                    except authorization.OperationDenied:
                        # Diagnostic validation cannot alter the readiness probe.
                        diagnostic["snapshotError"] = "COHORT_RUNTIME_ROW_INVALID"
            matches = [r for r in rows if r.get("id") == peer["containerId"]]
            require(len(matches) <= 1, "COHORT_RUNTIME_IDENTITY_AMBIGUOUS")
            if not matches:
                raise PeerNotReady("PEER_NOT_LISTED")
            if matches[0].get("status") == "creating":
                raise PeerNotReady("PEER_CREATING")
            if matches[0].get("status") == "stopped" and matches[0].get("pid") == 0:
                sibling = self.epochs.current(self.cfg["registryRoot"], peer["containerId"])
                if (sibling is not None and sibling["bootId"] == self.epochs.boot_id()
                        and sibling["authorizationSha256"] == self.binding["authorizationSha256"]
                        and sibling["runtimeRoot"] == self.args.runtime_root and sibling["state"] == "CREATING"
                        and sibling["bundleHash"] == peer["applicationHash"] and sibling["driverHash"] is None):
                    raise PeerNotReady("PEER_STOPPED_SIBLING_CREATING")
            require(matches[0].get("status") in ("created", "running"), "COHORT_PEER_STATE_DENIED")
            try:
                return collect(peer, self.args.runtime_root, self.template["candidate"]["runtimeBinding"],
                               self.commands(), run, lambda p: private(Path(p)),
                               lambda pid: NativeBackend.generation(None, pid), self.budget)
            except ValueError as error:
                if str(error) in ("PEER_INTERFACES_NOT_READY", "PEER_ADDRESSES_NOT_READY", "PEER_INTERFACE_MISSING"):
                    raise PeerNotReady(str(error)) from None
                raise

        try:
            while True:
                self.budget.check()
                require(self.budget.remaining(18) >= 3, "COHORT_PEER_WAIT_TIMEOUT")
                try:
                    for peer in peers:
                        diagnostic = diagnostics[peer["containerId"]]
                        self.budget.check()
                        require(self.budget.remaining(18) >= 3, "COHORT_PEER_WAIT_TIMEOUT")
                        diagnostic["attempts"] += 1
                        try:
                            probe(peer)
                        except (PeerNotReady, ValueError, authorization.OperationDenied) as error:
                            diagnostic["lastReason"] = denial_code(error)
                            raise
                except PeerNotReady:
                    time.sleep(self.budget.remaining(0.1))
                    continue
                self.budget.check()
                break
        except (ValueError, authorization.OperationDenied):
            self.cohort = {"peers": list(diagnostics.values())}
            for diagnostic in diagnostics.values():
                self.peer_snapshot(diagnostic)
            raise
        require(self.runtime(state) == (app, live) and self.record() == old and self.gate.record() == created,
                "BROKER_COHORT_CHANGED_DURING_WAIT")
        self.stable()

    @staticmethod
    def public_runtime_row(row):
        require(row.get("status") in ("creating", "created", "running", "stopped", "paused")
                and type(row.get("pid")) is int and 0 <= row["pid"] < 2 ** 22, "COHORT_RUNTIME_ROW_INVALID")
        return {k: row[k] for k in ("status", "pid")}

    def peer_snapshot(self, diagnostic):
        """Read only, bounded, source-bound commands; never replace the original denial."""
        try:
            self.budget.check()
            row = diagnostic["runc"]
            require(row is not None and row["pid"] > 1, "COHORT_SNAPSHOT_PID_UNAVAILABLE")
            commands, run = self.commands(), self.observer().run
            # Verify ip too: nsenter executes this path rather than run(ip, ...).
            from tools.semantic_provider_deployment_producer import program
            program(commands["ip"], self.budget)
            children = json.loads(run(commands["nsenter"], ["--net=/proc/" + str(row["pid"]) + "/ns/net",
                                      commands["ip"]["path"], "-j", "addr", "show"], 131072))
            program(commands["ip"], self.budget)
            require(type(children) is list and len(children) <= 32, "COHORT_SNAPSHOT_INTERFACES_UNBOUNDED")
            snapshot = {"interfaces": [], "hosts": []}
            diagnostic["snapshot"] = snapshot
            for child in children:
                require(type(child) is dict, "COHORT_SNAPSHOT_INTERFACE_INVALID")
                if child.get("ifname") == "lo":
                    continue
                name = child.get("ifname")
                require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", name),
                        "COHORT_SNAPSHOT_INTERFACE_INVALID")
                indexes = {k: child.get(k) for k in ("ifindex", "link_index")}
                require(type(indexes["ifindex"]) is int and indexes["ifindex"] > 0
                        and (indexes["link_index"] is None or type(indexes["link_index"]) is int
                             and indexes["link_index"] > 0), "COHORT_SNAPSHOT_INDEX_INVALID")
                mac = child.get("address")
                require(mac is None or type(mac) is str and re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac),
                        "COHORT_SNAPSHOT_MAC_INVALID")
                addresses = child.get("addr_info", [])
                require(type(addresses) is list and len(addresses) <= 32 and all(type(a) is dict for a in addresses),
                        "COHORT_SNAPSHOT_ADDRESSES_UNBOUNDED")
                ipv4 = [str(ipaddress.IPv4Address(a["local"])) for a in addresses if a.get("family") == "inet"]
                snapshot["interfaces"].append({"ifname": name, **indexes, "address": mac, "ipv4": ipv4,
                    "ipv6Count": sum(a.get("family") == "inet6" for a in addresses)})
            indexes = sorted({c["link_index"] for c in snapshot["interfaces"] if c["link_index"] is not None})
            if indexes:
                hosts = json.loads(run(commands["ip"], ["-j", "link", "show"], 131072))
                require(type(hosts) is list and len(hosts) <= 1024 and all(type(h) is dict for h in hosts),
                        "COHORT_SNAPSHOT_HOSTS_UNBOUNDED")
                for index in indexes:
                    found = [h for h in hosts if h.get("ifindex") == index]
                    require(len(found) == 1, "COHORT_SNAPSHOT_HOST_MISSING")
                    host = found[0]
                    require(all(host.get(k) is None or type(host[k]) is str
                                and re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", host[k]) for k in ("ifname", "master")),
                            "COHORT_SNAPSHOT_HOST_INVALID")
                    snapshot["hosts"].append({"link_index": index, **{k: host.get(k) for k in ("ifname", "master")}})
        except Exception as error:
            diagnostic["snapshotError"] = denial_code(error)
        finally:
            if len(authorization.canonical(diagnostic.get("snapshot"))) > 4096:
                diagnostic.pop("snapshot", None)
                diagnostic["snapshotError"] = "COHORT_SNAPSHOT_UNBOUNDED"

    def record_denial(self, error):
        """Exclusive best-effort receipt only after establishing a private epoch."""
        try:
            root = self.denial_root
            self.epochs.directory(root)
            for parent in root.parents:
                info = parent.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                        "PRIVATE_ANCESTOR_REQUIRED")
            value = {"schema": DENIAL_SCHEMA, "containerId": self.cid, "epoch": self.args.epoch,
                     "mode": self.args.mode, "reason": denial_code(error), "at": int(self.clock()),
                     "cohort": self.cohort}
            validate_denial(authorization.canonical(value), self.cid, self.args.epoch, self.args.mode)
            evidence_v2.write_exclusive(root / ("broker-denial-" + self.args.mode + ".json"), value)
        except Exception:
            pass

    def prepare(self, state):
        with self.lock():
            app, live = self.runtime(state)
            old, created = self.record(), self.gate.record()
            require(old["state"] == created["state"] == "CREATED", "DO_NOT_REPLAY_BROKER_PREPARATION")
            require(old["bundleHash"] == created["bundleHash"] == app and created["generation"] == live,
                    "BROKER_CREATED_GENERATION_DRIFT")
            pending = self.publish(old, state="PREPARING")
            value = evidence_v2.observe(container_id=self.cid, epoch=self.args.epoch,
                authorization_sha256=self.binding["authorizationSha256"], authorization_role=self.role,
                bound_documents=self.bound, bundle=self.args.bundle, runtime_root=self.args.runtime_root,
                registry_root=self.cfg["registryRoot"],
                runtime_root_parent=self.cfg["runtimeRootParent"], runtime_binding=self.template["candidate"]["runtimeBinding"],
                commands=self.commands(), rootfs_limits=self.cfg["rootfsLimits"],
                creation_frame_observer_binding=self.cfg["creationFrameObserverBinding"], budget=self.budget, clock=self.clock)
            require(value["generation"] == live and value["bundleHash"] == app, "BROKER_CREATED_GENERATION_DRIFT")
            evidence_hash = evidence_v2.write(self.root / "evidence.json", value)
            self.stable()
            self.gate.ready_locked(value)
            request = self.preparer_request(evidence_hash)
            evidence_v2.write_exclusive(self.root / "preparer.json", request)
        result = self.preparer.prepare(copy.deepcopy(request), copy.deepcopy(state))
        with self.lock():
            self.stable()
            require(self.record() == pending and self.runtime(state) == (app, live), "BROKER_PREPARATION_DRIFT")
            require(type(result) is dict and set(result) == {"binding", "evidenceHash", "driverHash"}
                    and result["binding"] == self.binding and result["evidenceHash"] == evidence_hash
                    and hashed(result["driverHash"]) and authorization.sha(private(self.root / "driver.json")) == result["driverHash"]
                    and authorization.sha(private(self.root / "evidence.json")) == evidence_hash
                    and private(self.root / "preparer.json") == authorization.canonical(request), "BROKER_PREPARED_DRIVER_DRIFT")
            self.gate.seal_driver_locked(result["driverHash"])
            self.publish(pending, state="PROTECTED", driverHash=result["driverHash"])

    def preparer_request(self, evidence_hash):
        return {"epochRoot": str(self.root), "epoch": self.args.epoch, "binding": copy.deepcopy(self.binding),
                "bundle": self.args.bundle, "runtimeRoot": self.args.runtime_root,
                "template": copy.deepcopy(self.template),
                "configurationBinding": {"path": str(self.path), "sha256": authorization.sha(self.raw)},
                "evidenceBinding": {"path": str(self.root / "evidence.json"), "sha256": evidence_hash}}

    def operate(self, state):
        self.stable()
        mode = self.args.mode
        if mode == "authorize-create":
            require(type(state) is dict and set(state) == {"id", "bundleHash"} and state["id"] == self.cid
                    and hashed(state["bundleHash"]), "EXACT_BROKER_CREATE_REQUEST_REQUIRED")
            with self.lock():
                self.stable()
                self.stage_locked()
            self.gate.authorize_create(self.head())
            with self.lock():
                self.stable()
                old = self.record()
                require(old["state"] == "STAGED", "DO_NOT_REPLAY_BROKER_CREATE")
                self.publish(old, state="CREATING", runtimeRoot=self.args.runtime_root, bundleHash=state["bundleHash"])
        elif mode == "record-created":
            app, live = self.runtime(state)
            with self.lock():
                old = self.record()
                require(old["state"] == "CREATING" and old["bundleHash"] == app, "BROKER_CREATION_BINDING_DRIFT")
            self.gate.created(app, live)
            with self.lock():
                self.stable()
                self.publish(old, state="CREATED")
        elif mode == "cohort-ready":
            self.cohort_ready(state)
        elif mode == "prepare":
            self.prepare(state)
        elif mode == "cleanup":
            with self.lock():
                old = self.record()
                require(old["state"] == "PROTECTED"
                        and authorization.sha(private(self.root / "driver.json")) == old["driverHash"],
                        "OWNED_BROKER_CLEANUP_REQUIRED")
                request = authorization.decode(private(self.root / "preparer.json"))
                consumed = self.gate.record()
                require(request == self.preparer_request(consumed["evidenceHash"])
                        and consumed["driverHash"] == old["driverHash"]
                        and authorization.sha(private(self.root / "evidence.json")) == consumed["evidenceHash"],
                        "BROKER_CLEANUP_REQUEST_DRIFT")
            self.preparer.cleanup(copy.deepcopy(request))
            with self.lock():
                self.stable()
                self.publish(old, state="CLEANED")


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        require(False, "EXACT_BROKER_ARGUMENTS_REQUIRED")


def main(argv=None):
    broker = None
    parser = Arguments()
    for key in ("configuration", "container-id", "bundle", "runtime-root", "mode"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--epoch", required=True, type=int)
    try:
        args = parser.parse_args(argv)
        cfg, raw = load(args.configuration)
        broker = Broker.__new__(Broker)
        broker.__init__(cfg, raw, args.configuration, args)
        from tools.semantic_provider_deployment_authentication import decode
        state = {} if args.mode == "cleanup" else decode(sys.stdin.buffer.read(16385), 16384)
        broker.operate(state)
        print("SEMANTIC_DEPLOYMENT_BROKER=PASS MODE=" + args.mode)
        return 0
    except Exception as error:
        if broker is not None:
            broker.record_denial(error)
        print("SEMANTIC_DEPLOYMENT_BROKER=DENIED " + denial_code(error), file=sys.stderr)
        return 1
