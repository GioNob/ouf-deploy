"""Source-pinned epoch broker. Native IO is Linux root-only; policy is portable."""
import argparse
import copy
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
from typing import Protocol

from tools.semantic_provider_operation import authorization
from .consumption_v2 import EpochConsumption, hashed, operating_role, require
from . import evidence_v2

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
SOURCES = {"tools/" + name + ".py" for name in MODULES}
MODES = {"authorize-create": "OPENING", "record-created": "CREATING", "cohort-ready": "CREATED",
         "prepare": "PREPARING", "cleanup": "DELETING"}


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
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_SOURCE_ROOT_REQUIRED")
    verified = {p: read_binding({"path": str(root / p), "sha256": cfg["sourceHashes"][p]}) for p in SOURCES}
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


class Broker:
    def __init__(self, cfg, raw, configuration_path, args, preparer=None, clock=time.time):
        from tools.semantic_provider_deployment_authentication import VerificationBudget, decode
        from tools.semantic_provider_lease_coordination import PrivateJournal, hold_common_lock
        require(validate(raw) == cfg, "BROKER_CONFIGURATION_DRIFT")
        self.cfg, self.raw, self.path, self.args, self.clock = cfg, raw, configuration_path, args, clock
        self.budget = VerificationBudget(18)
        self.preparer = preparer if preparer is not None else UnavailablePreparer()
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
        self.lock = lambda: hold_common_lock(Path(self.template["lockFile"]))
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
        for path, expected in self.cfg["sourceHashes"].items():
            require(authorization.sha(private(Path(self.cfg["sourceRoot"]) / path)) == expected,
                    "BROKER_SOURCE_PACKAGE_DRIFT")
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
        from tools.semantic_provider_peer_bindings import declarations, collect, await_peers, PeerNotReady
        from tools.semantic_provider_preexec_native import NativeBackend
        app, live = self.runtime(state)
        old, created = self.record(), self.gate.record()
        require(old["state"] == created["state"] == "CREATED" and old["bundleHash"] == created["bundleHash"] == app
                and created["generation"] == live, "BROKER_COHORT_CREATED_STATE_REQUIRED")
        peers = declarations(self.template["candidate"]["transport"], self.cid)
        if not peers:
            self.stable()
            return
        run = self.observer().run

        def probe(peer):
            # Lists have a different JSON shape from the bounded object decoder.
            import json
            rows = json.loads(run(self.template["candidate"]["runtimeBinding"],
                                  ["--root", self.args.runtime_root, "list", "--format", "json"]))
            require(type(rows) is list and len(rows) <= 1024, "BOUNDED_COHORT_RUNTIME_INVENTORY_REQUIRED")
            matches = [r for r in rows if r.get("id") == peer["containerId"]]
            require(len(matches) <= 1, "COHORT_RUNTIME_IDENTITY_AMBIGUOUS")
            if not matches or matches[0].get("status") == "creating":
                raise PeerNotReady()
            if matches[0].get("status") == "stopped" and matches[0].get("pid") == 0:
                sibling = self.epochs.current(self.cfg["registryRoot"], peer["containerId"])
                if (sibling is not None and sibling["bootId"] == self.epochs.boot_id()
                        and sibling["authorizationSha256"] == self.binding["authorizationSha256"]
                        and sibling["runtimeRoot"] == self.args.runtime_root and sibling["state"] == "CREATING"
                        and sibling["bundleHash"] == peer["applicationHash"] and sibling["driverHash"] is None):
                    raise PeerNotReady()
            require(matches[0].get("status") in ("created", "running"), "COHORT_PEER_STATE_DENIED")
            try:
                return collect(peer, self.args.runtime_root, self.template["candidate"]["runtimeBinding"],
                               self.commands(), run, lambda p: private(Path(p)),
                               lambda pid: NativeBackend.generation(None, pid), self.budget)
            except ValueError as error:
                if str(error) in ("PEER_INTERFACES_NOT_READY", "PEER_ADDRESSES_NOT_READY", "PEER_INTERFACE_MISSING"):
                    raise PeerNotReady() from None
                raise

        await_peers(peers, probe, self.budget)
        require(self.runtime(state) == (app, live) and self.record() == old and self.gate.record() == created,
                "BROKER_COHORT_CHANGED_DURING_WAIT")
        self.stable()

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
    parser = Arguments()
    for key in ("configuration", "container-id", "bundle", "runtime-root", "mode"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--epoch", required=True, type=int)
    try:
        args = parser.parse_args(argv)
        cfg, raw = load(args.configuration)
        from tools.semantic_provider_deployment_authentication import decode
        state = {} if args.mode == "cleanup" else decode(sys.stdin.buffer.read(16385), 16384)
        Broker(cfg, raw, args.configuration, args).operate(state)
        print("SEMANTIC_DEPLOYMENT_BROKER=PASS MODE=" + args.mode)
        return 0
    except Exception:
        print("SEMANTIC_DEPLOYMENT_BROKER=DENIED", file=sys.stderr)
        return 1
