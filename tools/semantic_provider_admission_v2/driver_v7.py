"""Closed unsigned epoch grant and versioned preexec driver.

Native protection remains owned by the source-pinned v1 Preexec/NativeBackend.
Only admission and consumption are replaced here.
"""
import copy
import os
from pathlib import Path, PurePosixPath
import sys
import time
import types

from tools.semantic_provider_operation import authorization
from . import broker_v2 as broker, evidence_v2
from .consumption_v2 import EpochConsumption, hashed, operating_role, require
from .reauthorization_v2 import sealed_authorizer_v2

SCHEMA = "ouf.semantic-preexec-driver.v7"
BASE = {"schema", "sourceRoot", "sourceHashes", "profile", "kernel", "dns", "coordinationBinding",
        "coordinationJournal", "preexecJournal", "lockFile", "commands", "budgetSeconds", "runtimeBinding",
        "operationBinding", "evidenceBinding", "consumptionJournal", "operation", "creationFrameObserverBinding"}
OPERATION = {"authorizationRoot", "anchorBinding", "mandateRoot", "opensslBinding", "mandatesModule",
             "installationRef", "entityRef", "issuerRef"}
PROFILE = {"schema", "transactionId", "containerId", "bundlePath", "bundleHash", "namespacePath",
           "namespaceInode", "namespaceLinks", "policy", "expectedFootprint", "applicationStartAuthorized",
           "infrastructureAuthorityComplete", "namespaceOrigin"}


def correlation(binding):
    return authorization.sha(authorization.canonical({k: binding[k] for k in
                             ("containerId", "epoch", "authorizationSha256")}))


def validate(raw):
    value = authorization.decode(raw)
    require(set(value) in (BASE, BASE | {"peerBinding"}) and value["schema"] == SCHEMA,
            "EXACT_DRIVER_CONFIGURATION_REQUIRED")
    sealed = value["operationBinding"]
    require(type(sealed) is dict and set(sealed) == {"authorizationSha256", "epoch", "containerId", "configurationHash"}
            and all(hashed(sealed[k]) for k in ("authorizationSha256", "containerId", "configurationHash"))
            and type(sealed["epoch"]) is int and 1 <= sealed["epoch"] <= 10 ** 9,
            "EXACT_DRIVER_OPERATION_BINDING_REQUIRED")
    op = value["operation"]
    require(type(op) is dict and set(op) == OPERATION
            and all(authorization.identity(op[k]) for k in ("installationRef", "entityRef", "issuerRef"))
            and all(broker.absolute(op[k]) for k in ("authorizationRoot", "mandateRoot"))
            and broker.binding(op["anchorBinding"]) and broker.binding(op["mandatesModule"])
            and broker.binding(op["opensslBinding"], ("version",))
            and type(op["opensslBinding"]["version"]) is str,
            "EXACT_DRIVER_OPERATION_REQUIRED")
    require(broker.absolute(value["sourceRoot"]) and type(value["sourceHashes"]) is dict
            and set(value["sourceHashes"]) == broker.SOURCES
            and all(hashed(h) for h in value["sourceHashes"].values()), "EXACT_DRIVER_SOURCE_SET_REQUIRED")
    require(all(broker.absolute(value[k]) for k in ("coordinationJournal", "preexecJournal", "lockFile", "consumptionJournal"))
            and broker.binding(value["evidenceBinding"]), "EXACT_DRIVER_PATHS_REQUIRED")
    root = PurePosixPath(value["consumptionJournal"]).parent
    require(root.name == str(sealed["epoch"]) and root.parent.name == "epochs"
            and root.parent.parent.name == sealed["containerId"]
            and value["consumptionJournal"] == str(root / "deployment.json")
            and value["preexecJournal"] == str(root / "preexec.json")
            and value["evidenceBinding"]["path"] == str(root / "evidence.json"), "DRIVER_EPOCH_PATH_DRIFT")
    profile = value["profile"]
    require(type(profile) is dict and set(profile) == PROFILE and profile["schema"] == "ouf.semantic-preexec-profile.v2"
            and profile["containerId"] == sealed["containerId"] and profile["transactionId"] == correlation(sealed)
            and profile["bundlePath"] == str(root / "bundle")
            and all(hashed(profile[k]) for k in ("bundleHash", "expectedFootprint"))
            and broker.absolute(profile["namespacePath"]) and type(profile["namespaceInode"]) is int
            and profile["namespaceInode"] > 0 and profile["namespaceOrigin"] in ("PREPARED", "OCI_CREATED")
            and profile["applicationStartAuthorized"] is True and profile["infrastructureAuthorityComplete"] is True
            and type(profile["namespaceLinks"]) is list and type(profile["policy"]) is dict,
            "EXACT_DRIVER_PROFILE_REQUIRED")
    runtime = value["runtimeBinding"]
    require(broker.binding(runtime, ("root",)) and broker.absolute(runtime["root"]), "EXACT_DRIVER_RUNTIME_REQUIRED")
    require(type(value["commands"]) is dict and set(value["commands"]) == {"nft", "ip", "nsenter"}
            and all(broker.absolute(p) for p in value["commands"].values())
            and type(value["budgetSeconds"]) is int and 1 <= value["budgetSeconds"] <= 5,
            "EXACT_DRIVER_COMMANDS_REQUIRED")
    frame = value["creationFrameObserverBinding"]
    require(type(frame) is dict and set(frame) == {"python", "source", "configuration"}
            and all(broker.binding(b) for b in frame.values()), "EXACT_DRIVER_FRAME_REQUIRED")
    coordination = value["coordinationBinding"]
    require(type(coordination) is dict and set(coordination) == {"transactionId", "configurationHash", "leaseStructureHash"}
            and all(hashed(v) for v in coordination.values()), "EXACT_DRIVER_COORDINATION_REQUIRED")
    require(type(value["kernel"]) is dict and type(value["dns"]) is dict, "EXACT_DRIVER_LEASE_REQUIRED")
    if "peerBinding" in value:
        peer = value["peerBinding"]
        require(type(peer) is dict and set(peer) == {"declaredPolicy", "observations", "commandBindings"}
                and type(peer["declaredPolicy"]) is dict
                and set(peer["declaredPolicy"]) == {"networkBindings", "transport", "tableName"}
                and type(peer["observations"]) is dict and bool(peer["observations"])
                and type(peer["commandBindings"]) is dict and set(peer["commandBindings"]) == {"ip", "nsenter"}
                and all(broker.binding(b) and b["path"] == value["commands"][k]
                        for k, b in peer["commandBindings"].items()), "EXACT_DRIVER_PEERS_REQUIRED")
    return value


def load(path):
    """Execute v1 modules only after the same custody/hash checks as broker.load."""
    raw = broker.private(path)
    value = validate(raw)
    # Same ordered source package as broker.load; the grant is its own
    # configuration and carries no path to a mutable broker configuration.
    root = Path(value["sourceRoot"])
    verified = broker.verify_sources(value)
    import tools as package
    for name in broker.MODULES:
        full = "tools." + name
        module = types.ModuleType(full)
        module.__package__, module.__file__ = "tools", str(root / "tools" / (name + ".py"))
        sys.modules[full] = module
        setattr(package, name, module)
        exec(compile(verified["tools/" + name + ".py"], module.__file__, "exec"), module.__dict__)
    require(broker.private(path) == raw, "DRIVER_CONFIGURATION_DRIFT")
    return value, raw


class Operation:
    def __init__(self, value, budget, clock=time.time):
        self.value, self.budget, self.clock = copy.deepcopy(value), budget, clock
        op = self.value["operation"]
        self.raw = broker.read_binding(op["mandatesModule"])
        self.mandates = types.ModuleType("driver_v7_verified_mandates")
        exec(compile(self.raw, "<verified-mandates>", "exec"), self.mandates.__dict__)
        self.binding = {**self.value["operationBinding"], **{k: op[k] for k in ("installationRef", "entityRef")}}

    def head(self):
        op = self.value["operation"]
        require(broker.read_binding(op["mandatesModule"]) == self.raw, "DRIVER_MANDATES_MODULE_DRIFT")
        return authorization.head(self.mandates, op["anchorBinding"], op["mandateRoot"], op["opensslBinding"],
                                  op["authorizationRoot"], op["installationRef"], op["entityRef"], op["issuerRef"],
                                  self.clock, self.budget)

    def authorizer(self):
        value = self.value
        sealed = sealed_authorizer_v2(head_reader=self.head, binding=self.binding,
            evidence_binding=value["evidenceBinding"], creation_frame_observer_binding=value["creationFrameObserverBinding"],
            bundle=value["profile"]["bundlePath"], budget=self.budget)

        def authorize():
            sealed()
            role = operating_role(self.head(), self.binding)
            raw = broker.read_binding(value["evidenceBinding"])
            evidence = evidence_v2.validate(authorization.decode(raw))
            require(evidence["bundleHash"] == value["profile"]["bundleHash"]
                    and evidence["transportSha256"] == role["transportSha256"]
                    and role["framePolicySha256"] == value["creationFrameObserverBinding"]["configuration"]["sha256"]
                    and role["tableName"] == value["profile"]["policy"]["tableName"], "DRIVER_OPERATION_SCOPE_DRIFT")
            from tools.semantic_provider_node_observation import NodeObservation
            run = NodeObservation({}, self.budget).run
            if "peerBinding" in value:
                verify_peers(value, role["transportSha256"], self.budget, run)
            return True
        return authorize


def verify_peers(value, transport_hash, budget, run):
    """v6 recollection, replacing its authorityScope read with the durable role."""
    from tools.semantic_provider_peer_bindings import declarations, collect, resolve, digest
    from tools.semantic_provider_preexec_native import NativeBackend
    peer = value["peerBinding"]
    policy = peer["declaredPolicy"]
    require(digest(policy) == transport_hash, "PEER_DRIVER_TRANSPORT_SCOPE_DRIFT")
    peers = declarations(policy["transport"], value["profile"]["containerId"])
    require(bool(peers) and set(peer["observations"]) == {p["containerId"] for p in peers}, "EXACT_PEER_COHORT_REQUIRED")
    runtime = {k: value["runtimeBinding"][k] for k in ("path", "sha256")}
    observed = {p["containerId"]: collect(p, value["runtimeBinding"]["root"], runtime, peer["commandBindings"],
        run, lambda path: broker.private(path), lambda pid: NativeBackend.generation(None, pid), budget) for p in peers}
    require(observed == peer["observations"], "PEER_GENERATION_OR_LINK_CHANGED")
    require(policy["tableName"] == value["profile"]["policy"]["tableName"]
            and resolve(policy["transport"], peers, observed, value["profile"]["containerId"])
            == value["profile"]["policy"]["flows"], "PEER_KERNEL_PROFILE_DRIFT")
    budget.check()


def coordinator(value):
    from tools.semantic_provider_lease_coordination import Coordinator, PrivateJournal, hold_common_lock
    from tools.semantic_provider_lease_nft import NftBackend
    from tools.semantic_provider_lease_owner import LeaseOwner
    lease = NftBackend([value["commands"]["nft"]], value["kernel"],
                       value["coordinationBinding"]["leaseStructureHash"], value["budgetSeconds"])
    journal = PrivateJournal(Path(value["coordinationJournal"]))
    return Coordinator(LeaseOwner(value["kernel"], value["dns"], lease), value["coordinationBinding"],
                       lambda: hold_common_lock(Path(value["lockFile"])), journal.read, journal.write)


def components(value):
    from tools.semantic_provider_lease_coordination import PrivateJournal
    from tools.semantic_provider_preexec import Preexec
    from tools.semantic_provider_preexec_native import NativeBackend
    coord = coordinator(value)
    backend = NativeBackend(value["profile"], value["commands"], value["budgetSeconds"])
    return Preexec(value["profile"], backend, coord, PrivateJournal(Path(value["preexecJournal"]))), backend


def operate(value, raw, configuration, mode, state=None):
    broker.verify_sources(value)
    from tools.semantic_provider_deployment_authentication import VerificationBudget
    from tools.semantic_provider_lease_coordination import PrivateJournal
    gate, backend = components(value)
    require(broker.private(configuration) == raw, "DRIVER_CONFIGURATION_DRIFT")
    # Rollback is deliberately independent of operation authority/revocation.
    if mode == "rollback":
        return gate.operate(mode)
    operation = Operation(value, VerificationBudget(value["budgetSeconds"], deadline=backend.deadline))
    authorize = operation.authorizer()
    if mode == "start":
        receipt = EpochConsumption(operation.binding, PrivateJournal(Path(value["consumptionJournal"])), gate.coord.hold_lock)
        driver_hash = authorization.sha(raw)
        def consume(generation, starter):
            require(broker.private(configuration) == raw, "DRIVER_CONFIGURATION_DRIFT")
            return receipt.consume_locked(value["evidenceBinding"]["sha256"], driver_hash, generation, authorize, starter)
        return gate.before_process(backend.runtime(value["runtimeBinding"], "state"),
            lambda: backend.runtime(value["runtimeBinding"], "start"), authorize, consume)
    if mode == "hook":
        return gate.before_process(state, authorizer=authorize)
    return gate.operate(mode, authorize)


def main(argv=None):
    parser = broker.Arguments()
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--mode", required=True, choices=("plan", "apply", "verify", "reconcile", "hook", "start", "rollback"))
    try:
        args = parser.parse_args(argv)
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, "ROOT_ISOLATED_NO_BYTECODE_REQUIRED")
        value, raw = load(args.configuration)
        state = authorization.decode(sys.stdin.buffer.read(16385)) if args.mode == "hook" else None
        require(args.mode != "hook" or len(authorization.canonical(state)) <= 16384, "OCI_STATE_UNBOUNDED")
        result = operate(value, raw, args.configuration, args.mode, state)
        print(authorization.canonical({"result": result}).decode())
        return 0
    except Exception:
        print("SEMANTIC_PREEXEC=DENIED", file=sys.stderr)
        return 1
