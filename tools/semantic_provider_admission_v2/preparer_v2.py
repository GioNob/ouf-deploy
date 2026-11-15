"""Versioned v1 native preparation, with durable operation/epoch admission only."""
import copy
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

from tools.semantic_provider_operation import authorization
from . import broker_v2 as broker, driver_v7 as driver, evidence_v2
from .consumption_v2 import EpochConsumption, operating_role, require

class Worker:
    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.raw = broker.private(path)
        request = authorization.decode(self.raw)
        require(set(request) == {"epochRoot", "epoch", "binding", "bundle", "runtimeRoot", "template",
                                "configurationBinding", "evidenceBinding"}, "EXACT_PREPARER_REQUEST_REQUIRED")
        self.request = request
        require(broker.binding(request["configurationBinding"]), "EXACT_PREPARER_CONFIGURATION_BINDING_REQUIRED")
        self.cfg, raw = broker.load(request["configurationBinding"]["path"])
        require(authorization.sha(raw) == request["configurationBinding"]["sha256"], "PREPARER_CONFIGURATION_DRIFT")
        cfg = self.cfg
        self.entry = Path(cfg["sourceRoot"]) / broker.ENTRYPOINTS[1]
        self.hook = Path(cfg["sourceRoot"]) / broker.ENTRYPOINTS[2]
        self.root = Path(cfg["registryRoot"]) / cfg["containerId"] / "epochs" / str(request["epoch"])
        expected_binding = {**{k: cfg["authorities"][k] for k in ("installationRef", "entityRef")},
                            "containerId": cfg["containerId"], "epoch": request["epoch"],
                            "configurationHash": authorization.sha(raw),
                            "authorizationSha256": request["binding"].get("authorizationSha256")}
        self.template_raw = broker.read_binding(cfg["preparerTemplate"])
        self.template = authorization.decode(self.template_raw)
        require(request["binding"] == expected_binding and type(request["epoch"]) is int
                and 1 <= request["epoch"] <= 10 ** 9 and request["epochRoot"] == str(self.root)
                and request["bundle"] == str(self.root / "bundle") and self.path == self.root / "preparer.json"
                and request["template"] == self.template and broker.binding(request["evidenceBinding"])
                and request["evidenceBinding"]["path"] == str(self.root / "evidence.json")
                and broker.absolute(request["runtimeRoot"])
                and Path(request["runtimeRoot"]).is_relative_to(Path(cfg["runtimeRootParent"]))
                and request["runtimeRoot"] != cfg["runtimeRootParent"], "PREPARER_EPOCH_REQUEST_DRIFT")
        broker.epoch_module().directory(self.root)
        from tools.semantic_provider_lease_coordination import PrivateJournal
        from .locking import wait_common_lock
        from tools.semantic_provider_deployment_authentication import VerificationBudget
        from tools.semantic_provider_deployment_producer import program
        t = self.template
        require(set(t) == {"schema", "pythonPath", "pythonHash", "commands", "commandHashes", "candidate", "kernel", "dns",
                          "coordinationBinding", "coordinationJournal", "lockFile", "budgetSeconds", "hostNetworkNamespace"}
                and t["schema"] == "ouf.semantic-admission-preparer-template.v1"
                and set(t["commands"]) == set(t["commandHashes"]) == {"nft", "ip", "nsenter", "unshare", "mount", "umount"}
                and type(t["budgetSeconds"]) is int and 1 <= t["budgetSeconds"] <= 5
                and type(t["hostNetworkNamespace"]) is int and t["hostNetworkNamespace"] > 0,
                "EXACT_NATIVE_PREPARER_TEMPLATE_REQUIRED")
        self.budget = VerificationBudget(18)
        self.python = {"path": t["pythonPath"], "sha256": t["pythonHash"]}
        program(self.python, self.budget)
        for key in t["commands"]:
            program(self.command(key), self.budget)
        self.lock = lambda: wait_common_lock(Path(t["lockFile"]), self.budget.deadline)
        self.consumption = EpochConsumption(request["binding"], PrivateJournal(self.root / "deployment.json"), self.lock)
        self.journal = PrivateJournal(self.root / "admission.json")
        self.clock = clock

    def command(self, name):
        return {"path": self.template["commands"][name], "sha256": self.template["commandHashes"][name]}

    def stable(self):
        self.budget.check()
        broker.verify_sources(self.cfg)
        require(broker.private(self.path) == self.raw
                and broker.read_binding(self.request["configurationBinding"]) == authorization.canonical(self.cfg)
                and broker.read_binding(self.cfg["preparerTemplate"]) == self.template_raw, "PREPARER_INPUT_DRIFT")

    def invoke(self, argv, raw=None, limit=131072):
        with tempfile.TemporaryFile() as out:
            result = subprocess.run(argv, input=raw, stdout=out, stderr=subprocess.DEVNULL,
                timeout=self.budget.remaining(18), env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            out.seek(0)
            content = out.read(limit + 1)
        require(result.returncode == 0 and len(content) <= limit, "SEALED_WORKER_OR_DRIVER_DENIED")
        return content

    def run(self, name, argv, raw=None):
        from tools.semantic_provider_deployment_producer import program
        item = self.command(name)
        path = program(item, self.budget)
        result = self.invoke([path, *argv], raw.encode() if raw is not None else None, 2000000)
        program(item, self.budget)
        return result.decode()

    def invoke_result(self, argv, raw):
        content = self.invoke(argv, raw)
        require(content.endswith(b"\n"), "SEALED_WORKER_RESULT_DRIFT")
        # The worker protocol is one canonical object followed by exactly LF.
        return authorization.decode(content[:-1])

    def python_argv(self):
        from tools.semantic_provider_deployment_producer import program
        return [program(self.python, self.budget), "-I", "-B"]

    def initial(self):
        return {"schema": "ouf.semantic-admission-journal.v1", "transactionId": driver.correlation(self.request["binding"]),
                "configurationHash": authorization.sha(self.raw), "state": "STAGED", "driverHash": None,
                "namespaceOwned": False, "namespaceInode": None, "containerGeneration": None}

    def record(self):
        value, initial = self.journal.read(), self.initial()
        require(set(value) == set(initial) and all(value[k] == initial[k] for k in ("schema", "transactionId", "configurationHash"))
                and value["state"] in ("STAGED", "PREPARING", "PREPARED", "PROTECTED", "CLEANED"),
                "ADMISSION_JOURNAL_BINDING_DRIFT")
        return value

    def publish(self, old, **changes):
        with self.lock():
            self.stable()
            require(self.record() == old, "ADMISSION_JOURNAL_CHANGED")
            value = {**old, **changes}
            self.journal.write(old, value)
            return value

    def receipt_ready(self, evidence, generation=None):
        receipt = self.consumption.record()
        require(receipt["state"] == "READY" and receipt["driverHash"] is None
                and receipt["evidenceHash"] == self.request["evidenceBinding"]["sha256"]
                and receipt["bundleHash"] == evidence["applicationHash"]
                and receipt["generation"] == evidence["generation"]
                and (generation is None or generation == receipt["generation"]), "CONSUMPTION_PREPARATION_CUSTODY_DRIFT")

    def prepare(self, state):
        from tools.semantic_provider_deployment_admission import application_hash, live_profile, mirrors
        from tools.semantic_provider_preexec import digest
        from tools.semantic_provider_preexec_native import NativeBackend
        from tools.semantic_provider_peer_bindings import declarations, collect, resolve
        from tools.semantic_provider_node_observation import NodeObservation
        self.stable()
        t, r = self.template, self.request
        require(os.stat("/proc/self/ns/net").st_ino == t["hostNetworkNamespace"], "HOST_NAMESPACE_CUSTODY_DRIFT")
        evidence = evidence_v2.validate(authorization.decode(broker.read_binding(r["evidenceBinding"])))
        candidate = copy.deepcopy(t["candidate"])
        require(set(candidate) == {"containerId", "transactionId", "networkBindings", "transport", "tableName", "runtimeBinding"}
                and candidate["containerId"] == r["binding"]["containerId"]
                and candidate["tableName"] != t["kernel"]["tableName"], "EXACT_CANDIDATE_INTENT_REQUIRED")
        candidate.update(transactionId=driver.correlation(r["binding"]), bundlePath=r["bundle"],
                         applicationHash=evidence["applicationHash"],
                         runtimeBinding={**candidate["runtimeBinding"], "root": r["runtimeRoot"]})
        provisional = {"operation": {**self.cfg["operation"], **self.cfg["authorities"]},
                       "operationBinding": {k: r["binding"][k] for k in
                           ("authorizationSha256", "epoch", "containerId", "configurationHash")},
                       "evidenceBinding": r["evidenceBinding"],
                       "creationFrameObserverBinding": self.cfg["creationFrameObserverBinding"],
                       "profile": {"bundlePath": r["bundle"]}}
        operation = driver.Operation(provisional, self.budget, self.clock)
        from .reauthorization_v2 import sealed_authorizer_v2
        authorize = sealed_authorizer_v2(head_reader=operation.head, binding=r["binding"], evidence_binding=r["evidenceBinding"],
            creation_frame_observer_binding=self.cfg["creationFrameObserverBinding"], bundle=r["bundle"], budget=self.budget)
        coordination = driver.coordinator({**t, "commands": {k: t["commands"][k] for k in ("nft", "ip", "nsenter")}})
        with self.lock():
            lease = coordination.journal()
            require(lease["state"] == "QUIESCED" and not lease["leaseAuthorized"] and not any(coordination.sets()),
                    "EXISTING_LEASE_QUIESCENCE_REQUIRED")
            authorize()
            role = operating_role(operation.head(), r["binding"])
            docs = {k: broker.read_binding(self.cfg[k + "Binding"]) for k in evidence_v2.DOCUMENTS}
            evidence_v2.verify(evidence, role, docs)
            require({k: candidate[k] for k in ("networkBindings", "transport", "tableName")}
                    == evidence_v2.documents(role, docs)["transport"], "PREPARER_TRANSPORT_DRIFT")
            self.receipt_ready(evidence)
            require(not any(os.path.lexists(self.root / p) for p in ("admission.json", "preexec.json", "driver.json")),
                    "EXPLICIT_RECOVERY_NO_REPLAY")
            evidence_v2.write_exclusive(self.root / "admission.json", self.initial())
        record = self.record()
        require(type(state) is dict and state.get("id") == candidate["containerId"] and state.get("bundle") == r["bundle"]
                and state.get("status") == "created" and type(state.get("pid")) is int and state["pid"] > 1,
                "CREATED_OCI_STATE_REQUIRED")
        bundle = authorization.decode(broker.private(Path(r["bundle"]) / "config.json"))
        require(application_hash(bundle) == candidate["applicationHash"], "APPLICATION_ACCEPTANCE_DRIFT")
        record = self.publish(record, state="PREPARING")
        networks = [v for v in bundle["linux"]["namespaces"] if v.get("type") == "network"]
        require(len(networks) == 1, "EXACT_NETWORK_NAMESPACE_REQUIRED")
        namespace = networks[0].get("path")
        owned = not bool(namespace)
        if owned:
            namespace = str(self.root / "netns")
            evidence_v2.write_exclusive(Path(namespace), {})
            self.run("mount", ["--bind", "/proc/" + str(state["pid"]) + "/ns/net", namespace])
        inode = os.stat(namespace).st_ino
        record = self.publish(record, namespaceOwned=owned, namespaceInode=inode)
        # Array output is intentionally parsed separately from canonical objects.
        import json
        children = [v for v in json.loads(self.run("nsenter", ["--net=" + namespace, t["commands"]["ip"], "-j", "addr", "show"]))
                    if v["ifname"] != "lo"]
        peer_declarations = declarations(candidate["transport"], candidate["containerId"])
        peer_commands = {k: self.command(k) for k in ("ip", "nsenter")}
        peer_runtime = {k: candidate["runtimeBinding"][k] for k in ("path", "sha256")}
        observations = {p["containerId"]: collect(p, r["runtimeRoot"], peer_runtime, peer_commands,
            NodeObservation({}, self.budget).run, broker.private, lambda pid: NativeBackend.generation(None, pid), self.budget)
            for p in peer_declarations}
        resolved = resolve(candidate["transport"], peer_declarations, observations, candidate["containerId"])
        indexes = {v["link_index"] for v in children}
        indexes.update(v["peerIngress"]["ifindex"] for v in resolved if v["peerIngress"]["kind"] != "HOST")
        require(len(indexes) <= 160, "NATIVE_PEER_COUNT_UNBOUNDED")
        hosts = []
        for index in sorted(indexes):
            name = socket.if_indextoname(index)
            found = json.loads(self.run("ip", ["-j", "link", "show", "dev", name]))
            require(len(found) == 1 and found[0]["ifindex"] == index and found[0]["ifname"] == name,
                    "HOST_INDEX_NAME_BINDING_DRIFT")
            hosts.append(found[0])
        profile = live_profile(candidate, bundle, namespace, inode, children, hosts, observations)
        backend = NativeBackend(profile, {k: t["commands"][k] for k in ("nft", "ip", "nsenter")}, t["budgetSeconds"])
        actual = backend.runtime(candidate["runtimeBinding"], "state")
        require(all(actual.get(k) == state[k] for k in ("id", "bundle", "pid", "status")), "INDEPENDENT_RUNTIME_STATE_DRIFT")
        generation = backend.bindings(profile, state)
        record = self.publish(record, containerGeneration=generation)
        packet = {"profile": profile, "mirrors": mirrors(profile, hosts), "parentNamespace": t["hostNetworkNamespace"]}
        result = self.invoke_result([t["commands"]["unshare"], "--net", "--fork", *self.python_argv(), str(self.entry),
            "--configuration", str(self.path), "--mode", "template"], authorization.canonical(packet))
        require(result["isolated"] is True and result["profileHash"] == digest(profile), "INDEPENDENT_TEMPLATE_BINDING_DRIFT")
        profile["expectedFootprint"] = result["footprint"]
        grant = {"schema": driver.SCHEMA, "sourceRoot": self.cfg["sourceRoot"], "sourceHashes": self.cfg["sourceHashes"],
                 "profile": profile, **{k: t[k] for k in ("kernel", "dns", "coordinationBinding", "coordinationJournal", "lockFile", "budgetSeconds")},
                 "commands": {k: t["commands"][k] for k in ("nft", "ip", "nsenter")},
                 "preexecJournal": str(self.root / "preexec.json"), "runtimeBinding": candidate["runtimeBinding"],
                 "consumptionJournal": str(self.root / "deployment.json"),
                 **{k: provisional[k] for k in ("operation", "operationBinding", "evidenceBinding", "creationFrameObserverBinding")}}
        if peer_declarations:
            grant["peerBinding"] = {"declaredPolicy": {k: candidate[k] for k in ("networkBindings", "transport", "tableName")},
                                    "observations": observations, "commandBindings": peer_commands}
        driver.validate(authorization.canonical(grant))
        gate, _ = driver.components(grant)
        with self.lock():
            self.stable()
            authorize()
            gate.quiesced()
            self.receipt_ready(evidence, generation)
            evidence_v2.write_exclusive(self.root / "preexec.json", {"schema": "ouf.semantic-preexec-journal.v1",
                "transactionId": candidate["transactionId"], "configurationHash": digest(profile), "state": "STAGED",
                "sharedStructureHash": None, "containerGeneration": None})
            driver_hash = evidence_v2.write_exclusive(self.root / "driver.json", grant)
        record = self.publish(record, state="PREPARED", driverHash=driver_hash)
        for mode in ("plan", "apply", "verify"):
            self.invoke([*self.python_argv(), str(self.hook), "--configuration", str(self.root / "driver.json"), "--mode", mode])
        self.publish(record, state="PROTECTED")
        return {"binding": r["binding"], "evidenceHash": r["evidenceBinding"]["sha256"], "driverHash": driver_hash}

    def cleanup(self):
        from tools.semantic_provider_lease_coordination import PrivateJournal
        require(os.stat("/proc/self/ns/net").st_ino == self.template["hostNetworkNamespace"], "HOST_NAMESPACE_CUSTODY_DRIFT")
        with self.lock():
            self.stable()
            record = self.record()
            raw = broker.private(self.root / "driver.json")
            grant = driver.validate(raw)
            require(record["state"] == "PROTECTED" and authorization.sha(raw) == record["driverHash"], "OWNED_CLEANUP_REQUIRED")
            prior = PrivateJournal(self.root / "preexec.json").read()
            require(prior["state"] == "ROLLED_BACK" and prior["transactionId"] == record["transactionId"], "INDEPENDENT_ROLLBACK_REQUIRED")
            gate, backend = driver.components(grant)
            gate.record()
            require(backend.tables() is None, "REMOVAL_UNPROVEN")
            require(record["containerGeneration"] is not None and backend.generation_alive(record["containerGeneration"]) is False,
                    "LIVE_GENERATION_CLEANUP_DENIED")
            if record["namespaceOwned"]:
                namespace = self.root / "netns"
                require(namespace.lstat().st_ino == record["namespaceInode"], "OWNED_NAMESPACE_DRIFT")
                self.run("umount", [str(namespace)])
                namespace.unlink()
            self.journal.write(record, {**record, "state": "CLEANED"})
        return {"state": "CLEANED"}


def main(argv=None):
    parser = broker.Arguments()
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--mode", choices=("prepare", "template", "cleanup"), required=True)
    try:
        args = parser.parse_args(argv)
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, "ROOT_ISOLATED_NO_BYTECODE_REQUIRED")
        worker = Worker(args.configuration)
        if args.mode == "prepare":
            state = authorization.decode(sys.stdin.buffer.read(16385))
            require(len(authorization.canonical(state)) <= 16384, "OCI_STATE_UNBOUNDED")
            result = worker.prepare(state)
        elif args.mode == "cleanup":
            result = worker.cleanup()
        else:
            from tools.semantic_provider_deployment_admission import isolated_template
            packet = authorization.decode(sys.stdin.buffer.read(131073))
            require(set(packet) == {"profile", "mirrors", "parentNamespace"}
                    and packet["parentNamespace"] == worker.template["hostNetworkNamespace"], "EXACT_TEMPLATE_REQUEST_REQUIRED")
            result = isolated_template(packet["profile"], packet["mirrors"], packet["parentNamespace"],
                                       os.stat("/proc/self/ns/net").st_ino, worker.run)
        print(authorization.canonical(result).decode())
        return 0
    except Exception as error:
        code = str(error)
        if re.fullmatch(r"[A-Z0-9_]{1,80}", code) is None:
            code = "INTERNAL_ERROR"
        print("SEMANTIC_ADMISSION_PREPARER=DENIED " + code, file=sys.stderr)
        return 1
