"""Reconcile the prepared, already rolled-back R3 epoch under human control."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace
from typing import NamedTuple

from tools.semantic_lease_kernel_migration import boot_dispatcher as custody
from tools.semantic_provider_operation import authorization as A
from tools.semantic_provider_r3 import driver_denial_overlay_v16 as overlay

SCHEMA = "ouf.semantic-provider-r3-reconcile.v1"
ROOT = Path("/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1")
WRAPPER = "/usr/local/sbin/ouf-semantic-admitted-v2"
PYTHON = "/usr/bin/python3.13"
GUARD = Path("/run/ouf-semantic-boot-guard/guard.lock")
DOCKER = {"path": "/usr/bin/docker",
          "sha256": "7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40"}
DOCKER_HOST = "unix:///var/run/docker.sock"
INSTALL_VERSION = 18
DELIVERY = Path(__file__).resolve().parents[2]
RUNTIME_CONFIGURATION = "runtime-configuration.json"
BOOTSTRAP = "scripts/semantic-provider-deployment-broker-v2.py"
MANDATES = "tools/semantic_authority_mandates/mandates.py"
INTENT = "r3-reconcile-intent.json"
CLAIM_PREFIX = "r3-reconcile-claim-"
require, canonical, sha = A.require, A.canonical, A.sha


class RoleFacts(NamedTuple):
    saved: dict
    journals: dict
    mount: dict | None
    runc: dict | None
    receipt: dict | None


def read_runtime(root, version):
    directory = root / "versions" / str(version)
    return custody.private(directory / RUNTIME_CONFIGURATION)


def installed_runtime(root):
    directory = root / "versions" / str(INSTALL_VERSION)
    source = directory / "source" / overlay.RUNTIME
    delivered = {p: (DELIVERY / p).read_bytes() for p in (overlay.RUNTIME, overlay.EPOCHS)}
    verified = overlay.sources_v16(delivered, {p: p for p in delivered})
    raw = custody.private(source, sha(verified[overlay.RUNTIME]))
    # The wrapper contract matches install_common.wrapper_bytes, restricted to v18.
    wrapper = (f'#!/bin/sh\nexec {PYTHON} -I -B {source} '
               f'--configuration {directory / RUNTIME_CONFIGURATION} "$@"\n').encode("ascii")
    custody.executable(WRAPPER, sha(wrapper))
    require(stat.S_IMODE(Path(WRAPPER).lstat().st_mode) == 0o755, "R3_WRAPPER_DRIFT")
    runtime = ModuleType("r3_reconcile_installed_runtime")
    runtime.__file__ = str(source)
    exec(compile(raw, str(source), "exec"), vars(runtime))
    runtime.private_directory(root)
    runtime.private_directory(directory.parent)
    runtime.private_directory(directory)
    cfg, configuration = runtime.load_configuration(directory / RUNTIME_CONFIGURATION)
    settings = A.decode((DELIVERY / "ops/vps/r3-settings.json").read_bytes().rstrip(b"\r\n"))
    authority = "tools/semantic_provider_operation/authorization.py"
    verified.update({p: (DELIVERY / p).read_bytes() for p in (authority, MANDATES)})
    bindings = (("authorizationModule", authority), ("epochsModule", overlay.EPOCHS))
    require(all(cfg[key] == {"path": str(directory / "source" / relative), "sha256": sha(verified[relative])}
                for key, relative in bindings)
            and cfg["operation"]["mandatesModule"] == {"path": str(directory / "source" / MANDATES),
                                                       "sha256": sha(verified[MANDATES])}
            and all(cfg["operation"][k] == settings[k] for k in
                    ("anchorBinding", "mandateRoot", "installationRef", "entityRef", "issuerRef"))
            and cfg["opensslBinding"] == settings["opensslBinding"],
            "R3_RECONCILE_CURRENT_TRUST_DRIFT")
    runtime.verify_files(cfg)
    require(cfg["registryRoot"] == str(root / "registry")
            and cfg["operation"]["authorizationRoot"] == str(root / "authorization")
            and cfg["runtimeStateRoot"] == "/run/docker" and cfg["pythonPath"] == PYTHON,
            "R3_INSTALLED_ROOT_DRIFT")
    runtime.private_directory(root / "registry")
    return runtime, cfg, configuration, sha(wrapper)


def native_command(runtime, binding, argv):
    binary, digest = binding["path"], binding["sha256"]
    runtime.executable(binary, digest)
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([binary, *argv], stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=20, env=runtime.ENV)
            output.seek(0)
            raw = output.read(131073)
        require(result.returncode == 0 and len(raw) <= 131072, "R3_RECONCILE_COMMAND_UNPROVEN")
        return raw
    finally:
        runtime.executable(binary, digest)


def docker_state(runtime, cid):
    raw = native_command(runtime, DOCKER, ["--host", DOCKER_HOST, "inspect", "--type", "container", cid])
    rows = runtime.parse(raw)
    require(type(rows) is list and len(rows) == 1 and rows[0]["Id"] == cid, "R3_DOCKER_INSPECT_DRIFT")
    row = rows[0]
    state, host = row["State"], row["HostConfig"]
    require(state["Status"] == "exited" and state["Running"] is False
            and type(state["Pid"]) is int and state["Pid"] == 0
            and host["Runtime"] == "ouf-semantic-admitted-v2",
            "R3_DOCKER_NOT_EXITED")
    require(all(type(state[k]) is str and re.fullmatch(r"[0-9TZ:.+-]{1,64}", state[k])
                for k in ("StartedAt", "FinishedAt"))
            and type(row["RestartCount"]) is int and row["RestartCount"] >= 0
            and host["RestartPolicy"]["Name"] in {"no", "always", "on-failure", "unless-stopped"},
            "R3_DOCKER_INSPECT_DRIFT")
    return {"status": state["Status"], "pid": state["Pid"], "startedAt": state["StartedAt"],
            "finishedAt": state["FinishedAt"], "restartCount": row["RestartCount"],
            "restartPolicy": host["RestartPolicy"]["Name"]}


def chain(runtime, cfg, auth, root, clock):
    op = cfg["operation"]
    directory = root / "authorization"

    def snapshot():
        return [(auth.private_file(directory / f"{n}.json"),
                 auth.private_file(directory / f"{n}.signature.json"))
                for n in range(1, auth.inventory(directory) + 1)]

    before = snapshot()
    bound = op["mandatesModule"]
    mandates = runtime.compiled(runtime.bound_bytes(bound), bound["path"], "r3_reconcile_mandates")
    head = auth.head(mandates, op["anchorBinding"], op["mandateRoot"], cfg["opensslBinding"], str(directory),
                     op["installationRef"], op["entityRef"], op["issuerRef"], clock)
    require(before == snapshot() and head["sequence"] == len(before)
            and head["sha256"] == sha(before[-1][0]), "R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION")
    entries, hashes = {}, []
    for sequence, (raw, signature) in enumerate(before, 1):
        digest, payload = sha(raw), auth.validate(raw)
        entries[digest] = {"sha256": digest, "sequence": sequence, "decision": payload["decision"],
                           "authorization": payload}
        hashes.append([digest, sha(signature)])
    return head, entries, sha(canonical(hashes))


def authorization_role(entry, cfg, raw, cid, role):
    payload = entry["authorization"]
    signed = payload["roles"][role]
    require(entry["decision"] == "OPERATE" and payload["runtimeConfigurationSha256"] == sha(raw)
            and signed["containerId"] == cid
            and signed["admissionConfigurationSha256"] == cfg["admissionConfigurations"][cid]["sha256"],
            "R3_RECONCILE_AUTHORIZATION_BINDING_DRIFT")
    return signed


def coordinator(runtime, cfg, entry):
    sup = A.decode(runtime.bound_bytes(cfg["leaseQuiesce"]["configuration"]))
    binding = sup["coordinator"]
    owner = A.decode(runtime.bound_bytes(binding["ownerConfiguration"]))
    runtime.bound_bytes(binding["dnsProfile"])
    signed = entry["authorization"]["lease"]
    require(sup["registryRoot"] == cfg["registryRoot"]
            and sup["authorizationRoot"] == cfg["operation"]["authorizationRoot"]
            and binding["commonLockPath"] == owner["commonLockFile"] == str(GUARD)
            and binding["journalPath"] == owner["journalFile"]
            and binding["nftBinding"] == {"path": owner["nftPath"], "sha256": owner["nftSha256"]}
            and signed == {"ownerConfigurationSha256": binding["ownerConfiguration"]["sha256"],
                           "leaseStructureHash": owner["binding"]["leaseStructureHash"],
                           "dnsProfileSha256": binding["dnsProfile"]["sha256"]},
            "R3_RECONCILE_COORDINATOR_DRIFT")
    return binding, owner


def historical(runtime, current, root, epoch, head, entries):
    entry = entries.get(epoch["authorizationSha256"])
    require(entry is not None and entry["decision"] == "OPERATE"
            and entry["sequence"] < head["sequence"]
            and entry["authorization"]["runtimeConfigurationSha256"] == epoch["configurationHash"],
            "R3_RECONCILE_HISTORICAL_AUTHORIZATION_UNPROVEN")
    versions = []
    for version in range(2, INSTALL_VERSION):
        directory = root / "versions" / str(version)
        if os.path.lexists(directory):
            runtime.private_directory(directory)
            if sha(read_runtime(root, version)) == epoch["configurationHash"]:
                versions.append(version)
    require(len(versions) == 1, "R3_RECONCILE_HISTORICAL_CONFIGURATION_UNPROVEN")
    version = versions[0]
    directory = root / "versions" / str(version)
    cfg, raw = runtime.load_configuration(directory / RUNTIME_CONFIGURATION)
    source = directory / "source" / overlay.RUNTIME
    require(sha(raw) == epoch["configurationHash"]
            and sha(custody.private(source)) == cfg["sourceHash"] == current["sourceHash"]
            and cfg["registryRoot"] == current["registryRoot"]
            and all(cfg[k] == current[k] for k in ("runtimePath", "runtimeSha256", "runtimeStateRoot",
                                                   "opensslBinding", "pythonPath", "pythonSha256"))
            and {k: v for k, v in cfg["operation"].items() if k != "mandatesModule"}
            == {k: v for k, v in current["operation"].items() if k != "mandatesModule"},
            "R3_RECONCILE_HISTORICAL_RUNTIME_DRIFT")
    require(cfg["operation"]["mandatesModule"] == {"path": str(directory / "source" / MANDATES),
                                                  "sha256": current["operation"]["mandatesModule"]["sha256"]},
            "R3_RECONCILE_HISTORICAL_TRUST_DRIFT")
    # Current trusted runtime verifies the identical historical v5.2 source
    # and its direct bindings. No historical runtime is executed.
    runtime.verify_files(cfg)
    return entry, cfg, raw, version


@contextmanager
def historical_package(runtime, cfg, cid):
    # Start with the delivery bootstrap. It verifies the historical entrypoints
    # and all transitive application bytes before executing any of that package.
    before = sys.modules.copy()
    try:
        raw = (DELIVERY / BOOTSTRAP).read_bytes()
        require(sha(raw) == cfg["admissionSha256"], "R3_RECONCILE_BOOTSTRAP_DRIFT")
        bootstrap = runtime.compiled(raw, cfg["admissionPath"], "r3_reconcile_bootstrap")
        bound = cfg["admissionConfigurations"][cid]
        broker_raw = runtime.bound_bytes(bound)
        broker_config = A.decode(broker_raw)
        root, verified = bootstrap.load_sources(bound["path"])
        require(broker_raw == runtime.bound_bytes(bound)
                and all(cfg[k] == {"path": str(root / relative), "sha256": sha(verified[relative])}
                        for k, relative in (("authorizationModule", "tools/semantic_provider_operation/authorization.py"),
                                            ("epochsModule", overlay.EPOCHS)))
                and cfg["driverPath"] == str(root / bootstrap.ENTRYPOINTS[2])
                and cfg["driverSha256"] == sha(verified[bootstrap.ENTRYPOINTS[2]]),
                "R3_RECONCILE_HISTORICAL_CLOSURE_DRIFT")
        broker = bootstrap.execute(root, verified)
        require(broker.validate(broker_raw) == broker_config, "R3_RECONCILE_HISTORICAL_CLOSURE_DRIFT")
        driver = sys.modules["tools.semantic_provider_admission_v2.driver_v7"]
        preparer = sys.modules["tools.semantic_provider_admission_v2.preparer_v2"]
        yield driver, broker, broker_config, preparer
    finally:
        for name in sys.modules.keys() - before.keys():
            del sys.modules[name]
        sys.modules.update(before)


def cleanup_broker(broker, cfg, path, entry, epoch, folder, clock):
    """Use the broker's record and CAS in a cleanup-only epoch context."""
    class HistoricalCleanup(broker.Broker):
        def head(self):
            return entry

        def check_epoch(self, head):
            current = self.epochs.current(self.cfg["registryRoot"], self.cid)
            require(self.args.mode == "cleanup" and current == epoch
                    and epoch["bootId"] == self.epochs.boot_id()
                    and epoch["authorizationSha256"] == head["sha256"],
                    "R3_RECONCILE_BROKER_EPOCH_DRIFT")
            return current

        def operate(self, state):
            raise A.OperationDenied("R3_RECONCILE_CLEANUP_CONTEXT_ONLY")

    args = SimpleNamespace(mode="cleanup", container_id=epoch["containerId"], epoch=epoch["epoch"],
                           bundle=str(folder / "bundle"), runtime_root=epoch["runtimeRoot"])
    return HistoricalCleanup(cfg, broker.read_binding(path), path["path"], args, clock=clock)


def role_state(runtime, epochs, current, cfg, epoch, folder, signed, port, worker, driver,
               broker, current_coordinator, current_owner, table_names, clock):
    cid = epoch["containerId"]
    driver_raw = runtime.read(folder / "driver.json")
    grant = driver.validate(driver_raw)
    profile, template = grant["profile"], worker.template
    consumed, state, admission = port.gate.record(), port.record(), worker.record()
    evidence_raw = broker.read_binding(worker.request["evidenceBinding"])
    evidence = broker.evidence_v2.verify(A.decode(evidence_raw), signed, port.bound)
    generation = consumed["generation"]
    namespace = folder / "netns"
    bundle = A.decode(runtime.read(folder / "bundle" / "config.json"))
    application = sys.modules["tools.semantic_provider_deployment_admission"].application_hash(bundle)
    require(sha(driver_raw) == epoch["driverHash"] == state["driverHash"] == consumed["driverHash"]
            == admission["driverHash"] and state["bundleHash"] == consumed["bundleHash"]
            == evidence["bundleHash"] == application
            and profile["bundleHash"] == runtime.digest(bundle) == epoch["bundleHash"]
            and generation == evidence["generation"] == admission["containerGeneration"]
            and (epoch["generation"] is None or epoch["generation"] ==
                 {k: generation[k] for k in ("pid", "startTicks")})
            and all(evidence[k] == port.binding[k] for k in ("containerId", "epoch", "authorizationSha256"))
            and consumed["state"] in {"READY", "STARTING", "STARTED"}
            and consumed["evidenceHash"] == sha(evidence_raw)
            and worker.request == port.preparer_request(consumed["evidenceHash"]),
            "R3_RECONCILE_PREPARATION_BINDING_DRIFT")
    require(grant["operationBinding"] == {k: port.binding[k] for k in
                                         ("authorizationSha256", "containerId", "epoch", "configurationHash")}
            and grant["operation"] == {**cfg["operation"], "opensslBinding": cfg["opensslBinding"]}
            and grant["sourceRoot"] == port.cfg["sourceRoot"] and grant["sourceHashes"] == port.cfg["sourceHashes"]
            and grant["runtimeBinding"] == {"path": cfg["runtimePath"], "sha256": cfg["runtimeSha256"],
                                           "root": epoch["runtimeRoot"]}
            and grant["evidenceBinding"] == worker.request["evidenceBinding"]
            and grant["creationFrameObserverBinding"] == port.cfg["creationFrameObserverBinding"]
            and all(grant[k] == template[k] for k in ("lockFile", "coordinationJournal", "coordinationBinding",
                                                     "dns", "kernel", "budgetSeconds"))
            and all(path == template["commands"][name] for name, path in grant["commands"].items())
            and profile["policy"]["tableName"] == signed["tableName"]
            and profile["bundlePath"] == str(folder / "bundle"),
            "R3_RECONCILE_DRIVER_BINDING_DRIFT")
    require(grant["lockFile"] == str(GUARD)
            and grant["coordinationJournal"] == current_coordinator["journalPath"]
            and grant["kernel"] == current_owner["kernel"] and grant["coordinationBinding"] == current_owner["binding"]
            and worker.command("nft") == current_coordinator["nftBinding"],
            "R3_RECONCILE_COORDINATOR_DRIFT")
    require(admission["namespaceOwned"] is True and type(admission["namespaceInode"]) is int
            and admission["namespaceInode"] == profile["namespaceInode"] == generation["namespaceInode"]
            and profile["namespaceOrigin"] == "OCI_CREATED" and profile["namespacePath"] == str(namespace)
            and [v for v in bundle["linux"]["namespaces"] if v.get("type") == "network"] == [{"type": "network"}]
            and os.stat("/proc/self/ns/net").st_ino == template["hostNetworkNamespace"],
            "R3_RECONCILE_NAMESPACE_CUSTODY_DRIFT")
    gate, backend = driver.components(grant)
    preexec = gate.record()
    require(preexec["state"] == "ROLLED_BACK" and preexec["transactionId"] == admission["transactionId"]
            and preexec["containerGeneration"] == generation,
            "R3_RECONCILE_ROLLBACK_UNPROVEN")
    gate.quiesced()
    lease = gate.coord.journal()
    require(not any(lease["leaseAddresses"]), "R3_RECONCILE_LEASE_JOURNAL_NOT_EMPTY")
    nft = runtime.parse(native_command(runtime, worker.command("nft"), ["-j", "list", "tables"]))
    require(type(nft) is dict and set(nft) == {"nftables"} and type(nft["nftables"]) is list
            and all(type(item) is dict and (set(item) in ({"table"}, {"metainfo"})) for item in nft["nftables"]),
            "R3_RECONCILE_NFT_READBACK_INVALID")
    require(all(item["table"]["name"] not in table_names for item in nft["nftables"] if "table" in item),
            "R3_RECONCILE_ROLE_TABLE_PRESENT")
    require(backend.generation_alive(generation) is False and epochs.start_ticks(generation["pid"]) is None,
            "R3_RECONCILE_LIVE_OR_RECYCLED_GENERATION")
    docker = docker_state(runtime, cid)
    runc_root = Path(epoch["runtimeRoot"])
    runtime.executable(current["runtimePath"], current["runtimeSha256"])
    runc = runtime.failed_runtime_state(current, cid, runc_root, folder, epoch, epochs)
    if runc is not None:
        require(runc["status"] == "stopped" and runc["pid"] in (0, generation["pid"]),
                "R3_RECONCILE_RUNC_NOT_STOPPED")
        runc = {k: runc[k] for k in ("id", "bundle", "pid", "status")}
    mount = broker.owned_namespace_mount(namespace, admission["namespaceInode"])
    denial_raw = runtime.read(folder / "broker-denial-cleanup.json")
    denial = broker.validate_denial(denial_raw, cid, epoch["epoch"], "cleanup")
    require(denial["reason"] == "CONSUMPTION_CONFIGURATION_DRIFT" and denial["cohort"] is None
            and epoch["openedAt"] <= denial["at"] <= int(clock()),
            "R3_RECONCILE_INCIDENT_UNPROVEN")
    receipt = runtime.cleanup_receipt(folder, epoch, None)
    immutable = {name: sha(runtime.read(folder / name)) for name in
                 ("adapter.json", "preexec.json", "deployment.json", "evidence.json", "preparer.json",
                  "driver.json", "broker-denial-cleanup.json", "bundle/config.json")}
    immutable["current"] = sha(runtime.read(folder.parent.parent / "current"))
    saved = {"cid": cid, "epoch": epoch["epoch"], "authorizationSha256": epoch["authorizationSha256"],
             "configurationSha256": epoch["configurationHash"], "immutable": immutable,
             "docker": docker, "leaseSha256": sha(canonical(lease)), "runtimeRoot": str(runc_root)}
    journals = {"broker": state, "admission": admission}
    return RoleFacts(saved, journals, mount, runc, receipt)


def claim_name(digest):
    return f"{CLAIM_PREFIX}{digest}.json"


def plan_digest(plan):
    return sha(canonical({k: v for k, v in plan.items() if k != "planSha256"}))


def role_proof(runtime, folder, anchor, role, saved, journals, mount, runc, receipt):
    intent_path = folder / INTENT
    if not os.path.lexists(intent_path):
        require(all(value["state"] == "PROTECTED" for value in journals.values())
                and mount is not None and receipt is None, "R3_RECONCILE_UNPROVEN_PARTIAL_ROLE")
        return {**saved, "state": "PENDING", "mount": mount, "runc": runc,
                "beforeSha256": {k: sha(canonical(v)) for k, v in journals.items()},
                "cleanedSha256": {k: sha(canonical({**v, "state": "CLEANED"})) for k, v in journals.items()}}
    intent = A.decode(runtime.read(intent_path))
    digest, at = intent["planSha256"], intent["at"]
    require(set(intent) == {"schema", "planSha256", "at", "role"} and intent["schema"] == SCHEMA
            and A.HEX64.fullmatch(digest) and type(at) is int and at > 0 and intent["role"] == role,
            "R3_RECONCILE_ROLE_INTENT_DRIFT")
    plan = A.decode(runtime.read(anchor / claim_name(digest)))
    before = plan["roles"][role]
    expected = {"schema": "ouf.semantic-docker-runtime-cleanup.v1", "epoch": saved["epoch"], "operation": "delete",
                "at": at, "runcStatusBefore": "absent" if before["runc"] is None else "stopped"}
    require(plan["schema"] == SCHEMA and plan["planSha256"] == digest == plan_digest(plan)
            and before["state"] == "PENDING" and all(before[k] == value for k, value in saved.items())
            and before["cleanedSha256"] == {k: sha(canonical(v)) for k, v in journals.items()}
            and all(value["state"] == "CLEANED" for value in journals.values())
            and mount is None and runc is None and receipt == expected
            and runtime.read(folder / "netns") == b"{}",
            "R3_RECONCILE_UNPROVEN_PARTIAL_ROLE")
    return {**saved, "state": "CLEANED", "claimSha256": digest, "receipt": expected,
            "cleanedSha256": before["cleanedSha256"], "mount": None, "runc": None}


class Reconciliation:
    def __init__(self, root=ROOT, clock=time.time):
        self.root, self.clock = root, clock

    @contextmanager
    def locked(self):
        _, preliminary, raw, wrapper = installed_runtime(self.root)
        with ExitStack() as locks:
            for cid in sorted(preliminary["candidates"]):
                locks.enter_context(custody.lock(self.root / "registry" / cid / "operation.lock"))
            locks.enter_context(custody.directory_lock(self.root / "authorization"))
            locks.enter_context(custody.lock(GUARD))
            runtime, self.cfg, current_raw, current_wrapper = installed_runtime(self.root)
            require((current_raw, current_wrapper) == (raw, wrapper), "R3_RECONCILE_INSTALLATION_CHANGED")
            self.runtime, self.raw, self.wrapper = runtime, raw, wrapper
            self.auth, self.epochs = runtime.operation_modules(self.cfg)
            yield

    def observe(self):
        cfg, rt = self.cfg, self.runtime
        head, entries, self.chain_hash = chain(rt, cfg, self.auth, self.root, self.clock)
        self.head = head
        self.coordinator, self.owner = coordinator(rt, cfg, head)
        boot = self.epochs.boot_id()
        self.contexts, table_names = {}, set()
        for cid, item in sorted(cfg["candidates"].items()):
            role = item["role"]
            signed_current = authorization_role(head, cfg, self.raw, cid, role)
            epoch = self.epochs.current(cfg["registryRoot"], cid)
            require(epoch is not None and epoch["state"] == "FAILED" and epoch["bootId"] == boot
                    and epoch["failure"] == "TWO_PHASE_BROKER_DENIED" and epoch["driverHash"] is not None,
                    "R3_RECONCILE_SAME_BOOT_PREPARED_FAILURE_REQUIRED")
            folder = self.root / "registry" / cid / "epochs" / str(epoch["epoch"])
            entry, old_cfg, old_raw, version = historical(rt, cfg, self.root, epoch, head, entries)
            require(old_cfg["candidates"][cid]["role"] == role, "R3_RECONCILE_HISTORICAL_ROLE_DRIFT")
            binding, _ = coordinator(rt, old_cfg, entry)
            require(binding["ownerConfiguration"] == self.coordinator["ownerConfiguration"],
                    "R3_RECONCILE_COORDINATOR_DRIFT")
            signed = authorization_role(entry, old_cfg, old_raw, cid, role)
            table_names.update((signed_current["tableName"], signed["tableName"]))
            self.contexts[role] = (epoch, folder, entry, old_cfg, signed, version)
        self.tables = table_names
        self.anchor = self.contexts["adapter"][1]
        roles = {role: self.inspect_role(role) for role in sorted(self.contexts)}
        plan = {"schema": SCHEMA, "bootId": boot, "wrapperSha256": self.wrapper,
                "configurationSha256": sha(self.raw), "headSha256": head["sha256"],
                "headSequence": head["sequence"], "chainSha256": self.chain_hash, "roles": roles}
        return {**plan, "planSha256": plan_digest(plan)}

    def inspect_role(self, role, *, approve=None, at=None):
        epoch, folder, entry, cfg, signed, version = self.contexts[role]
        runtime, cid = self.runtime, epoch["containerId"]
        bound = cfg["admissionConfigurations"][cid]
        directory = self.root / "versions" / str(version)
        source = directory / "source"
        broker_data = A.decode(runtime.bound_bytes(bound))
        require(bound["path"] == str(directory / "broker" / f"{role}.json")
                and broker_data["sourceRoot"] == str(source)
                and broker_data["containerId"] == cid and broker_data["role"] == role
                and broker_data["registryRoot"] == cfg["registryRoot"]
                and broker_data["runtimeRootParent"] == cfg["runtimeStateRoot"]
                and cfg["admissionPath"] == str(source / BOOTSTRAP)
                and broker_data["operation"] == {**{k: v for k, v in cfg["operation"].items() if k not in
                                                        ("installationRef", "entityRef", "issuerRef")},
                                                "opensslBinding": cfg["opensslBinding"]}
                and broker_data["authorities"] == {k: cfg["operation"][k] for k in
                                                    ("installationRef", "entityRef", "issuerRef")},
                "R3_RECONCILE_HISTORICAL_CLOSURE_DRIFT")
        with historical_package(runtime, cfg, cid) as (driver, broker, broker_config, preparer):
            port = cleanup_broker(broker, broker_config, bound, entry, epoch, folder, self.clock)
            worker = preparer.Worker(folder / "preparer.json", self.clock)
            facts = role_state(runtime, self.epochs, self.cfg, cfg, epoch, folder, signed, port, worker,
                               driver, broker, self.coordinator, self.owner, self.tables, self.clock)
            saved, journals, mount, runc, receipt = facts
            scoped = {**saved, "historicalVersion": version, "historicalSequence": entry["sequence"]}
            proof = role_proof(runtime, folder, self.anchor, role, scoped, journals, mount, runc, receipt)
            if approve is not None:
                require(proof == approve["roles"][role] and proof["state"] == "PENDING",
                        "R3_RECONCILE_ROLE_CHANGED")
                head, _, chain_hash = chain(runtime, self.cfg, self.auth, self.root, self.clock)
                require(head == self.head and chain_hash == self.chain_hash, "R3_RECONCILE_AUTHORIZATION_CHANGED")
                port.stable()
                worker.stable()
                namespace = folder / "netns"
                require(broker.owned_namespace_mount(namespace, journals["admission"]["namespaceInode"]) == mount,
                        "R3_RECONCILE_NAMESPACE_CHANGED")
                custody.write_once(folder / INTENT, canonical({"schema": SCHEMA, "role": role, "at": at,
                                                                "planSha256": approve["planSha256"]}))
                root = Path(epoch["runtimeRoot"])
                if runc is not None:
                    binding = {"path": cfg["runtimePath"], "sha256": cfg["runtimeSha256"]}
                    native_command(runtime, binding, ["--root", str(root), "delete", cid])
                require(runtime.failed_runtime_state(self.cfg, cid, root, folder, epoch, self.epochs) is None,
                        "R3_RECONCILE_RUNC_ABSENCE_UNPROVEN")
                require(broker.owned_namespace_mount(namespace, journals["admission"]["namespaceInode"]) == mount,
                        "R3_RECONCILE_NAMESPACE_CHANGED")
                worker.run("umount", [str(namespace)])
                require(broker.owned_namespace_mount(namespace, journals["admission"]["namespaceInode"]) is None
                        and runtime.read(namespace) == b"{}", "R3_RECONCILE_UNMOUNT_UNPROVEN")
                closed = {**journals["admission"], "state": "CLEANED"}
                worker.journal.write(journals["admission"], closed)
                require(worker.record() == closed, "R3_RECONCILE_ADMISSION_READBACK_DRIFT")
                port.publish(journals["broker"], state="CLEANED")
                after = role_state(runtime, self.epochs, self.cfg, cfg, epoch, folder, signed, port, worker,
                                   driver, broker, self.coordinator, self.owner, self.tables, self.clock)
                require(after.saved == saved
                        and {k: sha(canonical(v)) for k, v in after.journals.items()} == proof["cleanedSha256"]
                        and after.mount is after.runc is after.receipt is None, "R3_RECONCILE_READBACK_DRIFT")
                custody.write_once(folder / "runtime-cleanup.json", canonical({
                    "schema": "ouf.semantic-docker-runtime-cleanup.v1", "epoch": epoch["epoch"],
                    "operation": "delete", "at": at, "runcStatusBefore": "absent" if runc is None else "stopped"}))
            return proof

    def run(self, expected=None, report=None):
        report = {} if report is None else report
        require(expected is None or type(expected) is str and A.HEX64.fullmatch(expected),
                "R3_RECONCILE_ARGUMENTS_REQUIRED")
        with self.locked():
            plan = self.observe()
            if expected is None:
                return plan
            claim = self.anchor / claim_name(expected)
            require(not os.path.lexists(claim), "R3_RECONCILE_CLAIM_ALREADY_CONSUMED")
            require(plan["planSha256"] == expected, "R3_RECONCILE_PLAN_DIGEST_CHANGED")
            pending = [role for role, proof in plan["roles"].items() if proof["state"] == "PENDING"]
            if pending:
                at = int(self.clock())
                require(at > 0, "R3_RECONCILE_CLOCK_UNPROVEN")
                report.update(planSha256=expected, phase="CLAIM", completedRoles=[])
                custody.write_once(claim, canonical(plan))
                for role in pending:
                    report.update(phase="CLEANUP", role=role)
                    self.inspect_role(role, approve=plan, at=at)
                    require(self.inspect_role(role)["state"] == "CLEANED", "R3_RECONCILE_ROLE_READBACK_DRIFT")
                    report["completedRoles"].append(role)
            result = self.observe()
            require(all(row["state"] == "CLEANED" for row in result["roles"].values()),
                    "R3_RECONCILE_COHORT_READBACK_DRIFT")
            return {**result, "planSha256": expected, "readbackSha256": result["planSha256"],
                    "status": "CLEANED" if pending else "ALREADY_CLEANED"}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    report = {}
    try:
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.dont_write_bytecode, "ROOT_ISOLATED_NO_BYTECODE_REQUIRED")
        require(argv == ["plan"] or len(argv) == 2 and argv[0] == "apply" and A.HEX64.fullmatch(argv[1]),
                "R3_RECONCILE_ARGUMENTS_REQUIRED")
        result = Reconciliation().run(None if argv == ["plan"] else argv[1], report)
        print(canonical(result).decode("ascii"))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        code = str(error)
        if isinstance(error, BlockingIOError):
            code = "R3_RECONCILE_LOCK_BUSY"
        elif isinstance(error, KeyboardInterrupt):
            code = "R3_RECONCILE_INTERRUPTED"
        elif not isinstance(error, (RuntimeError, ValueError)) or not re.fullmatch("[A-Z][A-Z0-9_]{1,95}", code):
            code = "R3_RECONCILE_UNPROVEN"
        print(canonical({"status": "HELD", "reason": code, **report}).decode("ascii"))
        return 1
