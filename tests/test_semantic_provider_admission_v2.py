"""Portable admission tests and gated Linux root integration with real authority/epochs."""
import ast
import copy
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import types
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_operation import authorization as a
from tools.semantic_provider_admission_v2 import broker_v2 as b, evidence_v2 as ev
from tools.semantic_provider_admission_v2.consumption_v2 import EpochConsumption
from tools.semantic_provider_admission_v2.reauthorization_v2 import sealed_authorizer_v2

NATIVE = os.environ.get("OUF_ADMISSION_V2_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_ADMISSION_V2_NATIVE requires Linux root:root; refusing to skip")
CID = "a" * 64
GEN = {"pid": 42, "startTicks": 123, "namespaceInode": 456}
SOURCE = ROOT / "tools/semantic_cohort_admission/cohort-draft"


@contextmanager
def libraries():
    """Compile unchanged local bytes for portable tests; Linux IO stays uncalled.

    Windows lacks fcntl: the import-only sentinel makes any native lock use fail.
    Production load() never installs this sentinel and verifies custody/hashes.
    """
    import tools
    old_attributes = {n: getattr(tools, n) for n in b.MODULES if hasattr(tools, n)}
    try:
        with patch.dict(sys.modules):
            if sys.platform != "linux":
                sys.modules["fcntl"] = types.ModuleType("fcntl")
            for name in b.MODULES:
                module = types.ModuleType("tools." + name)
                module.__package__ = "tools"
                module.__file__ = str(SOURCE / "tools" / (name + ".py"))
                sys.modules[module.__name__] = module
                setattr(tools, name, module)
                exec(compile(Path(module.__file__).read_bytes(), module.__file__, "exec"), module.__dict__)
            yield
    finally:
        for name in b.MODULES:
            if name in old_attributes:
                setattr(tools, name, old_attributes[name])
            elif hasattr(tools, name):
                delattr(tools, name)


def fixture():
    documents = {"framePolicy": a.canonical({"expectedOci": {"root": {"path": "/rootfs"}}}),
                 "rootfsSeal": a.canonical({"schema": "ouf.semantic-rootfs-seal.v1", "sha256": "4" * 64,
                                           "entries": 1, "bytes": 0}),
                 "transport": a.canonical({"networkBindings": [], "transport": [], "tableName": "ouf_adapter"})}
    role = {"containerId": CID, "admissionConfigurationSha256": "3" * 64, "tableName": "ouf_adapter",
            **{ev.DOCUMENTS[k]: a.sha(v) for k, v in documents.items()}}
    binding = {"installationRef": "inst", "entityRef": "ent", "containerId": CID, "epoch": 1,
               "authorizationSha256": "1" * 64, "configurationHash": "3" * 64}
    head = {"sha256": "1" * 64, "decision": "OPERATE", "authorization": {"installationRef": "inst", "entityRef": "ent",
            "roles": {"adapter": role}}}
    app = a.sha(a.canonical(json.loads(documents["framePolicy"])["expectedOci"]))
    evidence = {"schema": ev.SCHEMA, "containerId": CID, "epoch": 1, "authorizationSha256": "1" * 64,
                "generation": GEN, "bundleHash": app, "applicationHash": app, "creationFrameHash": "5" * 64,
                "rootfsSeal": json.loads(documents["rootfsSeal"]), "transportSha256": role["transportSha256"], "observedAt": 1500}
    return binding, head, role, documents, evidence


class MemoryJournal:
    def __init__(self):
        self.value = None
        self.states = []

    def read(self):
        return copy.deepcopy(self.value)

    def write(self, previous, value):
        if previous != self.value:
            raise a.OperationDenied("FOREIGN_JOURNAL_PRESERVED")
        self.value = copy.deepcopy(value)
        self.states.append(value["state"])


class ConsumptionTests(unittest.TestCase):
    def setUp(self):
        self.binding, self.head, self.role, self.docs, self.evidence = fixture()
        self.journal = MemoryJournal()
        self.locked = False

        @contextmanager
        def lock():
            self.assertFalse(self.locked)
            self.locked = True
            try:
                yield
            finally:
                self.locked = False
        self.lock = lock
        self.gate = EpochConsumption(self.binding, self.journal, lock)
        self.journal.value = self.gate.initial()

    def ready(self):
        self.gate.authorize_create(self.head)
        self.gate.created(self.evidence["bundleHash"], GEN)
        with self.lock():
            self.gate.ready_locked(self.evidence)
            self.gate.seal_driver_locked("6" * 64)

    def test_transitions_and_no_replay(self):
        self.ready()
        events = []
        with self.lock():
            self.gate.consume_locked(a.sha(a.canonical(self.evidence)), "6" * 64, GEN,
                lambda: events.append(self.gate.record()["state"]), lambda: events.append("start"))
        self.assertEqual(events, ["READY", "STARTING", "start"])
        self.assertEqual(self.journal.states, ["CREATING", "CREATED", "READY", "READY", "STARTING", "STARTED"])
        for action in (lambda: self.gate.authorize_create(self.head),
                       lambda: self.gate.created(self.evidence["bundleHash"], GEN),
                       lambda: self.gate.ready_locked(self.evidence),
                       lambda: self.gate.consume_locked("0" * 64, "6" * 64, GEN, lambda: True, lambda: None)):
            with self.assertRaises(a.OperationDenied):
                action()

    def test_stop_hash_role_and_configuration_denials(self):
        for change in ({"decision": "STOP"}, {"sha256": "9" * 64},
                       {"authorization": {"installationRef": "inst", "entityRef": "ent", "roles": {}}}):
            with self.subTest(change=change), self.assertRaises(a.OperationDenied):
                self.gate.authorize_create({**self.head, **change})
            self.assertEqual(self.gate.record()["state"], "STAGED")
        self.head["authorization"]["roles"]["adapter"]["admissionConfigurationSha256"] = "8" * 64
        with self.assertRaisesRegex(a.OperationDenied, "CONSUMPTION_CONFIGURATION_DRIFT"):
            self.gate.authorize_create(self.head)

    def test_new_epoch_has_independent_consumption(self):
        self.ready()
        journal = MemoryJournal()
        gate = EpochConsumption({**self.binding, "epoch": 2}, journal, self.lock)
        journal.value = gate.initial()
        gate.authorize_create(self.head)
        self.assertEqual((self.gate.record()["state"], gate.record()["state"]), ("READY", "CREATING"))

    def test_failed_second_authorization_preserves_starting(self):
        self.ready()
        starter = Mock()
        authorize = Mock(side_effect=[True, a.OperationDenied("REVOKED")])
        with self.lock(), self.assertRaisesRegex(a.OperationDenied, "REVOKED"):
            self.gate.consume_locked(a.sha(a.canonical(self.evidence)), "6" * 64, GEN, authorize, starter)
        self.assertEqual(self.gate.record()["state"], "STARTING")
        starter.assert_not_called()

    def test_ready_binds_generation_bundle_and_epoch(self):
        self.gate.authorize_create(self.head)
        self.gate.created(self.evidence["bundleHash"], GEN)
        for key, value in (("generation", {**GEN, "namespaceInode": 457}), ("bundleHash", "0" * 64), ("epoch", 2)):
            with self.subTest(key=key), self.assertRaises(a.OperationDenied):
                self.gate.ready_locked({**self.evidence, key: value})
        self.assertEqual(self.gate.record()["state"], "CREATED")

    def test_cas_foreign_and_malformed_journal(self):
        old = self.gate.record()
        self.journal.value["state"] = "CREATING"
        with self.assertRaisesRegex(a.OperationDenied, "CONSUMPTION_CHANGED_UNDER_LOCK"):
            self.gate.publish(old, state="CREATING")
        self.journal.value["extra"] = True
        with self.assertRaisesRegex(a.OperationDenied, "FOREIGN_CONSUMPTION_JOURNAL"):
            self.gate.record()


class EvidenceTests(unittest.TestCase):
    def test_good_and_each_divergence(self):
        _, _, role, docs, value = fixture()
        self.assertEqual(ev.verify(value, role, docs), value)
        cases = [("frame", value, {**docs, "framePolicy": a.canonical({"expectedOci": {}})}, "EVIDENCE_FRAMEPOLICY_BINDING_DRIFT"),
                 ("rootfs", {**value, "rootfsSeal": {**value["rootfsSeal"], "sha256": "0" * 64}}, docs, "EVIDENCE_ROOTFS_DRIFT"),
                 ("application", {**value, "applicationHash": "0" * 64}, docs, "EVIDENCE_APPLICATION_DRIFT"),
                 ("transport", {**value, "transportSha256": "0" * 64}, docs, "EVIDENCE_TRANSPORT_DRIFT")]
        for name, evidence, bound, code in cases:
            with self.subTest(name=name), self.assertRaisesRegex(a.OperationDenied, code):
                ev.verify(evidence, role, bound)
        for name in docs:
            with self.subTest(document=name), self.assertRaises(a.OperationDenied):
                ev.verify(value, role, {**docs, name: docs[name] + b" "})
        with self.assertRaisesRegex(a.OperationDenied, "EXACT_EPOCH_EVIDENCE_REQUIRED"):
            ev.verify({**value, "extra": True}, role, docs)

    def test_reauthorization_revocation_frame_generation_and_seal(self):
        binding, head, _, _, evidence = fixture()
        raw = a.canonical(evidence)
        with libraries():
            import tools.semantic_provider_deployment_authentication as auth
            import tools.semantic_provider_preexec_native as native
            observer = Mock()
            observer.observe.return_value = (evidence["creationFrameHash"], {})
            reader = Mock(return_value=head)
            with patch.object(auth, "private_bytes", return_value=raw) as file_reader, patch.object(auth, "CreatedFrameObserver", return_value=observer), \
                    patch.object(native.NativeBackend, "generation", return_value=GEN):
                callback = sealed_authorizer_v2(head_reader=reader, binding=binding,
                    evidence_binding={"path": "/epoch/evidence.json", "sha256": a.sha(raw)},
                    creation_frame_observer_binding={}, bundle="/epoch/bundle", budget=Mock())
                self.assertTrue(callback())
                reader.return_value = {**head, "decision": "STOP"}
                with self.assertRaisesRegex(a.OperationDenied, "OPERATION_HEAD_DRIFT"):
                    callback()
                reader.side_effect = a.OperationDenied("OPERATION_KEY_REVOKED")
                with self.assertRaisesRegex(a.OperationDenied, "OPERATION_KEY_REVOKED"):
                    callback()
                reader.side_effect, reader.return_value = None, head
                observer.observe.return_value = ("0" * 64, {})
                with self.assertRaisesRegex(a.OperationDenied, "LATE_CREATED_FRAME_DRIFT"):
                    callback()
                observer.observe.return_value = (evidence["creationFrameHash"], {})
                with patch.object(native.NativeBackend, "generation", return_value={**GEN, "startTicks": 124}), \
                        self.assertRaisesRegex(a.OperationDenied, "LATE_EPOCH_GENERATION_DRIFT"):
                    callback()
                file_reader.return_value = raw + b" "
                with self.assertRaisesRegex(a.OperationDenied, "SEALED_EPOCH_EVIDENCE_DRIFT"):
                    callback()
                file_reader.return_value = raw
                reader.side_effect = [head, {**head, "decision": "STOP"}]
                with self.assertRaisesRegex(a.OperationDenied, "OPERATION_HEAD_DRIFT"):
                    callback()


def configuration():
    bound = {"path": "/private/file", "sha256": "1" * 64}
    return {"schema": b.SCHEMA, "sourceRoot": "/source", "sourceHashes": {k: "2" * 64 for k in b.SOURCES},
            "authorities": {"installationRef": "inst", "entityRef": "ent", "issuerRef": "installer"},
            "operation": {"authorizationRoot": "/authorization", "anchorBinding": bound, "mandateRoot": "/mandates",
                          "opensslBinding": {**bound, "version": "3.0.0"}, "mandatesModule": bound},
            "role": "adapter", "containerId": CID, "registryRoot": "/registry", "framePolicyBinding": bound,
            "rootfsSealBinding": bound, "transportBinding": bound, "preparerTemplate": bound,
            "runtimeRootParent": "/runtime", "rootfsLimits": {"maxEntries": 10, "maxBytes": 1024, "maxDepth": 4},
            "creationFrameObserverBinding": {k: bound for k in ("python", "source", "configuration")}}


class ConfigurationTests(unittest.TestCase):
    def test_closed_configuration_and_nested_fields(self):
        cfg = configuration()
        self.assertEqual(b.validate(a.canonical(cfg)), cfg)
        for key in cfg:
            bad = copy.deepcopy(cfg)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(a.OperationDenied):
                b.validate(a.canonical(bad))
        for key in (None, "operation", "authorities", "creationFrameObserverBinding", "rootfsLimits", "preparerTemplate"):
            bad = copy.deepcopy(cfg)
            (bad if key is None else bad[key])["foreign"] = True
            with self.subTest(extra=key), self.assertRaises(a.OperationDenied):
                b.validate(a.canonical(bad))
        for key, value in (("epoch", 1), ("epochRoot", "/epoch"), ("producers", {}), ("signingKeyBinding", {})):
            with self.subTest(key=key), self.assertRaises(a.OperationDenied):
                b.validate(a.canonical({**cfg, key: value}))
        with self.assertRaises(a.OperationDenied):
            b.validate(a.canonical(cfg) + b"\n")

    def test_no_issuance_references_in_v2_sources(self):
        forbidden = {"LocalEvidenceProducer", "ExistingEd25519Signer", "InstallerApproval", "NodeAttestor"}
        paths = [* (ROOT / "tools/semantic_provider_admission_v2").glob("*.py"),
                 ROOT / "scripts/semantic-provider-deployment-broker-v2.py"]
        for path in paths:
            raw = path.read_text(encoding="utf-8")
            self.assertFalse(any(name in raw for name in forbidden), path.name)
            tree = ast.parse(raw)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.assertNotIn("semantic_provider_deployment_signing", ast.unparse(node))
                if isinstance(node, ast.Call):
                    self.assertNotIn(getattr(node.func, "attr", None), {"emit", "sign"})

    def test_unavailable_port_denies_and_cli_hides_details(self):
        with self.assertRaisesRegex(a.OperationDenied, "PREPARER_V2_UNAVAILABLE"):
            b.UnavailablePreparer().prepare({}, {})
        output = io.StringIO()
        with patch.object(b, "load", side_effect=RuntimeError("/private/secret")), patch("sys.stderr", output):
            self.assertEqual(b.main(["--configuration", "/cfg", "--container-id", CID, "--epoch", "1",
                                     "--bundle", "/bundle", "--runtime-root", "/runtime", "--mode", "prepare"]), 1)
        self.assertEqual(output.getvalue(), "SEMANTIC_DEPLOYMENT_BROKER=DENIED\n")
        output = io.StringIO()
        with patch("sys.stderr", output):
            self.assertEqual(b.main(["--epoch", "invalid"]), 1)
        self.assertEqual(output.getvalue(), "SEMANTIC_DEPLOYMENT_BROKER=DENIED\n")


# Reuse the actual task-37 fixture; no second authority implementation.
spec = importlib.util.spec_from_file_location("admission_operation_fixture", ROOT / "tests/test_semantic_provider_operation.py")
operation_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operation_tests)


class NativeTests(operation_tests.Fixture):
    __unittest_skip__ = not NATIVE
    __unittest_skip_why__ = "set OUF_ADMISSION_V2_NATIVE=1 under native Linux root"

    def setUp(self):
        super().setUp()
        self.lib = libraries()
        self.lib.__enter__()
        self.addCleanup(self.lib.__exit__, None, None, None)
        import tools.semantic_provider_node_observation as observation
        import tools.semantic_provider_deployment_authentication as auth
        self.auth = auth
        self.cfg = configuration()
        self.cfg["registryRoot"] = str(self.root / "registry")
        self.cfg["runtimeRootParent"] = str(self.root / "runtime")
        self.runtime_root = self.root / "runtime/owned"
        self.runtime_root.mkdir(parents=True, mode=0o700)
        self.source = self.root / "source"
        (self.source / "tools").mkdir(parents=True, mode=0o700)
        for relative in b.SOURCES:
            self.write(self.source / relative, (SOURCE / relative).read_bytes())
        self.cfg["sourceRoot"] = str(self.source)
        self.cfg["sourceHashes"] = {p: a.sha((self.source / p).read_bytes()) for p in b.SOURCES}
        self.rootfs = self.root / "rootfs"
        self.rootfs.mkdir(mode=0o700)
        self.write(self.rootfs / "application", b"synthetic application")
        self.oci = {"root": {"path": str(self.rootfs), "readonly": True},
                    "linux": {"namespaces": [{"type": "network"}]}}
        nic = {"interface": "eth0", "bridge": "br_test", "mac": "02:00:00:00:00:01", "ipv4": "10.10.0.2",
               "workloadRef": "provider", "bindingRef": "provider_nic"}
        self.transport = {"networkBindings": [nic], "tableName": "ouf_b2_adapter", "transport": [
            {"purpose": "DNS", "authorityRef": "dns", "source": "10.10.0.2", "destination": "10.10.0.3",
             "protocol": "udp", "port": 53, "peerIngress": {"kind": "HOST", "ifindex": 0}}]}
        self.peer_fixture = self._testMethodName == "test_peer_bundle_and_live_observations"
        self.extra_states = {}
        child = {"ifname": "eth0", "ifindex": 12, "link_index": 1, "address": nic["mac"],
                 "addr_info": [{"family": "inet", "local": nic["ipv4"]}]}
        host = {"ifname": "lo", "ifindex": 1, "link_index": 12, "master": "br_test"}
        self.runc = self.script("runc", "import json,pathlib,sys\np=pathlib.Path(" + repr(str(self.root / "runc-state.json"))
                                + ")\nd=json.loads(p.read_text())\nprint(json.dumps(list(d.values()) if 'list' in sys.argv else d[sys.argv[-1]]))\n")
        ip_body = "print(" + repr(json.dumps([host])) + ")\n"
        ns_body = "print(" + repr(json.dumps([child])) + ")\n"
        if self.peer_fixture:
            # Real process generation and interface name lookup, synthetic command reports.
            host_index, host_name = next((i, n) for i, n in socket.if_nameindex() if i > 1)
            peer_process = subprocess.Popen(["/usr/bin/sleep", "60"], stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            def stop_peer():
                peer_process.terminate()
                peer_process.wait(timeout=3)
            self.addCleanup(stop_peer)
            self.peer_bundle = Path(self.cfg["registryRoot"]) / ("b" * 64) / "epochs/1/bundle"
            self.peer_bundle.mkdir(parents=True, mode=0o700)
            peer_oci = {**self.oci, "annotations": {"fixture": "independent-peer"}}
            self.write(self.peer_bundle / "config.json", a.canonical(peer_oci))
            self.extra_states = {"b" * 64: {"id": "b" * 64, "status": "created", "pid": peer_process.pid,
                                           "bundle": str(self.peer_bundle)}}
            peer_nic = {**nic, "bindingRef": "peer_nic", "ipv4": "10.10.0.3", "mac": "02:00:00:00:00:02"}
            declaration = {"containerId": "b" * 64, "applicationHash": a.sha(a.canonical(peer_oci)),
                           "networkBindings": [peer_nic]}
            self.transport["transport"][0]["peerIngress"] = {
                "kind": "CREATED_CANDIDATE", "declaration": declaration, "bindingRef": "peer_nic"}
            peer_child = {**child, "ifindex": 13, "link_index": host_index, "address": peer_nic["mac"],
                          "addr_info": [{"family": "inet", "local": peer_nic["ipv4"]}]}
            peer_host = {**host, "ifname": host_name, "ifindex": host_index, "link_index": 13}
            ip_body = "import sys\nprint(" + repr(json.dumps([host])) + " if sys.argv[-1]=='lo' else " + repr(json.dumps([peer_host])) + ")\n"
            peer_namespace = "--net=/proc/" + str(peer_process.pid) + "/ns/net"
            ns_body = "import sys\nprint(" + repr(json.dumps([peer_child])) + " if " + repr(peer_namespace) + " in sys.argv else " + repr(json.dumps([child])) + ")\n"
        ip = self.script("ip", ip_body)
        ns = self.script("nsenter", ns_body)
        self.frame_marker = self.root / "frame-marker"
        self.write(self.frame_marker, b"first")
        frame_code = """import json,sys,pathlib
r=json.load(sys.stdin)
v={'schema':'ouf.semantic-configured-created-frame.v1',
   'configuredPolicy':{'configuredPolicyConforms':True,'applicationHash':r['applicationHash'],
                       'marker':pathlib.Path(MARKER).read_text()},
   'sourceMountFrame':{'sourceByteHashesMatchExpected':True,'stableAcrossReads':True,'privateMaterialSpooled':False,
                       'mountObservation':{'effectiveReadOnlyFileBindingsObserved':True}},
   'policyAuthenticationProven':False,'rootfsSealProven':False,'imagePublisherProvenanceVerified':False,
   'completeCreationAccepted':False,'acceptanceGranted':False,'signaturesIssued':0,'startAuthorized':False}
print(json.dumps(v))
""".replace("MARKER", repr(str(self.frame_marker)))
        frame_source = self.document("observer.py", frame_code.encode())
        limits = {"maxEntries": 10, "maxBytes": 4096, "maxDepth": 4}
        self.cfg["rootfsLimits"] = limits
        self.cfg["framePolicyBinding"] = self.document("frame.json", a.canonical({"expectedOci": self.oci}))
        self.cfg["rootfsSealBinding"] = self.document("seal.json", a.canonical(
            observation.rootfs_seal(self.rootfs, limits, auth.VerificationBudget(18))))
        self.cfg["transportBinding"] = self.document("transport.json", a.canonical(self.transport))
        python = Path("/usr/bin/python3").resolve()
        self.cfg["creationFrameObserverBinding"] = {"python": {"path": str(python), "sha256": a.sha(python.read_bytes())},
            "source": frame_source, "configuration": self.cfg["framePolicyBinding"]}
        lock = self.root / "common.lock"
        self.write(lock, b"")
        template = {"schema": "ouf.semantic-admission-preparer-template.v1", "pythonPath": str(python), "pythonHash": "0" * 64,
                    "commands": {"ip": ip["path"], "nsenter": ns["path"]},
                    "commandHashes": {"ip": ip["sha256"], "nsenter": ns["sha256"]},
                    "candidate": {**self.transport, "containerId": CID, "transactionId": "8" * 64, "runtimeBinding": self.runc},
                    "kernel": {}, "dns": {}, "coordinationBinding": {}, "coordinationJournal": str(self.root / "unused"),
                    "lockFile": str(lock), "budgetSeconds": 18, "hostNetworkNamespace": "/proc/1/ns/net"}
        self.cfg["preparerTemplate"] = self.document("template.json", a.canonical(template))
        self.cfg["operation"] = {"authorizationRoot": str(self.chain), "anchorBinding": self.anchor,
            "mandateRoot": str(self.ledger_root), "opensslBinding": self.ssl,
            "mandatesModule": self.document("mandates.py", (ROOT / "tools/semantic_authority_mandates/mandates.py").read_bytes())}
        self.raw = a.canonical(self.cfg)
        self.configuration_path = self.root / "configuration.json"
        self.write(self.configuration_path, self.raw)
        payload = json.loads(self.payload())
        payload["roles"]["adapter"].update(admissionConfigurationSha256=a.sha(self.raw),
            framePolicySha256=self.cfg["framePolicyBinding"]["sha256"], rootfsSealSha256=self.cfg["rootfsSealBinding"]["sha256"],
            transportSha256=self.cfg["transportBinding"]["sha256"])
        self.operation_raw = self.put(1, a.canonical(payload))
        self.epoch = 1
        self.publish_epoch("OPENING")
        self.preparer = Mock()
        self.preparer.prepare.side_effect = self.prepared

    def document(self, name, raw):
        path = self.root / name
        self.write(path, raw)
        return {"path": str(path), "sha256": a.sha(raw)}

    def script(self, name, body):
        result = self.document(name, ("#!/usr/bin/python3\n" + body).encode())
        Path(result["path"]).chmod(0o700)
        return result

    def publish_epoch(self, state, **changes):
        base = Path(self.cfg["registryRoot"]) / CID
        self.epoch_root = base / "epochs" / str(self.epoch)
        self.epoch_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        for path in (Path(self.cfg["registryRoot"]), base, base / "epochs", self.epoch_root):
            path.chmod(0o700)
        bundle = self.epoch_root / "bundle"
        bundle.mkdir(mode=0o700, exist_ok=True)
        self.write(bundle / "config.json", a.canonical(self.oci))
        self.state = {"id": CID, "bundle": str(bundle), "status": "created", "pid": os.getpid()}
        self.write(self.root / "runc-state.json", a.canonical({CID: self.state, **self.extra_states}))
        journal = {"schema": self.e.JOURNAL_SCHEMA, "containerId": CID, "epoch": self.epoch,
            "bootId": self.e.boot_id(), "authorizationSha256": a.sha(self.operation_raw), "configurationHash": "2" * 64,
            "state": state, "runtimeRoot": str(self.runtime_root), "bundleHash": a.sha(a.canonical(self.oci)),
            "driverHash": None, "generation": None, "openedAt": 1500, "failure": None}
        journal.update(changes)
        raw = a.canonical(journal)
        self.write(self.epoch_root / "adapter.json", raw)
        self.write(base / "current", a.canonical({"epoch": self.epoch, "journalSha256": a.sha(raw)}))

    def broker(self, phase, **args_changes):
        args = {"container_id": CID, "epoch": self.epoch, "bundle": str(self.epoch_root / "bundle"),
                "runtime_root": str(self.runtime_root), "mode": phase}
        args.update(args_changes)
        cfg, raw = b.load(self.configuration_path)
        return b.Broker(cfg, raw, self.configuration_path, types.SimpleNamespace(**args), self.preparer, self.clock)

    def prepared(self, request, state):
        self.assertEqual(Path(request["epochRoot"]), self.epoch_root)
        driver = {"schema": "test-only-port-result", "binding": request["binding"], "evidenceBinding": request["evidenceBinding"]}
        digest = ev.write_exclusive(self.epoch_root / "driver.json", driver)
        return {"binding": request["binding"], "evidenceHash": request["evidenceBinding"]["sha256"], "driverHash": digest}

    def through_prepare(self):
        gate = self.broker("authorize-create")
        # Patch the only potentially available issuance class; the others must not load.
        module = sys.modules["tools.semantic_provider_deployment_producer"]
        with patch.object(module, "LocalEvidenceProducer", side_effect=AssertionError("issuance forbidden")):
            gate.operate({"id": CID, "bundleHash": a.sha(a.canonical(self.oci))})
        for mode, phase in (("record-created", "CREATING"), ("cohort-ready", "CREATED"), ("prepare", "PREPARING")):
            self.publish_epoch(phase)
            gate = self.broker(mode)
            module = sys.modules["tools.semantic_provider_deployment_producer"]
            with patch.object(module, "LocalEvidenceProducer", side_effect=AssertionError("issuance forbidden")):
                gate.operate(self.state)
        for name in ("semantic_provider_deployment_signing", "semantic_provider_installer_approval", "semantic_provider_node_attestor"):
            self.assertNotIn("tools." + name, sys.modules)
        return gate

    def test_all_modes_and_new_epoch_without_reissuing_authority(self):
        self.now = 5000  # durable authorization survives the issuance mandate window
        gate = self.through_prepare()
        self.assertEqual(gate.record()["state"], "PROTECTED")
        self.assertEqual(gate.gate.record()["state"], "READY")
        self.publish_epoch("DELETING")
        gate = self.broker("cleanup")
        gate.operate({})
        self.assertEqual(gate.record()["state"], "CLEANED")
        self.preparer.cleanup.assert_called_once()
        with self.assertRaises(a.OperationDenied):
            gate.operate({})
        self.epoch = 2
        self.publish_epoch("OPENING")
        next_gate = self.through_prepare()
        self.assertEqual(next_gate.binding["configurationHash"], gate.binding["configurationHash"])
        self.assertEqual(next_gate.binding["authorizationSha256"], gate.binding["authorizationSha256"])
        self.assertNotEqual(next_gate.root, gate.root)

    def test_replay_runtime_state_and_epoch_binding_denials(self):
        gate = self.broker("authorize-create")
        request = {"id": CID, "bundleHash": a.sha(a.canonical(self.oci))}
        gate.operate(request)
        with self.assertRaises(a.OperationDenied):
            self.broker("authorize-create").operate(request)
        self.publish_epoch("CREATING")
        gate = self.broker("record-created")
        with self.assertRaisesRegex(a.OperationDenied, "BROKER_LIVE_CREATED_STATE_DRIFT"):
            gate.operate({**self.state, "pid": os.getpid() + 1})
        self.publish_epoch("CREATED", bootId="6dc087ac-1111-4222-8333-000000000000")
        with self.assertRaisesRegex(a.OperationDenied, "BROKER_CURRENT_EPOCH_DRIFT"):
            self.broker("cohort-ready")
        self.publish_epoch("CREATED")
        for change in ({"epoch": 2}, {"bundle": "/wrong"}, {"container_id": "b" * 64},
                       {"runtime_root": "/outside"}, {"mode": "prepare"}):
            with self.subTest(change=change), self.assertRaises(a.OperationDenied):
                self.broker("cohort-ready", **change)

    def test_live_frame_and_revocation_at_start(self):
        gate = self.through_prepare()
        callback = sealed_authorizer_v2(head_reader=gate.head, binding=gate.binding,
            evidence_binding={"path": str(self.epoch_root / "evidence.json"), "sha256": gate.gate.record()["evidenceHash"]},
            creation_frame_observer_binding=self.cfg["creationFrameObserverBinding"], bundle=self.state["bundle"], budget=gate.budget)
        self.assertTrue(callback())
        self.write(self.frame_marker, b"changed")
        with self.assertRaisesRegex(a.OperationDenied, "LATE_CREATED_FRAME_DRIFT"):
            callback()
        self.write(self.frame_marker, b"first")
        self.append([{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900 + 60 * operation_tests.DAY, "state": "REVOKED"}])
        self.now = 1600
        with self.assertRaisesRegex(a.OperationDenied, "OPERATION_KEY_REVOKED"):
            callback()

    def test_custody_source_pin_and_exclusive_evidence(self):
        gate = self.through_prepare()
        value = a.decode(b.private(self.epoch_root / "evidence.json"))
        self.assertEqual((self.epoch_root / "evidence.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            ev.write(self.epoch_root / "evidence.json", value)
        path = self.source / next(iter(b.SOURCES))
        self.write(path, path.read_bytes() + b"\n")
        with self.assertRaisesRegex(a.OperationDenied, "BROKER_BOUND_FILE_DRIFT"):
            self.broker("prepare")

    def test_initial_pair_and_partial_are_never_repaired(self):
        gate = self.broker("authorize-create")
        with gate.lock():
            gate.stage_locked()
            gate.stage_locked()  # identical unused STAGED pair is accepted
        gate.operate({"id": CID, "bundleHash": a.sha(a.canonical(self.oci))})
        self.epoch = 2
        self.publish_epoch("OPENING")
        gate = self.broker("authorize-create")
        ev.write_exclusive(self.epoch_root / "deployment.json", gate.gate.initial())
        before = (self.epoch_root / "deployment.json").read_bytes()
        with self.assertRaisesRegex(a.OperationDenied, "DO_NOT_REPLAY_DEPLOYMENT_CREATE"):
            gate.operate({"id": CID, "bundleHash": a.sha(a.canonical(self.oci))})
        self.assertEqual((self.epoch_root / "deployment.json").read_bytes(), before)
        self.assertFalse((self.epoch_root / "broker-state.json").exists())

    def test_peer_bundle_and_live_observations(self):
        gate = self.through_prepare()
        self.assertEqual(gate.record()["state"], "PROTECTED")
        self.write(self.peer_bundle / "config.json", a.canonical({**self.oci, "annotations": {"fixture": "tampered"}}))
        with self.assertRaisesRegex(ValueError, "PEER_COMPLETE_OCI_DRIFT"):
            ev.observe(container_id=CID, epoch=self.epoch, authorization_sha256=gate.binding["authorizationSha256"],
                authorization_role=gate.role, bound_documents=gate.bound, bundle=self.state["bundle"],
                registry_root=self.cfg["registryRoot"], runtime_root=str(self.runtime_root),
                runtime_root_parent=self.cfg["runtimeRootParent"], runtime_binding=self.runc, commands=gate.commands(),
                rootfs_limits=self.cfg["rootfsLimits"], creation_frame_observer_binding=self.cfg["creationFrameObserverBinding"],
                budget=gate.budget, clock=self.clock)


if __name__ == "__main__":
    unittest.main()
