"""v7 contracts plus gated root-native broker/preparer/hook integration."""
import ast
import copy
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_operation import authorization as a
from tools.semantic_provider_admission_v2 import broker_v2 as b, driver_v7 as d, preparer_v2 as p

spec = importlib.util.spec_from_file_location("admission_part_a_fixture", ROOT / "tests/test_semantic_provider_admission_v2.py")
part_a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(part_a)


def grant():
    binding, _, _, _, _ = part_a.fixture()
    root = "/registry/" + binding["containerId"] + "/epochs/1"
    bound = {"path": "/private/file", "sha256": "a" * 64}
    return {"schema": d.SCHEMA, "sourceRoot": "/source", "sourceHashes": {k: "a" * 64 for k in b.SOURCES},
        "operationBinding": {k: binding[k] for k in ("authorizationSha256", "epoch", "containerId", "configurationHash")},
        "operation": {**part_a.configuration()["operation"], "installationRef": binding["installationRef"],
                      "entityRef": binding["entityRef"], "issuerRef": "installer"},
        "evidenceBinding": {**bound, "path": root + "/evidence.json"}, "consumptionJournal": root + "/deployment.json",
        "creationFrameObserverBinding": {k: bound for k in ("python", "source", "configuration")},
        "profile": {"schema": "ouf.semantic-preexec-profile.v2", "transactionId": d.correlation(binding),
            "containerId": binding["containerId"], "bundlePath": root + "/bundle", "bundleHash": "a" * 64,
            "namespacePath": root + "/netns", "namespaceInode": 123, "namespaceOrigin": "OCI_CREATED",
            "namespaceLinks": [], "policy": {}, "expectedFootprint": "b" * 64,
            "applicationStartAuthorized": True, "infrastructureAuthorityComplete": True},
        "kernel": {}, "dns": {}, "coordinationBinding": {k: "c" * 64 for k in
            ("transactionId", "configurationHash", "leaseStructureHash")}, "coordinationJournal": "/private/lease.json",
        "preexecJournal": root + "/preexec.json", "lockFile": "/private/common.lock",
        "commands": {k: "/bin/" + k for k in ("nft", "ip", "nsenter")}, "budgetSeconds": 5,
        "runtimeBinding": {**bound, "root": "/run/runtime"}}


class ContractTests(unittest.TestCase):
    def test_driver_consumes_under_common_lock_and_rollback_skips_authority(self):
        value = grant()
        binding, head, _, _, evidence = part_a.fixture()
        value["evidenceBinding"]["sha256"] = a.sha(a.canonical(evidence))
        raw = a.canonical(value)
        journal = part_a.MemoryJournal()
        locked = False
        @contextmanager
        def lock():
            nonlocal locked
            self.assertFalse(locked)
            locked = True
            try:
                yield
            finally:
                locked = False
        receipt = part_a.EpochConsumption(binding, journal, lock)
        journal.value = receipt.initial()
        receipt.authorize_create(head)
        receipt.created(evidence["bundleHash"], part_a.GEN)
        with lock():
            receipt.ready_locked(evidence)
            receipt.seal_driver_locked(a.sha(raw))
        backend = Mock(deadline=time.monotonic() + 4)
        state = {"status": "created"}
        backend.runtime.side_effect = lambda binding, mode: state if mode == "state" else self.assertTrue(locked)
        gate = Mock()
        gate.coord.hold_lock = lock
        def before(state, starter=None, authorizer=None, consume=None):
            with lock():
                authorizer()
                if starter is not None:
                    consume(part_a.GEN, starter)
            return {"protectedBeforeProcess": True}
        gate.before_process.side_effect = before
        operation = Mock(binding=binding)
        operation.authorizer.return_value = Mock(side_effect=lambda: self.assertTrue(locked))
        with part_a.libraries():
            from tools import semantic_provider_lease_coordination as coordination, semantic_provider_deployment_producer as producer
            from tools import semantic_provider_deployment_admission as admission
            with patch.object(d, "components", return_value=(gate, backend)), patch.object(d, "Operation", return_value=operation) as constructor, \
                    patch.object(b, "verify_sources"), \
                    patch.object(b, "private", return_value=raw), patch.object(coordination, "PrivateJournal", return_value=journal), \
                    patch.object(producer, "LocalEvidenceProducer", side_effect=AssertionError("issuance forbidden")), \
                    patch.object(admission, "authority", side_effect=AssertionError("legacy authority forbidden")):
                d.operate(value, raw, "/grant", "hook", state)
                self.assertEqual(receipt.record()["state"], "READY")
                d.operate(value, raw, "/grant", "start")
                self.assertEqual(receipt.record()["state"], "STARTED")
                with self.assertRaisesRegex(a.OperationDenied, "DO_NOT_REPLAY_DEPLOYMENT_START"):
                    d.operate(value, raw, "/grant", "start")
                constructor.reset_mock()
                d.operate(value, raw, "/grant", "rollback")
                constructor.assert_not_called()
                gate.operate.assert_called_once_with("rollback")

    def test_peer_recollection_rejects_transport_and_generation_drift(self):
        value = grant()
        peer_id = "b" * 64
        nic = {"interface": "eth0", "bridge": "br_test", "mac": "02:00:00:00:00:02", "ipv4": "10.10.0.3",
               "workloadRef": "peer", "bindingRef": "peer_nic"}
        declaration = {"containerId": peer_id, "applicationHash": "2" * 64, "networkBindings": [nic]}
        policy = {"tableName": "ouf_test", "networkBindings": [], "transport": [{"purpose": "DNS", "authorityRef": "dns",
            "source": "10.10.0.2", "destination": "10.10.0.3", "protocol": "udp", "port": 53,
            "peerIngress": {"kind": "CREATED_CANDIDATE", "declaration": declaration, "bindingRef": "peer_nic"}}]}
        snapshot = {"containerId": peer_id, "applicationHash": "2" * 64, "generation": part_a.GEN,
                    "bindings": [{**nic, "hostIfindex": 20}]}
        value["peerBinding"] = {"declaredPolicy": policy, "observations": {peer_id: snapshot},
            "commandBindings": {k: {"path": value["commands"][k], "sha256": "a" * 64} for k in ("ip", "nsenter")}}
        with part_a.libraries():
            from tools import semantic_provider_peer_bindings as peer
            value["profile"]["policy"] = {"tableName": "ouf_test", "flows": peer.resolve(policy["transport"],
                [declaration], {peer_id: snapshot}, part_a.CID)}
            d.validate(a.canonical(value))
            with patch.object(peer, "collect", return_value=snapshot) as collect:
                d.verify_peers(value, peer.digest(policy), Mock(), Mock())
                self.assertEqual(collect.call_count, 1)
                with self.assertRaisesRegex(a.OperationDenied, "PEER_DRIVER_TRANSPORT_SCOPE_DRIFT"):
                    d.verify_peers(value, "0" * 64, Mock(), Mock())
                collect.return_value = {**snapshot, "generation": {**part_a.GEN, "startTicks": 999}}
                with self.assertRaisesRegex(a.OperationDenied, "PEER_GENERATION_OR_LINK_CHANGED"):
                    d.verify_peers(value, peer.digest(policy), Mock(), Mock())

    def test_closed_grant_and_each_binding(self):
        value = grant()
        self.assertEqual(d.validate(a.canonical(value)), value)
        for key in value:
            bad = copy.deepcopy(value)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(Exception):
                d.validate(a.canonical(bad))
        for key in ("extra", "authorityBinding", "authorityScope", "consumptionBinding", "authenticationBinding"):
            with self.subTest(extra=key), self.assertRaises(a.OperationDenied):
                d.validate(a.canonical({**value, key: {}}))
        cases = [("operationBinding", "epoch", True), ("operationBinding", "configurationHash", "bad"),
                 ("operationBinding", "containerId", "b" * 64), ("operationBinding", "epoch", 2),
                 ("profile", "transactionId", "0" * 64), ("profile", "schema", "ouf.semantic-preexec-profile.v1"),
                 ("runtimeBinding", "root", "/bad/../root"), ("evidenceBinding", "path", "/other/evidence.json")]
        for section, key, datum in cases:
            bad = copy.deepcopy(value)
            bad[section][key] = datum
            with self.subTest(section=section, key=key), self.assertRaises(a.OperationDenied):
                d.validate(a.canonical(bad))
        for section in ("operationBinding", "operation", "evidenceBinding", "runtimeBinding", "profile", "creationFrameObserverBinding"):
            bad = copy.deepcopy(value)
            bad[section]["extra"] = True
            with self.subTest(nested=section), self.assertRaises(a.OperationDenied):
                d.validate(a.canonical(bad))
        with self.assertRaises(a.OperationDenied):
            d.validate(a.canonical(value) + b"\n")

    def test_subprocess_exact_request_state_and_result(self):
        request = {"epochRoot": "/epoch", "binding": {"epoch": 1}, "evidenceBinding": {"sha256": "e" * 64},
                   "template": {"pythonPath": "/bin/python", "pythonHash": "f" * 64},
                   "configurationBinding": {"path": "/configuration", "sha256": "c" * 64}}
        cfg = part_a.configuration()
        cfg["sourceRoot"] = "/explicit-pinned-package"
        state = {"id": "a" * 64, "status": "created"}
        good = {"binding": request["binding"], "evidenceHash": "e" * 64, "driverHash": "d" * 64}
        responses = [good, {**good, "extra": True}, {**good, "binding": {}}, {**good, "evidenceHash": "0" * 64},
                     {**good, "driverHash": "invalid"}, {"state": "WRONG"}]
        with part_a.libraries():
            from tools import semantic_provider_deployment_producer as producer
            self.enterContext(patch.object(b, "read_binding", return_value=a.canonical(cfg)))
            checked = self.enterContext(patch.object(b, "verify_sources"))
            for response in responses:
                def run(argv, **kwargs):
                    self.assertEqual(argv[0:3], ["/bin/python", "-I", "-B"])
                    self.assertEqual(Path(argv[3]), Path(cfg["sourceRoot"]) / b.ENTRYPOINTS[1])
                    self.assertEqual(argv[-4:], ["--configuration", "/epoch/preparer.json", "--mode", "prepare"])
                    self.assertEqual(kwargs["input"], a.canonical(state))
                    self.assertEqual(b.private("/epoch/preparer.json"), a.canonical(request))
                    kwargs["stdout"].write(a.canonical(response) + b"\n")
                    return types.SimpleNamespace(returncode=0)
                with patch.object(b, "private", return_value=a.canonical(request)), \
                        patch.object(producer, "program", return_value="/bin/python"), patch.object(b.subprocess, "run", side_effect=run):
                    if response == good:
                        self.assertEqual(b.SubprocessPreparer().prepare(request, state), good)
                    else:
                        with self.assertRaises(a.OperationDenied):
                            b.SubprocessPreparer().prepare(request, state)
            for raw, status in ((b"not-json\n", 0), (a.canonical(good), 0), (b"", 1), (b"x" * 131073, 0)):
                def run(argv, **kwargs):
                    kwargs["stdout"].write(raw)
                    return types.SimpleNamespace(returncode=status)
                with patch.object(b, "private", return_value=a.canonical(request)), \
                        patch.object(producer, "program", return_value="/bin/python"), patch.object(b.subprocess, "run", side_effect=run), \
                        self.assertRaises(Exception):
                    b.SubprocessPreparer().prepare(request, state)
            def cleanup(argv, **kwargs):
                self.assertEqual(argv[-1], "cleanup")
                self.assertIsNone(kwargs["input"])
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                kwargs["stdout"].write(b'{"state":"CLEANED"}\n')
                return types.SimpleNamespace(returncode=0)
            with patch.object(b, "private", return_value=a.canonical(request)), \
                    patch.object(producer, "program", return_value="/bin/python"), patch.object(b.subprocess, "run", side_effect=cleanup):
                self.assertEqual(b.SubprocessPreparer().cleanup(request), {"state": "CLEANED"})
            self.assertTrue(checked.called)
            checked.side_effect = a.OperationDenied("BROKER_SOURCE_PACKAGE_DRIFT")
            with patch.object(b, "private", return_value=a.canonical(request)), \
                    patch.object(producer, "program", return_value="/bin/python"), \
                    patch.object(b.subprocess, "run") as denied, \
                    self.assertRaisesRegex(a.OperationDenied, "BROKER_SOURCE_PACKAGE_DRIFT"):
                b.SubprocessPreparer().prepare(request, state)
            denied.assert_not_called()

    def test_no_issuance_and_public_cli_errors(self):
        forbidden = {"LocalEvidenceProducer", "ExistingEd25519Signer", "InstallerApproval", "NodeAttestor"}
        for path in [*(ROOT / "tools/semantic_provider_admission_v2").glob("*.py"),
                     *(ROOT / entry for entry in b.ENTRYPOINTS)]:
            raw = path.read_text(encoding="utf-8")
            self.assertFalse(any(name in raw for name in forbidden), path.name)
            for node in ast.walk(ast.parse(raw)):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.assertNotIn("semantic_provider_deployment_signing", ast.unparse(node))
                if isinstance(node, ast.Call):
                    self.assertNotIn(getattr(node.func, "attr", None), {"emit", "sign"})
                if path.parent.name == "scripts" and isinstance(node, ast.Attribute):
                    self.assertFalse(isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "path")
        for module in (p, d):
            output = io.StringIO()
            with patch("sys.stderr", output), patch.object(module.os, "geteuid", return_value=1, create=True):
                self.assertEqual(module.main(["--configuration", "/SECRET", "--mode", "prepare" if module is p else "start"]), 1)
            self.assertIn("=DENIED", output.getvalue())
            self.assertNotIn("SECRET", output.getvalue())


class SourceClosureTests(unittest.TestCase):
    def entry(self, relative):
        spec = importlib.util.spec_from_file_location("bootstrap_fixture", ROOT / relative)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def source_bytes(self):
        legacy = {"tools/" + name + ".py" for name in b.MODULES}
        return {relative: ((part_a.SOURCE if relative in legacy else ROOT) / relative).read_bytes()
                for relative in b.SOURCES}

    def test_exact_manifest_in_all_entrypoints_and_schemas(self):
        expected = (set(b.ENTRYPOINTS) | {"tools/" + name + ".py" for name in b.MODULES}
                    | {str(path.relative_to(ROOT).as_posix())
                       for path in (ROOT / "tools/semantic_provider_admission_v2").glob("*.py")}
                    | {"tools/semantic_provider_operation/authorization.py", "tools/semantic_provider_operation/epochs.py"})
        self.assertEqual(b.SOURCES, expected)
        bootstraps = []
        for relative in b.ENTRYPOINTS:
            entry = self.entry(relative)
            self.assertEqual(entry.SOURCES, expected)
            self.assertEqual(entry.MODULES, b.MODULES)
            self.assertEqual(entry.V2_MODULES, b.V2_MODULES)
            tree = ast.parse((ROOT / relative).read_bytes())
            tree.body = [node for node in tree.body if not (isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id in {"SELF", "TARGET"}
                                 for target in node.targets))]
            bootstraps.append(ast.dump(tree, include_attributes=False))
        self.assertEqual(len(set(bootstraps)), 1)
        for make, validate in ((part_a.configuration, b.validate), (grant, d.validate)):
            for change in ("extra", "missing", "invalid"):
                value = make()
                if change == "extra":
                    value["sourceHashes"]["tools/extra.py"] = "a" * 64
                elif change == "missing":
                    del value["sourceHashes"][b.ENTRYPOINTS[0]]
                else:
                    value["sourceHashes"][b.ENTRYPOINTS[0]] = "INVALID"
                with self.subTest(schema=value["schema"], change=change), self.assertRaises(a.OperationDenied):
                    validate(a.canonical(value))

    def test_entrypoints_verify_every_byte_before_any_application_exec(self):
        sources = self.source_bytes()
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            for relative in b.ENTRYPOINTS:
                entry = self.entry(relative)
                cfg = grant() if entry.TARGET == "driver_v7" else part_a.configuration()
                cfg.update(sourceRoot=str(root), sourceHashes={p: a.sha(raw) for p, raw in sources.items()})
                config = root / "configuration.json"
                request = root / "preparer.json"
                files = {str(root / p): raw for p, raw in sources.items()}
                files[str(config)] = a.canonical(cfg)
                if entry.TARGET == "preparer_v2":
                    files[str(request)] = a.canonical({"configurationBinding":
                        {"path": str(config), "sha256": a.sha(files[str(config)])}})
                input_path = request if entry.TARGET == "preparer_v2" else config
                with patch.object(entry, "__file__", str(root / relative)), \
                        patch.object(entry, "private_root"), \
                        patch.object(entry, "private", side_effect=lambda path: files[str(Path(path))]), \
                        patch.object(entry, "execute") as execute:
                    entry.bootstrap(input_path)
                    self.assertEqual(execute.call_args.args, (root, sources))
                    execute.reset_mock()
                    # Mutation happens after the canonical configuration was decoded.
                    for changed in sorted(b.SOURCES):
                        original_decode = entry.decode
                        def decode_then_mutate(raw):
                            value = original_decode(raw)
                            if "sourceHashes" in value:
                                files[str(root / changed)] = sources[changed] + b"\nraise AssertionError('UNVERIFIED')\n"
                            return value
                        with self.subTest(entry=relative, changed=changed), \
                                patch.object(entry, "decode", side_effect=decode_then_mutate), \
                                self.assertRaisesRegex(RuntimeError, "BROKER_SOURCE_PACKAGE_DRIFT"):
                            entry.bootstrap(input_path)
                        execute.assert_not_called()
                        files[str(root / changed)] = sources[changed]
                    for change in ("extra", "missing"):
                        bad = copy.deepcopy(cfg)
                        if change == "extra":
                            bad["sourceHashes"]["tools/extra.py"] = "a" * 64
                        else:
                            del bad["sourceHashes"][b.ENTRYPOINTS[0]]
                        files[str(config)] = a.canonical(bad)
                        if entry.TARGET == "preparer_v2":
                            files[str(request)] = a.canonical({"configurationBinding":
                                {"path": str(config), "sha256": a.sha(files[str(config)])}})
                        with self.subTest(entry=relative, change=change), \
                                self.assertRaisesRegex(RuntimeError, "EXACT_BROKER_SOURCE_SET_REQUIRED"):
                            entry.bootstrap(input_path)
                        execute.assert_not_called()
                    files[str(config)] = a.canonical(cfg)
                    if entry.TARGET == "preparer_v2":
                        files[str(request)] = a.canonical({"configurationBinding":
                            {"path": str(config), "sha256": a.sha(files[str(config)])}})
                    with patch.object(entry, "__file__", str(root / "wrong-entry.py")), \
                            self.assertRaisesRegex(RuntimeError, "BROKER_ENTRYPOINT_PATH_DRIFT"):
                        entry.bootstrap(input_path)
                    execute.assert_not_called()

    def test_compiles_snapshot_with_empty_package_search_locations(self):
        sources = self.source_bytes()
        for relative in b.ENTRYPOINTS:
            entry = self.entry(relative)
            # No filesystem imports are available through these package paths.
            with self.subTest(entry=relative), patch.dict(sys.modules):
                if sys.platform != "linux":
                    sys.modules["fcntl"] = types.ModuleType("fcntl")
                module = entry.execute(Path("/verified-snapshot"), sources)
                self.assertEqual(module.__name__, "tools.semantic_provider_admission_v2." + entry.TARGET)
                for package in ("tools", "tools.semantic_provider_operation", "tools.semantic_provider_admission_v2"):
                    self.assertEqual(sys.modules[package].__path__, [])
                self.assertIs(sys.modules["authorization"], sys.modules["tools.semantic_provider_operation.authorization"])
                self.assertEqual(sys.modules["tools.semantic_provider_operation.epochs"].sha,
                                 sys.modules["authorization"].sha)

    def test_rechecks_after_loading_for_broker_preparer_and_hook(self):
        cfg = part_a.configuration()
        sources = self.source_bytes()
        cfg["sourceHashes"] = {p: a.sha(raw) for p, raw in sources.items()}
        root = Path(cfg["sourceRoot"])
        files = {str(root / p): raw for p, raw in sources.items()}
        info = types.SimpleNamespace(st_mode=0o40700, st_uid=0, st_gid=0)
        with patch.object(Path, "lstat", return_value=info), \
                patch.object(b, "private", side_effect=lambda path: files[str(Path(path))]):
            self.assertEqual(b.verify_sources(cfg), sources)
            files[str(root / "tools/semantic_provider_operation/authorization.py")] += b"\n"
            worker = p.Worker.__new__(p.Worker)
            worker.cfg, worker.budget = cfg, Mock()
            broker = b.Broker.__new__(b.Broker)
            broker.cfg, broker.budget = cfg, Mock()
            broker.path, broker.raw = "/configuration", a.canonical(cfg)
            broker.template_raw = b"template"
            broker.bound = {}
            files[str(Path(broker.path))] = broker.raw
            files[str(Path(cfg["preparerTemplate"]["path"]))] = broker.template_raw
            # The template binding is irrelevant to source drift; keep it valid.
            cfg["preparerTemplate"]["sha256"] = a.sha(broker.template_raw)
            for check in (broker.stable, worker.stable, lambda: d.operate(cfg, b"grant", "/grant", "rollback")):
                with self.assertRaisesRegex(a.OperationDenied, "BROKER_SOURCE_PACKAGE_DRIFT"):
                    check()


# No reusable fake nft executable exists in semantic_transaction_profiles or the
# vendored preexec native tests. This CLI models tables/empty timeout sets, with
# independent per-network-namespace storage. It NEVER executes nft or ip.
FAKE_NFT = r'''import json,os,pathlib,re,sys
base=pathlib.Path(BASE)
path=base/('nft-'+str(os.stat('/proc/self/ns/net').st_ino)+'.json')
tables=json.loads(path.read_text()) if path.exists() else json.loads(SEED)
args=sys.argv[1:]
if args[-2:]==['list','tables']:
    print(json.dumps({'nftables':[{'table':{'family':k.split(':')[0],'name':k.split(':')[1]}} for k in sorted(tables)]}))
elif 'list' in args and 'table' in args:
    print(json.dumps(tables[args[-2]+':'+args[-1]]))
elif args==['-f','-']:
    raw=sys.stdin.read()
    for family,name in re.findall(r'delete table (inet|bridge) (\w+)',raw):
        del tables[family+':'+name]
    for match in re.finditer(r'(?m)^table (inet|bridge) (\w+) \{',raw):
        end=match.end(); depth=1
        while depth:
            depth+=(raw[end]=='{')-(raw[end]=='}'); end+=1
        family,name=match.groups()
        tables[family+':'+name]={'nftables':[{'table':{'family':family,'name':name}},
            {'rule':{'family':family,'table':name,'fixtureText':raw[match.end():end-1]}}]}
    path.write_text(json.dumps(tables))
else:
    raise SystemExit(2)
'''


class NativeTests(part_a.NativeTests):
    __unittest_skip__ = not part_a.NATIVE
    __unittest_skip_why__ = "set OUF_ADMISSION_V2_NATIVE=1 under Linux root"

    # Only the tests below belong to part B; inherited part A methods are already
    # executed by their own CI step and require their synthetic port.
    def setUp(self):
        super().setUp()
        from tools.semantic_provider_lease_nft import structure_hash
        self.process = subprocess.Popen(["/usr/bin/python3", "-c", "import time; time.sleep(120)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_generation)
        self.started = self.root / "started"
        self.runc = self.script("runc", "import json,pathlib,sys\n"
            "p=pathlib.Path(" + repr(str(self.root / "runc-state.json")) + ")\n"
            "if 'start' in sys.argv: pathlib.Path(" + repr(str(self.started)) + ").write_text('started')\n"
            "else:\n d=json.loads(p.read_text()); print(json.dumps(list(d.values()) if 'list' in sys.argv else d[sys.argv[-1]]))\n")
        self.host_index, self.host_name = next((i, n) for i, n in socket.if_nameindex() if i > 1)
        host = {"ifname": self.host_name, "ifindex": self.host_index, "link_index": 12, "master": "br_test"}
        child = {"ifname": "eth0", "ifindex": 12, "link_index": self.host_index,
                 "address": "02:00:00:00:00:01", "addr_info": [{"family": "inet", "local": "10.10.0.2"}]}
        ip = self.script("ip", "print(" + repr(json.dumps([host])) + ")\n")
        ns = self.script("nsenter", "print(" + repr(json.dumps([child])) + ")\n")
        kernel = {"tableName": "ouf_fixture_lease", "guardedInterfaces": ["br_lease"], "existingInterfaces": [], "staticFlows": [],
            "providerFlows": [{"endpointRef": "fixture", "endpoint": "https://provider.example", "source": "10.20.0.2",
                               "addresses": [], "leaseSeconds": 60, "resolutionEvidenceRef": "fixture_dns", "allowedPrivateAddresses": []}]}
        lease_tables = {f: {"nftables": [{"table": {"family": f, "name": kernel["tableName"]}},
            {"set": {"family": f, "table": kernel["tableName"], "name": "provider_0", "type": "ipv4_addr", "flags": ["timeout"]}}]}
            for f in ("inet", "bridge")}
        seed = {f + ":" + kernel["tableName"]: table for f, table in lease_tables.items()}
        nft = self.script("nft", FAKE_NFT.replace("BASE", repr(str(self.root))).replace("SEED", repr(json.dumps(seed))))
        template = a.decode(Path(self.cfg["preparerTemplate"]["path"]).read_bytes())
        commands = {"nft": nft, "ip": ip, "nsenter": ns}
        for key in ("mount", "umount", "unshare"):
            executable = Path(shutil.which(key)).resolve(strict=True)
            commands[key] = {"path": str(executable), "sha256": a.sha(executable.read_bytes())}
        template.update(commands={k: v["path"] for k, v in commands.items()},
            commandHashes={k: v["sha256"] for k, v in commands.items()}, kernel=kernel,
            pythonHash=a.sha(Path(template["pythonPath"]).read_bytes()), budgetSeconds=5,
            hostNetworkNamespace=os.stat("/proc/self/ns/net").st_ino,
            dns={"resolvers": ["10.20.0.53"], "resolverPort": 53, "timeoutSeconds": 1, "maxLeaseSeconds": 60, "applyBudgetSeconds": 1},
            coordinationBinding={"transactionId": "c" * 64, "configurationHash": a.sha(a.canonical(kernel)),
                                 "leaseStructureHash": structure_hash(lease_tables)},
            coordinationJournal=str(self.root / "coordination.json"))
        template["candidate"]["runtimeBinding"] = self.runc
        self.write(self.root / "coordination.json", a.canonical({"schema": "ouf.semantic-lease-coordination.v1",
            **template["coordinationBinding"], "state": "QUIESCED", "leaseAuthorized": False,
            "startAuthorized": False, "leaseAddresses": [[]]}))
        self.cfg["preparerTemplate"] = self.document("template.json", a.canonical(template))
        # Sentinels live in the disposable, hash-bound copy, including subprocesses.
        # The repository's pinned cohort-draft is never modified.
        for relative, suffix in {
            "tools/semantic_provider_deployment_producer.py": b"\ndef forbidden(*a, **k): raise AssertionError('issuance forbidden')\nLocalEvidenceProducer.__init__ = forbidden\n",
            "tools/semantic_provider_deployment_admission.py": b"\ndef authority(*a, **k): raise AssertionError('legacy authority forbidden')\n",
        }.items():
            source = self.source / relative
            self.write(source, source.read_bytes() + suffix)
            self.cfg["sourceHashes"][relative] = a.sha(source.read_bytes())
        self.raw = a.canonical(self.cfg)
        self.write(self.configuration_path, self.raw)
        payload = json.loads(self.payload())
        payload["roles"]["adapter"].update(admissionConfigurationSha256=a.sha(self.raw),
            framePolicySha256=self.cfg["framePolicyBinding"]["sha256"], rootfsSealSha256=self.cfg["rootfsSealBinding"]["sha256"],
            transportSha256=self.cfg["transportBinding"]["sha256"])
        self.operation_raw = self.put(1, a.canonical(payload))
        self.preparer = b.SubprocessPreparer()
        self.publish_epoch("OPENING")
        self.addCleanup(self.unmount_retained)

    def publish_epoch(self, state, **changes):
        super().publish_epoch(state, **changes)
        if hasattr(self, "process"):
            self.state["pid"] = self.process.pid
            self.write(self.root / "runc-state.json", a.canonical({part_a.CID: self.state}))

    def stop_generation(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=3)

    def unmount_retained(self):
        path = self.epoch_root / "netns"
        if path.exists() and os.path.ismount(path):
            subprocess.run([str(Path(shutil.which("umount")).resolve()), str(path)], check=True, timeout=3,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def hook(self, mode, good=True):
        result = subprocess.run([str(Path("/usr/bin/python3").resolve()), "-I", "-B",
            str(self.source / b.ENTRYPOINTS[2]), "--configuration", str(self.epoch_root / "driver.json"),
            "--mode", mode], input=a.canonical(self.state) if mode == "hook" else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(result.returncode, 0 if good else 1, result.stderr.decode())
        return result

    def test_real_preparation_start_replay_rollback_cleanup(self):
        gate = self.through_prepare()
        value = d.validate((self.epoch_root / "driver.json").read_bytes())
        self.assertEqual(value["schema"], d.SCHEMA)
        self.assertEqual((self.epoch_root / "driver.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.epoch_root / "preexec.json").read_bytes())["state"], "PROTECTED")
        self.hook("hook")
        self.hook("start")
        self.assertEqual(gate.gate.record()["state"], "STARTED")
        self.assertTrue(self.started.exists())
        self.hook("start", good=False)
        self.stop_generation()
        self.hook("rollback")
        self.publish_epoch("DELETING")
        self.broker("cleanup").operate({})
        self.assertEqual(json.loads((self.epoch_root / "admission.json").read_bytes())["state"], "CLEANED")
        self.assertFalse((self.epoch_root / "netns").exists())

    def test_revocation_between_prepare_and_start(self):
        gate = self.through_prepare()
        self.append([{"keyRef": "key-a", "notBefore": 1900, "expiresAt": 1900 + 60 * part_a.operation_tests.DAY, "state": "REVOKED"}])
        self.hook("start", good=False)
        self.assertFalse(self.started.exists())
        self.assertEqual(gate.gate.record()["state"], "READY")
        self.stop_generation()
        self.hook("rollback")  # no authorization even after revocation

    def test_frame_changed_before_start(self):
        gate = self.through_prepare()
        self.write(self.frame_marker, b"changed")
        self.hook("start", good=False)
        self.assertFalse(self.started.exists())
        self.assertEqual(gate.gate.record()["state"], "READY")

    def test_all_three_pinned_entrypoints_end_to_end(self):
        def broker_cli(mode, state):
            result = subprocess.run([str(Path("/usr/bin/python3").resolve()), "-I", "-B",
                str(self.source / b.ENTRYPOINTS[0]), "--configuration", str(self.configuration_path),
                "--container-id", part_a.CID, "--epoch", str(self.epoch),
                "--bundle", str(self.epoch_root / "bundle"), "--runtime-root", str(self.runtime_root), "--mode", mode],
                input=a.canonical(state), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=22)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        broker_cli("authorize-create", {"id": part_a.CID, "bundleHash": a.sha(a.canonical(self.oci))})
        for mode, phase in (("record-created", "CREATING"), ("cohort-ready", "CREATED"), ("prepare", "PREPARING")):
            self.publish_epoch(phase)
            broker_cli(mode, self.state)
        self.hook("start")
        self.assertEqual(a.decode((self.epoch_root / "deployment.json").read_bytes())["state"], "STARTED")
        self.stop_generation()
        self.hook("rollback")
        self.publish_epoch("DELETING")
        broker_cli("cleanup", {})
        self.assertEqual(a.decode((self.epoch_root / "admission.json").read_bytes())["state"], "CLEANED")

    def test_cli_source_drift_denied_before_any_changed_module_runs(self):
        request = self.document("request.json", a.canonical({"configurationBinding":
            {"path": str(self.configuration_path), "sha256": a.sha(self.raw)}}))
        value = {"schema": d.SCHEMA, "sourceRoot": self.cfg["sourceRoot"], "sourceHashes": self.cfg["sourceHashes"]}
        driver = self.document("unexecuted-grant.json", a.canonical(value))
        marker = self.root / "unverified-module-ran"
        changed = self.source / "tools/semantic_provider_operation/authorization.py"
        self.write(changed, changed.read_bytes() + ("\nfrom pathlib import Path\nPath(" + repr(str(marker))
                                                   + ").write_text('UNVERIFIED')\n").encode())
        for relative, configuration, mode, code in (
                (b.ENTRYPOINTS[0], str(self.configuration_path), "authorize-create", "SEMANTIC_DEPLOYMENT_BROKER"),
                (b.ENTRYPOINTS[1], request["path"], "prepare", "SEMANTIC_ADMISSION_PREPARER"),
                (b.ENTRYPOINTS[2], driver["path"], "start", "SEMANTIC_PREEXEC")):
            result = subprocess.run([str(Path("/usr/bin/python3").resolve()), "-I", "-B",
                str(self.source / relative), "--configuration", configuration, "--mode", mode],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, (code + "=DENIED\n").encode())
            self.assertEqual(result.stdout, b"")
            self.assertFalse(marker.exists())


# Avoid inheriting task-38a test methods into this separate native suite.
for _name in list(part_a.NativeTests.__dict__):
    if _name.startswith("test_"):
        setattr(NativeTests, _name, None)

if __name__ == "__main__":
    unittest.main()
