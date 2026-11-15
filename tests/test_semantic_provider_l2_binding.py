"""Portable D-037(a) checks against unchanged historical admission libraries."""
import copy
from contextlib import nullcontext
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_semantic_provider_admission_v2 as F
from tools.semantic_provider_admission_v2 import l2_binding as L, broker_v2 as B, evidence_v2 as E
from tools.semantic_provider_admission_v2 import preparer_v2 as P, driver_v7 as D

A, CID, GEN = F.a, F.CID, F.GEN
PEER = "b" * 64
MAC = "62:a3:21:47:8b:96"
NIC = dict(interface="eth0", ipv4="10.10.0.2", bridge="br_test", mac=L.L2_LIVE_MAC,
           workloadRef="provider", bindingRef="provider_nic")
COMMANDS = {k: {"path": "/" + k, "sha256": "a" * 64} for k in ("ip", "nsenter")}
RUNTIME = {"path": "/runc", "sha256": "b" * 64, "root": "/runtime/owned"}


def observation(cid=CID, nic=None, mac=MAC):
    return {"containerId": cid, "generation": copy.deepcopy(GEN), "bindings": [
        {**(nic or NIC), "mac": mac, "childIfindex": 12, "hostIfindex": 13, "hostInterface": "veth_test"}]}


def policy():
    return {"networkBindings": [copy.deepcopy(NIC)], "transport": [{"purpose": "DNS", "authorityRef": "dns",
        "source": NIC["ipv4"], "destination": "10.10.0.3", "protocol": "udp", "port": 53,
        "peerIngress": {"kind": "HOST", "ifindex": 0}}], "tableName": "ouf_test"}


class L2Tests(unittest.TestCase):
    def setUp(self):
        self.libs = F.libraries()
        self.libs.__enter__()
        self.addCleanup(self.libs.__exit__, None, None, None)
        from tools import semantic_provider_deployment_producer as producer
        from tools import semantic_provider_preexec_native as native
        for target, name, value in ((producer, "program", lambda b, _: b["path"]),
                                     (native.NativeBackend, "generation", lambda *_: copy.deepcopy(GEN))):
            p = patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.state = {"id": CID, "pid": GEN["pid"], "bundle": "/bundle", "status": "created"}
        self.children = [{"ifname": "lo"}, {"ifname": "eth0", "ifindex": 12, "link_index": 13,
            "address": MAC, "addr_info": [{"family": "inet", "local": NIC["ipv4"]}]}]
        self.hosts = [{"ifindex": 13, "ifname": "veth_test", "link_index": 12, "master": NIC["bridge"]}]
        self.run = Mock(side_effect=self.command)
        self.budget = Mock()

    def command(self, binding, args, limit=131072):
        return json.dumps(self.state if binding["path"] == "/runc" else
                          self.children if binding["path"] == "/nsenter" else self.hosts).encode()

    def observe(self):
        return L.observe(CID, GEN, RUNTIME, COMMANDS, self.budget, network_bindings=[NIC], run=self.run)

    def test_double_read_and_effective_copy(self):
        doc = policy()
        original = copy.deepcopy(doc)
        row = self.observe()
        self.assertEqual(row, observation())
        self.assertEqual(sum(c.args[0]["path"] == "/nsenter" for c in self.run.call_args_list), 2)
        effective = L.effective(doc, {CID: row})
        self.assertEqual(effective, {**doc, "networkBindings": [{**NIC, "mac": MAC}]})
        self.assertEqual(doc, original)
        self.assertNotEqual(A.sha(A.canonical(doc)), A.sha(A.canonical(effective)))

    def test_effective_denies_every_signed_nic_field_and_missing_observation(self):
        for key in NIC:
            if key == "mac":
                continue
            obs = observation()
            obs["bindings"][0][key] = "drift"
            with self.subTest(key=key), self.assertRaisesRegex(A.OperationDenied, "^L2_SIGNED_FIELD_DRIFT$"):
                L.effective(policy(), {CID: obs}, container_id=CID)
        with self.assertRaisesRegex(A.OperationDenied, "^L2_OBSERVATION_REQUIRED$"):
            L.effective(policy(), {}, container_id=CID)
        fixed = policy()
        fixed["networkBindings"][0]["mac"] = "02:11:22:33:44:55"
        with self.assertRaisesRegex(A.OperationDenied, "^L2_SIGNED_FIELD_DRIFT$"):
            L.effective(fixed, {CID: observation()}, container_id=CID)

    def test_invalid_multicast_null_and_placeholder_mac(self):
        for mac in ("01:00:00:00:00:01", "00:00:00:00:00:00", L.L2_LIVE_MAC, None, "malformed"):
            self.children[1]["address"] = mac
            with self.subTest(mac=mac), self.assertRaisesRegex(A.OperationDenied, "^L2_MAC_INVALID$"):
                self.observe()

    def test_no_other_network_condition_relaxes(self):
        mutations = [("child", "addr_info", [{"family": "inet", "local": "10.10.0.99"}], "L2_IP_DRIFT"),
                     ("child", "ifname", "eth1", "PEER_INTERFACE_MISSING"),
                     ("host", "master", "br_other", "L2_RECIPROCAL_BRIDGE_DRIFT"),
                     ("host", "link_index", 99, "L2_RECIPROCAL_BRIDGE_DRIFT"),
                     ("child", "addr_info", [{"family": "inet", "local": NIC["ipv4"]},
                                              {"family": "inet6", "local": "fe80::1"}], "L2_IPV6_UNAPPROVED")]
        for where, key, value, code in mutations:
            target = self.children[1] if where == "child" else self.hosts[0]
            old = copy.deepcopy(target[key])
            target[key] = value
            with self.subTest(code=code), self.assertRaisesRegex(A.OperationDenied, "^" + code + "$"):
                self.observe()
            target[key] = old

    def test_unstable_second_read_and_generation(self):
        first = self.command(COMMANDS["nsenter"], [])
        def changing(binding, args, limit=131072):
            result = self.command(binding, args, limit)
            if binding["path"] == "/nsenter" and result == first:
                self.children[1]["address"] = "02:11:22:33:44:55"
            return result
        self.run.side_effect = changing
        with self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_CHANGED$"):
            self.observe()
        from tools.semantic_provider_preexec_native import NativeBackend
        with patch.object(NativeBackend, "generation", return_value={**GEN, "startTicks": 999}), \
                self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_CHANGED$"):
            self.observe()

    def test_exclusive_epoch_binding_and_exact_comparison(self):
        rows = {CID: observation()}
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(L.os, "open", wraps=os.open) as opened:
                L.write_exclusive(folder, rows)
                self.assertEqual(opened.call_args_list[0].args[2], 0o600)
            path = Path(folder) / "l2-binding.json"
            raw = path.read_bytes()
            self.assertEqual(json.loads(raw), {"schema": L.SCHEMA, "containers": rows})
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_EXISTS$"):
                L.write_exclusive(folder, rows)
            self.assertEqual(path.read_bytes(), raw)
            with patch.object(B, "private", side_effect=lambda p: Path(p).read_bytes()):
                L.check(folder, rows)
                for key in ("mac", "generation"):
                    changed = copy.deepcopy(rows)
                    if key == "mac":
                        changed[CID]["bindings"][0]["mac"] = "02:11:22:33:44:55"
                    else:
                        changed[CID]["generation"]["namespaceInode"] += 1
                    with self.subTest(key=key), self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_CHANGED$"):
                        L.check(folder, changed)
                (Path(folder) / "2").mkdir()
                L.write_exclusive(Path(folder) / "2", rows)

    def test_bound_reobserves_whole_cohort_and_cannot_republish(self):
        rows = {CID: observation()}
        with patch.object(L, "cohort", return_value=rows) as collect, \
                patch.object(B, "private", return_value=A.canonical({"schema": L.SCHEMA, "containers": rows})), \
                patch.object(L, "write_exclusive", side_effect=AssertionError("republish forbidden")):
            self.assertEqual(L.bound(policy(), CID, "/epoch", RUNTIME, COMMANDS, self.budget)["networkBindings"][0]["mac"], MAC)
            self.assertEqual(collect.call_count, 1)
            collect.return_value = {CID: observation(mac="02:11:22:33:44:55")}
            with self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_CHANGED$"):
                L.bound(policy(), CID, "/epoch", RUNTIME, COMMANDS, self.budget)

    def test_cohort_observes_candidate_and_created_peers(self):
        from tools.semantic_provider_preexec_native import NativeBackend
        doc = policy()
        peer_nic = {**NIC, "ipv4": "10.10.0.3", "bindingRef": "peer_nic"}
        doc["transport"][0]["peerIngress"] = {"kind": "CREATED_CANDIDATE", "bindingRef": "peer_nic",
            "declaration": {"containerId": PEER, "applicationHash": "2" * 64, "networkBindings": [peer_nic]}}
        peer_gen = {**GEN, "pid": 43, "namespaceInode": 457}
        peer_child = {**self.children[1], "ifindex": 14, "link_index": 15, "address": "02:11:22:33:44:55",
                      "addr_info": [{"family": "inet", "local": peer_nic["ipv4"]}]}
        peer_host = {**self.hosts[0], "ifindex": 15, "link_index": 14, "ifname": "veth_peer"}
        def run(binding, args, limit=131072):
            if binding["path"] == "/runc":
                return json.dumps({**self.state, "id": args[-1], "pid": 43 if args[-1] == PEER else 42}).encode()
            if binding["path"] == "/nsenter":
                return json.dumps([peer_child] if "--net=/proc/43/ns/net" in args else self.children).encode()
            return json.dumps([*self.hosts, peer_host]).encode()
        with patch.object(NativeBackend, "generation", side_effect=lambda _, pid: peer_gen if pid == 43 else GEN):
            rows = L.cohort(doc, CID, RUNTIME, COMMANDS, self.budget, run=run)
            self.assertEqual(set(rows), {CID, PEER})
            self.assertEqual(rows[PEER]["generation"], peer_gen)
            self.assertEqual(rows[PEER]["bindings"][0]["mac"], peer_child["address"])
            raw = A.canonical({"schema": L.SCHEMA, "containers": rows})
            with patch.object(B, "private", return_value=raw):
                L.bound(doc, CID, "/epoch", RUNTIME, COMMANDS, self.budget, run=run)
                peer_child["addr_info"][0]["local"] = "10.10.0.99"
                with self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_CHANGED$"):
                    L.bound(doc, CID, "/epoch", RUNTIME, COMMANDS, self.budget, run=run)

    def test_historical_profile_and_nft_use_observed_mac(self):
        from tools.semantic_provider_deployment_admission import live_profile
        from tools.semantic_provider_preexec import rules
        effective = L.effective(policy(), {CID: observation()}, container_id=CID)
        bundle = {"linux": {"namespaces": [{"type": "network"}]}}
        candidate = {**effective, "containerId": CID, "transactionId": "c" * 64, "bundlePath": "/bundle",
                     "applicationHash": A.sha(A.canonical(bundle))}
        profile = live_profile(candidate, bundle, "/proc/42/ns/net", GEN["namespaceInode"],
                               self.children[1:], self.hosts)
        self.assertEqual(profile["policy"]["attachments"][0]["mac"], MAC)
        text = rules(profile)
        self.assertIn("ether saddr != " + MAC, text)
        self.assertIn("arp saddr ether " + MAC, text)
        self.assertNotIn(L.L2_LIVE_MAC, text)

    def test_broker_observes_before_historical_collect_and_publishes_once(self):
        import test_semantic_provider_broker_denials as diagnostics
        fixture = diagnostics.CohortTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        broker = fixture.broker
        fixture.nic["mac"] = L.L2_LIVE_MAC
        broker.template["candidate"].update(containerId=CID, networkBindings=[NIC])
        broker.runtime.return_value = ("app", GEN)
        broker.gate.record = lambda: {"state": "CREATED", "bundleHash": "app", "generation": GEN}
        broker.lock = nullcontext
        rows = {CID: observation(), PEER: observation(PEER, fixture.nic, fixture.children[1]["address"])}
        with tempfile.TemporaryDirectory() as root, patch.object(L, "cohort", return_value=rows), \
                patch.object(fixture.peers, "collect", wraps=fixture.peers.collect) as historical:
            broker.root = Path(root)
            broker.cohort_ready({})
            passed = historical.call_args.args[0]
            self.assertEqual(passed["networkBindings"][0]["mac"], fixture.children[1]["address"])
            self.assertEqual(fixture.nic["mac"], L.L2_LIVE_MAC)
            binding = json.loads((Path(root) / "l2-binding.json").read_bytes())
            self.assertEqual(binding, {"schema": L.SCHEMA, "containers": rows})
            with self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_EXISTS$"):
                broker.cohort_ready({})

    def test_l2_broker_denial_retains_task44_snapshot_and_reason(self):
        import test_semantic_provider_broker_denials as diagnostics
        fixture = diagnostics.CohortTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.nic["mac"] = L.L2_LIVE_MAC
        fixture.children[1]["address"] = L.L2_LIVE_MAC
        peer = fixture.denied("L2_MAC_INVALID")
        self.assertEqual(peer["lastReason"], "L2_MAC_INVALID")
        self.assertEqual(peer["snapshot"]["interfaces"][0]["address"], L.L2_LIVE_MAC)

    def test_evidence_checks_signed_hash_and_passes_effective_transport_hash(self):
        from tools import semantic_provider_node_observation as native_observation
        from tools import semantic_provider_deployment_authentication as authentication
        _, _, role, docs, _ = F.fixture()
        docs["transport"] = A.canonical(policy())
        role["transportSha256"] = A.sha(docs["transport"])
        role["tableName"] = "ouf_test"
        expected_oci = json.loads(docs["framePolicy"])["expectedOci"]
        app = A.sha(A.canonical(expected_oci))
        bundle = Path("/registry") / CID / "epochs/1/bundle"
        state = {**self.state, "bundle": str(bundle)}
        effective = L.effective(policy(), {CID: observation()}, container_id=CID)
        outer = self
        class Observer:
            def __init__(self, cfg, budget):
                self.cfg = cfg
            def run(self, *args):
                return json.dumps(state).encode()
            def observe(self, request, journal, reader):
                outer.assertEqual(self.cfg["candidate"], effective)
                outer.assertEqual(request["transportHash"], A.sha(A.canonical(effective)))
                outer.assertNotEqual(request["transportHash"], role["transportSha256"])
                return {"bundle": str(bundle), "state": state, "rootfsSeal": json.loads(docs["rootfsSeal"])}
        args = dict(container_id=CID, epoch=1, authorization_sha256="f" * 64, authorization_role=role,
            bound_documents=docs, bundle=bundle, registry_root="/registry", runtime_root=RUNTIME["root"],
            runtime_root_parent="/runtime", runtime_binding={k: RUNTIME[k] for k in ("path", "sha256")},
            commands=COMMANDS, rootfs_limits={}, creation_frame_observer_binding={}, budget=self.budget)
        frame = Mock()
        frame.observe.return_value = ("d" * 64, {})
        with patch.object(native_observation, "NodeObservation", Observer), \
                patch.object(authentication, "CreatedFrameObserver", return_value=frame), \
                patch.object(authentication, "private_bytes", return_value=A.canonical(expected_oci)), \
                patch.object(L, "cohort", return_value={CID: observation()}) as observed, \
                patch.object(B, "private", return_value=A.canonical({"schema": L.SCHEMA, "containers": {CID: observation()}})):
            value = E.observe(**args)
            self.assertEqual(value["transportSha256"], role["transportSha256"])
            self.assertEqual(observed.call_count, 2)
            observed.reset_mock()
            docs["transport"] = A.canonical({**policy(), "tableName": "changed"})
            with self.assertRaisesRegex(A.OperationDenied, "^EVIDENCE_TRANSPORT_BINDING_DRIFT$"):
                E.observe(**args)
            observed.assert_not_called()

    def test_preparer_checks_signed_document_before_materializing_candidate(self):
        _, _, role, docs, _ = F.fixture()
        docs["transport"] = A.canonical(policy())
        role.update(transportSha256=A.sha(docs["transport"]), tableName="ouf_test")
        worker = P.Worker.__new__(P.Worker)
        worker.root, worker.budget, worker.command = Path("/epoch"), self.budget, COMMANDS.__getitem__
        candidate = {**policy(), "containerId": CID, "runtimeBinding": RUNTIME}
        rows = {CID: observation()}
        with patch.object(L, "cohort", return_value=rows) as collect, \
                patch.object(B, "private", return_value=A.canonical({"schema": L.SCHEMA, "containers": rows})):
            signed, effective = worker.effective_candidate(candidate, role, docs)
            self.assertEqual(signed, policy())
            self.assertEqual(candidate["networkBindings"][0]["mac"], MAC)
            self.assertEqual(effective["networkBindings"], candidate["networkBindings"])
            collect.reset_mock()
            with self.assertRaisesRegex(A.OperationDenied, "^PREPARER_TRANSPORT_DRIFT$"):
                worker.effective_candidate(candidate, role, docs)
            collect.assert_not_called()
            candidate = {**policy(), "containerId": CID, "runtimeBinding": RUNTIME}
            docs["transport"] += b" "
            with self.assertRaisesRegex(A.OperationDenied, "^EVIDENCE_TRANSPORT_BINDING_DRIFT$"):
                worker.effective_candidate(candidate, role, docs)
            collect.assert_not_called()

    def test_driver_verifies_signed_policy_and_effective_peer_scope(self):
        import test_semantic_provider_admission_v2_preparer as driver_fixture
        from tools import semantic_provider_peer_bindings as peers
        value = driver_fixture.grant()
        doc = policy()
        peer_nic = {**NIC, "ipv4": "10.10.0.3", "bindingRef": "peer_nic"}
        doc["transport"][0]["peerIngress"] = {"kind": "CREATED_CANDIDATE", "bindingRef": "peer_nic",
            "declaration": {"containerId": PEER, "applicationHash": "2" * 64, "networkBindings": [peer_nic]}}
        rows = {CID: observation(), PEER: observation(PEER, peer_nic, "02:11:22:33:44:55")}
        effective = L.effective(doc, rows, container_id=CID)
        snapshot = {**rows[PEER], "applicationHash": "2" * 64}
        value["l2Binding"] = {"signedTransport": doc, "commandBindings": COMMANDS}
        value["peerBinding"] = {"declaredPolicy": effective, "commandBindings": COMMANDS,
                               "observations": {PEER: snapshot}}
        value["profile"]["policy"] = {"tableName": doc["tableName"],
            "attachments": [{k: rows[CID]["bindings"][0][k] for k in ("mac", "ipv4", "bridge", "workloadRef", "bindingRef")}],
            "flows": peers.resolve(effective["transport"], peers.declarations(effective["transport"], CID), {PEER: snapshot}, CID)}
        with patch.object(L, "cohort", return_value=rows), \
                patch.object(B, "private", return_value=A.canonical({"schema": L.SCHEMA, "containers": rows})), \
                patch.object(peers, "collect", return_value=snapshot) as historical:
            result = D.verify_l2(value, A.sha(A.canonical(doc)), self.budget, self.run)
            D.verify_peers(value, A.sha(A.canonical(result)), self.budget, self.run)
            self.assertEqual(historical.call_args.args[0]["networkBindings"][0]["mac"], rows[PEER]["bindings"][0]["mac"])
            with self.assertRaisesRegex(A.OperationDenied, "^PEER_DRIVER_TRANSPORT_SCOPE_DRIFT$"):
                D.verify_l2(value, "0" * 64, self.budget, self.run)
            value["peerBinding"]["declaredPolicy"]["transport"][0]["port"] += 1
            with self.assertRaisesRegex(A.OperationDenied, "^L2_SIGNED_FIELD_DRIFT$"):
                D.verify_l2(value, A.sha(A.canonical(doc)), self.budget, self.run)

    def test_driver_authorizer_reobserves_instead_of_caching_binding(self):
        import test_semantic_provider_admission_v2_preparer as driver_fixture
        binding, head, role, _, evidence = F.fixture()
        value = driver_fixture.grant()
        role.update(transportSha256=A.sha(A.canonical(policy())), tableName="ouf_test")
        evidence["transportSha256"] = role["transportSha256"]
        value["profile"].update(bundleHash=evidence["bundleHash"], policy={"tableName": "ouf_test",
            "attachments": [{k: observation()["bindings"][0][k] for k in ("mac", "ipv4", "bridge", "workloadRef", "bindingRef")}]})
        value["creationFrameObserverBinding"]["configuration"]["sha256"] = role["framePolicySha256"]
        value["l2Binding"] = {"signedTransport": policy(), "commandBindings": COMMANDS}
        value["commands"].update({k: v["path"] for k, v in COMMANDS.items()})
        D.validate(A.canonical(value))
        operation = D.Operation.__new__(D.Operation)
        operation.value, operation.binding, operation.budget = value, binding, self.budget
        operation.head = lambda: head
        rows = {CID: observation()}
        with patch.object(D, "sealed_authorizer_v2", return_value=lambda: True), \
                patch.object(B, "read_binding", return_value=A.canonical(evidence)), \
                patch.object(B, "private", return_value=A.canonical({"schema": L.SCHEMA, "containers": rows})), \
                patch.object(L, "cohort", return_value=rows) as observed:
            authorize = operation.authorizer()
            self.assertTrue(authorize())
            changed = copy.deepcopy(rows)
            changed[CID]["generation"]["startTicks"] += 1
            observed.return_value = changed
            with self.assertRaisesRegex(A.OperationDenied, "^L2_BINDING_CHANGED$"):
                authorize()
            self.assertEqual(observed.call_count, 2)

    def test_current_source_contract_requires_l2_module(self):
        cfg = F.configuration()
        cfg["sourceHashes"].pop("tools/semantic_provider_admission_v2/l2_binding.py")
        with self.assertRaisesRegex(A.OperationDenied, "^EXACT_BROKER_SOURCE_SET_REQUIRED$"):
            B.validate(A.canonical(cfg))


if __name__ == "__main__":
    unittest.main()
