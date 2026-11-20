"""Synthetic section-14 structure, real repository blobs and component validators."""
import copy
import base64
import importlib.util
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from types import SimpleNamespace
import unittest
import zlib
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from r3_sealed_inputs import sealed_blob
from tools.semantic_provider_r3 import compose as C
from tools.semantic_provider_operation import authorization as A
from tools.semantic_provider_admission_v2 import broker_v2 as B, driver_v7 as D, evidence_v2 as E


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


accept_fixture = load("tests/test_semantic_b1_acceptance.py", "r3_acceptance_fixture")
grant_fixture = load("tests/test_semantic_provider_admission_v2_preparer.py", "r3_grant_fixture")
SOURCE_CACHE = None


def fixture(version=1, *, read_blob=None):
    global SOURCE_CACHE
    if read_blob is None:
        # Exercise the worktree, preserving the delivery's LF recovery pins.
        def read_blob(path):
            return (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
        if SOURCE_CACHE is None:
            SOURCE_CACHE = {p: read_blob(p) for p in C.SOURCE_INPUTS}
        sources = SOURCE_CACHE.copy()
    else:
        sources = {p: read_blob(p) for p in C.SOURCE_INPUTS}
    files = {}
    def put(name, value):
        files[name] = A.canonical(value) + b"\n"
    accepted = accept_fixture.fixture()
    accepted.update(generation=3, issuedAt=1794736800)
    owner = {"binding": {"transactionId": "90323380" + "0" * 56, "configurationHash": "44ef757d" + "0" * 56,
                         "leaseStructureHash": "1eddee4c" + "0" * 56},
        "expectedStructureHash": "1eddee4c" + "0" * 56,
        "journalFile": "/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-uz9gw5ny/coordination-journal.json",
        "commonLockFile": "/run/ouf-semantic-boot-guard/guard.lock", "nftPath": "/usr/sbin/nft", "nftSha256": "5" * 64,
        "kernel": {"tableName": "ouf_sem_provider", "flows": [
            {"id": "schema-gov", "leaseSeconds": 30}, {"id": "ouf-oidc", "leaseSeconds": 30}]},
        "dns": {"resolvers": [{"address": "46.38.225.230", "port": 53}, {"address": "46.38.252.230", "port": 53}]}}
    if version >= 9:
        # Shape of the real 2026-11-09 coordinator kernel (VPS diagnostic), names only.
        owner["kernel"].update(guardedInterfaces=["oufsp-int", "oufsp-egress"],
            existingInterfaces=["br-backend", "docker0"],
            providerFlows=[{"source": "172.22.0.2"}, {"source": "172.22.0.3"}],
            staticFlows=[{"source": "172.21.0.3", "destination": "172.21.0.2"}])
    put("coordinator", owner)
    put("coordinationJournal", {"schema": "ouf.semantic-lease-coordination.v1", **owner["binding"],
        "state": "QUIESCED", "leaseAuthorized": False, "startAuthorized": False, "leaseAddresses": [[], []]})
    settings = {"installRoot": "/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1", "issuedAt": 1794736801,
        "installationRef": accepted["installationRef"], "entityRef": accepted["entityRef"],
        "issuerRef": "ouf-lab-infrastructure-installer", "anchorBinding": accepted["trustPolicy"],
        "mandateRoot": "/var/lib/ouf-authority-mandates/b1b2",
        "opensslBinding": {"path": "/usr/bin/openssl", "sha256": "4" * 64, "version": "3.0.0"},
        "coordinatorBinding": {"path": "/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-uz9gw5ny/coordinated-configuration.json",
                               "sha256": A.sha(files["coordinator"])},
        "tableNames": {"adapter": "ouf_r3_adapter", "southbound": "ouf_r3_southbound"},
        "runtimeBinding": {"path": "/usr/bin/runc", "sha256": "3" * 64}, "runtimeRootParent": "/run/docker/runtime-runc",
        "rootfsLimits": {"maxEntries": 100000, "maxBytes": 8589934592, "maxDepth": 64},
        "supervisorLimits": {"maxActivationsPerHour": 6, "heartbeatSeconds": 1, "pollSeconds": 15}}
    put("settings", settings)
    nics, old = {}, {"adapter": "c" * 64, "southbound": "d" * 64}
    policies, successors, seals = {}, [], {}
    for role, suffix in (("adapter", "3"), ("southbound", "2")):
        nics[role] = [{"interface": "eth0", "bridge": "oufsp-int", "mac": "02:00:00:00:00:0" + suffix,
                       "ipv4": "172.21.0." + suffix, "workloadRef": role, "bindingRef": role + "-internal"},
            {"interface": "eth1", "bridge": "oufsp-egress", "mac": "02:00:00:00:01:0" + suffix,
             "ipv4": "172.22.0." + suffix, "workloadRef": role, "bindingRef": role + "-egress",
             "leaseGuard": {"configurationHash": "8" * 64, "tableName": "ouf_sem_provider"}}]
        if role == "southbound":
            nics[role].append({"interface": "eth2", "bridge": "br-backend", "mac": "02:00:00:00:02:02",
                "ipv4": "172.18.0.14", "workloadRef": role, "bindingRef": "southbound-backend"})
        baseline = json.loads(read_blob("tools/semantic_frame_compiler/containerd-overlayfs-adapter.json" if role == "adapter"
            else "tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json"))
        cid = accepted["roles"][role]["containerId"]
        context = {"schema": "ouf.semantic-docker-frame-context.v1", "containerId": cid,
            "bundleParent": "/run/containerd/io.containerd.runtime.v2.task/moby", "metadataParent": "/var/lib/docker/containers",
            "networkNamespaceParent": "/var/run/docker/netns", "networkNamespaceName": None,
            "cgroupDriver": "systemd", "rootfsPath": "/var/lib/docker/rootfs/overlayfs/" + cid, "storageParent": "/var/lib/docker"}
        recipe = {"template": baseline["template"], "launch": baseline["launch"], "context": context}
        recipe["policy"] = C.compile_policy(**recipe)
        policies[role] = recipe["policy"]
        for k, v in recipe.items():
            put(role + "/" + k, v)
            accepted["roles"][role]["recipe"][k]["sha256"] = A.sha(files[role + "/" + k])
        row = accepted["roles"][role]
        row["rootfs"]["effectiveSeal"].update(entries=3390 if role == "adapter" else 7458,
            sha256=("87447240" if role == "adapter" else "52e06f47") + "0" * 56)
        seals[role] = {"containerId": cid, "imageId": row["imageId"], "effectiveSeal": row["rootfs"]["effectiveSeal"]}
        successors.append({"containerId": cid, "image": row["imageId"], "status": "created",
            "runtime": "ouf-semantic-admitted-v2", "transaction": accepted["creation"]["roles"][role]["transactionRef"]})
    for role in C.ROLES:
        other = "southbound" if role == "adapter" else "adapter"
        flow = {"purpose": "GATEWAY_ADAPTER", "authorityRef": "provider", "source": "172.21.0.2", "destination": "172.21.0.3",
            "protocol": "tcp", "port": 9443, "peerIngress": {"kind": "CREATED_CANDIDATE", "bindingRef": other + "-internal",
                "declaration": {"containerId": old[other], "applicationHash": "1" * 64, "networkBindings": nics[other]}}}
        flows = [flow]
        if role == "southbound":
            flows.append({"purpose": "WORKLOAD_GATEWAY", "authorityRef": "semantic", "source": "172.18.0.6",
                "destination": "172.18.0.14", "protocol": "tcp", "port": 10443,
                "peerIngress": {"kind": "BRIDGE_PORT", "ifindex": 1377}})
        put(role + "/historicalTemplate", {"schema": "ouf.semantic-admission-preparer-template.v1",
            "pythonPath": "/usr/bin/python3.12", "pythonHash": "889c603f" + "0" * 56,
            "commands": {n: "/usr/bin/" + n for n in ("ip", "mount", "nft", "nsenter", "umount", "unshare")},
            "commandHashes": {n: "2" * 64 for n in ("ip", "mount", "nft", "nsenter", "umount", "unshare")},
            "budgetSeconds": 5, "hostNetworkNamespace": 4026531840,
            "candidate": {"containerId": old[role], "transactionId": "7" * 64, "networkBindings": nics[role],
                "transport": flows, "tableName": "ouf_v2_" + role, "runtimeBinding": settings["runtimeBinding"]},
            "kernel": {}, "dns": {}, "coordinationBinding": {k: "8" * 64 for k in owner["binding"]},
            "coordinationJournal": "/old/journal.json", "lockFile": owner["commonLockFile"]})
    put("successors", {"containers": successors, "transactions": {r["containerId"]: r["transaction"] for r in successors}})
    put("semanticPeer", {"schema": "ouf.semantic-provider-preparation-a.peer.v1", "containerId": "e" * 64,
        "binding": {"hostIfindex": 1450}, "proposedIngress": {"kind": "BRIDGE_PORT", "ifindex": 1450,
            "sourceIpv4": "172.18.0.6", "destinationIpv4": "172.18.0.14", "destinationPort": 10443, "protocol": "tcp"}})
    body = {"schema": "ouf.semantic-provider-preparation-a.manifest.v1", "successors": json.loads(files["successors"]),
        "semanticPeer": json.loads(files["semanticPeer"]), "directory": {"path": accepted["preparationA"]["root"]},
        "filesCreated": [{"path": accepted["preparationA"]["root"] + "/" + filename, "sha256": A.sha(files[k])}
                         for k, filename in (("successors", "successors.json"), ("semanticPeer", "semantic-peer.json"))]}
    put("a2Manifest", {"manifest": body, "planSha256": accepted["preparationA"]["planSha256"]})
    for k, field in (("a2Manifest", "manifest"), ("successors", "successors"), ("semanticPeer", "semanticPeer")):
        accepted["preparationA"]["files"][field]["sha256"] = A.sha(files[k])
    put("rootfs", {"roles": seals, "aSuccessors": accepted["preparationA"]["files"]["successors"]})
    files["acceptance"] = C.ACCEPT.build_acceptance(**accepted)
    if version >= 6:
        sources.pop(C.OBSERVER)
        sources[C.OBSERVER_V2] = read_blob(C.OBSERVER_V2)
    if version >= 11:
        owner['dns'] = {'resolvers': ['46.38.225.230', '46.38.252.230'], 'resolverPort': 53,
                        'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}
        put('coordinator', owner)
        settings['coordinatorBinding']['sha256'] = A.sha(files['coordinator'])
        put('settings', settings)
        sources = {p: read_blob(p) for p in C.SOURCE_INPUTS_V11}
    return {"files": files, "sources": sources}


class ComposeTests(unittest.TestCase):
    def test_dns_v11_preserves_every_v1_to_v10_document_and_authorization(self):
        expected = json.loads((ROOT / 'tests/fixtures/r3-v1-v10-dns-tolerance-hashes.json').read_bytes())
        for version in range(1, 11):
            kw = {} if version == 1 else {'sequence': version, 'supersedes': 'a'*64}
            result = C.compose(fixture(version, read_blob=sealed_blob), version, **kw)
            self.assertEqual(A.sha(A.canonical(result['hashes'])), expected[str(version)])

    def test_v11_profile_source_aliases_and_authorization_hashes(self):
        inputs = fixture(11)
        original = copy.deepcopy(inputs)
        result = C.compose(inputs, 11, sequence=11, supersedes='a'*64)
        self.assertEqual(inputs, original)
        prefix = 'versions/11/'
        docs = result['documents']
        supervisor = json.loads(docs[prefix + 'supervisor/configuration.json'])
        owner = json.loads(inputs['files']['coordinator'])
        profile = json.loads(docs[prefix + 'supervisor/dns-profile.json'])
        self.assertEqual(profile, {**owner['dns'], 'timeoutSeconds': 10})
        auth = A.validate(result['authorization'])
        self.assertEqual(auth['lease']['ownerConfigurationSha256'], A.sha(inputs['files']['coordinator']))
        self.assertEqual(auth['lease']['dnsProfileSha256'], A.sha(A.canonical(profile)))
        self.assertEqual(supervisor['coordinator']['ownerConfiguration'],
                         json.loads(inputs['files']['settings'])['coordinatorBinding'])
        for role in C.ROLES:
            template = json.loads(docs[prefix + 'documents/' + role + '/preparer-template.json'])
            self.assertEqual(template['dns'], profile)
        for target, original in C.SOURCE_MAP_V11.items():
            raw = docs[prefix + 'source/' + target]
            self.assertEqual(raw, inputs['sources'][original])
            if target in supervisor['sourceHashes']:
                self.assertEqual(supervisor['sourceHashes'][target], A.sha(raw))
        module = C.contract_module(inputs['sources'][C.SOURCE_MAP_V11[C.SUPERVISOR]], 'v11_supervisor')
        self.assertEqual(module.validate(A.canonical(supervisor)), supervisor)
        for name, digest in module.PINS.items():
            self.assertEqual(A.sha(docs[prefix + 'source/tools/semantic_lease_recovery/' + name + '.py']), digest)
        self.assertEqual(module.SOURCES, C.SUPERVISOR_SOURCES_V11)
        bootstrap_path = 'scripts/semantic-provider-lease-supervisor-v2.py'
        bootstrap = C.contract_module(inputs['sources'][C.SOURCE_MAP_V11[bootstrap_path]], 'v11_bootstrap')
        self.assertEqual(bootstrap.SOURCES, module.SOURCES)
        self.assertEqual(docs[prefix + 'source/tools/semantic_provider_dns.py'],
                         docs[prefix + 'source/tools/semantic_lease_recovery/dns.py'])

    def test_v11_rejects_old_or_mixed_closure(self):
        with self.assertRaisesRegex(A.OperationDenied, 'EXACT_R3_INPUT_SET_REQUIRED'):
            C.compose(fixture(10), 11, sequence=11, supersedes='a'*64)
        with self.assertRaisesRegex(A.OperationDenied, 'EXACT_R3_INPUT_SET_REQUIRED'):
            C.compose(fixture(11), 10, sequence=10, supersedes='a'*64)

    def test_v9_lease_guard_binds_kernel_digest_and_v8_is_unchanged(self):
        def guards(result, version):
            prefix = "versions/%d/" % version
            values = []
            for role in C.ROLES:
                doc = json.loads(result["documents"][prefix + "documents/" + role + "/transport.json"])
                values += [n["leaseGuard"] for n in doc["networkBindings"] if "leaseGuard" in n]
                for flow in doc["transport"]:
                    if flow["peerIngress"]["kind"] == "CREATED_CANDIDATE":
                        values += [n["leaseGuard"] for n in flow["peerIngress"]["declaration"]["networkBindings"]
                                   if "leaseGuard" in n]
            return values
        inputs = fixture(9)
        owner = json.loads(inputs["files"]["coordinator"])
        kernel_hash = C.lease_guard_hash(owner["kernel"])
        v9 = C.compose(inputs, 9, sequence=9, supersedes="a" * 64)
        found = guards(v9, 9)
        self.assertTrue(found)
        self.assertEqual({g["configurationHash"] for g in found}, {kernel_hash})
        v8 = C.compose(inputs, 8, sequence=8, supersedes="a" * 64)
        binding_hash = owner["binding"]["configurationHash"]
        self.assertEqual({g["configurationHash"] for g in guards(v8, 8)}, {binding_hash})

    def test_v9_rejects_lease_guard_outside_kernel_scope_at_composition(self):
        kernel = {"tableName": "t", "guardedInterfaces": ["g0"], "existingInterfaces": ["e0"],
                  "providerFlows": [{"source": "10.0.0.2"}], "staticFlows": [{"source": "10.0.0.3", "destination": "10.0.0.4"}]}
        ok = {"bridge": "g0", "ipv4": "10.0.0.4", "leaseGuard": {"tableName": "t", "configurationHash": "0" * 64}}
        C.check_lease_guard(ok, kernel)
        for change, code in (({"bridge": "e0"}, "R3_LEASE_GUARD_SCOPE_DRIFT"), ({"bridge": "x0"}, "R3_LEASE_GUARD_SCOPE_DRIFT"),
                             ({"leaseGuard": {"tableName": "u", "configurationHash": "0" * 64}}, "R3_LEASE_GUARD_SCOPE_DRIFT"),
                             ({"ipv4": "10.9.9.9"}, "R3_LEASE_GUARD_SOURCE_UNBOUND")):
            with self.subTest(code=code, change=change), self.assertRaisesRegex(Exception, code):
                C.check_lease_guard({**ok, **change}, kernel)

    def test_v6_selects_source_sealed_observer_v2_and_keeps_broker_source_set(self):
        inputs = fixture(6)
        original = copy.deepcopy(inputs)
        for version in (6, 7):
            result = C.compose(inputs, version, sequence=version, supersedes='a' * 64)
            self.assertEqual(result, C.compose(inputs, version, sequence=version, supersedes='a' * 64))
            prefix = f'versions/{version}/'
            self.assertNotIn(prefix + 'source/' + C.OBSERVER, result['documents'])
            self.assertEqual(result['documents'][prefix + 'source/' + C.OBSERVER_V2], inputs['sources'][C.OBSERVER_V2])
            for role in C.ROLES:
                cfg = B.validate(result['documents'][prefix + 'broker/' + role + '.json'])
                source = cfg['creationFrameObserverBinding']['source']
                self.assertTrue(source['path'].endswith('/source/' + C.OBSERVER_V2))
                self.assertEqual(source['sha256'], A.sha(inputs['sources'][C.OBSERVER_V2]))
                self.assertEqual(set(cfg['sourceHashes']), B.SOURCES)
        self.assertEqual(inputs, original)
        for version, wrong in ((5, fixture(6)), (6, fixture())):
            with self.subTest(version=version), self.assertRaisesRegex(A.OperationDenied, 'EXACT_R3_INPUT_SET_REQUIRED'):
                C.compose(wrong, version, sequence=version, supersedes='a' * 64)

    def test_v1_through_v5_keep_the_legacy_observer_closure(self):
        inputs = fixture()
        for version in range(1, 6):
            result = C.compose(inputs, version, **({} if version == 1 else dict(sequence=version, supersedes='a' * 64)))
            prefix = '' if version == 1 else f'versions/{version}/'
            self.assertNotIn(prefix + 'source/' + C.OBSERVER_V2, result['documents'])
            self.assertEqual(result['documents'][prefix + 'source/' + C.OBSERVER], inputs['sources'][C.OBSERVER])
            for role in C.ROLES:
                cfg = B.validate(result['documents'][prefix + 'broker/' + role + '.json'])
                self.assertTrue(cfg['creationFrameObserverBinding']['source']['path'].endswith('/source/' + C.OBSERVER))

    def test_v6_issuance_and_upgrade_readers_accept_only_closed_source_sets(self):
        from tools.semantic_provider_r3 import upgrade
        issuer = load('scripts/issue-semantic-provider-operation-authorization.py', 'v6_input_reader_issuer')
        for version in (5, 6):
            inputs = fixture(version)
            index = dict(schema='ouf.semantic-provider-r3-inputs.v1',
                         files=dict.fromkeys(inputs['files'], 'file'), sources=dict.fromkeys(inputs['sources'], 'source'))
            args = SimpleNamespace(inputs='/inputs', inputs_sha256='a' * 64, install_root='/install', issued_at=1794736801,
                                   table_name=['adapter=ouf_r3_adapter', 'southbound=ouf_r3_southbound'],
                                   private_key_path=[], authority_profile='/profile', authority_profile_sha256='b' * 64)
            profile = dict(schema='ouf.semantic-existing-installation-authority-bindings.v1', keyBindings={})
            for extra in (False, True):
                candidate = copy.deepcopy(index)
                if extra:
                    candidate['sources']['unreviewed.py'] = 'source'
                reader = Mock()
                reader.read.return_value = A.canonical(candidate)
                reader.bound.side_effect = RuntimeError('TEST_INPUTS_ACCEPTED')
                with patch.object(upgrade.I, 'Reader', return_value=reader):
                    with self.assertRaisesRegex(RuntimeError, 'R3_EXACT_INPUT_MANIFEST_REQUIRED' if extra else 'TEST_INPUTS_ACCEPTED'):
                        upgrade.read_inputs(args)
                if extra:
                    reader.bound.assert_not_called()
                reader = Mock(private_paths=set())
                reader.read.side_effect = [A.canonical(profile), A.canonical(candidate)]
                reader.bound.side_effect = RuntimeError('TEST_INPUTS_ACCEPTED')
                with patch.object(issuer, 'Reader', return_value=reader):
                    with self.assertRaisesRegex(RuntimeError, 'EXACT_R3_INPUT_MANIFEST_REQUIRED' if extra else 'TEST_INPUTS_ACCEPTED'):
                        issuer.observe(args, lambda: args.issued_at)
                if extra:
                    reader.bound.assert_not_called()
        v5 = C.compose(fixture(), 5, sequence=5, supersedes='a' * 64)
        head = dict(sequence=5, decision='OPERATE', sha256=A.sha(v5['authorization']), authorization=json.loads(v5['authorization']))
        v6 = issuer.compose_next(fixture(6), head, head['authorization']['issuedAt'])
        self.assertEqual(json.loads(v6['authorization'])['sequence'], 6)
        self.assertIn('versions/6/source/' + C.OBSERVER_V2, v6['documents'])

    def test_version_one_fixed_fixture_has_identical_document_bytes(self):
        baseline = json.loads((ROOT / "tests/fixtures/r3-v1-document-hashes.json").read_bytes())
        inputs = fixture(read_blob=sealed_blob)
        # Versioned releases retain their original source INPUTS. Current
        # sources belong to the new closure, never to a rewritten old oracle.
        previous = json.loads((ROOT / "tests/fixtures/r3-v3-document-hashes.json").read_bytes())["retainedSources"]
        for path, packed in previous.items():
            inputs["sources"][path] = zlib.decompress(base64.b64decode(packed))
        retained = json.loads((ROOT / "tests/fixtures/r3-v2-document-hashes.json").read_bytes())["retainedSources"]
        for path, packed in retained.items():
            inputs["sources"][path] = zlib.decompress(base64.b64decode(packed))
        inputs["sources"].pop(C.L2_SOURCE)
        current = C.compose(inputs, version=1)
        # Every input and every output is pinned, including source copies,
        # registry lock bytes and authorization; no dynamically computed oracle.
        self.assertEqual(current["inputHashes"], baseline["inputHashes"])
        self.assertEqual(current["hashes"], baseline["hashes"])
        self.assertEqual(current, C.compose(inputs))

    def test_version_two_fixed_inputs_and_version_four_current_closure(self):
        baseline = json.loads((ROOT / "tests/fixtures/r3-v2-document-hashes.json").read_bytes())
        inputs = fixture(read_blob=sealed_blob)
        previous = json.loads((ROOT / "tests/fixtures/r3-v3-document-hashes.json").read_bytes())["retainedSources"]
        for path, packed in previous.items():
            inputs["sources"][path] = zlib.decompress(base64.b64decode(packed))
        for path, packed in baseline["retainedSources"].items():
            inputs["sources"][path] = zlib.decompress(base64.b64decode(packed))
        inputs["sources"].pop(C.L2_SOURCE)
        old = C.compose(inputs, 2, sequence=2, supersedes="a"*64)
        self.assertEqual(old["inputHashes"], baseline["inputHashes"])
        self.assertEqual(old["hashes"], baseline["hashes"])
        current = fixture()
        new = C.compose(current, 4, sequence=4, supersedes=A.sha(old["authorization"]))
        for path in ("tools/semantic_provider_admission_v2/broker_v2.py", B.ENTRYPOINTS[0]):
            self.assertEqual(new["documents"]["versions/4/source/" + path], current["sources"][path])
            self.assertNotEqual(A.sha(current["sources"][path]), baseline["inputHashes"]["repository/" + path])

    def test_version_three_retained_bytes(self):
        baseline = json.loads((ROOT / "tests/fixtures/r3-v3-document-hashes.json").read_bytes())
        inputs = fixture(read_blob=sealed_blob)
        inputs["sources"].pop(C.L2_SOURCE)
        for path, packed in baseline["retainedSources"].items():
            inputs["sources"][path] = zlib.decompress(base64.b64decode(packed))
        result = C.compose(inputs, 3, sequence=3, supersedes="a" * 64)
        self.assertEqual(result["inputHashes"], baseline["inputHashes"])
        self.assertEqual(result["hashes"], baseline["hashes"])

    def test_version_four_changes_only_successor_interface_and_mac_fields(self):
        from tools.semantic_provider_admission_v2.l2_binding import L2_LIVE_MAC, live_interface
        inputs = fixture()
        v3 = C.compose(inputs, 3, sequence=3, supersedes="a" * 64)
        v4 = C.compose(inputs, 4, sequence=4, supersedes="a" * 64)
        def placeholders(value):
            if type(value) is list:
                return [placeholders(v) for v in value]
            if type(value) is dict:
                return {k: [{**nic, "interface": live_interface(i), "mac": L2_LIVE_MAC}
                            for i, nic in enumerate(v)] if k == "networkBindings" else placeholders(v)
                        for k, v in value.items()}
            return value
        for role in C.ROLES:
            for name in ("transport.json", "preparer-template.json"):
                suffix = "documents/" + role + "/" + name
                self.assertEqual(json.loads(v4["documents"]["versions/4/" + suffix]),
                                 placeholders(json.loads(v3["documents"]["versions/3/" + suffix])))
        peer = json.loads(v4["documents"]["versions/4/documents/southbound/transport.json"])["transport"][1]["peerIngress"]
        self.assertEqual(peer, {"kind": "BRIDGE_PORT", "ifindex": 1450})

    def test_versions_keep_state_shared_and_payload_chain_explicit(self):
        inputs = fixture()
        original = copy.deepcopy(inputs)
        for version in (2, 3):
            composed = C.compose(inputs, version, sequence=version, supersedes="a"*64)
            prefix = f"versions/{version}/"
            root = json.loads(inputs["files"]["settings"])["installRoot"]
            cfg = json.loads(composed["documents"][prefix+"runtime-configuration.json"])
            sup = json.loads(composed["documents"][prefix+"supervisor/configuration.json"])
            payload = A.validate(composed["authorization"])
            self.assertTrue(all(p.startswith(prefix) for p in composed["documents"]))
            self.assertEqual(cfg["registryRoot"], root+"/registry")
            self.assertEqual(sup["statusPath"], root+"/supervisor/state/status.json")
            self.assertEqual(sup["recoveryJournalRoot"], root+"/supervisor/state/recovery")
            self.assertEqual(sup["authorizationRoot"], root+"/authorization")
            self.assertEqual(sup["sourceRoot"], root+"/"+prefix+"source")
            self.assertEqual(payload["sequence"], version)
            self.assertEqual(payload["supersedes"], "a"*64)
            self.assertEqual(payload["runtimeConfigurationSha256"], A.sha(composed["documents"][prefix+"runtime-configuration.json"]))
            for role in C.ROLES:
                broker = json.loads(composed["documents"][prefix+"broker/"+role+".json"])
                B.validate(A.canonical(broker))
                self.assertEqual(broker["registryRoot"], root+"/registry")
                self.assertEqual(broker["sourceRoot"], root+"/"+prefix+"source")
                self.assertTrue(broker["preparerTemplate"]["path"].startswith(root+"/"+prefix))
                self.assertEqual(payload["roles"][role]["admissionConfigurationSha256"],
                                 A.sha(composed["documents"][prefix+"broker/"+role+".json"]))
        self.assertEqual(inputs, original)

    def test_invalid_versions_and_missing_successor_metadata_are_denied(self):
        for version in (True, 0, -1, "2", 2.0):
            with self.subTest(version=version), self.assertRaisesRegex(A.OperationDenied, "R3_VERSION_REQUIRED"):
                C.compose(fixture(), version)
        for params in ({}, {"sequence": 1, "supersedes": "a"*64}, {"sequence": 2, "supersedes": None}):
            with self.subTest(params=params), self.assertRaisesRegex(A.OperationDenied, "R3_SUCCESSOR_CHAIN_REQUIRED"):
                C.compose(fixture(), 2, **params)

    def test_determinism_input_change_and_no_mutation(self):
        inputs = fixture()
        original = copy.deepcopy(inputs)
        first = C.compose(inputs)
        self.assertEqual(first, C.compose(inputs))
        self.assertEqual(inputs, original)
        inputs["files"]["settings"] = inputs["files"]["settings"].replace(b'1794736801', b'1794736802')
        self.assertNotEqual(first["authorization"], C.compose(inputs)["authorization"])
        inputs = fixture()
        inputs["sources"][C.OBSERVER] += b"\n"
        self.assertNotEqual(first["hashes"], C.compose(inputs)["hashes"])

    def test_cross_bindings_and_real_validators(self):
        inputs = fixture()
        result = C.compose(inputs)
        docs = result["documents"]
        payload = A.validate(result["authorization"])
        runtime = json.loads(docs["runtime-configuration.json"])
        sup_module = C.contract_module(inputs["sources"][C.SUPERVISOR], "supervisor")
        sup = sup_module.validate(docs["supervisor/configuration.json"])
        self.assertEqual(payload["runtimeConfigurationSha256"], A.sha(docs["runtime-configuration.json"]))
        self.assertEqual(payload["lease"]["ownerConfigurationSha256"], A.sha(inputs["files"]["coordinator"]))
        self.assertEqual(payload["lease"]["dnsProfileSha256"], A.sha(docs["supervisor/dns-profile.json"]))
        self.assertEqual(payload["lease"]["leaseStructureHash"], json.loads(inputs["files"]["coordinator"])["binding"]["leaseStructureHash"])
        self.assertEqual(sup["coordinator"]["ownerConfiguration"]["sha256"], payload["lease"]["ownerConfigurationSha256"])
        for role in C.ROLES:
            cfg = B.validate(docs["broker/" + role + ".json"])
            entry = payload["roles"][role]
            self.assertEqual(docs["registry/" + entry["containerId"] + "/operation.lock"], b"")
            self.assertIn("registry/" + entry["containerId"] + "/epochs", result["layout"]["directories0700"])
            self.assertEqual(entry["admissionConfigurationSha256"], A.sha(docs["broker/" + role + ".json"]))
            self.assertEqual(runtime["admissionConfigurations"][entry["containerId"]]["sha256"], entry["admissionConfigurationSha256"])
            self.assertEqual(cfg["creationFrameObserverBinding"]["configuration"], cfg["framePolicyBinding"])
            prefix = "documents/" + role + "/"
            decoded = E.documents(entry, {k: docs[prefix + f] for k, f in
                (("framePolicy", "frame-policy.json"), ("rootfsSeal", "rootfs-seal.json"), ("transport", "transport.json"))})
            self.assertEqual(result["audit"][role]["applicationHash"], A.sha(A.canonical(decoded["framePolicy"]["expectedOci"])))
            self.assertEqual(result["audit"][role]["artifactHash"], entry["framePolicySha256"])
            self.assertEqual(inputs["files"][role + "/policy"], docs[prefix + "frame-policy.json"] + b"\n")
            # Real v7 validator, with only the future live fields supplied by a
            # synthetic epoch. No driver/epoch document is published by R3.
            grant = grant_fixture.grant()
            grant.update(sourceRoot=cfg["sourceRoot"], sourceHashes=cfg["sourceHashes"],
                creationFrameObserverBinding=cfg["creationFrameObserverBinding"],
                operation={**cfg["operation"], **cfg["authorities"]})
            t = json.loads(docs[prefix + "preparer-template.json"])
            grant.update({k: t[k] for k in ("kernel", "dns", "coordinationBinding", "coordinationJournal", "lockFile", "budgetSeconds")})
            grant["commands"] = {k: t["commands"][k] for k in ("nft", "ip", "nsenter")}
            grant["runtimeBinding"] = {**t["candidate"]["runtimeBinding"], "root": "/run/runtime/moby"}
            grant["operationBinding"].update(containerId=entry["containerId"],
                authorizationSha256=A.sha(result["authorization"]), configurationHash=entry["admissionConfigurationSha256"])
            epoch = cfg["registryRoot"] + "/" + entry["containerId"] + "/epochs/1"
            grant.update(consumptionJournal=epoch + "/deployment.json", preexecJournal=epoch + "/preexec.json")
            grant["evidenceBinding"]["path"] = epoch + "/evidence.json"
            grant["profile"].update(containerId=entry["containerId"], bundlePath=epoch + "/bundle",
                bundleHash=result["audit"][role]["applicationHash"], transactionId=D.correlation(grant["operationBinding"]))
            D.validate(A.canonical(grant))
        for target, original in C.SOURCE_MAP.items():
            self.assertEqual(docs["source/" + target], inputs["sources"][original])

    def test_nics_and_closed_transport_delta(self):
        inputs = fixture()
        result = C.compose(inputs)
        owner = json.loads(inputs["files"]["coordinator"])
        for role in C.ROLES:
            previous = json.loads(inputs["files"][role + "/historicalTemplate"])
            template = json.loads(result["documents"]["documents/" + role + "/preparer-template.json"])
            for k in ("commands", "commandHashes", "pythonPath", "pythonHash", "budgetSeconds", "hostNetworkNamespace"):
                self.assertEqual(template[k], previous[k])
            for old, new in zip(previous["candidate"]["networkBindings"], template["candidate"]["networkBindings"]):
                self.assertEqual({k: v for k, v in old.items() if k != "leaseGuard"},
                                 {k: v for k, v in new.items() if k != "leaseGuard"})
                if "leaseGuard" in new:
                    self.assertEqual(new["leaseGuard"]["configurationHash"], owner["binding"]["configurationHash"])
            self.assertEqual(template["coordinationBinding"], owner["binding"])
            self.assertEqual(template["kernel"], owner["kernel"])
            self.assertEqual(template["dns"], owner["dns"])
            for old, new in zip(previous["candidate"]["transport"], template["candidate"]["transport"]):
                self.assertEqual({k: v for k, v in old.items() if k != "peerIngress"},
                                 {k: v for k, v in new.items() if k != "peerIngress"})
        transport = json.loads(result["documents"]["documents/southbound/transport.json"])
        self.assertEqual(transport["transport"][1]["peerIngress"], {"kind": "BRIDGE_PORT", "ifindex": 1450})

    def test_real_frame_observer_artifact_and_application_checks(self):
        result = C.compose(fixture())
        with grant_fixture.part_a.libraries():
            from tools import semantic_provider_deployment_authentication as authentication
            CreatedFrameObserver = authentication.CreatedFrameObserver
            cfg = json.loads(result["documents"]["broker/adapter.json"])
            entry = A.validate(result["authorization"])["roles"]["adapter"]
            application = result["audit"]["adapter"]["applicationHash"]
            with patch.object(authentication, "ancestors"):
                observer = CreatedFrameObserver(cfg["creationFrameObserverBinding"], Mock())
            frame = {"schema": "ouf.semantic-configured-created-frame.v1", "configuredPolicy": {
                "configuredPolicyConforms": True, "applicationHash": application}, "sourceMountFrame": {
                "sourceByteHashesMatchExpected": True, "stableAcrossReads": True, "privateMaterialSpooled": False,
                "mountObservation": {"effectiveReadOnlyFileBindingsObserved": True}},
                **dict.fromkeys(("policyAuthenticationProven", "rootfsSealProven", "imagePublisherProvenanceVerified",
                    "completeCreationAccepted", "acceptanceGranted", "startAuthorized"), False), "signaturesIssued": 0}
            private = {"source": b"observer", "configuration": result["documents"]["documents/adapter/frame-policy.json"]}
            with patch.object(observer, "pinned", return_value=("/python", private)), \
                    patch.object(observer, "invoke", return_value=A.canonical(frame)) as invoke:
                observer.observe({"pid": 3}, PurePosixPath("/bundle"), application, entry["framePolicySha256"])
                packet = json.loads(invoke.call_args.args[1])
                self.assertEqual(packet["policyHash"], A.sha(private["configuration"]))
                with self.assertRaisesRegex(Exception, "CREATED_FRAME_ARTIFACT_DRIFT"):
                    observer.observe({"pid": 3}, PurePosixPath("/bundle"), application, "0" * 64)
                frame["configuredPolicy"]["applicationHash"] = "0" * 64
                invoke.return_value = A.canonical(frame)
                with self.assertRaisesRegex(Exception, "NODE_CONFIGURED_SOURCE_MOUNT_FRAME_REQUIRED"):
                    observer.observe({"pid": 3}, PurePosixPath("/bundle"), application, entry["framePolicySha256"])

    def test_fail_closed_on_policy_format_and_input_drift(self):
        for suffix in (b"", b"\n\n", b"\r\n", b" \n"):
            inputs = fixture()
            inputs["files"]["adapter/policy"] = inputs["files"]["adapter/policy"][:-1] + suffix
            with self.subTest(suffix=suffix), self.assertRaisesRegex(Exception, "RECIPE_POLICY_NOT_CANONICAL_PLUS_LF"):
                C.compose(inputs)
        for key, field, value in (("settings", "tableNames", {"adapter": "ouf_v2_adapter", "southbound": "fresh"}),
                                  ("coordinationJournal", "state", "BLOCKED")):
            inputs = fixture()
            doc = json.loads(inputs["files"][key]); doc[field] = value
            inputs["files"][key] = A.canonical(doc)
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                C.compose(inputs)
        inputs = fixture()
        inputs["sources"]["tools/semantic_lease_recovery/dns.py"] += b"\n"
        with self.assertRaisesRegex(RuntimeError, "SUPERVISOR_RECOVERY_PIN_MISMATCH"):
            C.compose(inputs)


if __name__ == "__main__":
    unittest.main()
