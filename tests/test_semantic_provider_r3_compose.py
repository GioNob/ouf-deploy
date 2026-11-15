"""Synthetic section-14 structure, real repository blobs and component validators."""
import copy
import importlib.util
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
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


def fixture():
    global SOURCE_CACHE
    if SOURCE_CACHE is None:
        # Exercise the current implementation, including uncommitted modules.
        # Delivery is LF; preserve the fixed recovery pins on CRLF checkouts.
        SOURCE_CACHE = {p: (ROOT / p).read_bytes().replace(b"\r\n", b"\n") for p in C.SOURCE_INPUTS}
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
        baseline = json.loads((ROOT / ("tools/semantic_frame_compiler/containerd-overlayfs-adapter.json" if role == "adapter"
            else "tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json")).read_bytes())
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
    return {"files": files, "sources": SOURCE_CACHE.copy()}


class ComposeTests(unittest.TestCase):
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
