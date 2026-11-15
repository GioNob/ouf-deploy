"""Task-35: read-only B2 inventory. Runs on Linux as any user (custody uid = own uid).

The fixture reproduces the shapes the reader walks: wrapper, v5.1 configuration,
B1 switch backup -> v4 configuration -> broker -> policy/producers -> driver and
journals, versioned base, A2 ingress, recipes and a fake nft. Every file also
carries a sentinel in a non-whitelisted field: it must never reach the output.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/read-semantic-provider-b2-inputs.py"
RUNBOOK = ROOT / "ops/vps/b2-read.sh"
SENTINEL = "SENTINEL-NEVER-PRINTED"
POSIX = sys.platform == "linux"
ADAPTER = "a" * 64
SOUTHBOUND = "b" * 64
OLD = "c" * 64


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load():
    spec = importlib.util.spec_from_file_location("b2_inventory", SCRIPT)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    value.REQUIRED_UID = os.geteuid()
    return value


def write(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
    path.write_bytes(raw)
    os.chmod(path, mode)
    return {"path": str(path), "sha256": sha(raw)}


def key(ref, issuer, roles):
    return {"keyRef": ref, "issuerRef": issuer, "roles": roles, "publicKey": "d" * 64,
            "notBefore": 1, "expiresAt": 2000000000, "state": "ACTIVE"}


@unittest.skipUnless(POSIX, "POSIX custody (O_NOFOLLOW, uid) required")
class Inventory(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.t = t
        policy = {"schema": "ouf.semantic-deployment-trust-policy.v1", "installationRef": "inst", "entityRef": "ent",
                  "keys": [key("installer", "ouf-lab-infrastructure-installer", ["DEPLOYMENT_INTENT"])],
                  "secretish": SENTINEL}
        policy_binding = write(t / "policy/trust-policy.json", policy)
        candidate_root = t / "historic/registry" / OLD
        write(candidate_root / "broker-state.json", {"schema": "ouf.semantic-deployment-broker-journal.v1",
                                                     "state": "CLEANED", "x": SENTINEL})
        coordination = write(t / "historic/lease/coordination.json",
                             {"schema": "lease.v1", "state": "QUIESCED", "leaseAuthorized": False, "x": SENTINEL})
        write(candidate_root / "driver.json", {"schema": "ouf.semantic-preexec-driver.v6",
              "kernel": {"tableName": "ouf_lease", "leaseStructureHash": "e" * 64, "secret": SENTINEL},
              "coordinationJournal": coordination["path"], "lockFile": "/run/x.lock", "commands": SENTINEL})
        producer_source = write(t / "historic/source/producer.py", b"print(1)\n")
        producer_config = write(t / "historic/approval-producer.json",
                                {"schema": "ouf.semantic-installer-approval-producer.v1", "keyRef": "installer",
                                 "signingKeyBinding": {"path": "/etc/never/opened.key", "sha256": "f" * 64},
                                 "other": SENTINEL})
        intent = write(t / "historic/intent.json", {"x": SENTINEL})
        broker = {"schema": "ouf.semantic-deployment-broker.v1", "sourceRoot": str(t / "historic/source"),
                  "sourceHashes": {"a.py": "0" * 64}, "authorities": {"installationRef": "inst"},
                  "intentBinding": intent, "policyBinding": policy_binding,
                  "signatureDirectory": str(t / "sigs"), "opensslBinding": {"path": "/usr/bin/openssl",
                  "sha256": "1" * 64, "version": "OpenSSL 3"},
                  "producers": {"approval": {"python": {"path": "/usr/bin/python3", "sha256": "2" * 64},
                                             "source": producer_source, "configuration": producer_config}},
                  "preparerTemplate": intent, "candidateRoot": str(candidate_root), "runtimeRootParent": "/run",
                  "hidden": SENTINEL}
        broker_binding = write(t / "historic/broker.json", broker)
        v4 = {"schema": "ouf.semantic-docker-runtime-adapter.v4", "candidates": {OLD: {
              "intentRef": intent["sha256"], "bundleParents": ["/run/containerd"],
              "admissionConfiguration": broker_binding["path"],
              "admissionConfigurationHash": broker_binding["sha256"]}}, "hidden": SENTINEL}
        v4_binding = write(t / "historic/runtime-configuration.json", v4)
        write(t / "b1/switch/prior-runtime-wrapper.sh",
              f'#!/bin/sh\nexec /usr/bin/python3 -I -B /h/runtime.py --configuration {v4_binding["path"]} "$@"\n'.encode())
        registry = t / "v51-registry"
        registry.mkdir(mode=0o700)
        arming = t / "v51/arming"
        arming.mkdir(parents=True, mode=0o700)
        v51 = {"schema": "ouf.semantic-docker-runtime-adapter.v5.1", "registryRoot": str(registry),
               "runtimeStateRoot": str(t / "state"), "armingRoot": str(arming), "admissionPath": "/a.py",
               "admissionSha256": "3" * 64, "candidates": {
                   ADAPTER: {"phase": "INACTIVE", "bundleParents": ["/run/containerd"]},
                   SOUTHBOUND: {"phase": "INACTIVE", "bundleParents": ["/run/containerd"]}},
               "hidden": SENTINEL}
        v51_binding = write(t / "v51/runtime-configuration.json", v51)
        self.wrapper = write(t / "wrapper", f'#!/bin/sh\nexec /usr/bin/python3 -I -B /v/runtime.py '
                             f'--configuration {v51_binding["path"]} "$@"\n'.encode(), 0o755)["path"]
        base = {**policy, "keys": [key("installer", "i", ["DEPLOYMENT_INTENT"]), key("attestor", "a",
                                                                                    ["CREATION_ATTESTATION"])]}
        write(t / "base-versioned/1.json", base)
        self.latest = write(t / "base-versioned/2.json", base)
        write(t / "a2/result.json", {"semanticPeer": {"proposedIngress": {"kind": "BRIDGE_PORT",
                                    "destinationPort": 10443}, "secret": SENTINEL}})
        write(t / "recipes/adapter/context.json", {"schema": "ouf.recipe.v1", "x": SENTINEL})
        nft = t / "nft"
        nft.write_text("#!/bin/sh\nif [ \"$3\" = tables ]; then\n"
                       "echo '{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"ouf_lease\"}}]}'\n"
                       "else\necho '{\"nftables\":[{\"set\":{\"name\":\"provider_1\",\"elem\":[]}}]}'\nfi\n")
        os.chmod(nft, 0o755)
        self.args = self.m.arguments(["--wrapper", self.wrapper, "--b1-root", str(t / "b1"), "--a2-root",
                                      str(t / "a2"), "--recipes-root", str(t / "recipes"),
                                      "--versioned-base-root", str(t / "base-versioned"), "--nft", str(nft)])

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_inventory(self):
        report = self.m.collect(self.args)
        self.assertEqual(report["sectionErrors"], [], report)
        self.assertEqual(report["v51"]["schema"], "ouf.semantic-docker-runtime-adapter.v5.1")
        self.assertEqual(report["v51"]["candidateRegistryEntries"], {ADAPTER: None, SOUTHBOUND: None})
        self.assertEqual(report["v51"]["arming"]["entries"], [])
        old = report["historicV4"]["candidates"][OLD]
        self.assertTrue(old["broker"]["matchesCandidate"])
        self.assertTrue(old["broker"]["producers"]["approval"]["signingKeyBindingPresent"])
        self.assertEqual(old["driver"]["coordinationJournalState"]["state"], "QUIESCED")
        self.assertEqual(old["broker-state.json"]["state"], "CLEANED")
        self.assertEqual(report["versionedBase"]["generations"], [1, 2])
        self.assertEqual(report["versionedBase"]["latest"]["sha256"], self.latest["sha256"])
        self.assertEqual(report["nft"]["detail"], {"inet ouf_lease": [["provider_1", 0]]})
        self.assertEqual(report["a2Ingress"][0]["proposedIngress"]["destinationPort"], 10443)
        for name in ("writes", "containerOperations", "nftWrites", "privateKeysRead", "signaturesIssued"):
            self.assertEqual(report[name], 0)

    def test_never_prints_content(self):
        text = json.dumps(self.m.collect(self.args))
        self.assertNotIn(SENTINEL, text)
        self.assertNotIn("opened.key", text)

    def test_drift_is_reported_per_section(self):
        broker = json.loads(Path(self.t / "historic/broker.json").read_bytes())
        broker["runtimeRootParent"] = "/elsewhere"
        write(self.t / "historic/broker.json", broker)
        report = self.m.collect(self.args)
        self.assertFalse(report["historicV4"]["candidates"][OLD]["broker"]["matchesCandidate"])
        os.chmod(self.t / "base-versioned/2.json", 0o666)
        report = self.m.collect(self.args)
        self.assertIn("versionedBase", report["sectionErrors"])
        self.assertEqual(report["versionedBase"]["error"], "NOT_WRITABLE_BY_OTHERS_REQUIRED")
        self.assertNotIn("v51", report["sectionErrors"])

    def test_symlink_refused(self):
        target = self.t / "v51/runtime-configuration.json"
        link = self.t / "link-wrapper"
        os.symlink(self.wrapper, link)
        self.assertEqual(self.m.collect(self.m.arguments(
            ["--wrapper", str(link), "--b1-root", "/n", "--a2-root", "/n", "--recipes-root", "/n",
             "--versioned-base-root", "/n", "--nft", "/n"]))["wrapper"]["error"], "OS_ERROR")
        self.assertTrue(target.exists())

    def test_main_requires_isolated_root(self):
        result = subprocess.run([sys.executable, str(SCRIPT), *sum(([f"--{n}", "/n"] for n in (
            "wrapper", "b1-root", "a2-root", "recipes-root", "versioned-base-root", "nft")), [])],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "ROOT_ISOLATED_PYTHON_REQUIRED")


class Contract(unittest.TestCase):
    def test_runbook_pins_reader_blob(self):
        blob = subprocess.run(["git", "-C", str(ROOT), "show", "HEAD:scripts/read-semantic-provider-b2-inputs.py"],
                              capture_output=True, check=True).stdout
        text = RUNBOOK.read_text()
        pinned = re.search(r"^R=([0-9a-f]{64})$", text, re.M).group(1)
        self.assertEqual(pinned, sha(blob))

    def test_runbook_read_only(self):
        text = RUNBOOK.read_text()
        for word in ("--apply", "docker start", "nft add", "nft delete", "rm -"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
