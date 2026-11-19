"""Checks for A's read-only plan, certificate projection, and kernel veth read."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-semantic-provider-a-20261111.py"
if not SCRIPT.exists():
    SCRIPT = Path(__file__).with_name(SCRIPT.name)
A = runpy.run_path(str(SCRIPT))
MODULE = A["main"].__globals__


class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.crt"
            subprocess.run(("/usr/bin/openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:P-256", "-nodes", "-x509", "-days", "1",
                            "-subj", "/CN=" + A["SOUTHBOUND_HOST"], "-out", str(path),
                            "-keyout", str(path.with_suffix(".key"))), capture_output=True, check=True, timeout=10)
            cls.leaf = path.read_bytes()

    def test_apisix_ssl_der_sni_and_key_projection(self):
        resource = {"type": "server", "status": 1, "snis": [A["SOUTHBOUND_HOST"]],
                    "cert": self.leaf.decode().replace("\n", "\r\n"), "key": {"ignored": "private fixture"}}
        def routes(rows):
            return json.dumps({"ssls": rows}).encode() + b"#END\n"
        A["verify_served_certificate"](routes([resource]), self.leaf)
        for rows in (
            [],
            [resource, resource],
            [resource | {"cert": self.leaf.decode() * 2}],
            [resource | {"cert": self.leaf.decode().replace("MI", "AJ", 1)}],
            [resource | {"certs": [self.leaf.decode()]}],
            [resource | {"snis": ["other.example"]}],
            [resource | {"type": "client"}],
        ):
            with self.assertRaisesRegex(A["Held"], "^SOUTHBOUND_SERVED_CERTIFICATE_MISMATCH$"):
                A["verify_served_certificate"](routes(rows), self.leaf)

    def test_rejects_a_non_reciprocal_link(self):
        child = {"ifname": "eth0", "ifindex": 3, "link_index": 931, "address": "b2:96:a1:e2:c1:8d",
                 "addr_info": [{"family": "inet", "local": "172.18.0.6"}], "linkinfo": {"info_kind": "veth"}}
        host = {"ifname": "veth123", "ifindex": 931, "link_index": 3, "master": "br-113b5f0a3c53",
                "linkinfo": {"info_kind": "veth"}}
        def check(row):
            return A["reciprocal_link"]([child], lambda index: row, child["addr_info"][0]["local"],
                                        child["address"], host["master"])
        self.assertEqual(check(host)["hostIfindex"], 931)
        with self.assertRaisesRegex(A["Held"], "^SEMANTIC_VETH_PEER_CHANGED$"):
            check(host | {"link_index": 4})

    def test_plan_and_wrong_hash_never_stage(self):
        calls = []
        digest = "a" * 64
        def capture(fd, raw):
            calls.append(bytes(raw))
            return len(raw)
        def forbidden_stage(*args):
            self.fail("plan or rejected digest attempted a write")
        with patch.dict(MODULE, helpers=lambda: (None, None), plan=lambda *_: ({}, digest, {}),
                        stage=forbidden_stage), patch.object(os, "geteuid", return_value=0), patch.object(os, "write", side_effect=capture):
            with patch.object(sys, "argv", [str(SCRIPT), "--plan"]):
                self.assertEqual(A["main"](), 0)
                self.assertEqual(json.loads(calls.pop())["status"], "PLAN_READY")
            with patch.object(sys, "argv", [str(SCRIPT), "--apply", "--plan-sha256", "b" * 64]):
                self.assertEqual(A["main"](), 1)
                self.assertEqual(json.loads(calls.pop())["reason"], "PLAN_DIGEST_CHANGED")

    def test_stage_creates_exact_manifest_files_and_keeps_first_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "private"
            guard = lambda: A["require"](not root.exists(), "PREPARATION_SCOPE_ALREADY_EXISTS")
            manifest = {"filesCreated": list(A["OUTPUTS"])}
            data = {"semantic-peer.json": {"containerId": "fixture"}, "successors.json": {"containers": []}}
            report = {}
            with patch.dict(MODULE, WORK=root, check_work_parent=guard), patch.object(os, "fchown"):
                A["stage"](manifest, "a" * 64, data, report)
                with self.assertRaisesRegex(A["Held"], "^PREPARATION_SCOPE_ALREADY_EXISTS$"):
                    A["stage"](manifest, "b" * 64, data, {})
            self.assertEqual(set(p.name for p in root.iterdir()), set(A["OUTPUTS"]))
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all((p.stat().st_mode & 0o777) == 0o600 for p in root.iterdir()))
            self.assertEqual(json.loads((root / "result.json").read_bytes()), report)
            self.assertEqual(json.loads((root / "manifest.json").read_bytes())["planSha256"], "a" * 64)

    @unittest.skipUnless(os.environ.get("OUF_A_NATIVE") == "1", "requires isolated host network fixtures")
    def test_native_observation_reads_actual_host_and_child_indices(self):
        network_id = uuid.uuid4().hex * 2
        bridge, namespace, veth = "br-" + network_id[:12], "oufa-" + network_id[:7], "v" + network_id[:9]
        cutover = types.SimpleNamespace(NETWORK_ID=network_id, NETWORK="fixture", ADDRESS="172.18.0.6",
                                        MAC="b2:96:a1:e2:c1:8d", remaining=lambda deadline, limit: limit)
        def ip(*args):
            subprocess.run((A["IP"], *args), capture_output=True, check=True, timeout=5)
        ip("netns", "add", namespace)
        self.addCleanup(ip, "netns", "delete", namespace)
        ip("link", "add", bridge, "type", "bridge")
        self.addCleanup(ip, "link", "delete", bridge)
        ip("link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", namespace)
        self.addCleanup(ip, "link", "delete", veth)
        ip("link", "set", veth, "master", bridge)
        ip("-n", namespace, "link", "set", "eth0", "address", cutover.MAC)
        ip("-n", namespace, "addr", "add", cutover.ADDRESS + "/16", "dev", "eth0")
        process = subprocess.Popen((A["IP"], "netns", "exec", namespace, "/usr/bin/sleep", "30"))
        def stop():
            process.terminate()
            process.wait(timeout=5)
        self.addCleanup(stop)
        for _ in range(40):
            if Path("/proc", str(process.pid), "ns/net").stat().st_ino == Path("/run/netns", namespace).stat().st_ino:
                break
            time.sleep(0.05)
        else:
            self.fail("fixture process did not enter the network namespace")
        current = {"Id": "c" * 64, "Image": "fixture", "State": {"Pid": process.pid, "StartedAt": "fixture"},
                   "NetworkSettings": {"Networks": {"fixture": {"EndpointID": "e" * 64}}}}
        peer = A["observe_peer"](cutover, time.monotonic() + 10, current)
        self.assertEqual(peer["generation"]["pid"], process.pid)
        self.assertEqual(peer["binding"]["hostInterface"], veth)
        self.assertEqual(peer["binding"]["hostIfindex"], int(Path("/sys/class/net", veth, "ifindex").read_text()))
