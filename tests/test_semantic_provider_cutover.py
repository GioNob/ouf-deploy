"""Run D restoration against disposable Docker containers on the hosted runner."""
import copy
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
D = runpy.run_path(str(SCRIPTS / "cutover-semantic-provider-20261111.py"))
NAMESPACE = D["restore"].__globals__
DOCKER_HOST = os.environ.get("DOCKER_HOST", "unix:///run/docker.sock")


def cli(*args):
    return subprocess.check_output(("docker", *args), timeout=30, text=True).strip()


class CutoverTests(unittest.TestCase):
    def test_merge_loadable_by_java_with_default_and_provider_anchors(self):
        _, _, trust = D["load_helpers"]()
        stock = subprocess.check_output(("keytool", "-J-XX:-UsePerfData", "-list", "-rfc", "-cacerts",
                                        "-storepass", "changeit"), stderr=subprocess.DEVNULL, timeout=20)
        certificates = {D["ssl"].PEM_cert_to_DER_cert(value.decode()) for value in trust.PEM.findall(stock)}
        self.assertGreater(len(certificates), 50)
        with tempfile.TemporaryDirectory() as temp:
            cert = Path(temp) / "fixture.crt"
            subprocess.run(("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=ouf-public-fixture", "-keyout", str(Path(temp) / "fixture.key"),
                            "-out", str(cert)), check=True, capture_output=True, timeout=10)
            added = D["ssl"].PEM_cert_to_DER_cert(cert.read_text())
            self.assertNotIn(added, certificates)
            path = Path(temp) / "merged.p12"
            path.write_bytes(trust._pkcs12(sorted(certificates | {added}, key=D["sha"])))
            result = subprocess.check_output(("keytool", "-list", "-keystore", str(path), "-storetype",
                                              "PKCS12", "-storepass", "changeit"), timeout=20)
        self.assertEqual(result.count(b"trustedCertEntry"), len(certificates) + 1)

    def test_interrupted_terminal_during_apply_preserves_receipt(self):
        fixture = textwrap.dedent("""\
            from contextlib import nullcontext
            import os, runpy, signal, sys
            from pathlib import Path
            from unittest.mock import patch

            source, work, scenario = sys.argv[1:]
            d = runpy.run_path(source)
            namespace = d["main"].__globals__
            supervisor_group = os.getpgrp()
            signals = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
            for signum in signals:
                signal.signal(signum, signal.SIG_DFL)
            old = {"Id": d["OLD"]}
            stopped = {"State": {"Running": True, "Pid": 50}}
            reads = iter((old, stopped))
            actions = []

            def action(deadline, cid, operation):
                assert operation == "stop?t=15" and cid == old["Id"]
                assert os.getsid(0) == os.getpid() and os.getpgrp() != supervisor_group
                actions.append(operation)
                for signum in signals:
                    os.kill(os.getpid(), signum)
                if scenario == "supervisor_killed":
                    os.killpg(supervisor_group, signal.SIGKILL)

            def restore(*args):
                assert actions == ["stop?t=15"]
                for signum in signals:
                    os.kill(os.getpid(), signum)
                if scenario == "held":
                    raise d["Held"]("FIXTURE_RESTORE_FAILED")

            digest = "a" * 64
            manifest = {"filesCreatedUnderPrivateDirectory": list(d["JOURNAL_FILES"])}
            planned = (manifest, digest, old, {"Labels": {}}, b"", b"", "b" * 64)
            sys.argv = [source, "--apply", "--plan-sha256", digest]
            ownership = nullcontext() if os.geteuid() == 0 else patch.object(os, "fchown")
            with ownership, patch.object(os, "geteuid", return_value=0), patch.dict(
                namespace, WORK=Path(work), load_helpers=lambda: (None, None, None),
                plan=lambda *args: planned, inspect=lambda *args: next(reads), action=action, restore=restore,
            ):
                raise SystemExit(d["main"]())
            """)
        for scenario in ("restored", "held", "supervisor_killed"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                work = Path(temp) / "journal"
                reader, writer = os.pipe()
                os.close(reader)
                with os.fdopen(writer, "wb") as broken_stdout:
                    child = subprocess.Popen(
                        (sys.executable, "-I", "-B", "-c", fixture,
                         str(SCRIPTS / "cutover-semantic-provider-20261111.py"), str(work), scenario),
                        stdout=broken_stdout, stderr=subprocess.PIPE, start_new_session=True,
                    )
                _, stderr = child.communicate(timeout=10)
                self.assertEqual(stderr, b"")
                self.assertEqual(child.returncode, -signal.SIGKILL if scenario == "supervisor_killed" else 1)
                path = work / "result.json"
                receipt = json.loads(path.read_bytes())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_uid, os.geteuid())
                if os.geteuid() == 0:
                    self.assertEqual(path.stat().st_gid, 0)
                self.assertIn("result.json", receipt["manifest"]["filesCreatedUnderPrivateDirectory"])
                self.assertEqual(receipt["reason"], "OLD_STOP_FRAME_CHANGED")
                if scenario == "held":
                    self.assertEqual(receipt["status"], "HELD")
                    self.assertEqual(receipt["restoreReason"], "FIXTURE_RESTORE_FAILED")
                else:
                    self.assertEqual(receipt["status"], "SEMANTIC_PREVIOUS_CONTAINER_RESTORED")
                    self.assertTrue((work / "restored.json").exists())

    def test_alias_guard_rejects_changes_hidden_by_compatibility_view(self):
        aliases = list(D["BACKEND_ALIASES"])
        cid, net = D["OLD"], D["NETWORK"]
        name = "ouf-semantic-cutover-fixture"
        old = {"Id": cid, "Name": "/" + name, "State": {"Pid": 100}, "Config": {"Hostname": aliases[-1]},
               "NetworkSettings": {"Networks": {net: {
                   "Aliases": aliases + [cid[:12]], "DNSNames": [name, *aliases, cid[:12]], "EndpointID": "fixture",
               }}}}
        native = copy.deepcopy(old)
        native_endpoint = native["NetworkSettings"]["Networks"][net]
        native_endpoint["Aliases"] = aliases.copy()
        with patch.dict(NAMESPACE, inspect=lambda *args, **kwargs: native):
            self.assertEqual(D["verify_backend_names"](time.monotonic() + 5, old, aliases), aliases)
            native_endpoint["Aliases"].append(cid[:12])
            with self.assertRaisesRegex(D["Held"], "^BACKEND_ALIAS_SET_CHANGED$"):
                D["verify_backend_names"](time.monotonic() + 5, old, aliases)
            native_endpoint["Aliases"].pop()
            native_endpoint["DNSNames"].remove(name)
            with self.assertRaisesRegex(D["Held"], "^BACKEND_ALIAS_OBSERVATION_CHANGED$"):
                D["verify_backend_names"](time.monotonic() + 5, old, aliases)

    def test_replacement_and_restore_preserve_backend_dns(self):
        self.assertTrue(DOCKER_HOST.startswith("unix://"))
        socket = DOCKER_HOST.removeprefix("unix://")
        docker_socket = patch.dict(NAMESPACE, DOCKER_SOCKET=socket)
        docker_socket.start()
        self.addCleanup(docker_socket.stop)
        version = D["engine"](time.monotonic() + 5, "GET", "/version", api=D["RECONNECT_API"])
        self.assertEqual(version["Version"], "29.8.1")
        prefix = "ouf-d-ci-" + uuid.uuid4().hex[:10]
        name = prefix + "-semantic"
        retained = name + "-before"
        failed = name + "-failed"
        ip, mac = "172.29.218.6", "b2:96:a1:e2:c1:8d"
        aliases = list(D["BACKEND_ALIASES"])
        network = cli("network", "create", "--subnet", "172.29.218.0/24", prefix)
        cids = []
        def cleanup():
            if cids:
                subprocess.run(("docker", "rm", "-f", *cids), capture_output=True, timeout=30, check=True)
            cli("network", "rm", network)
        self.addCleanup(cleanup)
        image = cli("image", "inspect", "busybox:1.37.0", "--format", "{{.Id}}")
        base = {"Image": image, "Hostname": aliases[-1], "Cmd": ["/bin/sh", "-c",
                "trap ':' USR1; touch /tmp/fixture-ready; while :; do sleep 1; done"],
                "HostConfig": {"NetworkMode": prefix, "RestartPolicy": {"Name": "no"}},
                "NetworkingConfig": {"EndpointsConfig": {prefix: {
                    "IPAMConfig": {"IPv4Address": ip}, "MacAddress": mac, "Aliases": aliases,
                }}}}
        deadline = time.monotonic() + 60
        def create(request, labels):
            result = D["engine"](deadline, "POST", "/containers/create?name=" + name, request | {"Labels": labels})
            cids.append(result["Id"])
            return result["Id"]
        cid = create(base, {})
        D["action"](deadline, cid, "start")
        old = D["inspect"](deadline, cid)
        old_endpoint = old["NetworkSettings"]["Networks"][prefix]
        self.assertEqual(old["Config"]["MacAddress"], mac)
        self.assertEqual(old_endpoint["MacAddress"], mac)
        self.assertEqual(set(old_endpoint["DNSNames"]), {name, cid[:12], *aliases})
        with patch.dict(NAMESPACE, NETWORK=prefix):
            configured = D["verify_backend_names"](deadline, old, aliases)
        D["action"](deadline, cid, "stop?t=2")
        D["engine"](deadline, "POST", f"/networks/{network}/disconnect", {"Container": cid, "Force": False})
        D["action"](deadline, cid, "rename?name=" + retained)
        retained_old = D["inspect"](deadline, cid)
        self.assertNotIn("MacAddress", retained_old["Config"])
        self.assertEqual(retained_old["NetworkSettings"]["Networks"], {})
        digest = "c" * 64
        request = copy.deepcopy(base)
        request["NetworkingConfig"]["EndpointsConfig"][prefix]["Aliases"] = old_endpoint["Aliases"]
        candidate = create(request, {D["LABEL"]: digest})
        D["action"](deadline, candidate, "start")
        new = D["inspect"](deadline, candidate)
        self.assertEqual(new["NetworkSettings"]["Networks"][prefix]["MacAddress"], mac)
        with patch.dict(NAMESPACE, NETWORK=prefix):
            D["verify_replacement_dns"](old, new)
        def ready(doc):
            for _ in range(30):
                status = subprocess.run(("docker", "exec", doc["Id"], "cat", "/proc/1/status"),
                                        capture_output=True, timeout=4)
                caught = re.search(rb"^SigCgt:\s*([0-9a-f]+)$", status.stdout, re.MULTILINE)
                if status.returncode == 0 and caught and int(caught[1], 16) & (1 << 9):
                    return
                time.sleep(0.1)
            self.fail("Fixture gate did not start")
        rollout = SimpleNamespace(mounts=lambda doc: doc["Mounts"], gate_running=ready)
        manifest = {"newContainer": {"name": name}, "retainedName": retained, "failureName": failed,
                    "observedGateway": "fixture", "network": {"configuredAliases": configured}}
        with patch.dict(NAMESPACE, OLD=cid, NETWORK=prefix, NETWORK_ID=network, IMAGE=image, ADDRESS=ip, MAC=mac,
                        await_health=lambda *_: ready(D["inspect"](time.monotonic() + 5, cid))):
            D["restore"](rollout, old, manifest, digest, candidate)
        actual = D["inspect"](time.monotonic() + 5, cid)
        self.assertTrue(actual["State"]["Running"])
        self.assertEqual(actual["Name"], "/" + name)
        self.assertEqual(set(actual["NetworkSettings"]["Networks"][prefix]["DNSNames"]), set(old_endpoint["DNSNames"]))
        replacement = D["inspect"](time.monotonic() + 5, candidate)
        self.assertEqual(replacement["Name"], "/" + failed)
        self.assertFalse(replacement["State"]["Running"])
        self.assertEqual(replacement["NetworkSettings"]["Networks"], {})


if __name__ == "__main__":
    unittest.main()
